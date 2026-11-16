package repository

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/google/uuid"
)

const maxFidoMDSBlobSize = 64 << 20

type FidoMDSConfig struct {
	URL               string
	CacheFile         string
	AcceptLegalHeader bool
	RequestTimeout    time.Duration
	RefreshRetryDelay time.Duration
}

// FidoMDSProvider verifies the MDS BLOB signature and caches the parsed,
// status-aware provider. It refreshes at/after nextUpdate and fails closed if
// a stale BLOB cannot be updated.
type FidoMDSProvider struct {
	mu          sync.RWMutex
	config      FidoMDSConfig
	client      *http.Client
	decoder     *metadata.Decoder
	provider    metadata.Provider
	nextUpdate  time.Time
	blobNumber  int
	retryAt     time.Time
	lastRefresh error
}

type fidoMDSMetadataProvider struct {
	entries   map[uuid.UUID]*metadata.Entry
	undesired []metadata.AuthenticatorStatus
}

func (provider *fidoMDSMetadataProvider) GetEntry(_ context.Context, aaguid uuid.UUID) (*metadata.Entry, error) {
	return provider.entries[aaguid], nil
}
func (*fidoMDSMetadataProvider) GetValidateEntry(context.Context) bool { return true }
func (*fidoMDSMetadataProvider) GetValidateEntryPermitZeroAAGUID(context.Context) bool {
	return false
}
func (*fidoMDSMetadataProvider) GetValidateTrustAnchor(context.Context) bool { return true }
func (*fidoMDSMetadataProvider) GetValidateStatus(context.Context) bool      { return true }
func (*fidoMDSMetadataProvider) GetValidateAttestationTypes(context.Context) bool {
	return true
}
func (provider *fidoMDSMetadataProvider) ValidateStatusReports(_ context.Context, reports []metadata.StatusReport) error {
	return metadata.ValidateStatusReports(reports, nil, provider.undesired)
}

var _ metadata.Provider = (*fidoMDSMetadataProvider)(nil)

// GF-10027 — Loads and verifies a signed FIDO MDS BLOB before enabling RP metadata checks.
func NewFidoMDSProvider(config FidoMDSConfig) (*FidoMDSProvider, error) {
	if !config.AcceptLegalHeader {
		return nil, errors.New("FIDO MDS legal header must be explicitly accepted")
	}
	if config.CacheFile == "" {
		return nil, errors.New("FIDO MDS cache_file is required")
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 10 * time.Second
	}
	if config.RefreshRetryDelay <= 0 {
		config.RefreshRetryDelay = time.Minute
	}
	if config.URL == "" {
		config.URL = metadata.ProductionMDSURL
	}
	parsedURL, err := url.ParseRequestURI(config.URL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return nil, errors.New("FIDO MDS URL must be an HTTPS URL without credentials, query, or fragment")
	}
	decoder, err := metadata.NewDecoder(metadata.WithIgnoreEntryParsingErrors())
	if err != nil {
		return nil, fmt.Errorf("initialize FIDO MDS decoder: %w", err)
	}
	client := &http.Client{
		Timeout: config.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || req.URL.Host != parsedURL.Host {
				return errors.New("FIDO MDS redirect must remain on the configured HTTPS origin")
			}
			if len(via) >= 3 {
				return errors.New("too many FIDO MDS redirects")
			}
			return nil
		},
	}
	provider := &FidoMDSProvider{config: config, client: client, decoder: decoder}
	if info, statErr := os.Stat(config.CacheFile); statErr == nil && info.Size() > maxFidoMDSBlobSize {
		return nil, errors.New("cached FIDO MDS BLOB exceeds the size limit")
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("stat FIDO MDS cache: %w", statErr)
	}
	blob, readErr := os.ReadFile(config.CacheFile)
	if readErr == nil {
		if err = provider.install(blob, false, true); err != nil {
			return nil, fmt.Errorf("validate cached FIDO MDS BLOB: %w", err)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return nil, fmt.Errorf("read FIDO MDS cache: %w", readErr)
	}

	provider.mu.RLock()
	needsUpdate := provider.provider == nil || !time.Now().Before(provider.nextUpdate)
	provider.mu.RUnlock()
	if needsUpdate {
		if err = provider.fetchAndInstall(context.Background()); err != nil {
			return nil, fmt.Errorf("load current FIDO MDS BLOB: %w", err)
		}
	}
	return provider, nil
}

// GF-10028 — Looks up AAGUID metadata only after validating freshness.
func (provider *FidoMDSProvider) GetEntry(ctx context.Context, aaguid uuid.UUID) (*metadata.Entry, error) {
	if err := provider.refreshIfNeeded(ctx); err != nil {
		return nil, err
	}
	provider.mu.RLock()
	current := provider.provider
	provider.mu.RUnlock()
	if current == nil {
		return nil, metadata.ErrNotInitialized
	}
	return current.GetEntry(ctx, aaguid)
}

func (provider *FidoMDSProvider) GetValidateEntry(context.Context) bool { return true }
func (provider *FidoMDSProvider) GetValidateEntryPermitZeroAAGUID(context.Context) bool {
	return false
}
func (provider *FidoMDSProvider) GetValidateTrustAnchor(context.Context) bool { return true }
func (provider *FidoMDSProvider) GetValidateStatus(context.Context) bool      { return true }
func (provider *FidoMDSProvider) GetValidateAttestationTypes(context.Context) bool {
	return true
}

func (provider *FidoMDSProvider) ValidateStatusReports(ctx context.Context, reports []metadata.StatusReport) error {
	if err := provider.refreshIfNeeded(ctx); err != nil {
		return err
	}
	provider.mu.RLock()
	current := provider.provider
	provider.mu.RUnlock()
	if current == nil {
		return metadata.ErrNotInitialized
	}
	return current.ValidateStatusReports(ctx, reports)
}

// GF-10029 — Refreshes at nextUpdate and rejects stale metadata on update failure.
func (provider *FidoMDSProvider) refreshIfNeeded(ctx context.Context) error {
	if provider == nil {
		return metadata.ErrNotInitialized
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.provider != nil && time.Now().Before(provider.nextUpdate) {
		return nil
	}
	if !provider.retryAt.IsZero() && time.Now().Before(provider.retryAt) {
		return provider.lastRefresh
	}
	if err := provider.fetchAndInstallLocked(ctx); err != nil {
		provider.lastRefresh = err
		provider.retryAt = time.Now().Add(provider.config.RefreshRetryDelay)
		return err
	}
	provider.lastRefresh = nil
	provider.retryAt = time.Time{}
	return nil
}

func (provider *FidoMDSProvider) fetchAndInstall(ctx context.Context) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.fetchAndInstallLocked(ctx)
}

func (provider *FidoMDSProvider) fetchAndInstallLocked(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.config.URL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/jwt")
	response, err := provider.client.Do(request)
	if err != nil {
		return fmt.Errorf("request FIDO MDS BLOB: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("FIDO MDS BLOB returned HTTP %d", response.StatusCode)
	}
	blob, err := io.ReadAll(io.LimitReader(response.Body, maxFidoMDSBlobSize+1))
	if err != nil {
		return fmt.Errorf("read FIDO MDS BLOB: %w", err)
	}
	if len(blob) == 0 || len(blob) > maxFidoMDSBlobSize {
		return errors.New("FIDO MDS BLOB size is invalid")
	}
	return provider.installLocked(blob, true, false)
}

func (provider *FidoMDSProvider) install(blob []byte, persist, allowExpired bool) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.installLocked(blob, persist, allowExpired)
}

// GF-10030 — Verifies BLOB signature, legal acceptance, serial monotonicity, and status provider.
func (provider *FidoMDSProvider) installLocked(blob []byte, persist, allowExpired bool) error {
	payload, err := provider.decoder.DecodeBytes(blob)
	if err != nil {
		return fmt.Errorf("verify FIDO MDS BLOB signature: %w", err)
	}
	parsed, err := provider.decoder.Parse(payload)
	if err != nil {
		return fmt.Errorf("parse FIDO MDS BLOB: %w", err)
	}
	if strings.TrimSpace(parsed.Parsed.LegalHeader) == "" || parsed.Parsed.Number <= 0 || parsed.Parsed.NextUpdate.IsZero() {
		return errors.New("FIDO MDS BLOB lacks legalHeader, serial number, or nextUpdate")
	}
	if provider.provider != nil && parsed.Parsed.Number < provider.blobNumber {
		return errors.New("FIDO MDS BLOB serial number rollback detected")
	}
	if !allowExpired && !parsed.Parsed.NextUpdate.After(time.Now()) {
		return errors.New("FIDO MDS BLOB is already past nextUpdate")
	}
	mdsProvider := &fidoMDSMetadataProvider{
		entries:   parsed.ToMap(),
		undesired: metadata.DefaultUndesiredAuthenticatorStatuses(),
	}
	if persist {
		if err := writeMDSCache(provider.config.CacheFile, blob); err != nil {
			return err
		}
	}
	provider.provider = mdsProvider
	provider.nextUpdate = parsed.Parsed.NextUpdate
	provider.blobNumber = parsed.Parsed.Number
	return nil
}

func writeMDSCache(path string, blob []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create FIDO MDS cache directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".mds-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary FIDO MDS cache: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(blob)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return fmt.Errorf("write FIDO MDS cache: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close FIDO MDS cache: %w", closeErr)
	}
	if err = os.Rename(name, path); err != nil {
		return fmt.Errorf("replace FIDO MDS cache: %w", err)
	}
	return nil
}
