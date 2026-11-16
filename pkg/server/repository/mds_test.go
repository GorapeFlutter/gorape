package repository

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/google/uuid"
)

func TestFidoMDSProviderVerifiesSignedBlobAndCachesIt(t *testing.T) {
	rootKey, leafKey, rootDER, leafDER := newMDSTestCertificates(t)
	decoder, err := metadata.NewDecoder(
		metadata.WithRootCertificate(base64.StdEncoding.EncodeToString(rootDER)),
		metadata.WithIgnoreEntryParsingErrors(),
	)
	if err != nil {
		t.Fatal(err)
	}
	cacheFile := t.TempDir() + "/fido-mds.jwt"
	provider := &FidoMDSProvider{
		config:  FidoMDSConfig{CacheFile: cacheFile, AcceptLegalHeader: true},
		decoder: decoder,
	}
	blob := signMDSTestBlob(t, leafKey, leafDER, rootDER, 7, time.Now().AddDate(0, 0, 2))
	if err := provider.install(blob, true, false); err != nil {
		t.Fatalf("install signed MDS blob: %v", err)
	}
	if provider.blobNumber != 7 {
		t.Fatalf("serial number = %d, want 7", provider.blobNumber)
	}
	if info, err := os.Stat(cacheFile); err != nil || info.Size() == 0 {
		t.Fatalf("MDS cache was not persisted: stat=%v error=%v", info, err)
	}
	if _, err := provider.GetEntry(t.Context(), uuid.Nil); err != nil {
		t.Fatalf("read verified metadata provider: %v", err)
	}

	updatedBlob := signMDSTestBlob(t, leafKey, leafDER, rootDER, 8, time.Now().AddDate(0, 0, 3))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write(updatedBlob)
	}))
	defer server.Close()
	provider.client = server.Client()
	provider.config.URL = server.URL
	provider.nextUpdate = time.Now().Add(-time.Second)
	if err := provider.refreshIfNeeded(context.Background()); err != nil {
		t.Fatalf("refresh expired MDS cache: %v", err)
	}
	if provider.blobNumber != 8 {
		t.Fatalf("refreshed serial number = %d, want 8", provider.blobNumber)
	}

	rollback := signMDSTestBlob(t, leafKey, leafDER, rootDER, 6, time.Now().AddDate(0, 0, 2))
	if err := provider.install(rollback, false, false); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("serial rollback error = %v, want rollback rejection", err)
	}

	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 1
	if err := provider.install(tampered, false, false); err == nil {
		t.Fatal("tampered MDS signature was accepted")
	}
	_ = rootKey
}

func TestFidoMDSProviderRejectsMissingLegalAcceptanceAndExpiredBlob(t *testing.T) {
	if _, err := NewFidoMDSProvider(FidoMDSConfig{CacheFile: "unused.jwt"}); err == nil {
		t.Fatal("MDS setup without explicit legal-header acceptance must fail")
	}
	rootKey, leafKey, rootDER, leafDER := newMDSTestCertificates(t)
	decoder, err := metadata.NewDecoder(
		metadata.WithRootCertificate(base64.StdEncoding.EncodeToString(rootDER)),
		metadata.WithIgnoreEntryParsingErrors(),
	)
	if err != nil {
		t.Fatal(err)
	}
	provider := &FidoMDSProvider{
		config:  FidoMDSConfig{CacheFile: t.TempDir() + "/blob", AcceptLegalHeader: true},
		decoder: decoder,
	}
	blob := signMDSTestBlob(t, leafKey, leafDER, rootDER, 1, time.Now().AddDate(0, 0, -1))
	if err := provider.install(blob, false, false); err == nil {
		t.Fatal("expired MDS blob was accepted")
	}
	_ = rootKey
}

func TestFidoMDSMetadataProviderRejectsRevokedAuthenticatorStatus(t *testing.T) {
	provider := &fidoMDSMetadataProvider{
		entries:   map[uuid.UUID]*metadata.Entry{},
		undesired: metadata.DefaultUndesiredAuthenticatorStatuses(),
	}
	err := provider.ValidateStatusReports(context.Background(), []metadata.StatusReport{{Status: metadata.Revoked}})
	if err == nil {
		t.Fatal("revoked authenticator status should be rejected")
	}
}

func TestNilFidoMDSProviderFailsClosedWithoutPanicking(t *testing.T) {
	var provider *FidoMDSProvider
	if _, err := provider.GetEntry(context.Background(), uuid.Nil); !errors.Is(err, metadata.ErrNotInitialized) {
		t.Fatalf("nil provider GetEntry error = %v, want ErrNotInitialized", err)
	}
	if err := provider.ValidateStatusReports(context.Background(), nil); !errors.Is(err, metadata.ErrNotInitialized) {
		t.Fatalf("nil provider ValidateStatusReports error = %v, want ErrNotInitialized", err)
	}
}

func newMDSTestCertificates(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "MDS Test Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "MDS Test Signer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return rootKey, leafKey, rootDER, leafDER
}

func signMDSTestBlob(t *testing.T, key *ecdsa.PrivateKey, leafDER, rootDER []byte, serial int, nextUpdate time.Time) []byte {
	t.Helper()
	header := map[string]any{
		"alg": "ES256",
		"x5c": []string{
			base64.StdEncoding.EncodeToString(leafDER),
			base64.StdEncoding.EncodeToString(rootDER),
		},
	}
	claims := map[string]any{
		"legalHeader": "accepted for automated test",
		"no":          serial,
		"nextUpdate":  nextUpdate.UTC().Format(time.DateOnly),
		"entries":     []any{},
	}
	encode := func(value any) string {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	input := encode(header) + "." + encode(claims)
	hash := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return []byte(input + "." + base64.RawURLEncoding.EncodeToString(signature))
}
