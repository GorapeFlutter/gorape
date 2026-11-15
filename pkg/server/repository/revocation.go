package repository

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/go-webauthn/x/revoke"
)

const maxRevocationCacheEntries = 8192
const maxRevocationResponseBytes = 16 << 20

var ErrRevocationResponseTooLarge = errors.New("revocation response exceeds the size limit")

type boundedRevocationTransport struct {
	base http.RoundTripper
}

func (transport boundedRevocationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err == nil && response != nil && response.Body != nil {
		response.Body = &boundedRevocationBody{ReadCloser: response.Body, remaining: maxRevocationResponseBytes}
	}
	return response, err
}

type boundedRevocationBody struct {
	io.ReadCloser
	remaining int64
}

func (body *boundedRevocationBody) Read(buffer []byte) (int, error) {
	if body.remaining == 0 {
		var extra [1]byte
		count, err := body.ReadCloser.Read(extra[:])
		if count > 0 {
			return 0, ErrRevocationResponseTooLarge
		}
		return 0, err
	}
	if int64(len(buffer)) > body.remaining {
		buffer = buffer[:body.remaining]
	}
	count, err := body.ReadCloser.Read(buffer)
	body.remaining -= int64(count)
	return count, err
}

var (
	ErrCertificateRevoked           = errors.New("certificate is revoked or outside its validity period")
	ErrCertificateRevocationUnknown = errors.New("certificate revocation status is unavailable")
)

var nonPublicRevocationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2001:10::/28"),
}

type revocationCacheEntry struct {
	revoked bool
	expires time.Time
}

// CertificateRevocationChecker performs issuer-published CRL/OCSP checks and
// caches only definitive Good/Revoked results. Network failures fail closed.
type CertificateRevocationChecker struct {
	mu       sync.Mutex
	cache    map[[32]byte]revocationCacheEntry
	cacheTTL time.Duration
}

// NewCertificateRevocationChecker configures the shared revocation transport.
// The package dependency uses process-global transport settings, so call this
// once during server initialization.
// GF-10032 — Configures bounded, public-address-only CRL/OCSP transport and cache.
func NewCertificateRevocationChecker(timeout, cacheTTL time.Duration) (*CertificateRevocationChecker, error) {
	if timeout < time.Second || timeout > 30*time.Second {
		return nil, errors.New("revocation timeout must be between 1s and 30s")
	}
	if cacheTTL < time.Minute || cacheTTL > 7*24*time.Hour {
		return nil, errors.New("revocation cache TTL must be between 1m and 7d")
	}
	transport := &http.Transport{
		Proxy:                 nil,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, candidate := range addresses {
				ip := candidate.IP
				if !isPublicRevocationIP(ip) {
					continue
				}
				dialer := net.Dialer{Timeout: timeout}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
			return nil, errors.New("revocation URL resolved only to non-public addresses")
		},
	}
	client := &http.Client{
		Transport: boundedRevocationTransport{base: transport},
		Timeout:   timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if request.URL.User != nil || (request.URL.Scheme != "http" && request.URL.Scheme != "https") {
				return errors.New("revocation redirect URL is not permitted")
			}
			if len(via) >= 3 {
				return errors.New("too many revocation redirects")
			}
			return nil
		},
	}
	revoke.HTTPClient = client
	revoke.HardFail = true
	return &CertificateRevocationChecker{cache: make(map[[32]byte]revocationCacheEntry), cacheTTL: cacheTTL}, nil
}

func isPublicRevocationIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range nonPublicRevocationPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// Check rejects revoked certificates and any certificate whose advertised
// revocation source cannot be checked. A certificate without CRL/OCSP pointers
// has no issuer-provided status mechanism and is accepted by this checker.
// GF-10033 — Fails closed on revoked or uncheckable issuer-published certificate status.
func (checker *CertificateRevocationChecker) Check(_ context.Context, certificate *x509.Certificate) error {
	if checker == nil || certificate == nil {
		return errors.New("revocation checker and certificate are required")
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	now := time.Now()
	checker.mu.Lock()
	if cached, ok := checker.cache[fingerprint]; ok && now.Before(cached.expires) {
		checker.mu.Unlock()
		if cached.revoked {
			return errors.New("certificate is revoked")
		}
		return nil
	}
	delete(checker.cache, fingerprint)
	checker.mu.Unlock()

	revoked, checked, err := revoke.VerifyCertificateError(certificate)
	if !checked {
		return ErrCertificateRevocationUnknown
	}
	if revoked {
		checker.store(fingerprint, true, now)
		return ErrCertificateRevoked
	}
	if err != nil {
		return ErrCertificateRevocationUnknown
	}
	checker.store(fingerprint, false, now)
	return nil
}

func (checker *CertificateRevocationChecker) store(fingerprint [32]byte, revoked bool, now time.Time) {
	checker.mu.Lock()
	defer checker.mu.Unlock()
	if len(checker.cache) >= maxRevocationCacheEntries {
		for key, value := range checker.cache {
			if !now.Before(value.expires) {
				delete(checker.cache, key)
			}
		}
		if len(checker.cache) >= maxRevocationCacheEntries {
			checker.cache = make(map[[32]byte]revocationCacheEntry)
		}
	}
	checker.cache[fingerprint] = revocationCacheEntry{revoked: revoked, expires: now.Add(checker.cacheTTL)}
}
