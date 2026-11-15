package repository

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRevocationCheckerCachesDefinitiveGoodStatus(t *testing.T) {
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "No revocation URLs"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
	}, &x509.Certificate{
		SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "No revocation URLs"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	checker := &CertificateRevocationChecker{
		cache: make(map[[32]byte]revocationCacheEntry), cacheTTL: time.Minute,
	}
	if err := checker.Check(context.Background(), certificate); err != nil {
		t.Fatalf("certificate without issuer revocation URLs should be accepted: %v", err)
	}
	if len(checker.cache) != 1 {
		t.Fatalf("definitive status cache entries = %d, want 1", len(checker.cache))
	}
}

func TestRevocationCheckerRejectsNonPublicStatusEndpoints(t *testing.T) {
	for _, test := range []struct {
		ip   string
		want bool
	}{
		{ip: "8.8.8.8", want: true},
		{ip: "10.0.0.1"},
		{ip: "127.0.0.1"},
		{ip: "169.254.169.254"},
		{ip: "100.64.0.1"},
		{ip: "192.0.2.1"},
		{ip: "2001:db8::1"},
	} {
		if got := isPublicRevocationIP(net.ParseIP(test.ip)); got != test.want {
			t.Errorf("isPublicRevocationIP(%s) = %t, want %t", test.ip, got, test.want)
		}
	}
}

func TestRevocationErrorsAreGeneric(t *testing.T) {
	if ErrCertificateRevoked == nil || ErrCertificateRevocationUnknown == nil ||
		errors.Is(ErrCertificateRevoked, ErrCertificateRevocationUnknown) {
		t.Fatal("revocation outcomes must be distinct generic errors")
	}
}

func TestBoundedRevocationBodyRejectsOversizedResponses(t *testing.T) {
	body := &boundedRevocationBody{ReadCloser: io.NopCloser(strings.NewReader("123456")), remaining: 5}
	if _, err := io.ReadAll(body); !errors.Is(err, ErrRevocationResponseTooLarge) {
		t.Fatalf("oversized response error = %v, want size-limit error", err)
	}

	exact := &boundedRevocationBody{ReadCloser: io.NopCloser(strings.NewReader("12345")), remaining: 5}
	content, err := io.ReadAll(exact)
	if err != nil || string(content) != "12345" {
		t.Fatalf("response exactly at the size bound = %q, %v", content, err)
	}
}
