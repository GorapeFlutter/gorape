package repository

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

var ErrUnsupportedAttestation = errors.New("attestation platform is unsupported")

type AttestationRequest struct {
	Platform     string
	Challenge    []byte
	PublicKeyPEM string
	Evidence     map[string]any
}
type AttestationResult struct {
	Type            string
	SecurityLevel   string
	Status          string
	VerifierVersion string
}
type AttestationVerifier interface {
	Verify(context.Context, AttestationRequest) (*AttestationResult, error)
}
type VerifierRegistry struct {
	items             map[string]AttestationVerifier
	androidConfigured bool
}

func NewVerifierRegistry(androidRoots []string) (*VerifierRegistry, error) {
	a, e := NewAndroidVerifier(androidRoots)
	if e != nil {
		return nil, e
	}
	return &VerifierRegistry{items: map[string]AttestationVerifier{"android": a}, androidConfigured: len(androidRoots) > 0}, nil
}
func (rcvr *VerifierRegistry) Verify(ctx context.Context, q AttestationRequest) (*AttestationResult, error) {
	v := rcvr.items[q.Platform]
	if v == nil {
		return nil, ErrUnsupportedAttestation
	}
	return v.Verify(ctx, q)
}
func (rcvr *VerifierRegistry) Capabilities() map[string]string {
	android := "unconfigured"
	if rcvr.androidConfigured {
		android = "implemented"
	}
	return map[string]string{"android": android, "windows": "unsupported", "ios": "unsupported", "macos": "unsupported"}
}

type AndroidVerifier struct{ roots *x509.CertPool }

func NewAndroidVerifier(files []string) (*AndroidVerifier, error) {
	p := x509.NewCertPool()
	for _, f := range files {
		b, e := os.ReadFile(f)
		if e != nil {
			return nil, fmt.Errorf("read Android trust anchor: %w", e)
		}
		if !p.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("no certificate in Android trust anchor %s", f)
		}
	}
	return &AndroidVerifier{roots: p}, nil
}

var androidKeyDescriptionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

type keyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	TEEEnforced              asn1.RawValue
}

func (rcvr *AndroidVerifier) Verify(_ context.Context, q AttestationRequest) (*AttestationResult, error) {
	if len(rcvr.roots.Subjects()) == 0 {
		return nil, errors.New("Android attestation trust anchors are not configured")
	}
	rawChain, ok := q.Evidence["certificate_chain"].([]any)
	if !ok || len(rawChain) < 2 {
		return nil, errors.New("Android certificate_chain must contain leaf and issuer certificates")
	}
	chain := make([]*x509.Certificate, 0, len(rawChain))
	for _, x := range rawChain {
		s, ok := x.(string)
		if !ok {
			return nil, errors.New("invalid certificate_chain entry")
		}
		c, e := parseCertificate(s)
		if e != nil {
			return nil, e
		}
		chain = append(chain, c)
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, e := chain[0].Verify(x509.VerifyOptions{Roots: rcvr.roots, Intermediates: inter, CurrentTime: time.Now()}); e != nil {
		return nil, fmt.Errorf("Android certificate chain: %w", e)
	}
	pubBlock, _ := pem.Decode([]byte(q.PublicKeyPEM))
	if pubBlock == nil {
		return nil, errors.New("public_key_pem is invalid")
	}
	pub, e := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if e != nil {
		return nil, e
	}
	expected, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		return nil, e
	}
	actual, e := x509.MarshalPKIXPublicKey(chain[0].PublicKey)
	if e != nil || !bytes.Equal(expected, actual) {
		return nil, errors.New("attested public key does not match submitted public key")
	}
	var kd keyDescription
	found := false
	for _, ext := range chain[0].Extensions {
		if ext.Id.Equal(androidKeyDescriptionOID) {
			if _, e := asn1.Unmarshal(ext.Value, &kd); e != nil {
				return nil, fmt.Errorf("Android key description: %w", e)
			}
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("Android key attestation extension is missing")
	}
	if !bytes.Equal(kd.AttestationChallenge, q.Challenge) {
		return nil, errors.New("Android attestation challenge mismatch")
	}
	level := "software"
	if kd.AttestationSecurityLevel == 1 {
		level = "trusted_environment"
	}
	if kd.AttestationSecurityLevel == 2 {
		level = "strongbox"
	}
	return &AttestationResult{Type: "android-key-attestation", SecurityLevel: level, Status: "verified", VerifierVersion: "gorape-android-v1"}, nil
}
func parseCertificate(s string) (*x509.Certificate, error) {
	if b, _ := pem.Decode([]byte(s)); b != nil {
		return x509.ParseCertificate(b.Bytes)
	}
	raw, e := base64.StdEncoding.DecodeString(s)
	if e != nil {
		return nil, errors.New("certificate must be PEM or base64 DER")
	}
	return x509.ParseCertificate(raw)
}
