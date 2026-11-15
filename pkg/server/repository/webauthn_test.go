package repository

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
)

func TestWebAuthnRPDefaultsToDeny(t *testing.T) {
	rp, err := NewWebAuthnRP(WebAuthnRPConfig{
		RPID: "gorape.example", RPDisplayName: "Gorape",
		RPOrigins: []string{"https://gorape.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = rp.RegistrationOptions(WebAuthnUser{
		ID: []byte("user-handle"), Name: "user", DisplayName: "Gorape user",
	})
	if !errors.Is(err, ErrAttestationPolicyDenied) {
		t.Fatalf("RegistrationOptions error = %v, want default-deny policy error", err)
	}
}

func TestWebAuthnRegistrationOptionsHonorConfiguredConveyance(t *testing.T) {
	rp, err := NewWebAuthnRP(WebAuthnRPConfig{
		RPID: "gorape.example", RPDisplayName: "Gorape",
		RPOrigins:             []string{"https://gorape.example"},
		AttestationConveyance: "direct", AllowNone: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	options, session, err := rp.RegistrationOptions(WebAuthnUser{
		ID: []byte("user-handle"), Name: "user", DisplayName: "Gorape user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options["attestation"] != "direct" {
		t.Fatalf("attestation preference = %v, want direct", options["attestation"])
	}
	if session.Challenge == "" {
		t.Fatal("registration session did not contain a challenge")
	}
}

func TestWebAuthnRPUsesConfiguredMDSProviderForTrustAndStatus(t *testing.T) {
	provider := &fidoMDSMetadataProvider{
		entries:   map[uuid.UUID]*metadata.Entry{},
		undesired: metadata.DefaultUndesiredAuthenticatorStatuses(),
	}
	rp, err := NewWebAuthnRP(WebAuthnRPConfig{
		RPID: "gorape.example", RPOrigins: []string{"https://gorape.example"},
		AllowedFormats: []string{"packed"}, MDS: provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rp.server.Config.MDS != provider {
		t.Fatal("WebAuthn library was not configured with the verified MDS provider")
	}
	if !rp.registrationPolicyEnabled() {
		t.Fatal("configured MDS provider and allowed format should enable registration options")
	}
}

func TestWebAuthnAttestationTrustPolicy(t *testing.T) {
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "WebAuthn Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	attestation := protocol.AttestationObject{
		Format:       "tpm",
		AttStatement: map[string]any{"x5c": []any{der}},
	}
	rp := &WebAuthnRP{
		allowed:    map[string]bool{"tpm": true},
		trustRoots: map[string]*x509.CertPool{"tpm": roots},
	}
	result, err := rp.verifyTrust(context.Background(), "tpm", attestation)
	if err != nil {
		t.Fatalf("trusted chain rejected: %v", err)
	}
	if result.SecurityLevel != "tpm_attested" {
		t.Fatalf("security level = %q, want tpm_attested", result.SecurityLevel)
	}

	rp.trustRoots = nil
	if _, err = rp.verifyTrust(context.Background(), "tpm", attestation); !errors.Is(err, ErrAttestationPolicyDenied) {
		t.Fatalf("missing roots error = %v, want default-deny policy error", err)
	}
}

func TestWebAuthnRejectsUnknownConfiguredFormats(t *testing.T) {
	_, err := NewWebAuthnRP(WebAuthnRPConfig{
		RPID: "gorape.example", RPOrigins: []string{"https://gorape.example"},
		AllowedFormats: []string{"unknown"},
	})
	if err == nil {
		t.Fatal("expected unknown attestation format to fail startup")
	}
}

func TestWebAuthnDoesNotIssueOptionsForFormatsWithoutTrust(t *testing.T) {
	rp, err := NewWebAuthnRP(WebAuthnRPConfig{
		RPID: "gorape.example", RPOrigins: []string{"https://gorape.example"},
		AllowedFormats: []string{"tpm"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = rp.RegistrationOptions(WebAuthnUser{ID: []byte("user"), Name: "user", DisplayName: "user"})
	if !errors.Is(err, ErrAttestationPolicyDenied) {
		t.Fatalf("RegistrationOptions error = %v, want trust-anchor policy error", err)
	}
}

func TestWebAuthnRPValidatesExactOriginsAndAndroidNativeOrigin(t *testing.T) {
	if err := validateRPIdentity("gorape.example", []string{
		"https://app.gorape.example",
		"android:apk-key-hash:ABCDEF",
	}); err != nil {
		t.Fatalf("valid browser/native origins rejected: %v", err)
	}
	for _, test := range []struct {
		name    string
		rpID    string
		origins []string
	}{
		{name: "wildcard", rpID: "gorape.example", origins: []string{"https://*.gorape.example"}},
		{name: "unrelated origin", rpID: "gorape.example", origins: []string{"https://attacker.example"}},
		{name: "public suffix RP ID", rpID: "com", origins: []string{"https://example.com"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateRPIdentity(test.rpID, test.origins); err == nil {
				t.Fatal("expected invalid RP/origin configuration to be rejected")
			}
		})
	}
}

func TestWebAuthnBrowserPortalMustBeAnAllowedRPOrigin(t *testing.T) {
	config := WebAuthnRPConfig{
		RPID: "gorape.example", RPOrigins: []string{"https://api.gorape.example"},
		PortalOrigin: "https://app.gorape.example", BrowserAPIOrigin: "https://api.gorape.example",
	}
	if _, err := NewWebAuthnRP(config); err == nil {
		t.Fatal("portal origin not in the WebAuthn RP origin allowlist was accepted")
	}

	config.RPOrigins = append(config.RPOrigins, config.PortalOrigin)
	rp, err := NewWebAuthnRP(config)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rp.BrowserPortalURL(), "https://app.gorape.example/passkey-ceremony.html"; got != want {
		t.Fatalf("BrowserPortalURL() = %q, want %q", got, want)
	}
	if !rp.BrowserPortalReady() {
		t.Fatal("configured portal and API origin should enable browser handoff")
	}
}

func TestWebAuthnAssuranceLevelClassification(t *testing.T) {
	rp := &WebAuthnRP{
		allowNone: true,
		allowSelf: true,
		allowed:   map[string]bool{"packed": true},
	}
	// fmt=none + BE=0 => device_bound_unattested
	res, err := rp.verifyTrust(context.Background(), "none", protocol.AttestationObject{
		Format:   "none",
		AuthData: protocol.AuthenticatorData{Flags: protocol.FlagUserPresent | protocol.FlagUserVerified},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.AssuranceLevel != model.AssuranceLevelDeviceBoundUnattested || res.HardwareProtected {
		t.Fatalf("BE=0 fmt=none got %+v, want device_bound_unattested", res)
	}

	// fmt=none + BE=1 => standard_passkey
	resSync, err := rp.verifyTrust(context.Background(), "none", protocol.AttestationObject{
		Format:   "none",
		AuthData: protocol.AuthenticatorData{Flags: protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagBackupEligible},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resSync.AssuranceLevel != model.AssuranceLevelStandardPasskey || resSync.HardwareProtected {
		t.Fatalf("BE=1 fmt=none got %+v, want standard_passkey", resSync)
	}

	// AssuranceSatisfies hierarchy check
	if !model.AssuranceSatisfies(model.AssuranceLevelHardwareAttested, model.AssuranceLevelHardwareAttested) {
		t.Fatal("hardware_attested must satisfy hardware_attested")
	}
	if model.AssuranceSatisfies(model.AssuranceLevelDeviceBoundUnattested, model.AssuranceLevelHardwareAttested) {
		t.Fatal("device_bound_unattested must not satisfy hardware_attested")
	}
	if model.AssuranceSatisfies(model.AssuranceLevelStandardPasskey, model.AssuranceLevelDeviceBoundUnattested) {
		t.Fatal("standard_passkey must not satisfy device_bound_unattested")
	}
}

func TestWebAuthnAndroidKeyRequiresHardwareTEEAndLockedBoot(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kd := androidPolicyDescription(t, true, 140000, 202601, 20260101, 20260101, make([]byte, 32))
	kdDER, err := asn1.Marshal(kd)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Android Key Leaf"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: androidKeyDescriptionOID, Value: kdDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyWebAuthnAndroidKeyLeaf(cert); err != nil {
		t.Fatalf("valid TEE android-key leaf rejected: %v", err)
	}

	// Software-level key must be rejected
	kdSoftware := kd
	kdSoftware.AttestationSecurityLevel = 0
	kdSoftware.KeymasterSecurityLevel = 0
	softDER, _ := asn1.Marshal(kdSoftware)
	template.ExtraExtensions = []pkix.Extension{{Id: androidKeyDescriptionOID, Value: softDER}}
	softCertDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	softCert, _ := x509.ParseCertificate(softCertDER)
	if err := verifyWebAuthnAndroidKeyLeaf(softCert); !errors.Is(err, ErrAttestationPolicyDenied) {
		t.Fatalf("software android-key leaf error = %v, want ErrAttestationPolicyDenied", err)
	}
}
