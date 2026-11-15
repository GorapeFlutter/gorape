package config

import (
	"testing"
	"time"
)

func TestWebAuthnConfigurationDefaultsAreStrict(t *testing.T) {
	config := finishConfig(YamlConfig{})
	server := config.YamlConfig.Application.Server
	if server.WebAuthn.RPDisplayName != "Gorape" {
		t.Fatalf("RP display name = %q, want Gorape", server.WebAuthn.RPDisplayName)
	}
	if server.WebAuthn.AttestationConveyance != "direct" {
		t.Fatalf("attestation conveyance = %q, want direct", server.WebAuthn.AttestationConveyance)
	}
	if server.WebAuthn.UserVerification != "required" {
		t.Fatalf("user verification = %q, want required", server.WebAuthn.UserVerification)
	}
	policy := server.Attestation.WebAuthn
	if len(policy.AllowedFormats) != 0 || policy.AllowNone || policy.AllowSelfAttestation {
		t.Fatalf("zero-value attestation policy must deny formats, none, and self-attestation: %+v", policy)
	}
	if policy.MDS.Enabled || server.Attestation.Revocation.Enabled {
		t.Fatal("external metadata/revocation fetches must remain opt-in by default")
	}
	if server.Attestation.Revocation.Timeout != 5*time.Second || server.Attestation.Revocation.CacheTTL != time.Minute {
		t.Fatalf("revocation defaults = %+v", server.Attestation.Revocation)
	}
	if server.AuthenticationAssurance.Enabled || server.AuthenticationAssurance.MaxAuthAge != 0 {
		t.Fatalf("authentication assurance must remain opt-in: %+v", server.AuthenticationAssurance)
	}
}

func TestAuthenticationAssuranceConfiguration(t *testing.T) {
	config := YamlConfig{}
	config.Application.Server.AuthenticationAssurance = AuthenticationAssuranceConfig{
		Enabled: true, RequiredACR: "gorape-passkey", MaxAuthAgeText: "3m",
	}
	server := finishConfig(config).YamlConfig.Application.Server
	if !server.AuthenticationAssurance.Enabled ||
		server.AuthenticationAssurance.RequiredACR != "gorape-passkey" ||
		server.AuthenticationAssurance.MaxAuthAge != 3*time.Minute {
		t.Fatalf("authentication assurance config = %+v", server.AuthenticationAssurance)
	}
}

func TestTLSConfigurationDefaultsAndEnvironmentOverrides(t *testing.T) {
	t.Setenv("GORAPE_TLS_CERT_FILE", "/run/secrets/server.crt")
	t.Setenv("GORAPE_TLS_KEY_FILE", "/run/secrets/server.key")

	config := finishConfig(YamlConfig{})
	server := config.YamlConfig.Application.Server
	if server.TLSPort != 8443 {
		t.Fatalf("TLS port = %d, want 8443", server.TLSPort)
	}
	if server.TLSCertFile != "/run/secrets/server.crt" || server.TLSKeyFile != "/run/secrets/server.key" {
		t.Fatalf("TLS files = %q, %q", server.TLSCertFile, server.TLSKeyFile)
	}
}
