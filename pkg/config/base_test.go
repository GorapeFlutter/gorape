package config

import "testing"

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
