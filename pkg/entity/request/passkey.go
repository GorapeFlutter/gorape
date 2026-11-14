package request

import "encoding/json"

// PasskeyRegistrationOptions starts a registration ceremony for a Gorape RP
// credential, separate from any Keycloak RP credential.
type PasskeyRegistrationOptions struct {
	Platform    string `json:"platform" binding:"required"`
	DisplayName string `json:"display_name" binding:"required"`
}

type PasskeyAuthenticationOptions struct {
	Platform string `json:"platform" binding:"required"`
}

// PasskeyRegistrationVerify carries the complete browser/platform
// PublicKeyCredential response. The server parses the attestationObject and
// does not trust client-supplied public keys or attestation claims.
type PasskeyRegistrationVerify struct {
	ChallengeID string          `json:"challenge_id" binding:"required"`
	Platform    string          `json:"platform" binding:"required"`
	DisplayName string          `json:"display_name" binding:"required"`
	Credential  json.RawMessage `json:"credential" binding:"required"`
}

// PasskeyAuthenticationVerify carries a WebAuthn assertion for a device.
type PasskeyAuthenticationVerify struct {
	ChallengeID string          `json:"challenge_id" binding:"required"`
	Credential  json.RawMessage `json:"credential" binding:"required"`
}

// BrowserPasskeyOptions and BrowserPasskeyVerify are short-lived, one-time
// portal capabilities. They are used only by Linux desktop's external-browser
// WebAuthn bridge; native and Web clients use the authenticated endpoints.
type BrowserPasskeyOptions struct {
	ChallengeID string `json:"challenge_id" binding:"required"`
}

type BrowserPasskeyRegistrationVerify struct {
	ChallengeID string          `json:"challenge_id" binding:"required"`
	Credential  json.RawMessage `json:"credential" binding:"required"`
}

type BrowserPasskeyAuthenticationVerify struct {
	ChallengeID string          `json:"challenge_id" binding:"required"`
	Credential  json.RawMessage `json:"credential" binding:"required"`
}
