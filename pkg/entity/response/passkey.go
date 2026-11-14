package response

import (
	"time"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
)

type PasskeyCeremonyOptions struct {
	ChallengeID      string         `json:"challenge_id"`
	ExpiresAt        time.Time      `json:"expires_at"`
	PublicKey        map[string]any `json:"public_key"`
	BrowserURL       string         `json:"browser_url,omitempty"`
	BrowserAPIOrigin string         `json:"browser_api_origin,omitempty"`
}

type PasskeyBrowserOptions struct {
	Ceremony  string         `json:"ceremony"`
	PublicKey map[string]any `json:"public_key"`
}

type PasskeyAttestation struct {
	AttestationType    string `json:"attestation_type"`
	SecurityLevel      string `json:"security_level"`
	VerificationStatus string `json:"verification_status"`
	VerifierVersion    string `json:"verifier_version"`
}

type PasskeyRegistrationResult struct {
	Device      model.Device       `json:"device"`
	Attestation PasskeyAttestation `json:"attestation"`
}
