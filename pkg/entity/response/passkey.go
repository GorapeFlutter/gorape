package response

import (
	"time"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/google/uuid"
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
	AssuranceLevel     string `json:"assurance_level"`
	HardwareProtected  bool   `json:"hardware_protected"`
	BackupEligible     bool   `json:"backup_eligible"`
	BackupState        bool   `json:"backup_state"`
	VerificationStatus string `json:"verification_status"`
	VerifierVersion    string `json:"verifier_version"`
}

type PasskeyRegistrationResult struct {
	Device      model.Device       `json:"device"`
	Attestation PasskeyAttestation `json:"attestation"`
}

// ProofRequestOptions is the GF-API-01 response for external service proof requests.
type ProofRequestOptions struct {
	ProofID          string         `json:"proof_id"`
	ExpiresAt        time.Time      `json:"expires_at"`
	PublicKeyOptions map[string]any `json:"public_key_options"`
}

// ProofRequestVerifyResult is the GF-API-02 response for verified assertions.
type ProofRequestVerifyResult struct {
	Verified       bool      `json:"verified"`
	PrincipalID    uuid.UUID `json:"principal_id"`
	DeviceID       uuid.UUID `json:"device_id"`
	CredentialID   string    `json:"credential_id"`
	AssuranceLevel string    `json:"assurance_level"`
	OperationID    string    `json:"operation_id"`
}
