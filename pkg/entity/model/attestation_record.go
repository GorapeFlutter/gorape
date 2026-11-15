package model

import (
	"time"

	"github.com/google/uuid"
)

const (
	AssuranceLevelHardwareAttested      = "hardware_attested"
	AssuranceLevelDeviceBoundUnattested = "device_bound_unattested"
	AssuranceLevelStandardPasskey       = "standard_passkey"
	AssuranceLevelRejected              = "rejected"
)

func ValidAssuranceLevel(level string) bool {
	switch level {
	case AssuranceLevelHardwareAttested,
		AssuranceLevelDeviceBoundUnattested,
		AssuranceLevelStandardPasskey,
		AssuranceLevelRejected:
		return true
	default:
		return false
	}
}

func AssuranceRank(level string) int {
	switch level {
	case AssuranceLevelHardwareAttested:
		return 3
	case AssuranceLevelDeviceBoundUnattested:
		return 2
	case AssuranceLevelStandardPasskey:
		return 1
	default:
		return 0
	}
}

func AssuranceSatisfies(actual, required string) bool {
	if required == "" {
		required = AssuranceLevelStandardPasskey
	}
	if !ValidAssuranceLevel(actual) || !ValidAssuranceLevel(required) {
		return false
	}
	if actual == AssuranceLevelRejected || required == AssuranceLevelRejected {
		return false
	}
	return AssuranceRank(actual) >= AssuranceRank(required)
}

func ResolveAssuranceLevel(securityLevel string, backupEligible bool, verified bool) string {
	if !verified {
		return AssuranceLevelRejected
	}
	if backupEligible {
		return AssuranceLevelStandardPasskey
	}
	switch securityLevel {
	case "strongbox",
		"trusted_environment",
		"tpm_attested",
		"android_key_attested",
		"apple_anonymous_attestation",
		"fido_u2f_attestation",
		"packed_attestation",
		"fido_mds_verified":
		return AssuranceLevelHardwareAttested
	default:
		return AssuranceLevelDeviceBoundUnattested
	}
}

// Attestation はデバイス鍵の検証結果記録
type Attestation struct {
	ID                 uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ProjectID          uuid.UUID `gorm:"type:uuid;not null;index" json:"project_id"`
	DeviceKeyID        uuid.UUID `gorm:"column:key_id;type:uuid;not null" json:"key_id"`
	AttestationType    string    `gorm:"not null" json:"attestation_type"`
	SecurityLevel      string    `gorm:"not null" json:"security_level"`
	AssuranceLevel     string    `gorm:"-" json:"assurance_level,omitempty"`
	VerificationStatus string    `gorm:"not null" json:"verification_status"`
	VerifierVersion    string    `gorm:"not null" json:"verifier_version"`
	VerifiedAt         time.Time `json:"verified_at"`
	EvidenceReference  string    `json:"evidence_reference,omitempty"`
}

func (a Attestation) EffectiveAssuranceLevel(backupEligible bool) string {
	if ValidAssuranceLevel(a.AssuranceLevel) {
		return a.AssuranceLevel
	}
	if ValidAssuranceLevel(a.EvidenceReference) {
		return a.EvidenceReference
	}
	return ResolveAssuranceLevel(a.SecurityLevel, backupEligible, a.VerificationStatus == "verified")
}

func (Attestation) TableName() string { return "attestations" }
