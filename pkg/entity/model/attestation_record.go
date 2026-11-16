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

// AssuranceEvidence is the server-verified evidence used to derive a
// credential assurance level. HardwareProtection must come from a verified
// attestation chain or authenticator metadata; it must never be inferred from
// the client-supplied platform name.
type AssuranceEvidence struct {
	Verified          bool
	SecurityLevel     string
	HardwareProtected bool
	BackupEligible    bool
	BackupState       bool
	MetadataVerified  bool
	RevocationChecked bool
	TrustSource       string
}

// GF-10038 — Resolves assurance from verified evidence, never from OS names.
//
// Rules:
//   - unverified evidence is rejected;
//   - a backup-eligible (synchronizable) credential is a standard passkey even
//     when the authenticator reports hardware-backed attestation;
//   - BE=false plus verified hardware protection is hardware_attested;
//   - BE=false without hardware proof is device_bound_unattested.
func ResolveAssurance(evidence AssuranceEvidence) string {
	if !evidence.Verified {
		return AssuranceLevelRejected
	}
	if evidence.BackupEligible {
		return AssuranceLevelStandardPasskey
	}
	if evidence.HardwareProtected {
		return AssuranceLevelHardwareAttested
	}
	return AssuranceLevelDeviceBoundUnattested
}

// ResolveAssuranceLevel is the legacy convenience form. Only security levels
// whose semantics prove non-exportable hardware key residency are treated as
// hardware-backed. In particular, packed attestation and "MDS verified" alone
// do not prove hardware protection.
func ResolveAssuranceLevel(securityLevel string, backupEligible bool, verified bool) string {
	return ResolveAssurance(AssuranceEvidence{
		Verified:          verified,
		SecurityLevel:     securityLevel,
		HardwareProtected: SecurityLevelProvesHardware(securityLevel),
		BackupEligible:    backupEligible,
	})
}

// SecurityLevelProvesHardware reports whether the named attestation security
// level is defined to prove hardware-protected, non-exportable key residency.
func SecurityLevelProvesHardware(securityLevel string) bool {
	switch securityLevel {
	case "strongbox",
		"trusted_environment",
		"tpm_attested",
		"android_key_attested",
		"apple_anonymous_attestation",
		"fido_u2f_attestation":
		return true
	default:
		return false
	}
}

// Attestation はデバイス鍵の検証結果記録
type Attestation struct {
	ID                 uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	ProjectID          uuid.UUID  `gorm:"type:uuid;not null;index" json:"project_id"`
	DeviceKeyID        uuid.UUID  `gorm:"column:key_id;type:uuid;not null" json:"key_id"`
	AAGUID             *uuid.UUID `gorm:"column:aaguid;type:uuid" json:"aaguid,omitempty"`
	AttestationType    string     `gorm:"not null" json:"attestation_type"`
	SecurityLevel      string     `gorm:"not null" json:"security_level"`
	AssuranceLevel     string     `gorm:"column:assurance_level" json:"assurance_level,omitempty"`
	HardwareProtected  bool       `gorm:"column:hardware_protected;not null" json:"hardware_protected"`
	BackupEligible     bool       `gorm:"column:backup_eligible;not null" json:"backup_eligible"`
	BackupState        bool       `gorm:"column:backup_state;not null" json:"backup_state"`
	TrustSource        string     `gorm:"column:trust_source;not null" json:"trust_source"`
	AttestationCert    []byte     `gorm:"column:attestation_certificate" json:"-"`
	VerificationStatus string     `gorm:"not null" json:"verification_status"`
	VerifierVersion    string     `gorm:"not null" json:"verifier_version"`
	VerifiedAt         time.Time  `json:"verified_at"`
	LastEvaluatedAt    *time.Time `gorm:"column:last_evaluated_at" json:"last_evaluated_at,omitempty"`
	EvidenceReference  string     `json:"evidence_reference,omitempty"`
}

// EffectiveAssuranceLevel returns the persisted level when present and derives
// it conservatively otherwise. It accepts the current credential backup flag so
// a synchronizable credential can never retain a hardware-attested level.
func (a Attestation) EffectiveAssuranceLevel(backupEligible bool) string {
	backupEligible = backupEligible || a.BackupEligible
	if ValidAssuranceLevel(a.AssuranceLevel) {
		if a.AssuranceLevel == AssuranceLevelRejected {
			return AssuranceLevelRejected
		}
		if backupEligible && a.AssuranceLevel == AssuranceLevelHardwareAttested {
			return AssuranceLevelStandardPasskey
		}
		return a.AssuranceLevel
	}
	if ValidAssuranceLevel(a.EvidenceReference) {
		return a.EvidenceReference
	}
	return ResolveAssurance(AssuranceEvidence{
		Verified:          a.VerificationStatus == "verified",
		SecurityLevel:     a.SecurityLevel,
		HardwareProtected: a.HardwareProtected,
		BackupEligible:    backupEligible,
		BackupState:       a.BackupState,
		TrustSource:       a.TrustSource,
	})
}

func (Attestation) TableName() string { return "attestations" }
