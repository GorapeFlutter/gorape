package model

import (
	"time"

	"github.com/google/uuid"
)

// Attestation はデバイス鍵の検証結果記録
type Attestation struct {
	ID                 uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ProjectID          uuid.UUID `gorm:"type:uuid;not null;index" json:"project_id"`
	DeviceKeyID        uuid.UUID `gorm:"column:key_id;type:uuid;not null" json:"key_id"`
	AttestationType    string    `gorm:"not null" json:"attestation_type"`
	SecurityLevel      string    `gorm:"not null" json:"security_level"`
	VerificationStatus string    `gorm:"not null" json:"verification_status"`
	VerifierVersion    string    `gorm:"not null" json:"verifier_version"`
	VerifiedAt         time.Time `json:"verified_at"`
	EvidenceReference  string    `json:"evidence_reference,omitempty"`
}

func (Attestation) TableName() string { return "attestations" }
