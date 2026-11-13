package model

import (
	"time"

	"github.com/google/uuid"
)

type Device struct {
	ID               uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	ProjectID        uuid.UUID  `gorm:"type:uuid;not null;index" json:"project_id"`
	OwnerPrincipalID uuid.UUID  `gorm:"column:owner_id;type:uuid;not null" json:"owner_id"`
	Platform         string     `gorm:"not null" json:"platform"`
	DisplayName      string     `gorm:"not null" json:"display_name"`
	Status           string     `gorm:"not null" json:"status"`
	RegisteredAt     time.Time  `json:"registered_at"`
	LastVerifiedAt   *time.Time `json:"last_verified_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	Version          uint       `gorm:"not null" json:"version"`
}

func (Device) TableName() string { return "devices" }
