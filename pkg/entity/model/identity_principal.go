package model

import (
	"time"

	"github.com/google/uuid"
)

// Principal はOIDC認証済みのアイデンティティ
type Principal struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ProjectID   uuid.UUID `gorm:"type:uuid;not null;index" json:"project_id"`
	OIDCIssuer  string    `gorm:"column:issuer;not null" json:"issuer"`
	OIDCSubject string    `gorm:"column:subject;not null" json:"subject"`
	CreatedAt   time.Time `json:"created_at"`
}

func (Principal) TableName() string { return "principals" }
