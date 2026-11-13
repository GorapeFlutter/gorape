package model

import (
	"time"

	"github.com/google/uuid"
)

// IdentityPrincipal はOIDC認証済みのアイデンティティ
type IdentityPrincipal struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ProjectID   uuid.UUID `gorm:"type:uuid;not null;index" json:"project_id"`
	OIDCIssuer  string    `gorm:"column:oidc_issuer;not null" json:"oidc_issuer"`
	OIDCSubject string    `gorm:"column:oidc_subject;not null" json:"oidc_subject"`
	CreatedAt   time.Time `json:"created_at"`
}

func (IdentityPrincipal) TableName() string { return "identity_principals" }
