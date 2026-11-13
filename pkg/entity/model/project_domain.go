package model

import (
	"time"

	"github.com/google/uuid"
)

// ProjectDomain はビュー/クエリ用のプロジェクト集約ルート
type ProjectDomain struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Slug          string    `gorm:"uniqueIndex;not null" json:"slug"`
	Name          string    `gorm:"not null" json:"name"`
	OIDCIssuer    string    `gorm:"column:oidc_issuer;uniqueIndex;not null" json:"oidc_issuer"`
	KeycloakRealm string    `gorm:"not null" json:"keycloak_realm"`
	Status        string    `gorm:"not null" json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (ProjectDomain) TableName() string { return "project_domains" }
