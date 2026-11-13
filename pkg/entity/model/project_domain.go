package model

import (
	"time"

	"github.com/google/uuid"
)

// Project はビュー/クエリ用のプロジェクト集約ルート
type Project struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Slug          string    `gorm:"uniqueIndex;not null" json:"slug"`
	Name          string    `gorm:"not null" json:"name"`
	OIDCIssuer    string    `gorm:"column:issuer;uniqueIndex;not null" json:"issuer"`
	KeycloakRealm string    `gorm:"column:realm;not null" json:"realm"`
	Status        string    `gorm:"not null" json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (Project) TableName() string { return "projects" }
