package model

import (
	"time"

	"github.com/google/uuid"
)

// ProjectRoleBinding はプロジェクトレベルのロール付与
type ProjectRoleBinding struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ProjectID   uuid.UUID `gorm:"type:uuid;not null;index" json:"project_id"`
	PrincipalID uuid.UUID `gorm:"type:uuid;not null" json:"principal_id"`
	Role        Role      `gorm:"not null" json:"role"`
	CreatedAt   time.Time `json:"created_at"`
}

func (ProjectRoleBinding) TableName() string { return "project_role_bindings" }
