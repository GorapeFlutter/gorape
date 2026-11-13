package model

import (
	"time"

	"github.com/google/uuid"
)

// GroupRoleBinding はグループレベルのロール付与
type GroupRoleBinding struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ProjectID   uuid.UUID `gorm:"type:uuid;not null;index" json:"project_id"`
	GroupID     uuid.UUID `gorm:"type:uuid;not null" json:"group_id"`
	PrincipalID uuid.UUID `gorm:"type:uuid;not null" json:"principal_id"`
	Role        Role      `gorm:"not null" json:"role"`
	CreatedAt   time.Time `json:"created_at"`
}

func (GroupRoleBinding) TableName() string { return "group_role_bindings" }
