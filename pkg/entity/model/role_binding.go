package model

import (
	"time"

	"github.com/google/uuid"
)

const (
	BindingScopeProject = "project"
	BindingScopeGroup   = "group"
)

// RoleBinding attaches a role definition to an identity principal, either at
// project scope or at a specific group scope.
type RoleBinding struct {
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	ProjectID   uuid.UUID  `gorm:"type:uuid;not null;index" json:"project_id"`
	PrincipalID uuid.UUID  `gorm:"type:uuid;not null;index" json:"principal_id"`
	Scope       string     `gorm:"not null" json:"scope"`
	GroupID     *uuid.UUID `gorm:"type:uuid" json:"group_id,omitempty"`
	RoleKey     string     `gorm:"not null" json:"role_key"`
	CreatedAt   time.Time  `json:"created_at"`
}

func (RoleBinding) TableName() string { return "role_bindings" }

func (rcvr RoleBinding) IsProjectScope() bool {
	return rcvr.Scope == BindingScopeProject
}
