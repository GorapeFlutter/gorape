package model

import (
	"time"

	"github.com/google/uuid"
)

// RoleDefinition is a project-scoped role that maps a stable role key to a set
// of fine-grained permissions.
//
// KeycloakRole is optional. When set, any access token containing that realm
// role (realm_access.roles) or client role (resource_access.*.roles) receives
// this role dynamically. When empty, the convention gorape-<key> is used.
type RoleDefinition struct {
	ID           uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	ProjectID    uuid.UUID      `gorm:"type:uuid;not null;index" json:"project_id"`
	Key          string         `gorm:"not null" json:"key"`
	Name         string         `gorm:"not null" json:"name"`
	Permissions  PermissionList `gorm:"type:jsonb;not null" json:"permissions"`
	KeycloakRole string         `json:"keycloak_role,omitempty"`
	Builtin      bool           `gorm:"not null" json:"builtin"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

func (RoleDefinition) TableName() string { return "role_definitions" }

func (rcvr RoleDefinition) EffectiveKeycloakRole() string {
	if rcvr.KeycloakRole != "" {
		return rcvr.KeycloakRole
	}
	return KeycloakRoleName(rcvr.Key)
}

// BuiltinRoleDefinition builds an in-memory definition for databases created
// before the role_definitions table existed. The migration seeds the same rows
// for normal deployments.
func BuiltinRoleDefinition(projectID uuid.UUID, key string) (RoleDefinition, bool) {
	perms, ok := BuiltinPermissions(key)
	if !ok {
		return RoleDefinition{}, false
	}
	return RoleDefinition{
		ProjectID:    projectID,
		Key:          key,
		Name:         key,
		Permissions:  PermissionList(perms),
		KeycloakRole: KeycloakRoleName(key),
		Builtin:      true,
	}, true
}
