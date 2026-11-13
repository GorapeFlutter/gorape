package request

// RoleCreate is a role binding request. Role is a role definition key such as
// the built-in admin/editor/viewer, or a dynamically provisioned custom key.
type RoleCreate struct {
	OIDCSubject string `json:"subject" binding:"required"`
	Role        string `json:"role" binding:"required"`
}

// RoleDefinitionPut creates or replaces a project role definition.
type RoleDefinitionPut struct {
	Name         string   `json:"name"`
	Permissions  []string `json:"permissions" binding:"required"`
	KeycloakRole string   `json:"keycloak_role"`
}
