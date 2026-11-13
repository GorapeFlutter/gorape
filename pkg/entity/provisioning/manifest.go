// Package provisioning defines the declarative manifest shared by the Gorape
// server and the admin CLI. A single manifest can provision both Keycloak
// (realms, roles, groups, clients, authorization services) and Gorape
// (projects, role definitions, groups, role bindings).
package provisioning

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	APIVersion = "gorape/v1"
	Kind       = "Provisioning"
)

// Manifest is the top-level declarative provisioning document.
//
// Both sections are optional. Keycloak changes are applied through the
// Keycloak Admin REST API by the Gorape server; Gorape changes are applied
// transactionally to PostgreSQL. The CLI never talks to PostgreSQL or Keycloak
// directly.
type Manifest struct {
	APIVersion string        `json:"apiVersion" yaml:"apiVersion"`
	Kind       string        `json:"kind" yaml:"kind"`
	Keycloak   *KeycloakSpec `json:"keycloak,omitempty" yaml:"keycloak,omitempty"`
	Gorape     *GorapeSpec   `json:"gorape,omitempty" yaml:"gorape,omitempty"`
}

// Action describes one planned or applied mutation.
type Action struct {
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
	Name      string `json:"name"`
	Detail    string `json:"detail,omitempty"`
}

// Result is returned by plan and apply.
type Result struct {
	Applied   bool     `json:"applied"`
	ProjectID string   `json:"project_id,omitempty"`
	Actions   []Action `json:"actions"`
}

// KeycloakSpec declares identity-provider configuration.
type KeycloakSpec struct {
	Realm         string             `json:"realm" yaml:"realm"`
	CreateRealm   bool               `json:"create_realm,omitempty" yaml:"create_realm,omitempty"`
	RealmSettings *RealmSettingsSpec `json:"realm_settings,omitempty" yaml:"realm_settings,omitempty"`
	Roles         []RoleSpec         `json:"roles,omitempty" yaml:"roles,omitempty"`
	Groups        []GroupSpec        `json:"groups,omitempty" yaml:"groups,omitempty"`
	Clients       []ClientSpec       `json:"clients,omitempty" yaml:"clients,omitempty"`
	Authorization *AuthorizationSpec `json:"authorization,omitempty" yaml:"authorization,omitempty"`
}

type RealmSettingsSpec struct {
	DisplayName         string `json:"display_name,omitempty" yaml:"display_name,omitempty"`
	SSLRequired         string `json:"ssl_required,omitempty" yaml:"ssl_required,omitempty"`
	AccessTokenLifespan *int   `json:"access_token_lifespan,omitempty" yaml:"access_token_lifespan,omitempty"`
}

type RoleSpec struct {
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Composite   []string `json:"composite,omitempty" yaml:"composite,omitempty"`
}

type GroupSpec struct {
	Name       string              `json:"name" yaml:"name"`
	Path       string              `json:"path,omitempty" yaml:"path,omitempty"`
	Attributes map[string][]string `json:"attributes,omitempty" yaml:"attributes,omitempty"`
	RealmRoles []string            `json:"realm_roles,omitempty" yaml:"realm_roles,omitempty"`
	SubGroups  []GroupSpec         `json:"sub_groups,omitempty" yaml:"sub_groups,omitempty"`
}

type ProtocolMapperSpec struct {
	Name           string            `json:"name" yaml:"name"`
	Protocol       string            `json:"protocol" yaml:"protocol"`
	ProtocolMapper string            `json:"protocol_mapper" yaml:"protocol_mapper"`
	Config         map[string]string `json:"config,omitempty" yaml:"config,omitempty"`
}

type ClientSpec struct {
	ClientID                     string               `json:"client_id" yaml:"client_id"`
	Name                         string               `json:"name,omitempty" yaml:"name,omitempty"`
	Description                  string               `json:"description,omitempty" yaml:"description,omitempty"`
	Enabled                      *bool                `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	PublicClient                 *bool                `json:"public_client,omitempty" yaml:"public_client,omitempty"`
	BearerOnly                   *bool                `json:"bearer_only,omitempty" yaml:"bearer_only,omitempty"`
	StandardFlowEnabled          *bool                `json:"standard_flow_enabled,omitempty" yaml:"standard_flow_enabled,omitempty"`
	DirectAccessGrantsEnabled    *bool                `json:"direct_access_grants_enabled,omitempty" yaml:"direct_access_grants_enabled,omitempty"`
	ServiceAccountsEnabled       *bool                `json:"service_accounts_enabled,omitempty" yaml:"service_accounts_enabled,omitempty"`
	AuthorizationServicesEnabled *bool                `json:"authorization_services_enabled,omitempty" yaml:"authorization_services_enabled,omitempty"`
	Secret                       string               `json:"secret,omitempty" yaml:"secret,omitempty"`
	RedirectURIs                 []string             `json:"redirect_uris,omitempty" yaml:"redirect_uris,omitempty"`
	WebOrigins                   []string             `json:"web_origins,omitempty" yaml:"web_origins,omitempty"`
	Attributes                   map[string]string    `json:"attributes,omitempty" yaml:"attributes,omitempty"`
	ProtocolMappers              []ProtocolMapperSpec `json:"protocol_mappers,omitempty" yaml:"protocol_mappers,omitempty"`
}

type AuthorizationSpec struct {
	ClientID     string           `json:"client_id" yaml:"client_id"`
	Resources    []ResourceSpec   `json:"resources,omitempty" yaml:"resources,omitempty"`
	Scopes       []ScopeSpec      `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	RolePolicies []RolePolicySpec `json:"role_policies,omitempty" yaml:"role_policies,omitempty"`
	Permissions  []PermissionSpec `json:"permissions,omitempty" yaml:"permissions,omitempty"`
}

type ScopeSpec struct {
	Name        string `json:"name" yaml:"name"`
	DisplayName string `json:"display_name,omitempty" yaml:"display_name,omitempty"`
	IconURI     string `json:"icon_uri,omitempty" yaml:"icon_uri,omitempty"`
}

type ResourceSpec struct {
	Name               string            `json:"name" yaml:"name"`
	DisplayName        string            `json:"display_name,omitempty" yaml:"display_name,omitempty"`
	Type               string            `json:"type,omitempty" yaml:"type,omitempty"`
	OwnerManagedAccess bool              `json:"owner_managed_access,omitempty" yaml:"owner_managed_access,omitempty"`
	Attributes         map[string]string `json:"attributes,omitempty" yaml:"attributes,omitempty"`
	Scopes             []string          `json:"scopes,omitempty" yaml:"scopes,omitempty"`
}

type RolePolicySpec struct {
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Roles       []string `json:"roles" yaml:"roles"`
	Logic       string   `json:"logic,omitempty" yaml:"logic,omitempty"`
}

type PermissionSpec struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Type is "resource" (default) or "scope".
	Type             string   `json:"type,omitempty" yaml:"type,omitempty"`
	Resources        []string `json:"resources,omitempty" yaml:"resources,omitempty"`
	Scopes           []string `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	Policies         []string `json:"policies,omitempty" yaml:"policies,omitempty"`
	Logic            string   `json:"logic,omitempty" yaml:"logic,omitempty"`
	DecisionStrategy string   `json:"decision_strategy,omitempty" yaml:"decision_strategy,omitempty"`
}

// GorapeSpec declares Gorape project, role and binding configuration.
type GorapeSpec struct {
	Project  ProjectSpec   `json:"project" yaml:"project"`
	Roles    []RoleDefSpec `json:"roles,omitempty" yaml:"roles,omitempty"`
	Groups   []GorapeGroup `json:"groups,omitempty" yaml:"groups,omitempty"`
	Bindings []BindingSpec `json:"bindings,omitempty" yaml:"bindings,omitempty"`
}

type ProjectSpec struct {
	Slug   string `json:"slug" yaml:"slug"`
	Name   string `json:"name" yaml:"name"`
	Issuer string `json:"issuer" yaml:"issuer"`
	Realm  string `json:"realm,omitempty" yaml:"realm,omitempty"`
	Status string `json:"status,omitempty" yaml:"status,omitempty"`
}

type RoleDefSpec struct {
	Key          string   `json:"key" yaml:"key"`
	Name         string   `json:"name,omitempty" yaml:"name,omitempty"`
	Permissions  []string `json:"permissions" yaml:"permissions"`
	KeycloakRole string   `json:"keycloak_role,omitempty" yaml:"keycloak_role,omitempty"`
}

type GorapeGroup struct {
	Slug   string `json:"slug" yaml:"slug"`
	Name   string `json:"name,omitempty" yaml:"name,omitempty"`
	Status string `json:"status,omitempty" yaml:"status,omitempty"`
}

type BindingSpec struct {
	Subject string `json:"subject" yaml:"subject"`
	Scope   string `json:"scope,omitempty" yaml:"scope,omitempty"`
	Group   string `json:"group,omitempty" yaml:"group,omitempty"`
	Role    string `json:"role" yaml:"role"`
}

var (
	slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	rolePattern = regexp.MustCompile(`^[a-z][a-z0-9:_-]{0,62}$`)
)

// Validate checks manifest structure without contacting Keycloak or PostgreSQL.
func (rcvr Manifest) Validate() error {
	if rcvr.APIVersion != APIVersion {
		return fmt.Errorf("apiVersion must be %q", APIVersion)
	}
	if rcvr.Kind != Kind {
		return fmt.Errorf("kind must be %q", Kind)
	}
	if rcvr.Keycloak == nil && rcvr.Gorape == nil {
		return errors.New("manifest must contain keycloak and/or gorape")
	}
	if rcvr.Keycloak != nil {
		if rcvr.Keycloak.Realm == "" {
			return errors.New("keycloak.realm is required")
		}
		for _, r := range rcvr.Keycloak.Roles {
			if strings.TrimSpace(r.Name) == "" {
				return errors.New("keycloak role name is required")
			}
		}
		if a := rcvr.Keycloak.Authorization; a != nil {
			if a.ClientID == "" {
				return errors.New("keycloak.authorization.client_id is required")
			}
			for _, p := range a.Permissions {
				if p.Name == "" {
					return errors.New("keycloak authorization permission name is required")
				}
				if p.Type != "" && p.Type != "resource" && p.Type != "scope" {
					return fmt.Errorf("permission %q type must be resource or scope", p.Name)
				}
			}
		}
	}
	if rcvr.Gorape != nil {
		if !slugPattern.MatchString(rcvr.Gorape.Project.Slug) {
			return errors.New("gorape.project.slug must contain lowercase letters, numbers, and hyphens")
		}
		if rcvr.Gorape.Project.Issuer == "" {
			return errors.New("gorape.project.issuer is required")
		}
		for _, r := range rcvr.Gorape.Roles {
			if !rolePattern.MatchString(r.Key) {
				return fmt.Errorf("gorape role key %q is invalid", r.Key)
			}
			if len(r.Permissions) == 0 {
				return fmt.Errorf("gorape role %q must grant at least one permission", r.Key)
			}
		}
		for _, b := range rcvr.Gorape.Bindings {
			if b.Subject == "" || b.Role == "" {
				return errors.New("gorape binding subject and role are required")
			}
			if b.Scope != "" && b.Scope != "project" && b.Scope != "group" {
				return fmt.Errorf("binding scope must be project or group")
			}
			if b.Scope == "group" && b.Group == "" {
				return errors.New("group binding requires group")
			}
		}
	}
	return nil
}
