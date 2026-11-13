package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/config"
	"github.com/Gorapeflutter/gorape/pkg/entity/provisioning"
	"github.com/google/uuid"
)

// KeycloakProvisioner applies declarative Keycloak configuration through the
// Admin REST API. It is invoked by the Gorape server, never by the CLI.
type KeycloakProvisioner interface {
	Plan(ctx context.Context, spec provisioning.KeycloakSpec) ([]provisioning.Action, error)
	Apply(ctx context.Context, spec provisioning.KeycloakSpec) ([]provisioning.Action, error)
}

type HTTPError struct {
	Method string
	URL    string
	Status int
	Body   string
}

func (rcvr *HTTPError) Error() string {
	return fmt.Sprintf("keycloak %s %s: HTTP %d: %s", rcvr.Method, rcvr.URL, rcvr.Status, strings.TrimSpace(rcvr.Body))
}

func isHTTPStatus(err error, status int) bool {
	var e *HTTPError
	return errors.As(err, &e) && e.Status == status
}

type KeycloakAdmin struct {
	cfg   config.KeycloakConfig
	http  *http.Client
	mu    sync.Mutex
	token string
	until time.Time
}

func NewKeycloakAdmin(cfg config.KeycloakConfig) (*KeycloakAdmin, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("keycloak.base_url is required")
	}
	if cfg.AdminRealm == "" {
		cfg.AdminRealm = cfg.AuthRealm
	}
	if cfg.AuthRealm == "" {
		cfg.AuthRealm = "master"
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "admin-cli"
	}
	if cfg.ClientSecret == "" && (cfg.Username == "" || cfg.Password == "") {
		return nil, errors.New("keycloak provisioning requires client_secret or username/password")
	}
	return &KeycloakAdmin{cfg: cfg, http: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (rcvr *KeycloakAdmin) Plan(ctx context.Context, spec provisioning.KeycloakSpec) ([]provisioning.Action, error) {
	return rcvr.apply(ctx, spec, true)
}

func (rcvr *KeycloakAdmin) Apply(ctx context.Context, spec provisioning.KeycloakSpec) ([]provisioning.Action, error) {
	return rcvr.apply(ctx, spec, false)
}

func (rcvr *KeycloakAdmin) apply(ctx context.Context, spec provisioning.KeycloakSpec, dry bool) ([]provisioning.Action, error) {
	realm := spec.Realm
	if realm == "" {
		realm = rcvr.cfg.AdminRealm
	}
	actions := make([]provisioning.Action, 0, 32)

	if e := rcvr.ensureRealm(ctx, spec, dry, &actions); e != nil {
		return nil, e
	}
	for _, role := range spec.Roles {
		if e := rcvr.ensureRole(ctx, realm, role, dry, &actions); e != nil {
			return nil, e
		}
	}
	for _, group := range spec.Groups {
		if e := rcvr.ensureGroup(ctx, realm, "", group, dry, false, &actions); e != nil {
			return nil, e
		}
	}
	for _, client := range spec.Clients {
		if _, e := rcvr.ensureClient(ctx, realm, client, dry, &actions); e != nil {
			return nil, e
		}
	}
	if authz := spec.Authorization; authz != nil {
		if e := rcvr.ensureAuthorization(ctx, realm, *authz, dry, &actions); e != nil {
			return nil, e
		}
	}
	return actions, nil
}

func (rcvr *KeycloakAdmin) ensureRealm(ctx context.Context, spec provisioning.KeycloakSpec, dry bool, actions *[]provisioning.Action) error {
	realm := spec.Realm
	if realm == "" {
		realm = rcvr.cfg.AdminRealm
	}
	var existing map[string]any
	e := rcvr.request(ctx, http.MethodGet, rcvr.serverURL("/admin/realms/"+url.PathEscape(realm)), nil, &existing)
	if e != nil {
		if !isHTTPStatus(e, http.StatusNotFound) {
			return e
		}
		if !spec.CreateRealm {
			return fmt.Errorf("keycloak realm %q does not exist (set create_realm to create it)", realm)
		}
		body := map[string]any{"realm": realm, "enabled": true}
		*actions = append(*actions, provisioning.Action{Operation: "create", Resource: "keycloak.realm", Name: realm})
		if !dry {
			if e := rcvr.request(ctx, http.MethodPost, rcvr.serverURL("/admin/realms"), body, nil); e != nil {
				return e
			}
		}
		return rcvr.applyRealmSettings(ctx, realm, spec.RealmSettings, dry, actions)
	}
	return rcvr.applyRealmSettings(ctx, realm, spec.RealmSettings, dry, actions)
}

// applyRealmSettings updates optional realm attributes after a realm has been
// created or discovered. Keeping it separate ensures create_realm manifests
// also apply their realm_settings instead of silently dropping them.
func (rcvr *KeycloakAdmin) applyRealmSettings(ctx context.Context, realm string, spec *provisioning.RealmSettingsSpec, dry bool, actions *[]provisioning.Action) error {
	if spec == nil {
		return nil
	}
	body := map[string]any{}
	if spec.DisplayName != "" {
		body["displayName"] = spec.DisplayName
	}
	if spec.SSLRequired != "" {
		body["sslRequired"] = spec.SSLRequired
	}
	if spec.AccessTokenLifespan != nil {
		body["accessTokenLifespan"] = *spec.AccessTokenLifespan
	}
	if len(body) == 0 {
		return nil
	}
	*actions = append(*actions, provisioning.Action{Operation: "update", Resource: "keycloak.realm", Name: realm})
	if dry {
		return nil
	}
	return rcvr.request(ctx, http.MethodPut, rcvr.serverURL("/admin/realms/"+url.PathEscape(realm)), body, nil)
}

func (rcvr *KeycloakAdmin) ensureRole(ctx context.Context, realm string, spec provisioning.RoleSpec, dry bool, actions *[]provisioning.Action) error {
	if spec.Name == "" {
		return errors.New("keycloak role name is required")
	}
	body := map[string]any{"name": spec.Name, "description": spec.Description}
	var existing map[string]any
	e := rcvr.request(ctx, http.MethodGet, rcvr.adminURL(realm, "/roles/"+url.PathEscape(spec.Name)), nil, &existing)
	exists := e == nil
	if e != nil && !isHTTPStatus(e, http.StatusNotFound) {
		return e
	}
	if exists {
		*actions = append(*actions, provisioning.Action{Operation: "update", Resource: "keycloak.role", Name: spec.Name})
		if !dry {
			if e := rcvr.request(ctx, http.MethodPut, rcvr.adminURL(realm, "/roles/"+url.PathEscape(spec.Name)), body, nil); e != nil {
				return e
			}
		}
	} else {
		*actions = append(*actions, provisioning.Action{Operation: "create", Resource: "keycloak.role", Name: spec.Name})
		if !dry {
			if e := rcvr.request(ctx, http.MethodPost, rcvr.adminURL(realm, "/roles"), body, nil); e != nil {
				return e
			}
		}
	}
	if len(spec.Composite) > 0 {
		reps := make([]map[string]any, 0, len(spec.Composite))
		for _, name := range spec.Composite {
			if name == "" || name == spec.Name {
				continue
			}
			var role map[string]any
			if e := rcvr.request(ctx, http.MethodGet, rcvr.adminURL(realm, "/roles/"+url.PathEscape(name)), nil, &role); e != nil {
				return fmt.Errorf("composite role %q: %w", name, e)
			}
			reps = append(reps, role)
		}
		if len(reps) > 0 {
			*actions = append(*actions, provisioning.Action{Operation: "update", Resource: "keycloak.role_composite", Name: spec.Name})
			if !dry {
				if e := rcvr.request(ctx, http.MethodPost, rcvr.adminURL(realm, "/roles/"+url.PathEscape(spec.Name)+"/composites"), reps, nil); e != nil {
					return e
				}
			}
		}
	}
	return nil
}

func (rcvr *KeycloakAdmin) ensureGroup(ctx context.Context, realm, parentID string, spec provisioning.GroupSpec, dry, parentMissing bool, actions *[]provisioning.Action) error {
	name := spec.Name
	if name == "" && spec.Path != "" {
		parts := strings.Split(strings.Trim(spec.Path, "/"), "/")
		name = parts[len(parts)-1]
	}
	if name == "" {
		return errors.New("keycloak group name is required")
	}
	parentPath := "/groups"
	if parentID != "" {
		parentPath = "/groups/" + url.PathEscape(parentID) + "/children"
	}

	var (
		groupID string
		exists  bool
	)
	if parentMissing {
		// A parent that does not exist cannot have children. This happens
		// during plan for a brand-new nested group tree, where querying
		// /groups/<new-id>/children would return 404.
		groupID = uuid.NewString()
	} else {
		var e error
		groupID, exists, e = rcvr.findGroup(ctx, realm, parentID, name)
		if e != nil {
			return e
		}
	}
	if exists {
		*actions = append(*actions, provisioning.Action{Operation: "update", Resource: "keycloak.group", Name: name})
		if !dry {
			body := map[string]any{"name": name}
			if spec.Attributes != nil {
				body["attributes"] = spec.Attributes
			}
			if e := rcvr.request(ctx, http.MethodPut, rcvr.adminURL(realm, "/groups/"+url.PathEscape(groupID)), body, nil); e != nil {
				return e
			}
		}
	} else {
		*actions = append(*actions, provisioning.Action{Operation: "create", Resource: "keycloak.group", Name: name})
		if !dry {
			attributes := spec.Attributes
			if attributes == nil {
				attributes = map[string][]string{}
			}
			body := map[string]any{"name": name, "attributes": attributes}
			var created struct {
				ID string `json:"id"`
			}
			if e := rcvr.request(ctx, http.MethodPost, rcvr.adminURL(realm, parentPath), body, &created); e != nil {
				return e
			}
			groupID = created.ID
			if groupID == "" {
				var found bool
				g, found, e := rcvr.findGroup(ctx, realm, parentID, name)
				if e != nil {
					return e
				}
				groupID = g
				_ = found
				if !found {
					return fmt.Errorf("keycloak group %q was created but not found", name)
				}
			}
		}
	}
	if len(spec.RealmRoles) > 0 && !dry {
		roles := make([]map[string]any, 0, len(spec.RealmRoles))
		for _, roleName := range spec.RealmRoles {
			var role map[string]any
			if e := rcvr.request(ctx, http.MethodGet, rcvr.adminURL(realm, "/roles/"+url.PathEscape(roleName)), nil, &role); e != nil {
				return e
			}
			roles = append(roles, role)
		}
		if e := rcvr.request(ctx, http.MethodPost, rcvr.adminURL(realm, "/groups/"+url.PathEscape(groupID)+"/role-mappings/realm"), roles, nil); e != nil {
			return e
		}
		*actions = append(*actions, provisioning.Action{Operation: "update", Resource: "keycloak.group_roles", Name: name})
	}
	childParentMissing := parentMissing || (dry && !exists)
	for _, child := range spec.SubGroups {
		if e := rcvr.ensureGroup(ctx, realm, groupID, child, dry, childParentMissing, actions); e != nil {
			return e
		}
	}
	return nil
}

func (rcvr *KeycloakAdmin) findGroup(ctx context.Context, realm, parentID, name string) (string, bool, error) {
	path := "/groups?briefRepresentation=false&max=1000"
	if parentID != "" {
		path = "/groups/" + url.PathEscape(parentID) + "/children?briefRepresentation=false&max=1000"
	}
	var groups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if e := rcvr.request(ctx, http.MethodGet, rcvr.adminURL(realm, path), nil, &groups); e != nil {
		return "", false, e
	}
	for _, g := range groups {
		if g.Name == name {
			return g.ID, true, nil
		}
	}
	return "", false, nil
}

func (rcvr *KeycloakAdmin) ensureClient(ctx context.Context, realm string, spec provisioning.ClientSpec, dry bool, actions *[]provisioning.Action) (string, error) {
	if spec.ClientID == "" {
		return "", errors.New("keycloak client_id is required")
	}
	existing, err := rcvr.findClient(ctx, realm, spec.ClientID)
	if err != nil {
		return "", err
	}
	body := map[string]any{"clientId": spec.ClientID}
	if spec.Name != "" {
		body["name"] = spec.Name
	}
	if spec.Description != "" {
		body["description"] = spec.Description
	}
	if spec.Enabled != nil {
		body["enabled"] = *spec.Enabled
	}
	if spec.PublicClient != nil {
		body["publicClient"] = *spec.PublicClient
	}
	if spec.BearerOnly != nil {
		body["bearerOnly"] = *spec.BearerOnly
	}
	if spec.StandardFlowEnabled != nil {
		body["standardFlowEnabled"] = *spec.StandardFlowEnabled
	}
	if spec.DirectAccessGrantsEnabled != nil {
		body["directAccessGrantsEnabled"] = *spec.DirectAccessGrantsEnabled
	}
	if spec.ServiceAccountsEnabled != nil {
		body["serviceAccountsEnabled"] = *spec.ServiceAccountsEnabled
	}
	if spec.AuthorizationServicesEnabled != nil {
		body["authorizationServicesEnabled"] = *spec.AuthorizationServicesEnabled
	}
	if spec.Secret != "" {
		body["secret"] = spec.Secret
	}
	if spec.RedirectURIs != nil {
		body["redirectUris"] = spec.RedirectURIs
	}
	if spec.WebOrigins != nil {
		body["webOrigins"] = spec.WebOrigins
	}
	if spec.Attributes != nil {
		body["attributes"] = spec.Attributes
	}

	clientID := ""
	if existing != nil {
		clientID, _ = existing["id"].(string)
		*actions = append(*actions, provisioning.Action{Operation: "update", Resource: "keycloak.client", Name: spec.ClientID})
		if !dry {
			if e := rcvr.request(ctx, http.MethodPut, rcvr.adminURL(realm, "/clients/"+url.PathEscape(clientID)), body, nil); e != nil {
				return "", e
			}
		}
	} else {
		*actions = append(*actions, provisioning.Action{Operation: "create", Resource: "keycloak.client", Name: spec.ClientID})
		if dry {
			clientID = uuid.NewString()
		} else {
			if e := rcvr.request(ctx, http.MethodPost, rcvr.adminURL(realm, "/clients"), body, nil); e != nil {
				return "", e
			}
			found, e := rcvr.findClient(ctx, realm, spec.ClientID)
			if e != nil || found == nil {
				return "", fmt.Errorf("keycloak client %q was created but not found", spec.ClientID)
			}
			clientID, _ = found["id"].(string)
		}
	}
	for _, mapper := range spec.ProtocolMappers {
		if e := rcvr.ensureProtocolMapper(ctx, realm, clientID, mapper, dry, actions); e != nil {
			return "", e
		}
	}
	return clientID, nil
}

func (rcvr *KeycloakAdmin) findClient(ctx context.Context, realm, clientID string) (map[string]any, error) {
	var clients []map[string]any
	q := url.Values{"clientId": {clientID}, "search": {"true"}}
	if e := rcvr.request(ctx, http.MethodGet, rcvr.adminURL(realm, "/clients?"+q.Encode()), nil, &clients); e != nil {
		return nil, e
	}
	for _, c := range clients {
		if c["clientId"] == clientID {
			return c, nil
		}
	}
	return nil, nil
}

func (rcvr *KeycloakAdmin) ensureProtocolMapper(ctx context.Context, realm, clientID string, spec provisioning.ProtocolMapperSpec, dry bool, actions *[]provisioning.Action) error {
	if spec.Name == "" || spec.ProtocolMapper == "" {
		return errors.New("protocol mapper name and protocol_mapper are required")
	}
	protocol := spec.Protocol
	if protocol == "" {
		protocol = "openid-connect"
	}
	var mappers []map[string]any
	if e := rcvr.request(ctx, http.MethodGet, rcvr.adminURL(realm, "/clients/"+url.PathEscape(clientID)+"/protocol-mappers/models"), nil, &mappers); e != nil {
		return e
	}
	body := map[string]any{
		"name":           spec.Name,
		"protocol":       protocol,
		"protocolMapper": spec.ProtocolMapper,
		"config":         spec.Config,
	}
	for _, m := range mappers {
		if m["name"] == spec.Name {
			id, _ := m["id"].(string)
			*actions = append(*actions, provisioning.Action{Operation: "update", Resource: "keycloak.protocol_mapper", Name: spec.Name})
			if !dry {
				return rcvr.request(ctx, http.MethodPut, rcvr.adminURL(realm, "/clients/"+url.PathEscape(clientID)+"/protocol-mappers/models/"+url.PathEscape(id)), body, nil)
			}
			return nil
		}
	}
	*actions = append(*actions, provisioning.Action{Operation: "create", Resource: "keycloak.protocol_mapper", Name: spec.Name})
	if dry {
		return nil
	}
	return rcvr.request(ctx, http.MethodPost, rcvr.adminURL(realm, "/clients/"+url.PathEscape(clientID)+"/protocol-mappers/models"), body, nil)
}

func (rcvr *KeycloakAdmin) ensureAuthorization(ctx context.Context, realm string, spec provisioning.AuthorizationSpec, dry bool, actions *[]provisioning.Action) error {
	client, err := rcvr.findClient(ctx, realm, spec.ClientID)
	if err != nil {
		return err
	}
	if client == nil {
		return fmt.Errorf("keycloak client %q not found for authorization", spec.ClientID)
	}
	clientID, _ := client["id"].(string)
	base := "/clients/" + url.PathEscape(clientID) + "/authz/resource-server"

	*actions = append(*actions, provisioning.Action{Operation: "update", Resource: "keycloak.authorization", Name: spec.ClientID})
	if !dry {
		settings := map[string]any{
			"allowRemoteResourceManagement": true,
			"policyEnforcementMode":         "PERMISSIVE",
			"decisionStrategy":              "UNANIMOUS",
		}
		if e := rcvr.request(ctx, http.MethodPut, rcvr.adminURL(realm, base), settings, nil); e != nil && !isHTTPStatus(e, http.StatusConflict) {
			return e
		}
	}

	scopeIDs, err := rcvr.ensureAuthzScopes(ctx, realm, base, spec.Scopes, dry, actions)
	if err != nil {
		return err
	}
	resourceIDs, err := rcvr.ensureAuthzResources(ctx, realm, base, spec.Resources, scopeIDs, dry, actions)
	if err != nil {
		return err
	}
	policyIDs, err := rcvr.ensureAuthzRolePolicies(ctx, realm, base, spec.RolePolicies, dry, actions)
	if err != nil {
		return err
	}
	return rcvr.ensureAuthzPermissions(ctx, realm, base, spec.Permissions, resourceIDs, scopeIDs, policyIDs, dry, actions)
}

func (rcvr *KeycloakAdmin) ensureAuthzScopes(ctx context.Context, realm, base string, specs []provisioning.ScopeSpec, dry bool, actions *[]provisioning.Action) (map[string]string, error) {
	ids := map[string]string{}
	var existing []map[string]any
	if e := rcvr.request(ctx, http.MethodGet, rcvr.adminURL(realm, base+"/scope?first=0&max=1000"), nil, &existing); e != nil {
		return nil, e
	}
	byName := map[string]string{}
	for _, v := range existing {
		name, _ := v["name"].(string)
		id, _ := v["id"].(string)
		byName[name] = id
	}
	for _, s := range specs {
		body := map[string]any{"name": s.Name, "displayName": s.DisplayName, "iconUri": s.IconURI}
		if id, ok := byName[s.Name]; ok {
			*actions = append(*actions, provisioning.Action{Operation: "update", Resource: "keycloak.scope", Name: s.Name})
			if !dry {
				if e := rcvr.request(ctx, http.MethodPut, rcvr.adminURL(realm, base+"/scope/"+url.PathEscape(id)), body, nil); e != nil {
					return nil, e
				}
			}
			ids[s.Name] = id
			continue
		}
		*actions = append(*actions, provisioning.Action{Operation: "create", Resource: "keycloak.scope", Name: s.Name})
		if dry {
			ids[s.Name] = uuid.NewString()
			continue
		}
		var created struct {
			ID string `json:"id"`
		}
		if e := rcvr.request(ctx, http.MethodPost, rcvr.adminURL(realm, base+"/scope"), body, &created); e != nil {
			return nil, e
		}
		ids[s.Name] = created.ID
	}
	return ids, nil
}

func (rcvr *KeycloakAdmin) ensureAuthzResources(ctx context.Context, realm, base string, specs []provisioning.ResourceSpec, scopeIDs map[string]string, dry bool, actions *[]provisioning.Action) (map[string]string, error) {
	ids := map[string]string{}
	var existing []map[string]any
	if e := rcvr.request(ctx, http.MethodGet, rcvr.adminURL(realm, base+"/resource?first=0&max=1000"), nil, &existing); e != nil {
		return nil, e
	}
	byName := map[string]string{}
	for _, v := range existing {
		name, _ := v["name"].(string)
		id, _ := v["id"].(string)
		byName[name] = id
	}
	for _, r := range specs {
		scopes := make([]map[string]any, 0, len(r.Scopes))
		for _, name := range r.Scopes {
			id, ok := scopeIDs[name]
			if !ok {
				return nil, fmt.Errorf("resource %q references unknown scope %q", r.Name, name)
			}
			scopes = append(scopes, map[string]any{"id": id, "name": name})
		}
		body := map[string]any{
			"name":               r.Name,
			"displayName":        r.DisplayName,
			"type":               r.Type,
			"ownerManagedAccess": r.OwnerManagedAccess,
			"attributes":         r.Attributes,
			"scopes":             scopes,
		}
		if id, ok := byName[r.Name]; ok {
			*actions = append(*actions, provisioning.Action{Operation: "update", Resource: "keycloak.resource", Name: r.Name})
			if !dry {
				if e := rcvr.request(ctx, http.MethodPut, rcvr.adminURL(realm, base+"/resource/"+url.PathEscape(id)), body, nil); e != nil {
					return nil, e
				}
			}
			ids[r.Name] = id
			continue
		}
		*actions = append(*actions, provisioning.Action{Operation: "create", Resource: "keycloak.resource", Name: r.Name})
		if dry {
			ids[r.Name] = uuid.NewString()
			continue
		}
		var created struct {
			ID string `json:"id"`
		}
		if e := rcvr.request(ctx, http.MethodPost, rcvr.adminURL(realm, base+"/resource"), body, &created); e != nil {
			return nil, e
		}
		ids[r.Name] = created.ID
	}
	return ids, nil
}

func (rcvr *KeycloakAdmin) ensureAuthzRolePolicies(ctx context.Context, realm, base string, specs []provisioning.RolePolicySpec, dry bool, actions *[]provisioning.Action) (map[string]string, error) {
	ids := map[string]string{}
	var existing []map[string]any
	if e := rcvr.request(ctx, http.MethodGet, rcvr.adminURL(realm, base+"/policy?first=0&max=1000"), nil, &existing); e != nil {
		return nil, e
	}
	byName := map[string]string{}
	for _, v := range existing {
		name, _ := v["name"].(string)
		id, _ := v["id"].(string)
		byName[name] = id
	}
	for _, p := range specs {
		roles := make([]map[string]any, 0, len(p.Roles))
		for _, name := range p.Roles {
			var role map[string]any
			if e := rcvr.request(ctx, http.MethodGet, rcvr.adminURL(realm, "/roles/"+url.PathEscape(name)), nil, &role); e != nil {
				return nil, fmt.Errorf("role policy %q role %q: %w", p.Name, name, e)
			}
			roles = append(roles, map[string]any{"id": role["id"], "required": false})
		}
		rolesJSON, _ := json.Marshal(roles)
		logic := p.Logic
		if logic == "" {
			logic = "POSITIVE"
		}
		body := map[string]any{
			"name":        p.Name,
			"description": p.Description,
			"type":        "role",
			"logic":       logic,
			"config":      map[string]any{"roles": string(rolesJSON)},
		}
		if id, ok := byName[p.Name]; ok {
			*actions = append(*actions, provisioning.Action{Operation: "update", Resource: "keycloak.role_policy", Name: p.Name})
			if !dry {
				if e := rcvr.request(ctx, http.MethodPut, rcvr.adminURL(realm, base+"/policy/role/"+url.PathEscape(id)), body, nil); e != nil {
					return nil, e
				}
			}
			ids[p.Name] = id
			continue
		}
		*actions = append(*actions, provisioning.Action{Operation: "create", Resource: "keycloak.role_policy", Name: p.Name})
		if dry {
			ids[p.Name] = uuid.NewString()
			continue
		}
		var created struct {
			ID string `json:"id"`
		}
		if e := rcvr.request(ctx, http.MethodPost, rcvr.adminURL(realm, base+"/policy/role"), body, &created); e != nil {
			return nil, e
		}
		ids[p.Name] = created.ID
	}
	return ids, nil
}

func (rcvr *KeycloakAdmin) ensureAuthzPermissions(ctx context.Context, realm, base string, specs []provisioning.PermissionSpec, resourceIDs, scopeIDs, policyIDs map[string]string, dry bool, actions *[]provisioning.Action) error {
	var existing []map[string]any
	if e := rcvr.request(ctx, http.MethodGet, rcvr.adminURL(realm, base+"/permission?first=0&max=1000"), nil, &existing); e != nil {
		return e
	}
	byName := map[string]string{}
	for _, v := range existing {
		name, _ := v["name"].(string)
		id, _ := v["id"].(string)
		byName[name] = id
	}
	for _, p := range specs {
		permissionType := p.Type
		if permissionType == "" {
			permissionType = "resource"
		}
		resources := make([]string, 0, len(p.Resources))
		for _, name := range p.Resources {
			id, ok := resourceIDs[name]
			if !ok {
				return fmt.Errorf("permission %q references unknown resource %q", p.Name, name)
			}
			resources = append(resources, id)
		}
		scopes := make([]string, 0, len(p.Scopes))
		for _, name := range p.Scopes {
			id, ok := scopeIDs[name]
			if !ok {
				return fmt.Errorf("permission %q references unknown scope %q", p.Name, name)
			}
			scopes = append(scopes, id)
		}
		policies := make([]string, 0, len(p.Policies))
		for _, name := range p.Policies {
			id, ok := policyIDs[name]
			if !ok {
				return fmt.Errorf("permission %q references unknown policy %q", p.Name, name)
			}
			policies = append(policies, id)
		}
		logic := p.Logic
		if logic == "" {
			logic = "POSITIVE"
		}
		decision := p.DecisionStrategy
		if decision == "" {
			decision = "UNANIMOUS"
		}
		body := map[string]any{
			"name":             p.Name,
			"description":      p.Description,
			"type":             permissionType,
			"logic":            logic,
			"decisionStrategy": decision,
			"resources":        resources,
			"policies":         policies,
			"scopes":           scopes,
		}
		updatePath := base + "/permission/" + permissionType + "/"
		createPath := base + "/permission/" + permissionType
		if id, ok := byName[p.Name]; ok {
			*actions = append(*actions, provisioning.Action{Operation: "update", Resource: "keycloak.permission", Name: p.Name})
			if !dry {
				if e := rcvr.request(ctx, http.MethodPut, rcvr.adminURL(realm, updatePath+url.PathEscape(id)), body, nil); e != nil {
					return e
				}
			}
			continue
		}
		*actions = append(*actions, provisioning.Action{Operation: "create", Resource: "keycloak.permission", Name: p.Name})
		if !dry {
			if e := rcvr.request(ctx, http.MethodPost, rcvr.adminURL(realm, createPath), body, nil); e != nil {
				return e
			}
		}
	}
	return nil
}

func (rcvr *KeycloakAdmin) adminURL(realm, path string) string {
	return rcvr.serverURL("/admin/realms/" + url.PathEscape(realm) + path)
}

func (rcvr *KeycloakAdmin) serverURL(path string) string {
	return strings.TrimRight(rcvr.cfg.BaseURL, "/") + path
}

func (rcvr *KeycloakAdmin) accessToken(ctx context.Context) (string, error) {
	rcvr.mu.Lock()
	defer rcvr.mu.Unlock()
	if rcvr.token != "" && time.Now().Before(rcvr.until.Add(-30*time.Second)) {
		return rcvr.token, nil
	}
	form := url.Values{}
	if rcvr.cfg.ClientSecret != "" {
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", rcvr.cfg.ClientID)
		form.Set("client_secret", rcvr.cfg.ClientSecret)
	} else {
		form.Set("grant_type", "password")
		form.Set("client_id", rcvr.cfg.ClientID)
		form.Set("username", rcvr.cfg.Username)
		form.Set("password", rcvr.cfg.Password)
	}
	tokenURL := rcvr.serverURL("/realms/" + url.PathEscape(rcvr.cfg.AuthRealm) + "/protocol/openid-connect/token")
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if e != nil {
		return "", e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, e := rcvr.http.Do(req)
	if e != nil {
		return "", e
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &HTTPError{Method: http.MethodPost, URL: tokenURL, Status: resp.StatusCode, Body: string(raw)}
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if e := json.Unmarshal(raw, &out); e != nil {
		return "", e
	}
	if out.AccessToken == "" {
		return "", errors.New("keycloak token endpoint returned no access token")
	}
	rcvr.token = out.AccessToken
	if out.ExpiresIn <= 0 {
		out.ExpiresIn = 60
	}
	rcvr.until = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return rcvr.token, nil
}

func (rcvr *KeycloakAdmin) request(ctx context.Context, method, target string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, e := json.Marshal(body)
		if e != nil {
			return e
		}
		reader = bytes.NewReader(raw)
	}
	req, e := http.NewRequestWithContext(ctx, method, target, reader)
	if e != nil {
		return e
	}
	token, e := rcvr.accessToken(ctx)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, e := rcvr.http.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{Method: method, URL: target, Status: resp.StatusCode, Body: string(raw)}
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if e := json.Unmarshal(raw, out); e != nil {
			return e
		}
	}
	return nil
}
