package usecase

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/google/uuid"
)

type Project interface {
	Authenticate(ctx context.Context, projectID, token string) (model.AuthContext, error)
	AuthenticateIssuer(ctx context.Context, token string) (model.AuthContext, error)
	AuthenticatePlatform(ctx context.Context, token string) (model.AuthContext, error)
	RequirePlatform(ctx context.Context, a model.AuthContext) error
	RequireProject(ctx context.Context, a model.AuthContext, permission model.Permission) error
	RequireProjectRole(ctx context.Context, a model.AuthContext, role model.Role) error
	EffectivePermissions(ctx context.Context, a model.AuthContext, group *uuid.UUID) (model.PermissionSet, []string, error)
}

type projectUsecase struct {
	store  *repository.Store
	tokens repository.TokenValidator

	platformIssuer     string
	platformAdminRoles []string
}

func NewProject(store *repository.Store, tokens repository.TokenValidator) Project {
	return &projectUsecase{store: store, tokens: tokens}
}

func (rcvr *projectUsecase) configurePlatform(issuer string, adminRoles []string) {
	rcvr.platformIssuer = strings.TrimRight(issuer, "/")
	rcvr.platformAdminRoles = adminRoles
}

func (rcvr *projectUsecase) Authenticate(ctx context.Context, projectID, token string) (model.AuthContext, error) {
	id, e := repository.ParseUUID(projectID)
	if e != nil {
		return model.AuthContext{}, e
	}
	p, e := rcvr.store.Project(ctx, id)
	if e != nil {
		return model.AuthContext{}, e
	}
	claims, e := rcvr.tokens.Validate(ctx, p, token)
	if e != nil {
		return model.AuthContext{}, e
	}
	principal, e := rcvr.store.EnsurePrincipal(ctx, p, claims.Issuer, claims.Subject)
	if e != nil {
		return model.AuthContext{}, e
	}
	return model.AuthContext{Project: p, Principal: principal, Claims: claims}, nil
}

func (rcvr *projectUsecase) AuthenticateIssuer(ctx context.Context, token string) (model.AuthContext, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return model.AuthContext{}, errors.New("malformed access token")
	}
	b, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return model.AuthContext{}, errors.New("malformed access token")
	}
	var hint struct {
		Issuer string `json:"iss"`
	}
	if json.Unmarshal(b, &hint) != nil || hint.Issuer == "" {
		return model.AuthContext{}, errors.New("access token issuer is missing")
	}
	p, e := rcvr.store.ProjectByIssuer(ctx, hint.Issuer)
	if e != nil {
		return model.AuthContext{}, e
	}
	return rcvr.Authenticate(ctx, p.ID.String(), token)
}

// AuthenticatePlatform validates a token against the configured platform
// issuer without requiring an existing Gorape project. This is what lets an
// administrator bootstrap the first project through the server.
func (rcvr *projectUsecase) AuthenticatePlatform(ctx context.Context, token string) (model.AuthContext, error) {
	if rcvr.platformIssuer == "" {
		return model.AuthContext{}, ErrPlatformDisabled
	}
	p := model.Project{
		ID:         uuid.Nil,
		Slug:       "platform",
		OIDCIssuer: rcvr.platformIssuer,
		Status:     "active",
	}
	claims, e := rcvr.tokens.Validate(ctx, p, token)
	if e != nil {
		return model.AuthContext{}, e
	}
	a := model.AuthContext{Claims: claims}
	if e = rcvr.RequirePlatform(ctx, a); e != nil {
		return model.AuthContext{}, e
	}
	return a, nil
}

// RequirePlatform verifies that an already validated token belongs to the
// configured platform issuer and carries one of platform.admin_roles. It never
// performs token validation itself; callers must use AuthenticatePlatform.
func (rcvr *projectUsecase) RequirePlatform(_ context.Context, a model.AuthContext) error {
	if rcvr.platformIssuer == "" {
		return ErrPlatformDisabled
	}
	if a.Claims.Issuer != rcvr.platformIssuer || a.Claims.Subject == "" {
		return ErrForbidden
	}
	roles := map[string]struct{}{}
	for _, role := range a.Claims.AllRoles() {
		roles[role] = struct{}{}
	}
	for _, role := range rcvr.platformAdminRoles {
		if _, ok := roles[role]; ok {
			return nil
		}
	}
	return ErrForbidden
}

func (rcvr *projectUsecase) RequireProject(ctx context.Context, a model.AuthContext, permission model.Permission) error {
	set, _, e := rcvr.EffectivePermissions(ctx, a, nil)
	if e != nil {
		return ErrForbidden
	}
	if !set.Allows(permission) {
		return ErrForbidden
	}
	return nil
}

// RequireProjectRole preserves the earlier role-oriented API for callers that
// still need coarse checks. Authorization in controllers uses permissions.
func (rcvr *projectUsecase) RequireProjectRole(ctx context.Context, a model.AuthContext, role model.Role) error {
	switch role {
	case model.RoleAdmin:
		return rcvr.RequireProject(ctx, a, model.PermissionProjectManage)
	case model.RoleEditor:
		return rcvr.RequireProject(ctx, a, model.PermissionDeviceRegister)
	case model.RoleViewer:
		return rcvr.RequireProject(ctx, a, model.PermissionProjectRead)
	default:
		return ErrForbidden
	}
}

// EffectivePermissions resolves both Gorape role bindings and dynamic Keycloak
// claims. Project-scoped permissions always apply. Group-scoped bindings and
// Keycloak group paths apply only when group is non-nil.
func (rcvr *projectUsecase) EffectivePermissions(ctx context.Context, a model.AuthContext, group *uuid.UUID) (model.PermissionSet, []string, error) {
	definitions, e := rcvr.store.RoleDefinitions(ctx, a.Project.ID)
	if e != nil {
		return nil, nil, e
	}
	definitions = withBuiltinDefinitions(a.Project.ID, definitions)
	byKey := make(map[string]model.RoleDefinition, len(definitions))
	for _, d := range definitions {
		byKey[d.Key] = d
	}

	keys := make([]string, 0, 8)
	seen := map[string]struct{}{}
	add := func(key string) {
		if key == "" {
			return
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}

	bindings, e := rcvr.store.RoleBindings(ctx, a.Project.ID, a.Principal.ID)
	if e != nil {
		return nil, nil, e
	}
	for _, b := range bindings {
		if b.Scope == model.BindingScopeProject {
			add(b.RoleKey)
			continue
		}
		if group != nil && b.GroupID != nil && *b.GroupID == *group {
			add(b.RoleKey)
		}
	}

	// Dynamic roles from realm_access.roles and resource_access.*.roles.
	for _, role := range a.Claims.AllRoles() {
		for _, d := range definitions {
			if role == d.EffectiveKeycloakRole() {
				add(d.Key)
			}
		}
	}

	// Dynamic group memberships, with explicit paths:
	//   /gorape/projects/<slug>/roles/<roleKey>
	//   /gorape/projects/<slug>/groups/<groupSlug>/roles/<roleKey>
	var groupSlug string
	if group != nil {
		if g, e := rcvr.store.Group(ctx, a.Project.ID, *group); e == nil {
			groupSlug = g.Slug
		}
	}
	for _, path := range a.Claims.Groups {
		roleKey, pathGroup, ok := ParseKeycloakGroupPath(path, a.Project.Slug)
		if !ok {
			continue
		}
		if pathGroup == "" {
			add(roleKey)
			continue
		}
		if groupSlug != "" && pathGroup == groupSlug {
			add(roleKey)
		}
	}

	set := model.EffectivePermissions(definitions, keys)
	return set, keys, nil
}

// ParseKeycloakGroupPath extracts a Gorape role key and optional group slug
// from a Keycloak group path.
func ParseKeycloakGroupPath(path, projectSlug string) (roleKey, groupSlug string, ok bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 || parts[0] != "gorape" || parts[1] != "projects" || parts[2] != projectSlug {
		return "", "", false
	}
	rest := parts[3:]
	if len(rest) == 2 && rest[0] == "roles" {
		return rest[1], "", true
	}
	if len(rest) == 4 && rest[0] == "groups" && rest[2] == "roles" {
		return rest[3], rest[1], true
	}
	return "", "", false
}

func withBuiltinDefinitions(projectID uuid.UUID, definitions []model.RoleDefinition) []model.RoleDefinition {
	seen := map[string]struct{}{}
	out := make([]model.RoleDefinition, 0, len(definitions)+3)
	for _, d := range definitions {
		seen[d.Key] = struct{}{}
		out = append(out, d)
	}
	for _, key := range []string{string(model.RoleAdmin), string(model.RoleEditor), string(model.RoleViewer)} {
		if _, ok := seen[key]; ok {
			continue
		}
		if d, ok := model.BuiltinRoleDefinition(projectID, key); ok {
			out = append(out, d)
		}
	}
	return out
}
