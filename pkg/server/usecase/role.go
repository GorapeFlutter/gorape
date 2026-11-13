package usecase

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/request"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/google/uuid"
)

type Role interface {
	DeleteRoleBinding(ctx context.Context, a model.AuthContext, b uuid.UUID) error
	PutProjectRole(ctx context.Context, a model.AuthContext, q request.RoleCreate) error
	PutGroupRole(ctx context.Context, a model.AuthContext, g uuid.UUID, q request.RoleCreate) error
	PutRoleDefinition(ctx context.Context, a model.AuthContext, key string, q request.RoleDefinitionPut) (model.RoleDefinition, error)
	DeleteRoleDefinition(ctx context.Context, a model.AuthContext, key string) error
}

type roleUsecase struct {
	store     *repository.Store
	projectUC Project
}

func NewRole(store *repository.Store, projectUC Project) Role {
	return &roleUsecase{store: store, projectUC: projectUC}
}

func (rcvr *roleUsecase) DeleteRoleBinding(ctx context.Context, a model.AuthContext, b uuid.UUID) error {
	target, e := rcvr.store.RoleBinding(ctx, a.Project.ID, b)
	if e != nil {
		return e
	}
	if target.PrincipalID == a.Principal.ID {
		return errors.New("self role changes are not allowed")
	}
	if target.Scope == model.BindingScopeGroup && target.GroupID != nil {
		if e := rcvr.projectUC.RequireProject(ctx, a, model.PermissionRoleManage); e != nil {
			// A group admin may manage non-admin group roles. The repository
			// still enforces the last project admin rule for project bindings.
			if e2 := requireGroupPermission(rcvr.projectUC, ctx, a, *target.GroupID, model.PermissionRoleManage); e2 != nil {
				return e2
			}
		}
	} else if e := rcvr.projectUC.RequireProject(ctx, a, model.PermissionRoleManage); e != nil {
		return e
	}
	return rcvr.store.DeleteRoleBinding(ctx, a.Project.ID, b)
}

func (rcvr *roleUsecase) PutProjectRole(ctx context.Context, a model.AuthContext, q request.RoleCreate) error {
	if e := rcvr.projectUC.RequireProject(ctx, a, model.PermissionRoleManage); e != nil {
		return e
	}
	if _, e := rcvr.resolveDefinition(ctx, a, q.Role); e != nil {
		return e
	}
	p, e := rcvr.store.EnsurePrincipal(ctx, a.Project, a.Project.OIDCIssuer, q.OIDCSubject)
	if e != nil {
		return e
	}
	if p.ID == a.Principal.ID {
		return errors.New("self role changes are not allowed")
	}
	return rcvr.store.PutRoleBinding(ctx, &model.RoleBinding{
		ProjectID:   a.Project.ID,
		PrincipalID: p.ID,
		Scope:       model.BindingScopeProject,
		RoleKey:     q.Role,
	})
}

func (rcvr *roleUsecase) PutGroupRole(ctx context.Context, a model.AuthContext, g uuid.UUID, q request.RoleCreate) error {
	definition, e := rcvr.resolveDefinition(ctx, a, q.Role)
	if e != nil {
		return e
	}
	if grantsAdmin(definition.Permissions) {
		if e := rcvr.projectUC.RequireProject(ctx, a, model.PermissionRoleManage); e != nil {
			return ErrForbidden
		}
	} else if e := requireGroupPermission(rcvr.projectUC, ctx, a, g, model.PermissionRoleManage); e != nil {
		return e
	}
	p, e := rcvr.store.EnsurePrincipal(ctx, a.Project, a.Project.OIDCIssuer, q.OIDCSubject)
	if e != nil {
		return e
	}
	if p.ID == a.Principal.ID {
		return errors.New("self role changes are not allowed")
	}
	return rcvr.store.PutRoleBinding(ctx, &model.RoleBinding{
		ProjectID:   a.Project.ID,
		PrincipalID: p.ID,
		Scope:       model.BindingScopeGroup,
		GroupID:     &g,
		RoleKey:     q.Role,
	})
}

func (rcvr *roleUsecase) PutRoleDefinition(ctx context.Context, a model.AuthContext, key string, q request.RoleDefinitionPut) (model.RoleDefinition, error) {
	if e := rcvr.projectUC.RequireProject(ctx, a, model.PermissionRoleManage); e != nil {
		return model.RoleDefinition{}, e
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9:_-]{0,62}$`).MatchString(key) {
		return model.RoleDefinition{}, errors.New("role key must start with a lowercase letter and contain lowercase letters, numbers, colons, underscores, or hyphens")
	}
	if len(q.Permissions) == 0 {
		return model.RoleDefinition{}, errors.New("role permissions must not be empty")
	}
	if key == string(model.RoleAdmin) && !permissionListGrantsAdmin(q.Permissions) {
		return model.RoleDefinition{}, errors.New("the built-in admin role must keep project:manage or *")
	}
	existing, e := rcvr.store.RoleDefinition(ctx, a.Project.ID, key)
	builtin := e == nil && existing.Builtin
	if e != nil && !errors.Is(e, repository.ErrNotFound) {
		return model.RoleDefinition{}, e
	}
	if e != nil {
		_, builtin = model.BuiltinPermissions(key)
	}
	name := strings.TrimSpace(q.Name)
	if name == "" {
		name = key
	}
	d := model.RoleDefinition{
		ProjectID:    a.Project.ID,
		Key:          key,
		Name:         name,
		Permissions:  model.PermissionList(q.Permissions),
		KeycloakRole: q.KeycloakRole,
		Builtin:      builtin,
	}
	if e := rcvr.store.PutRoleDefinition(ctx, &d); e != nil {
		return model.RoleDefinition{}, e
	}
	return rcvr.store.RoleDefinition(ctx, a.Project.ID, key)
}

func (rcvr *roleUsecase) DeleteRoleDefinition(ctx context.Context, a model.AuthContext, key string) error {
	if e := rcvr.projectUC.RequireProject(ctx, a, model.PermissionRoleManage); e != nil {
		return e
	}
	return rcvr.store.DeleteRoleDefinition(ctx, a.Project.ID, key)
}

func (rcvr *roleUsecase) resolveDefinition(ctx context.Context, a model.AuthContext, key string) (model.RoleDefinition, error) {
	d, e := rcvr.store.RoleDefinition(ctx, a.Project.ID, key)
	if e == nil {
		return d, nil
	}
	if !errors.Is(e, repository.ErrNotFound) {
		return model.RoleDefinition{}, e
	}
	if d, ok := model.BuiltinRoleDefinition(a.Project.ID, key); ok {
		return d, nil
	}
	return model.RoleDefinition{}, errors.New("role is not defined")
}

func requireGroupPermission(projectUC Project, ctx context.Context, a model.AuthContext, group uuid.UUID, permission model.Permission) error {
	set, _, e := projectUC.EffectivePermissions(ctx, a, &group)
	if e != nil {
		return ErrForbidden
	}
	if !set.Allows(permission) {
		return ErrForbidden
	}
	return nil
}

func grantsAdmin(permissions model.PermissionList) bool {
	for _, p := range permissions {
		if p == "*" || p == string(model.PermissionProjectManage) || p == string(model.PermissionRoleManage) {
			return true
		}
	}
	return false
}

func permissionListGrantsAdmin(permissions []string) bool {
	for _, p := range permissions {
		if p == "*" || p == string(model.PermissionProjectManage) {
			return true
		}
	}
	return false
}
