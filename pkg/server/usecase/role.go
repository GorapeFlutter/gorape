package usecase

import (
	"context"
	"errors"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/request"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/google/uuid"
)

type Role interface {
	DeleteProjectRole(ctx context.Context, a model.AuthContext, b uuid.UUID) error
	DeleteGroupRole(ctx context.Context, a model.AuthContext, g, b uuid.UUID) error
	PutProjectRole(ctx context.Context, a model.AuthContext, q request.RoleCreate) error
	PutGroupRole(ctx context.Context, a model.AuthContext, g uuid.UUID, q request.RoleCreate) error
}

type roleUsecase struct {
	store     *repository.Store
	projectUC Project
}

func NewRole(store *repository.Store, projectUC Project) Role {
	return &roleUsecase{store: store, projectUC: projectUC}
}

func (rcvr *roleUsecase) DeleteProjectRole(ctx context.Context, a model.AuthContext, b uuid.UUID) error {
	if e := rcvr.projectUC.RequireProject(ctx, a, model.RoleAdmin); e != nil {
		return e
	}
	target, e := rcvr.store.ProjectRoleBinding(ctx, a.Project.ID, b)
	if e != nil {
		return e
	}
	if target.PrincipalID == a.Principal.ID {
		return errors.New("self role changes are not allowed")
	}
	return rcvr.store.DeleteProjectRole(ctx, a.Project.ID, b)
}

func (rcvr *roleUsecase) DeleteGroupRole(ctx context.Context, a model.AuthContext, g, b uuid.UUID) error {
	target, e := rcvr.store.GroupRoleBinding(ctx, a.Project.ID, g, b)
	if e != nil {
		return e
	}
	if target.PrincipalID == a.Principal.ID {
		return errors.New("self role changes are not allowed")
	}
	pr, _ := rcvr.store.ProjectRole(ctx, a.Project.ID, a.Principal.ID)
	gr, _ := rcvr.store.GroupRole(ctx, a.Project.ID, g, a.Principal.ID)
	if pr != model.RoleAdmin && (gr != model.RoleAdmin || target.Role == model.RoleAdmin) {
		return ErrForbidden
	}
	return rcvr.store.DeleteGroupRole(ctx, a.Project.ID, g, b)
}

func (rcvr *roleUsecase) PutProjectRole(ctx context.Context, a model.AuthContext, q request.RoleCreate) error {
	if !q.Role.Valid() {
		return errors.New("invalid role")
	}
	if e := rcvr.projectUC.RequireProject(ctx, a, model.RoleAdmin); e != nil {
		return e
	}
	p, e := rcvr.store.EnsurePrincipal(ctx, a.Project, a.Project.OIDCIssuer, q.OIDCSubject)
	if e != nil {
		return e
	}
	if p.ID == a.Principal.ID {
		return errors.New("self role changes are not allowed")
	}
	return rcvr.store.PutProjectRole(ctx, &model.ProjectRoleBinding{ProjectID: a.Project.ID, PrincipalID: p.ID, Role: q.Role})
}

func (rcvr *roleUsecase) PutGroupRole(ctx context.Context, a model.AuthContext, g uuid.UUID, q request.RoleCreate) error {
	if !q.Role.Valid() {
		return errors.New("invalid role")
	}
	pr, _ := rcvr.store.ProjectRole(ctx, a.Project.ID, a.Principal.ID)
	gr, _ := rcvr.store.GroupRole(ctx, a.Project.ID, g, a.Principal.ID)
	if pr != model.RoleAdmin && (gr != model.RoleAdmin || q.Role == model.RoleAdmin) {
		return ErrForbidden
	}
	p, e := rcvr.store.EnsurePrincipal(ctx, a.Project, a.Project.OIDCIssuer, q.OIDCSubject)
	if e != nil {
		return e
	}
	if p.ID == a.Principal.ID {
		return errors.New("self role changes are not allowed")
	}
	return rcvr.store.PutGroupRole(ctx, &model.GroupRoleBinding{ProjectID: a.Project.ID, GroupID: g, PrincipalID: p.ID, Role: q.Role})
}
