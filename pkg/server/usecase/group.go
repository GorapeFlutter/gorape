package usecase

import (
	"context"
	"errors"
	"regexp"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/request"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/google/uuid"
)

type Group interface {
	RequireGroup(ctx context.Context, a model.AuthContext, g uuid.UUID, permission model.Permission) error
	CreateGroup(ctx context.Context, a model.AuthContext, q request.GroupCreate) (model.Group, error)
}

type groupUsecase struct {
	store     *repository.Store
	projectUC Project
}

func NewGroup(store *repository.Store, projectUC Project) Group {
	return &groupUsecase{store: store, projectUC: projectUC}
}

// Allows is retained for tests and for callers that still reason in role ranks.
// New authorization decisions should use permission sets.
func Allows(projectRole, groupRole, min model.Role) bool {
	return projectRole.Rank() >= min.Rank() || groupRole.Rank() >= min.Rank()
}

func (rcvr *groupUsecase) RequireGroup(ctx context.Context, a model.AuthContext, g uuid.UUID, permission model.Permission) error {
	set, _, e := rcvr.projectUC.EffectivePermissions(ctx, a, &g)
	if e != nil {
		return ErrForbidden
	}
	if !set.Allows(permission) {
		return ErrForbidden
	}
	return nil
}

func (rcvr *groupUsecase) CreateGroup(ctx context.Context, a model.AuthContext, q request.GroupCreate) (model.Group, error) {
	if e := rcvr.projectUC.RequireProject(ctx, a, model.PermissionProjectManage); e != nil {
		return model.Group{}, e
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`).MatchString(q.Slug) {
		return model.Group{}, errors.New("group slug must contain lowercase letters, numbers, and hyphens")
	}
	v := model.Group{ProjectID: a.Project.ID, Slug: q.Slug, Name: q.Name}
	return v, rcvr.store.CreateGroup(ctx, &v)
}
