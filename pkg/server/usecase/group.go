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
	RequireGroup(ctx context.Context, a model.AuthContext, g uuid.UUID, min model.Role) error
	CreateGroup(ctx context.Context, a model.AuthContext, q request.GroupCreate) (model.GroupDomain, error)
}

type groupUsecase struct {
	store     *repository.Store
	projectUC Project
}

func NewGroup(store *repository.Store, projectUC Project) Group {
	return &groupUsecase{store: store, projectUC: projectUC}
}

func Allows(projectRole, groupRole, min model.Role) bool {
	return projectRole.Rank() >= min.Rank() || groupRole.Rank() >= min.Rank()
}

func (rcvr *groupUsecase) RequireGroup(ctx context.Context, a model.AuthContext, g uuid.UUID, min model.Role) error {
	pr, _ := rcvr.store.ProjectRole(ctx, a.Project.ID, a.Principal.ID)
	gr, _ := rcvr.store.GroupRole(ctx, a.Project.ID, g, a.Principal.ID)
	if !Allows(pr, gr, min) {
		return ErrForbidden
	}
	return nil
}

func (rcvr *groupUsecase) CreateGroup(ctx context.Context, a model.AuthContext, q request.GroupCreate) (model.GroupDomain, error) {
	if e := rcvr.projectUC.RequireProject(ctx, a, model.RoleAdmin); e != nil {
		return model.GroupDomain{}, e
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`).MatchString(q.Slug) {
		return model.GroupDomain{}, errors.New("group slug must contain lowercase letters, numbers, and hyphens")
	}
	v := model.GroupDomain{ProjectID: a.Project.ID, Slug: q.Slug, Name: q.Name}
	return v, rcvr.store.CreateGroup(ctx, &v)
}
