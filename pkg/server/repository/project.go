package repository

import (
	"context"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Project interface {
	Project(ctx context.Context, id uuid.UUID) (model.Project, error)
	ProjectByIssuer(ctx context.Context, issuer string) (model.Project, error)
	ProjectBySlug(ctx context.Context, slug string) (model.Project, error)
	Projects(ctx context.Context, principal uuid.UUID) ([]model.Project, error)
	PutProject(ctx context.Context, v *model.Project) error
}

type projectRepository struct {
	db *gorm.DB
}

func NewProject(db *gorm.DB) Project {
	return &projectRepository{db: db}
}

func (rcvr *projectRepository) Project(ctx context.Context, id uuid.UUID) (model.Project, error) {
	var v model.Project
	e := rcvr.db.WithContext(ctx).Where("id = ? AND status = 'active'", id).First(&v).Error
	return v, mapNotFound(e)
}

func (rcvr *projectRepository) ProjectByIssuer(ctx context.Context, issuer string) (model.Project, error) {
	var v model.Project
	e := rcvr.db.WithContext(ctx).Where("issuer = ? AND status = 'active'", issuer).First(&v).Error
	return v, mapNotFound(e)
}

func (rcvr *projectRepository) ProjectBySlug(ctx context.Context, slug string) (model.Project, error) {
	var v model.Project
	e := rcvr.db.WithContext(ctx).Where("slug=?", slug).First(&v).Error
	return v, mapNotFound(e)
}

func (rcvr *projectRepository) PutProject(ctx context.Context, v *model.Project) error {
	return rcvr.db.WithContext(ctx).Save(v).Error
}

func (rcvr *projectRepository) Projects(ctx context.Context, principal uuid.UUID) ([]model.Project, error) {
	var v []model.Project
	e := rcvr.db.WithContext(ctx).Table("projects p").Select("p.*").Joins("JOIN role_bindings r ON r.project_id=p.id AND r.scope='project'").Where("r.principal_id=? AND p.status='active'", principal).Order("p.slug").Scan(&v).Error
	return v, e
}
