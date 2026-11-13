package repository

import (
	"context"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Project interface {
	Project(ctx context.Context, id uuid.UUID) (model.ProjectDomain, error)
	ProjectByIssuer(ctx context.Context, issuer string) (model.ProjectDomain, error)
	Projects(ctx context.Context, principal uuid.UUID) ([]model.ProjectDomain, error)
}

type projectRepository struct {
	db *gorm.DB
}

func NewProject(db *gorm.DB) Project {
	return &projectRepository{db: db}
}

func (rcvr *projectRepository) Project(ctx context.Context, id uuid.UUID) (model.ProjectDomain, error) {
	var v model.ProjectDomain
	e := rcvr.db.WithContext(ctx).Where("id = ? AND status = 'active'", id).First(&v).Error
	return v, mapNotFound(e)
}

func (rcvr *projectRepository) ProjectByIssuer(ctx context.Context, issuer string) (model.ProjectDomain, error) {
	var v model.ProjectDomain
	e := rcvr.db.WithContext(ctx).Where("oidc_issuer = ? AND status = 'active'", issuer).First(&v).Error
	return v, mapNotFound(e)
}

func (rcvr *projectRepository) Projects(ctx context.Context, principal uuid.UUID) ([]model.ProjectDomain, error) {
	var v []model.ProjectDomain
	e := rcvr.db.WithContext(ctx).Table("project_domains p").Select("p.*").Joins("JOIN project_role_bindings r ON r.project_id=p.id").Where("r.principal_id=? AND p.status='active'", principal).Order("p.slug").Scan(&v).Error
	return v, e
}
