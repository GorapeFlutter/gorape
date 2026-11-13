package repository

import (
	"context"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Group interface {
	Groups(ctx context.Context, project uuid.UUID) ([]model.Group, error)
	Group(ctx context.Context, project, id uuid.UUID) (model.Group, error)
	CreateGroup(ctx context.Context, v *model.Group) error
	UpdateGroup(ctx context.Context, v *model.Group) error
	DeleteGroup(ctx context.Context, project, id uuid.UUID) error
}

type groupRepository struct {
	db *gorm.DB
}

func NewGroup(db *gorm.DB) Group {
	return &groupRepository{db: db}
}

func (rcvr *groupRepository) Groups(ctx context.Context, project uuid.UUID) ([]model.Group, error) {
	var v []model.Group
	e := rcvr.db.WithContext(ctx).Where("project_id=?", project).Order("slug").Find(&v).Error
	return v, e
}

func (rcvr *groupRepository) Group(ctx context.Context, project, id uuid.UUID) (model.Group, error) {
	var v model.Group
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND id=?", project, id).First(&v).Error
	return v, mapNotFound(e)
}

func (rcvr *groupRepository) CreateGroup(ctx context.Context, v *model.Group) error {
	v.ID = uuid.New()
	v.Status = "active"
	return rcvr.db.WithContext(ctx).Create(v).Error
}

func (rcvr *groupRepository) UpdateGroup(ctx context.Context, v *model.Group) error {
	return rcvr.db.WithContext(ctx).Model(&model.Group{}).Where("project_id=? AND id=?", v.ProjectID, v.ID).Updates(map[string]any{"name": v.Name, "status": v.Status}).Error
}

func (rcvr *groupRepository) DeleteGroup(ctx context.Context, project, id uuid.UUID) error {
	return rcvr.db.WithContext(ctx).Where("project_id=? AND id=?", project, id).Delete(&model.Group{}).Error
}
