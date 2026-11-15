package repository

import (
	"context"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/global"
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
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNGR1, "Groups start", map[string]interface{}{"project": project})
	}
	var v []model.Group
	e := rcvr.db.WithContext(ctx).Where("project_id=?", project).Order("slug").Find(&v).Error
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNGR2, "Groups done", map[string]interface{}{"count": len(v), "error": e})
	}
	return v, e
}

func (rcvr *groupRepository) Group(ctx context.Context, project, id uuid.UUID) (model.Group, error) {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNGR3, "Group start", map[string]interface{}{"project": project, "id": id})
	}
	var v model.Group
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND id=?", project, id).First(&v).Error
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNGR4, "Group not found or error", map[string]interface{}{"error": e})
		}
	}
	return v, mapNotFound(e)
}

func (rcvr *groupRepository) CreateGroup(ctx context.Context, v *model.Group) error {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNGR5, "CreateGroup start", map[string]interface{}{"project": v.ProjectID})
	}
	v.ID = uuid.New()
	v.Status = "active"
	e := rcvr.db.WithContext(ctx).Create(v).Error
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNGR6, "CreateGroup error", map[string]interface{}{"error": e})
		}
	}
	return e
}

func (rcvr *groupRepository) UpdateGroup(ctx context.Context, v *model.Group) error {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNGR7, "UpdateGroup start", map[string]interface{}{"project": v.ProjectID, "id": v.ID})
	}
	e := rcvr.db.WithContext(ctx).Model(&model.Group{}).Where("project_id=? AND id=?", v.ProjectID, v.ID).Updates(map[string]any{"name": v.Name, "status": v.Status}).Error
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNGR8, "UpdateGroup error", map[string]interface{}{"error": e})
		}
	}
	return e
}

func (rcvr *groupRepository) DeleteGroup(ctx context.Context, project, id uuid.UUID) error {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNGR9, "DeleteGroup start", map[string]interface{}{"project": project, "id": id})
	}
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND id=?", project, id).Delete(&model.Group{}).Error
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNGR10, "DeleteGroup error", map[string]interface{}{"error": e})
		}
	}
	return e
}
