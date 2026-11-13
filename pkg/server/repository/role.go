package repository

import (
	"context"
	"errors"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Role interface {
	ProjectRole(ctx context.Context, project, principal uuid.UUID) (model.Role, error)
	GroupRole(ctx context.Context, project, group, principal uuid.UUID) (model.Role, error)
	ProjectRoles(ctx context.Context, project uuid.UUID) ([]model.ProjectRoleBinding, error)
	GroupRoles(ctx context.Context, project, group uuid.UUID) ([]model.GroupRoleBinding, error)
	ProjectRoleBinding(ctx context.Context, project, binding uuid.UUID) (model.ProjectRoleBinding, error)
	GroupRoleBinding(ctx context.Context, project, group, binding uuid.UUID) (model.GroupRoleBinding, error)
	PutProjectRole(ctx context.Context, v *model.ProjectRoleBinding) error
	PutGroupRole(ctx context.Context, v *model.GroupRoleBinding) error
	DeleteProjectRole(ctx context.Context, project, binding uuid.UUID) error
	DeleteGroupRole(ctx context.Context, project, group, binding uuid.UUID) error
}

type roleRepository struct {
	db *gorm.DB
}

func NewRole(db *gorm.DB) Role {
	return &roleRepository{db: db}
}

func (rcvr *roleRepository) ProjectRole(ctx context.Context, project, principal uuid.UUID) (model.Role, error) {
	var v model.ProjectRoleBinding
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND principal_id=?", project, principal).First(&v).Error
	return v.Role, mapNotFound(e)
}

func (rcvr *roleRepository) GroupRole(ctx context.Context, project, group, principal uuid.UUID) (model.Role, error) {
	var v model.GroupRoleBinding
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND group_id=? AND principal_id=?", project, group, principal).First(&v).Error
	return v.Role, mapNotFound(e)
}

func (rcvr *roleRepository) ProjectRoles(ctx context.Context, project uuid.UUID) ([]model.ProjectRoleBinding, error) {
	var v []model.ProjectRoleBinding
	e := rcvr.db.WithContext(ctx).Where("project_id=?", project).Order("created_at").Find(&v).Error
	return v, e
}

func (rcvr *roleRepository) GroupRoles(ctx context.Context, project, group uuid.UUID) ([]model.GroupRoleBinding, error) {
	var v []model.GroupRoleBinding
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND group_id=?", project, group).Order("created_at").Find(&v).Error
	return v, e
}

func (rcvr *roleRepository) ProjectRoleBinding(ctx context.Context, project, binding uuid.UUID) (model.ProjectRoleBinding, error) {
	var v model.ProjectRoleBinding
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND id=?", project, binding).First(&v).Error
	return v, mapNotFound(e)
}

func (rcvr *roleRepository) GroupRoleBinding(ctx context.Context, project, group, binding uuid.UUID) (model.GroupRoleBinding, error) {
	var v model.GroupRoleBinding
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND group_id=? AND id=?", project, group, binding).First(&v).Error
	return v, mapNotFound(e)
}

func (rcvr *roleRepository) PutProjectRole(ctx context.Context, v *model.ProjectRoleBinding) error {
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	v.CreatedAt = time.Now().UTC()
	return rcvr.db.WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "project_id"}, {Name: "principal_id"}}, DoUpdates: clause.AssignmentColumns([]string{"role"})}).Create(v).Error
}

func (rcvr *roleRepository) PutGroupRole(ctx context.Context, v *model.GroupRoleBinding) error {
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	v.CreatedAt = time.Now().UTC()
	return rcvr.db.WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "project_id"}, {Name: "group_id"}, {Name: "principal_id"}}, DoUpdates: clause.AssignmentColumns([]string{"role"})}).Create(v).Error
}

func (rcvr *roleRepository) DeleteProjectRole(ctx context.Context, project, binding uuid.UUID) error {
	return rcvr.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var projectLock struct{ ID uuid.UUID }
		if e := tx.Table("project_domains").Select("id").Clauses(clause.Locking{Strength: "UPDATE"}).Where("id=?", project).Take(&projectLock).Error; e != nil {
			return mapNotFound(e)
		}
		var v model.ProjectRoleBinding
		if e := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("project_id=? AND id=?", project, binding).First(&v).Error; e != nil {
			return mapNotFound(e)
		}
		if v.Role == model.RoleAdmin {
			var n int64
			if e := tx.Model(&model.ProjectRoleBinding{}).Where("project_id=? AND role=?", project, model.RoleAdmin).Count(&n).Error; e != nil {
				return e
			}
			if n <= 1 {
				return errors.New("cannot remove last project admin")
			}
		}
		return tx.Delete(&v).Error
	})
}

func (rcvr *roleRepository) DeleteGroupRole(ctx context.Context, project, group, binding uuid.UUID) error {
	return rcvr.db.WithContext(ctx).Where("project_id=? AND group_id=? AND id=?", project, group, binding).Delete(&model.GroupRoleBinding{}).Error
}
