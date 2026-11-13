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

var (
	ErrRoleDefinitionInUse = errors.New("role definition is still bound to principals")
	ErrLastProjectAdmin    = errors.New("cannot remove last project admin")
)

type Role interface {
	RoleDefinition(ctx context.Context, project uuid.UUID, key string) (model.RoleDefinition, error)
	RoleDefinitions(ctx context.Context, project uuid.UUID) ([]model.RoleDefinition, error)
	PutRoleDefinition(ctx context.Context, v *model.RoleDefinition) error
	DeleteRoleDefinition(ctx context.Context, project uuid.UUID, key string) error

	RoleBindings(ctx context.Context, project, principal uuid.UUID) ([]model.RoleBinding, error)
	ProjectRoleBindings(ctx context.Context, project uuid.UUID) ([]model.RoleBinding, error)
	GroupRoleBindings(ctx context.Context, project, group uuid.UUID) ([]model.RoleBinding, error)
	RoleBinding(ctx context.Context, project, binding uuid.UUID) (model.RoleBinding, error)
	PutRoleBinding(ctx context.Context, v *model.RoleBinding) error
	DeleteRoleBinding(ctx context.Context, project, binding uuid.UUID) error
}

type roleRepository struct {
	db *gorm.DB
}

func NewRole(db *gorm.DB) Role {
	return &roleRepository{db: db}
}

func (rcvr *roleRepository) RoleDefinition(ctx context.Context, project uuid.UUID, key string) (model.RoleDefinition, error) {
	var v model.RoleDefinition
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND key=?", project, key).First(&v).Error
	return v, mapNotFound(e)
}

func (rcvr *roleRepository) RoleDefinitions(ctx context.Context, project uuid.UUID) ([]model.RoleDefinition, error) {
	var v []model.RoleDefinition
	e := rcvr.db.WithContext(ctx).Where("project_id=?", project).Order("key").Find(&v).Error
	return v, e
}

func (rcvr *roleRepository) PutRoleDefinition(ctx context.Context, v *model.RoleDefinition) error {
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	now := time.Now().UTC()
	v.CreatedAt = now
	v.UpdatedAt = now
	if v.Name == "" {
		v.Name = v.Key
	}
	if v.Permissions == nil {
		v.Permissions = model.PermissionList{}
	}
	return rcvr.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "project_id"}, {Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"name", "permissions", "keycloak_role", "builtin", "updated_at"}),
	}).Create(v).Error
}

func (rcvr *roleRepository) DeleteRoleDefinition(ctx context.Context, project uuid.UUID, key string) error {
	return rcvr.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var n int64
		if e := tx.Model(&model.RoleBinding{}).Where("project_id=? AND role_key=?", project, key).Count(&n).Error; e != nil {
			return e
		}
		if n > 0 {
			return ErrRoleDefinitionInUse
		}
		r := tx.Where("project_id=? AND key=? AND builtin=false", project, key).Delete(&model.RoleDefinition{})
		if r.Error != nil {
			return r.Error
		}
		if r.RowsAffected != 1 {
			return ErrNotFound
		}
		return nil
	})
}

func (rcvr *roleRepository) RoleBindings(ctx context.Context, project, principal uuid.UUID) ([]model.RoleBinding, error) {
	var v []model.RoleBinding
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND principal_id=?", project, principal).Order("scope, created_at").Find(&v).Error
	return v, e
}

func (rcvr *roleRepository) ProjectRoleBindings(ctx context.Context, project uuid.UUID) ([]model.RoleBinding, error) {
	var v []model.RoleBinding
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND scope='project'", project).Order("created_at").Find(&v).Error
	return v, e
}

func (rcvr *roleRepository) GroupRoleBindings(ctx context.Context, project, group uuid.UUID) ([]model.RoleBinding, error) {
	var v []model.RoleBinding
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND scope='group' AND group_id=?", project, group).Order("created_at").Find(&v).Error
	return v, e
}

func (rcvr *roleRepository) RoleBinding(ctx context.Context, project, binding uuid.UUID) (model.RoleBinding, error) {
	var v model.RoleBinding
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND id=?", project, binding).First(&v).Error
	return v, mapNotFound(e)
}

func (rcvr *roleRepository) PutRoleBinding(ctx context.Context, v *model.RoleBinding) error {
	return rcvr.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var definition model.RoleDefinition
		if e := tx.Where("project_id=? AND key=?", v.ProjectID, v.RoleKey).First(&definition).Error; e != nil {
			if errors.Is(e, gorm.ErrRecordNotFound) {
				builtin, ok := model.BuiltinRoleDefinition(v.ProjectID, v.RoleKey)
				if !ok {
					return ErrNotFound
				}
				builtin.ID = uuid.New()
				builtin.CreatedAt = time.Now().UTC()
				builtin.UpdatedAt = builtin.CreatedAt
				if e = tx.Create(&builtin).Error; e != nil {
					return e
				}
			} else {
				return e
			}
		}
		if v.Scope == model.BindingScopeGroup {
			if v.GroupID == nil {
				return errors.New("group binding requires group_id")
			}
		} else {
			v.Scope = model.BindingScopeProject
			v.GroupID = nil
		}
		if v.ID == uuid.Nil {
			v.ID = uuid.New()
		}
		v.CreatedAt = time.Now().UTC()

		q := tx.Where("project_id=? AND principal_id=?", v.ProjectID, v.PrincipalID)
		if v.Scope == model.BindingScopeGroup {
			q = q.Where("scope='group' AND group_id=?", *v.GroupID)
		} else {
			q = q.Where("scope='project'")
		}
		if e := q.Delete(&model.RoleBinding{}).Error; e != nil {
			return e
		}
		return tx.Create(v).Error
	})
}

func (rcvr *roleRepository) DeleteRoleBinding(ctx context.Context, project, binding uuid.UUID) error {
	return rcvr.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var projectLock struct{ ID uuid.UUID }
		if e := tx.Table("projects").Select("id").Clauses(clause.Locking{Strength: "UPDATE"}).Where("id=?", project).Take(&projectLock).Error; e != nil {
			return mapNotFound(e)
		}
		var v model.RoleBinding
		if e := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("project_id=? AND id=?", project, binding).First(&v).Error; e != nil {
			return mapNotFound(e)
		}
		if v.Scope == model.BindingScopeProject {
			var definition model.RoleDefinition
			if e := tx.Where("project_id=? AND key=?", project, v.RoleKey).First(&definition).Error; e != nil {
				builtin, ok := model.BuiltinRoleDefinition(project, v.RoleKey)
				if !ok {
					return mapNotFound(e)
				}
				definition = builtin
			}
			if grantsProjectAdmin(definition.Permissions) {
				var n int64
				if e := tx.Raw(`
					SELECT count(*)
					FROM role_bindings b
					JOIN role_definitions d ON d.project_id=b.project_id AND d.key=b.role_key
					WHERE b.project_id=? AND b.scope='project'
					  AND (d.permissions @> '["*"]'::jsonb OR d.permissions @> '["project:manage"]'::jsonb)`,
					project,
				).Scan(&n).Error; e != nil {
					return e
				}
				if n <= 1 {
					return ErrLastProjectAdmin
				}
			}
		}
		return tx.Delete(&v).Error
	})
}

func grantsProjectAdmin(permissions model.PermissionList) bool {
	for _, p := range permissions {
		if p == "*" || p == string(model.PermissionProjectManage) {
			return true
		}
	}
	return false
}
