package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/provisioning"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Provisioning applies declarative Gorape project configuration. It is
// intentionally separate from the domain repositories because the operation is
// transactional across projects, roles, groups, identities and bindings.
type Provisioning interface {
	ApplyGorape(ctx context.Context, spec provisioning.GorapeSpec) (uuid.UUID, []provisioning.Action, error)
}

type provisioningRepository struct {
	db *gorm.DB
}

func NewProvisioning(db *gorm.DB) Provisioning {
	return &provisioningRepository{db: db}
}

func (rcvr *provisioningRepository) ApplyGorape(ctx context.Context, spec provisioning.GorapeSpec) (uuid.UUID, []provisioning.Action, error) {
	actions := make([]provisioning.Action, 0, 16)
	var projectID uuid.UUID
	err := rcvr.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		issuer := strings.TrimRight(spec.Project.Issuer, "/")
		status := spec.Project.Status
		if status == "" {
			status = "active"
		}
		var project model.Project
		e := tx.Where("slug=?", spec.Project.Slug).First(&project).Error
		switch {
		case errors.Is(e, gorm.ErrRecordNotFound):
			project = model.Project{
				ID:            uuid.New(),
				Slug:          spec.Project.Slug,
				Name:          spec.Project.Name,
				OIDCIssuer:    issuer,
				KeycloakRealm: spec.Project.Realm,
				Status:        status,
				CreatedAt:     now,
				UpdatedAt:     now,
			}
			if e = tx.Create(&project).Error; e != nil {
				return fmt.Errorf("create project: %w", e)
			}
			actions = append(actions, provisioning.Action{Operation: "create", Resource: "gorape.project", Name: project.Slug})
		case e != nil:
			return e
		default:
			updates := map[string]any{
				"name":       spec.Project.Name,
				"issuer":     issuer,
				"realm":      spec.Project.Realm,
				"status":     status,
				"updated_at": now,
			}
			if e = tx.Model(&model.Project{}).Where("id=?", project.ID).Updates(updates).Error; e != nil {
				return fmt.Errorf("update project: %w", e)
			}
			project.Name = spec.Project.Name
			project.OIDCIssuer = issuer
			project.KeycloakRealm = spec.Project.Realm
			project.Status = status
			actions = append(actions, provisioning.Action{Operation: "update", Resource: "gorape.project", Name: project.Slug})
		}
		projectID = project.ID

		// Always guarantee the built-in role definitions exist. Manifests may
		// override their permissions, but a project without admin/editor/viewer
		// would be difficult to recover.
		for _, key := range []string{string(model.RoleAdmin), string(model.RoleEditor), string(model.RoleViewer)} {
			d, ok := model.BuiltinRoleDefinition(project.ID, key)
			if !ok {
				continue
			}
			r := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&d)
			if r.Error != nil {
				return r.Error
			}
			if r.RowsAffected > 0 {
				actions = append(actions, provisioning.Action{Operation: "create", Resource: "gorape.role", Name: key})
			}
		}

		for _, role := range spec.Roles {
			name := role.Name
			if name == "" {
				name = role.Key
			}
			permissions := model.PermissionList(role.Permissions)
			keycloakRole := role.KeycloakRole
			if keycloakRole == "" {
				keycloakRole = model.KeycloakRoleName(role.Key)
			}
			d := model.RoleDefinition{
				ID:           uuid.New(),
				ProjectID:    project.ID,
				Key:          role.Key,
				Name:         name,
				Permissions:  permissions,
				KeycloakRole: keycloakRole,
				Builtin:      model.BuiltinRolePermissions[role.Key] != nil,
				CreatedAt:    now,
				UpdatedAt:    now,
			}
			if e := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "project_id"}, {Name: "key"}},
				DoUpdates: clause.AssignmentColumns([]string{"name", "permissions", "keycloak_role", "builtin", "updated_at"}),
			}).Create(&d).Error; e != nil {
				return fmt.Errorf("upsert role %s: %w", role.Key, e)
			}
			actions = append(actions, provisioning.Action{Operation: "upsert", Resource: "gorape.role", Name: role.Key})
		}

		groupIDs := map[string]uuid.UUID{}
		var existingGroups []model.Group
		if e := tx.Where("project_id=?", project.ID).Find(&existingGroups).Error; e != nil {
			return e
		}
		for _, g := range existingGroups {
			groupIDs[g.Slug] = g.ID
		}
		for _, g := range spec.Groups {
			status := g.Status
			if status == "" {
				status = "active"
			}
			if id, ok := groupIDs[g.Slug]; ok {
				if e := tx.Model(&model.Group{}).Where("project_id=? AND id=?", project.ID, id).
					Updates(map[string]any{"name": g.Name, "status": status, "updated_at": now}).Error; e != nil {
					return e
				}
				actions = append(actions, provisioning.Action{Operation: "update", Resource: "gorape.group", Name: g.Slug})
				continue
			}
			id := uuid.New()
			v := model.Group{ID: id, ProjectID: project.ID, Slug: g.Slug, Name: g.Name, Status: status, CreatedAt: now, UpdatedAt: now}
			if e := tx.Create(&v).Error; e != nil {
				return fmt.Errorf("create group %s: %w", g.Slug, e)
			}
			groupIDs[g.Slug] = id
			actions = append(actions, provisioning.Action{Operation: "create", Resource: "gorape.group", Name: g.Slug})
		}

		for _, b := range spec.Bindings {
			subject := strings.TrimSpace(b.Subject)
			if subject == "" {
				return errors.New("binding subject is required")
			}
			principal, e := ensurePrincipalTx(tx, project, subject, now)
			if e != nil {
				return e
			}
			var definition model.RoleDefinition
			if e := tx.Where("project_id=? AND key=?", project.ID, b.Role).First(&definition).Error; e != nil {
				if !errors.Is(e, gorm.ErrRecordNotFound) {
					return e
				}
				builtin, ok := model.BuiltinRoleDefinition(project.ID, b.Role)
				if !ok {
					return fmt.Errorf("role %q is not defined", b.Role)
				}
				builtin.ID = uuid.New()
				builtin.CreatedAt = now
				builtin.UpdatedAt = now
				if e := tx.Create(&builtin).Error; e != nil {
					return e
				}
			}
			scope := b.Scope
			if scope == "" {
				scope = model.BindingScopeProject
			}
			var groupID *uuid.UUID
			if scope == model.BindingScopeGroup {
				id, ok := groupIDs[b.Group]
				if !ok {
					return fmt.Errorf("group %q is not defined", b.Group)
				}
				groupID = &id
			}
			q := tx.Where("project_id=? AND principal_id=?", project.ID, principal.ID)
			if groupID != nil {
				q = q.Where("scope='group' AND group_id=?", *groupID)
			} else {
				q = q.Where("scope='project'")
			}
			if e := q.Delete(&model.RoleBinding{}).Error; e != nil {
				return e
			}
			binding := model.RoleBinding{
				ID:          uuid.New(),
				ProjectID:   project.ID,
				PrincipalID: principal.ID,
				Scope:       scope,
				GroupID:     groupID,
				RoleKey:     b.Role,
				CreatedAt:   now,
			}
			if e := tx.Create(&binding).Error; e != nil {
				return fmt.Errorf("create binding for %s: %w", subject, e)
			}
			name := b.Role
			if b.Group != "" {
				name = b.Group + "/" + b.Role
			}
			actions = append(actions, provisioning.Action{Operation: "upsert", Resource: "gorape.role_binding", Name: name, Detail: subject})
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, nil, err
	}
	return projectID, actions, nil
}

func ensurePrincipalTx(tx *gorm.DB, project model.Project, subject string, now time.Time) (model.Principal, error) {
	if subject == "" {
		return model.Principal{}, errors.New("subject is required")
	}
	v := model.Principal{
		ID:          uuid.New(),
		ProjectID:   project.ID,
		OIDCIssuer:  project.OIDCIssuer,
		OIDCSubject: subject,
		CreatedAt:   now,
	}
	if e := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "issuer"}, {Name: "subject"}},
		DoNothing: true,
	}).Create(&v).Error; e != nil {
		return model.Principal{}, e
	}
	var found model.Principal
	if e := tx.Where("issuer=? AND subject=?", project.OIDCIssuer, subject).First(&found).Error; e != nil {
		return model.Principal{}, e
	}
	return found, nil
}
