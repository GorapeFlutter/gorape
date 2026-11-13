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

type Principal interface {
	EnsurePrincipal(ctx context.Context, project model.ProjectDomain, issuer, subject string) (model.IdentityPrincipal, error)
	PrincipalBySubject(ctx context.Context, project uuid.UUID, subject string) (model.IdentityPrincipal, error)
}

type principalRepository struct {
	db *gorm.DB
}

func NewPrincipal(db *gorm.DB) Principal {
	return &principalRepository{db: db}
}

func (rcvr *principalRepository) EnsurePrincipal(ctx context.Context, project model.ProjectDomain, issuer, subject string) (model.IdentityPrincipal, error) {
	if issuer != project.OIDCIssuer || subject == "" {
		return model.IdentityPrincipal{}, errors.New("identity does not belong to project")
	}
	v := model.IdentityPrincipal{ID: uuid.New(), ProjectID: project.ID, OIDCIssuer: issuer, OIDCSubject: subject, CreatedAt: time.Now().UTC()}
	e := rcvr.db.WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "oidc_issuer"}, {Name: "oidc_subject"}}, DoNothing: true}).Create(&v).Error
	if e != nil {
		return model.IdentityPrincipal{}, e
	}
	// The insert may have been skipped on conflict, leaving v.ID pointing at a
	// different row. Always load by the natural key into a fresh value so GORM
	// does not add v's generated primary key to the WHERE clause.
	var found model.IdentityPrincipal
	e = rcvr.db.WithContext(ctx).Where("oidc_issuer=? AND oidc_subject=?", issuer, subject).First(&found).Error
	return found, e
}

func (rcvr *principalRepository) PrincipalBySubject(ctx context.Context, project uuid.UUID, subject string) (model.IdentityPrincipal, error) {
	var v model.IdentityPrincipal
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND oidc_subject=?", project, subject).First(&v).Error
	return v, mapNotFound(e)
}
