package repository

import (
	"context"
	"errors"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/global"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Principal interface {
	EnsurePrincipal(ctx context.Context, project model.Project, issuer, subject string) (model.Principal, error)
	PrincipalBySubject(ctx context.Context, project uuid.UUID, subject string) (model.Principal, error)
}

type principalRepository struct {
	db *gorm.DB
}

func NewPrincipal(db *gorm.DB) Principal {
	return &principalRepository{db: db}
}

func (rcvr *principalRepository) EnsurePrincipal(ctx context.Context, project model.Project, issuer, subject string) (model.Principal, error) {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNUPR1, "EnsurePrincipal start", map[string]interface{}{"project": project.ID, "issuer": issuer})
	}
	if issuer != project.OIDCIssuer || subject == "" {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNUPR2, "EnsurePrincipal invalid identity", nil)
		}
		return model.Principal{}, errors.New("identity does not belong to project")
	}
	v := model.Principal{ID: uuid.New(), ProjectID: project.ID, OIDCIssuer: issuer, OIDCSubject: subject, CreatedAt: time.Now().UTC()}
	e := rcvr.db.WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "issuer"}, {Name: "subject"}}, DoNothing: true}).Create(&v).Error
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNUPR3, "EnsurePrincipal create error", map[string]interface{}{"error": e})
		}
		return model.Principal{}, e
	}
	var found model.Principal
	e = rcvr.db.WithContext(ctx).Where("issuer=? AND subject=?", issuer, subject).First(&found).Error
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNUPR4, "EnsurePrincipal load error", map[string]interface{}{"error": e})
		}
	}
	return found, e
}

func (rcvr *principalRepository) PrincipalBySubject(ctx context.Context, project uuid.UUID, subject string) (model.Principal, error) {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNUPR5, "PrincipalBySubject start", map[string]interface{}{"project": project, "subject": subject})
	}
	var v model.Principal
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND subject=?", project, subject).First(&v).Error
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNUPR6, "PrincipalBySubject not found or error", map[string]interface{}{"error": e})
		}
	}
	return v, mapNotFound(e)
}
