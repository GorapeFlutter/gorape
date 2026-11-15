package repository

import (
	"context"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/global"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AttestationStore interface {
	Attestations(ctx context.Context, project, device uuid.UUID) ([]model.Attestation, error)
}

type attestationRepository struct {
	db *gorm.DB
}

func NewAttestationStore(db *gorm.DB) AttestationStore {
	return &attestationRepository{db: db}
}

func (rcvr *attestationRepository) Attestations(ctx context.Context, project, device uuid.UUID) ([]model.Attestation, error) {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNAS1, "Attestations start", map[string]interface{}{"project": project, "device": device})
	}
	var v []model.Attestation
	e := rcvr.db.WithContext(ctx).Table("attestations a").Joins("JOIN device_keys k ON k.project_id=a.project_id AND k.id=a.key_id").Where("a.project_id=? AND k.device_id=?", project, device).Order("a.verified_at DESC").Scan(&v).Error
	for i := range v {
		v[i].AssuranceLevel = v[i].EffectiveAssuranceLevel(false)
	}
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNAS2, "Attestations done", map[string]interface{}{"count": len(v), "error": e})
	}
	return v, e
}
