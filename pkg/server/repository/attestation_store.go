package repository

import (
	"context"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/global"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AttestationStore interface {
	Attestations(ctx context.Context, project, device uuid.UUID) ([]model.Attestation, error)
	UpdateAttestationEvaluation(ctx context.Context, project, id uuid.UUID, assurance, status string, evaluatedAt time.Time) error
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
		v[i].AssuranceLevel = v[i].EffectiveAssuranceLevel(v[i].BackupEligible)
	}
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNAS2, "Attestations done", map[string]interface{}{"count": len(v), "error": e})
	}
	return v, e
}

// Persists the re-evaluated assurance and metadata status.
func (rcvr *attestationRepository) UpdateAttestationEvaluation(ctx context.Context, project, id uuid.UUID, assurance, status string, evaluatedAt time.Time) error {
	result := rcvr.db.WithContext(ctx).Model(&model.Attestation{}).
		Where("project_id=? AND id=?", project, id).
		Updates(map[string]any{
			"assurance_level":     assurance,
			"verification_status": status,
			"last_evaluated_at":   evaluatedAt,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrNotFound
	}
	return nil
}
