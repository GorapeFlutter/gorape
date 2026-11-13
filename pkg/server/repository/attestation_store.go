package repository

import (
	"context"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AttestationStore interface {
	Attestations(ctx context.Context, project, device uuid.UUID) ([]model.AttestationRecord, error)
}

type attestationRepository struct {
	db *gorm.DB
}

func NewAttestationStore(db *gorm.DB) AttestationStore {
	return &attestationRepository{db: db}
}

func (rcvr *attestationRepository) Attestations(ctx context.Context, project, device uuid.UUID) ([]model.AttestationRecord, error) {
	var v []model.AttestationRecord
	e := rcvr.db.WithContext(ctx).Table("attestation_records a").Joins("JOIN device_keys k ON k.project_id=a.project_id AND k.id=a.device_key_id").Where("a.project_id=? AND k.device_id=?", project, device).Order("a.verified_at DESC").Scan(&v).Error
	return v, e
}
