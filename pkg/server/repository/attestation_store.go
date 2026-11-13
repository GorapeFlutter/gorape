package repository

import (
	"context"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
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
	var v []model.Attestation
	e := rcvr.db.WithContext(ctx).Table("attestations a").Joins("JOIN device_keys k ON k.project_id=a.project_id AND k.id=a.key_id").Where("a.project_id=? AND k.device_id=?", project, device).Order("a.verified_at DESC").Scan(&v).Error
	return v, e
}
