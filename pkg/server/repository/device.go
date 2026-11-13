package repository

import (
	"context"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Device interface {
	Devices(ctx context.Context, project uuid.UUID) ([]model.Device, error)
	Device(ctx context.Context, project, id uuid.UUID) (model.Device, error)
	DeviceKey(ctx context.Context, project, device uuid.UUID) (model.DeviceKey, error)
	RegisterDevice(ctx context.Context, d *model.Device, k *model.DeviceKey, a *model.AttestationRecord, actor uuid.UUID) error
	RevokeDevice(ctx context.Context, project, id, actor uuid.UUID) error
	MarkDeviceVerified(ctx context.Context, project, id, actor uuid.UUID) error
	GroupDevices(ctx context.Context, project, group uuid.UUID) ([]model.Device, error)
	BindDevice(ctx context.Context, project, group, device uuid.UUID) error
	UnbindDevice(ctx context.Context, project, group, device uuid.UUID) error
}

type deviceRepository struct {
	db *gorm.DB
}

func NewDevice(db *gorm.DB) Device {
	return &deviceRepository{db: db}
}

func (rcvr *deviceRepository) Devices(ctx context.Context, project uuid.UUID) ([]model.Device, error) {
	var v []model.Device
	e := rcvr.db.WithContext(ctx).Where("project_id=?", project).Order("registered_at DESC").Find(&v).Error
	return v, e
}

func (rcvr *deviceRepository) Device(ctx context.Context, project, id uuid.UUID) (model.Device, error) {
	var v model.Device
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND id=?", project, id).First(&v).Error
	return v, mapNotFound(e)
}

func (rcvr *deviceRepository) DeviceKey(ctx context.Context, project, device uuid.UUID) (model.DeviceKey, error) {
	var v model.DeviceKey
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND device_id=? AND status='active'", project, device).Order("created_at DESC").First(&v).Error
	return v, mapNotFound(e)
}

func (rcvr *deviceRepository) RegisterDevice(ctx context.Context, d *model.Device, k *model.DeviceKey, a *model.AttestationRecord, actor uuid.UUID) error {
	return rcvr.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		d.ID = uuid.New()
		d.RegisteredAt = now
		d.LastVerifiedAt = &now
		d.Status = "active"
		d.Version = 1
		if e := tx.Create(d).Error; e != nil {
			return e
		}
		k.ID = uuid.New()
		k.ProjectID = d.ProjectID
		k.DeviceID = d.ID
		k.Status = "active"
		k.CreatedAt = now
		if e := tx.Create(k).Error; e != nil {
			return e
		}
		a.ID = uuid.New()
		a.ProjectID = d.ProjectID
		a.DeviceKeyID = k.ID
		a.VerifiedAt = now
		if e := tx.Create(a).Error; e != nil {
			return e
		}
		return tx.Create(&model.DeviceEvent{ID: uuid.New(), ProjectID: d.ProjectID, DeviceID: d.ID, ActorPrincipalID: actor, EventType: "registered", Result: "success", OccurredAt: now}).Error
	})
}

func (rcvr *deviceRepository) RevokeDevice(ctx context.Context, project, id, actor uuid.UUID) error {
	return rcvr.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		r := tx.Model(&model.Device{}).Where("project_id=? AND id=? AND status='active'", project, id).Updates(map[string]any{"status": "revoked", "revoked_at": now, "version": gorm.Expr("version + 1")})
		if r.Error != nil {
			return r.Error
		}
		if r.RowsAffected != 1 {
			return ErrNotFound
		}
		return tx.Create(&model.DeviceEvent{ID: uuid.New(), ProjectID: project, DeviceID: id, ActorPrincipalID: actor, EventType: "revoked", Result: "success", OccurredAt: now}).Error
	})
}

func (rcvr *deviceRepository) MarkDeviceVerified(ctx context.Context, project, id, actor uuid.UUID) error {
	return rcvr.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		r := tx.Model(&model.Device{}).Where("project_id=? AND id=? AND status='active'", project, id).Update("last_verified_at", now)
		if r.Error != nil {
			return r.Error
		}
		if r.RowsAffected != 1 {
			return ErrNotFound
		}
		return tx.Create(&model.DeviceEvent{ID: uuid.New(), ProjectID: project, DeviceID: id, ActorPrincipalID: actor, EventType: "proof_verified", Result: "success", OccurredAt: now}).Error
	})
}

func (rcvr *deviceRepository) GroupDevices(ctx context.Context, project, group uuid.UUID) ([]model.Device, error) {
	var v []model.Device
	e := rcvr.db.WithContext(ctx).Table("devices d").Select("d.*").Joins("JOIN device_group_bindings b ON b.project_id=d.project_id AND b.device_id=d.id").Where("d.project_id=? AND b.group_id=? AND b.status='active'", project, group).Scan(&v).Error
	return v, e
}

func (rcvr *deviceRepository) BindDevice(ctx context.Context, project, group, device uuid.UUID) error {
	v := model.DeviceGroupBinding{ID: uuid.New(), ProjectID: project, GroupID: group, DeviceID: device, Status: "active", CreatedAt: time.Now().UTC()}
	return rcvr.db.WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "project_id"}, {Name: "device_id"}, {Name: "group_id"}}, DoUpdates: clause.AssignmentColumns([]string{"status"})}).Create(&v).Error
}

func (rcvr *deviceRepository) UnbindDevice(ctx context.Context, project, group, device uuid.UUID) error {
	return rcvr.db.WithContext(ctx).Where("project_id=? AND group_id=? AND device_id=?", project, group, device).Delete(&model.DeviceGroupBinding{}).Error
}
