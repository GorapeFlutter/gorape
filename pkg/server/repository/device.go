package repository

import (
	"context"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/global"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Device interface {
	Devices(ctx context.Context, project uuid.UUID) ([]model.Device, error)
	Device(ctx context.Context, project, id uuid.UUID) (model.Device, error)
	DeviceKey(ctx context.Context, project, device uuid.UUID) (model.DeviceKey, error)
	UpdateCredentialData(ctx context.Context, project, device uuid.UUID, data []byte) error
	RegisterDevice(ctx context.Context, d *model.Device, k *model.DeviceKey, a *model.Attestation, actor uuid.UUID) error
	RevokeDevice(ctx context.Context, project, id, actor uuid.UUID) error
	MarkDeviceVerified(ctx context.Context, project, id, actor uuid.UUID) error
	GroupDevices(ctx context.Context, project, group uuid.UUID) ([]model.Device, error)
	BindDevice(ctx context.Context, project, group, device uuid.UUID) error
	UnbindDevice(ctx context.Context, project, group, device uuid.UUID) error
	DeviceGroupIDs(ctx context.Context, project, device uuid.UUID) ([]uuid.UUID, error)
}

type deviceRepository struct {
	db *gorm.DB
}

func NewDevice(db *gorm.DB) Device {
	return &deviceRepository{db: db}
}

func (rcvr *deviceRepository) Devices(ctx context.Context, project uuid.UUID) ([]model.Device, error) {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNDR1, "Devices start", map[string]interface{}{"project": project})
	}
	var v []model.Device
	e := rcvr.db.WithContext(ctx).Where("project_id=?", project).Order("registered_at DESC").Find(&v).Error
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNDR2, "Devices done", map[string]interface{}{"count": len(v), "error": e})
	}
	return v, e
}

func (rcvr *deviceRepository) Device(ctx context.Context, project, id uuid.UUID) (model.Device, error) {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNDR3, "Device start", map[string]interface{}{"project": project, "id": id})
	}
	var v model.Device
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND id=?", project, id).First(&v).Error
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNDR4, "Device not found or error", map[string]interface{}{"error": e})
		}
	}
	return v, mapNotFound(e)
}

func (rcvr *deviceRepository) DeviceKey(ctx context.Context, project, device uuid.UUID) (model.DeviceKey, error) {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNDR5, "DeviceKey start", map[string]interface{}{"project": project, "device": device})
	}
	var v model.DeviceKey
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND device_id=? AND status='active'", project, device).Order("created_at DESC").First(&v).Error
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNDR6, "DeviceKey not found or error", map[string]interface{}{"error": e})
		}
	}
	return v, mapNotFound(e)
}

func (rcvr *deviceRepository) UpdateCredentialData(ctx context.Context, project, device uuid.UUID, data []byte) error {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNDR7, "UpdateCredentialData start", map[string]interface{}{"project": project, "device": device})
	}
	result := rcvr.db.WithContext(ctx).Model(&model.DeviceKey{}).
		Where("project_id=? AND device_id=? AND status='active'", project, device).
		Update("credential_data", data)
	if result.Error != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNDR8, "UpdateCredentialData error", map[string]interface{}{"error": result.Error})
		}
		return result.Error
	}
	if result.RowsAffected != 1 {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNDR9, "UpdateCredentialData not found", nil)
		}
		return ErrNotFound
	}
	return nil
}

func (rcvr *deviceRepository) RegisterDevice(ctx context.Context, d *model.Device, k *model.DeviceKey, a *model.Attestation, actor uuid.UUID) error {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNDR10, "RegisterDevice start", map[string]interface{}{"actor": actor})
	}
	e := rcvr.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNDR11, "RegisterDevice error", map[string]interface{}{"error": e})
		}
	}
	return e
}

func (rcvr *deviceRepository) RevokeDevice(ctx context.Context, project, id, actor uuid.UUID) error {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNDR12, "RevokeDevice start", map[string]interface{}{"project": project, "id": id})
	}
	e := rcvr.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNDR13, "RevokeDevice error", map[string]interface{}{"error": e})
		}
	}
	return e
}

func (rcvr *deviceRepository) MarkDeviceVerified(ctx context.Context, project, id, actor uuid.UUID) error {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNDR14, "MarkDeviceVerified start", map[string]interface{}{"project": project, "id": id})
	}
	e := rcvr.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNDR15, "MarkDeviceVerified error", map[string]interface{}{"error": e})
		}
	}
	return e
}

func (rcvr *deviceRepository) GroupDevices(ctx context.Context, project, group uuid.UUID) ([]model.Device, error) {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNDR16, "GroupDevices start", map[string]interface{}{"project": project, "group": group})
	}
	var v []model.Device
	e := rcvr.db.WithContext(ctx).Table("devices d").Select("d.*").Joins("JOIN device_group_bindings b ON b.project_id=d.project_id AND b.device_id=d.id").Where("d.project_id=? AND b.group_id=? AND b.status='active'", project, group).Scan(&v).Error
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNDR17, "GroupDevices done", map[string]interface{}{"count": len(v), "error": e})
	}
	return v, e
}

func (rcvr *deviceRepository) BindDevice(ctx context.Context, project, group, device uuid.UUID) error {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNDR18, "BindDevice start", map[string]interface{}{"project": project, "group": group, "device": device})
	}
	v := model.DeviceGroupBinding{ID: uuid.New(), ProjectID: project, GroupID: group, DeviceID: device, Status: "active", CreatedAt: time.Now().UTC()}
	e := rcvr.db.WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "project_id"}, {Name: "device_id"}, {Name: "group_id"}}, DoUpdates: clause.AssignmentColumns([]string{"status"})}).Create(&v).Error
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNDR19, "BindDevice error", map[string]interface{}{"error": e})
		}
	}
	return e
}

func (rcvr *deviceRepository) UnbindDevice(ctx context.Context, project, group, device uuid.UUID) error {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNDR20, "UnbindDevice start", map[string]interface{}{"project": project, "group": group, "device": device})
	}
	e := rcvr.db.WithContext(ctx).Where("project_id=? AND group_id=? AND device_id=?", project, group, device).Delete(&model.DeviceGroupBinding{}).Error
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNDR21, "UnbindDevice error", map[string]interface{}{"error": e})
		}
	}
	return e
}

func (rcvr *deviceRepository) DeviceGroupIDs(ctx context.Context, project, device uuid.UUID) ([]uuid.UUID, error) {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNDR22, "DeviceGroupIDs start", map[string]interface{}{"project": project, "device": device})
	}
	var v []uuid.UUID
	e := rcvr.db.WithContext(ctx).Model(&model.DeviceGroupBinding{}).
		Where("project_id=? AND device_id=? AND status='active'", project, device).
		Pluck("group_id", &v).Error
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNDR23, "DeviceGroupIDs done", map[string]interface{}{"count": len(v), "error": e})
	}
	return v, e
}
