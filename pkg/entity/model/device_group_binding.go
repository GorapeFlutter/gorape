package model

import (
	"time"

	"github.com/google/uuid"
)

// DeviceGroupBinding はデバイスとグループの紐付け
type DeviceGroupBinding struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ProjectID uuid.UUID `gorm:"type:uuid;not null;index" json:"project_id"`
	DeviceID  uuid.UUID `gorm:"type:uuid;not null" json:"device_id"`
	GroupID   uuid.UUID `gorm:"type:uuid;not null" json:"group_id"`
	Status    string    `gorm:"not null" json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

func (DeviceGroupBinding) TableName() string { return "device_group_bindings" }
