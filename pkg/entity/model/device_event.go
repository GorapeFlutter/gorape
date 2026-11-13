package model

import (
	"time"

	"github.com/google/uuid"
)

// DeviceEvent はデバイス操作の監査ログ
type DeviceEvent struct {
	ID               uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ProjectID        uuid.UUID `gorm:"type:uuid;not null;index" json:"project_id"`
	DeviceID         uuid.UUID `gorm:"type:uuid;not null" json:"device_id"`
	ActorPrincipalID uuid.UUID `gorm:"type:uuid;not null" json:"actor_id"`
	EventType        string    `gorm:"not null" json:"event_type"`
	Result           string    `gorm:"not null" json:"result"`
	OccurredAt       time.Time `gorm:"not null" json:"occurred_at"`
}

func (DeviceEvent) TableName() string { return "device_events" }
