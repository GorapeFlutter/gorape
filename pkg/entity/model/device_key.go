package model

import (
	"time"

	"github.com/google/uuid"
)

// DeviceKey はデバイスに紐づく公開鍵
type DeviceKey struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ProjectID     uuid.UUID `gorm:"type:uuid;not null;index" json:"project_id"`
	DeviceID      uuid.UUID `gorm:"type:uuid;not null" json:"device_id"`
	PublicKey     []byte    `gorm:"not null" json:"-"`
	KeyIdentifier string    `gorm:"not null" json:"key_identifier"`
	Algorithm     string    `gorm:"not null" json:"algorithm"`
	Status        string    `gorm:"not null" json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

func (DeviceKey) TableName() string { return "device_keys" }
