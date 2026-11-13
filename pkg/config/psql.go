package config

import (
	"fmt"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type PostgreSQL struct {
	Host    string `yaml:"host"`
	User    string `yaml:"user"`
	Pass    string `yaml:"pass"`
	Port    string `yaml:"port"`
	Db      string `yaml:"db"`
	SSLMode string `yaml:"sslmode"`
}

// ConnectDB connects to PostgreSQL only when needed (safe to call multiple times).
func (rcvr *BaseConfig) ConnectDB() error {
	if rcvr.DBConnection != nil {
		return nil
	}
	db := NewDBConnection(rcvr.YamlConfig)
	if db == nil {
		return fmt.Errorf("failed to connect database")
	}
	rcvr.DBConnection = db
	return nil
}

func NewDBConnection(conf YamlConfig) *gorm.DB {
	sslmode := conf.PostgreSQL.SSLMode
	if sslmode == "" {
		sslmode = "disable"
	}
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=UTC",
		conf.PostgreSQL.Host, conf.PostgreSQL.User, conf.PostgreSQL.Pass, conf.PostgreSQL.Db, conf.PostgreSQL.Port, sslmode)

	log.Printf("[C-NDBC-1] Attempting database connection to %s:%s/%s", conf.PostgreSQL.Host, conf.PostgreSQL.Port, conf.PostgreSQL.Db)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Printf("[C-NDBC-3] Failed to connect to database %s:%s/%s: %v", conf.PostgreSQL.Host, conf.PostgreSQL.Port, conf.PostgreSQL.Db, err)
		return nil
	}

	log.Printf("[C-NDBC-2] Database connection established to %s:%s/%s", conf.PostgreSQL.Host, conf.PostgreSQL.Port, conf.PostgreSQL.Db)
	return db
}
