package config

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

type LoggerConfig struct {
	Component    string `json:"component" yaml:"component"`
	Service      string `json:"service" yaml:"service"`
	Level        string `json:"level" yaml:"level"`
	Structured   bool   `json:"structured" yaml:"structured"`
	EnableCaller bool   `json:"enable_caller" yaml:"enable_caller"`
	Output       string `json:"output" yaml:"output"`
}

type BaseConfig struct {
	DBConnection *gorm.DB
	YamlConfig   YamlConfig
	Logger       interface{}
}
type YamlConfig struct {
	Application Application  `yaml:"Application"`
	PostgreSQL  PostgreSQL   `yaml:"PostgreSQL"`
	Redis       Redis        `yaml:"Redis"`
	Logger      LoggerConfig `yaml:"Logger"`
}

type Redis struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	User string `yaml:"user"`
	Pass string `yaml:"pass"`
	DB   int    `yaml:"db"`
}
type RedisConfig struct {
	ChallengePrefix string `yaml:"challenge_prefix"`
}
type OIDCConfig struct {
	Audience       string            `yaml:"audience"`
	RequiredScopes []string          `yaml:"required_scopes"`
	ProviderURLs   map[string]string `yaml:"provider_urls"`
}
type AttestationConfig struct {
	AndroidTrustAnchors []string `yaml:"android_trust_anchors"`
}
type Server struct {
	Port             int               `yaml:"port"`
	LogLevel         string            `yaml:"log_level"`
	Redis            RedisConfig       `yaml:"redis"`
	OIDC             OIDCConfig        `yaml:"oidc"`
	ChallengeTTL     time.Duration     `yaml:"-"`
	ChallengeTTLText string            `yaml:"challenge_ttl"`
	Attestation      AttestationConfig `yaml:"attestation"`
}
type ClientOIDCConfig struct {
	IssuerURL   string   `yaml:"issuer_url"`
	ClientID    string   `yaml:"client_id"`
	RedirectURL string   `yaml:"redirect_url"`
	Scopes      []string `yaml:"scopes"`
}
type Client struct {
	ServerEndpoint string           `yaml:"ServerEndpoint"`
	OIDC           ClientOIDCConfig `yaml:"oidc"`
}
type Application struct {
	Server Server `yaml:"Server"`
	Client Client `yaml:"Client"`
}

func NewBaseConfig() *BaseConfig   { return NewBaseConfigWithContext(context.Background()) }
func NewClientConfig() *BaseConfig { return NewBaseConfig() }

func NewBaseConfigWithContext(ctx context.Context) *BaseConfig {
	var cfg YamlConfig
	if os.Getenv("USE_SECRETSMANAGER") == "true" {
		secretID, local := GetConfigFromEnv()
		if secretID != "" {
			loaded, err := LoadConfigFromSecretsManager(ctx, secretID, local)
			if err == nil {
				cfg = *loaded
				return finishConfig(cfg)
			}
			log.Printf("configuration: Secrets Manager unavailable, using file: %v", err)
		}
	}
	path := os.Getenv("CONFIG_FILE")
	if path == "" {
		path = "etc/server.yaml"
	}
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("configuration: open %s: %v", path, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		log.Fatalf("configuration: read %s: %v", path, err)
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("configuration: parse %s: %v", path, err)
	}
	return finishConfig(cfg)
}

func finishConfig(cfg YamlConfig) *BaseConfig {
	if cfg.Application.Server.Port == 0 {
		cfg.Application.Server.Port = 8000
	}
	if cfg.Application.Server.ChallengeTTLText == "" {
		cfg.Application.Server.ChallengeTTLText = "5m"
	}
	ttl, err := time.ParseDuration(cfg.Application.Server.ChallengeTTLText)
	if err != nil || ttl < time.Minute || ttl > 15*time.Minute {
		log.Fatalf("configuration: challenge_ttl must be between 1m and 15m")
	}
	cfg.Application.Server.ChallengeTTL = ttl
	if cfg.Application.Server.Redis.ChallengePrefix == "" {
		cfg.Application.Server.Redis.ChallengePrefix = "gorape:challenge:"
	}
	if cfg.Logger.Component == "" {
		cfg.Logger.Component = "gorape"
	}
	if cfg.Logger.Service == "" {
		cfg.Logger.Service = "gorape"
	}
	if cfg.Logger.Level == "" {
		cfg.Logger.Level = "INFO"
	}
	if cfg.Logger.Output == "" {
		cfg.Logger.Output = "stdout"
	}
	return &BaseConfig{YamlConfig: cfg}
}

func NewBaseConfigFromSource(ctx context.Context) *BaseConfig {
	switch os.Getenv("CONFIG_SOURCE") {
	case "", "localfile":
		os.Setenv("USE_SECRETSMANAGER", "false")
	case "secretsmanager":
		os.Setenv("USE_SECRETSMANAGER", "true")
	default:
		log.Fatal(fmt.Errorf("invalid CONFIG_SOURCE"))
	}
	return NewBaseConfigWithContext(ctx)
}
