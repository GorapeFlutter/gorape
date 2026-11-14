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
	AndroidTrustAnchors []string                  `yaml:"android_trust_anchors"`
	WebAuthn            WebAuthnAttestationConfig `yaml:"webauthn"`
}
type WebAuthnAttestationConfig struct {
	AllowedFormats       []string            `yaml:"allowed_formats"`
	AllowNone            bool                `yaml:"allow_none"`
	AllowSelfAttestation bool                `yaml:"allow_self_attestation"`
	TrustAnchors         map[string][]string `yaml:"trust_anchors"`
}
type WebAuthnConfig struct {
	RPID                  string   `yaml:"rp_id"`
	RPDisplayName         string   `yaml:"rp_display_name"`
	RPOrigins             []string `yaml:"rp_origins"`
	PortalOrigin          string   `yaml:"portal_origin"`
	BrowserAPIOrigin      string   `yaml:"browser_api_origin"`
	AttestationConveyance string   `yaml:"attestation_conveyance"`
	UserVerification      string   `yaml:"user_verification"`
}
type PlatformConfig struct {
	Issuer      string   `yaml:"issuer"`
	ProviderURL string   `yaml:"provider_url"`
	AdminRoles  []string `yaml:"admin_roles"`
}
type KeycloakConfig struct {
	BaseURL      string `yaml:"base_url"`
	AuthRealm    string `yaml:"auth_realm"`
	AdminRealm   string `yaml:"admin_realm"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
}
type Server struct {
	Port             int               `yaml:"port"`
	TLSPort          int               `yaml:"tls_port"`
	TLSCertFile      string            `yaml:"tls_cert_file"`
	TLSKeyFile       string            `yaml:"tls_key_file"`
	LogLevel         string            `yaml:"log_level"`
	Redis            RedisConfig       `yaml:"redis"`
	OIDC             OIDCConfig        `yaml:"oidc"`
	ChallengeTTL     time.Duration     `yaml:"-"`
	ChallengeTTLText string            `yaml:"challenge_ttl"`
	Attestation      AttestationConfig `yaml:"attestation"`
	WebAuthn         WebAuthnConfig    `yaml:"webauthn"`
	WebOrigins       []string          `yaml:"web_origins"`
	Platform         PlatformConfig    `yaml:"platform"`
	Keycloak         KeycloakConfig    `yaml:"keycloak"`
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
	if cfg.Application.Server.TLSPort == 0 {
		cfg.Application.Server.TLSPort = 8443
	}
	if certFile := os.Getenv("GORAPE_TLS_CERT_FILE"); certFile != "" {
		cfg.Application.Server.TLSCertFile = certFile
	}
	if keyFile := os.Getenv("GORAPE_TLS_KEY_FILE"); keyFile != "" {
		cfg.Application.Server.TLSKeyFile = keyFile
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
	if len(cfg.Application.Server.Platform.AdminRoles) == 0 {
		cfg.Application.Server.Platform.AdminRoles = []string{"gorape-platform-admin"}
	}
	if cfg.Application.Server.Keycloak.AuthRealm == "" {
		cfg.Application.Server.Keycloak.AuthRealm = "master"
	}
	if cfg.Application.Server.Keycloak.AdminRealm == "" {
		cfg.Application.Server.Keycloak.AdminRealm = cfg.Application.Server.Keycloak.AuthRealm
	}
	if cfg.Application.Server.Keycloak.ClientID == "" {
		cfg.Application.Server.Keycloak.ClientID = "admin-cli"
	}
	if cfg.Application.Server.WebAuthn.RPDisplayName == "" {
		cfg.Application.Server.WebAuthn.RPDisplayName = "Gorape"
	}
	if cfg.Application.Server.WebAuthn.AttestationConveyance == "" {
		cfg.Application.Server.WebAuthn.AttestationConveyance = "direct"
	}
	if cfg.Application.Server.WebAuthn.UserVerification == "" {
		cfg.Application.Server.WebAuthn.UserVerification = "required"
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
