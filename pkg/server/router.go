package server

import (
	"log"
	"net/http"

	"github.com/Gorapeflutter/gorape/pkg/config"
	"github.com/Gorapeflutter/gorape/pkg/server/controller"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/Gorapeflutter/gorape/pkg/server/share"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/gin-gonic/gin"
)

func InitRouter(conf config.BaseConfig) *gin.Engine {
	// Initialize global server logger
	if logger, ok := conf.Logger.(*share.ServerLogger); ok {
		share.SetServerLogger(logger)
	}

	if logger, ok := conf.Logger.(share.LoggerInterface); ok {
		gin.DefaultWriter = share.NewGinLoggerWriter(logger)
		gin.DefaultErrorWriter = share.NewGinLoggerWriter(logger)
	}

	if conf.DBConnection == nil {
		log.Fatal("database connection is required")
	}
	if conf.YamlConfig.Application.Server.OIDC.Audience == "" {
		log.Fatal("OIDC audience is required")
	}

	// ============================================================
	// Repository / Usecase / Controller initialization
	// ============================================================

	// -- Infrastructure / Stores --
	rdb, err := config.NewRedisClient(conf.YamlConfig.Redis)
	if err != nil {
		log.Fatalf("Redis initialization failed: %v", err)
	}
	registry, err := repository.NewVerifierRegistry(conf.YamlConfig.Application.Server.Attestation.AndroidTrustAnchors)
	if err != nil {
		log.Fatalf("attestation initialization failed: %v", err)
	}
	var webAuthnRP *repository.WebAuthnRP
	webAuthnConfig := conf.YamlConfig.Application.Server.WebAuthn
	if webAuthnConfig.RPID != "" || len(webAuthnConfig.RPOrigins) != 0 {
		trustAnchors := conf.YamlConfig.Application.Server.Attestation.WebAuthn.TrustAnchors
		if trustAnchors == nil {
			trustAnchors = map[string][]string{}
		}
		if len(trustAnchors["android-key"]) == 0 {
			trustAnchors["android-key"] = conf.YamlConfig.Application.Server.Attestation.AndroidTrustAnchors
		}
		webAuthnRP, err = repository.NewWebAuthnRP(repository.WebAuthnRPConfig{
			RPID:                  webAuthnConfig.RPID,
			RPDisplayName:         webAuthnConfig.RPDisplayName,
			RPOrigins:             webAuthnConfig.RPOrigins,
			PortalOrigin:          webAuthnConfig.PortalOrigin,
			BrowserAPIOrigin:      webAuthnConfig.BrowserAPIOrigin,
			AttestationConveyance: webAuthnConfig.AttestationConveyance,
			UserVerification:      webAuthnConfig.UserVerification,
			AllowedFormats:        conf.YamlConfig.Application.Server.Attestation.WebAuthn.AllowedFormats,
			AllowNone:             conf.YamlConfig.Application.Server.Attestation.WebAuthn.AllowNone,
			AllowSelfAttestation:  conf.YamlConfig.Application.Server.Attestation.WebAuthn.AllowSelfAttestation,
			TrustAnchors:          trustAnchors,
			ChallengeTTL:          conf.YamlConfig.Application.Server.ChallengeTTL,
		})
		if err != nil {
			log.Fatalf("WebAuthn RP initialization failed: %v", err)
		}
	}
	platformCfg := conf.YamlConfig.Application.Server.Platform
	providerURLs := conf.YamlConfig.Application.Server.OIDC.ProviderURLs
	if platformCfg.Issuer != "" && platformCfg.ProviderURL != "" {
		if providerURLs == nil {
			providerURLs = map[string]string{}
		}
		providerURLs[platformCfg.Issuer] = platformCfg.ProviderURL
	}
	tokens := repository.NewOIDCValidator(
		conf.YamlConfig.Application.Server.OIDC.Audience,
		conf.YamlConfig.Application.Server.OIDC.RequiredScopes,
		providerURLs,
	)
	challenges := repository.NewRedisChallengeStore(
		rdb,
		conf.YamlConfig.Application.Server.Redis.ChallengePrefix,
		conf.YamlConfig.Application.Server.ChallengeTTL,
	)

	// -- Repositories --
	store := repository.NewStore(conf.DBConnection)

	// -- Usecases --
	service := usecase.NewService(store, tokens, challenges, registry)
	service.ConfigureWebAuthn(webAuthnRP)
	if platformCfg.Issuer != "" {
		service.ConfigurePlatform(platformCfg.Issuer, platformCfg.AdminRoles)
	}
	var keycloak repository.KeycloakProvisioner
	if conf.YamlConfig.Application.Server.Keycloak.BaseURL != "" {
		admin, e := repository.NewKeycloakAdmin(conf.YamlConfig.Application.Server.Keycloak)
		if e != nil {
			log.Fatalf("Keycloak provisioning initialization failed: %v", e)
		}
		keycloak = admin
	}
	service.ConfigureProvisioning(repository.NewProvisioning(conf.DBConnection), keycloak)

	// -- Controllers --
	projectCtrl := controller.NewProject(service)
	groupCtrl := controller.NewGroup(service)
	deviceCtrl := controller.NewDevice(service)
	assignmentCtrl := controller.NewAssignment(service)
	roleCtrl := controller.NewRole(service)
	attestationCtrl := controller.NewAttestation(service)
	provisioningCtrl := controller.NewProvisioning(service)

	// ============================================================
	// Router setup
	// ============================================================

	router := gin.New()

	var loggerMW gin.HandlerFunc
	if logger, ok := conf.Logger.(share.LoggerInterface); ok {
		loggerMW = share.LoggerWithConfig(logger)
	} else {
		loggerMW = func(c *gin.Context) { c.Next() }
	}

	webOrigins := append([]string(nil), conf.YamlConfig.Application.Server.WebOrigins...)
	if webAuthnConfig.PortalOrigin != "" {
		webOrigins = append(webOrigins, webAuthnConfig.PortalOrigin)
	}
	router.Use(gin.Recovery(), share.RequestID(), share.CORS(webOrigins), share.RateLimit(120), loggerMW)

	// Health check (no authentication required)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"service": "gorape", "status": "ok"})
	})

	v1 := router.Group("/v1")
	// Linux desktop's external-browser ceremony uses a short-lived capability
	// created by an authenticated options call, not an OIDC token in the browser.
	v1.POST("/passkeys/browser/options", deviceCtrl.BrowserPasskeyOptions)
	v1.POST("/passkeys/browser/registration/verify", deviceCtrl.BrowserPasskeyRegistrationVerify)
	v1.POST("/passkeys/browser/authentication/verify", deviceCtrl.BrowserPasskeyAuthenticationVerify)

	// ============ Projects (Token auth by Issuer) ============
	projects := v1.Group("/projects")
	projects.Use(share.Authenticate(service, true))
	projects.GET("", projectCtrl.ListProjects)

	// ============ Platform Administration (platform issuer token) ============
	platform := v1.Group("/platform")
	platform.Use(share.AuthenticatePlatform(service))
	platform.POST("/provisioning/plan", provisioningCtrl.PlanProvisioning)
	platform.POST("/provisioning/apply", provisioningCtrl.ApplyProvisioning)

	// ============ Project Scoped APIs ============
	p := v1.Group("/projects/:projectId")
	p.Use(share.Authenticate(service, false))

	// Projects
	p.GET("", projectCtrl.GetProject)
	p.GET("/permissions", roleCtrl.Permissions)

	// Groups
	p.GET("/groups", groupCtrl.ListGroups)
	p.POST("/groups", groupCtrl.CreateGroup)
	p.GET("/groups/:groupId", groupCtrl.GetGroup)
	p.PATCH("/groups/:groupId", groupCtrl.UpdateGroup)
	p.DELETE("/groups/:groupId", groupCtrl.DeleteGroup)

	// Devices
	p.GET("/devices", deviceCtrl.ListDevices)
	p.GET("/devices/:deviceId", deviceCtrl.GetDevice)
	p.DELETE("/devices/:deviceId", deviceCtrl.RevokeDevice)
	p.POST("/devices/registration/challenge", deviceCtrl.RegistrationChallenge)
	p.POST("/devices/registration/verify", deviceCtrl.RegistrationVerify)
	p.POST("/devices/passkeys/registration/options", deviceCtrl.PasskeyRegistrationOptions)
	p.POST("/devices/passkeys/registration/verify", deviceCtrl.PasskeyRegistrationVerify)
	p.POST("/devices/:deviceId/challenge", deviceCtrl.ProofChallenge)
	p.POST("/devices/:deviceId/verify", deviceCtrl.ProofVerify)
	p.POST("/devices/:deviceId/passkeys/authentication/options", deviceCtrl.PasskeyAuthenticationOptions)
	p.POST("/devices/:deviceId/passkeys/authentication/verify", deviceCtrl.PasskeyAuthenticationVerify)

	// Group Device Assignments
	p.GET("/groups/:groupId/devices", assignmentCtrl.GroupDevices)
	p.POST("/groups/:groupId/devices", assignmentCtrl.BindDevice)
	p.DELETE("/groups/:groupId/devices/:deviceId", assignmentCtrl.UnbindDevice)

	// Roles
	p.GET("/roles", roleCtrl.ProjectRoles)
	p.POST("/roles", roleCtrl.PutProjectRole)
	p.DELETE("/roles/:bindingId", roleCtrl.DeleteBinding)
	p.GET("/groups/:groupId/roles", roleCtrl.GroupRoles)
	p.POST("/groups/:groupId/roles", roleCtrl.PutGroupRole)
	p.GET("/role-definitions", roleCtrl.ProjectRoleDefinitions)
	p.PUT("/role-definitions/:key", roleCtrl.PutRoleDefinition)
	p.DELETE("/role-definitions/:key", roleCtrl.DeleteRoleDefinition)

	// Attestation
	p.GET("/attestation/capabilities", attestationCtrl.Capabilities)
	p.GET("/devices/:deviceId/attestation", attestationCtrl.Attestations)

	return router
}
