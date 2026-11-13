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
	tokens := repository.NewOIDCValidator(
		conf.YamlConfig.Application.Server.OIDC.Audience,
		conf.YamlConfig.Application.Server.OIDC.RequiredScopes,
		conf.YamlConfig.Application.Server.OIDC.ProviderURLs,
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

	// -- Controllers --
	projectCtrl := controller.NewProject(service)
	groupCtrl := controller.NewGroup(service)
	deviceCtrl := controller.NewDevice(service)
	assignmentCtrl := controller.NewAssignment(service)
	roleCtrl := controller.NewRole(service)
	attestationCtrl := controller.NewAttestation(service)

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

	router.Use(gin.Recovery(), share.RequestID(), share.RateLimit(120), loggerMW)

	// Health check (no authentication required)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"service": "gorape", "status": "ok"})
	})

	v1 := router.Group("/v1")

	// ============ Projects (Token auth by Issuer) ============
	projects := v1.Group("/projects")
	projects.Use(share.Authenticate(service, true))
	projects.GET("", projectCtrl.ListProjects)

	// ============ Project Scoped APIs ============
	p := v1.Group("/projects/:projectId")
	p.Use(share.Authenticate(service, false))

	// Projects
	p.GET("", projectCtrl.GetProject)

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
	p.POST("/devices/:deviceId/challenge", deviceCtrl.ProofChallenge)
	p.POST("/devices/:deviceId/verify", deviceCtrl.ProofVerify)

	// Group Device Assignments
	p.GET("/groups/:groupId/devices", assignmentCtrl.GroupDevices)
	p.POST("/groups/:groupId/devices", assignmentCtrl.BindDevice)
	p.DELETE("/groups/:groupId/devices/:deviceId", assignmentCtrl.UnbindDevice)

	// Roles
	p.GET("/roles", roleCtrl.ProjectRoles)
	p.POST("/roles", roleCtrl.PutProjectRole)
	p.DELETE("/roles/:bindingId", roleCtrl.DeleteProjectRole)
	p.GET("/groups/:groupId/roles", roleCtrl.GroupRoles)
	p.POST("/groups/:groupId/roles", roleCtrl.PutGroupRole)
	p.DELETE("/groups/:groupId/roles/:bindingId", roleCtrl.DeleteGroupRole)

	// Attestation
	p.GET("/attestation/capabilities", attestationCtrl.Capabilities)
	p.GET("/devices/:deviceId/attestation", attestationCtrl.Attestations)

	return router
}
