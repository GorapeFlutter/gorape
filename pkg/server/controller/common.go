package controller

import (
	"errors"
	"net/http"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/Gorapeflutter/gorape/pkg/server/share"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type APIInterface interface {
	Project
	Group
	Device
	Assignment
	Role
	Attestation
	Provisioning
}

type API struct {
	service      *usecase.Service
	project      Project
	group        Group
	device       Device
	assignment   Assignment
	role         Role
	attestation  Attestation
	provisioning Provisioning
}

func NewAPI(s *usecase.Service) *API {
	return &API{
		service:      s,
		project:      NewProject(s),
		group:        NewGroup(s),
		device:       NewDevice(s),
		assignment:   NewAssignment(s),
		role:         NewRole(s),
		attestation:  NewAttestation(s),
		provisioning: NewProvisioning(s),
	}
}

// Project delegation
func (rcvr *API) ListProjects(c *gin.Context) { rcvr.project.ListProjects(c) }
func (rcvr *API) GetProject(c *gin.Context)   { rcvr.project.GetProject(c) }

// Group delegation
func (rcvr *API) ListGroups(c *gin.Context)  { rcvr.group.ListGroups(c) }
func (rcvr *API) CreateGroup(c *gin.Context) { rcvr.group.CreateGroup(c) }
func (rcvr *API) GetGroup(c *gin.Context)    { rcvr.group.GetGroup(c) }
func (rcvr *API) UpdateGroup(c *gin.Context) { rcvr.group.UpdateGroup(c) }
func (rcvr *API) DeleteGroup(c *gin.Context) { rcvr.group.DeleteGroup(c) }

// Device delegation
func (rcvr *API) ListDevices(c *gin.Context)           { rcvr.device.ListDevices(c) }
func (rcvr *API) GetDevice(c *gin.Context)             { rcvr.device.GetDevice(c) }
func (rcvr *API) RevokeDevice(c *gin.Context)          { rcvr.device.RevokeDevice(c) }
func (rcvr *API) RegistrationChallenge(c *gin.Context) { rcvr.device.RegistrationChallenge(c) }
func (rcvr *API) RegistrationVerify(c *gin.Context)    { rcvr.device.RegistrationVerify(c) }
func (rcvr *API) ProofChallenge(c *gin.Context)        { rcvr.device.ProofChallenge(c) }
func (rcvr *API) ProofVerify(c *gin.Context)           { rcvr.device.ProofVerify(c) }

// Assignment delegation
func (rcvr *API) GroupDevices(c *gin.Context) { rcvr.assignment.GroupDevices(c) }
func (rcvr *API) BindDevice(c *gin.Context)   { rcvr.assignment.BindDevice(c) }
func (rcvr *API) UnbindDevice(c *gin.Context) { rcvr.assignment.UnbindDevice(c) }

// Role delegation
func (rcvr *API) Permissions(c *gin.Context)            { rcvr.role.Permissions(c) }
func (rcvr *API) ProjectRoles(c *gin.Context)           { rcvr.role.ProjectRoles(c) }
func (rcvr *API) ProjectRoleDefinitions(c *gin.Context) { rcvr.role.ProjectRoleDefinitions(c) }
func (rcvr *API) PutRoleDefinition(c *gin.Context)      { rcvr.role.PutRoleDefinition(c) }
func (rcvr *API) DeleteRoleDefinition(c *gin.Context)   { rcvr.role.DeleteRoleDefinition(c) }
func (rcvr *API) PutProjectRole(c *gin.Context)         { rcvr.role.PutProjectRole(c) }
func (rcvr *API) DeleteBinding(c *gin.Context)          { rcvr.role.DeleteBinding(c) }
func (rcvr *API) GroupRoles(c *gin.Context)             { rcvr.role.GroupRoles(c) }
func (rcvr *API) PutGroupRole(c *gin.Context)           { rcvr.role.PutGroupRole(c) }

// Attestation delegation
func (rcvr *API) Capabilities(c *gin.Context) { rcvr.attestation.Capabilities(c) }
func (rcvr *API) Attestations(c *gin.Context) { rcvr.attestation.Attestations(c) }

// Provisioning delegation
func (rcvr *API) PlanProvisioning(c *gin.Context)  { rcvr.provisioning.PlanProvisioning(c) }
func (rcvr *API) ApplyProvisioning(c *gin.Context) { rcvr.provisioning.ApplyProvisioning(c) }

func auth(c *gin.Context) (model.AuthContext, bool) {
	a, ok := share.Auth(c)
	if !ok {
		fail(c, http.StatusUnauthorized, errors.New("authentication context missing"))
	}
	return a, ok
}

func id(c *gin.Context, name string) (uuid.UUID, bool) {
	v, e := repository.ParseUUID(c.Param(name))
	if e != nil {
		fail(c, http.StatusBadRequest, e)
		return uuid.Nil, false
	}
	return v, true
}

func bind(c *gin.Context, v any) bool {
	if e := c.ShouldBindJSON(v); e != nil {
		fail(c, http.StatusBadRequest, e)
		return false
	}
	return true
}

func fail(c *gin.Context, status int, e error) {
	code := "request_failed"
	if errors.Is(e, usecase.ErrForbidden) {
		status = http.StatusForbidden
		code = "forbidden"
	}
	if errors.Is(e, repository.ErrNotFound) {
		status = http.StatusNotFound
		code = "not_found"
	}
	if errors.Is(e, repository.ErrChallengeInvalid) {
		status = http.StatusUnauthorized
		code = "challenge_invalid"
	}
	if errors.Is(e, repository.ErrUnsupportedAttestation) {
		status = http.StatusUnprocessableEntity
		code = "attestation_unsupported"
	}
	c.JSON(status, gin.H{"code": code, "message": e.Error()})
}
