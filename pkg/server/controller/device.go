package controller

import (
	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/request"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/gin-gonic/gin"
)

type Device interface {
	ListDevices(c *gin.Context)
	GetDevice(c *gin.Context)
	RevokeDevice(c *gin.Context)
	RegistrationChallenge(c *gin.Context)
	RegistrationVerify(c *gin.Context)
	ProofChallenge(c *gin.Context)
	ProofVerify(c *gin.Context)
}

type deviceController struct {
	service *usecase.Service
}

func NewDevice(service *usecase.Service) Device {
	return &deviceController{service: service}
}

func (rcvr *deviceController) ListDevices(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	if e := rcvr.service.RequireProject(c, x, model.PermissionDeviceRead); e != nil {
		fail(c, 403, e)
		return
	}
	v, e := rcvr.service.Store.Devices(c, x.Project.ID)
	if e != nil {
		fail(c, 500, e)
		return
	}
	c.JSON(200, v)
}

func (rcvr *deviceController) GetDevice(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	d, ok := id(c, "deviceId")
	if !ok {
		return
	}
	v, e := rcvr.service.Store.Device(c, x.Project.ID, d)
	if e != nil {
		fail(c, 404, e)
		return
	}
	if v.OwnerPrincipalID != x.Principal.ID {
		if e = rcvr.service.RequireProject(c, x, model.PermissionDeviceRead); e != nil {
			fail(c, 403, e)
			return
		}
	}
	c.JSON(200, v)
}

func (rcvr *deviceController) RevokeDevice(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	d, ok := id(c, "deviceId")
	if !ok {
		return
	}
	if e := rcvr.service.RequireProject(c, x, model.PermissionDeviceRevoke); e != nil {
		fail(c, 403, e)
		return
	}
	if e := rcvr.service.Store.RevokeDevice(c, x.Project.ID, d, x.Principal.ID); e != nil {
		fail(c, 400, e)
		return
	}
	c.Status(204)
}

func (rcvr *deviceController) RegistrationChallenge(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	var q request.DeviceChallenge
	if !bind(c, &q) {
		return
	}
	v, e := rcvr.service.RegistrationChallenge(c, x, q.Platform)
	if e != nil {
		fail(c, 400, e)
		return
	}
	c.JSON(201, gin.H{"challenge_id": v.ID, "challenge": repository.EncodeChallenge(v), "expires_at": v.ExpiresAt})
}

func (rcvr *deviceController) RegistrationVerify(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	var q request.RegistrationVerify
	if !bind(c, &q) {
		return
	}
	v, e := rcvr.service.VerifyRegistration(c, x, q)
	if e != nil {
		fail(c, 422, e)
		return
	}
	c.JSON(201, v)
}

func (rcvr *deviceController) ProofChallenge(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	d, ok := id(c, "deviceId")
	if !ok {
		return
	}
	v, e := rcvr.service.ProofChallenge(c, x, d)
	if e != nil {
		fail(c, 400, e)
		return
	}
	c.JSON(201, gin.H{"challenge_id": v.ID, "challenge": repository.EncodeChallenge(v), "expires_at": v.ExpiresAt})
}

func (rcvr *deviceController) ProofVerify(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	d, ok := id(c, "deviceId")
	if !ok {
		return
	}
	var q request.ProofVerify
	if !bind(c, &q) {
		return
	}
	if e := rcvr.service.VerifyProof(c, x, d, q); e != nil {
		fail(c, 401, e)
		return
	}
	c.JSON(200, gin.H{"status": "verified"})
}
