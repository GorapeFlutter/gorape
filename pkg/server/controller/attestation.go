package controller

import (
	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/gin-gonic/gin"
)

type Attestation interface {
	Capabilities(c *gin.Context)
	Attestations(c *gin.Context)
}

type attestationController struct {
	service *usecase.Service
}

func NewAttestation(service *usecase.Service) Attestation {
	return &attestationController{service: service}
}

func (rcvr *attestationController) Capabilities(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	if e := rcvr.service.RequireProject(c, x, model.PermissionAttestationRead); e != nil {
		fail(c, 403, e)
		return
	}
	c.JSON(200, gin.H{"verifiers": rcvr.service.Verifiers.Capabilities()})
}

func (rcvr *attestationController) Attestations(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	d, ok := id(c, "deviceId")
	if !ok {
		return
	}
	dev, e := rcvr.service.Store.Device(c, x.Project.ID, d)
	if e != nil {
		fail(c, 404, e)
		return
	}
	if dev.OwnerPrincipalID != x.Principal.ID {
		if e = rcvr.service.RequireProject(c, x, model.PermissionAttestationRead); e != nil {
			fail(c, 403, e)
			return
		}
	}
	v, e := rcvr.service.Store.Attestations(c, x.Project.ID, d)
	if e != nil {
		fail(c, 500, e)
		return
	}
	c.JSON(200, v)
}
