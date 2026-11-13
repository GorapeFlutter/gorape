package controller

import (
	"errors"
	"io"
	"net/http"

	"github.com/Gorapeflutter/gorape/pkg/entity/provisioning"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

type Provisioning interface {
	PlanProvisioning(c *gin.Context)
	ApplyProvisioning(c *gin.Context)
}

type provisioningController struct {
	service *usecase.Service
}

func NewProvisioning(service *usecase.Service) Provisioning {
	return &provisioningController{service: service}
}

func (rcvr *provisioningController) PlanProvisioning(c *gin.Context) {
	rcvr.handle(c, false)
}

func (rcvr *provisioningController) ApplyProvisioning(c *gin.Context) {
	rcvr.handle(c, true)
}

func (rcvr *provisioningController) handle(c *gin.Context, apply bool) {
	x, ok := auth(c)
	if !ok {
		return
	}
	var m provisioning.Manifest
	if !bindManifest(c, &m) {
		return
	}
	var (
		result provisioning.Result
		e      error
	)
	if apply {
		result, e = rcvr.service.ApplyProvisioning(c, x, m)
	} else {
		result, e = rcvr.service.PlanProvisioning(c, x, m)
	}
	if e != nil {
		switch {
		case errors.Is(e, usecase.ErrPlatformDisabled):
			fail(c, http.StatusServiceUnavailable, e)
		case errors.Is(e, usecase.ErrForbidden):
			fail(c, http.StatusForbidden, e)
		case errors.Is(e, usecase.ErrProvisioningDisabled):
			fail(c, http.StatusServiceUnavailable, e)
		default:
			fail(c, http.StatusUnprocessableEntity, e)
		}
		return
	}
	c.JSON(http.StatusOK, result)
}

// bindManifest accepts both JSON (used by the CLI) and YAML for operators who
// prefer curl with an on-disk manifest. YAML is a JSON superset, so one parser
// handles both.
func bindManifest(c *gin.Context, m *provisioning.Manifest) bool {
	raw, e := io.ReadAll(c.Request.Body)
	if e != nil {
		fail(c, http.StatusBadRequest, e)
		return false
	}
	if e = yaml.Unmarshal(raw, m); e != nil {
		fail(c, http.StatusBadRequest, e)
		return false
	}
	return true
}
