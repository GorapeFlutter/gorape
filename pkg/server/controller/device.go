package controller

import (
	"errors"
	"net/http"

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
	PasskeyRegistrationOptions(c *gin.Context)
	PasskeyRegistrationVerify(c *gin.Context)
	ProofChallenge(c *gin.Context)
	ProofVerify(c *gin.Context)
	PasskeyAuthenticationOptions(c *gin.Context)
	PasskeyAuthenticationVerify(c *gin.Context)
	BrowserPasskeyOptions(c *gin.Context)
	BrowserPasskeyRegistrationVerify(c *gin.Context)
	BrowserPasskeyAuthenticationVerify(c *gin.Context)
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

func (rcvr *deviceController) PasskeyRegistrationOptions(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	var q request.PasskeyRegistrationOptions
	if !bind(c, &q) {
		return
	}
	v, err := rcvr.service.PasskeyRegistrationOptions(c, x, q)
	if err != nil {
		failPasskey(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(201, v)
}

func (rcvr *deviceController) PasskeyRegistrationVerify(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	var q request.PasskeyRegistrationVerify
	if !bindWebAuthnCredential(c, &q) {
		return
	}
	v, err := rcvr.service.VerifyPasskeyRegistration(c, x, q)
	if err != nil {
		failPasskey(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
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

func (rcvr *deviceController) PasskeyAuthenticationOptions(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	d, ok := id(c, "deviceId")
	if !ok {
		return
	}
	var q request.PasskeyAuthenticationOptions
	if !bind(c, &q) {
		return
	}
	v, err := rcvr.service.PasskeyAuthenticationOptions(c, x, d, q)
	if err != nil {
		failPasskey(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(201, v)
}

func (rcvr *deviceController) PasskeyAuthenticationVerify(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	d, ok := id(c, "deviceId")
	if !ok {
		return
	}
	var q request.PasskeyAuthenticationVerify
	if !bindWebAuthnCredential(c, &q) {
		return
	}
	if err := rcvr.service.VerifyPasskeyAuthentication(c, x, d, q); err != nil {
		failPasskeyAssertion(c, err)
		return
	}
	c.JSON(200, gin.H{"status": "verified"})
}

// BrowserPasskeyOptions is unauthenticated because the short-lived challenge
// ID is a bearer capability handed to the browser fragment by the app.
func (rcvr *deviceController) BrowserPasskeyOptions(c *gin.Context) {
	var q request.BrowserPasskeyOptions
	if !bind(c, &q) {
		return
	}
	v, err := rcvr.service.PasskeyBrowserOptions(c, q.ChallengeID)
	if err != nil {
		failPasskey(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, v)
}

// BrowserPasskeyRegistrationVerify consumes the single-use browser capability.
func (rcvr *deviceController) BrowserPasskeyRegistrationVerify(c *gin.Context) {
	var q request.BrowserPasskeyRegistrationVerify
	if !bindWebAuthnCredential(c, &q) {
		return
	}
	v, err := rcvr.service.VerifyBrowserPasskeyRegistration(c, q)
	if err != nil {
		failPasskey(c, err)
		return
	}
	c.JSON(201, v)
}

func (rcvr *deviceController) BrowserPasskeyAuthenticationVerify(c *gin.Context) {
	var q request.BrowserPasskeyAuthenticationVerify
	if !bindWebAuthnCredential(c, &q) {
		return
	}
	if err := rcvr.service.VerifyBrowserPasskeyAuthentication(c, q); err != nil {
		failPasskeyAssertion(c, err)
		return
	}
	c.JSON(200, gin.H{"status": "verified"})
}

func bindWebAuthnCredential(c *gin.Context, value any) bool {
	const maxCredentialResponseBytes = 1 << 20
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxCredentialResponseBytes)
	return bind(c, value)
}

func failPasskey(c *gin.Context, err error) {
	status := 422
	switch {
	case errors.Is(err, usecase.ErrPasskeyUnavailable):
		status = 503
	case errors.Is(err, usecase.ErrForbidden):
		status = 403
	case errors.Is(err, repository.ErrChallengeInvalid):
		status = 401
	}
	fail(c, status, err)
}

func failPasskeyAssertion(c *gin.Context, err error) {
	status := 401
	switch {
	case errors.Is(err, usecase.ErrPasskeyUnavailable):
		status = 503
	case errors.Is(err, usecase.ErrForbidden):
		status = 403
	}
	fail(c, status, err)
}
