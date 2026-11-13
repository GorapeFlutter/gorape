package controller

import (
	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/request"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/gin-gonic/gin"
)

type Assignment interface {
	GroupDevices(c *gin.Context)
	BindDevice(c *gin.Context)
	UnbindDevice(c *gin.Context)
}

type assignmentController struct {
	service *usecase.Service
}

func NewAssignment(service *usecase.Service) Assignment {
	return &assignmentController{service: service}
}

func (rcvr *assignmentController) GroupDevices(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	g, ok := id(c, "groupId")
	if !ok {
		return
	}
	if e := rcvr.service.RequireGroup(c, x, g, model.RoleViewer); e != nil {
		fail(c, 403, e)
		return
	}
	v, e := rcvr.service.Store.GroupDevices(c, x.Project.ID, g)
	if e != nil {
		fail(c, 500, e)
		return
	}
	c.JSON(200, v)
}

func (rcvr *assignmentController) BindDevice(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	g, ok := id(c, "groupId")
	if !ok {
		return
	}
	if e := rcvr.service.RequireGroup(c, x, g, model.RoleEditor); e != nil {
		fail(c, 403, e)
		return
	}
	var q request.DeviceGroupCreate
	if !bind(c, &q) {
		return
	}
	d, e := repository.ParseUUID(q.DeviceID)
	if e != nil {
		fail(c, 400, e)
		return
	}
	if _, e = rcvr.service.Store.Device(c, x.Project.ID, d); e != nil {
		fail(c, 404, e)
		return
	}
	if e = rcvr.service.Store.BindDevice(c, x.Project.ID, g, d); e != nil {
		fail(c, 400, e)
		return
	}
	c.Status(204)
}

func (rcvr *assignmentController) UnbindDevice(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	g, ok := id(c, "groupId")
	if !ok {
		return
	}
	d, ok := id(c, "deviceId")
	if !ok {
		return
	}
	if e := rcvr.service.RequireGroup(c, x, g, model.RoleEditor); e != nil {
		fail(c, 403, e)
		return
	}
	if e := rcvr.service.Store.UnbindDevice(c, x.Project.ID, g, d); e != nil {
		fail(c, 400, e)
		return
	}
	c.Status(204)
}
