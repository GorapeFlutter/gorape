package controller

import (
	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/request"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/gin-gonic/gin"
)

type Role interface {
	ProjectRoles(c *gin.Context)
	PutProjectRole(c *gin.Context)
	DeleteProjectRole(c *gin.Context)
	GroupRoles(c *gin.Context)
	PutGroupRole(c *gin.Context)
	DeleteGroupRole(c *gin.Context)
}

type roleController struct {
	service *usecase.Service
}

func NewRole(service *usecase.Service) Role {
	return &roleController{service: service}
}

func (rcvr *roleController) ProjectRoles(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	if e := rcvr.service.RequireProject(c, x, model.RoleAdmin); e != nil {
		fail(c, 403, e)
		return
	}
	v, e := rcvr.service.Store.ProjectRoles(c, x.Project.ID)
	if e != nil {
		fail(c, 500, e)
		return
	}
	c.JSON(200, v)
}

func (rcvr *roleController) PutProjectRole(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	var q request.RoleCreate
	if !bind(c, &q) {
		return
	}
	if e := rcvr.service.PutProjectRole(c, x, q); e != nil {
		fail(c, 400, e)
		return
	}
	c.Status(204)
}

func (rcvr *roleController) DeleteProjectRole(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	b, ok := id(c, "bindingId")
	if !ok {
		return
	}
	if e := rcvr.service.DeleteProjectRole(c, x, b); e != nil {
		fail(c, 400, e)
		return
	}
	c.Status(204)
}

func (rcvr *roleController) GroupRoles(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	g, ok := id(c, "groupId")
	if !ok {
		return
	}
	if e := rcvr.service.RequireGroup(c, x, g, model.RoleAdmin); e != nil {
		fail(c, 403, e)
		return
	}
	v, e := rcvr.service.Store.GroupRoles(c, x.Project.ID, g)
	if e != nil {
		fail(c, 500, e)
		return
	}
	c.JSON(200, v)
}

func (rcvr *roleController) PutGroupRole(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	g, ok := id(c, "groupId")
	if !ok {
		return
	}
	var q request.RoleCreate
	if !bind(c, &q) {
		return
	}
	if e := rcvr.service.PutGroupRole(c, x, g, q); e != nil {
		fail(c, 400, e)
		return
	}
	c.Status(204)
}

func (rcvr *roleController) DeleteGroupRole(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	g, ok := id(c, "groupId")
	if !ok {
		return
	}
	b, ok := id(c, "bindingId")
	if !ok {
		return
	}
	if e := rcvr.service.DeleteGroupRole(c, x, g, b); e != nil {
		fail(c, 400, e)
		return
	}
	c.Status(204)
}
