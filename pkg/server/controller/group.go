package controller

import (
	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/request"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/gin-gonic/gin"
)

type Group interface {
	ListGroups(c *gin.Context)
	CreateGroup(c *gin.Context)
	GetGroup(c *gin.Context)
	UpdateGroup(c *gin.Context)
	DeleteGroup(c *gin.Context)
}

type groupController struct {
	service *usecase.Service
}

func NewGroup(service *usecase.Service) Group {
	return &groupController{service: service}
}

func (rcvr *groupController) ListGroups(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	if e := rcvr.service.RequireProject(c, x, model.PermissionGroupRead); e != nil {
		fail(c, 403, e)
		return
	}
	v, e := rcvr.service.Store.Groups(c, x.Project.ID)
	if e != nil {
		fail(c, 500, e)
		return
	}
	c.JSON(200, v)
}

func (rcvr *groupController) CreateGroup(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	var q request.GroupCreate
	if !bind(c, &q) {
		return
	}
	v, e := rcvr.service.CreateGroup(c, x, q)
	if e != nil {
		fail(c, 400, e)
		return
	}
	c.JSON(201, v)
}

func (rcvr *groupController) GetGroup(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	g, ok := id(c, "groupId")
	if !ok {
		return
	}
	if e := rcvr.service.RequireGroup(c, x, g, model.PermissionGroupRead); e != nil {
		fail(c, 403, e)
		return
	}
	v, e := rcvr.service.Store.Group(c, x.Project.ID, g)
	if e != nil {
		fail(c, 404, e)
		return
	}
	c.JSON(200, v)
}

func (rcvr *groupController) UpdateGroup(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	g, ok := id(c, "groupId")
	if !ok {
		return
	}
	if e := rcvr.service.RequireProject(c, x, model.PermissionGroupManage); e != nil {
		fail(c, 403, e)
		return
	}
	var q request.GroupUpdate
	if !bind(c, &q) {
		return
	}
	if q.Status == "" {
		q.Status = "active"
	}
	v := model.Group{ID: g, ProjectID: x.Project.ID, Name: q.Name, Status: q.Status}
	if e := rcvr.service.Store.UpdateGroup(c, &v); e != nil {
		fail(c, 400, e)
		return
	}
	c.JSON(200, v)
}

func (rcvr *groupController) DeleteGroup(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	g, ok := id(c, "groupId")
	if !ok {
		return
	}
	if e := rcvr.service.RequireProject(c, x, model.PermissionGroupManage); e != nil {
		fail(c, 403, e)
		return
	}
	if e := rcvr.service.Store.DeleteGroup(c, x.Project.ID, g); e != nil {
		fail(c, 400, e)
		return
	}
	c.Status(204)
}
