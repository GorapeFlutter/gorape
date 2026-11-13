package controller

import (
	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/request"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/gin-gonic/gin"
)

type Role interface {
	Permissions(c *gin.Context)
	ProjectRoles(c *gin.Context)
	ProjectRoleDefinitions(c *gin.Context)
	PutRoleDefinition(c *gin.Context)
	DeleteRoleDefinition(c *gin.Context)
	PutProjectRole(c *gin.Context)
	DeleteBinding(c *gin.Context)
	GroupRoles(c *gin.Context)
	PutGroupRole(c *gin.Context)
}

type roleController struct {
	service *usecase.Service
}

func NewRole(service *usecase.Service) Role {
	return &roleController{service: service}
}

// Permissions returns the caller's effective project permissions. This is the
// same evaluation used by authorization checks, which lets the CLI and UI
// explain why an action is or is not allowed.
func (rcvr *roleController) Permissions(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	set, roles, e := rcvr.service.EffectivePermissions(c, x, nil)
	if e != nil {
		fail(c, 500, e)
		return
	}
	c.JSON(200, gin.H{"permissions": set.Slice(), "roles": roles})
}

func (rcvr *roleController) ProjectRoles(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	if e := rcvr.service.RequireProject(c, x, model.PermissionRoleRead); e != nil {
		fail(c, 403, e)
		return
	}
	definitions, e := rcvr.service.Store.RoleDefinitions(c, x.Project.ID)
	if e != nil {
		fail(c, 500, e)
		return
	}
	bindings, e := rcvr.service.Store.ProjectRoleBindings(c, x.Project.ID)
	if e != nil {
		fail(c, 500, e)
		return
	}
	c.JSON(200, gin.H{"definitions": definitions, "bindings": bindings})
}

func (rcvr *roleController) ProjectRoleDefinitions(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	if e := rcvr.service.RequireProject(c, x, model.PermissionRoleRead); e != nil {
		fail(c, 403, e)
		return
	}
	v, e := rcvr.service.Store.RoleDefinitions(c, x.Project.ID)
	if e != nil {
		fail(c, 500, e)
		return
	}
	c.JSON(200, v)
}

func (rcvr *roleController) PutRoleDefinition(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	var q request.RoleDefinitionPut
	if !bind(c, &q) {
		return
	}
	v, e := rcvr.service.PutRoleDefinition(c, x, c.Param("key"), q)
	if e != nil {
		fail(c, 400, e)
		return
	}
	c.JSON(200, v)
}

func (rcvr *roleController) DeleteRoleDefinition(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	if e := rcvr.service.DeleteRoleDefinition(c, x, c.Param("key")); e != nil {
		fail(c, 400, e)
		return
	}
	c.Status(204)
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

func (rcvr *roleController) DeleteBinding(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	b, ok := id(c, "bindingId")
	if !ok {
		return
	}
	if e := rcvr.service.DeleteRoleBinding(c, x, b); e != nil {
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
	if e := rcvr.service.RequireGroup(c, x, g, model.PermissionRoleRead); e != nil {
		fail(c, 403, e)
		return
	}
	v, e := rcvr.service.Store.GroupRoleBindings(c, x.Project.ID, g)
	if e != nil {
		fail(c, 500, e)
		return
	}
	c.JSON(200, gin.H{"bindings": v})
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
