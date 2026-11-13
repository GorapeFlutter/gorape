package controller

import (
	"net/http"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/gin-gonic/gin"
)

type Project interface {
	ListProjects(c *gin.Context)
	GetProject(c *gin.Context)
}

type projectController struct {
	service *usecase.Service
}

func NewProject(service *usecase.Service) Project {
	return &projectController{service: service}
}

func (rcvr *projectController) ListProjects(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	if e := rcvr.service.RequireProject(c, x, model.RoleViewer); e != nil {
		fail(c, http.StatusForbidden, e)
		return
	}
	c.JSON(http.StatusOK, []model.ProjectDomain{x.Project})
}

func (rcvr *projectController) GetProject(c *gin.Context) {
	x, ok := auth(c)
	if !ok {
		return
	}
	if e := rcvr.service.RequireProject(c, x, model.RoleViewer); e != nil {
		fail(c, http.StatusForbidden, e)
		return
	}
	c.JSON(http.StatusOK, x.Project)
}
