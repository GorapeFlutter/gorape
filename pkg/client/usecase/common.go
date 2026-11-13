package usecase

import (
	"encoding/json"

	"github.com/Gorapeflutter/gorape/pkg/client/repository"
)

type APIInterface interface {
	Project
	Group
	Device
}

type API struct {
	repo    *repository.API
	project Project
	group   Group
	device  Device
}

func NewAPI(r *repository.API) *API {
	return &API{
		repo:    r,
		project: NewProject(r),
		group:   NewGroup(r),
		device:  NewDevice(r),
	}
}

// Project delegation
func (rcvr *API) ListProjects() (json.RawMessage, error) {
	return rcvr.project.ListProjects()
}

// Group delegation
func (rcvr *API) ListGroups(project string) (json.RawMessage, error) {
	return rcvr.group.ListGroups(project)
}
func (rcvr *API) CreateGroup(project, slug, name string) (json.RawMessage, error) {
	return rcvr.group.CreateGroup(project, slug, name)
}

// Device delegation
func (rcvr *API) ListDevices(project string) (json.RawMessage, error) {
	return rcvr.device.ListDevices(project)
}
func (rcvr *API) RevokeDevice(project, device string) (json.RawMessage, error) {
	return rcvr.device.RevokeDevice(project, device)
}
