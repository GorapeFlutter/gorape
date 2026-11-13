package usecase

import (
	"encoding/json"

	"github.com/Gorapeflutter/gorape/pkg/client/repository"
	"github.com/Gorapeflutter/gorape/pkg/entity/provisioning"
)

type APIInterface interface {
	Project
	Group
	Device
	Provisioning
}

type API struct {
	repo         *repository.API
	project      Project
	group        Group
	device       Device
	provisioning Provisioning
}

func NewAPI(r *repository.API) *API {
	return &API{
		repo:         r,
		project:      NewProject(r),
		group:        NewGroup(r),
		device:       NewDevice(r),
		provisioning: NewProvisioning(r),
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

// Provisioning delegation
func (rcvr *API) PlanProvisioning(m provisioning.Manifest) (json.RawMessage, error) {
	return rcvr.provisioning.PlanProvisioning(m)
}
func (rcvr *API) ApplyProvisioning(m provisioning.Manifest) (json.RawMessage, error) {
	return rcvr.provisioning.ApplyProvisioning(m)
}
func (rcvr *API) BootstrapProject(slug, name, issuer, realm, subject string) (json.RawMessage, error) {
	return rcvr.provisioning.BootstrapProject(slug, name, issuer, realm, subject)
}
