package usecase

import (
	"encoding/json"
	"net/http"

	"github.com/Gorapeflutter/gorape/pkg/client/repository"
	"github.com/Gorapeflutter/gorape/pkg/entity/provisioning"
)

type Provisioning interface {
	PlanProvisioning(m provisioning.Manifest) (json.RawMessage, error)
	ApplyProvisioning(m provisioning.Manifest) (json.RawMessage, error)
	BootstrapProject(slug, name, issuer, realm, subject string) (json.RawMessage, error)
}

type provisioningUsecase struct {
	repo repository.APIInterface
}

func NewProvisioning(repo repository.APIInterface) Provisioning {
	return &provisioningUsecase{repo: repo}
}

func (rcvr *provisioningUsecase) PlanProvisioning(m provisioning.Manifest) (json.RawMessage, error) {
	return rcvr.repo.Do(http.MethodPost, "/v1/platform/provisioning/plan", m)
}

func (rcvr *provisioningUsecase) ApplyProvisioning(m provisioning.Manifest) (json.RawMessage, error) {
	return rcvr.repo.Do(http.MethodPost, "/v1/platform/provisioning/apply", m)
}

// BootstrapProject creates a project and its first administrator through the
// server. It never connects to PostgreSQL or Keycloak directly.
func (rcvr *provisioningUsecase) BootstrapProject(slug, name, issuer, realm, subject string) (json.RawMessage, error) {
	m := provisioning.Manifest{
		APIVersion: provisioning.APIVersion,
		Kind:       provisioning.Kind,
		Gorape: &provisioning.GorapeSpec{
			Project: provisioning.ProjectSpec{Slug: slug, Name: name, Issuer: issuer, Realm: realm},
			Bindings: []provisioning.BindingSpec{
				{Subject: subject, Role: "admin"},
			},
		},
	}
	return rcvr.ApplyProvisioning(m)
}
