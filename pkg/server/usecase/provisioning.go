package usecase

import (
	"context"
	"errors"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/provisioning"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
)

// ErrProvisioningDisabled is returned when the server has no Keycloak
// provisioner configured. Gorape-only manifests still work without Keycloak.
var ErrProvisioningDisabled = errors.New("keycloak provisioning is not configured")

// Provisioning plans and applies declarative manifests. Keycloak is applied
// first so that Gorape role definitions can safely reference Keycloak roles.
type Provisioning interface {
	PlanProvisioning(ctx context.Context, a model.AuthContext, m provisioning.Manifest) (provisioning.Result, error)
	ApplyProvisioning(ctx context.Context, a model.AuthContext, m provisioning.Manifest) (provisioning.Result, error)
}

type provisioningUsecase struct {
	gorape   repository.Provisioning
	keycloak repository.KeycloakProvisioner
	project  Project
}

func NewProvisioning(gorape repository.Provisioning, keycloak repository.KeycloakProvisioner, project Project) Provisioning {
	return &provisioningUsecase{gorape: gorape, keycloak: keycloak, project: project}
}

func (rcvr *provisioningUsecase) PlanProvisioning(ctx context.Context, a model.AuthContext, m provisioning.Manifest) (provisioning.Result, error) {
	if e := rcvr.project.RequirePlatform(ctx, a); e != nil {
		return provisioning.Result{}, e
	}
	if e := m.Validate(); e != nil {
		return provisioning.Result{}, e
	}
	actions := make([]provisioning.Action, 0, 16)
	if m.Gorape != nil {
		actions = append(actions, gorapePlanActions(*m.Gorape)...)
	}
	if m.Keycloak != nil {
		if rcvr.keycloak == nil {
			return provisioning.Result{}, ErrProvisioningDisabled
		}
		kcActions, e := rcvr.keycloak.Plan(ctx, *m.Keycloak)
		if e != nil {
			return provisioning.Result{}, e
		}
		// Keycloak runs first during apply, so report it first.
		actions = append(kcActions, actions...)
	}
	return provisioning.Result{Applied: false, Actions: actions}, nil
}

func (rcvr *provisioningUsecase) ApplyProvisioning(ctx context.Context, a model.AuthContext, m provisioning.Manifest) (provisioning.Result, error) {
	if e := rcvr.project.RequirePlatform(ctx, a); e != nil {
		return provisioning.Result{}, e
	}
	if e := m.Validate(); e != nil {
		return provisioning.Result{}, e
	}
	actions := make([]provisioning.Action, 0, 16)
	if m.Keycloak != nil {
		if rcvr.keycloak == nil {
			return provisioning.Result{}, ErrProvisioningDisabled
		}
		kcActions, e := rcvr.keycloak.Apply(ctx, *m.Keycloak)
		if e != nil {
			return provisioning.Result{}, e
		}
		actions = append(actions, kcActions...)
	}
	result := provisioning.Result{Applied: true, Actions: actions}
	if m.Gorape != nil {
		if rcvr.gorape == nil {
			return provisioning.Result{}, errors.New("gorape provisioning is not configured")
		}
		projectID, gorapeActions, e := rcvr.gorape.ApplyGorape(ctx, *m.Gorape)
		if e != nil {
			return provisioning.Result{}, e
		}
		result.ProjectID = projectID.String()
		result.Actions = append(result.Actions, gorapeActions...)
	}
	return result, nil
}

// gorapePlanActions produces an offline plan for the Gorape section. The
// apply path is transactional, so the plan is intentionally declarative: it
// lists the resources the manifest owns without touching PostgreSQL.
func gorapePlanActions(spec provisioning.GorapeSpec) []provisioning.Action {
	actions := make([]provisioning.Action, 0, 4+len(spec.Roles)+len(spec.Groups)+len(spec.Bindings))
	actions = append(actions, provisioning.Action{Operation: "upsert", Resource: "gorape.project", Name: spec.Project.Slug})
	for _, role := range spec.Roles {
		actions = append(actions, provisioning.Action{Operation: "upsert", Resource: "gorape.role", Name: role.Key})
	}
	for _, group := range spec.Groups {
		actions = append(actions, provisioning.Action{Operation: "upsert", Resource: "gorape.group", Name: group.Slug})
	}
	for _, binding := range spec.Bindings {
		name := binding.Role
		if binding.Group != "" {
			name = binding.Group + "/" + binding.Role
		}
		actions = append(actions, provisioning.Action{Operation: "upsert", Resource: "gorape.role_binding", Name: name, Detail: binding.Scope})
	}
	return actions
}
