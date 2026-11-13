package provisioning_test

import (
	"testing"

	"github.com/Gorapeflutter/gorape/pkg/entity/provisioning"
	"github.com/stretchr/testify/require"
)

func TestManifestValidate(t *testing.T) {
	m := provisioning.Manifest{
		APIVersion: provisioning.APIVersion,
		Kind:       provisioning.Kind,
		Gorape: &provisioning.GorapeSpec{
			Project: provisioning.ProjectSpec{Slug: "demo", Name: "Demo", Issuer: "https://keycloak.example/realms/gorape"},
			Roles: []provisioning.RoleDefSpec{
				{Key: "auditor", Permissions: []string{"project:read"}},
			},
			Bindings: []provisioning.BindingSpec{
				{Subject: "user-1", Role: "auditor"},
			},
		},
	}
	require.NoError(t, m.Validate())

	bad := m
	bad.APIVersion = "gorape/v2"
	require.Error(t, bad.Validate())

	badBinding := m
	badBinding.Gorape = &provisioning.GorapeSpec{
		Project:  m.Gorape.Project,
		Bindings: []provisioning.BindingSpec{{Subject: "user-1", Role: "auditor", Scope: "group"}},
	}
	require.Error(t, badBinding.Validate())
}
