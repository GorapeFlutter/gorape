package model_test

import (
	"testing"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPermissionSetWildcards(t *testing.T) {
	set := model.NewPermissionSet()
	set.Add("device:*", "project:read")

	require.True(t, set.Allows(model.PermissionDeviceRegister))
	require.True(t, set.Allows(model.PermissionDeviceRevoke))
	require.True(t, set.Allows(model.PermissionProjectRead))
	require.False(t, set.Allows(model.PermissionProjectManage))

	all := model.NewPermissionSet()
	all.Add("*")
	require.True(t, all.Allows(model.PermissionProvisionManage))
}

func TestEffectivePermissionsFromDefinitions(t *testing.T) {
	definitions := []model.RoleDefinition{
		{Key: "auditor", Permissions: model.PermissionList{"project:read", "device:read"}},
	}
	set := model.EffectivePermissions(definitions, []string{"auditor", "viewer"})
	require.True(t, set.Allows(model.PermissionProjectRead))
	require.True(t, set.Allows(model.PermissionDeviceRead))
	require.False(t, set.Allows(model.PermissionDeviceRevoke))
}

func TestBuiltinRoleDefinition(t *testing.T) {
	d, ok := model.BuiltinRoleDefinition(uuid.Nil, string(model.RoleAdmin))
	require.True(t, ok)
	require.True(t, d.Builtin)
	require.Equal(t, "gorape-admin", d.EffectiveKeycloakRole())
}
