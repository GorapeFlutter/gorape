package usecase_test

import (
	"testing"

	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/stretchr/testify/require"
)

func TestParseKeycloakGroupPath(t *testing.T) {
	role, group, ok := usecase.ParseKeycloakGroupPath("/gorape/projects/demo/roles/admin", "demo")
	require.True(t, ok)
	require.Equal(t, "admin", role)
	require.Empty(t, group)

	role, group, ok = usecase.ParseKeycloakGroupPath("/gorape/projects/demo/groups/team/roles/editor", "demo")
	require.True(t, ok)
	require.Equal(t, "editor", role)
	require.Equal(t, "team", group)

	_, _, ok = usecase.ParseKeycloakGroupPath("/gorape/projects/other/roles/admin", "demo")
	require.False(t, ok)

	_, _, ok = usecase.ParseKeycloakGroupPath("/unrelated/group", "demo")
	require.False(t, ok)
}
