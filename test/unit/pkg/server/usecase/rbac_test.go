package usecase_test

import (
	"testing"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/stretchr/testify/assert"
)

func TestRoleInheritance(t *testing.T) {
	assert.True(t, usecase.Allows(model.RoleEditor, model.RoleViewer, model.RoleEditor))
	assert.True(t, usecase.Allows("", model.RoleAdmin, model.RoleEditor))
	assert.False(t, usecase.Allows(model.RoleViewer, "", model.RoleEditor))
	assert.False(t, usecase.Allows("", "", model.RoleViewer))
}
