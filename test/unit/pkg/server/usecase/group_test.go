package usecase_test

import (
	"context"
	"testing"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/request"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestGroupUsecase_CreateGroup_SlugValidation(t *testing.T) {
	store, mock := newMockStore(t)
	projectUC := usecase.NewProject(store, &countingValidator{})
	groupUC := usecase.NewGroup(store, projectUC)

	projectID := uuid.New()
	principalID := uuid.New()
	authCtx := model.AuthContext{
		Project:   model.Project{ID: projectID, Slug: "demo"},
		Principal: model.Principal{ID: principalID},
	}

	// The admin binding satisfies the project:manage requirement.
	mock.ExpectQuery(`SELECT \* FROM "role_definitions"`).
		WithArgs(projectID).
		WillReturnRows(roleDefinitionRows(projectID, "admin", `["*"]`))
	mock.ExpectQuery(`SELECT \* FROM "role_bindings"`).
		WithArgs(projectID, principalID).
		WillReturnRows(roleBindingRows(projectID, principalID, "admin"))

	// Invalid slug with spaces or uppercase.
	_, err := groupUC.CreateGroup(context.Background(), authCtx, request.GroupCreate{
		Slug: "Invalid Slug!",
		Name: "Test Group",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "group slug must contain lowercase letters")

	require.NoError(t, mock.ExpectationsWereMet())
}
