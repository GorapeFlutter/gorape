package usecase_test

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/request"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestGroupUsecase_CreateGroup_SlugValidation(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{DisableAutomaticPing: true})
	require.NoError(t, err)

	store := repository.NewStore(db)
	projectUC := usecase.NewProject(store, &countingValidator{})
	groupUC := usecase.NewGroup(store, projectUC)

	projectID := uuid.New()
	principalID := uuid.New()
	authCtx := model.AuthContext{
		Project:   model.ProjectDomain{ID: projectID},
		Principal: model.IdentityPrincipal{ID: principalID},
	}

	// Admin role check passes
	mock.ExpectQuery(`SELECT .*project_role_bindings.*`).
		WithArgs(projectID, principalID, 1).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("admin"))

	// Invalid slug with spaces or uppercase
	_, err = groupUC.CreateGroup(context.Background(), authCtx, request.GroupCreate{
		Slug: "Invalid Slug!",
		Name: "Test Group",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "group slug must contain lowercase letters")

	require.NoError(t, mock.ExpectationsWereMet())
}
