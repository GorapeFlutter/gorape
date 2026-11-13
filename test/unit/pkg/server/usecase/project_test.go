package usecase_test

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestProjectUsecase_RequireProject(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{DisableAutomaticPing: true})
	require.NoError(t, err)

	store := repository.NewStore(db)
	v := &countingValidator{}
	projectUC := usecase.NewProject(store, v)

	projectID := uuid.New()
	principalID := uuid.New()
	authCtx := model.AuthContext{
		Project:   model.ProjectDomain{ID: projectID},
		Principal: model.IdentityPrincipal{ID: principalID},
	}

	// Case 1: Role meets requirement (Admin >= Viewer)
	mock.ExpectQuery(`SELECT .*project_role_bindings.*`).
		WithArgs(projectID, principalID, 1).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("admin"))

	err = projectUC.RequireProject(context.Background(), authCtx, model.RoleViewer)
	require.NoError(t, err)

	// Case 2: Role does not meet requirement (Viewer < Admin)
	mock.ExpectQuery(`SELECT .*project_role_bindings.*`).
		WithArgs(projectID, principalID, 1).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("viewer"))

	err = projectUC.RequireProject(context.Background(), authCtx, model.RoleAdmin)
	require.ErrorIs(t, err, usecase.ErrForbidden)

	// Case 3: Role not found
	mock.ExpectQuery(`SELECT .*project_role_bindings.*`).
		WithArgs(projectID, principalID, 1).
		WillReturnError(errors.New("not found"))

	err = projectUC.RequireProject(context.Background(), authCtx, model.RoleViewer)
	require.ErrorIs(t, err, usecase.ErrForbidden)

	require.NoError(t, mock.ExpectationsWereMet())
}
