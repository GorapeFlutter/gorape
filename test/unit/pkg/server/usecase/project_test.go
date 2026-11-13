package usecase_test

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func newMockStore(t *testing.T) (*repository.Store, sqlmock.Sqlmock) {
	t.Helper()
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{DisableAutomaticPing: true})
	require.NoError(t, err)
	return repository.NewStore(db), mock
}

func roleDefinitionRows(projectID uuid.UUID, key string, permissions string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "project_id", "key", "name", "permissions", "keycloak_role", "builtin", "created_at", "updated_at"}).
		AddRow(uuid.New(), projectID, key, key, []byte(permissions), model.KeycloakRoleName(key), true, time.Now(), time.Now())
}

func roleBindingRows(projectID, principalID uuid.UUID, roleKey string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "project_id", "principal_id", "scope", "group_id", "role_key", "created_at"}).
		AddRow(uuid.New(), projectID, principalID, model.BindingScopeProject, nil, roleKey, time.Now())
}

func TestProjectUsecase_RequireProjectPermissions(t *testing.T) {
	store, mock := newMockStore(t)
	v := &countingValidator{}
	projectUC := usecase.NewProject(store, v)

	projectID := uuid.New()
	principalID := uuid.New()
	authCtx := model.AuthContext{
		Project:   model.Project{ID: projectID, Slug: "demo"},
		Principal: model.Principal{ID: principalID},
	}

	// Case 1: an admin binding grants project:manage through the wildcard.
	mock.ExpectQuery(`SELECT \* FROM "role_definitions"`).
		WithArgs(projectID).
		WillReturnRows(roleDefinitionRows(projectID, "admin", `["*"]`))
	mock.ExpectQuery(`SELECT \* FROM "role_bindings"`).
		WithArgs(projectID, principalID).
		WillReturnRows(roleBindingRows(projectID, principalID, "admin"))

	err := projectUC.RequireProject(context.Background(), authCtx, model.PermissionProjectManage)
	require.NoError(t, err)

	// Case 2: a viewer binding does not grant project:manage.
	mock.ExpectQuery(`SELECT \* FROM "role_definitions"`).
		WithArgs(projectID).
		WillReturnRows(roleDefinitionRows(projectID, "viewer", `["project:read"]`))
	mock.ExpectQuery(`SELECT \* FROM "role_bindings"`).
		WithArgs(projectID, principalID).
		WillReturnRows(roleBindingRows(projectID, principalID, "viewer"))

	err = projectUC.RequireProject(context.Background(), authCtx, model.PermissionProjectManage)
	require.ErrorIs(t, err, usecase.ErrForbidden)

	// Case 3: no Gorape binding, but a dynamic Keycloak realm role grants admin.
	dynamic := authCtx
	dynamic.Claims.RealmAccess.Roles = []string{"gorape-admin"}
	mock.ExpectQuery(`SELECT \* FROM "role_definitions"`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "key", "name", "permissions", "keycloak_role", "builtin", "created_at", "updated_at"}))
	mock.ExpectQuery(`SELECT \* FROM "role_bindings"`).
		WithArgs(projectID, principalID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "principal_id", "scope", "group_id", "role_key", "created_at"}))

	err = projectUC.RequireProject(context.Background(), dynamic, model.PermissionProjectManage)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestProjectUsecase_RequireProjectDatabaseError(t *testing.T) {
	store, mock := newMockStore(t)
	projectUC := usecase.NewProject(store, &countingValidator{})

	projectID := uuid.New()
	principalID := uuid.New()
	authCtx := model.AuthContext{
		Project:   model.Project{ID: projectID, Slug: "demo"},
		Principal: model.Principal{ID: principalID},
	}

	mock.ExpectQuery(`SELECT \* FROM "role_definitions"`).
		WithArgs(projectID).
		WillReturnError(context.DeadlineExceeded)

	err := projectUC.RequireProject(context.Background(), authCtx, model.PermissionProjectRead)
	require.ErrorIs(t, err, usecase.ErrForbidden)
	require.NoError(t, mock.ExpectationsWereMet())
}
