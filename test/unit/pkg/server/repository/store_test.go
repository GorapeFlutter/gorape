package repository_test

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestRepositories_Instantiation(t *testing.T) {
	sqlDB, _, err := sqlmock.New()
	require.NoError(t, err)
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{DisableAutomaticPing: true})
	require.NoError(t, err)

	// Verify each repository constructor produces an interface-compatible instance
	var projectRepo repository.Project = repository.NewProject(db)
	require.NotNil(t, projectRepo)

	var groupRepo repository.Group = repository.NewGroup(db)
	require.NotNil(t, groupRepo)

	var deviceRepo repository.Device = repository.NewDevice(db)
	require.NotNil(t, deviceRepo)

	var roleRepo repository.Role = repository.NewRole(db)
	require.NotNil(t, roleRepo)

	var principalRepo repository.Principal = repository.NewPrincipal(db)
	require.NotNil(t, principalRepo)

	var attestationRepo repository.AttestationStore = repository.NewAttestationStore(db)
	require.NotNil(t, attestationRepo)

	var store repository.StoreInterface = repository.NewStore(db)
	require.NotNil(t, store)
}
