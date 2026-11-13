package usecase_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type countingValidator struct{ calls int }

func (v *countingValidator) Validate(context.Context, model.ProjectDomain, string) (model.AccessTokenClaims, error) {
	v.calls++
	return model.AccessTokenClaims{}, errors.New("unexpected validation")
}

func TestUnknownIssuerDoesNotReachOIDCDiscovery(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{DisableAutomaticPing: true})
	require.NoError(t, err)
	mock.ExpectQuery(`SELECT .*project_domains.*oidc_issuer`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	v := &countingValidator{}
	s := usecase.NewService(repository.NewStore(db), v, nil, nil)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://evil.example/realm"}`))
	_, err = s.AuthenticateIssuer(context.Background(), "e30."+payload+".signature")
	require.Error(t, err)
	require.Zero(t, v.calls)
	require.NoError(t, mock.ExpectationsWereMet())
}
