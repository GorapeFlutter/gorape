package repository_test

import (
	"context"
	"testing"

	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/stretchr/testify/require"
)

func TestUnsupportedVerifierFailsClosed(t *testing.T) {
	r, err := repository.NewVerifierRegistry(nil)
	require.NoError(t, err)
	_, err = r.Verify(context.Background(), repository.AttestationRequest{Platform: "windows"})
	require.ErrorIs(t, err, repository.ErrUnsupportedAttestation)
	_, err = r.Verify(context.Background(), repository.AttestationRequest{Platform: "android"})
	require.Error(t, err)
}
