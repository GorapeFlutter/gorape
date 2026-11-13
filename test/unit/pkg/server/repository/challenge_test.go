package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestMemoryChallengeIsSingleUse(t *testing.T) {
	s := repository.NewMemoryChallengeStore(time.Minute)
	v, err := s.Create(context.Background(), uuid.New(), "sub", "proof", uuid.New())
	require.NoError(t, err)
	_, err = s.Consume(context.Background(), v.ID)
	require.NoError(t, err)
	_, err = s.Consume(context.Background(), v.ID)
	require.ErrorIs(t, err, repository.ErrChallengeInvalid)
	require.Len(t, v.Value, 32)
}
