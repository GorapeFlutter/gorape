package repository_test

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestMemoryChallengeStoresWebAuthnPayload(t *testing.T) {
	s := repository.NewMemoryChallengeStore(time.Minute)
	value := []byte("01234567890123456789012345678901")
	payload := json.RawMessage(`{"session":{"challenge":"abc"}}`)
	v, err := s.CreateWithValue(context.Background(), uuid.New(), "sub", "webauthn-proof", uuid.New(), value, payload)
	require.NoError(t, err)
	read, err := s.Get(context.Background(), v.ID)
	require.NoError(t, err)
	require.Equal(t, payload, read.Payload)

	consumed, err := s.Consume(context.Background(), v.ID)
	require.NoError(t, err)
	require.Equal(t, value, consumed.Value)
	require.True(t, bytes.Equal(payload, consumed.Payload))
	require.Equal(t, "webauthn-proof", consumed.Purpose)
	_, err = s.Get(context.Background(), v.ID)
	require.ErrorIs(t, err, repository.ErrChallengeInvalid)
}
