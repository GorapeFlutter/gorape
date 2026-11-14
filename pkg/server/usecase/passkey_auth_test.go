package usecase

import (
	"errors"
	"testing"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
)

func TestRequirePasskeyAuthentication(t *testing.T) {
	if err := requirePasskeyAuthentication(model.AuthContext{}); !errors.Is(err, ErrPasskeyAuthenticationRequired) {
		t.Fatalf("passwordless claim absent: got %v", err)
	}

	auth := model.AuthContext{Claims: model.AccessTokenClaims{AuthenticationMethods: []string{"pwd"}}}
	if err := requirePasskeyAuthentication(auth); !errors.Is(err, ErrPasskeyAuthenticationRequired) {
		t.Fatalf("password claim only: got %v", err)
	}

	auth.Claims.AuthenticationMethods = []string{"passkey"}
	if err := requirePasskeyAuthentication(auth); err != nil {
		t.Fatalf("passkey claim rejected: %v", err)
	}
}
