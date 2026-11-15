package usecase

import (
	"errors"
	"testing"
	"time"

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

func TestAuthenticationAssuranceRequiresRecentExactACRAndPasskeyAMR(t *testing.T) {
	policy := AuthenticationAssurancePolicy{
		Enabled: true, RequiredACR: "gorape-passkey", MaxAuthAge: 5 * time.Minute,
	}
	now := time.Now().Unix()
	valid := model.AuthContext{Claims: model.AccessTokenClaims{
		AuthenticationMethods: []string{"pwd", "passkey"},
		AuthenticationContext: "gorape-passkey",
		AuthenticationTime:    now - 60,
	}}
	if err := policy.RequirePasskey(valid); err != nil {
		t.Fatalf("recent passkey authentication rejected: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*model.AuthContext)
	}{
		{name: "missing auth_time", mutate: func(auth *model.AuthContext) { auth.Claims.AuthenticationTime = 0 }},
		{name: "stale auth_time", mutate: func(auth *model.AuthContext) { auth.Claims.AuthenticationTime = now - 600 }},
		{name: "future auth_time", mutate: func(auth *model.AuthContext) { auth.Claims.AuthenticationTime = now + 120 }},
		{name: "wrong ACR", mutate: func(auth *model.AuthContext) { auth.Claims.AuthenticationContext = "urn:password" }},
		{name: "ACR case mismatch", mutate: func(auth *model.AuthContext) { auth.Claims.AuthenticationContext = "GORAPE-PASSKEY" }},
		{name: "missing passkey AMR", mutate: func(auth *model.AuthContext) { auth.Claims.AuthenticationMethods = []string{"pwd"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth := valid
			test.mutate(&auth)
			if err := policy.RequirePasskey(auth); !errors.Is(err, ErrAuthenticationStepUpRequired) &&
				!(test.name == "missing passkey AMR" && errors.Is(err, ErrPasskeyAuthenticationRequired)) {
				t.Fatalf("RequirePasskey() error = %v, want step-up rejection", err)
			}
		})
	}
}

func TestAuthenticationAssuranceDisabledAllowsStandardOIDCLogin(t *testing.T) {
	policy := AuthenticationAssurancePolicy{}
	auth := model.AuthContext{Claims: model.AccessTokenClaims{AuthenticationMethods: []string{"pwd"}}}
	if err := policy.RequirePasskey(auth); err != nil {
		t.Fatalf("disabled assurance policy must allow standard OIDC login: %v", err)
	}
}

func TestAuthenticationAssuranceOnlyGatesStepUpWhenEnabled(t *testing.T) {
	if err := (AuthenticationAssurancePolicy{}).RequireStepUp(model.AuthContext{}); err != nil {
		t.Fatalf("disabled step-up policy must not alter existing operations: %v", err)
	}
	policy := AuthenticationAssurancePolicy{
		Enabled: true, RequiredACR: "gorape-passkey", MaxAuthAge: time.Minute,
	}
	if err := policy.RequireStepUp(model.AuthContext{}); !errors.Is(err, ErrPasskeyAuthenticationRequired) {
		t.Fatalf("enabled step-up policy accepted a token without passkey AMR: %v", err)
	}
}
