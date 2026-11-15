package model

import (
	"encoding/json"
	"testing"
)

func TestPasskeyAuthenticatedRequiresKeycloakAMR(t *testing.T) {
	for _, test := range []struct {
		name string
		amr  []string
		want bool
	}{
		{name: "passkey", amr: []string{"passkey"}, want: true},
		{name: "password only", amr: []string{"pwd"}},
		{name: "empty", amr: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := AccessTokenClaims{AuthenticationMethods: test.amr}
			if got := claims.PasskeyAuthenticated(); got != test.want {
				t.Fatalf("PasskeyAuthenticated() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestAccessTokenClaimsParseAuthenticationAssurance(t *testing.T) {
	var claims AccessTokenClaims
	if err := json.Unmarshal([]byte(`{"auth_time":1735689600,"acr":"gorape-passkey","amr":["passkey"]}`), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.AuthenticationTime != 1735689600 || claims.AuthenticationContext != "gorape-passkey" || !claims.PasskeyAuthenticated() {
		t.Fatalf("authentication assurance claims were not retained: %+v", claims)
	}
}
