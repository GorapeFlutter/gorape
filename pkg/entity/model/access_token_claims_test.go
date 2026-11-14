package model

import "testing"

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
