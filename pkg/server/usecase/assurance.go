package usecase

import (
	"strings"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
)

const authenticationClockSkew = 30 * time.Second

// AuthenticationAssurancePolicy applies a recent, explicitly identified
// Keycloak authentication to sensitive device and credential operations.
// A zero-value policy preserves the existing passkey-AMR requirement only.
type AuthenticationAssurancePolicy struct {
	Enabled     bool
	RequiredACR string
	MaxAuthAge  time.Duration
}

// RequireStepUp leaves legacy operations unchanged unless the policy is enabled.
func (policy AuthenticationAssurancePolicy) RequireStepUp(auth model.AuthContext) error {
	if !policy.Enabled {
		return nil
	}
	return policy.RequirePasskey(auth)
}

// GF-10034 — Enforces passkey AMR, configured ACR, and auth_time freshness when enabled.
func (policy AuthenticationAssurancePolicy) RequirePasskey(auth model.AuthContext) error {
	if !policy.Enabled {
		return nil
	}
	if err := requirePasskeyAuthentication(auth); err != nil {
		return err
	}
	if strings.TrimSpace(policy.RequiredACR) == "" || policy.MaxAuthAge <= 0 ||
		strings.TrimSpace(auth.Claims.AuthenticationContext) != strings.TrimSpace(policy.RequiredACR) {
		return ErrAuthenticationStepUpRequired
	}
	if auth.Claims.AuthenticationTime <= 0 {
		return ErrAuthenticationStepUpRequired
	}
	authenticatedAt := time.Unix(auth.Claims.AuthenticationTime, 0)
	now := time.Now()
	if authenticatedAt.After(now.Add(authenticationClockSkew)) || now.Sub(authenticatedAt) > policy.MaxAuthAge {
		return ErrAuthenticationStepUpRequired
	}
	return nil
}
