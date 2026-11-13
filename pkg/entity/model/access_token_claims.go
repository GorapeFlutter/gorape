package model

// Roles is the Keycloak role container used by realm_access and
// resource_access.<client>.roles.
type Roles struct {
	Roles []string `json:"roles"`
}

// AccessTokenClaims はOIDCアクセストークンのクレーム
type AccessTokenClaims struct {
	Issuer         string           `json:"iss"`
	Subject        string           `json:"sub"`
	Scope          string           `json:"scope"`
	ExpiresAt      int64            `json:"exp"`
	NotBefore      int64            `json:"nbf"`
	RealmAccess    Roles            `json:"realm_access"`
	ResourceAccess map[string]Roles `json:"resource_access"`
	Groups         []string         `json:"groups"`
}

// AllRoles returns realm roles plus every client role. Gorape maps these role
// names to project role definitions at request time, so Keycloak remains the
// source of truth for role membership.
func (rcvr AccessTokenClaims) AllRoles() []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(rcvr.RealmAccess.Roles))
	add := func(roles []string) {
		for _, role := range roles {
			if role == "" {
				continue
			}
			if _, ok := seen[role]; ok {
				continue
			}
			seen[role] = struct{}{}
			out = append(out, role)
		}
	}
	add(rcvr.RealmAccess.Roles)
	for _, access := range rcvr.ResourceAccess {
		add(access.Roles)
	}
	return out
}
