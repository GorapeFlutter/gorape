package model

// AuthContext はリクエストごとの認証コンテキスト
type AuthContext struct {
	Project   ProjectDomain
	Principal IdentityPrincipal
	Claims    AccessTokenClaims
}
