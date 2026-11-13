package model

// AuthContext はリクエストごとの認証コンテキスト
type AuthContext struct {
	Project   Project
	Principal Principal
	Claims    AccessTokenClaims
}
