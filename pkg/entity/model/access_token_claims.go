package model

// AccessTokenClaims はOIDCアクセストークンのクレーム
type AccessTokenClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Scope     string `json:"scope"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
}
