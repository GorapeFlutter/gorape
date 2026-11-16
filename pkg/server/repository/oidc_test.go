package repository

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/google/uuid"
)

func TestOIDCValidatorSupportsGorapeFlutterSiteAndCustomDomainIssuers(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "test-kid-1"

	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/gorape/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 "http://idp.gorapeflutter.site:8080/realms/gorape",
				"authorization_endpoint": "http://idp.gorapeflutter.site:8080/realms/gorape/protocol/openid-connect/auth",
				"token_endpoint":         "http://idp.gorapeflutter.site:8080/realms/gorape/protocol/openid-connect/token",
				"jwks_uri":               "http://idp.gorapeflutter.site:8080/realms/gorape/protocol/openid-connect/certs",
			})
		case "/realms/gorape/protocol/openid-connect/certs":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{
					{
						"kty": "RSA",
						"alg": "RS256",
						"use": "sig",
						"kid": keyID,
						"n":   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
						"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	issuer := "http://idp.gorapeflutter.site:8080/realms/gorape"
	validator := NewOIDCValidator(
		"gorape-api",
		[]string{"openid"},
		map[string]string{
			issuer: serverURL + "/realms/gorape",
		},
	)

	now := time.Now()
	rawToken := signTestRS256JWT(t, priv, keyID, map[string]any{
		"iss":   issuer,
		"sub":   "49a63887-99b1-41ab-b0d1-5f4ed8254afb",
		"aud":   "gorape-api",
		"scope": "openid profile",
		"amr":   []string{"passkey"},
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
	})

	project := model.Project{
		ID:         uuid.New(),
		Slug:       "demo",
		OIDCIssuer: issuer,
		Status:     "active",
	}
	claims, err := validator.Validate(context.Background(), project, rawToken)
	if err != nil {
		t.Fatalf("Validate failed for %s: %v", issuer, err)
	}
	if claims.Issuer != issuer || claims.Subject != "49a63887-99b1-41ab-b0d1-5f4ed8254afb" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if !claims.PasskeyAuthenticated() {
		t.Fatalf("expected passkey AMR in validated claims: %+v", claims.AuthenticationMethods)
	}
}

func signTestRS256JWT(t *testing.T, key *rsa.PrivateKey, kid string, payload map[string]any) string {
	t.Helper()
	headerBytes, err := json.Marshal(map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	})
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(payloadBytes)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}
