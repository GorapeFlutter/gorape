package repository

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
)

type TokenValidator interface {
	Validate(context.Context, model.ProjectDomain, string) (model.AccessTokenClaims, error)
}
type OIDCValidator struct {
	audience     string
	scopes       []string
	mu           sync.Mutex
	verifiers    map[string]*gooidc.IDTokenVerifier
	providerURLs map[string]string
}

func NewOIDCValidator(audience string, scopes []string, providerURLs map[string]string) *OIDCValidator {
	return &OIDCValidator{audience: audience, scopes: scopes, providerURLs: providerURLs, verifiers: map[string]*gooidc.IDTokenVerifier{}}
}
func (rcvr *OIDCValidator) Validate(ctx context.Context, p model.ProjectDomain, raw string) (model.AccessTokenClaims, error) {
	if p.OIDCIssuer == "" || p.Status != "active" {
		return model.AccessTokenClaims{}, errors.New("inactive or invalid project issuer")
	}
	verifier, err := rcvr.verifier(ctx, p.OIDCIssuer)
	if err != nil {
		return model.AccessTokenClaims{}, err
	}
	tok, err := verifier.Verify(ctx, raw)
	if err != nil {
		return model.AccessTokenClaims{}, fmt.Errorf("access token verification failed: %w", err)
	}
	var c model.AccessTokenClaims
	if err := tok.Claims(&c); err != nil {
		return c, err
	}
	if c.Issuer != p.OIDCIssuer || c.Subject == "" {
		return c, errors.New("invalid issuer or subject")
	}
	have := map[string]bool{}
	for _, s := range strings.Fields(c.Scope) {
		have[s] = true
	}
	for _, s := range rcvr.scopes {
		if !have[s] {
			return c, fmt.Errorf("required scope %q is missing", s)
		}
	}
	return c, nil
}
func (rcvr *OIDCValidator) verifier(ctx context.Context, issuer string) (*gooidc.IDTokenVerifier, error) {
	rcvr.mu.Lock()
	defer rcvr.mu.Unlock()
	if x := rcvr.verifiers[issuer]; x != nil {
		return x, nil
	}
	providerURL := issuer
	if internal := rcvr.providerURLs[issuer]; internal != "" {
		providerURL = internal
		ctx = gooidc.InsecureIssuerURLContext(ctx, issuer)
		ctx = gooidc.ClientContext(ctx, &http.Client{Transport: &issuerRewriteTransport{issuer: issuer, internal: internal, base: http.DefaultTransport}})
	}
	p, err := gooidc.NewProvider(ctx, providerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery for registered issuer: %w", err)
	}
	x := p.Verifier(&gooidc.Config{ClientID: rcvr.audience})
	rcvr.verifiers[issuer] = x
	return x, nil
}

type issuerRewriteTransport struct {
	issuer, internal string
	base             http.RoundTripper
}

func (rcvr *issuerRewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	from, _ := url.Parse(rcvr.issuer)
	to, _ := url.Parse(rcvr.internal)
	if r.URL.Host == from.Host {
		clone := r.Clone(r.Context())
		clone.URL.Scheme = to.Scheme
		clone.URL.Host = to.Host
		r = clone
	}
	return rcvr.base.RoundTrip(r)
}
