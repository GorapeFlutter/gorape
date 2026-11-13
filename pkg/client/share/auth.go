package share

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/config"
)

type Manager struct {
	conf          config.BaseConfig
	profile       string
	explicitToken string
}

func NewManager(c config.BaseConfig, p string) *Manager { return &Manager{conf: c, profile: p} }
func (rcvr *Manager) WithToken(t string) *Manager {
	return &Manager{conf: rcvr.conf, profile: rcvr.profile, explicitToken: t}
}
func (rcvr *Manager) Conf() config.BaseConfig { return rcvr.conf }
func (rcvr *Manager) IsAnonymous() bool       { return rcvr.profile == "anonymous" }
func (rcvr *Manager) tokenDir() string {
	return filepath.Join("etc", ".gorape", "client", rcvr.profile)
}
func (rcvr *Manager) Token() (string, error) {
	if rcvr.explicitToken != "" {
		return rcvr.explicitToken, nil
	}
	if t := os.Getenv("GORAPE_ACCESS_TOKEN"); t != "" {
		return t, nil
	}
	b, _ := os.ReadFile(filepath.Join(rcvr.tokenDir(), "access_token"))
	t := strings.TrimSpace(string(b))
	if t == "" || isTokenExpired(t) {
		return "", errors.New("no valid access token; run `gorape-client login` or set GORAPE_ACCESS_TOKEN")
	}
	return t, nil
}
func (rcvr *Manager) ForceLogin(_ string) error {
	_, e := rcvr.loginPKCE(context.Background())
	return e
}
func (rcvr *Manager) ForceRefresh() error {
	return errors.New("refresh tokens are not stored; run login again")
}
func (rcvr *Manager) SaveTokenPair(access, _ string) {
	_ = os.MkdirAll(rcvr.tokenDir(), 0700)
	_ = os.WriteFile(filepath.Join(rcvr.tokenDir(), "access_token"), []byte(access), 0600)
}
func (rcvr *Manager) ClearTokens() {
	_ = os.Remove(filepath.Join(rcvr.tokenDir(), "access_token"))
	_ = os.Unsetenv("GORAPE_ACCESS_TOKEN")
}
func (rcvr *Manager) HTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &authTransport{manager: rcvr, base: http.DefaultTransport}}
}
func (rcvr *Manager) ServerBase() string {
	return strings.TrimRight(rcvr.conf.YamlConfig.Application.Client.ServerEndpoint, "/")
}

type discovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func (rcvr *Manager) loginPKCE(ctx context.Context) (string, error) {
	cfg := rcvr.conf.YamlConfig.Application.Client.OIDC
	if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return "", errors.New("client oidc issuer_url, client_id, and redirect_url are required")
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(cfg.IssuerURL, "/")+"/.well-known/openid-configuration", nil)
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		return "", e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("OIDC discovery HTTP %d", resp.StatusCode)
	}
	var d discovery
	if e = json.NewDecoder(resp.Body).Decode(&d); e != nil {
		return "", e
	}
	verifier := randomURL(32)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randomURL(24)
	redirect, e := url.Parse(cfg.RedirectURL)
	if e != nil {
		return "", e
	}
	ln, e := net.Listen("tcp", redirect.Host)
	if e != nil {
		return "", fmt.Errorf("listen for OIDC callback: %w", e)
	}
	defer ln.Close()
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	mux.HandleFunc(redirect.Path, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state mismatch", 400)
			errCh <- errors.New("OIDC state mismatch")
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			errCh <- errors.New("OIDC callback missing code")
			return
		}
		io.WriteString(w, "Gorape login completed. You may close this window.")
		codeCh <- code
	})
	go server.Serve(ln)
	defer server.Shutdown(context.Background())
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile"}
	}
	u, _ := url.Parse(d.AuthorizationEndpoint)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURL)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	_ = openBrowser(u.String())
	fmt.Printf("Open this URL to authenticate:\n%s\n", u.String())
	var code string
	select {
	case code = <-codeCh:
	case e = <-errCh:
		return "", e
	case <-time.After(3 * time.Minute):
		return "", errors.New("OIDC login timed out")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {cfg.ClientID}, "redirect_uri": {cfg.RedirectURL}, "code": {code}, "code_verifier": {verifier}}
	tr, e := http.NewRequestWithContext(ctx, "POST", d.TokenEndpoint, strings.NewReader(form.Encode()))
	if e != nil {
		return "", e
	}
	tr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResp, e := http.DefaultClient.Do(tr)
	if e != nil {
		return "", e
	}
	defer tokenResp.Body.Close()
	raw, _ := io.ReadAll(tokenResp.Body)
	if tokenResp.StatusCode != 200 {
		return "", fmt.Errorf("token endpoint HTTP %d: %s", tokenResp.StatusCode, raw)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if e = json.Unmarshal(raw, &out); e != nil || out.AccessToken == "" {
		return "", errors.New("token endpoint did not return an access token")
	}
	rcvr.SaveTokenPair(out.AccessToken, "")
	return out.AccessToken, nil
}
func randomURL(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func openBrowser(u string) error {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("open", u)
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		c = exec.Command("xdg-open", u)
	}
	return c.Start()
}
func isTokenExpired(t string) bool {
	p := strings.Split(t, ".")
	if len(p) != 3 {
		return true
	}
	b, e := base64.RawURLEncoding.DecodeString(p[1])
	if e != nil {
		return true
	}
	var c struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(b, &c) != nil {
		return true
	}
	return time.Now().Unix() >= c.Exp-10
}

type authTransport struct {
	manager *Manager
	base    http.RoundTripper
}

func (rcvr *authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	token, e := rcvr.manager.Token()
	if e != nil {
		return nil, e
	}
	clone := r.Clone(r.Context())
	clone.Header = clone.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+token)
	if r.Body != nil {
		b, e := io.ReadAll(r.Body)
		if e != nil {
			return nil, e
		}
		clone.Body = io.NopCloser(bytes.NewReader(b))
	}
	return rcvr.base.RoundTrip(clone)
}
