package repository

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/net/publicsuffix"
)

var ErrAttestationPolicyDenied = errors.New("WebAuthn attestation is not allowed by policy")

// WebAuthnRPConfig contains RP identity and explicit attestation trust policy.
// Empty format allowlists and AllowNone=false intentionally reject all new
// credentials (default deny).
type WebAuthnRPConfig struct {
	RPID                  string
	RPDisplayName         string
	RPOrigins             []string
	PortalOrigin          string
	BrowserAPIOrigin      string
	AttestationConveyance string
	UserVerification      string
	AllowedFormats        []string
	AllowNone             bool
	AllowSelfAttestation  bool
	TrustAnchors          map[string][]string
	ChallengeTTL          time.Duration
}

type WebAuthnRP struct {
	server           *webauthn.WebAuthn
	portalOrigin     string
	browserAPIOrigin string
	allowed          map[string]bool
	allowNone        bool
	allowSelf        bool
	trustRoots       map[string]*x509.CertPool
	challengeTTL     time.Duration
}

// WebAuthnUser is the account identity and the credential set presented to
// go-webauthn for one registration or assertion ceremony.
type WebAuthnUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u WebAuthnUser) WebAuthnID() []byte                         { return u.ID }
func (u WebAuthnUser) WebAuthnName() string                       { return u.Name }
func (u WebAuthnUser) WebAuthnDisplayName() string                { return u.DisplayName }
func (u WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type WebAuthnAttestationResult struct {
	Format          string
	SecurityLevel   string
	VerifierVersion string
}

func NewWebAuthnRP(config WebAuthnRPConfig) (*WebAuthnRP, error) {
	if config.RPID == "" || len(config.RPOrigins) == 0 {
		return nil, errors.New("WebAuthn RP ID and at least one allowed origin are required")
	}
	if err := validateRPIdentity(config.RPID, config.RPOrigins); err != nil {
		return nil, err
	}
	portalOrigin := strings.TrimSpace(config.PortalOrigin)
	if portalOrigin != "" {
		if err := validateRPIdentity(config.RPID, []string{portalOrigin}); err != nil {
			return nil, fmt.Errorf("invalid WebAuthn portal_origin: %w", err)
		}
		if !slices.Contains(config.RPOrigins, portalOrigin) {
			return nil, errors.New("WebAuthn portal_origin must also be listed in rp_origins")
		}
		parsedPortal, _ := url.Parse(portalOrigin)
		if parsedPortal.Path != "" && parsedPortal.Path != "/" {
			return nil, errors.New("WebAuthn portal_origin must not contain a path")
		}
	}
	browserAPIOrigin := strings.TrimRight(strings.TrimSpace(config.BrowserAPIOrigin), "/")
	if browserAPIOrigin != "" {
		parsedAPI, err := url.Parse(browserAPIOrigin)
		if err != nil || parsedAPI.Host == "" || parsedAPI.Path != "" || parsedAPI.RawQuery != "" || parsedAPI.Fragment != "" {
			return nil, errors.New("WebAuthn browser_api_origin must be an origin without path, query, or fragment")
		}
		if parsedAPI.Scheme != "https" && !(parsedAPI.Scheme == "http" && (parsedAPI.Hostname() == "localhost" || parsedAPI.Hostname() == "127.0.0.1")) {
			return nil, errors.New("WebAuthn browser_api_origin must use HTTPS except on localhost")
		}
	}
	if config.RPDisplayName == "" {
		config.RPDisplayName = "Gorape"
	}
	if config.ChallengeTTL <= 0 {
		config.ChallengeTTL = 5 * time.Minute
	}
	if config.UserVerification == "" {
		config.UserVerification = string(protocol.VerificationRequired)
	}
	verification := protocol.UserVerificationRequirement(config.UserVerification)
	switch verification {
	case protocol.VerificationRequired, protocol.VerificationPreferred, protocol.VerificationDiscouraged:
	default:
		return nil, fmt.Errorf("invalid WebAuthn user_verification %q", config.UserVerification)
	}

	conveyance := protocol.ConveyancePreference(config.AttestationConveyance)
	if conveyance == "" {
		conveyance = protocol.PreferDirectAttestation
	}
	switch conveyance {
	case protocol.PreferNoAttestation, protocol.PreferIndirectAttestation, protocol.PreferDirectAttestation, protocol.PreferEnterpriseAttestation:
	default:
		return nil, fmt.Errorf("invalid WebAuthn attestation_conveyance %q", config.AttestationConveyance)
	}

	allowed := make(map[string]bool, len(config.AllowedFormats))
	for _, format := range config.AllowedFormats {
		format = bytesToLowerTrim(format)
		if format == "" || format == string(protocol.AttestationFormatNone) {
			return nil, fmt.Errorf("attestation format %q must not be empty or none; use allow_none for none", format)
		}
		if !supportedTrustedFormat(format) {
			return nil, fmt.Errorf("unsupported WebAuthn attestation format %q", format)
		}
		allowed[format] = true
	}

	selection := protocol.AuthenticatorSelection{
		ResidentKey:        protocol.ResidentKeyRequirementRequired,
		RequireResidentKey: protocol.ResidentKeyRequired(),
		UserVerification:   verification,
	}
	server, err := webauthn.New(&webauthn.Config{
		RPID:                   config.RPID,
		RPDisplayName:          config.RPDisplayName,
		RPOrigins:              config.RPOrigins,
		AttestationPreference:  conveyance,
		AuthenticatorSelection: selection,
		Timeouts: webauthn.TimeoutsConfig{
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: config.ChallengeTTL},
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: config.ChallengeTTL},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize WebAuthn RP: %w", err)
	}

	roots := make(map[string]*x509.CertPool, len(config.TrustAnchors))
	for format, paths := range config.TrustAnchors {
		format = bytesToLowerTrim(format)
		if !supportedTrustedFormat(format) {
			return nil, fmt.Errorf("unsupported WebAuthn trust-anchor format %q", format)
		}
		pool := x509.NewCertPool()
		for _, path := range paths {
			pemBytes, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil, fmt.Errorf("read WebAuthn %s trust anchor %q: %w", format, path, readErr)
			}
			if !pool.AppendCertsFromPEM(pemBytes) {
				return nil, fmt.Errorf("WebAuthn %s trust anchor %q contains no PEM certificates", format, path)
			}
		}
		roots[format] = pool
	}

	return &WebAuthnRP{
		server: server, portalOrigin: portalOrigin, browserAPIOrigin: browserAPIOrigin,
		allowed: allowed, allowNone: config.AllowNone,
		allowSelf: config.AllowSelfAttestation, trustRoots: roots,
		challengeTTL: config.ChallengeTTL,
	}, nil
}

func (rp *WebAuthnRP) BrowserPortalURL() string {
	if rp == nil || rp.portalOrigin == "" {
		return ""
	}
	return strings.TrimRight(rp.portalOrigin, "/") + "/passkey-ceremony.html"
}

func (rp *WebAuthnRP) BrowserAPIOrigin() string {
	if rp == nil {
		return ""
	}
	return rp.browserAPIOrigin
}

func (rp *WebAuthnRP) BrowserPortalReady() bool {
	return rp.BrowserPortalURL() != "" && rp.BrowserAPIOrigin() != ""
}

func (rp *WebAuthnRP) RegistrationOptions(user WebAuthnUser) (map[string]any, webauthn.SessionData, error) {
	if !rp.registrationPolicyEnabled() {
		return nil, webauthn.SessionData{}, ErrAttestationPolicyDenied
	}
	credentials := webauthn.Credentials(user.WebAuthnCredentials())
	creation, session, err := rp.server.BeginRegistration(
		user,
		webauthn.WithExclusions(credentials.CredentialDescriptors()),
	)
	if err != nil {
		return nil, webauthn.SessionData{}, err
	}
	session.Expires = time.Now().Add(rp.challengeTTL)
	options, err := toOptionsMap(creation.Response)
	return options, *session, err
}

func (rp *WebAuthnRP) registrationPolicyEnabled() bool {
	if rp.allowNone {
		return true
	}
	for format := range rp.allowed {
		if roots := rp.trustRoots[format]; roots != nil && len(roots.Subjects()) > 0 {
			return true
		}
		if format == string(protocol.AttestationFormatPacked) && rp.allowSelf {
			return true
		}
	}
	return false
}

func (rp *WebAuthnRP) VerifyRegistration(user WebAuthnUser, session webauthn.SessionData, credentialJSON []byte) (*webauthn.Credential, WebAuthnAttestationResult, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(credentialJSON)
	if err != nil {
		return nil, WebAuthnAttestationResult{}, err
	}
	if err = validateCredentialID(parsed.ID, parsed.RawID); err != nil {
		return nil, WebAuthnAttestationResult{}, err
	}
	if !bytes.Equal(parsed.RawID, parsed.Response.AttestationObject.AuthData.AttData.CredentialID) {
		return nil, WebAuthnAttestationResult{}, errors.New("credential id does not match attested credential id")
	}
	format := bytesToLowerTrim(parsed.Response.AttestationObject.Format)
	if format == string(protocol.AttestationFormatNone) {
		if !rp.allowNone {
			return nil, WebAuthnAttestationResult{}, ErrAttestationPolicyDenied
		}
	} else if !rp.allowed[format] {
		return nil, WebAuthnAttestationResult{}, fmt.Errorf("%w: format %q", ErrAttestationPolicyDenied, format)
	}

	stored, err := rp.server.CreateCredential(user, session, parsed)
	if err != nil {
		return nil, WebAuthnAttestationResult{}, fmt.Errorf("verify WebAuthn registration: %w", err)
	}
	result, err := rp.verifyTrust(format, parsed.Response.AttestationObject)
	if err != nil {
		return nil, WebAuthnAttestationResult{}, err
	}
	return stored, result, nil
}

func (rp *WebAuthnRP) AuthenticationOptions(user WebAuthnUser) (map[string]any, webauthn.SessionData, error) {
	assertion, session, err := rp.server.BeginLogin(user)
	if err != nil {
		return nil, webauthn.SessionData{}, err
	}
	session.Expires = time.Now().Add(rp.challengeTTL)
	options, err := toOptionsMap(assertion.Response)
	return options, *session, err
}

func (rp *WebAuthnRP) VerifyAuthentication(user WebAuthnUser, session webauthn.SessionData, credentialJSON []byte) (*webauthn.Credential, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(credentialJSON)
	if err != nil {
		return nil, err
	}
	if err = validateCredentialID(parsed.ID, parsed.RawID); err != nil {
		return nil, err
	}
	return rp.server.ValidateLogin(user, session, parsed)
}

func (rp *WebAuthnRP) verifyTrust(format string, attestation protocol.AttestationObject) (WebAuthnAttestationResult, error) {
	if format == string(protocol.AttestationFormatNone) {
		return WebAuthnAttestationResult{Format: format, SecurityLevel: "none", VerifierVersion: "gorape-webauthn-v1"}, nil
	}
	chain, hasX5C, err := attestationCertificates(attestation)
	if err != nil {
		return WebAuthnAttestationResult{}, err
	}
	if !hasX5C {
		if rp.allowSelf && format == string(protocol.AttestationFormatPacked) {
			return WebAuthnAttestationResult{Format: format, SecurityLevel: "self_attested", VerifierVersion: "gorape-webauthn-v1"}, nil
		}
		return WebAuthnAttestationResult{}, fmt.Errorf("%w: format %q has no trusted certificate chain", ErrAttestationPolicyDenied, format)
	}
	roots := rp.trustRoots[format]
	if roots == nil || len(roots.Subjects()) == 0 {
		return WebAuthnAttestationResult{}, fmt.Errorf("%w: no trust anchors configured for format %q", ErrAttestationPolicyDenied, format)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: time.Now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return WebAuthnAttestationResult{}, fmt.Errorf("WebAuthn %s attestation certificate chain: %w", format, err)
	}
	return WebAuthnAttestationResult{
		Format: format, SecurityLevel: attestationSecurityLevel(format),
		VerifierVersion: "gorape-webauthn-v1",
	}, nil
}

func toOptionsMap(options any) (map[string]any, error) {
	raw, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err = json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func attestationCertificates(attestation protocol.AttestationObject) ([]*x509.Certificate, bool, error) {
	value, exists := attestation.AttStatement["x5c"]
	if !exists {
		return nil, false, nil
	}
	encoded, ok := value.([]any)
	if !ok || len(encoded) == 0 {
		return nil, true, errors.New("WebAuthn attestation x5c must be a non-empty certificate array")
	}
	chain := make([]*x509.Certificate, 0, len(encoded))
	for _, value := range encoded {
		der, ok := value.([]byte)
		if !ok {
			return nil, true, errors.New("WebAuthn attestation x5c contains a non-DER certificate")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, true, fmt.Errorf("parse WebAuthn attestation certificate: %w", err)
		}
		chain = append(chain, cert)
	}
	return chain, true, nil
}

func validateCredentialID(id string, rawID []byte) error {
	if len(rawID) == 0 || id != base64.RawURLEncoding.EncodeToString(rawID) {
		return errors.New("credential id and rawId do not match")
	}
	return nil
}

func supportedTrustedFormat(format string) bool {
	switch format {
	case string(protocol.AttestationFormatPacked),
		string(protocol.AttestationFormatTPM),
		string(protocol.AttestationFormatAndroidKey),
		string(protocol.AttestationFormatFIDOUniversalSecondFactor),
		string(protocol.AttestationFormatApple):
		return true
	default:
		return false
	}
}

func attestationSecurityLevel(format string) string {
	switch format {
	case string(protocol.AttestationFormatTPM):
		return "tpm_attested"
	case string(protocol.AttestationFormatAndroidKey):
		return "android_key_attested"
	case string(protocol.AttestationFormatApple):
		return "apple_anonymous_attestation"
	case string(protocol.AttestationFormatFIDOUniversalSecondFactor):
		return "fido_u2f_attestation"
	case string(protocol.AttestationFormatPacked):
		return "packed_attestation"
	default:
		return "attested"
	}
}

func validateRPIdentity(rpID string, origins []string) error {
	rpID = strings.TrimSpace(rpID)
	if rpID == "" || strings.HasSuffix(rpID, ".") || rpID != strings.ToLower(rpID) || strings.ContainsAny(rpID, "/:@?#* ") {
		return errors.New("WebAuthn rp_id must be a lowercase host name without scheme, port, path, or wildcard")
	}
	if rpID != "localhost" {
		publicSuffix, _ := publicsuffix.PublicSuffix(rpID)
		if publicSuffix == rpID {
			return fmt.Errorf("WebAuthn rp_id %q must not be a public suffix", rpID)
		}
	}
	for _, origin := range origins {
		if origin == "" || strings.TrimSpace(origin) != origin || strings.Contains(origin, "*") {
			return errors.New("WebAuthn rp_origins must be exact non-empty origins without wildcards")
		}
		parsed, err := url.Parse(origin)
		if err != nil {
			return fmt.Errorf("invalid WebAuthn origin %q: %w", origin, err)
		}
		if parsed.Scheme == "https" || parsed.Scheme == "http" {
			host := strings.ToLower(parsed.Hostname())
			if host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
				return fmt.Errorf("WebAuthn origin %q must be an origin, not a URL path", origin)
			}
			if parsed.Scheme == "http" && host != "localhost" && host != "127.0.0.1" && host != "::1" {
				return fmt.Errorf("WebAuthn origin %q must use HTTPS except for localhost", origin)
			}
			if host != rpID && !strings.HasSuffix(host, "."+rpID) {
				return fmt.Errorf("WebAuthn origin host %q is not within RP ID %q", host, rpID)
			}
			continue
		}
		// Android Credential Manager uses this native WebAuthn origin form;
		// go-webauthn compares it literally against the configured allowlist.
		if parsed.Scheme != "android" || !strings.HasPrefix(origin, "android:apk-key-hash:") || strings.ContainsAny(origin, " \t\r\n") {
			return fmt.Errorf("invalid WebAuthn origin %q", origin)
		}
	}
	return nil
}

func bytesToLowerTrim(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
