package repository

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/global"
	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
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
	MDS                   metadata.Provider
	RevocationChecker     *CertificateRevocationChecker
}

type WebAuthnRP struct {
	server            *webauthn.WebAuthn
	portalOrigin      string
	browserAPIOrigin  string
	allowed           map[string]bool
	allowNone         bool
	allowSelf         bool
	trustRoots        map[string]*x509.CertPool
	mds               metadata.Provider
	revocationChecker *CertificateRevocationChecker
	challengeTTL      time.Duration
}

// WebAuthnUser is the account identity and the credential set presented to
// go-webauthn for one registration or assertion ceremony.
type WebAuthnUser struct {
	ID                 []byte
	AllowedUserHandles [][]byte
	Name               string
	DisplayName        string
	Credentials        []webauthn.Credential
}

func (u WebAuthnUser) WebAuthnID() []byte                         { return u.ID }
func (u WebAuthnUser) WebAuthnName() string                       { return u.Name }
func (u WebAuthnUser) WebAuthnDisplayName() string                { return u.DisplayName }
func (u WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type WebAuthnAttestationResult struct {
	Format            string
	SecurityLevel     string
	AssuranceLevel    string
	HardwareProtected bool
	BackupEligible    bool
	BackupState       bool
	VerifierVersion   string
}

// GF-10010 — Validates RP/attestation configuration and constructs the WebAuthn RP.
func NewWebAuthnRP(config WebAuthnRPConfig) (*WebAuthnRP, error) {
	if LoggerInstance != nil {
		LoggerInstance.DEBUG("", global.SRNWA1, "NewWebAuthnRP start", map[string]interface{}{"rp_id": config.RPID})
	}
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
		MDS:                    config.MDS,
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
		allowSelf: config.AllowSelfAttestation, trustRoots: roots, mds: config.MDS,
		revocationChecker: config.RevocationChecker,
		challengeTTL:      config.ChallengeTTL,
	}, nil
}

func (rp *WebAuthnRP) RPID() string {
	if rp == nil || rp.server == nil || rp.server.Config == nil {
		return ""
	}
	return rp.server.Config.RPID
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

// GF-10012 — Creates WebAuthn registration options while excluding existing credentials.
func (rp *WebAuthnRP) RegistrationOptions(user WebAuthnUser) (map[string]any, webauthn.SessionData, error) {
	if LoggerInstance != nil {
		LoggerInstance.DEBUG("", global.SRNWA2, "RegistrationOptions start", map[string]interface{}{"user": user.Name})
	}
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
	if rp.mds != nil && len(rp.allowed) > 0 {
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

// GF-10013 — Verifies the registration response, credential ID, format, and attestation trust.
func (rp *WebAuthnRP) VerifyRegistration(ctx context.Context, user WebAuthnUser, session webauthn.SessionData, credentialJSON []byte) (*webauthn.Credential, WebAuthnAttestationResult, error) {
	if LoggerInstance != nil {
		LoggerInstance.DEBUG("", global.SRNWA3, "VerifyRegistration start", map[string]interface{}{"user": user.Name})
	}
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
	if !stored.Flags.BackupEligible && stored.Flags.BackupState {
		return nil, WebAuthnAttestationResult{}, errors.New("invalid WebAuthn flags: backup state set on non-backup-eligible credential")
	}
	result, err := rp.verifyTrust(ctx, format, parsed.Response.AttestationObject)
	if err != nil {
		return nil, WebAuthnAttestationResult{}, err
	}
	result.BackupEligible = stored.Flags.BackupEligible
	result.BackupState = stored.Flags.BackupState
	result.AssuranceLevel = model.ResolveAssuranceLevel(result.SecurityLevel, stored.Flags.BackupEligible, true)
	if !rp.allowNone && !rp.allowSelf && result.AssuranceLevel != model.AssuranceLevelHardwareAttested {
		return nil, WebAuthnAttestationResult{}, fmt.Errorf("%w: high-assurance policy requires hardware_attested (got %s)", ErrAttestationPolicyDenied, result.AssuranceLevel)
	}
	return stored, result, nil
}

// GF-10014 — Creates an assertion challenge for an enrolled WebAuthn credential.
func (rp *WebAuthnRP) AuthenticationOptions(user WebAuthnUser) (map[string]any, webauthn.SessionData, error) {
	if LoggerInstance != nil {
		LoggerInstance.DEBUG("", global.SRNWA4, "AuthenticationOptions start", map[string]interface{}{"user": user.Name})
	}
	assertion, session, err := rp.server.BeginLogin(user)
	if err != nil {
		return nil, webauthn.SessionData{}, err
	}
	session.Expires = time.Now().Add(rp.challengeTTL)
	options, err := toOptionsMap(assertion.Response)
	return options, *session, err
}

// GF-10015 — Verifies the WebAuthn assertion and returns the updated credential state.
func (rp *WebAuthnRP) VerifyAuthentication(user WebAuthnUser, session webauthn.SessionData, credentialJSON []byte) (*webauthn.Credential, error) {
	if LoggerInstance != nil {
		LoggerInstance.DEBUG("", global.SRNWA5, "VerifyAuthentication start", map[string]interface{}{"user": user.Name})
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(credentialJSON)
	if err != nil {
		return nil, err
	}
	if err = validateCredentialID(parsed.ID, parsed.RawID); err != nil {
		return nil, err
	}
	if len(parsed.Response.UserHandle) > 0 && !bytes.Equal(parsed.Response.UserHandle, user.ID) {
		for _, existing := range user.Credentials {
			if bytes.Equal(existing.ID, parsed.RawID) {
				user.ID = append([]byte(nil), parsed.Response.UserHandle...)
				session.UserID = append([]byte(nil), parsed.Response.UserHandle...)
				break
			}
		}
	}
	updated, err := rp.server.ValidateLogin(user, session, parsed)
	if err != nil {
		return nil, err
	}
	if !updated.Flags.BackupEligible && updated.Flags.BackupState {
		return nil, errors.New("invalid WebAuthn assertion flags: backup state set on non-backup-eligible credential")
	}
	if updated.Authenticator.CloneWarning {
		return nil, errors.New("WebAuthn authenticator clone warning detected")
	}
	for _, existing := range user.Credentials {
		if bytes.Equal(existing.ID, updated.ID) && existing.Flags.BackupEligible != updated.Flags.BackupEligible {
			return nil, errors.New("WebAuthn credential backup eligibility changed after registration")
		}
	}
	return updated, nil
}

func (rp *WebAuthnRP) verifyTrust(ctx context.Context, format string, attestation protocol.AttestationObject) (WebAuthnAttestationResult, error) {
	backupEligible := attestation.AuthData.Flags.HasBackupEligible()
	backupState := attestation.AuthData.Flags.HasBackupState()
	if format == string(protocol.AttestationFormatNone) {
		return WebAuthnAttestationResult{
			Format:            format,
			SecurityLevel:     "none",
			AssuranceLevel:    model.ResolveAssuranceLevel("none", backupEligible, true),
			HardwareProtected: false,
			BackupEligible:    backupEligible,
			BackupState:       backupState,
			VerifierVersion:   "gorape-webauthn-v1",
		}, nil
	}
	chain, hasX5C, err := attestationCertificates(attestation)
	if err != nil {
		return WebAuthnAttestationResult{}, err
	}
	if !hasX5C {
		if rp.allowSelf && format == string(protocol.AttestationFormatPacked) {
			return WebAuthnAttestationResult{
				Format:            format,
				SecurityLevel:     "self_attested",
				AssuranceLevel:    model.ResolveAssuranceLevel("self_attested", backupEligible, true),
				HardwareProtected: false,
				BackupEligible:    backupEligible,
				BackupState:       backupState,
				VerifierVersion:   "gorape-webauthn-v1",
			}, nil
		}
		return WebAuthnAttestationResult{}, fmt.Errorf("%w: format %q has no trusted certificate chain", ErrAttestationPolicyDenied, format)
	}
	if format == string(protocol.AttestationFormatAndroidKey) {
		if err := verifyWebAuthnAndroidKeyLeaf(chain[0]); err != nil {
			return WebAuthnAttestationResult{}, err
		}
	}
	if rp.mds != nil {
		aaguid, err := uuid.FromBytes(attestation.AuthData.AttData.AAGUID)
		if err != nil {
			return WebAuthnAttestationResult{}, fmt.Errorf("invalid WebAuthn AAGUID: %w", err)
		}
		x5cs, ok := attestation.AttStatement["x5c"].([]any)
		if !ok {
			return WebAuthnAttestationResult{}, fmt.Errorf("%w: MDS trust validation requires x5c", ErrAttestationPolicyDenied)
		}
		if err := protocol.ValidateMetadata(ctx, rp.mds, aaguid, "", format, x5cs); err != nil {
			return WebAuthnAttestationResult{}, fmt.Errorf("WebAuthn FIDO MDS validation: %w", err)
		}
		if err := rp.checkCertificateRevocation(ctx, chain); err != nil {
			return WebAuthnAttestationResult{}, err
		}
		return WebAuthnAttestationResult{
			Format:            format,
			SecurityLevel:     "fido_mds_verified",
			AssuranceLevel:    model.ResolveAssuranceLevel("fido_mds_verified", backupEligible, true),
			HardwareProtected: true,
			BackupEligible:    backupEligible,
			BackupState:       backupState,
			VerifierVersion:   "gorape-webauthn-mds-v1",
		}, nil
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
	if err := rp.checkCertificateRevocation(ctx, chain); err != nil {
		return WebAuthnAttestationResult{}, err
	}
	secLevel := attestationSecurityLevel(format)
	return WebAuthnAttestationResult{
		Format:            format,
		SecurityLevel:     secLevel,
		AssuranceLevel:    model.ResolveAssuranceLevel(secLevel, backupEligible, true),
		HardwareProtected: true,
		BackupEligible:    backupEligible,
		BackupState:       backupState,
		VerifierVersion:   "gorape-webauthn-v1",
	}, nil
}

// verifyWebAuthnAndroidKeyLeaf enforces TEE/StrongBox hardware backing and
// verified-boot RootOfTrust when an Android Key Attestation extension is present.
func verifyWebAuthnAndroidKeyLeaf(leaf *x509.Certificate) error {
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(androidKeyDescriptionOID) {
			continue
		}
		var kd keyDescription
		if _, err := asn1.Unmarshal(ext.Value, &kd); err != nil {
			return fmt.Errorf("WebAuthn android-key description: %w", err)
		}
		if (kd.AttestationSecurityLevel != 1 && kd.AttestationSecurityLevel != 2) ||
			kd.KeymasterSecurityLevel != kd.AttestationSecurityLevel {
			return fmt.Errorf("%w: Android WebAuthn key is not hardware-backed (TEE/StrongBox required)", ErrAttestationPolicyDenied)
		}
		tee, err := parseAndroidAuthorizationList(kd.TEEEnforced)
		if err != nil {
			return fmt.Errorf("WebAuthn android-key TEE authorization list: %w", err)
		}
		origin, ok, err := androidExplicitInt(tee, androidTagOrigin)
		if err != nil || !ok || origin != androidOriginGenerated {
			return fmt.Errorf("%w: Android WebAuthn key origin must be generated in hardware", ErrAttestationPolicyDenied)
		}
		root, ok, err := parseAndroidRootOfTrust(tee)
		if err != nil || !ok || len(root.VerifiedBootKey) == 0 || !root.DeviceLocked || root.VerifiedBootState != androidVerifiedBootState {
			return fmt.Errorf("%w: Android WebAuthn RootOfTrust must be locked and verified", ErrAttestationPolicyDenied)
		}
		return nil
	}
	return fmt.Errorf("%w: WebAuthn android-key certificate is missing Android key attestation extension", ErrAttestationPolicyDenied)
}

func (rp *WebAuthnRP) checkCertificateRevocation(ctx context.Context, chain []*x509.Certificate) error {
	if rp.revocationChecker == nil {
		return nil
	}
	for _, cert := range chain {
		if err := rp.revocationChecker.Check(ctx, cert); err != nil {
			return fmt.Errorf("WebAuthn attestation certificate revocation check: %w", err)
		}
	}
	return nil
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

// GF-10011 — Enforces a host-only RP ID and exact HTTPS/native origin allowlist.
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
			isLocalhost := host == "localhost" || host == "127.0.0.1" || host == "::1"
			if parsed.Scheme == "http" && !isLocalhost {
				return fmt.Errorf("WebAuthn origin %q must use HTTPS except for localhost", origin)
			}
			if !isLocalhost && host != rpID && !strings.HasSuffix(host, "."+rpID) {
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
