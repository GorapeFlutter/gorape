package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/global"
)

var ErrUnsupportedAttestation = errors.New("attestation platform is unsupported")

type AttestationRequest struct {
	Platform     string
	Challenge    []byte
	PublicKeyPEM string
	Evidence     map[string]any
}
type AttestationResult struct {
	Type            string
	SecurityLevel   string
	Status          string
	VerifierVersion string
}

// AndroidAttestationPolicy must bind a trusted app signing identity. Patch
// floors are optional, but the corresponding attested fields are checked when set.
type AndroidAttestationPolicy struct {
	Applications            map[string][]string
	MinimumOSVersion        int
	MinimumOSPatchLevel     int
	MinimumVendorPatchLevel int
	MinimumBootPatchLevel   int
	RevocationChecker       *CertificateRevocationChecker
}

// GF-10031 — Requires a complete package/signing digest allowlist for Android attestation.
func (policy AndroidAttestationPolicy) Configured() bool {
	if len(policy.Applications) == 0 || policy.MinimumOSVersion < 0 ||
		policy.MinimumOSPatchLevel < 0 || policy.MinimumVendorPatchLevel < 0 ||
		policy.MinimumBootPatchLevel < 0 {
		return false
	}
	for packageName, digests := range policy.Applications {
		if strings.TrimSpace(packageName) == "" || len(digests) == 0 {
			return false
		}
		for _, digest := range digests {
			decoded, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(digest)), "sha256:"))
			if err != nil || len(decoded) != sha256.Size {
				return false
			}
		}
	}
	return true
}

type AttestationVerifier interface {
	Verify(context.Context, AttestationRequest) (*AttestationResult, error)
}
type VerifierRegistry struct {
	items             map[string]AttestationVerifier
	androidConfigured bool
}

func NewVerifierRegistry(androidRoots []string, policies ...AndroidAttestationPolicy) (*VerifierRegistry, error) {
	var policy AndroidAttestationPolicy
	if len(policies) > 0 {
		policy = policies[0]
	}
	a, e := NewAndroidVerifier(androidRoots, policy)
	if e != nil {
		return nil, e
	}
	return &VerifierRegistry{items: map[string]AttestationVerifier{"android": a}, androidConfigured: len(androidRoots) > 0 && policy.Configured()}, nil
}
func (rcvr *VerifierRegistry) Verify(ctx context.Context, q AttestationRequest) (*AttestationResult, error) {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNAT1, "VerifierRegistry Verify start", map[string]interface{}{"platform": q.Platform})
	}
	v := rcvr.items[q.Platform]
	if v == nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNAT2, "VerifierRegistry unsupported", nil)
		}
		return nil, ErrUnsupportedAttestation
	}
	res, e := v.Verify(ctx, q)
	if e != nil {
		if LoggerInstance != nil {
			LoggerInstance.DEBUG(rid, global.SRNAT3, "VerifierRegistry verify error", map[string]interface{}{"error": e})
		}
	}
	return res, e
}
func (rcvr *VerifierRegistry) Capabilities() map[string]string {
	android := "unconfigured"
	if rcvr.androidConfigured {
		android = "implemented"
	}
	return map[string]string{"android": android, "windows": "unsupported", "ios": "unsupported", "macos": "unsupported"}
}

type AndroidVerifier struct {
	roots  *x509.CertPool
	policy AndroidAttestationPolicy
}

func NewAndroidVerifier(files []string, policies ...AndroidAttestationPolicy) (*AndroidVerifier, error) {
	var policy AndroidAttestationPolicy
	if len(policies) > 0 {
		policy = policies[0]
	}
	p := x509.NewCertPool()
	for _, f := range files {
		b, e := os.ReadFile(f)
		if e != nil {
			return nil, fmt.Errorf("read Android trust anchor: %w", e)
		}
		if !p.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("no certificate in Android trust anchor %s", f)
		}
	}
	return &AndroidVerifier{roots: p, policy: policy}, nil
}

var androidKeyDescriptionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

type keyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	TEEEnforced              asn1.RawValue
}

type androidRootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte `asn1:"optional"`
}

type androidAttestationPackageInfo struct {
	PackageName []byte
	Version     int
}

type androidAttestationApplicationID struct {
	PackageInfos     []androidAttestationPackageInfo `asn1:"set"`
	SignatureDigests [][]byte                        `asn1:"set"`
}

const (
	androidTagPurpose        = 1
	androidTagAlgorithm      = 2
	androidTagKeySize        = 3
	androidTagDigest         = 5
	androidTagECurve         = 10
	androidTagOrigin         = 702
	androidTagRootOfTrust    = 704
	androidTagOSVersion      = 705
	androidTagOSPatchLevel   = 706
	androidTagApplicationID  = 709
	androidTagVendorPatch    = 718
	androidTagBootPatch      = 719
	androidAlgorithmEC       = 3
	androidPurposeSign       = 2
	androidPurposeVerify     = 3
	androidDigestSHA256      = 4
	androidCurveP256         = 1
	androidOriginGenerated   = 0
	androidVerifiedBootState = 0
)

func parseAndroidAuthorizationList(raw asn1.RawValue) (map[int]asn1.RawValue, error) {
	if len(raw.FullBytes) == 0 {
		return nil, errors.New("Android authorization list is missing")
	}
	var sequence asn1.RawValue
	remaining, err := asn1.Unmarshal(raw.FullBytes, &sequence)
	if err != nil || len(remaining) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence {
		return nil, errors.New("Android authorization list is malformed")
	}
	fields := make(map[int]asn1.RawValue)
	encoded := sequence.Bytes
	for len(encoded) > 0 {
		var field asn1.RawValue
		encoded, err = asn1.Unmarshal(encoded, &field)
		if err != nil || field.Class != asn1.ClassContextSpecific || !field.IsCompound {
			return nil, errors.New("Android authorization list contains an invalid field")
		}
		if _, exists := fields[field.Tag]; exists {
			return nil, errors.New("Android authorization list contains a duplicate field")
		}
		fields[field.Tag] = field
	}
	return fields, nil
}

func androidExplicitInt(fields map[int]asn1.RawValue, tag int) (int, bool, error) {
	field, ok := fields[tag]
	if !ok {
		return 0, false, nil
	}
	var value int
	remaining, err := asn1.Unmarshal(field.Bytes, &value)
	if err != nil || len(remaining) != 0 {
		return 0, true, fmt.Errorf("Android authorization integer tag %d is malformed", tag)
	}
	return value, true, nil
}

func androidExplicitIntSet(fields map[int]asn1.RawValue, tag int) ([]int, bool, error) {
	field, ok := fields[tag]
	if !ok {
		return nil, false, nil
	}
	var set asn1.RawValue
	remaining, err := asn1.Unmarshal(field.Bytes, &set)
	if err != nil || len(remaining) != 0 || set.Class != asn1.ClassUniversal || set.Tag != asn1.TagSet {
		return nil, true, fmt.Errorf("Android authorization SET tag %d is malformed", tag)
	}
	values := make([]int, 0)
	encoded := set.Bytes
	for len(encoded) > 0 {
		var value int
		encoded, err = asn1.Unmarshal(encoded, &value)
		if err != nil {
			return nil, true, fmt.Errorf("Android authorization SET tag %d is malformed", tag)
		}
		values = append(values, value)
	}
	return values, true, nil
}

func parseAndroidRootOfTrust(fields map[int]asn1.RawValue) (androidRootOfTrust, bool, error) {
	field, ok := fields[androidTagRootOfTrust]
	if !ok {
		return androidRootOfTrust{}, false, nil
	}
	var root androidRootOfTrust
	remaining, err := asn1.Unmarshal(field.Bytes, &root)
	if err != nil || len(remaining) != 0 {
		return androidRootOfTrust{}, true, errors.New("Android RootOfTrust is malformed")
	}
	return root, true, nil
}

func parseAndroidApplicationID(encoded []byte) (androidAttestationApplicationID, error) {
	var value []byte
	remaining, err := asn1.Unmarshal(encoded, &value)
	if err != nil || len(remaining) != 0 {
		return androidAttestationApplicationID{}, errors.New("Android attestationApplicationId OCTET STRING is malformed")
	}
	var appID androidAttestationApplicationID
	remaining, err = asn1.Unmarshal(value, &appID)
	if err != nil || len(remaining) != 0 {
		return androidAttestationApplicationID{}, errors.New("Android attestationApplicationId is malformed")
	}
	return appID, nil
}

func lookupAndroidAuthorizationValue(software, tee map[int]asn1.RawValue, tag int) (asn1.RawValue, bool) {
	if value, ok := tee[tag]; ok {
		return value, true
	}
	value, ok := software[tag]
	return value, ok
}

func (rcvr *AndroidVerifier) verifyAuthorizationPolicy(kd keyDescription) error {
	if !rcvr.policy.Configured() {
		return errors.New("Android application signing identity policy is not configured")
	}
	software, err := parseAndroidAuthorizationList(kd.SoftwareEnforced)
	if err != nil {
		return err
	}
	tee, err := parseAndroidAuthorizationList(kd.TEEEnforced)
	if err != nil {
		return err
	}
	if (kd.AttestationSecurityLevel != 1 && kd.AttestationSecurityLevel != 2) || kd.KeymasterSecurityLevel != kd.AttestationSecurityLevel {
		return errors.New("Android attestation and keymaster security levels must match TEE or StrongBox")
	}
	if err := verifyAndroidP256SigningKey(tee); err != nil {
		return err
	}
	root, ok, err := parseAndroidRootOfTrust(tee)
	if err != nil || !ok || len(root.VerifiedBootKey) == 0 || !root.DeviceLocked || root.VerifiedBootState != androidVerifiedBootState {
		return errors.New("Android RootOfTrust must be present, locked, and verified")
	}
	appIDRaw, ok := lookupAndroidAuthorizationValue(software, tee, androidTagApplicationID)
	if !ok {
		return errors.New("Android attestationApplicationId is missing")
	}
	appID, err := parseAndroidApplicationID(appIDRaw.Bytes)
	if err != nil {
		return err
	}
	if !androidApplicationAllowed(appID, rcvr.policy.Applications) {
		return errors.New("Android package identity or signing certificate is not allowed")
	}
	for _, threshold := range []struct {
		tag  int
		min  int
		name string
	}{
		{androidTagOSVersion, rcvr.policy.MinimumOSVersion, "OS version"},
		{androidTagOSPatchLevel, rcvr.policy.MinimumOSPatchLevel, "OS patch level"},
		{androidTagVendorPatch, rcvr.policy.MinimumVendorPatchLevel, "vendor patch level"},
		{androidTagBootPatch, rcvr.policy.MinimumBootPatchLevel, "boot patch level"},
	} {
		if threshold.min == 0 {
			continue
		}
		valueRaw, present := lookupAndroidAuthorizationValue(software, tee, threshold.tag)
		if !present {
			return fmt.Errorf("Android %s is required by policy", threshold.name)
		}
		value, err := decodeAndroidExplicitInt(valueRaw)
		if err != nil || value < threshold.min {
			return fmt.Errorf("Android %s is below the configured minimum", threshold.name)
		}
	}
	return nil
}

func verifyAndroidP256SigningKey(tee map[int]asn1.RawValue) error {
	algorithm, ok, err := androidExplicitInt(tee, androidTagAlgorithm)
	if err != nil || !ok || algorithm != androidAlgorithmEC {
		return errors.New("Android TEE key algorithm must be EC")
	}
	keySize, ok, err := androidExplicitInt(tee, androidTagKeySize)
	if err != nil || !ok || keySize != 256 {
		return errors.New("Android TEE key size must be P-256")
	}
	curve, ok, err := androidExplicitInt(tee, androidTagECurve)
	if err != nil || !ok || curve != androidCurveP256 {
		return errors.New("Android TEE elliptic curve must be P-256")
	}
	origin, ok, err := androidExplicitInt(tee, androidTagOrigin)
	if err != nil || !ok || origin != androidOriginGenerated {
		return errors.New("Android TEE key origin must be generated")
	}
	purposes, ok, err := androidExplicitIntSet(tee, androidTagPurpose)
	if err != nil || !ok || !containsAndroidInt(purposes, androidPurposeSign) || !containsAndroidInt(purposes, androidPurposeVerify) {
		return errors.New("Android TEE key purpose must include sign and verify")
	}
	digests, ok, err := androidExplicitIntSet(tee, androidTagDigest)
	if err != nil || !ok || !containsAndroidInt(digests, androidDigestSHA256) {
		return errors.New("Android TEE key digest must include SHA-256")
	}
	return nil
}

func decodeAndroidExplicitInt(raw asn1.RawValue) (int, error) {
	var value int
	remaining, err := asn1.Unmarshal(raw.Bytes, &value)
	if err != nil || len(remaining) != 0 {
		return 0, errors.New("Android authorization integer is malformed")
	}
	return value, nil
}

func containsAndroidInt(values []int, expected int) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func androidApplicationAllowed(appID androidAttestationApplicationID, allowed map[string][]string) bool {
	for _, pkg := range appID.PackageInfos {
		packageName := string(pkg.PackageName)
		digests, ok := allowed[packageName]
		if !ok {
			continue
		}
		for _, configured := range digests {
			configured = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(configured)), "sha256:")
			expected, err := hex.DecodeString(configured)
			if err != nil || len(expected) != sha256.Size {
				continue
			}
			for _, actual := range appID.SignatureDigests {
				if len(actual) == len(expected) && subtle.ConstantTimeCompare(actual, expected) == 1 {
					return true
				}
			}
		}
	}
	return false
}

func (rcvr *AndroidVerifier) Verify(ctx context.Context, q AttestationRequest) (*AttestationResult, error) {
	rid, _ := ctx.Value("requestID").(string)
	if LoggerInstance != nil {
		LoggerInstance.DEBUG(rid, global.SRNAT4, "AndroidVerifier Verify start", nil)
	}
	if len(rcvr.roots.Subjects()) == 0 {
		return nil, errors.New("Android attestation trust anchors are not configured")
	}
	rawChain, ok := q.Evidence["certificate_chain"].([]any)
	if !ok || len(rawChain) < 2 {
		return nil, errors.New("Android certificate_chain must contain leaf and issuer certificates")
	}
	chain := make([]*x509.Certificate, 0, len(rawChain))
	for _, x := range rawChain {
		s, ok := x.(string)
		if !ok {
			return nil, errors.New("invalid certificate_chain entry")
		}
		c, e := parseCertificate(s)
		if e != nil {
			return nil, e
		}
		chain = append(chain, c)
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, e := chain[0].Verify(x509.VerifyOptions{Roots: rcvr.roots, Intermediates: inter, CurrentTime: time.Now()}); e != nil {
		return nil, fmt.Errorf("Android certificate chain: %w", e)
	}
	if rcvr.policy.RevocationChecker != nil {
		for _, cert := range chain {
			if e := rcvr.policy.RevocationChecker.Check(ctx, cert); e != nil {
				return nil, fmt.Errorf("Android certificate revocation check: %w", e)
			}
		}
	}
	pubBlock, _ := pem.Decode([]byte(q.PublicKeyPEM))
	if pubBlock == nil {
		return nil, errors.New("public_key_pem is invalid")
	}
	pub, e := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if e != nil {
		return nil, e
	}
	expected, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		return nil, e
	}
	actual, e := x509.MarshalPKIXPublicKey(chain[0].PublicKey)
	if e != nil || !bytes.Equal(expected, actual) {
		return nil, errors.New("attested public key does not match submitted public key")
	}
	var kd keyDescription
	found := false
	for _, ext := range chain[0].Extensions {
		if ext.Id.Equal(androidKeyDescriptionOID) {
			if _, e := asn1.Unmarshal(ext.Value, &kd); e != nil {
				return nil, fmt.Errorf("Android key description: %w", e)
			}
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("Android key attestation extension is missing")
	}
	if !bytes.Equal(kd.AttestationChallenge, q.Challenge) {
		return nil, errors.New("Android attestation challenge mismatch")
	}
	if e := rcvr.verifyAuthorizationPolicy(kd); e != nil {
		return nil, e
	}
	level := "trusted_environment"
	if kd.AttestationSecurityLevel == 2 {
		level = "strongbox"
	}
	return &AttestationResult{Type: "android-key-attestation", SecurityLevel: level, Status: "verified", VerifierVersion: "gorape-android-v2"}, nil
}
func parseCertificate(s string) (*x509.Certificate, error) {
	if b, _ := pem.Decode([]byte(s)); b != nil {
		return x509.ParseCertificate(b.Bytes)
	}
	raw, e := base64.StdEncoding.DecodeString(s)
	if e != nil {
		return nil, errors.New("certificate must be PEM or base64 DER")
	}
	return x509.ParseCertificate(raw)
}
