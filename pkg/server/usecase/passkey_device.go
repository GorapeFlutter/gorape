package usecase

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/request"
	"github.com/Gorapeflutter/gorape/pkg/entity/response"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

var (
	ErrPasskeyUnavailable       = errors.New("Gorape WebAuthn RP is not configured")
	ErrPasskeyPortalUnavailable = errors.New("Gorape WebAuthn browser portal is not configured")
)

type PasskeyDevice interface {
	RegistrationOptions(context.Context, model.AuthContext, request.PasskeyRegistrationOptions) (response.PasskeyCeremonyOptions, error)
	VerifyRegistration(context.Context, model.AuthContext, request.PasskeyRegistrationVerify) (response.PasskeyRegistrationResult, error)
	AuthenticationOptions(context.Context, model.AuthContext, uuid.UUID, request.PasskeyAuthenticationOptions) (response.PasskeyCeremonyOptions, error)
	VerifyAuthentication(context.Context, model.AuthContext, uuid.UUID, request.PasskeyAuthenticationVerify) error
	CreateProofRequest(context.Context, model.AuthContext, request.ProofRequestCreate) (response.ProofRequestOptions, error)
	VerifyProofRequest(context.Context, model.AuthContext, string, request.ProofRequestVerify) (response.ProofRequestVerifyResult, error)
	BrowserOptions(context.Context, string) (response.PasskeyBrowserOptions, error)
	VerifyBrowserRegistration(context.Context, request.BrowserPasskeyRegistrationVerify) (response.PasskeyRegistrationResult, error)
	VerifyBrowserAuthentication(context.Context, request.BrowserPasskeyAuthenticationVerify) error
}

type passkeyDeviceUsecase struct {
	store         *repository.Store
	challenges    repository.ChallengeStore
	projectUC     Project
	deviceUC      Device
	rp            *repository.WebAuthnRP
	authAssurance AuthenticationAssurancePolicy
}

type registrationSessionPayload struct {
	Session     webauthn.SessionData `json:"session"`
	Platform    string               `json:"platform"`
	DisplayName string               `json:"display_name"`
	PrincipalID uuid.UUID            `json:"principal_id"`
	PasskeyAuth bool                 `json:"passkey_auth"`
	PublicKey   map[string]any       `json:"public_key"`
}

type authenticationSessionPayload struct {
	Session     webauthn.SessionData `json:"session"`
	PrincipalID uuid.UUID            `json:"principal_id"`
	Platform    string               `json:"platform"`
	PasskeyAuth bool                 `json:"passkey_auth"`
	PublicKey   map[string]any       `json:"public_key"`
}

type proofRequestCandidate struct {
	DeviceID       uuid.UUID `json:"device_id"`
	CredentialID   string    `json:"credential_id"`
	AssuranceLevel string    `json:"assurance_level"`
}

type proofRequestSessionPayload struct {
	Session           webauthn.SessionData             `json:"session"`
	ServiceID         string                           `json:"service_id"`
	PrincipalID       uuid.UUID                        `json:"principal_id"`
	PrincipalSubject  string                           `json:"principal_subject"`
	OperationID       string                           `json:"operation_id"`
	Method            string                           `json:"method"`
	Path              string                           `json:"path"`
	BodyHash          string                           `json:"body_hash"`
	RequiredAssurance string                           `json:"required_assurance"`
	Candidates        map[string]proofRequestCandidate `json:"candidates"`
}

func NewPasskeyDevice(store *repository.Store, challenges repository.ChallengeStore, projectUC Project, deviceUC Device, rp *repository.WebAuthnRP, policies ...AuthenticationAssurancePolicy) PasskeyDevice {
	var policy AuthenticationAssurancePolicy
	if len(policies) > 0 {
		policy = policies[0]
	}
	return &passkeyDeviceUsecase{store: store, challenges: challenges, projectUC: projectUC, deviceUC: deviceUC, rp: rp, authAssurance: policy}
}

// GF-10016 — Authorizes and binds registration options to a single-use challenge.
func (uc *passkeyDeviceUsecase) RegistrationOptions(ctx context.Context, auth model.AuthContext, q request.PasskeyRegistrationOptions) (response.PasskeyCeremonyOptions, error) {
	if err := uc.authAssurance.RequirePasskey(auth); err != nil {
		return response.PasskeyCeremonyOptions{}, err
	}
	if uc.rp == nil {
		return response.PasskeyCeremonyOptions{}, ErrPasskeyUnavailable
	}
	if err := uc.projectUC.RequireProject(ctx, auth, model.PermissionDeviceRegister); err != nil {
		return response.PasskeyCeremonyOptions{}, err
	}
	platform := strings.ToLower(strings.TrimSpace(q.Platform))
	if !supportedPasskeyPlatform(platform) {
		return response.PasskeyCeremonyOptions{}, fmt.Errorf("passkey platform %q is unsupported", platform)
	}
	browserURL := ""
	browserAPIOrigin := ""
	if platform == "linux" {
		browserURL = uc.rp.BrowserPortalURL()
		browserAPIOrigin = uc.rp.BrowserAPIOrigin()
		if !uc.rp.BrowserPortalReady() {
			return response.PasskeyCeremonyOptions{}, ErrPasskeyPortalUnavailable
		}
	} else if platform == "android" && uc.rp.RPID() == "localhost" && uc.rp.BrowserPortalReady() {
		browserURL = uc.rp.BrowserPortalURL()
		browserAPIOrigin = uc.rp.BrowserAPIOrigin()
	}
	displayName := strings.TrimSpace(q.DisplayName)
	if displayName == "" || len([]rune(displayName)) > 120 {
		return response.PasskeyCeremonyOptions{}, errors.New("display_name must contain between 1 and 120 characters")
	}
	user, err := uc.userWithExistingCredentials(ctx, auth)
	if err != nil {
		return response.PasskeyCeremonyOptions{}, err
	}
	options, session, err := uc.rp.RegistrationOptions(user)
	if err != nil {
		return response.PasskeyCeremonyOptions{}, err
	}
	payload, err := json.Marshal(registrationSessionPayload{
		Session: session, Platform: platform, DisplayName: displayName,
		PrincipalID: auth.Principal.ID, PasskeyAuth: true, PublicKey: options,
	})
	if err != nil {
		return response.PasskeyCeremonyOptions{}, err
	}
	challenge, err := decodeWebAuthnChallenge(session.Challenge)
	if err != nil {
		return response.PasskeyCeremonyOptions{}, err
	}
	ch, err := createWebAuthnChallenge(ctx, uc.challenges, auth, "webauthn-registration:"+platform, uuid.Nil, challenge, payload)
	if err != nil {
		return response.PasskeyCeremonyOptions{}, err
	}
	return response.PasskeyCeremonyOptions{
		ChallengeID: ch.ID, ExpiresAt: ch.ExpiresAt,
		PublicKey: options, BrowserURL: browserURL, BrowserAPIOrigin: browserAPIOrigin,
	}, nil
}

// GF-10017 — Consumes registration state, verifies the response, and stores the credential.
func (uc *passkeyDeviceUsecase) VerifyRegistration(ctx context.Context, auth model.AuthContext, q request.PasskeyRegistrationVerify) (response.PasskeyRegistrationResult, error) {
	if err := uc.authAssurance.RequirePasskey(auth); err != nil {
		return response.PasskeyRegistrationResult{}, err
	}
	if uc.rp == nil {
		return response.PasskeyRegistrationResult{}, ErrPasskeyUnavailable
	}
	if err := uc.projectUC.RequireProject(ctx, auth, model.PermissionDeviceRegister); err != nil {
		return response.PasskeyRegistrationResult{}, err
	}
	ch, err := uc.challenges.Consume(ctx, q.ChallengeID)
	if err != nil {
		return response.PasskeyRegistrationResult{}, err
	}
	return uc.verifyRegistrationChallenge(
		ctx, ch, &auth, strings.ToLower(strings.TrimSpace(q.Platform)),
		strings.TrimSpace(q.DisplayName), q.Credential,
	)
}

// GF-10021 — Completes browser registration using its single-use capability.
func (uc *passkeyDeviceUsecase) VerifyBrowserRegistration(ctx context.Context, q request.BrowserPasskeyRegistrationVerify) (response.PasskeyRegistrationResult, error) {
	if uc.rp == nil {
		return response.PasskeyRegistrationResult{}, ErrPasskeyUnavailable
	}
	ch, err := uc.challenges.Consume(ctx, q.ChallengeID)
	if err != nil {
		return response.PasskeyRegistrationResult{}, err
	}
	return uc.verifyRegistrationChallenge(ctx, ch, nil, "", "", q.Credential)
}

// GF-10020 — Reads only browser ceremony options bound to an unexpired capability.
func (uc *passkeyDeviceUsecase) BrowserOptions(ctx context.Context, challengeID string) (response.PasskeyBrowserOptions, error) {
	reader, ok := uc.challenges.(repository.ChallengeReader)
	if !ok {
		return response.PasskeyBrowserOptions{}, errors.New("challenge store does not support browser ceremony reads")
	}
	ch, err := reader.Get(ctx, challengeID)
	if err != nil {
		return response.PasskeyBrowserOptions{}, err
	}
	switch {
	case strings.HasPrefix(ch.Purpose, "webauthn-registration:"):
		var pending registrationSessionPayload
		if err := json.Unmarshal(ch.Payload, &pending); err != nil || !browserCeremonyAllowed(pending.Platform, uc.rp) || !pending.PasskeyAuth || pending.PrincipalID == uuid.Nil || len(pending.PublicKey) == 0 {
			return response.PasskeyBrowserOptions{}, repository.ErrChallengeInvalid
		}
		if ch.Purpose != "webauthn-registration:"+pending.Platform {
			return response.PasskeyBrowserOptions{}, repository.ErrChallengeInvalid
		}
		return response.PasskeyBrowserOptions{Ceremony: "registration", PublicKey: pending.PublicKey}, nil
	case ch.Purpose == "webauthn-proof":
		var pending authenticationSessionPayload
		if err := json.Unmarshal(ch.Payload, &pending); err != nil || !browserCeremonyAllowed(pending.Platform, uc.rp) || !pending.PasskeyAuth || pending.PrincipalID == uuid.Nil || len(pending.PublicKey) == 0 {
			return response.PasskeyBrowserOptions{}, repository.ErrChallengeInvalid
		}
		return response.PasskeyBrowserOptions{Ceremony: "authentication", PublicKey: pending.PublicKey}, nil
	default:
		return response.PasskeyBrowserOptions{}, repository.ErrChallengeInvalid
	}
}

func (uc *passkeyDeviceUsecase) verifyRegistrationChallenge(
	ctx context.Context,
	ch repository.Challenge,
	auth *model.AuthContext,
	requestedPlatform string,
	requestedDisplayName string,
	credentialJSON json.RawMessage,
) (response.PasskeyRegistrationResult, error) {
	var pending registrationSessionPayload
	if err := json.Unmarshal(ch.Payload, &pending); err != nil {
		return response.PasskeyRegistrationResult{}, repository.ErrChallengeInvalid
	}
	if ch.Purpose != "webauthn-registration:"+pending.Platform ||
		pending.PrincipalID == uuid.Nil ||
		!pending.PasskeyAuth ||
		(auth == nil && !browserCeremonyAllowed(pending.Platform, uc.rp)) ||
		(auth != nil && (ch.ProjectID != auth.Project.ID ||
			ch.Subject != auth.Claims.Subject || auth.Principal.ID != pending.PrincipalID)) ||
		(requestedPlatform != "" && pending.Platform != requestedPlatform) ||
		(requestedDisplayName != "" && pending.DisplayName != requestedDisplayName) {
		return response.PasskeyRegistrationResult{}, repository.ErrChallengeInvalid
	}
	if auth == nil {
		resolved, err := uc.authFromChallenge(ctx, ch, pending.PrincipalID)
		if err != nil {
			return response.PasskeyRegistrationResult{}, err
		}
		auth = &resolved
	}
	user := authWebAuthnUser(*auth)
	credential, attestation, err := uc.rp.VerifyRegistration(ctx, user, pending.Session, credentialJSON)
	if err != nil {
		return response.PasskeyRegistrationResult{}, err
	}
	coseAlg := credential.Attestation.PublicKeyAlgorithm
	if coseAlg == 0 {
		coseAlg = -7
	}
	algorithm := fmt.Sprintf("COSE-%d", coseAlg)
	credentialData, err := marshalCredentialWithoutAttestation(credential)
	if err != nil {
		return response.PasskeyRegistrationResult{}, err
	}
	keyID := base64.RawURLEncoding.EncodeToString(credential.ID)
	device := model.Device{
		ProjectID: auth.Project.ID, OwnerPrincipalID: auth.Principal.ID,
		Platform: pending.Platform, DisplayName: pending.DisplayName,
	}
	key := model.DeviceKey{
		PublicKey: credential.PublicKey, KeyIdentifier: keyID,
		Algorithm:      algorithm,
		CredentialData: credentialData,
	}
	assuranceLevel := attestation.AssuranceLevel
	if isHardwarePlatform(pending.Platform) {
		assuranceLevel = model.AssuranceLevelHardwareAttested
	}
	att := model.Attestation{
		AttestationType:    attestation.Format,
		SecurityLevel:      attestation.SecurityLevel,
		AssuranceLevel:     assuranceLevel,
		VerificationStatus: "verified",
		VerifierVersion:    attestation.VerifierVersion,
		EvidenceReference:  assuranceLevel,
	}
	if err := uc.store.RegisterDevice(ctx, &device, &key, &att, auth.Principal.ID); err != nil {
		return response.PasskeyRegistrationResult{}, err
	}
	return response.PasskeyRegistrationResult{
		Device: device,
		Attestation: response.PasskeyAttestation{
			AttestationType:    attestation.Format,
			SecurityLevel:      attestation.SecurityLevel,
			AssuranceLevel:     assuranceLevel,
			HardwareProtected:  attestation.HardwareProtected || isHardwarePlatform(pending.Platform),
			BackupEligible:     attestation.BackupEligible,
			BackupState:        attestation.BackupState,
			VerificationStatus: "verified",
			VerifierVersion:    attestation.VerifierVersion,
		},
	}, nil
}

// GF-10018 — Authorizes and binds assertion options to the requested device and challenge.
func (uc *passkeyDeviceUsecase) AuthenticationOptions(ctx context.Context, auth model.AuthContext, deviceID uuid.UUID, q request.PasskeyAuthenticationOptions) (response.PasskeyCeremonyOptions, error) {
	if err := uc.authAssurance.RequirePasskey(auth); err != nil {
		return response.PasskeyCeremonyOptions{}, err
	}
	if uc.rp == nil {
		return response.PasskeyCeremonyOptions{}, ErrPasskeyUnavailable
	}
	device, err := uc.store.Device(ctx, auth.Project.ID, deviceID)
	if err != nil || device.Status != "active" {
		return response.PasskeyCeremonyOptions{}, ErrForbidden
	}
	if err := uc.deviceUC.AuthorizeDevice(ctx, auth, deviceID, model.PermissionDeviceVerify); err != nil {
		return response.PasskeyCeremonyOptions{}, err
	}
	platform := strings.ToLower(strings.TrimSpace(q.Platform))
	if !supportedPasskeyPlatform(platform) {
		return response.PasskeyCeremonyOptions{}, fmt.Errorf("passkey platform %q is unsupported", platform)
	}
	browserURL := ""
	browserAPIOrigin := ""
	if platform == "linux" {
		browserURL = uc.rp.BrowserPortalURL()
		browserAPIOrigin = uc.rp.BrowserAPIOrigin()
		if !uc.rp.BrowserPortalReady() {
			return response.PasskeyCeremonyOptions{}, ErrPasskeyPortalUnavailable
		}
	} else if platform == "android" && uc.rp.RPID() == "localhost" && uc.rp.BrowserPortalReady() {
		browserURL = uc.rp.BrowserPortalURL()
		browserAPIOrigin = uc.rp.BrowserAPIOrigin()
	}
	key, err := uc.store.DeviceKey(ctx, auth.Project.ID, deviceID)
	if err != nil {
		return response.PasskeyCeremonyOptions{}, err
	}
	credential, err := unmarshalWebAuthnCredential(key.CredentialData)
	if err != nil {
		return response.PasskeyCeremonyOptions{}, errors.New("device is not registered with a WebAuthn passkey")
	}
	user := authWebAuthnUser(auth)
	user.Credentials = []webauthn.Credential{credential}
	options, session, err := uc.rp.AuthenticationOptions(user)
	if err != nil {
		return response.PasskeyCeremonyOptions{}, err
	}
	payload, err := json.Marshal(authenticationSessionPayload{
		Session: session, PrincipalID: auth.Principal.ID, Platform: platform,
		PasskeyAuth: true, PublicKey: options,
	})
	if err != nil {
		return response.PasskeyCeremonyOptions{}, err
	}
	challenge, err := decodeWebAuthnChallenge(session.Challenge)
	if err != nil {
		return response.PasskeyCeremonyOptions{}, err
	}
	ch, err := createWebAuthnChallenge(ctx, uc.challenges, auth, "webauthn-proof", deviceID, challenge, payload)
	if err != nil {
		return response.PasskeyCeremonyOptions{}, err
	}
	return response.PasskeyCeremonyOptions{
		ChallengeID: ch.ID, ExpiresAt: ch.ExpiresAt,
		PublicKey: options, BrowserURL: browserURL, BrowserAPIOrigin: browserAPIOrigin,
	}, nil
}

// GF-10019 — Consumes assertion state and records verified device possession.
func (uc *passkeyDeviceUsecase) VerifyAuthentication(ctx context.Context, auth model.AuthContext, deviceID uuid.UUID, q request.PasskeyAuthenticationVerify) error {
	if err := uc.authAssurance.RequirePasskey(auth); err != nil {
		return err
	}
	if uc.rp == nil {
		return ErrPasskeyUnavailable
	}
	ch, err := uc.challenges.Consume(ctx, q.ChallengeID)
	if err != nil {
		return err
	}
	if ch.ProjectID != auth.Project.ID || ch.Subject != auth.Claims.Subject || ch.Purpose != "webauthn-proof" || ch.DeviceID != deviceID {
		return repository.ErrChallengeInvalid
	}
	return uc.verifyAuthenticationChallenge(ctx, ch, auth, deviceID, q.Credential, true)
}

// GF-10022 — Completes browser assertion using its single-use capability.
func (uc *passkeyDeviceUsecase) VerifyBrowserAuthentication(ctx context.Context, q request.BrowserPasskeyAuthenticationVerify) error {
	if uc.rp == nil {
		return ErrPasskeyUnavailable
	}
	ch, err := uc.challenges.Consume(ctx, q.ChallengeID)
	if err != nil {
		return err
	}
	if ch.Purpose != "webauthn-proof" || ch.DeviceID == uuid.Nil {
		return repository.ErrChallengeInvalid
	}
	var pending authenticationSessionPayload
	if err := json.Unmarshal(ch.Payload, &pending); err != nil || pending.PrincipalID == uuid.Nil || !pending.PasskeyAuth {
		return repository.ErrChallengeInvalid
	}
	if !browserCeremonyAllowed(pending.Platform, uc.rp) {
		return repository.ErrChallengeInvalid
	}
	auth, err := uc.authFromChallenge(ctx, ch, pending.PrincipalID)
	if err != nil {
		return err
	}
	return uc.verifyAuthenticationChallenge(ctx, ch, auth, ch.DeviceID, q.Credential, false)
}

// GF-10035 — Creates an operation-bound WebAuthn challenge for an external relying service.
func (uc *passkeyDeviceUsecase) CreateProofRequest(ctx context.Context, auth model.AuthContext, q request.ProofRequestCreate) (response.ProofRequestOptions, error) {
	if uc.rp == nil {
		return response.ProofRequestOptions{}, ErrPasskeyUnavailable
	}
	if err := uc.projectUC.RequireProject(ctx, auth, model.PermissionProofRequest); err != nil {
		return response.ProofRequestOptions{}, err
	}
	serviceID := strings.TrimSpace(q.ServiceID)
	operationID := strings.TrimSpace(q.OperationID)
	method := strings.ToUpper(strings.TrimSpace(q.Method))
	path := strings.TrimSpace(q.Path)
	bodyHash := strings.TrimSpace(q.BodyHash)
	requiredAssurance := strings.ToLower(strings.TrimSpace(q.RequiredAssurance))
	if requiredAssurance == "" {
		requiredAssurance = model.AssuranceLevelStandardPasskey
	}
	if serviceID == "" || operationID == "" || method == "" || !strings.HasPrefix(path, "/") || bodyHash == "" {
		return response.ProofRequestOptions{}, errors.New("service_id, operation_id, method, normalized path, and body_hash are required")
	}
	if !model.ValidAssuranceLevel(requiredAssurance) || requiredAssurance == model.AssuranceLevelRejected {
		return response.ProofRequestOptions{}, fmt.Errorf("invalid required_assurance %q", requiredAssurance)
	}
	if err := verifyCallerServiceIdentity(auth, serviceID); err != nil {
		return response.ProofRequestOptions{}, err
	}
	principal, err := uc.resolveTargetPrincipal(ctx, auth.Project.ID, strings.TrimSpace(q.PrincipalID))
	if err != nil {
		return response.ProofRequestOptions{}, err
	}
	user, candidates, err := uc.userCredentialsForProofRequest(
		ctx, auth.Project.ID, principal, requiredAssurance, strings.TrimSpace(q.CredentialID),
	)
	if err != nil {
		return response.ProofRequestOptions{}, err
	}
	options, session, err := uc.rp.AuthenticationOptions(user)
	if err != nil {
		return response.ProofRequestOptions{}, err
	}
	enableCrossDeviceTransports(options)
	payload, err := json.Marshal(proofRequestSessionPayload{
		Session:           session,
		ServiceID:         serviceID,
		PrincipalID:       principal.ID,
		PrincipalSubject:  principal.OIDCSubject,
		OperationID:       operationID,
		Method:            method,
		Path:              path,
		BodyHash:          bodyHash,
		RequiredAssurance: requiredAssurance,
		Candidates:        candidates,
	})
	if err != nil {
		return response.ProofRequestOptions{}, err
	}
	challenge, err := decodeWebAuthnChallenge(session.Challenge)
	if err != nil {
		return response.ProofRequestOptions{}, err
	}
	store, ok := uc.challenges.(repository.ChallengePayloadStore)
	if !ok {
		return response.ProofRequestOptions{}, errors.New("challenge store does not support proof request state")
	}
	ch, err := store.CreateWithValue(ctx, auth.Project.ID, principal.OIDCSubject, "external-proof-request", uuid.Nil, challenge, payload)
	if err != nil {
		return response.ProofRequestOptions{}, err
	}
	return response.ProofRequestOptions{
		ProofID:          ch.ID,
		ExpiresAt:        ch.ExpiresAt,
		PublicKeyOptions: options,
	}, nil
}

// GF-10036 — Atomically consumes a proof request and verifies the operation-bound assertion.
func (uc *passkeyDeviceUsecase) VerifyProofRequest(ctx context.Context, auth model.AuthContext, proofID string, q request.ProofRequestVerify) (response.ProofRequestVerifyResult, error) {
	if uc.rp == nil {
		return response.ProofRequestVerifyResult{}, ErrPasskeyUnavailable
	}
	if err := uc.projectUC.RequireProject(ctx, auth, model.PermissionProofVerify); err != nil {
		return response.ProofRequestVerifyResult{}, err
	}
	serviceID := strings.TrimSpace(q.ServiceID)
	operationID := strings.TrimSpace(q.OperationID)
	if serviceID == "" || operationID == "" {
		return response.ProofRequestVerifyResult{}, errors.New("service_id and operation_id are required")
	}
	if err := verifyCallerServiceIdentity(auth, serviceID); err != nil {
		return response.ProofRequestVerifyResult{}, err
	}
	ch, err := uc.challenges.Consume(ctx, strings.TrimSpace(proofID))
	if err != nil {
		return response.ProofRequestVerifyResult{}, err
	}
	if ch.ProjectID != auth.Project.ID || ch.Purpose != "external-proof-request" {
		return response.ProofRequestVerifyResult{}, repository.ErrChallengeInvalid
	}
	var pending proofRequestSessionPayload
	if err := json.Unmarshal(ch.Payload, &pending); err != nil {
		return response.ProofRequestVerifyResult{}, repository.ErrChallengeInvalid
	}
	if pending.ServiceID != serviceID || pending.OperationID != operationID || pending.PrincipalID == uuid.Nil || len(pending.Candidates) == 0 {
		return response.ProofRequestVerifyResult{}, repository.ErrChallengeInvalid
	}
	var assertionEnvelope struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(q.Credential, &assertionEnvelope); err != nil || strings.TrimSpace(assertionEnvelope.ID) == "" {
		return response.ProofRequestVerifyResult{}, errors.New("invalid WebAuthn credential assertion")
	}
	candidate, ok := pending.Candidates[assertionEnvelope.ID]
	if !ok {
		return response.ProofRequestVerifyResult{}, ErrForbidden
	}
	device, err := uc.store.Device(ctx, auth.Project.ID, candidate.DeviceID)
	if err != nil || device.Status != "active" || device.OwnerPrincipalID != pending.PrincipalID {
		return response.ProofRequestVerifyResult{}, ErrForbidden
	}
	key, err := uc.store.DeviceKey(ctx, auth.Project.ID, device.ID)
	if err != nil || key.Status != "active" || key.KeyIdentifier != assertionEnvelope.ID {
		return response.ProofRequestVerifyResult{}, ErrForbidden
	}
	credential, err := unmarshalWebAuthnCredential(key.CredentialData)
	if err != nil {
		return response.ProofRequestVerifyResult{}, err
	}
	actualAssurance := uc.deviceAssuranceLevel(ctx, auth.Project.ID, device.ID, credential.Flags.BackupEligible, candidate.AssuranceLevel)
	if !model.AssuranceSatisfies(actualAssurance, pending.RequiredAssurance) {
		return response.ProofRequestVerifyResult{}, repository.ErrAttestationPolicyDenied
	}
	user := repository.WebAuthnUser{
		ID:                 append([]byte(nil), pending.PrincipalID[:]...),
		AllowedUserHandles: principalUserHandles(pending.PrincipalID, pending.PrincipalSubject),
		Name:               pending.PrincipalID.String(),
		DisplayName:        "Gorape user",
		Credentials:        []webauthn.Credential{credential},
	}
	updated, err := uc.rp.VerifyAuthentication(user, pending.Session, q.Credential)
	if err != nil {
		return response.ProofRequestVerifyResult{}, err
	}
	if !bytes.Equal(updated.ID, credential.ID) || base64.RawURLEncoding.EncodeToString(updated.ID) != key.KeyIdentifier {
		return response.ProofRequestVerifyResult{}, repository.ErrChallengeInvalid
	}
	credentialData, err := marshalCredentialWithoutAttestation(updated)
	if err != nil {
		return response.ProofRequestVerifyResult{}, err
	}
	if err := uc.store.UpdateCredentialData(ctx, auth.Project.ID, device.ID, credentialData); err != nil {
		return response.ProofRequestVerifyResult{}, err
	}
	if err := uc.store.MarkDeviceVerified(ctx, auth.Project.ID, device.ID, pending.PrincipalID); err != nil {
		return response.ProofRequestVerifyResult{}, err
	}
	return response.ProofRequestVerifyResult{
		Verified:       true,
		PrincipalID:    pending.PrincipalID,
		DeviceID:       device.ID,
		CredentialID:   key.KeyIdentifier,
		AssuranceLevel: actualAssurance,
		OperationID:    pending.OperationID,
	}, nil
}

func verifyCallerServiceIdentity(auth model.AuthContext, requestedServiceID string) error {
	tokenServiceID := strings.TrimSpace(auth.Claims.ServiceIdentifier())
	if tokenServiceID != "" && tokenServiceID != requestedServiceID && auth.Claims.Subject != requestedServiceID {
		return ErrForbidden
	}
	return nil
}

func (uc *passkeyDeviceUsecase) resolveTargetPrincipal(ctx context.Context, projectID uuid.UUID, identifier string) (model.Principal, error) {
	if id, err := uuid.Parse(identifier); err == nil {
		if principal, err := uc.store.Principal(ctx, projectID, id); err == nil {
			return principal, nil
		}
	}
	return uc.store.PrincipalBySubject(ctx, projectID, identifier)
}

func (uc *passkeyDeviceUsecase) userCredentialsForProofRequest(
	ctx context.Context,
	projectID uuid.UUID,
	principal model.Principal,
	requiredAssurance string,
	requestedCredentialID string,
) (repository.WebAuthnUser, map[string]proofRequestCandidate, error) {
	user := repository.WebAuthnUser{
		ID:          append([]byte(nil), principal.ID[:]...),
		Name:        principal.ID.String(),
		DisplayName: "Gorape user",
	}
	devices, err := uc.store.Devices(ctx, projectID)
	if err != nil {
		return repository.WebAuthnUser{}, nil, err
	}
	candidates := make(map[string]proofRequestCandidate)
	for _, device := range devices {
		if device.OwnerPrincipalID != principal.ID || device.Status != "active" {
			continue
		}
		key, keyErr := uc.store.DeviceKey(ctx, projectID, device.ID)
		if keyErr != nil || key.Status != "active" || len(key.CredentialData) == 0 {
			continue
		}
		if requestedCredentialID != "" && key.KeyIdentifier != requestedCredentialID {
			continue
		}
		credential, credErr := unmarshalWebAuthnCredential(key.CredentialData)
		if credErr != nil {
			continue
		}
		assurance := uc.deviceAssuranceLevel(ctx, projectID, device.ID, credential.Flags.BackupEligible, "")
		if !model.AssuranceSatisfies(assurance, requiredAssurance) {
			continue
		}
		credential.Transport = withCrossDeviceTransports(credential.Transport)
		user.Credentials = append(user.Credentials, credential)
		candidates[key.KeyIdentifier] = proofRequestCandidate{
			DeviceID:       device.ID,
			CredentialID:   key.KeyIdentifier,
			AssuranceLevel: assurance,
		}
	}
	if len(user.Credentials) == 0 {
		return repository.WebAuthnUser{}, nil, repository.ErrAttestationPolicyDenied
	}
	return user, candidates, nil
}

func (uc *passkeyDeviceUsecase) deviceAssuranceLevel(
	ctx context.Context,
	projectID, deviceID uuid.UUID,
	backupEligible bool,
	fallback string,
) string {
	device, devErr := uc.store.Device(ctx, projectID, deviceID)
	records, err := uc.store.Attestations(ctx, projectID, deviceID)
	if err == nil && len(records) > 0 {
		if records[0].VerificationStatus == "verified" && devErr == nil && isHardwarePlatform(device.Platform) {
			return model.AssuranceLevelHardwareAttested
		}
		return records[0].EffectiveAssuranceLevel(backupEligible)
	}
	if devErr == nil && device.Status == "active" && isHardwarePlatform(device.Platform) {
		return model.AssuranceLevelHardwareAttested
	}
	if model.ValidAssuranceLevel(fallback) {
		return fallback
	}
	return model.ResolveAssuranceLevel("none", backupEligible, true)
}

func isHardwarePlatform(platform string) bool {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "android", "ios", "macos", "windows":
		return true
	default:
		return false
	}
}

func withCrossDeviceTransports(transports []protocol.AuthenticatorTransport) []protocol.AuthenticatorTransport {
	out := append([]protocol.AuthenticatorTransport(nil), transports...)
	for _, needed := range []protocol.AuthenticatorTransport{protocol.Internal, protocol.Hybrid} {
		found := false
		for _, t := range out {
			if t == needed {
				found = true
				break
			}
		}
		if !found {
			out = append(out, needed)
		}
	}
	return out
}

func enableCrossDeviceTransports(options map[string]any) {
	rawList, ok := options["allowCredentials"].([]any)
	if !ok {
		return
	}
	for _, item := range rawList {
		descriptor, ok := item.(map[string]any)
		if !ok {
			continue
		}
		existing, _ := descriptor["transports"].([]any)
		seen := map[string]bool{}
		merged := make([]string, 0, len(existing)+2)
		for _, v := range existing {
			if s, ok := v.(string); ok && s != "" && !seen[s] {
				seen[s] = true
				merged = append(merged, s)
			}
		}
		for _, required := range []string{"internal", "hybrid"} {
			if !seen[required] {
				seen[required] = true
				merged = append(merged, required)
			}
		}
		descriptor["transports"] = merged
	}
}

func (uc *passkeyDeviceUsecase) verifyAuthenticationChallenge(
	ctx context.Context,
	ch repository.Challenge,
	auth model.AuthContext,
	deviceID uuid.UUID,
	credentialJSON json.RawMessage,
	checkPermission bool,
) error {
	if ch.ProjectID != auth.Project.ID || ch.Subject != auth.Claims.Subject || ch.Purpose != "webauthn-proof" || ch.DeviceID != deviceID {
		return repository.ErrChallengeInvalid
	}
	device, err := uc.store.Device(ctx, auth.Project.ID, deviceID)
	if err != nil || device.Status != "active" {
		return ErrForbidden
	}
	if checkPermission {
		if err := uc.deviceUC.AuthorizeDevice(ctx, auth, deviceID, model.PermissionDeviceVerify); err != nil {
			return err
		}
	}
	var pending authenticationSessionPayload
	if err := json.Unmarshal(ch.Payload, &pending); err != nil || !pending.PasskeyAuth {
		return repository.ErrChallengeInvalid
	}
	key, err := uc.store.DeviceKey(ctx, auth.Project.ID, deviceID)
	if err != nil {
		return err
	}
	credential, err := unmarshalWebAuthnCredential(key.CredentialData)
	if err != nil {
		return errors.New("device is not registered with a WebAuthn passkey")
	}
	user := authWebAuthnUser(auth)
	user.Credentials = []webauthn.Credential{credential}
	updated, err := uc.rp.VerifyAuthentication(user, pending.Session, credentialJSON)
	if err != nil {
		return err
	}
	if !bytes.Equal(updated.ID, credential.ID) || base64.RawURLEncoding.EncodeToString(updated.ID) != key.KeyIdentifier {
		return repository.ErrChallengeInvalid
	}
	credentialData, err := marshalCredentialWithoutAttestation(updated)
	if err != nil {
		return err
	}
	if err := uc.store.UpdateCredentialData(ctx, auth.Project.ID, deviceID, credentialData); err != nil {
		return err
	}
	return uc.store.MarkDeviceVerified(ctx, auth.Project.ID, deviceID, auth.Principal.ID)
}

func (uc *passkeyDeviceUsecase) authFromChallenge(ctx context.Context, challenge repository.Challenge, principalID uuid.UUID) (model.AuthContext, error) {
	project, err := uc.store.Project(ctx, challenge.ProjectID)
	if err != nil {
		return model.AuthContext{}, err
	}
	principal, err := uc.store.PrincipalBySubject(ctx, challenge.ProjectID, challenge.Subject)
	if err != nil || principal.ID != principalID {
		return model.AuthContext{}, repository.ErrChallengeInvalid
	}
	return model.AuthContext{
		Project:   project,
		Principal: principal,
		Claims:    model.AccessTokenClaims{Issuer: principal.OIDCIssuer, Subject: principal.OIDCSubject},
	}, nil
}

func authWebAuthnUser(auth model.AuthContext) repository.WebAuthnUser {
	id := append([]byte(nil), auth.Principal.ID[:]...)
	userID := auth.Principal.ID.String()
	return repository.WebAuthnUser{
		ID:                 id,
		AllowedUserHandles: principalUserHandles(auth.Principal.ID, auth.Principal.OIDCSubject),
		Name:               userID,
		DisplayName:        "Gorape user",
	}
}

func principalUserHandles(principalID uuid.UUID, subject string) [][]byte {
	handles := [][]byte{
		append([]byte(nil), principalID[:]...),
		[]byte(principalID.String()),
	}
	if trimmed := strings.TrimSpace(subject); trimmed != "" {
		handles = append(handles, []byte(trimmed))
		if subUUID, err := uuid.Parse(trimmed); err == nil {
			handles = append(handles, append([]byte(nil), subUUID[:]...))
		}
	}
	return handles
}

func (uc *passkeyDeviceUsecase) userWithExistingCredentials(ctx context.Context, auth model.AuthContext) (repository.WebAuthnUser, error) {
	user := authWebAuthnUser(auth)
	devices, err := uc.store.Devices(ctx, auth.Project.ID)
	if err != nil {
		return repository.WebAuthnUser{}, err
	}
	for _, device := range devices {
		if device.OwnerPrincipalID != auth.Principal.ID || device.Status != "active" {
			continue
		}
		key, keyErr := uc.store.DeviceKey(ctx, auth.Project.ID, device.ID)
		if keyErr != nil {
			if errors.Is(keyErr, repository.ErrNotFound) {
				continue
			}
			return repository.WebAuthnUser{}, keyErr
		}
		if len(key.CredentialData) == 0 {
			continue
		}
		credential, credentialErr := unmarshalWebAuthnCredential(key.CredentialData)
		if credentialErr != nil {
			return repository.WebAuthnUser{}, credentialErr
		}
		user.Credentials = append(user.Credentials, credential)
	}
	return user, nil
}

func createWebAuthnChallenge(ctx context.Context, challenges repository.ChallengeStore, auth model.AuthContext, purpose string, deviceID uuid.UUID, value []byte, payload json.RawMessage) (repository.Challenge, error) {
	store, ok := challenges.(repository.ChallengePayloadStore)
	if !ok {
		return repository.Challenge{}, errors.New("challenge store does not support WebAuthn ceremony state")
	}
	return store.CreateWithValue(ctx, auth.Project.ID, auth.Claims.Subject, purpose, deviceID, value, payload)
}

func decodeWebAuthnChallenge(challenge string) ([]byte, error) {
	value, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(value) < 16 {
		return nil, errors.New("WebAuthn library produced an invalid challenge")
	}
	return value, nil
}

func marshalCredentialWithoutAttestation(credential *webauthn.Credential) ([]byte, error) {
	if credential == nil {
		return nil, errors.New("WebAuthn credential is nil")
	}
	credential.Attestation = webauthn.CredentialAttestation{}
	return json.Marshal(credential)
}

func unmarshalWebAuthnCredential(data []byte) (webauthn.Credential, error) {
	var credential webauthn.Credential
	if len(data) == 0 {
		return credential, errors.New("missing WebAuthn credential data")
	}
	if err := json.Unmarshal(data, &credential); err != nil {
		return credential, err
	}
	if len(credential.ID) == 0 || len(credential.PublicKey) == 0 {
		return credential, errors.New("invalid WebAuthn credential data")
	}
	return credential, nil
}

func supportedPasskeyPlatform(platform string) bool {
	switch platform {
	case "android", "ios", "macos", "windows", "linux", "web":
		return true
	default:
		return false
	}
}

func browserCeremonyAllowed(platform string, rp *repository.WebAuthnRP) bool {
	if platform == "linux" {
		return true
	}
	return platform == "android" && rp != nil && rp.RPID() == "localhost"
}
