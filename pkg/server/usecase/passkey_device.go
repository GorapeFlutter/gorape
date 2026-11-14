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
	BrowserOptions(context.Context, string) (response.PasskeyBrowserOptions, error)
	VerifyBrowserRegistration(context.Context, request.BrowserPasskeyRegistrationVerify) (response.PasskeyRegistrationResult, error)
	VerifyBrowserAuthentication(context.Context, request.BrowserPasskeyAuthenticationVerify) error
}

type passkeyDeviceUsecase struct {
	store      *repository.Store
	challenges repository.ChallengeStore
	projectUC  Project
	deviceUC   Device
	rp         *repository.WebAuthnRP
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

func NewPasskeyDevice(store *repository.Store, challenges repository.ChallengeStore, projectUC Project, deviceUC Device, rp *repository.WebAuthnRP) PasskeyDevice {
	return &passkeyDeviceUsecase{store: store, challenges: challenges, projectUC: projectUC, deviceUC: deviceUC, rp: rp}
}

func (uc *passkeyDeviceUsecase) RegistrationOptions(ctx context.Context, auth model.AuthContext, q request.PasskeyRegistrationOptions) (response.PasskeyCeremonyOptions, error) {
	if err := requirePasskeyAuthentication(auth); err != nil {
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

func (uc *passkeyDeviceUsecase) VerifyRegistration(ctx context.Context, auth model.AuthContext, q request.PasskeyRegistrationVerify) (response.PasskeyRegistrationResult, error) {
	if err := requirePasskeyAuthentication(auth); err != nil {
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
		if err := json.Unmarshal(ch.Payload, &pending); err != nil || pending.Platform != "linux" || !pending.PasskeyAuth || pending.PrincipalID == uuid.Nil || len(pending.PublicKey) == 0 {
			return response.PasskeyBrowserOptions{}, repository.ErrChallengeInvalid
		}
		if ch.Purpose != "webauthn-registration:linux" {
			return response.PasskeyBrowserOptions{}, repository.ErrChallengeInvalid
		}
		return response.PasskeyBrowserOptions{Ceremony: "registration", PublicKey: pending.PublicKey}, nil
	case ch.Purpose == "webauthn-proof":
		var pending authenticationSessionPayload
		if err := json.Unmarshal(ch.Payload, &pending); err != nil || pending.Platform != "linux" || !pending.PasskeyAuth || pending.PrincipalID == uuid.Nil || len(pending.PublicKey) == 0 {
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
		(auth == nil && pending.Platform != "linux") ||
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
	credential, attestation, err := uc.rp.VerifyRegistration(user, pending.Session, credentialJSON)
	if err != nil {
		return response.PasskeyRegistrationResult{}, err
	}
	algorithm := fmt.Sprintf("COSE-%d", credential.Attestation.PublicKeyAlgorithm)
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
	att := model.Attestation{
		AttestationType: attestation.Format, SecurityLevel: attestation.SecurityLevel,
		VerificationStatus: "verified", VerifierVersion: attestation.VerifierVersion,
	}
	if err := uc.store.RegisterDevice(ctx, &device, &key, &att, auth.Principal.ID); err != nil {
		return response.PasskeyRegistrationResult{}, err
	}
	return response.PasskeyRegistrationResult{
		Device: device,
		Attestation: response.PasskeyAttestation{
			AttestationType: attestation.Format, SecurityLevel: attestation.SecurityLevel,
			VerificationStatus: "verified", VerifierVersion: attestation.VerifierVersion,
		},
	}, nil
}

func (uc *passkeyDeviceUsecase) AuthenticationOptions(ctx context.Context, auth model.AuthContext, deviceID uuid.UUID, q request.PasskeyAuthenticationOptions) (response.PasskeyCeremonyOptions, error) {
	if err := requirePasskeyAuthentication(auth); err != nil {
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

func (uc *passkeyDeviceUsecase) VerifyAuthentication(ctx context.Context, auth model.AuthContext, deviceID uuid.UUID, q request.PasskeyAuthenticationVerify) error {
	if err := requirePasskeyAuthentication(auth); err != nil {
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
	if pending.Platform != "linux" {
		return repository.ErrChallengeInvalid
	}
	auth, err := uc.authFromChallenge(ctx, ch, pending.PrincipalID)
	if err != nil {
		return err
	}
	return uc.verifyAuthenticationChallenge(ctx, ch, auth, ch.DeviceID, q.Credential, false)
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
	return repository.WebAuthnUser{ID: id, Name: userID, DisplayName: "Gorape user"}
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
