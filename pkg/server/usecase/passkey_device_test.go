package usecase

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

func TestStoredWebAuthnCredentialDropsRawAttestationEvidence(t *testing.T) {
	credential := &webauthn.Credential{
		ID:              []byte("credential-id"),
		PublicKey:       []byte("cose-public-key"),
		AttestationType: "tpm",
		Attestation: webauthn.CredentialAttestation{
			ClientDataJSON: []byte("client-data"),
			Object:         []byte("sensitive-attestation-object-and-certificate-chain"),
		},
	}

	stored, err := marshalCredentialWithoutAttestation(credential)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("sensitive-attestation-object-and-certificate-chain")) {
		t.Fatal("stored credential contains raw attestation evidence")
	}
	parsed, err := unmarshalWebAuthnCredential(stored)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Attestation.Object) != 0 || len(parsed.Attestation.ClientDataJSON) != 0 {
		t.Fatal("credential attestation data was not removed before persistence")
	}
	if !bytes.Equal(parsed.ID, credential.ID) || !bytes.Equal(parsed.PublicKey, credential.PublicKey) {
		t.Fatal("credential identifier or public key was lost")
	}
}

func TestBrowserOptionsExposeOnlyLinuxChallengesUntilConsumed(t *testing.T) {
	store := repository.NewMemoryChallengeStore(time.Minute)
	principalID := uuid.New()
	payload, err := json.Marshal(registrationSessionPayload{
		Platform: "linux", PrincipalID: principalID,
		PasskeyAuth: true, PublicKey: map[string]any{"challenge": "example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := store.CreateWithValue(context.Background(), uuid.New(), "subject", "webauthn-registration:linux", uuid.Nil, bytes.Repeat([]byte{1}, 32), payload)
	if err != nil {
		t.Fatal(err)
	}

	usecase := passkeyDeviceUsecase{challenges: store}
	options, err := usecase.BrowserOptions(context.Background(), challenge.ID)
	if err != nil {
		t.Fatal(err)
	}
	if options.Ceremony != "registration" || options.PublicKey["challenge"] != "example" {
		t.Fatalf("unexpected browser options: %+v", options)
	}

	if _, err = store.Consume(context.Background(), challenge.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = usecase.BrowserOptions(context.Background(), challenge.ID); err == nil {
		t.Fatal("consumed browser capability still returned WebAuthn options")
	}
}

func TestBrowserOptionsRejectsNonLinuxChallenge(t *testing.T) {
	store := repository.NewMemoryChallengeStore(time.Minute)
	payload, err := json.Marshal(registrationSessionPayload{
		Platform: "android", PrincipalID: uuid.New(),
		PasskeyAuth: true, PublicKey: map[string]any{"challenge": "example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := store.CreateWithValue(context.Background(), uuid.New(), "subject", "webauthn-registration:android", uuid.Nil, bytes.Repeat([]byte{2}, 32), payload)
	if err != nil {
		t.Fatal(err)
	}
	usecase := passkeyDeviceUsecase{challenges: store}
	if _, err := usecase.BrowserOptions(context.Background(), challenge.ID); err == nil {
		t.Fatal("browser endpoint exposed native-platform ceremony options")
	}
}
