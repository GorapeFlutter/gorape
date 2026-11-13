package usecase

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/request"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/google/uuid"
)

type Device interface {
	RegistrationChallenge(ctx context.Context, a model.AuthContext, platform string) (repository.Challenge, error)
	VerifyRegistration(ctx context.Context, a model.AuthContext, q request.RegistrationVerify) (model.Device, error)
	ProofChallenge(ctx context.Context, a model.AuthContext, d uuid.UUID) (repository.Challenge, error)
	VerifyProof(ctx context.Context, a model.AuthContext, d uuid.UUID, q request.ProofVerify) error
}

type deviceUsecase struct {
	store      *repository.Store
	challenges repository.ChallengeStore
	verifiers  *repository.VerifierRegistry
	projectUC  Project
}

func NewDevice(store *repository.Store, challenges repository.ChallengeStore, verifiers *repository.VerifierRegistry, projectUC Project) Device {
	return &deviceUsecase{store: store, challenges: challenges, verifiers: verifiers, projectUC: projectUC}
}

func (rcvr *deviceUsecase) RegistrationChallenge(ctx context.Context, a model.AuthContext, platform string) (repository.Challenge, error) {
	if e := rcvr.projectUC.RequireProject(ctx, a, model.RoleEditor); e != nil {
		return repository.Challenge{}, e
	}
	return rcvr.challenges.Create(ctx, a.Project.ID, a.Claims.Subject, "registration:"+platform, uuid.Nil)
}

func (rcvr *deviceUsecase) VerifyRegistration(ctx context.Context, a model.AuthContext, q request.RegistrationVerify) (model.Device, error) {
	if e := rcvr.projectUC.RequireProject(ctx, a, model.RoleEditor); e != nil {
		return model.Device{}, e
	}
	ch, e := rcvr.challenges.Consume(ctx, q.ChallengeID)
	if e != nil {
		return model.Device{}, e
	}
	if ch.ProjectID != a.Project.ID || ch.Subject != a.Claims.Subject || ch.Purpose != "registration:"+q.Platform {
		return model.Device{}, repository.ErrChallengeInvalid
	}
	result, e := rcvr.verifiers.Verify(ctx, repository.AttestationRequest{Platform: q.Platform, Challenge: ch.Value, PublicKeyPEM: q.PublicKeyPEM, Evidence: q.Evidence})
	if e != nil {
		return model.Device{}, e
	}
	block, _ := pem.Decode([]byte(q.PublicKeyPEM))
	if block == nil {
		return model.Device{}, errors.New("invalid public key PEM")
	}
	if _, e = x509.ParsePKIXPublicKey(block.Bytes); e != nil {
		return model.Device{}, e
	}
	d := model.Device{ProjectID: a.Project.ID, OwnerPrincipalID: a.Principal.ID, Platform: q.Platform, DisplayName: q.DisplayName}
	k := model.DeviceKey{PublicKey: block.Bytes, KeyIdentifier: q.KeyIdentifier, Algorithm: q.Algorithm}
	att := model.AttestationRecord{AttestationType: result.Type, SecurityLevel: result.SecurityLevel, VerificationStatus: result.Status, VerifierVersion: result.VerifierVersion}
	e = rcvr.store.RegisterDevice(ctx, &d, &k, &att, a.Principal.ID)
	return d, e
}

func (rcvr *deviceUsecase) ProofChallenge(ctx context.Context, a model.AuthContext, d uuid.UUID) (repository.Challenge, error) {
	dev, e := rcvr.store.Device(ctx, a.Project.ID, d)
	if e != nil {
		return repository.Challenge{}, e
	}
	if dev.Status != "active" {
		return repository.Challenge{}, ErrForbidden
	}
	if dev.OwnerPrincipalID != a.Principal.ID {
		if e = rcvr.projectUC.RequireProject(ctx, a, model.RoleEditor); e != nil {
			return repository.Challenge{}, e
		}
	}
	return rcvr.challenges.Create(ctx, a.Project.ID, a.Claims.Subject, "proof", d)
}

func (rcvr *deviceUsecase) VerifyProof(ctx context.Context, a model.AuthContext, d uuid.UUID, q request.ProofVerify) error {
	ch, e := rcvr.challenges.Consume(ctx, q.ChallengeID)
	if e != nil {
		return e
	}
	if ch.ProjectID != a.Project.ID || ch.Subject != a.Claims.Subject || ch.Purpose != "proof" || ch.DeviceID != d {
		return repository.ErrChallengeInvalid
	}
	dev, e := rcvr.store.Device(ctx, a.Project.ID, d)
	if e != nil || dev.Status != "active" {
		return ErrForbidden
	}
	if dev.OwnerPrincipalID != a.Principal.ID {
		if e = rcvr.projectUC.RequireProject(ctx, a, model.RoleEditor); e != nil {
			return e
		}
	}
	key, e := rcvr.store.DeviceKey(ctx, a.Project.ID, d)
	if e != nil {
		return e
	}
	if e = verifySignature(key.PublicKey, ch.Value, q.Signature); e != nil {
		return e
	}
	return rcvr.store.MarkDeviceVerified(ctx, a.Project.ID, d, a.Principal.ID)
}
