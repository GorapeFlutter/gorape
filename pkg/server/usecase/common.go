package usecase

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/entity/request"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/google/uuid"
)

var ErrForbidden = errors.New("forbidden")

type ServiceInterface interface {
	Project
	Group
	Role
	Device
}

type Service struct {
	Store      *repository.Store
	Tokens     repository.TokenValidator
	Challenges repository.ChallengeStore
	Verifiers  *repository.VerifierRegistry

	project Project
	group   Group
	role    Role
	device  Device
}

func NewService(s *repository.Store, t repository.TokenValidator, c repository.ChallengeStore, v *repository.VerifierRegistry) *Service {
	proj := NewProject(s, t)
	grp := NewGroup(s, proj)
	role := NewRole(s, proj)
	dev := NewDevice(s, c, v, proj)
	return &Service{
		Store:      s,
		Tokens:     t,
		Challenges: c,
		Verifiers:  v,
		project:    proj,
		group:      grp,
		role:       role,
		device:     dev,
	}
}

// Project delegation
func (rcvr *Service) Authenticate(ctx context.Context, projectID, token string) (model.AuthContext, error) {
	return rcvr.project.Authenticate(ctx, projectID, token)
}
func (rcvr *Service) AuthenticateIssuer(ctx context.Context, token string) (model.AuthContext, error) {
	return rcvr.project.AuthenticateIssuer(ctx, token)
}
func (rcvr *Service) RequireProject(ctx context.Context, a model.AuthContext, min model.Role) error {
	return rcvr.project.RequireProject(ctx, a, min)
}

// Group delegation
func (rcvr *Service) RequireGroup(ctx context.Context, a model.AuthContext, g uuid.UUID, min model.Role) error {
	return rcvr.group.RequireGroup(ctx, a, g, min)
}
func (rcvr *Service) CreateGroup(ctx context.Context, a model.AuthContext, q request.GroupCreate) (model.GroupDomain, error) {
	return rcvr.group.CreateGroup(ctx, a, q)
}

// Role delegation
func (rcvr *Service) DeleteProjectRole(ctx context.Context, a model.AuthContext, b uuid.UUID) error {
	return rcvr.role.DeleteProjectRole(ctx, a, b)
}
func (rcvr *Service) DeleteGroupRole(ctx context.Context, a model.AuthContext, g, b uuid.UUID) error {
	return rcvr.role.DeleteGroupRole(ctx, a, g, b)
}
func (rcvr *Service) PutProjectRole(ctx context.Context, a model.AuthContext, q request.RoleCreate) error {
	return rcvr.role.PutProjectRole(ctx, a, q)
}
func (rcvr *Service) PutGroupRole(ctx context.Context, a model.AuthContext, g uuid.UUID, q request.RoleCreate) error {
	return rcvr.role.PutGroupRole(ctx, a, g, q)
}

// Device delegation
func (rcvr *Service) RegistrationChallenge(ctx context.Context, a model.AuthContext, platform string) (repository.Challenge, error) {
	return rcvr.device.RegistrationChallenge(ctx, a, platform)
}
func (rcvr *Service) VerifyRegistration(ctx context.Context, a model.AuthContext, q request.RegistrationVerify) (model.Device, error) {
	return rcvr.device.VerifyRegistration(ctx, a, q)
}
func (rcvr *Service) ProofChallenge(ctx context.Context, a model.AuthContext, d uuid.UUID) (repository.Challenge, error) {
	return rcvr.device.ProofChallenge(ctx, a, d)
}
func (rcvr *Service) VerifyProof(ctx context.Context, a model.AuthContext, d uuid.UUID, q request.ProofVerify) error {
	return rcvr.device.VerifyProof(ctx, a, d, q)
}

func verifySignature(der, msg []byte, encoded string) error {
	pub, e := x509.ParsePKIXPublicKey(der)
	if e != nil {
		return e
	}
	sig, e := base64.RawURLEncoding.DecodeString(encoded)
	if e != nil {
		sig, e = base64.StdEncoding.DecodeString(encoded)
	}
	if e != nil {
		return errors.New("signature must be base64url or base64")
	}
	sum := sha256.Sum256(msg)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, sum[:], sig) {
			return errors.New("invalid ECDSA signature")
		}
	case *rsa.PublicKey:
		if e = rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig); e != nil {
			return errors.New("invalid RSA signature")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(k, msg, sig) {
			return errors.New("invalid Ed25519 signature")
		}
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
	return nil
}

func GenerateTestProofKey() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }
