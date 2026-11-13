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
	"github.com/Gorapeflutter/gorape/pkg/entity/provisioning"
	"github.com/Gorapeflutter/gorape/pkg/entity/request"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
	"github.com/google/uuid"
)

var (
	ErrForbidden        = errors.New("forbidden")
	ErrPlatformDisabled = errors.New("platform authentication is disabled")
)

type ServiceInterface interface {
	Project
	Group
	Role
	Device
	Provisioning
}

type Service struct {
	Store      *repository.Store
	Tokens     repository.TokenValidator
	Challenges repository.ChallengeStore
	Verifiers  *repository.VerifierRegistry

	project      Project
	group        Group
	role         Role
	device       Device
	provisioning Provisioning
}

func NewService(s *repository.Store, t repository.TokenValidator, c repository.ChallengeStore, v *repository.VerifierRegistry) *Service {
	proj := NewProject(s, t)
	return &Service{
		Store:      s,
		Tokens:     t,
		Challenges: c,
		Verifiers:  v,
		project:    proj,
		group:      NewGroup(s, proj),
		role:       NewRole(s, proj),
		device:     NewDevice(s, c, v, proj),
	}
}

// ConfigurePlatform enables platform administration tokens. The issuer must
// be the Keycloak realm issuer used by Gorape administrators, and adminRoles
// are realm or client roles that grant platform access.
func (rcvr *Service) ConfigurePlatform(issuer string, adminRoles []string) {
	if p, ok := rcvr.project.(*projectUsecase); ok {
		p.configurePlatform(issuer, adminRoles)
	}
}

// ConfigureProvisioning enables manifest provisioning. keycloak may be nil to
// allow Gorape-only manifests.
func (rcvr *Service) ConfigureProvisioning(gorape repository.Provisioning, keycloak repository.KeycloakProvisioner) {
	rcvr.provisioning = NewProvisioning(gorape, keycloak, rcvr.project)
}

// Project delegation
func (rcvr *Service) Authenticate(ctx context.Context, projectID, token string) (model.AuthContext, error) {
	return rcvr.project.Authenticate(ctx, projectID, token)
}
func (rcvr *Service) AuthenticateIssuer(ctx context.Context, token string) (model.AuthContext, error) {
	return rcvr.project.AuthenticateIssuer(ctx, token)
}
func (rcvr *Service) AuthenticatePlatform(ctx context.Context, token string) (model.AuthContext, error) {
	return rcvr.project.AuthenticatePlatform(ctx, token)
}
func (rcvr *Service) RequirePlatform(ctx context.Context, a model.AuthContext) error {
	return rcvr.project.RequirePlatform(ctx, a)
}
func (rcvr *Service) RequireProject(ctx context.Context, a model.AuthContext, permission model.Permission) error {
	return rcvr.project.RequireProject(ctx, a, permission)
}
func (rcvr *Service) RequireProjectRole(ctx context.Context, a model.AuthContext, role model.Role) error {
	return rcvr.project.RequireProjectRole(ctx, a, role)
}
func (rcvr *Service) EffectivePermissions(ctx context.Context, a model.AuthContext, group *uuid.UUID) (model.PermissionSet, []string, error) {
	return rcvr.project.EffectivePermissions(ctx, a, group)
}

// Group delegation
func (rcvr *Service) RequireGroup(ctx context.Context, a model.AuthContext, g uuid.UUID, permission model.Permission) error {
	return rcvr.group.RequireGroup(ctx, a, g, permission)
}
func (rcvr *Service) CreateGroup(ctx context.Context, a model.AuthContext, q request.GroupCreate) (model.Group, error) {
	return rcvr.group.CreateGroup(ctx, a, q)
}

// Role delegation
func (rcvr *Service) DeleteRoleBinding(ctx context.Context, a model.AuthContext, b uuid.UUID) error {
	return rcvr.role.DeleteRoleBinding(ctx, a, b)
}
func (rcvr *Service) PutProjectRole(ctx context.Context, a model.AuthContext, q request.RoleCreate) error {
	return rcvr.role.PutProjectRole(ctx, a, q)
}
func (rcvr *Service) PutGroupRole(ctx context.Context, a model.AuthContext, g uuid.UUID, q request.RoleCreate) error {
	return rcvr.role.PutGroupRole(ctx, a, g, q)
}
func (rcvr *Service) PutRoleDefinition(ctx context.Context, a model.AuthContext, key string, q request.RoleDefinitionPut) (model.RoleDefinition, error) {
	return rcvr.role.PutRoleDefinition(ctx, a, key, q)
}
func (rcvr *Service) DeleteRoleDefinition(ctx context.Context, a model.AuthContext, key string) error {
	return rcvr.role.DeleteRoleDefinition(ctx, a, key)
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
func (rcvr *Service) AuthorizeDevice(ctx context.Context, a model.AuthContext, d uuid.UUID, permission model.Permission) error {
	return rcvr.device.AuthorizeDevice(ctx, a, d, permission)
}

// Provisioning delegation
func (rcvr *Service) PlanProvisioning(ctx context.Context, a model.AuthContext, m provisioning.Manifest) (provisioning.Result, error) {
	if rcvr.provisioning == nil {
		return provisioning.Result{}, ErrProvisioningDisabled
	}
	return rcvr.provisioning.PlanProvisioning(ctx, a, m)
}
func (rcvr *Service) ApplyProvisioning(ctx context.Context, a model.AuthContext, m provisioning.Manifest) (provisioning.Result, error) {
	if rcvr.provisioning == nil {
		return provisioning.Result{}, ErrProvisioningDisabled
	}
	return rcvr.provisioning.ApplyProvisioning(ctx, a, m)
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
