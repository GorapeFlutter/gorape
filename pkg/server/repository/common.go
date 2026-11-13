package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var ErrNotFound = errors.New("not found")

type StoreInterface interface {
	DB() *gorm.DB
	Project
	Group
	Device
	Role
	Principal
	AttestationStore
}

type Store struct {
	db          *gorm.DB
	project     Project
	group       Group
	device      Device
	role        Role
	principal   Principal
	attestation AttestationStore
}

func NewStore(db *gorm.DB) *Store {
	return &Store{
		db:          db,
		project:     NewProject(db),
		group:       NewGroup(db),
		device:      NewDevice(db),
		role:        NewRole(db),
		principal:   NewPrincipal(db),
		attestation: NewAttestationStore(db),
	}
}

func (rcvr *Store) DB() *gorm.DB { return rcvr.db }

// Project methods
func (rcvr *Store) Project(ctx context.Context, id uuid.UUID) (model.ProjectDomain, error) {
	return rcvr.project.Project(ctx, id)
}
func (rcvr *Store) ProjectByIssuer(ctx context.Context, issuer string) (model.ProjectDomain, error) {
	return rcvr.project.ProjectByIssuer(ctx, issuer)
}
func (rcvr *Store) Projects(ctx context.Context, principal uuid.UUID) ([]model.ProjectDomain, error) {
	return rcvr.project.Projects(ctx, principal)
}

// Group methods
func (rcvr *Store) Groups(ctx context.Context, project uuid.UUID) ([]model.GroupDomain, error) {
	return rcvr.group.Groups(ctx, project)
}
func (rcvr *Store) Group(ctx context.Context, project, id uuid.UUID) (model.GroupDomain, error) {
	return rcvr.group.Group(ctx, project, id)
}
func (rcvr *Store) CreateGroup(ctx context.Context, v *model.GroupDomain) error {
	return rcvr.group.CreateGroup(ctx, v)
}
func (rcvr *Store) UpdateGroup(ctx context.Context, v *model.GroupDomain) error {
	return rcvr.group.UpdateGroup(ctx, v)
}
func (rcvr *Store) DeleteGroup(ctx context.Context, project, id uuid.UUID) error {
	return rcvr.group.DeleteGroup(ctx, project, id)
}

// Device methods
func (rcvr *Store) Devices(ctx context.Context, project uuid.UUID) ([]model.Device, error) {
	return rcvr.device.Devices(ctx, project)
}
func (rcvr *Store) Device(ctx context.Context, project, id uuid.UUID) (model.Device, error) {
	return rcvr.device.Device(ctx, project, id)
}
func (rcvr *Store) DeviceKey(ctx context.Context, project, device uuid.UUID) (model.DeviceKey, error) {
	return rcvr.device.DeviceKey(ctx, project, device)
}
func (rcvr *Store) RegisterDevice(ctx context.Context, d *model.Device, k *model.DeviceKey, a *model.AttestationRecord, actor uuid.UUID) error {
	return rcvr.device.RegisterDevice(ctx, d, k, a, actor)
}
func (rcvr *Store) RevokeDevice(ctx context.Context, project, id, actor uuid.UUID) error {
	return rcvr.device.RevokeDevice(ctx, project, id, actor)
}
func (rcvr *Store) MarkDeviceVerified(ctx context.Context, project, id, actor uuid.UUID) error {
	return rcvr.device.MarkDeviceVerified(ctx, project, id, actor)
}
func (rcvr *Store) GroupDevices(ctx context.Context, project, group uuid.UUID) ([]model.Device, error) {
	return rcvr.device.GroupDevices(ctx, project, group)
}
func (rcvr *Store) BindDevice(ctx context.Context, project, group, device uuid.UUID) error {
	return rcvr.device.BindDevice(ctx, project, group, device)
}
func (rcvr *Store) UnbindDevice(ctx context.Context, project, group, device uuid.UUID) error {
	return rcvr.device.UnbindDevice(ctx, project, group, device)
}

// Role methods
func (rcvr *Store) ProjectRole(ctx context.Context, project, principal uuid.UUID) (model.Role, error) {
	return rcvr.role.ProjectRole(ctx, project, principal)
}
func (rcvr *Store) GroupRole(ctx context.Context, project, group, principal uuid.UUID) (model.Role, error) {
	return rcvr.role.GroupRole(ctx, project, group, principal)
}
func (rcvr *Store) ProjectRoles(ctx context.Context, project uuid.UUID) ([]model.ProjectRoleBinding, error) {
	return rcvr.role.ProjectRoles(ctx, project)
}
func (rcvr *Store) GroupRoles(ctx context.Context, project, group uuid.UUID) ([]model.GroupRoleBinding, error) {
	return rcvr.role.GroupRoles(ctx, project, group)
}
func (rcvr *Store) ProjectRoleBinding(ctx context.Context, project, binding uuid.UUID) (model.ProjectRoleBinding, error) {
	return rcvr.role.ProjectRoleBinding(ctx, project, binding)
}
func (rcvr *Store) GroupRoleBinding(ctx context.Context, project, group, binding uuid.UUID) (model.GroupRoleBinding, error) {
	return rcvr.role.GroupRoleBinding(ctx, project, group, binding)
}
func (rcvr *Store) PutProjectRole(ctx context.Context, v *model.ProjectRoleBinding) error {
	return rcvr.role.PutProjectRole(ctx, v)
}
func (rcvr *Store) PutGroupRole(ctx context.Context, v *model.GroupRoleBinding) error {
	return rcvr.role.PutGroupRole(ctx, v)
}
func (rcvr *Store) DeleteProjectRole(ctx context.Context, project, binding uuid.UUID) error {
	return rcvr.role.DeleteProjectRole(ctx, project, binding)
}
func (rcvr *Store) DeleteGroupRole(ctx context.Context, project, group, binding uuid.UUID) error {
	return rcvr.role.DeleteGroupRole(ctx, project, group, binding)
}

// Principal methods
func (rcvr *Store) EnsurePrincipal(ctx context.Context, project model.ProjectDomain, issuer, subject string) (model.IdentityPrincipal, error) {
	return rcvr.principal.EnsurePrincipal(ctx, project, issuer, subject)
}
func (rcvr *Store) PrincipalBySubject(ctx context.Context, project uuid.UUID, subject string) (model.IdentityPrincipal, error) {
	return rcvr.principal.PrincipalBySubject(ctx, project, subject)
}

// AttestationStore methods
func (rcvr *Store) Attestations(ctx context.Context, project, device uuid.UUID) ([]model.AttestationRecord, error) {
	return rcvr.attestation.Attestations(ctx, project, device)
}

func mapNotFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}

func ParseUUID(s string) (uuid.UUID, error) {
	v, e := uuid.Parse(s)
	if e != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID: %w", e)
	}
	return v, nil
}
