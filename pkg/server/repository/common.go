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
func (rcvr *Store) Project(ctx context.Context, id uuid.UUID) (model.Project, error) {
	return rcvr.project.Project(ctx, id)
}
func (rcvr *Store) ProjectByIssuer(ctx context.Context, issuer string) (model.Project, error) {
	return rcvr.project.ProjectByIssuer(ctx, issuer)
}
func (rcvr *Store) ProjectBySlug(ctx context.Context, slug string) (model.Project, error) {
	return rcvr.project.ProjectBySlug(ctx, slug)
}
func (rcvr *Store) PutProject(ctx context.Context, v *model.Project) error {
	return rcvr.project.PutProject(ctx, v)
}
func (rcvr *Store) Projects(ctx context.Context, principal uuid.UUID) ([]model.Project, error) {
	return rcvr.project.Projects(ctx, principal)
}

// Group methods
func (rcvr *Store) Groups(ctx context.Context, project uuid.UUID) ([]model.Group, error) {
	return rcvr.group.Groups(ctx, project)
}
func (rcvr *Store) Group(ctx context.Context, project, id uuid.UUID) (model.Group, error) {
	return rcvr.group.Group(ctx, project, id)
}
func (rcvr *Store) CreateGroup(ctx context.Context, v *model.Group) error {
	return rcvr.group.CreateGroup(ctx, v)
}
func (rcvr *Store) UpdateGroup(ctx context.Context, v *model.Group) error {
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
func (rcvr *Store) RegisterDevice(ctx context.Context, d *model.Device, k *model.DeviceKey, a *model.Attestation, actor uuid.UUID) error {
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
func (rcvr *Store) DeviceGroupIDs(ctx context.Context, project, device uuid.UUID) ([]uuid.UUID, error) {
	return rcvr.device.DeviceGroupIDs(ctx, project, device)
}

// Role / permission methods
func (rcvr *Store) RoleDefinition(ctx context.Context, project uuid.UUID, key string) (model.RoleDefinition, error) {
	return rcvr.role.RoleDefinition(ctx, project, key)
}
func (rcvr *Store) RoleDefinitions(ctx context.Context, project uuid.UUID) ([]model.RoleDefinition, error) {
	return rcvr.role.RoleDefinitions(ctx, project)
}
func (rcvr *Store) PutRoleDefinition(ctx context.Context, v *model.RoleDefinition) error {
	return rcvr.role.PutRoleDefinition(ctx, v)
}
func (rcvr *Store) DeleteRoleDefinition(ctx context.Context, project uuid.UUID, key string) error {
	return rcvr.role.DeleteRoleDefinition(ctx, project, key)
}
func (rcvr *Store) RoleBindings(ctx context.Context, project, principal uuid.UUID) ([]model.RoleBinding, error) {
	return rcvr.role.RoleBindings(ctx, project, principal)
}
func (rcvr *Store) ProjectRoleBindings(ctx context.Context, project uuid.UUID) ([]model.RoleBinding, error) {
	return rcvr.role.ProjectRoleBindings(ctx, project)
}
func (rcvr *Store) GroupRoleBindings(ctx context.Context, project, group uuid.UUID) ([]model.RoleBinding, error) {
	return rcvr.role.GroupRoleBindings(ctx, project, group)
}
func (rcvr *Store) RoleBinding(ctx context.Context, project, binding uuid.UUID) (model.RoleBinding, error) {
	return rcvr.role.RoleBinding(ctx, project, binding)
}
func (rcvr *Store) PutRoleBinding(ctx context.Context, v *model.RoleBinding) error {
	return rcvr.role.PutRoleBinding(ctx, v)
}
func (rcvr *Store) DeleteRoleBinding(ctx context.Context, project, binding uuid.UUID) error {
	return rcvr.role.DeleteRoleBinding(ctx, project, binding)
}

// Principal methods
func (rcvr *Store) EnsurePrincipal(ctx context.Context, project model.Project, issuer, subject string) (model.Principal, error) {
	return rcvr.principal.EnsurePrincipal(ctx, project, issuer, subject)
}
func (rcvr *Store) PrincipalBySubject(ctx context.Context, project uuid.UUID, subject string) (model.Principal, error) {
	return rcvr.principal.PrincipalBySubject(ctx, project, subject)
}

// AttestationStore methods
func (rcvr *Store) Attestations(ctx context.Context, project, device uuid.UUID) ([]model.Attestation, error) {
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
