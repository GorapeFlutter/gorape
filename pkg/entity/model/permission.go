package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// Permission is a fine-grained authorization capability evaluated by Gorape.
//
// Wildcards are supported during evaluation:
//   - "*" grants every permission.
//   - "device:*" grants every permission whose name starts with "device:".
//
// Permissions are intentionally small, composable strings so that Keycloak
// role/group changes can take effect without changing the Gorape binary.
type Permission string

const (
	PermissionProjectRead   Permission = "project:read"
	PermissionProjectManage Permission = "project:manage"

	PermissionGroupRead   Permission = "group:read"
	PermissionGroupBind   Permission = "group:bind"
	PermissionGroupManage Permission = "group:manage"

	PermissionDeviceRead     Permission = "device:read"
	PermissionDeviceRegister Permission = "device:register"
	PermissionDeviceVerify   Permission = "device:verify"
	PermissionDeviceRevoke   Permission = "device:revoke"

	PermissionAttestationRead Permission = "attestation:read"

	PermissionRoleRead   Permission = "role:read"
	PermissionRoleManage Permission = "role:manage"

	PermissionProvisionManage Permission = "provision:manage"
)

// PermissionList is the JSONB representation of a role definition.
type PermissionList []string

func (rcvr PermissionList) Value() (driver.Value, error) {
	if rcvr == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]string(rcvr))
}

func (rcvr *PermissionList) Scan(value any) error {
	if value == nil {
		*rcvr = PermissionList{}
		return nil
	}
	var raw []byte
	switch v := value.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return errors.New("permission list must be JSONB")
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	*rcvr = PermissionList(out)
	return nil
}

// PermissionSet is the effective permission set for one request.
type PermissionSet map[string]struct{}

func NewPermissionSet() PermissionSet { return PermissionSet{} }

func (rcvr PermissionSet) Add(permissions ...string) {
	for _, p := range permissions {
		p = strings.TrimSpace(p)
		if p != "" {
			rcvr[p] = struct{}{}
		}
	}
}

func (rcvr PermissionSet) AddAll(other PermissionSet) {
	for p := range other {
		rcvr[p] = struct{}{}
	}
}

func (rcvr PermissionSet) Allows(required Permission) bool {
	if required == "" {
		return true
	}
	needle := string(required)
	for granted := range rcvr {
		if granted == "*" || granted == needle {
			return true
		}
		if strings.HasSuffix(granted, ":*") && strings.HasPrefix(needle, strings.TrimSuffix(granted, "*")) {
			return true
		}
	}
	return false
}

func (rcvr PermissionSet) Slice() []string {
	out := make([]string, 0, len(rcvr))
	for p := range rcvr {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// BuiltinRolePermissions defines the default permission presets. Projects can
// override them with role definitions stored in PostgreSQL, and may add custom
// roles that are mapped to Keycloak realm/client roles or group paths.
var BuiltinRolePermissions = map[string][]string{
	string(RoleViewer): {
		string(PermissionProjectRead),
		string(PermissionGroupRead),
		string(PermissionDeviceRead),
		string(PermissionAttestationRead),
	},
	string(RoleEditor): {
		string(PermissionProjectRead),
		string(PermissionGroupRead),
		string(PermissionGroupBind),
		string(PermissionDeviceRead),
		string(PermissionDeviceRegister),
		string(PermissionDeviceVerify),
		string(PermissionDeviceRevoke),
		string(PermissionAttestationRead),
	},
	string(RoleAdmin): {
		"*",
	},
}

func BuiltinPermissions(key string) ([]string, bool) {
	v, ok := BuiltinRolePermissions[key]
	if !ok {
		return nil, false
	}
	out := make([]string, len(v))
	copy(out, v)
	return out, true
}

// KeycloakRoleName returns the default Keycloak realm/client role that maps to
// a builtin Gorape role key. Provisioning stores this mapping explicitly, but
// the convention keeps existing manifests short.
func KeycloakRoleName(roleKey string) string { return "gorape-" + roleKey }

// EffectivePermissions expands role definitions into a permission set.
func EffectivePermissions(definitions []RoleDefinition, keys []string) PermissionSet {
	byKey := make(map[string]RoleDefinition, len(definitions))
	for _, d := range definitions {
		byKey[d.Key] = d
	}
	set := NewPermissionSet()
	for _, key := range keys {
		if d, ok := byKey[key]; ok {
			set.Add(d.Permissions...)
			continue
		}
		if perms, ok := BuiltinPermissions(key); ok {
			set.Add(perms...)
		}
	}
	return set
}
