package model

import (
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

func TestPersistedModelsMatchCurrentSchema(t *testing.T) {
	// Keep this list in sync with the ordered SQL migrations.
	tests := []struct {
		name    string
		model   any
		table   string
		columns []string
	}{
		{"project", &Project{}, "projects", []string{"id", "slug", "name", "issuer", "realm", "status", "created_at", "updated_at"}},
		{"group", &Group{}, "groups", []string{"id", "project_id", "slug", "name", "status", "created_at", "updated_at"}},
		{"principal", &Principal{}, "principals", []string{"id", "project_id", "issuer", "subject", "created_at"}},
		{"device", &Device{}, "devices", []string{"id", "project_id", "owner_id", "platform", "display_name", "status", "registered_at", "last_verified_at", "revoked_at", "version"}},
		{"device key", &DeviceKey{}, "device_keys", []string{"id", "project_id", "device_id", "public_key", "key_identifier", "algorithm", "credential_data", "status", "created_at"}},
		{"attestation", &Attestation{}, "attestations", []string{"id", "project_id", "key_id", "aaguid", "assurance_level", "hardware_protected", "backup_eligible", "backup_state", "trust_source", "attestation_certificate", "attestation_type", "security_level", "verification_status", "verifier_version", "verified_at", "last_evaluated_at", "evidence_reference"}},
		{"device event", &DeviceEvent{}, "device_events", []string{"id", "project_id", "device_id", "actor_id", "event_type", "result", "occurred_at"}},
		{"device group binding", &DeviceGroupBinding{}, "device_group_bindings", []string{"id", "project_id", "device_id", "group_id", "status", "created_at"}},
		{"role definition", &RoleDefinition{}, "role_definitions", []string{"id", "project_id", "key", "name", "permissions", "keycloak_role", "builtin", "created_at", "updated_at"}},
		{"role binding", &RoleBinding{}, "role_bindings", []string{"id", "project_id", "principal_id", "scope", "group_id", "role_key", "created_at"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := schema.Parse(test.model, &sync.Map{}, schema.NamingStrategy{})
			if err != nil {
				t.Fatalf("parse model schema: %v", err)
			}
			if parsed.Table != test.table {
				t.Errorf("table = %q, want %q", parsed.Table, test.table)
			}

			want := make(map[string]bool, len(test.columns))
			for _, column := range test.columns {
				want[column] = false
			}
			for _, field := range parsed.Fields {
				if field.DBName == "" {
					continue
				}
				if _, ok := want[field.DBName]; !ok {
					t.Errorf("unexpected database column %q", field.DBName)
					continue
				}
				want[field.DBName] = true
			}
			for column, found := range want {
				if !found {
					t.Errorf("model does not map database column %q", column)
				}
			}
		})
	}
}
