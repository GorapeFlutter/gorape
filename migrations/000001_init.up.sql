CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TYPE gorape_role AS ENUM ('admin','editor','viewer');

CREATE TABLE projects (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
 issuer TEXT NOT NULL UNIQUE, realm TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 CHECK (issuer ~ '^https://' OR issuer ~ '^http://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?/'), UNIQUE(id,issuer)
);
CREATE TABLE groups (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 slug TEXT NOT NULL, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(project_id,slug), UNIQUE(project_id,id)
);
CREATE TABLE principals (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 issuer TEXT NOT NULL, subject TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(issuer,subject), UNIQUE(project_id,id),
 FOREIGN KEY(project_id,issuer) REFERENCES projects(id,issuer)
);
CREATE TABLE project_role_bindings (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID NOT NULL, principal_id UUID NOT NULL, role gorape_role NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(project_id,principal_id),
 FOREIGN KEY(project_id,principal_id) REFERENCES principals(project_id,id) ON DELETE CASCADE
);
CREATE TABLE group_role_bindings (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID NOT NULL, group_id UUID NOT NULL, principal_id UUID NOT NULL,
 role gorape_role NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(project_id,group_id,principal_id),
 FOREIGN KEY(project_id,group_id) REFERENCES groups(project_id,id) ON DELETE CASCADE,
 FOREIGN KEY(project_id,principal_id) REFERENCES principals(project_id,id) ON DELETE CASCADE
);
CREATE TABLE devices (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID NOT NULL, owner_id UUID NOT NULL,
 platform TEXT NOT NULL CHECK(platform IN ('android','windows','ios','macos')), display_name TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')), registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 last_verified_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ, version BIGINT NOT NULL DEFAULT 1,
 UNIQUE(project_id,id), FOREIGN KEY(project_id,owner_id) REFERENCES principals(project_id,id)
);
CREATE TABLE device_group_bindings (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID NOT NULL, device_id UUID NOT NULL, group_id UUID NOT NULL,
 status TEXT NOT NULL DEFAULT 'active', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(project_id,device_id,group_id),
 FOREIGN KEY(project_id,device_id) REFERENCES devices(project_id,id) ON DELETE CASCADE,
 FOREIGN KEY(project_id,group_id) REFERENCES groups(project_id,id) ON DELETE CASCADE
);
CREATE TABLE device_keys (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID NOT NULL, device_id UUID NOT NULL, public_key BYTEA NOT NULL,
 key_identifier TEXT NOT NULL, algorithm TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(project_id,id), UNIQUE(project_id,key_identifier),
 FOREIGN KEY(project_id,device_id) REFERENCES devices(project_id,id) ON DELETE CASCADE
);
CREATE TABLE attestations (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID NOT NULL, key_id UUID NOT NULL,
 attestation_type TEXT NOT NULL, security_level TEXT NOT NULL, verification_status TEXT NOT NULL,
 verifier_version TEXT NOT NULL, verified_at TIMESTAMPTZ NOT NULL DEFAULT now(), evidence_reference TEXT,
 FOREIGN KEY(project_id,key_id) REFERENCES device_keys(project_id,id) ON DELETE CASCADE
);
CREATE TABLE device_events (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID NOT NULL, device_id UUID NOT NULL, actor_id UUID NOT NULL,
 event_type TEXT NOT NULL, result TEXT NOT NULL, occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 FOREIGN KEY(project_id,device_id) REFERENCES devices(project_id,id) ON DELETE CASCADE,
 FOREIGN KEY(project_id,actor_id) REFERENCES principals(project_id,id)
);
CREATE INDEX idx_project_roles_principal ON project_role_bindings(principal_id);
CREATE INDEX idx_group_roles_principal ON group_role_bindings(principal_id);
CREATE INDEX idx_devices_project_status ON devices(project_id,status);
CREATE INDEX idx_attestations_project_key ON attestations(project_id,key_id,verified_at DESC);
CREATE INDEX idx_device_events_project_device ON device_events(project_id,device_id,occurred_at DESC);
