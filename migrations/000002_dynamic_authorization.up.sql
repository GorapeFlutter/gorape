-- Dynamic, permission-based authorization.
--
-- Role definitions map stable role keys to fine-grained permissions. Role
-- bindings reference a role key at project or group scope. Existing rows from
-- project_role_bindings and group_role_bindings are preserved, and the built-in
-- admin/editor/viewer definitions are seeded for every project.
CREATE TABLE role_definitions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  name TEXT NOT NULL,
  permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
  keycloak_role TEXT,
  builtin BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(project_id, key),
  UNIQUE(project_id, id)
);

INSERT INTO role_definitions (project_id, key, name, permissions, keycloak_role, builtin)
SELECT p.id, r.key, r.name, r.permissions::jsonb, r.keycloak_role, true
FROM projects p
CROSS JOIN (VALUES
  ('viewer', 'viewer', '["project:read","group:read","device:read","attestation:read"]', 'gorape-viewer'),
  ('editor', 'editor', '["project:read","group:read","group:bind","device:read","device:register","device:verify","device:revoke","attestation:read"]', 'gorape-editor'),
  ('admin', 'admin', '["*"]', 'gorape-admin')
) AS r(key, name, permissions, keycloak_role)
ON CONFLICT (project_id, key) DO NOTHING;

CREATE TABLE role_bindings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL,
  principal_id UUID NOT NULL,
  scope TEXT NOT NULL CHECK (scope IN ('project', 'group')),
  group_id UUID,
  role_key TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  FOREIGN KEY (project_id, principal_id) REFERENCES principals(project_id, id) ON DELETE CASCADE,
  FOREIGN KEY (project_id, group_id) REFERENCES groups(project_id, id) ON DELETE CASCADE,
  FOREIGN KEY (project_id, role_key) REFERENCES role_definitions(project_id, key) ON DELETE RESTRICT,
  CHECK ((scope = 'project' AND group_id IS NULL) OR (scope = 'group' AND group_id IS NOT NULL))
);

CREATE UNIQUE INDEX idx_role_bindings_project_principal
  ON role_bindings(project_id, principal_id) WHERE scope = 'project';
CREATE UNIQUE INDEX idx_role_bindings_group_principal
  ON role_bindings(project_id, group_id, principal_id) WHERE scope = 'group';
CREATE INDEX idx_role_bindings_principal ON role_bindings(principal_id);
CREATE INDEX idx_role_bindings_group ON role_bindings(project_id, group_id);

INSERT INTO role_bindings (project_id, principal_id, scope, group_id, role_key)
SELECT project_id, principal_id, 'project', NULL, role::text
FROM project_role_bindings
ON CONFLICT DO NOTHING;

INSERT INTO role_bindings (project_id, principal_id, scope, group_id, role_key)
SELECT project_id, principal_id, 'group', group_id, role::text
FROM group_role_bindings
ON CONFLICT DO NOTHING;

DROP TABLE group_role_bindings;
DROP TABLE project_role_bindings;
DROP TYPE IF EXISTS gorape_role;
