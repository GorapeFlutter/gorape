-- Development-only authorization fixture.
--
-- This is mounted by docker/postgres.yaml into the official Postgres image's
-- initialization directory. It is applied to a fresh local database after the
-- schema migrations. There is no admin CLI/API or runtime provisioning script.
-- Keep the user01 and user04 subjects synchronized with their stable IDs in
-- etc/keycloak/gorape-realm.json.

INSERT INTO projects (slug, name, issuer, realm, status)
VALUES (
    'demo',
    'Gorape Demo',
    'http://idp.gorapeflutter.site:8080/realms/gorape',
    'gorape',
    'active'
)
ON CONFLICT (slug) DO NOTHING;

INSERT INTO role_definitions
    (project_id, key, name, permissions, keycloak_role, builtin)
SELECT p.id, fixture.key, fixture.name, fixture.permissions::jsonb,
       fixture.keycloak_role, fixture.builtin
FROM projects AS p
CROSS JOIN (VALUES
    ('admin', 'Administrator', '["*"]', 'gorape-admin', true),
    ('editor', 'Editor', '["project:read","group:read","group:bind","device:read","device:register","device:verify","device:revoke","attestation:read"]', 'gorape-editor', true),
    ('viewer', 'Viewer', '["project:read","group:read","device:read","attestation:read"]', 'gorape-viewer', true),
    ('auditor', 'Auditor', '["project:read","group:read","device:read","attestation:read"]', 'demo-auditor', false)
) AS fixture(key, name, permissions, keycloak_role, builtin)
WHERE p.slug = 'demo'
ON CONFLICT (project_id, key) DO NOTHING;

INSERT INTO groups (project_id, slug, name, status)
SELECT p.id, fixture.slug, fixture.name, 'active'
FROM projects AS p
CROSS JOIN (VALUES
    ('demo-team', 'Demo Team'),
    ('operations', 'Operations')
) AS fixture(slug, name)
WHERE p.slug = 'demo'
ON CONFLICT (project_id, slug) DO NOTHING;

-- user01 is the local app account and starts as project admin. user04 has a
-- viewer realm role and receives editor only for Demo Team through a Gorape DB
-- binding. These examples exercise global versus group-scoped permissions.
INSERT INTO principals (project_id, issuer, subject)
SELECT p.id, p.issuer, fixture.subject
FROM projects AS p
CROSS JOIN (VALUES
    ('49a63887-99b1-41ab-b0d1-5f4ed8254afb'),
    ('3f3e0133-0ee7-5dbf-8843-69abe24747a8')
) AS fixture(subject)
WHERE p.slug = 'demo'
ON CONFLICT (issuer, subject) DO NOTHING;

INSERT INTO role_bindings (project_id, principal_id, scope, group_id, role_key)
SELECT p.id, principal.id, 'project', NULL, 'admin'
FROM projects AS p
JOIN principals AS principal
  ON principal.project_id = p.id
 AND principal.subject = '49a63887-99b1-41ab-b0d1-5f4ed8254afb'
WHERE p.slug = 'demo'
ON CONFLICT DO NOTHING;

INSERT INTO role_bindings (project_id, principal_id, scope, group_id, role_key)
SELECT p.id, principal.id, 'group', g.id, 'editor'
FROM projects AS p
JOIN principals AS principal
  ON principal.project_id = p.id
 AND principal.subject = '3f3e0133-0ee7-5dbf-8843-69abe24747a8'
JOIN groups AS g
  ON g.project_id = p.id
 AND g.slug = 'demo-team'
WHERE p.slug = 'demo'
ON CONFLICT DO NOTHING;
