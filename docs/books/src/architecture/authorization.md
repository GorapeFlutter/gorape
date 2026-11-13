# Authorization and provisioning design

## 1. Scope

Keycloak 26.8.x remains the identity provider: OIDC login, passkeys/MFA, DPoP,
and token issuance. Gorape remains the device-trust backend: attestation,
device registration, key possession, device lifecycle, and API access control.

Gorape therefore does **not** try to reproduce Keycloak groups or roles. It
consumes Keycloak role and group claims dynamically and combines them with
Gorape-owned role bindings.

```text
Keycloak                         Gorape
--------                         ------
who the user is                  what the device is
realm/client roles               fine-grained permissions
group membership                 project/group role bindings
token issuance                   device lifecycle + access decisions
```

## 2. Permission model

Authorization is based on fine-grained permissions instead of the old fixed
`admin`/`editor`/`viewer` ranks.

| Permission | Meaning |
|---|---|
| `project:read` | Read project metadata and effective permissions |
| `project:manage` | Manage project-wide configuration |
| `group:read` | Read groups and group membership |
| `group:bind` | Bind or unbind devices to groups |
| `group:manage` | Create/update/delete groups |
| `device:read` | Read devices |
| `device:register` | Register a new device |
| `device:verify` | Prove possession or verify a device key |
| `device:revoke` | Revoke a device |
| `attestation:read` | Read attestation evidence |
| `role:read` | Read role definitions and bindings |
| `role:manage` | Create/delete role definitions and bindings |
| `provision:manage` | Reserved for platform administration |

Wildcards are evaluated by Gorape:

- `*` grants every permission.
- `device:*` grants every `device:` permission.

Built-in defaults are provided so existing deployments keep working:

| Role key | Default permissions | Default Keycloak role |
|---|---|---|
| `viewer` | `project:read`, `group:read`, `device:read`, `attestation:read` | `gorape-viewer` |
| `editor` | viewer + `group:bind`, `device:register`, `device:verify`, `device:revoke` | `gorape-editor` |
| `admin` | `*` | `gorape-admin` |

Projects may override these definitions and add custom roles. A custom role can
map to any Keycloak realm role, client role, or group path.

## 3. Role definitions and bindings

Two tables replace `project_role_bindings` and `group_role_bindings`:

- `role_definitions(project_id, key, name, permissions JSONB, keycloak_role, builtin)`
- `role_bindings(project_id, principal_id, scope, group_id, role_key)`

`scope` is `project` or `group`. A project-scoped binding applies everywhere in
the project. A group-scoped binding applies only while evaluating that group.
The unique indexes allow at most one project binding and one binding per group
for each principal.

The last project administrator cannot be removed or demoted. This is enforced
transactionally in the repository, independent of the caller.

## 4. Effective permission resolution

For each request, Gorape computes the effective permission set from all of:

1. **Gorape project bindings** for the authenticated principal.
2. **Gorape group bindings** when the request targets a group.
3. **Keycloak realm roles** (`realm_access.roles`).
4. **Keycloak client roles** (`resource_access.*.roles`), across all clients.
5. **Keycloak group paths** (`groups` claim).

Role and group claims are mapped at request time, so changing a Keycloak role or
group membership changes Gorape authorization without redeploying Gorape or
editing Gorape's database.

### Keycloak group path convention

```text
/gorape/projects/<projectSlug>/roles/<roleKey>
/gorape/projects/<projectSlug>/groups/<groupSlug>/roles/<roleKey>
```

The first form grants a project-wide role. The second grants a role only for a
specific Gorape group. Paths for other projects are ignored.

### Role mapping

A role definition has an optional `keycloak_role`. When empty, the convention is
`gorape-<key>`. A token role matches when it equals `keycloak_role` exactly.

### Evaluation

```text
bindings + realm/resource roles + group paths
                    |
                    v
      role definitions (permissions JSONB)
                    |
                    v
          union of permission strings
                    |
                    v
          wildcard-aware check
```

The same evaluator backs every controller check, so `GET
/v1/projects/{id}/permissions` explains why an action is allowed or denied.

## 5. API surface

New or changed endpoints:

```text
GET    /v1/projects/{projectId}/permissions
GET    /v1/projects/{projectId}/roles
POST   /v1/projects/{projectId}/roles
DELETE /v1/projects/{projectId}/roles/{bindingId}
GET    /v1/projects/{projectId}/role-definitions
PUT    /v1/projects/{projectId}/role-definitions/{key}
DELETE /v1/projects/{projectId}/role-definitions/{key}
GET    /v1/projects/{projectId}/groups/{groupId}/roles
POST   /v1/projects/{projectId}/groups/{groupId}/roles

POST   /v1/platform/provisioning/plan
POST   /v1/platform/provisioning/apply
```

All project routes require a Keycloak access token for the configured audience.
Platform routes require a token from `platform.issuer` carrying one of
`platform.admin_roles`. Platform authorization is intentionally independent of
an existing Gorape project, so the first project can be bootstrapped through the
server.

## 6. Declarative provisioning

A single manifest can describe Keycloak and Gorape changes:

```yaml
apiVersion: gorape/v1
kind: Provisioning
keycloak:
  realm: gorape
  roles: [...]
  groups: [...]
  clients: [...]
  authorization: {...}
gorape:
  project: {...}
  roles: [...]
  groups: [...]
  bindings: [...]
```

The CLI only calls the Gorape server:

```bash
gorape-admin provision plan  -f etc/provisioning.example.yaml
gorape-admin provision apply -f etc/provisioning.example.yaml
```

The server applies the manifest in this order:

1. **Keycloak** through the Admin REST API (realm, roles, groups, clients,
   protocol mappers, Authorization Services scopes/resources/policies/
   permissions).
2. **Gorape** in one PostgreSQL transaction (project, role definitions, groups,
   role bindings).

If the Keycloak step fails, Gorape is not changed. Gorape-only manifests are
allowed; Keycloak-only manifests are allowed when `keycloak.base_url` is
configured.

The provisioner authenticates to Keycloak with either a confidential client
(client credentials) or a development username/password (`admin-cli`). In
production, use a dedicated client whose service account has only the required
`realm-management` roles.

## 7. Configuration

```yaml
Application:
  Server:
    platform:
      issuer: https://keycloak.example.com/realms/gorape
      provider_url: ""
      admin_roles: [gorape-platform-admin]
    keycloak:
      base_url: https://keycloak.example.com
      auth_realm: master
      admin_realm: gorape
      client_id: gorape-provisioner
      client_secret: ${KEYCLOAK_PROVISIONER_SECRET}
```

`provider_url` is optional and is only needed when the server reaches Keycloak
through an internal hostname while tokens carry the public issuer.

## 8. Migration and compatibility

`migrations/000002_dynamic_authorization.up.sql`:

- creates `role_definitions` and `role_bindings`,
- seeds the built-in definitions for every existing project,
- copies existing project/group bindings,
- drops the legacy role tables and enum.

The old role-oriented `RequireProjectRole` helper is retained only for coarse
checks and tests. New controllers authorize with permissions.

## 9. Security notes

- Device owners always retain read and proof-of-possession access to their own
  device. Revocation still requires `device:revoke`.
- Users cannot change their own role bindings.
- Only a project-level `role:manage` holder can grant an admin-equivalent role.
- The last project administrator cannot be removed.
- Keycloak Admin credentials must never be exposed to the CLI.
- Changes to Keycloak roles/groups take effect on the next token refresh or new
  token. Already-issued JWTs keep the claims they were issued with.
