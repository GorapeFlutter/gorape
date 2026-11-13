# Authorization matrix

Authorization is permission-based. The built-in roles are presets; projects can
override them and add custom roles mapped to Keycloak realm/client roles or
Keycloak group paths. See [authorization.md](authorization.md) for the full
design.

| Operation | Required permission | viewer | editor | admin |
|---|---|---:|---:|---:|
| Project read | `project:read` | Yes | Yes | Yes |
| Project manage | `project:manage` | No | No | Yes |
| Group read | `group:read` | Yes | Yes | Yes |
| Group create/update/delete | `group:manage` | No | No | Yes |
| Group device bind/unbind | `group:bind` | No | Yes | Yes |
| Device read | `device:read` | Yes | Yes | Yes |
| Device registration | `device:register` | No | Yes | Yes |
| Device proof/verify | `device:verify` | No | Yes | Yes |
| Device revocation | `device:revoke` | No | Yes | Yes |
| Attestation read | `attestation:read` | Yes | Yes | Yes |
| Role read | `role:read` | No | No | Yes |
| Role manage | `role:manage` | No | No | Yes |

Project-scoped bindings apply across the project. Group-scoped bindings apply
only to that group. Keycloak `realm_access.roles`, `resource_access.*.roles`,
and group paths under `/gorape/projects/<slug>/...` are also resolved on each
request, so Keycloak remains the source of truth for role membership.

The database transaction prevents deletion of the last project administrator,
and users cannot modify their own role bindings.
