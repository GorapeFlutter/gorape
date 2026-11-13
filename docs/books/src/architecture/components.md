# Components

The Gorape ecosystem consists of the following components:

## 1. Gorape Server (`cmd/server`)
- Exposes REST API endpoints powered by the Gin web framework.
- Enforces OIDC token validation, project multi-tenancy, and RBAC rules.
- Manages single-use challenge creation and verification via Redis.
- Performs cryptographic attestation verification (e.g. Android Key Attestation certificate chains).

## 2. PostgreSQL Database
- **`project_domains`**: Maps to Keycloak realms. Contains project metadata, realm slug, and OIDC issuer.
- **`group_domains`**: Sub-organizational boundaries within a project.
- **`identity_principals`**: Normalized mappings of Keycloak `(oidc_issuer, oidc_subject)`.
- **`project_role_bindings` & `group_role_bindings`**: Associates principals with `admin`, `editor`, or `viewer` roles.
- **`devices`**: Registered client devices with platform type, status (`active`, `revoked`), and display names.
- **`device_keys`**: Hardware public keys and algorithms bound to devices.
- **`attestation_records`**: Detailed records of hardware verification results (TEE/StrongBox level, verifier version).
- **`device_events`**: Immutable audit logs capturing registrations, revocations, and proof verification events.

## 3. Redis Cache
- Manages cryptographically random 256-bit challenges with strict Time-To-Live (TTL, default: 5 minutes).
- Guarantees single-use execution through atomic Lua script operations (`GET` + `DEL`).

## 4. Administrative CLI (`cmd/client/admin`)
- Operations tool for bootstrapping new projects (`bootstrap-project`).
- Manages initial Project Admin assignment directly against PostgreSQL before API access is enabled.

## 5. Client CLI (`cmd/client/app`)
- Reference client demonstrating Authorization Code + PKCE login with Keycloak.
- Interacts with Gorape project, group, and device endpoints.
