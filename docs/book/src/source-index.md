# Backend source index

Backend documentation uses `GF-1xxxx` IDs to link a described behavior to its
Go implementation or schema migration. The IDs are stable references, not
runtime protocol values.

| ID | Responsibility |
|---|---|
| [GF-10001](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/base.go#L13) | Start HTTP and optional HTTPS listeners |
| [GF-10002](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/router.go#L15) | Configure middleware and register API routes |
| [GF-10003](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/share/base.go#L15) | Authenticate project/issuer bearer tokens |
| [GF-10004](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/share/base.go#L42) | Authenticate platform-administrator tokens |
| [GF-10005](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/project.go#L42) | Validate project tokens and resolve principals |
| [GF-10006](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/project.go#L63) | Resolve a project from the token issuer |
| [GF-10007](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/project.go#L158) | Resolve effective project/group permissions |
| [GF-10008](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/device.go#L146) | Require passkey AMR for device operations |
| [GF-10009](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/challenge.go#L75) | Atomically consume a one-time challenge |
| [GF-10010](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/webauthn.go#L99) | Construct the configured WebAuthn RP and trust policy |
| [GF-10011](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/webauthn.go#L816) | Validate RP ID and exact origin allowlist |
| [GF-10012](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/webauthn.go#L311) | Create WebAuthn registration options |
| [GF-10013](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/webauthn.go#L350) | Verify registration response and attestation |
| [GF-10014](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/webauthn.go#L475) | Create WebAuthn assertion options |
| [GF-10015](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/webauthn.go#L489) | Verify a WebAuthn assertion |
| [GF-10016](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L92) | Authorize and issue device registration options |
| [GF-10017](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L152) | Consume registration challenge and persist credential |
| [GF-10018](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L313) | Authorize and issue device proof options |
| [GF-10019](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L379) | Verify device possession and update credential state |
| [GF-10020](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L185) | Read browser options through a short-lived capability |
| [GF-10021](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L173) | Verify browser-mediated registration |
| [GF-10022](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L397) | Verify browser-mediated assertion |
| [GF-10023](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/provisioning.go#L33) | Produce a platform-admin provisioning plan |
| [GF-10024](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/provisioning.go#L59) | Apply a platform-admin provisioning manifest |
| [GF-10025](https://github.com/Gorapeflutter/gorape/blob/main/pkg/entity/model/permission.go#L167) | Expand role keys into effective permissions |
| [GF-10026](https://github.com/Gorapeflutter/gorape/blob/main/migrations/000003_webauthn.up.sql#L1) | Add WebAuthn credential state in the SQL migration |
| [GF-10027](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/mds.go#L68) | Load and verify a signed FIDO MDS BLOB |
| [GF-10028](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/mds.go#L131) | Look up AAGUID metadata after validating freshness |
| [GF-10029](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/mds.go#L168) | Refresh FIDO MDS BLOB at nextUpdate and reject stale data |
| [GF-10030](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/mds.go#L224) | Verify FIDO MDS BLOB signature, legal header, and status |
| [GF-10031](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/attestation.go#L48) | Validate Android attestation package/signing digest policy |
| [GF-10032](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/revocation.go#L92) | Configure bounded CRL/OCSP revocation checker and cache |
| [GF-10033](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/revocation.go#L166) | Fail closed on revoked or uncheckable certificate status |
| [GF-10034](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/assurance.go#L29) | Enforce optional passkey AMR, ACR, and auth_time freshness |
| [GF-10035](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L423) | Issue an operation-bound WebAuthn proof request for external services |
| [GF-10036](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L497) | Atomically consume and verify an external service proof request |
| [GF-10037](https://github.com/Gorapeflutter/gorape/blob/main/pkg/config/base.go#L194) | Normalize server listener, TLS, OIDC, attestation, and WebAuthn configuration |
| [GF-10038](https://github.com/Gorapeflutter/gorape/blob/main/pkg/entity/model/attestation_record.go#L69) | Resolve assurance from verified credential evidence |
| [GF-10039](https://github.com/Gorapeflutter/gorape/blob/main/migrations/000004_assurance.up.sql#L1) | Persist verified attestation assurance evidence |
| [GF-10040](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/webauthn.go#L397) | Enforce per-assurance registration policy |
| [GF-10041](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/webauthn.go#L435) | Re-evaluate assurance from MDS status and revocation |
| [GF-10042](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L696) | Preserve authenticator transports for cross-device hints |
| [GF-10043](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L738) | Enforce assurance consistently on assertions |
| [GF-10044](https://github.com/Gorapeflutter/gorape/blob/main/pkg/config/base.go#L277) | Normalize the explicit WebAuthn assurance policy |

Run `python3 scripts/docs/link_gf_ids.py` to refresh links after moving source
code. `scripts/check-docs.sh` verifies that every documented ID has a source
comment and a current GitHub link.
