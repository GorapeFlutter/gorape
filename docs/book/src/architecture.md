# Architecture

```text
Native / browser client ── Authorization Code + PKCE ── Keycloak
          │                                               │
          │ access token                                  │ iss + sub / AMR
          └───────────────────────────► Gorape API ◄──────┘
                                         │     │
                                     PostgreSQL Redis
```

The server starts the HTTP listener and an optional TLS listener from its
configuration ([GF-10001](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/base.go#L13)); the router composes auth, rate-limit, CORS, and
request-ID middleware with the REST controllers ([GF-10002](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/router.go#L15)).

Gorape is not an identity provider. Keycloak owns users, passwords, and login
sessions. Gorape validates access tokens and resolves principals by `iss + sub`
([GF-10003](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/share/base.go#L15), [GF-10005](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/project.go#L42), [GF-10006](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/project.go#L63)). The platform-provisioning API uses a
separate configured issuer and role gate ([GF-10004](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/share/base.go#L42), [GF-10023](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/provisioning.go#L33), [GF-10024](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/provisioning.go#L59)).
Gorape stores only project-scoped principals, groups, roles, devices, public
keys/WebAuthn credential state, verified attestation summaries, and audit
events. Gorape passkeys are a separate RP credential from Keycloak passkeys.

Project-scoped tables and repository queries are isolated by `project_id`.
Effective permissions combine Gorape role bindings and dynamic Keycloak claims
([GF-10007](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/project.go#L158), [GF-10025](https://github.com/Gorapeflutter/gorape/blob/main/pkg/entity/model/permission.go#L167)). Device registration and possession operations also
require a validated `amr: ["passkey"]` claim ([GF-10008](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/device.go#L125)); challenges are
short-lived, project/subject/purpose-bound, and consumed once ([GF-10009](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/challenge.go#L75)). Root
Domain is a cluster boundary and is not managed by the database or REST API.
