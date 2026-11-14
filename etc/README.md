# Configuration Files Guide

## File Structure

| File | Purpose |
|------|---------|
| `server.yaml.example` | Server configuration template (local development) |
| `server.yaml` | Local server configuration (not tracked by Git) |
| `server.yaml.docker` | Server configuration used by the `server` container |
| `admin.yaml.example` / `app.yaml.example` | CLI client configuration templates |
| `keycloak/gorape-realm.json` | Keycloak realm import (realm, client, users, groups) |
| `README.md` | This guide |

## Setup

```bash
cp etc/server.yaml.example etc/server.yaml
cp etc/admin.yaml.example  etc/admin.yaml
cp etc/app.yaml.example    etc/app.yaml
make dev-up
make build
```

`make bootstrap` performs the copies above and leaves existing files untouched.

## Keycloak

`etc/keycloak/gorape-realm.json` is imported automatically by the Keycloak container
(`start-dev --import-realm`).

- Realm: `gorape` (`http://localhost:8080/realms/gorape`)
- Public client: `gorape-client` (Authorization Code + PKCE, `S256`)
- API audience: `gorape-api`
- Redirect URI: `http://127.0.0.1:8400/callback`
- Development users:
  - `gorape-admin` / `ChangeMe123!` (temporary; change on first login)
  - `user01` ... `user50` / `Password123!`
- Development groups: `group001` ... `group100`
- Dynamic authorization groups: `/gorape/projects/demo/roles/admin` and
  `/gorape/projects/demo/groups/demo-team/roles/editor`
- Realm roles: `admin`, `editor`, `viewer`, `gorape-platform-admin`,
  `gorape-admin`, `gorape-editor`, `gorape-viewer`
- User emails use the `@gf.local` domain

Keycloak realm/client roles and group paths under `/gorape/projects/<slug>/...`
are resolved during every Gorape authorization decision. Gorape role bindings in
PostgreSQL still grant roles directly, and the two sources are combined. Built-in
role definitions map to `gorape-admin`, `gorape-editor`, and `gorape-viewer` by
convention.

To rebuild the realm after editing the JSON, recreate the containers and their volumes:

```bash
make dev-down
make dev-up
```

## Declarative provisioning

`provisioning.example.yaml` declares Keycloak roles/groups/clients/authorization
resources and Gorape projects/roles/groups/bindings in one document:

```bash
.bin/gorape-admin -c etc/admin.yaml provision plan  -f etc/provisioning.example.yaml
.bin/gorape-admin -c etc/admin.yaml provision apply -f etc/provisioning.example.yaml
```

The CLI calls the Gorape server. The server applies Keycloak via the Admin REST
API and Gorape in one PostgreSQL transaction. See
[authorization documentation](https://gorapeflutter.github.io/gorape/architecture.html).

## Server Configuration

`etc/server.yaml` (local) and `etc/server.yaml.docker` (container) use these sections:

```yaml
Application:
  Server:
    port: 8000
    oidc:
      audience: gorape-api
      required_scopes: [openid]
      provider_urls: {}
    attestation:
      android_trust_anchors: []
    platform:
      issuer: http://localhost:8080/realms/gorape
      provider_url: ""
      admin_roles: [gorape-platform-admin, admin]
    keycloak:
      base_url: http://localhost:8080
      auth_realm: master
      admin_realm: gorape
      client_id: admin-cli
      username: admin
      password: admin
PostgreSQL:
  host: localhost
  db: gorape
Redis:
  host: localhost
  db: 0
```

`provider_urls` maps a token issuer to the discovery URL used inside the container.
The Docker configuration maps:

```yaml
http://localhost:8080/realms/gorape: http://keycloak:8080/realms/gorape
```

## CLI Client Configuration

`admin.yaml` and `app.yaml` point at the same realm and public client:

```yaml
Application:
  Client:
    ServerEndpoint: http://localhost:8000
    oidc:
      issuer_url: http://localhost:8080/realms/gorape
      client_id: gorape-client
      redirect_url: http://127.0.0.1:8400/callback
      scopes: [openid, profile]
```

Authenticate once per profile:

```bash
.bin/gorape-admin -c etc/admin.yaml login
.bin/gorape-client -c etc/app.yaml login
```

Access tokens are stored under `etc/.gorape/client/<profile>/access_token` with mode `0600`.
Alternatively, set `GORAPE_ACCESS_TOKEN` for non-interactive use.
Gorape does not support email/password or client-secret login for CLI clients.

## Security Notes

- `etc/*.yaml` is ignored by Git; never commit real secrets or tokens.
- The bundled passwords and `sslRequired: none` are for local development only.
- Production issuers must use HTTPS; plain HTTP is accepted only for localhost.
- Change `gorape-admin`'s temporary password on first login.
