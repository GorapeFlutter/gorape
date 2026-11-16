# Gorape

Go製のDevice Trust / Hardware Attestationバックエンドです。

GorapeはKeycloakのaccess tokenを検証し、Project/Group権限、Device登録・失効、公開鍵の保有証明、Attestation履歴を管理します。IdP、CA、パスワード管理、秘密鍵保管は行いません。

## Documentation

- [Gorape Guide](https://gorapeflutter.github.io/gorape/)
- [ER diagram](https://gorapeflutter.github.io/gorape/er.html)
- [API endpoint table](https://gorapeflutter.github.io/gorape/endpoints.html)
- [Swagger UI](https://gorapeflutter.github.io/gorape/swagger/)
- [OpenAPI source](docs/openapi/openapi.yaml)

## Releases

`main`へのpushごとにコミット固有のprerelease、`vX.Y.Z`タグでは正式releaseを生成します。

- [GitHub Releases](https://github.com/Gorapeflutter/gorape/releases): OS別CLI archive、Linux向けdeb/rpm、checksum
- [GitHub Container Registry](https://github.com/Gorapeflutter/gorape/pkgs/container/gorape): `main`、`main-<sha>`、SemVerタグのmulti-architecture image

## Components

```text
Client ── Authorization Code + PKCE ── Keycloak (idp.gorapeflutter.site)
   │                                      │
   └──────── Access token ───────────── Gorape (api.gorapeflutter.site / RP ID: gorapeflutter.site)
                                          ├── PostgreSQL
                                          └── Redis
```

- 公式開発・検証用ドメイン: `gorapeflutter.site` (`*.gorapeflutter.site -> 127.0.0.1`)
  - WebAuthn RP ID: `gorapeflutter.site` (独自ドメインへの変更も可能)
  - OIDC Provider (Keycloak): `idp.gorapeflutter.site` (`http://idp.gorapeflutter.site:8080/realms/gorape` / 本番 `https://idp.gorapeflutter.site/realms/gorape`)
  - Gorape API: `api.gorapeflutter.site` (`https://api.gorapeflutter.site:8443` / `http://api.gorapeflutter.site:8000`)
  - ブラウザセレモニー / アプリ設定: `app.gorapeflutter.site` (`https://app.gorapeflutter.site:5174`)
- Keycloak RealmとProjectは1対1
- Principalは検証済み `iss + sub` だけを保持
- Project/Group単位のpermission-based authorization
- Redisによる短期・単回使用Challenge
- Legacy Android Keystore Key Attestation API
- WebAuthn RP用passkey registration/assertion endpoints
- WebAuthn attestation `tpm`, `android-key`, `apple`, `packed`, `fido-u2f`を検証。format allowlistとtrust anchorは必須
- Passkey attestationは既定でdefault-deny（空allowlist、`allow_none: false`）

## Quick start

```bash
make bootstrap
make dev-up
make build
make test
```

The local Keycloak realm and authorization fixture are loaded declaratively:
Keycloak imports `etc/keycloak/gorape-realm.json`, and a fresh PostgreSQL
container runs the schema migrations followed by
`scripts/data/postgres/004-gorape-demo-seed.sql`. The `demo` project, its groups,
role definitions, and permission-pattern test bindings are ready after `make dev-up`;
no `gorape-admin provision apply` step is needed for local development.

APIをホストで起動:

```bash
make dev-api
```

CLIでKeycloakへPKCEログイン:

```bash
.bin/gorape-client -c etc/app.yaml login
```

For non-container or custom deployments, project/Keycloak configuration can
still be managed declaratively through the provisioning manifest:

```bash
.bin/gorape-admin -c etc/admin.yaml provision plan  -f etc/provisioning.example.yaml
.bin/gorape-admin -c etc/admin.yaml provision apply -f etc/provisioning.example.yaml
```

## Documentation development

```bash
# mdBook 0.5.1 is required locally
make docs
make docs-serve
```

生成物は `_site/` に出力され、Git管理しません。GitHub PagesはCIがmdBookとSwagger UIを同一artifactとして生成・配信します。

## License

MIT — [LICENSE](LICENSE)
