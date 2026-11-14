# Gorape

Go製のDevice Trust / Hardware Attestationバックエンドです。

GorapeはKeycloakのaccess tokenを検証し、Project/Group権限、Device登録・失効、公開鍵の保有証明、Attestation履歴を管理します。IdP、CA、パスワード管理、秘密鍵保管は行いません。

## Documentation

- [Gorape Guide](https://gorapeflutter.github.io/gorape/)
- [ER diagram](https://gorapeflutter.github.io/gorape/er.html)
- [API endpoint table](https://gorapeflutter.github.io/gorape/endpoints.html)
- [Swagger UI](https://gorapeflutter.github.io/gorape/swagger/)
- [OpenAPI source](docs/openapi/openapi.yaml)

## Components

```text
Client ── Authorization Code + PKCE ── Keycloak
   │                                      │
   └──────── Access token ───────────── Gorape
                                          ├── PostgreSQL
                                          └── Redis
```

- Keycloak RealmとProjectは1対1
- Principalは検証済み `iss + sub` だけを保持
- Project/Group単位のpermission-based authorization
- Redisによる短期・単回使用Challenge
- Android Key Attestation対応
- Windows TPM / Apple App Attestはfail closedでunsupported

## Quick start

```bash
make bootstrap
make dev-up
make build
make test
```

APIをホストで起動:

```bash
make dev-api
```

CLIでKeycloakへPKCEログイン:

```bash
.bin/gorape-client -c etc/app.yaml login
```

Project/Keycloak構成はmanifest経由でplan/applyします。

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
