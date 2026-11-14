# Gorape

Gorapeは、Keycloakのaccess tokenで認証し、ハードウェアアテステーションとデバイス管理を提供するGoバックエンドです。

- Keycloak RealmとProjectを1対1で対応
- Project/Group単位の権限管理
- PostgreSQLによるテナント分離
- Redisによる単回使用Challenge
- Android Key Attestation検証
- OpenAPI 3.1 / JSON REST API

[Swagger UI](./swagger/) · [GitHub](https://github.com/Gorapeflutter/gorape)
