# Architecture

```text
Native client / gorape-client
          │ Authorization Code + PKCE
          ▼
       Keycloak
          │ Access token
          ▼
        Gorape ───── PostgreSQL
          │
          └──────── Redis
```

GorapeはIdPではありません。ユーザー、パスワード、ログインセッションはKeycloakが管理します。Gorapeは検証済みtokenの `iss + sub` をPrincipalとして参照し、Project、Group、Role、Device、公開鍵、Attestation、監査イベントだけを保存します。

すべてのProject配下テーブルとrepository queryは `project_id` で分離されます。Root Domainはクラスタ境界であり、DBやREST APIでは管理しません。
