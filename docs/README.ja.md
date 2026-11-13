# Gorape 日本語概要

Gorapeは、Keycloakで認証された主体に対してハードウェアアテステーション検証とデバイス管理APIを提供する独立したGoバックエンドです。認証、ユーザー管理、パスキー、MFAはKeycloakに委譲し、Gorapeはパスワードやハードウェア秘密鍵を保持しません。

ProjectはKeycloak Realmと1対1で対応し、GroupはProject配下の管理領域です。権限はadmin/editor/viewerで、Project権限をGroupで暗黙に降格しません。Root Domainはインフラ境界でありDBやREST APIには存在しません。

現時点ではAndroid Key Attestationを優先実装しています。Windows TPM、iOS、macOSは明示的にunsupportedを返します。

## アーキテクチャと実装規約

- **概念データごとのファイル分割**: 全ての層（`entity/model`, `entity/request`, `entity/response`, `repository`, `usecase`, `controller`）は、概念（Project, Group, Device, Role 等）ごとにファイルを分割しています。
- **インターフェースと同居**: 各概念ファイルには、`type <Concept> interface`、実装構造体（`type <concept>Usecase/Repository/Controller struct`）、およびコンストラクタ（`func New<Concept>(...) <Concept>`）が同一ファイルに実装されています。
- **共通・集約は `common.go`**: 複数概念の集約構造体（`Store`, `Service`, `API`）や共通ヘルパーは各パッケージの `common.go` に配置します。
- **レシーバ名の統一**: 全てのメソッドレシーバ名は `rcvr` で統一しています。
- **クリーンなEntity層**: 実際に永続化やロジックで使用されるドメインモデルのみを保持し、未使用のエンティティ定義は排除されています。
