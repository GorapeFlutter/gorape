# Security status

- 未登録IssuerはOIDC Discovery前に拒否
- JWT署名、Issuer、Audience、期限、Not Before、Scope、JWKS rotationを検証
- ChallengeはProject、Subject、用途へ紐付け、Redisで単回消費
- Project境界をAPI、query、複合外部キーで検証
- 未実装Verifierはfail closed
- Gorape RPのWebAuthn registrationでRP ID、origin、challenge、credential ID/public keyを検証
- Legacy device registration、proof、passkey registration/assertionは`amr: ["passkey"]`を要求 ([GF-10008](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/device.go#L125))
- Redis challengeはpurpose、project、subject、deviceへ結び付け、atomicに一度だけ消費 ([GF-10009](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/challenge.go#L75))
- WebAuthn attestationは許可formatとformat別trust anchorを要求し、既定はnoneを拒否
- proofは単回challengeに対するWebAuthn assertionを検証し、raw attestation evidenceは保存credentialから除去

未完了:

- Android/WebAuthn attestation証明書のCRL/OCSP検証
- Android application identity policy
- FIDO Metadata ServiceによるAAGUID status/revocation policy
- WebAuthn Windows TPM / Apple anonymous attestationの実機検証・運用trust bundle
- Windows/Linux/Web browser redirect, CORS, and RP-domain association needs per-deployment validation
- クラスタ共有Rate Limit
