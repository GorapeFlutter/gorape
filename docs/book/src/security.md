# Security status

- 未登録IssuerはOIDC Discovery前に拒否
- JWT署名、Issuer、Audience、期限、Not Before、Scope、JWKS rotationを検証
- ChallengeはProject、Subject、用途へ紐付け、Redisで単回消費
- Project境界をAPI、query、複合外部キーで検証
- 未実装Verifierはfail closed

未完了:

- Android証明書のCRL/OCSP検証
- Android application identity policy
- Windows TPM 2.0 / Apple App Attest
- クラスタ共有Rate Limit
