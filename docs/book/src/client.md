# Client integration

1. ProjectのKeycloak RealmへAuthorization Code + PKCEでログインします。
2. Access tokenを `Authorization: Bearer ...` でGorapeへ送ります。ID tokenは使用しません。
3. Device登録ではChallengeを取得し、ハードウェア鍵とAttestation evidenceを生成してverify endpointへ送ります。
4. 継続的な鍵保有証明では、base64url decodeしたChallenge bytesを登録鍵で署名します。

Androidの `evidence.certificate_chain` はleaf-firstのPEMまたはbase64 DER配列です。秘密鍵をGorapeへ送信してはいけません。
