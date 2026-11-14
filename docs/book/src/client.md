# Client integration

1. ProjectのKeycloak RealmへAuthorization Code + PKCEでログインします。
2. Access tokenを `Authorization: Bearer ...` でGorapeへ送ります。ID tokenは使用しません。
3. Passkey device登録ではGorape RPのcreation optionsを取得し、OS/browser credential providerの完全なWebAuthn responseをverify endpointへ送ります。
4. 継続的なpasskey proofでは新しいassertion optionsを取得し、OS/browser providerにchallengeを署名させます。
5. 旧Android Keystore登録APIは互換性用に残っていますが、passkeyと混同しないでください。

WebAuthnのRP IDはKeycloak RP IDと別に構成します。秘密鍵をGorapeへ送信してはいけません。Attestation formatとtrust anchorは [WebAuthn設定](webauthn.md)を参照してください。
