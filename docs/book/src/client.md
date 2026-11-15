# Client integration

1. ProjectのKeycloak RealmへAuthorization Code + PKCEでログインします。
2. Signed access tokenを`Authorization: Bearer ...`で送信します。ID tokenはAPI認証に使いません。Gorapeはissuer/subjectでPrincipalを解決します（[GF-10003](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/share/base.go#L15), [GF-10005](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/project.go#L42), [GF-10006](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/project.go#L63)）。
3. Device登録とproofには、署名検証済みtokenの`amr`に`passkey`が必要です（[GF-10008](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/device.go#L125)）。パスワードだけのログインではDevice操作を許可しません。
4. Android/iOS/macOS/WebではGorape RPのcreation optionsを取得し、OS/browser credential providerの完全なWebAuthn responseをregistration verify endpointへ送ります（[GF-10016](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L91), [GF-10017](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L151)）。
5. 継続的なproofではDevice IDに紐づいたassertion optionsを取得し、providerにchallengeを署名させます（[GF-10018](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L298), [GF-10019](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L364)）。
6. LinuxはブラウザにOIDC tokenを渡さず、短期・単回使用capabilityによるbrowser handoffを利用します（[GF-10020](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L184), [GF-10021](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L172), [GF-10022](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L382)）。
7. 旧Android Keystore登録APIは互換性用に残っていますが、WebAuthn passkeyと混同しないでください。

WebAuthnのRP IDはKeycloak RP IDと別に構成します。秘密鍵をGorapeへ送信してはいけません。Attestation formatとtrust anchorは [WebAuthn設定](webauthn.md)を参照してください。
