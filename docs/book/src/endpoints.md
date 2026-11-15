# API endpoints

`/health`はpublicです。通常のproject APIはKeycloak access tokenを必要とし、`/v1/projects`はissuerからprojectを解決します。Platform provisioningはplatform issuerのadmin roleで保護します。Browser passkey handoffの3 endpointだけはBearer tokenを受け取りません。代わりにoptions callから発行された短期・単回使用challenge IDをcapabilityとして検証します。Routeとmiddlewareは[GF-10002](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/router.go#L15)で登録されます。Swagger列は該当operationを直接開きます。

| Method | Endpoint | Purpose | Swagger |
|---|---|---|---|
| GET | `/health` | Liveness ([GF-10002](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/router.go#L15)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/System/health) |
| GET | `/v1/projects` | Token issuerに対応するProject一覧 ([GF-10003](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/share/base.go#L15)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Projects/listProjects) |
| POST | `/v1/passkeys/browser/options` | Capabilityでbrowser ceremony optionsを取得 ([GF-10020](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L184)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Passkeys/getBrowserPasskeyOptions) |
| POST | `/v1/passkeys/browser/registration/verify` | Browser registration responseを検証 ([GF-10021](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L172)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Passkeys/verifyBrowserPasskeyRegistration) |
| POST | `/v1/passkeys/browser/authentication/verify` | Browser assertionを検証 ([GF-10022](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L378)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Passkeys/verifyBrowserPasskeyAuthentication) |
| GET | `/v1/projects/{projectId}` | Project取得 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Projects/getProject) |
| POST | `/v1/platform/provisioning/plan` | Platform admin向けprovisioning plan ([GF-10023](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/provisioning.go#L33)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Provisioning/planProvisioning) |
| POST | `/v1/platform/provisioning/apply` | Platform admin向けprovisioning適用 ([GF-10024](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/provisioning.go#L59)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Provisioning/applyProvisioning) |
| GET | `/v1/projects/{projectId}/permissions` | Effective permission取得 ([GF-10007](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/project.go#L158)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Roles/getPermissions) |
| GET | `/v1/projects/{projectId}/groups` | Group一覧 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Groups/listGroups) |
| POST | `/v1/projects/{projectId}/groups` | Group作成 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Groups/createGroup) |
| GET | `/v1/projects/{projectId}/groups/{groupId}` | Group取得 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Groups/getGroup) |
| PATCH | `/v1/projects/{projectId}/groups/{groupId}` | Group更新 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Groups/updateGroup) |
| DELETE | `/v1/projects/{projectId}/groups/{groupId}` | Group削除 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Groups/deleteGroup) |
| GET | `/v1/projects/{projectId}/devices` | Device一覧 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Devices/listDevices) |
| GET | `/v1/projects/{projectId}/devices/{deviceId}` | Device取得 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Devices/getDevice) |
| DELETE | `/v1/projects/{projectId}/devices/{deviceId}` | Device失効 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Devices/revokeDevice) |
| POST | `/v1/projects/{projectId}/devices/registration/challenge` | 登録Challenge発行 (passkey AMR required, [GF-10008](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/device.go#L125)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Registration/createRegistrationChallenge) |
| POST | `/v1/projects/{projectId}/devices/registration/verify` | Attestation検証と登録 (passkey AMR required, [GF-10008](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/device.go#L125)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Registration/verifyRegistration) |
| POST | `/v1/projects/{projectId}/devices/passkeys/registration/options` | Gorape RP用WebAuthn registration options ([GF-10016](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L91)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Passkeys/createPasskeyRegistrationOptions) |
| POST | `/v1/projects/{projectId}/devices/passkeys/registration/verify` | WebAuthn credential/attestation検証と登録 ([GF-10017](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L151)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Passkeys/verifyPasskeyRegistration) |
| POST | `/v1/projects/{projectId}/devices/{deviceId}/challenge` | 鍵保有証明Challenge発行 (passkey AMR required, [GF-10008](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/device.go#L125)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Proof/createProofChallenge) |
| POST | `/v1/projects/{projectId}/devices/{deviceId}/verify` | 鍵保有証明検証 (passkey AMR required, [GF-10008](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/device.go#L125)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Proof/verifyProof) |
| POST | `/v1/projects/{projectId}/devices/{deviceId}/passkeys/authentication/options` | WebAuthn assertion options ([GF-10018](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L294)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Passkeys/createPasskeyAuthenticationOptions) |
| POST | `/v1/projects/{projectId}/devices/{deviceId}/passkeys/authentication/verify` | WebAuthn assertion検証 ([GF-10019](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L360)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Passkeys/verifyPasskeyAuthentication) |
| POST | `/v1/projects/{projectId}/proof-requests` | 外部サービス向け操作結合WebAuthn Challenge発行 ([GF-10035](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L404)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Passkeys/createProofRequest) |
| POST | `/v1/projects/{projectId}/proof-requests/{proofId}/verify` | 外部サービス向け操作結合WebAuthn Assertion検証 ([GF-10036](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L479)) | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Passkeys/verifyProofRequest) |
| GET | `/v1/projects/{projectId}/groups/{groupId}/devices` | Group Device一覧 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Assignments/listGroupDevices) |
| POST | `/v1/projects/{projectId}/groups/{groupId}/devices` | DeviceをGroupへ割当 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Assignments/bindDevice) |
| DELETE | `/v1/projects/{projectId}/groups/{groupId}/devices/{deviceId}` | Group割当解除 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Assignments/unbindDevice) |
| GET | `/v1/projects/{projectId}/roles` | Project Role binding一覧 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Roles/listProjectRoles) |
| POST | `/v1/projects/{projectId}/roles` | Project Role binding設定 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Roles/putProjectRole) |
| DELETE | `/v1/projects/{projectId}/roles/{bindingId}` | Project Role binding削除 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Roles/deleteRoleBinding) |
| GET | `/v1/projects/{projectId}/groups/{groupId}/roles` | Group Role binding一覧 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Roles/listGroupRoles) |
| POST | `/v1/projects/{projectId}/groups/{groupId}/roles` | Group Role binding設定 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Roles/putGroupRole) |
| GET | `/v1/projects/{projectId}/role-definitions` | Role定義一覧 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Roles/listRoleDefinitions) |
| PUT | `/v1/projects/{projectId}/role-definitions/{key}` | Role定義作成・更新 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Roles/putRoleDefinition) |
| DELETE | `/v1/projects/{projectId}/role-definitions/{key}` | Role定義削除 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Roles/deleteRoleDefinition) |
| GET | `/v1/projects/{projectId}/attestation/capabilities` | Legacy native-key verifier対応状況 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Attestation/getAttestationCapabilities) |
| GET | `/v1/projects/{projectId}/devices/{deviceId}/attestation` | Attestation履歴 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Attestation/listAttestations) |
