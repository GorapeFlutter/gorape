# API endpoints

すべての `/v1` endpointは、特記がない限りKeycloak access tokenを必要とします。Swagger列は該当operationを直接開きます。

| Method | Endpoint | Purpose | Swagger |
|---|---|---|---|
| GET | `/health` | Liveness | [Open](https://gorapeflutter.github.io/gorape/swagger/#/System/health) |
| GET | `/v1/projects` | Token issuerに対応するProject一覧 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Projects/listProjects) |
| GET | `/v1/projects/{projectId}` | Project取得 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Projects/getProject) |
| POST | `/v1/platform/provisioning/plan` | Provisioning plan作成 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Provisioning/planProvisioning) |
| POST | `/v1/platform/provisioning/apply` | Provisioning適用 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Provisioning/applyProvisioning) |
| GET | `/v1/projects/{projectId}/permissions` | Effective permission取得 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Roles/getPermissions) |
| GET | `/v1/projects/{projectId}/groups` | Group一覧 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Groups/listGroups) |
| POST | `/v1/projects/{projectId}/groups` | Group作成 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Groups/createGroup) |
| GET | `/v1/projects/{projectId}/groups/{groupId}` | Group取得 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Groups/getGroup) |
| PATCH | `/v1/projects/{projectId}/groups/{groupId}` | Group更新 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Groups/updateGroup) |
| DELETE | `/v1/projects/{projectId}/groups/{groupId}` | Group削除 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Groups/deleteGroup) |
| GET | `/v1/projects/{projectId}/devices` | Device一覧 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Devices/listDevices) |
| GET | `/v1/projects/{projectId}/devices/{deviceId}` | Device取得 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Devices/getDevice) |
| DELETE | `/v1/projects/{projectId}/devices/{deviceId}` | Device失効 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Devices/revokeDevice) |
| POST | `/v1/projects/{projectId}/devices/registration/challenge` | 登録Challenge発行 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Registration/createRegistrationChallenge) |
| POST | `/v1/projects/{projectId}/devices/registration/verify` | Attestation検証と登録 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Registration/verifyRegistration) |
| POST | `/v1/projects/{projectId}/devices/{deviceId}/challenge` | 鍵保有証明Challenge発行 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Proof/createProofChallenge) |
| POST | `/v1/projects/{projectId}/devices/{deviceId}/verify` | 鍵保有証明検証 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Proof/verifyProof) |
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
| GET | `/v1/projects/{projectId}/attestation/capabilities` | Verifier対応状況 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Attestation/getAttestationCapabilities) |
| GET | `/v1/projects/{projectId}/devices/{deviceId}/attestation` | Attestation履歴 | [Open](https://gorapeflutter.github.io/gorape/swagger/#/Attestation/listAttestations) |
