# High-Level Architecture

Gorape operates as an intermediate security trust authority between client devices and protected services.

```text
+-----------------------+
| Native App / CLI      |
+-----------------------+
    |           ^
    | (1) PKCE  | (2) Access Token
    v           |
+-----------------------+
| Keycloak (Realm)      |
+-----------------------+
    |
    | (3) Bearer Access Token
    v
+--------------------------------------------------------------+
| Gorape API Server                                            |
|                                                              |
|  [Controller Layer]  --> HTTP Handlers (Gin)                 |
|  [Usecase Layer]     --> RBAC, Challenge, Proof Verification |
|  [Repository Layer]  --> GORM, Redis, Verifiers, OIDC        |
+--------------------------------------------------------------+
    |                           |
    | (4) SQL                   | (5) Single-use Challenges
    v                           v
+-----------------------+   +-----------------------+
| PostgreSQL            |   | Redis                 |
| (Projects, Groups,    |   | (TTL-bound nonces,    |
|  Devices, Keys, RBAC) |   |  Atomic consumption)  |
+-----------------------+   +-----------------------+
```

## System Flow

1. **User Authentication**:
   The native client authenticates directly with Keycloak using OAuth 2.0 Authorization Code Flow with PKCE.

2. **API Access**:
   The client receives an OIDC access token containing `iss` (Issuer URL) and `sub` (Subject UUID). The client presents this access token to Gorape in the `Authorization: Bearer <token>` header.

3. **Gorape Validation**:
   Gorape validates the JWT signature via Keycloak's JWKS endpoint, verifies audience and scopes, and resolves the project and identity principal from `iss + sub`.

4. **Device Registration**:
   The client requests a single-use random challenge from Gorape, generates a hardware-backed cryptographic key pair, collects platform attestation evidence embedding the challenge, and submits the public key and evidence to Gorape.

5. **Hardware Attestation Verification**:
   Gorape verifies the platform certificate chain against configured trust anchors, extracts hardware security extensions (e.g., Keymaster/TEE/StrongBox), checks the embedded challenge, and persists the verified public key.

6. **Periodic Proof of Possession**:
   On subsequent sessions, Gorape issues an atomic challenge that the client signs with its hardware private key. Gorape verifies the signature against the registered public key and marks the device active and verified.
