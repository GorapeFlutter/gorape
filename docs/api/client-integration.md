# Client integration contract

Clients authenticate directly with the Project's Keycloak Realm using Authorization Code + PKCE and send the access token as `Authorization: Bearer ...`. ID tokens are rejected as API credentials.

Registration is two-step: request a challenge, generate a hardware-backed key, obtain platform evidence containing that challenge, then submit the public key and evidence. Challenges are bound to Project, OIDC subject, purpose, and a short expiry and can be consumed once.

Android `evidence.certificate_chain` is an array ordered leaf first. Each item is PEM or base64 DER. The leaf key must equal `public_key_pem`, and the Android KeyDescription challenge must equal the server challenge.

For ongoing proof, sign the raw decoded challenge bytes with the registered key. ECDSA signatures use ASN.1 DER; RSA uses PKCS#1 v1.5 with SHA-256; Ed25519 signs the raw challenge. Send the signature as base64url.
