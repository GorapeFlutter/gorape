# Security Policy

Report vulnerabilities privately through GitHub Security Advisories. Do not include production tokens, attestation evidence, certificates, or personal data in public issues.

Gorape requires HTTPS in production. Rotate Keycloak keys normally; JWKS refresh is handled by the OIDC library. Configure Android/WebAuthn trust anchors explicitly—an empty WebAuthn format allowlist and `allow_none: false` fail closed.

Known pre-release gaps:

- Android and WebAuthn attestation certificate revocation (CRL/OCSP), FIDO Metadata Service status checks, and Android application-identity authorization policy are not implemented.
- WebAuthn TPM/Apple format verifiers exist, but production trust bundles and physical-device coverage must be validated per deployment. This does not implement Apple App Attest.
- Windows/Linux/Web system-browser OIDC and the Linux browser-handoff flow need deployment-specific redirect, CORS, RP association, and browser/provider testing.
- Audit events currently cover device registration, proof, and revocation; complete RBAC/group audit coverage remains.
- The in-process rate limiter is per instance; clustered deployments need an ingress or shared limiter.

Do not treat this pre-release as production-ready until these items and an independent security review are complete.
