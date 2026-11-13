# Security Policy

Report vulnerabilities privately through GitHub Security Advisories. Do not include production tokens, attestation evidence, certificates, or personal data in public issues.

Gorape requires HTTPS in production. Rotate Keycloak keys normally; JWKS refresh is handled by the OIDC library. Configure Android trust anchors explicitly—an empty trust store fails closed.

Known pre-release gaps:

- Android certificate revocation (CRL/OCSP) and application-identity authorization policy are not implemented.
- Windows TPM 2.0 and Apple App Attest verifiers are unsupported.
- Audit events currently cover device registration, proof, and revocation; complete RBAC/group audit coverage remains.
- The in-process rate limiter is per instance; clustered deployments need an ingress or shared limiter.

Do not treat this pre-release as production-ready until these items and an independent security review are complete.
