# Introduction

**Gorape** is an open-source, production-grade Device Trust & Hardware Attestation backend written in Go.

It validates Keycloak access tokens, enforces multi-tenant project/group role-based access control (RBAC), registers hardware-attested device public keys, verifies ongoing cryptographic proof-of-possession, and maintains an immutable audit trail of device lifecycle events.

## Core Design Principles

1. **Identity Delegation to Keycloak**:
   Gorape is not an Identity Provider (IdP) or user management system. It does not store passwords, usernames, email addresses, or personal credentials. User authentication, password policies, MFA, WebAuthn, and user profile management are delegated entirely to Keycloak.

2. **No Private Key Storage**:
   Gorape never generates, receives, or stores private keys. Hardware-backed private keys are generated inside client secure hardware (e.g. Android Keystore / StrongBox / TEE) and never leave the device. Gorape only receives and stores attested public keys.

3. **Strict Fail-Closed Security**:
   Any attestation or verification challenge failure fails closed. Unconfigured platforms, unsupported hardware verifiers (e.g., Windows TPM or iOS/macOS prior to implementation), expired challenges, or signature mismatches are strictly rejected.

4. **Multi-Tenancy & Project Scoping**:
   Each `Project` in Gorape maps 1:1 to a designated Keycloak Realm. Every entity (groups, roles, devices, public keys, attestations, and audit logs) is scoped to a specific project. Cross-project data access is strictly prohibited at both the database schema constraint level and the application layer.
