# Architecture

Project Domains map one-to-one to Keycloak Realms. Group Domains, RBAC, devices, keys, attestation records, and events are project-scoped in PostgreSQL. Redis stores short-lived single-use challenges.
