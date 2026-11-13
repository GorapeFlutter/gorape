# Contributing

Use Go 1.25 or newer. Keep the inherited controller/usecase/repository layering, format changes with `gofmt`, and run `make test` before opening a pull request.

Follow these architectural rules:
- Split files per concept in each layer (`entity`, `repository`, `usecase`, `controller`).
- Co-locate interfaces, implementation structs, and `New<Concept>(...)` constructors in each concept file. Put cross-cutting helpers and aggregators in `common.go`.
- Name all method receivers `rcvr`.
- Keep `pkg/entity/model` minimal and clean; never retain unused domain/table definitions.

Changes must preserve project scoping in HTTP authorization, repository queries, and PostgreSQL constraints. Never add password login, unknown-issuer discovery, private-key storage, Casdoor, or client-certificate issuance.

Security-sensitive changes require tests for fail-closed behavior and cross-project access.
