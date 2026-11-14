# Development scripts

The inherited unified helper remains available:

```bash
./scripts/main.sh env up
./scripts/main.sh ci unit
./scripts/main.sh docs build
./scripts/main.sh secrets
```

Environment commands delegate to the repository Makefile so Compose service selection stays in one place.

`docs build` reads `docs/book/`, `docs/openapi/`, and `docs/pages/` and writes the ignored GitHub Pages artifact to `_site/`.
