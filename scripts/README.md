# Development scripts

The inherited unified helper remains available:

```bash
./scripts/main.sh env up
./scripts/main.sh ci unit
./scripts/main.sh docs build
./scripts/main.sh secrets
```

Environment commands delegate to the repository Makefile so Compose service selection stays in one place.
