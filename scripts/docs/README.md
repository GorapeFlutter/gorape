# Backend GF source IDs

Backend source references use `GF-1xxxx`, separate from the gf-app ID range.
Put the ID in a Go comment (or SQL comment for migrations) next to the function
or schema change documented in `docs/`:

```go
// GF-10001 — Starts the HTTP and optional HTTPS API listeners.
func Main(conf config.BaseConfig) { ... }
```

Run `python3 scripts/docs/link_gf_ids.py` to link those IDs in Markdown to the
corresponding GitHub source line. CI runs the read-only validation form:

```bash
python3 scripts/docs/link_gf_ids.py --check
```

The RP/credential IDs are documentation references only; they are not runtime
identifiers or secrets.
