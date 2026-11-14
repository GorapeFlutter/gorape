#!/usr/bin/env bash
function docs_build() {
  "$ROOT_DIR/scripts/check-docs.sh"
  "$ROOT_DIR/scripts/build-pages.sh"
}
function docs_serve() {
  docs_build
  info "Serving _site at http://localhost:8000"
  python3 -m http.server 8000 --directory "$ROOT_DIR/_site"
}
function docs_architecture() {
  info "ER diagram is rendered by Mermaid in docs/book/src/er.md"
}
