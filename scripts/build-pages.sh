#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
command -v mdbook >/dev/null 2>&1 || { echo "mdbook is required (CI uses mdbook 0.5.1)" >&2; exit 1; }
rm -rf "$ROOT_DIR/_site"
mdbook build docs/book
mkdir -p "$ROOT_DIR/_site/swagger"
cp docs/pages/swagger.html "$ROOT_DIR/_site/swagger/index.html"
cp docs/openapi/openapi.yaml "$ROOT_DIR/_site/swagger/openapi.yaml"
touch "$ROOT_DIR/_site/.nojekyll"
echo "Pages output: $ROOT_DIR/_site"
