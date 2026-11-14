#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
test ! -d docs/dist && test ! -d docs/_site || {
  echo "Generated static pages must not be stored under docs/" >&2
  exit 1
}
while read -r operation_id; do
  grep -Fq "/$operation_id)" docs/book/src/endpoints.md || {
    echo "Missing Swagger link for operationId: $operation_id" >&2
    exit 1
  }
done < <(awk '/operationId:/ {print $2}' docs/openapi/openapi.yaml)

operation_count="$(awk '/operationId:/ {count++} END {print count+0}' docs/openapi/openapi.yaml)"
table_count="$(grep -Ec '^\| (GET|POST|PUT|PATCH|DELETE) ' docs/book/src/endpoints.md)"
test "$operation_count" -eq "$table_count" || {
  echo "Endpoint table rows ($table_count) do not match OpenAPI operations ($operation_count)" >&2
  exit 1
}
echo "Documentation contract is consistent"
