#!/usr/bin/env bash
set -euo pipefail
COMMAND="${1:-help}"; shift || true
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/env.sh"
source "$SCRIPT_DIR/lib/ci.sh"
source "$SCRIPT_DIR/lib/docs.sh"
source "$SCRIPT_DIR/lib/secrets.sh"
source "$SCRIPT_DIR/lib/help.sh"
case "$COMMAND" in
  env) env_command "${1:-help}" "${@:2}" ;;
  ci) ci_command "${1:-run}" ;;
  docs) case "${1:-build}" in build) docs_build;; serve) docs_serve;; architecture) docs_architecture;; *) help;; esac ;;
  secrets) secrets_init ;;
  help|--help|-h) help ;;
  *) err "Unknown command: $COMMAND"; help; exit 1 ;;
esac
