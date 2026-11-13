#!/usr/bin/env bash
function env_command() {
  local command="$1"; shift || true
  case "$command" in
    up) make dev-up ;;
    recreate) make dev-down; make dev-up ;;
    down) make dev-down ;;
    status) docker compose ps ;;
    logs) make logs SERVICE="${1:-}" ;;
    *) help ;;
  esac
}
