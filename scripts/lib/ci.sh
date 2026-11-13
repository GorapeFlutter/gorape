#!/usr/bin/env bash
function ci_command() {
  case "$1" in
    run) go test ./... ;;
    unit) go test ./test/unit/... ;;
    e2e) go test -tags=e2e ./test/e2e/... ;;
    *) err "Unknown CI command: $1"; return 1 ;;
  esac
}
