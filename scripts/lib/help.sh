#!/usr/bin/env bash
function help() {
  cat <<'EOF'
Gorape development helper
  ./scripts/main.sh env up|down|recreate|status|logs
  ./scripts/main.sh ci run|unit|e2e
  ./scripts/main.sh docs build|serve|architecture
  ./scripts/main.sh secrets
EOF
}
