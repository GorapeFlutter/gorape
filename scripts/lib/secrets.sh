#!/usr/bin/env bash
# Secrets Management functions

# SCRIPT_DIR and ROOT_DIR are inherited from main.sh

function secrets_init() {
    info "Initializing LocalStack Secrets Manager..."

    # Wait for LocalStack to be ready
    until curl -s http://localhost:4566/_localstack/health | grep -q '"secretsmanager": "available"'; do
        info "Waiting for LocalStack Secrets Manager to be ready..."
        sleep 2
    done

    success "LocalStack is ready. Creating secrets..."

    # Path to config file
    local CONFIG_FILE="$ROOT_DIR/etc/server.yaml"

    # Convert YAML to JSON using Python
    info "Converting $CONFIG_FILE to JSON..."
    local CONFIG_JSON
    CONFIG_JSON=$(python3 -c "
import yaml
import json
with open('$CONFIG_FILE', 'r') as f:
    data = yaml.safe_load(f)
print(json.dumps(data, separators=(',', ':')))
")

    awslocal secretsmanager create-secret \
        --name gorape/config/server \
        --description "Gorape server configuration" \
        --secret-string "$CONFIG_JSON" \
        --region us-east-1 \
        --endpoint-url http://localhost:4566 || echo "Secret may already exist"

    success "Secrets created successfully!"
    echo ""
    echo "To retrieve the secret:"
    echo "  awslocal secretsmanager get-secret-value --secret-id gorape/config/server --endpoint-url http://localhost:4566"
}
