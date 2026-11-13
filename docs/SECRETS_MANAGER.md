# AWS Secrets Manager Integration

This document describes how to use AWS Secrets Manager for configuration management in the gorape application.

## Overview

gorape supports two configuration sources:
1. **File-based configuration** (default): Loads configuration from `etc/server.yaml`
2. **AWS Secrets Manager**: Loads configuration from AWS Secrets Manager (supports both LocalStack for development and production AWS)

## Configuration

### Environment Variables

The configuration source is controlled by environment variables:

```bash
# Configuration source selection
USE_SECRETSMANAGER=true    # Set to "true" to use Secrets Manager, "false" or unset to use file-based config

# AWS Secrets Manager configuration
SECRET_ID=gorape/config/server # The ID of the secret containing server configuration

# LocalStack configuration (for local development)
USE_LOCALSTACK=true        # Set to "true" to use LocalStack, "false" to use production AWS
AWS_ENDPOINT_URL=http://localhost:4566  # LocalStack endpoint URL
AWS_REGION=us-east-1       # AWS region
```

Set these variables in your shell or deployment environment.

## Local Development with LocalStack

### Prerequisites

- Docker and Docker Compose installed
- AWS CLI installed (optional, for manual testing)

### Setup

1. **Start LocalStack**:
   ```bash
   make localstack
   ```

2. **Initialize Secrets Manager** (automatically runs on container start):
   The secrets initialization is handled by `./scripts/main.sh secrets init`, which creates the `gorape/config/server` secret from `etc/server.yaml`.

3. **Verify secret creation** (optional):
   ```bash
   aws --endpoint-url=http://localhost:4566 secretsmanager list-secrets --region us-east-1
   aws --endpoint-url=http://localhost:4566 secretsmanager get-secret-value --secret-id gorape/config/server --region us-east-1
   ```

4. **Configure environment variables**:
   ```bash
   export USE_SECRETSMANAGER=true
   export USE_LOCALSTACK=true
   export SECRET_ID=gorape/config/server
   export AWS_ENDPOINT_URL=http://localhost:4566
   export AWS_REGION=us-east-1
   ```

5. **Run the application**:
   ```bash
   go run ./cmd/server -config etc/server.yaml
   ```

   The application will load configuration from LocalStack Secrets Manager instead of `etc/server.yaml`.

### Manual Secret Update

To update the secret manually:

```bash
# Create a JSON configuration file
cat > /tmp/config.json <<EOF
{
  "application": {
    "common": {
      "name": "gorape-updated",
      "version": "1.0.0",
      "env": "dev"
    },
    ...
  }
}
EOF

# Update the secret
aws --endpoint-url=http://localhost:4566 secretsmanager put-secret-value \
  --secret-id gorape/config/server \
  --secret-string file:///tmp/config.json \
  --region us-east-1
```

## Production Deployment

### Prerequisites

- AWS account with Secrets Manager access
- IAM credentials or IAM role with `secretsmanager:GetSecretValue` permission

### Setup

1. **Create secret in AWS Secrets Manager**:
   ```bash
   # Create JSON configuration file
   cat > /tmp/prod-config.json <<EOF
   {
     "Application": {
       "Server": {
         "port": 8000,
         "challenge_ttl": "5m",
         "oidc": {
           "audience": "gorape-api",
           "required_scopes": ["openid"],
           "provider_urls": {}
         },
         "attestation": {"android_trust_anchors": []}
       }
     },
     "PostgreSQL": {
       "host": "postgres.example.com",
       "user": "gorape",
       "pass": "your-production-password",
       "port": "5432",
       "db": "gorape",
       "sslmode": "require"
     },
     "Redis": {
       "host": "redis.example.com",
       "port": 6379,
       "user": "default",
       "pass": "your-production-password",
       "db": 0
     },
     "Logger": {
       "component": "gorape",
       "service": "gorape",
       "level": "INFO",
       "structured": true,
       "output": "stdout"
     }
   }
   EOF

   # Create the secret
   aws secretsmanager create-secret \
     --name gorape/config/server \
     --secret-string file:///tmp/prod-config.json \
     --region us-east-1
   ```

2. **Configure environment variables**:
   ```bash
   export USE_SECRETSMANAGER=true
   export USE_LOCALSTACK=false
   export SECRET_ID=gorape/config/server
   export AWS_REGION=us-east-1
   # AWS credentials will be loaded from default credential chain (environment variables, IAM role, etc.)
   ```

3. **Run the application**:
   ```bash
   ./gorape
   ```

## Fallback Behavior

If Secrets Manager configuration fails (e.g., network issues, invalid credentials), the application will automatically fall back to file-based configuration (`etc/server.yaml`).

Log messages will indicate which configuration source was used:
- `Successfully loaded configuration from Secrets Manager` - Secrets Manager was used
- `Successfully loaded configuration from file (etc/server.yaml)` - File-based config was used
- `Failed to load config from Secrets Manager: <error>, falling back to file-based config` - Secrets Manager failed, fell back to file

## Configuration Format

The secret value must be a JSON object matching the YAML structure in `etc/server.yaml`:

```json
{
  "Application": {
    "Server": {
      "port": 8000,
      "log_level": "info",
      "challenge_ttl": "5m",
      "redis": {"challenge_prefix": "gorape:challenge:"},
      "oidc": {
        "audience": "gorape-api",
        "required_scopes": ["openid"],
        "provider_urls": {}
      },
      "attestation": {"android_trust_anchors": []}
    }
  },
  "PostgreSQL": {
    "host": "localhost",
    "user": "user",
    "pass": "password",
    "port": "5432",
    "db": "gorape",
    "sslmode": "disable"
  },
  "Redis": {
    "host": "localhost",
    "port": 6379,
    "user": "default",
    "pass": "mysecretpassword",
    "db": 0
  },
  "Logger": {
    "component": "gorape",
    "service": "gorape",
    "level": "INFO",
    "structured": true,
    "output": "stdout"
  }
}
```

## Troubleshooting

### "Failed to create Secrets Manager client"

- Check that AWS credentials are properly configured
- Verify AWS_REGION is set correctly
- For LocalStack: ensure LocalStack is running and AWS_ENDPOINT_URL is correct

### "Failed to get secret"

- Verify the SECRET_ID matches the secret name in Secrets Manager
- Check IAM permissions include `secretsmanager:GetSecretValue`
- For LocalStack: ensure the init script ran successfully

### "Failed to unmarshal secret as JSON"

- Verify the secret value is valid JSON
- Check that the JSON structure matches the expected configuration format

### Application falls back to file-based config unexpectedly

- Check log messages for specific error details
- Verify USE_SECRETSMANAGER=true is set
- Ensure SECRET_ID is not empty
