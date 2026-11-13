package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"gopkg.in/yaml.v3"
)

// SecretsManagerClient wraps AWS Secrets Manager client
type SecretsManagerClient struct {
	client *secretsmanager.Client
}

// NewSecretsManagerClient creates a new Secrets Manager client
func NewSecretsManagerClient(ctx context.Context, useLocal bool) (*SecretsManagerClient, error) {
	var awsCfg aws.Config
	var err error

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	if useLocal {
		// Use LocalStack configuration
		endpoint := os.Getenv("AWS_ENDPOINT_URL")
		if endpoint == "" {
			endpoint = "http://localhost:4566"
		}

		// Load config with custom endpoint for LocalStack
		awsCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(region),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}

		// Create Secrets Manager client with custom endpoint
		client := secretsmanager.NewFromConfig(awsCfg, func(o *secretsmanager.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})

		return &SecretsManagerClient{
			client: client,
		}, nil
	}

	// Use production AWS configuration
	awsCfg, err = config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &SecretsManagerClient{
		client: secretsmanager.NewFromConfig(awsCfg),
	}, nil
}

// GetSecretString retrieves a secret string value
func (rcvr *SecretsManagerClient) GetSecretString(ctx context.Context, secretID string) (string, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	}

	result, err := rcvr.client.GetSecretValue(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to get secret: %w", err)
	}

	if result.SecretString != nil {
		return *result.SecretString, nil
	}

	return "", fmt.Errorf("secret does not contain string data")
}

// GetSecretAsJSON retrieves a secret and unmarshals it as JSON
func (rcvr *SecretsManagerClient) GetSecretAsJSON(ctx context.Context, secretID string, v interface{}) error {
	secretString, err := rcvr.GetSecretString(ctx, secretID)
	if err != nil {
		return err
	}

	if err := json.Unmarshal([]byte(secretString), v); err != nil {
		return fmt.Errorf("failed to unmarshal secret as JSON: %w", err)
	}

	return nil
}

// GetSecretAsYAML retrieves a secret and unmarshals it as YAML
func (rcvr *SecretsManagerClient) GetSecretAsYAML(ctx context.Context, secretID string, v interface{}) error {
	secretString, err := rcvr.GetSecretString(ctx, secretID)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal([]byte(secretString), v); err != nil {
		return fmt.Errorf("failed to unmarshal secret as YAML: %w", err)
	}

	return nil
}

// GetConfigFromEnv retrieves configuration from environment variables
func GetConfigFromEnv() (string, bool) {
	secretID := os.Getenv("SECRET_ID")
	useLocal := os.Getenv("USE_LOCALSTACK") == "true"
	return secretID, useLocal
}

// LoadConfigFromSecretsManager loads configuration from AWS Secrets Manager
func LoadConfigFromSecretsManager(ctx context.Context, secretID string, useLocal bool) (*YamlConfig, error) {
	client, err := NewSecretsManagerClient(ctx, useLocal)
	if err != nil {
		return nil, fmt.Errorf("failed to create Secrets Manager client: %w", err)
	}

	var config YamlConfig
	if err := client.GetSecretAsJSON(ctx, secretID, &config); err != nil {
		return nil, fmt.Errorf("failed to load config from Secrets Manager: %w", err)
	}

	return &config, nil
}
