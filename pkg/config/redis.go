package config

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"strings"

	"github.com/go-redis/redis/v8"
)

func NewRedisClient(cfg Redis) (*redis.Client, error) {
	opts := &redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password: cfg.Pass,
		DB:       int(cfg.DB), // IntOrString -> int
		Username: cfg.User,
	}

	// Auto-detect TLS required hosts like Upstash
	if strings.Contains(cfg.Host, "upstash.io") {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	client, err := connectRedisWithOptionalTLS(opts)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func connectRedisWithOptionalTLS(opts *redis.Options) (*redis.Client, error) {
	ctx := context.Background()
	client := redis.NewClient(opts)
	if _, err := client.Ping(ctx).Result(); err != nil {
		// Retry with TLS on EOF error (non-TLS → TLS pattern)
		if strings.Contains(err.Error(), "EOF") && opts.TLSConfig == nil {
			log.Println("Redis: EOF detected, retry with TLS enabled")
			optsTLS := *opts
			optsTLS.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			client = redis.NewClient(&optsTLS)
			if _, err2 := client.Ping(ctx).Result(); err2 != nil {
				return nil, fmt.Errorf("failed to connect to redis after TLS retry: %w", err2)
			}
			log.Println("Successfully connected to Redis (TLS retry)")
			return client, nil
		}
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}
	log.Println("Successfully connected to Redis")
	return client, nil
}
