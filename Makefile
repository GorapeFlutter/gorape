.DEFAULT_GOAL := help
.PHONY: help s bootstrap build fmt fmt-check vet lint tidy \
	test test-unit test-integration test-e2e test-race coverage \
	dev-up dev-down dev-recreate dev-api \
	svr-up svr-down config docs docs-build docs-serve \
	localstack logs clean

# ---------------------------------------------------------------------------
# Docker Compose — all service files merged via -f flags
# ---------------------------------------------------------------------------
COMPOSE = docker compose --project-directory . \
	-f docker/network.yaml \
	-f docker/postgres.yaml \
	-f docker/pgadmin.yaml \
	-f docker/redis.yaml \
	-f docker/keycloak.yaml \
	-f docker/server.yaml \
	-f docker/swagger.yaml \
	-f docker/godoc.yaml \
	-f docker/localstack.yaml

GO      ?= go
BIN_DIR ?= .bin

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
help:
	@echo "Gorape development tasks"
	@echo ""
	@echo "  Setup / build"
	@echo "    make bootstrap       Copy etc/*.yaml.example to local config files"
	@echo "    make build           Build binaries into $(BIN_DIR)/"
	@echo "    make tidy            go mod tidy"
	@echo ""
	@echo "  Development environment"
	@echo "    make dev-up          Start postgres, redis, pgadmin, keycloak"
	@echo "    make dev-down        Stop and remove dev containers and volumes"
	@echo "    make dev-recreate    dev-down + dev-up"
	@echo "    make dev-api         Run the API on the host (etc/server.yaml)"
	@echo "    make svr-up          Build and start the server container"
	@echo "    make svr-down        Stop and remove the server container"
	@echo "    make localstack      Start LocalStack (secretsmanager mock)"
	@echo "    make logs            Follow logs (SERVICE=postgres to filter)"
	@echo "    make config          Validate the merged compose configuration"
	@echo ""
	@echo "  Documentation"
	@echo "    make docs            Swagger UI + godoc containers"
	@echo "    make docs-build      Build static documentation into docs/dist"
	@echo "    make docs-serve      Serve docs/dist at http://localhost:8000"
	@echo ""
	@echo "  Quality"
	@echo "    make fmt             gofmt -w cmd pkg test"
	@echo "    make fmt-check       Fail if any file is not gofmt'd"
	@echo "    make vet             go vet ./..."
	@echo "    make lint            fmt-check + vet"
	@echo "    make test            go test ./..."
	@echo "    make test-unit       go test ./test/unit/..."
	@echo "    make test-integration go test ./test/integration/..."
	@echo "    make test-e2e        go test -tags=e2e ./test/e2e/..."
	@echo "    make test-race       go test -race ./..."
	@echo "    make coverage        Write coverage.out and coverage.html"
	@echo "    make clean           Remove coverage artifacts"

# ---------------------------------------------------------------------------
# Git shortcut (same as .legacy-cmn-core/Makefile)
# ---------------------------------------------------------------------------
s:
	git add .
	commit-emoji
	git push origin main

# ---------------------------------------------------------------------------
# Setup / build
# ---------------------------------------------------------------------------
bootstrap:
	@test -f etc/server.yaml || cp etc/server.yaml.example etc/server.yaml
	@test -f etc/app.yaml    || cp etc/app.yaml.example    etc/app.yaml
	@test -f etc/admin.yaml  || cp etc/admin.yaml.example  etc/admin.yaml
	@echo "Local configuration ready in etc/"

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/gorape        ./cmd/server
	$(GO) build -o $(BIN_DIR)/gorape-admin  ./cmd/client/admin
	$(GO) build -o $(BIN_DIR)/gorape-client ./cmd/client/app
	$(GO) build -o $(BIN_DIR)/gorape-health ./cmd/client/anonymous

tidy:
	$(GO) mod tidy

# ---------------------------------------------------------------------------
# Development environment (core infra + IdP; server excluded)
# ---------------------------------------------------------------------------
dev-up:
	$(COMPOSE) up -d postgres redis pgadmin keycloak

dev-down:
	$(COMPOSE) down -v --remove-orphans

dev-recreate:
	$(MAKE) dev-down
	$(MAKE) dev-up

# Run the API on the host against the dockerized dependencies
dev-api:
	$(GO) run ./cmd/server -config etc/server.yaml

# App server container (build image and start, dependencies unchanged)
svr-up:
	$(COMPOSE) up -d --build --no-deps server

# Stop and remove the app server container only
svr-down:
	$(COMPOSE) stop server
	$(COMPOSE) rm -f -v server

config:
	$(COMPOSE) config --quiet
	@echo "Compose configuration is valid"

# ---------------------------------------------------------------------------
# Documentation (swagger-ui + godoc)
# ---------------------------------------------------------------------------
docs:
	$(COMPOSE) up -d swagger-ui godoc
	@echo "Swagger UI: http://localhost:3002"
	@echo "Go Docs:    http://localhost:3003"

docs-build:
	./scripts/main.sh docs build

docs-serve:
	./scripts/main.sh docs serve

# ---------------------------------------------------------------------------
# AWS mock (localstack)
# ---------------------------------------------------------------------------
localstack:
	$(COMPOSE) up -d localstack

# Logs (pass SERVICE= to filter, e.g. make logs SERVICE=postgres)
logs:
	$(COMPOSE) logs -f $(SERVICE)

# ---------------------------------------------------------------------------
# Quality / tests
# ---------------------------------------------------------------------------
fmt:
	gofmt -w cmd pkg test

fmt-check:
	@test -z "$$(gofmt -l cmd pkg test)" || { \
		echo "gofmt required:"; gofmt -l cmd pkg test; exit 1; \
	}

vet:
	$(GO) vet ./...

lint: fmt-check vet

test:
	$(GO) test ./...

test-unit:
	$(GO) test ./test/unit/...

test-integration:
	$(GO) test ./test/integration/...

test-e2e:
	$(GO) test -tags=e2e ./test/e2e/...

test-race:
	$(GO) test -race ./...

coverage:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

clean:
	rm -f coverage.out coverage.html
