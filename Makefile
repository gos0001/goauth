.PHONY: dev build run generate wire test lint build-prod tools sqlc docker-up docker-down jwt-key admin-token image image-push image-login image-run

APP_BIN := ./bin/app
ENV_FILE := .env.development

# Container image. Override any of these on the command line:
#   make image-push VERSION=v1.0.0
IMAGE      ?= ghcr.io/gos0001/goauth
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PLATFORMS  ?= linux/amd64,linux/arm64

BUILD_ARGS := --build-arg VERSION=$(VERSION) \
              --build-arg COMMIT=$(COMMIT) \
              --build-arg BUILD_DATE=$(BUILD_DATE)

dev:
	@air

run:
	@export $$(cat $(ENV_FILE) | grep -v '^#' | xargs) && go run ./cmd

build:
	@go build -o $(APP_BIN) ./cmd

# sqlc MUST run before wire: wire cannot compile the postgres adapter until the
# generated/ package exists.
generate: sqlc wire

sqlc:
	@sqlc generate

wire:
	@wire ./cmd/

test:
	@go test ./... -race -count=1

lint:
	@golangci-lint run ./...

build-prod:
	@go build -tags production -o $(APP_BIN) ./cmd

tools:
	@go install github.com/air-verse/air@latest
	@go install github.com/google/wire/cmd/wire@latest
	@go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

docker-up:
	@docker compose up -d postgres redis

docker-down:
	@docker compose down

# Single-arch build loaded into the local daemon. buildx cannot --load a
# multi-arch manifest, which is why building locally and pushing are separate
# targets rather than one target with a flag.
image:
	@docker buildx build $(BUILD_ARGS) -t $(IMAGE):$(VERSION) -t $(IMAGE):dev --load .
	@echo "built $(IMAGE):$(VERSION)"

# GHCR authenticates with a personal access token carrying write:packages.
image-login:
	@echo $$GITHUB_TOKEN | docker login ghcr.io -u gos0001 --password-stdin

# Pushes only the version tag. `latest` and the semver aliases are owned by CI,
# which moves them on a release tag — a manual push must not be able to point
# `latest` at an unreviewed local build.
image-push:
	@docker buildx build $(BUILD_ARGS) --platform $(PLATFORMS) \
		-t $(IMAGE):$(VERSION) --push .
	@echo "pushed $(IMAGE):$(VERSION) for $(PLATFORMS)"

# Run the locally built image against the compose Postgres and Redis.
image-run:
	@docker run --rm -it --network goauth_default -p 8080:8080 \
		--env-file $(ENV_FILE) \
		-e POSTGRES_URL=postgres://postgres:postgres@postgres:5432/goauth_dev?sslmode=disable \
		-e REDIS_URL=redis://redis:6379 \
		-e ADMIN_ADDR=0.0.0.0:8081 \
		$(IMAGE):dev

# Ed25519 signing seed for JWT_PRIVATE_KEY. One per environment — never reuse a
# development key in production.
jwt-key:
	@openssl rand -base64 32

# Credential for the private admin listener (ADMIN_TOKEN). Machines only; a
# browser must never be given this value.
admin-token:
	@openssl rand -base64 32
