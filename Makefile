# Makefile for OpenTrusty Auth

BINARY_NAME=authd
MAIN_PATH=./cmd/authd/main.go

.PHONY: build test lint clean help run-health

help:
	@echo "OpenTrusty Auth Makefile"
	@echo "Usage:"
	@echo "  make build       - Build the authd binary"
	@echo "  make test        - Run all tests"
	@echo "  make lint        - Run linter"
	@echo "  make run-health  - Check if service is healthy (requires running service)"
	@echo "  make clean       - Clean build artifacts"

build:
	go build -o $(BINARY_NAME) $(MAIN_PATH)

deps:
	go mod download
	go mod tidy

test: test-service

test-unit:
	go test -v -short ./...

test-service:
	go test -v ./...

lint:
	golangci-lint run ./...

run-health:
	curl -f http://localhost:8080/health || (echo "Service health check failed" && exit 1)

clean:
	go clean -cache
	rm -f $(BINARY_NAME)
