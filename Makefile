SHELL := /bin/bash

COVER_PROFILE ?= coverage.out

GO ?= go
GOTEST := $(GO) test
GOBUILD := $(GO) build
GOLANGCI := golangci-lint
MDLINT := markdownlint

.PHONY: help
help: ## Show available make targets
	@echo "Available targets:"
	@grep -hE '^[%a-zA-Z0-9_/.\-]+:.*## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS=":.*## "}; {printf "  %-20s %s\n", $$1, $$2}'

.PHONY: check-deps
check-deps: ## Ensure required tools are installed
	@command -v $(GO) >/dev/null 2>&1 || { echo >&2 "$(GO) is required but not installed. Aborting."; exit 1; }
	@command -v $(GOLANGCI) >/dev/null 2>&1 || { echo >&2 "$(GOLANGCI) is required but not installed. Aborting."; exit 1; }
	@command -v $(MDLINT) >/dev/null 2>&1 || { echo >&2 "$(MDLINT) is required but not installed. Aborting."; exit 1; }

.PHONY: deps
deps: ## Download module dependencies
	@$(GO) mod download

.PHONY: tidy
tidy: ## Sync go.mod and go.sum
	@$(GO) mod tidy

.PHONY: fmt
fmt: check-deps ## Format Go source files using golangci-lint
	@$(GOLANGCI) run --config=.golangci.yml --fix --issues-exit-code=0 ./... >/dev/null

.PHONY: lint
lint: check-deps ## Run linters
	@$(GOLANGCI) run --config=.golangci.yml ./...
	@$(MDLINT) -c .markdownlint.yml .

.PHONY: test
test: ## Execute unit tests with coverage
	@$(GOTEST) -cover ./...

.PHONY: cover
cover: ## Run tests with coverage report
	@$(GOTEST) -coverprofile=$(COVER_PROFILE) ./...
	@$(GO) tool cover -func=$(COVER_PROFILE)

.PHONY: clean
clean: check-deps ## Remove build artifacts and caches
	@rm -f $(COVER_PROFILE)
	@rm -rf .cache
	@$(GO) clean -cache
	@$(GOLANGCI) cache clean
