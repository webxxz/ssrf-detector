.PHONY: build test clean install docker run help

BINARY_NAME=ssrfdetect
VERSION=1.0.0
BUILD_DIR=build
GO=go

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/$(BINARY_NAME) -ldflags="-X main.version=$(VERSION)" cmd/ssrfdetect/main.go
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

build-all: ## Build for all platforms
	@echo "Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 $(GO) build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 cmd/ssrfdetect/main.go
	GOOS=darwin GOARCH=amd64 $(GO) build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 cmd/ssrfdetect/main.go
	GOOS=darwin GOARCH=arm64 $(GO) build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 cmd/ssrfdetect/main.go
	GOOS=windows GOARCH=amd64 $(GO) build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe cmd/ssrfdetect/main.go
	@echo "Multi-platform build complete"

test: ## Run tests
	$(GO) test -v -race -coverprofile=coverage.out ./...

test-integration: ## Run integration tests
	$(GO) test -v -tags=integration ./test/integration/...

coverage: test ## Generate coverage report
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

clean: ## Clean build artifacts
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html
	@echo "Clean complete"

install: build ## Install binary to $GOPATH/bin
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/
	@echo "Installed to $(GOPATH)/bin/$(BINARY_NAME)"

docker: ## Build Docker image
	docker build -t ssrf-detector:$(VERSION) .
	docker tag ssrf-detector:$(VERSION) ssrf-detector:latest

docker-run: ## Run in Docker
	docker-compose up

run: build ## Build and run with example
	@echo "Running example scan..."
	./$(BUILD_DIR)/$(BINARY_NAME) \
		-u "https://example.com/fetch?url=test" \
		-p url \
		--oob-domain oob.example.com \
		-v

lint: ## Run linter
	golangci-lint run ./...

fmt: ## Format code
	$(GO) fmt ./...

vet: ## Run go vet
	$(GO) vet ./...

deps: ## Download dependencies
	$(GO) mod download
	$(GO) mod tidy

update-deps: ## Update dependencies
	$(GO) get -u ./...
	$(GO) mod tidy

.DEFAULT_GOAL := help