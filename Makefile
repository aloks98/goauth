.PHONY: all build test test-coverage lint clean fmt vet check
.PHONY: demo demo-http demo-gin demo-chi demo-echo demo-fiber demo-build demo-clean demo-help

# Default target
all: check test

# =============================================================================
# Code Quality
# =============================================================================

# Run all checks
check: fmt vet lint

# Format code
fmt:
	go fmt ./...

# Run go vet
vet:
	go vet ./...

# Run linter (requires golangci-lint)
lint:
	golangci-lint run

# =============================================================================
# Testing
# =============================================================================

# Run tests
test:
	go test -race ./...

# Run tests with coverage
test-coverage:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html

# Run integration tests (requires Docker)
test-integration:
	go test -race -tags=integration ./...

# Run benchmarks
bench:
	go test -bench=. -benchmem ./...

# =============================================================================
# Dependencies
# =============================================================================

# Tidy dependencies
tidy:
	go mod tidy

# Download dependencies
deps:
	go mod download

# Verify dependencies
verify:
	go mod verify

# =============================================================================
# Full-Stack Demo Application
# =============================================================================

DEMO_DIR := ./examples/fullstack

# Run demo with default backend (net/http)
demo: demo-http

# Run with net/http backend
demo-http:
	@echo "Starting GoAuth Full-Stack Demo (net/http)..."
	@cd $(DEMO_DIR) && go run ./cmd/http/main.go

# Run with Gin backend
demo-gin:
	@echo "Starting GoAuth Full-Stack Demo (Gin)..."
	@cd $(DEMO_DIR) && go run ./cmd/gin/main.go

# Run with Chi backend
demo-chi:
	@echo "Starting GoAuth Full-Stack Demo (Chi)..."
	@cd $(DEMO_DIR) && go run ./cmd/chi/main.go

# Run with Echo backend
demo-echo:
	@echo "Starting GoAuth Full-Stack Demo (Echo)..."
	@cd $(DEMO_DIR) && go run ./cmd/echo/main.go

# Run with Fiber backend
demo-fiber:
	@echo "Starting GoAuth Full-Stack Demo (Fiber)..."
	@cd $(DEMO_DIR) && go run ./cmd/fiber/main.go

# Build all demo backends
demo-build:
	@echo "Building all demo backends..."
	@mkdir -p $(DEMO_DIR)/bin
	@cd $(DEMO_DIR) && go build -o ./bin/http ./cmd/http/main.go
	@cd $(DEMO_DIR) && go build -o ./bin/gin ./cmd/gin/main.go
	@cd $(DEMO_DIR) && go build -o ./bin/chi ./cmd/chi/main.go
	@cd $(DEMO_DIR) && go build -o ./bin/echo ./cmd/echo/main.go
	@cd $(DEMO_DIR) && go build -o ./bin/fiber ./cmd/fiber/main.go
	@echo "Binaries built in $(DEMO_DIR)/bin/"

# Clean demo binaries
demo-clean:
	@rm -rf $(DEMO_DIR)/bin/

# Show demo help
demo-help:
	@echo "GoAuth Full-Stack Demo - Available targets:"
	@echo ""
	@echo "  make demo          - Run with net/http backend (default)"
	@echo "  make demo-http     - Run with net/http backend"
	@echo "  make demo-gin      - Run with Gin backend"
	@echo "  make demo-chi      - Run with Chi backend"
	@echo "  make demo-echo     - Run with Echo backend"
	@echo "  make demo-fiber    - Run with Fiber backend"
	@echo "  make demo-build    - Build all backends to ./examples/fullstack/bin/"
	@echo "  make demo-clean    - Remove built demo binaries"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - PostgreSQL running on localhost:15432"
	@echo "  - Database 'goauth_test' with user 'goauth:goauth'"
	@echo ""
	@echo "Demo users:"
	@echo "  - admin@example.com / admin123 (admin role)"
	@echo "  - user@example.com / user123 (user role)"
	@echo "  - viewer@example.com / viewer123 (viewer role)"

# =============================================================================
# Cleanup
# =============================================================================

# Clean build artifacts
clean:
	rm -f coverage.out coverage.html
	go clean -testcache

# =============================================================================
# Help
# =============================================================================

help:
	@echo "GoAuth - Available targets:"
	@echo ""
	@echo "Code Quality:"
	@echo "  make fmt           - Format code"
	@echo "  make vet           - Run go vet"
	@echo "  make lint          - Run golangci-lint"
	@echo "  make check         - Run all checks (fmt, vet, lint)"
	@echo ""
	@echo "Testing:"
	@echo "  make test          - Run tests"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make test-integration - Run integration tests"
	@echo "  make bench         - Run benchmarks"
	@echo ""
	@echo "Dependencies:"
	@echo "  make deps          - Download dependencies"
	@echo "  make tidy          - Tidy go.mod"
	@echo "  make verify        - Verify dependencies"
	@echo ""
	@echo "Full-Stack Demo:"
	@echo "  make demo          - Run demo (net/http)"
	@echo "  make demo-gin      - Run demo (Gin)"
	@echo "  make demo-chi      - Run demo (Chi)"
	@echo "  make demo-echo     - Run demo (Echo)"
	@echo "  make demo-fiber    - Run demo (Fiber)"
	@echo "  make demo-build    - Build all demo backends"
	@echo "  make demo-help     - Show demo help"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean         - Clean build artifacts"
