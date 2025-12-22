.PHONY: all build test test-coverage lint clean fmt vet check

# Default target
all: check test

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

# Clean build artifacts
clean:
	rm -f coverage.out coverage.html
	go clean -testcache

# Tidy dependencies
tidy:
	go mod tidy

# Download dependencies
deps:
	go mod download

# Verify dependencies
verify:
	go mod verify
