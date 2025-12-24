.PHONY: all http gin chi echo fiber clean

# Default target
all: http

# Run with net/http backend
http:
	@echo "Starting GoAuth Full-Stack Demo (net/http)..."
	@go run ./cmd/http/main.go

# Run with Gin backend
gin:
	@echo "Starting GoAuth Full-Stack Demo (Gin)..."
	@go run ./cmd/gin/main.go

# Run with Chi backend
chi:
	@echo "Starting GoAuth Full-Stack Demo (Chi)..."
	@go run ./cmd/chi/main.go

# Run with Echo backend
echo:
	@echo "Starting GoAuth Full-Stack Demo (Echo)..."
	@go run ./cmd/echo/main.go

# Run with Fiber backend
fiber:
	@echo "Starting GoAuth Full-Stack Demo (Fiber)..."
	@go run ./cmd/fiber/main.go

# Build all backends
build:
	@echo "Building all backends..."
	@go build -o bin/http ./cmd/http/main.go
	@go build -o bin/gin ./cmd/gin/main.go
	@go build -o bin/chi ./cmd/chi/main.go
	@go build -o bin/echo ./cmd/echo/main.go
	@go build -o bin/fiber ./cmd/fiber/main.go
	@echo "Binaries built in ./bin/"

# Clean built binaries
clean:
	@rm -rf bin/

# Start PostgreSQL (uses existing test database)
postgres:
	@echo "Using existing test database at localhost:15432"
	@echo "DSN: postgres://goauth:goauth@localhost:15432/goauth_test?sslmode=disable"

# Show help
help:
	@echo "GoAuth Full-Stack Demo - Available targets:"
	@echo ""
	@echo "  make http    - Run with net/http backend (default)"
	@echo "  make gin     - Run with Gin backend"
	@echo "  make chi     - Run with Chi backend"
	@echo "  make echo    - Run with Echo backend"
	@echo "  make fiber   - Run with Fiber backend"
	@echo "  make build   - Build all backends to ./bin/"
	@echo "  make clean   - Remove built binaries"
	@echo "  make help    - Show this help"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - PostgreSQL running on localhost:15432"
	@echo "  - Database 'goauth_test' with user 'goauth:goauth'"
	@echo ""
	@echo "Demo users:"
	@echo "  - admin@example.com / admin123 (admin role)"
	@echo "  - user@example.com / user123 (user role)"
	@echo "  - viewer@example.com / viewer123 (viewer role)"
