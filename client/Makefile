.PHONY: dev build build-all clean install-deps test fmt lint

# Default server URL (override with: make build SERVER_URL=https://your-server.com)
SERVER_URL ?= https://filterdns.example.com

# Build flags
LDFLAGS := -s -w -X 'github.com/zkmkarlsruhe/filterdns-client/internal/config.DefaultServerURL=$(SERVER_URL)'

# Build for current platform
build:
	go build -ldflags="$(LDFLAGS)" -o build/bin/filterdns-client .

# Build with optimizations (smaller binary)
build-release:
	go build -ldflags="$(LDFLAGS)" -o build/bin/filterdns-client .

# Cross-compile for all platforms
build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o build/bin/filterdns-client-linux-amd64 .

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o build/bin/filterdns-client-linux-arm64 .

build-darwin:
	GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o build/bin/filterdns-client-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o build/bin/filterdns-client-darwin-arm64 .

build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o build/bin/filterdns-client-windows-amd64.exe .

build-all: build-linux build-linux-arm64 build-darwin build-windows

# Install dependencies
install-deps:
	go mod download

# Clean build artifacts
clean:
	rm -rf build/bin

# Run tests
test:
	go test ./...

# Format code
fmt:
	go fmt ./...

# Lint
lint:
	go vet ./...

# Run in dev mode
dev:
	go run .
