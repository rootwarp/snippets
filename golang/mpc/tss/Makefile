.PHONY: all build run test test-short bench clean deps

# Default target
all: deps build

# Install dependencies
deps:
	go mod tidy
	go mod download

# Build the binary
build:
	go build -o mpc-tss .

# Run the demo
run: build
	./mpc-tss

# Run all tests
test:
	go test -v -timeout 30m ./...

# Run tests in short mode (faster)
test-short:
	go test -v -short -timeout 10m ./...

# Run only the key generation test
test-keygen:
	go test -v -run TestKeyGeneration -timeout 10m ./...

# Run only the signing test
test-signing:
	go test -v -run TestSigning -timeout 10m ./...

# Run only the resharing test
test-resharing:
	go test -v -run TestResharing -timeout 15m ./...

# Run benchmarks
bench:
	go test -bench=. -benchtime=1x -timeout 30m ./...

# Clean build artifacts
clean:
	rm -f mpc-tss
	go clean -cache

# Format code
fmt:
	go fmt ./...

# Lint code
lint:
	go vet ./...

# Show help
help:
	@echo "Available targets:"
	@echo "  all         - Install dependencies and build"
	@echo "  deps        - Install dependencies"
	@echo "  build       - Build the binary"
	@echo "  run         - Build and run the demo"
	@echo "  test        - Run all tests"
	@echo "  test-short  - Run tests in short mode"
	@echo "  test-keygen - Run key generation test"
	@echo "  test-signing - Run signing test"
	@echo "  test-resharing - Run resharing test"
	@echo "  bench       - Run benchmarks"
	@echo "  clean       - Clean build artifacts"
	@echo "  fmt         - Format code"
	@echo "  lint        - Lint code"
