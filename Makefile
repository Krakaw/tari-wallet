# Makefile for Tari Wallet - replicates CI workflow tests
.PHONY: help check format lint test test-all coverage security unused-deps setup-proto clean

# Default target
help:
	@echo "Available targets:"
	@echo "  setup-proto    - Download and setup protobuf files"
	@echo "  format         - Check code formatting"
	@echo "  lint           - Run clippy linting"
	@echo "  check          - Run format and lint checks"
	@echo "  test           - Run tests with default features"
	@echo "  test-all       - Run tests with all feature combinations"
	@echo "  coverage       - Generate test coverage report"
	@echo "  security       - Run security audit"
	@echo "  unused-deps    - Check for unused dependencies"
	@echo "  clean          - Clean build artifacts"

# Setup protobuf files (required for tests)
setup-proto:
	@echo "Checking for existing protobuf files..."
	@if [ -f "../tari/applications/minotari_app_grpc/proto/types.proto" ] && \
	     [ -f "../tari/applications/minotari_app_grpc/proto/transaction.proto" ] && \
	     [ -f "../tari/applications/minotari_app_grpc/proto/block.proto" ] && \
	     [ -f "../tari/applications/minotari_app_grpc/proto/network.proto" ] && \
	     [ -f "../tari/applications/minotari_app_grpc/proto/sidechain_types.proto" ] && \
	     [ -f "../tari/applications/minotari_app_grpc/proto/base_node.proto" ]; then \
		echo "Protobuf files already exist, skipping download..."; \
	else \
		echo "Setting up protobuf files..."; \
		mkdir -p ../tari/applications/minotari_app_grpc/proto; \
		cd ../tari/applications/minotari_app_grpc/proto && \
		curl -O https://raw.githubusercontent.com/tari-project/tari/refs/heads/development/applications/minotari_app_grpc/proto/types.proto && \
		curl -O https://raw.githubusercontent.com/tari-project/tari/refs/heads/development/applications/minotari_app_grpc/proto/transaction.proto && \
		curl -O https://raw.githubusercontent.com/tari-project/tari/refs/heads/development/applications/minotari_app_grpc/proto/block.proto && \
		curl -O https://raw.githubusercontent.com/tari-project/tari/refs/heads/development/applications/minotari_app_grpc/proto/network.proto && \
		curl -O https://raw.githubusercontent.com/tari-project/tari/refs/heads/development/applications/minotari_app_grpc/proto/sidechain_types.proto && \
		curl -O https://raw.githubusercontent.com/tari-project/tari/refs/heads/development/applications/minotari_app_grpc/proto/base_node.proto; \
	fi

# Check code formatting
format:
	@echo "Checking code formatting..."
	cargo fmt --all -- --check

# Run clippy linting
lint:
	@echo "Running clippy linting..."
	cargo clippy --all-targets --all-features -- -D warnings

# Run format and lint checks (equivalent to CI 'check' job)
check: format lint

# Common test flags to skip slow tests
TEST_SKIP_FLAGS := --skip test_large_scale_address_generation \
	--skip test_concurrent_wallet_operations \
	--skip test_concurrent_scanning_operations \
	--skip test_performance_degradation \
	--skip test_large_scale_wallet_generation \
	--skip test_memory_usage_stress \
	--skip test_large_dataset_scanning_performance

# Run tests with default features
test: setup-proto
	@echo "Running tests with default features..."
	cargo test -- $(TEST_SKIP_FLAGS)

# Run tests with all feature combinations (equivalent to CI 'test' job matrix)
test-all: setup-proto
	@echo "Running tests with no default features..."
	cargo test --no-default-features -- $(TEST_SKIP_FLAGS)
	@echo "Running tests with http features..."
	cargo test --features http -- $(TEST_SKIP_FLAGS)
	@echo "Running tests with grpc features..."
	cargo test --features grpc -- $(TEST_SKIP_FLAGS)
	@echo "Running tests with storage features..."
	cargo test --features storage -- $(TEST_SKIP_FLAGS)
	@echo "Running tests with grpc-storage features..."
	cargo test --features grpc-storage -- $(TEST_SKIP_FLAGS)
	@echo "Running tests with http-storage features..."
	cargo test --features http-storage -- $(TEST_SKIP_FLAGS)
	@echo "Running tests with all features..."
	cargo test --all-features -- $(TEST_SKIP_FLAGS)

# Generate test coverage (equivalent to CI 'coverage' job)
coverage: setup-proto
	@echo "Installing cargo-tarpaulin..."
	cargo install cargo-tarpaulin --quiet
	@echo "Generating test coverage..."
	cargo tarpaulin \
		--verbose \
		--all-features \
		--workspace \
		--timeout 120 \
		--exclude-files "src/bin/*" "examples/*" "tests/*" \
		--skip-clean \
		--out xml \
		--output-dir coverage \
		-- $(TEST_SKIP_FLAGS)
	@echo "Coverage report generated in coverage/cobertura.xml"

# Run security audit (equivalent to CI 'security' job)
security:
	@echo "Installing cargo-audit..."
	cargo install cargo-audit --quiet
	@echo "Running security audit..."
	cargo audit

# Check for unused dependencies (equivalent to CI 'unused-deps' job)
unused-deps:
	@echo "Installing cargo-machete..."
	cargo install cargo-machete --quiet
	@echo "Checking for unused dependencies..."
	cargo machete

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf coverage/

# Install required tools for development
install-tools:
	@echo "Installing development tools..."
	cargo install cargo-tarpaulin --quiet
	cargo install cargo-audit --quiet
	cargo install cargo-machete --quiet
	@echo "Development tools installed successfully" 
