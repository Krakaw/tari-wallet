.PHONY: wasm-node wasm-web wasm-all test-wasm install-wasm-deps clean clean-all help

# Build WASM for Node.js environment (includes scanner CLI functionality)
wasm-node:
	@echo "Building WASM package for Node.js..."
	wasm-pack build --target nodejs --out-dir examples/wasm/pkg_node --features wasm-node
	@echo "WASM Node.js package built successfully in examples/wasm/pkg_node/"

# Build WASM for web environment (browser compatibility)
wasm-web:
	@echo "Building WASM package for web..."
	wasm-pack build --target web --out-dir examples/wasm/pkg_web --features wasm-web
	@echo "WASM web package built successfully in examples/wasm/pkg_web/"

# Build both WASM targets
wasm-all: wasm-node wasm-web

# Test WASM functionality
test-wasm:
	@echo "Running WASM-specific tests..."
	wasm-pack test --node --features wasm-node
	@echo "WASM tests completed successfully"

# Install Node.js dependencies for CLI
install-wasm-deps:
	@echo "Installing Node.js dependencies for WASM CLI..."
	cd examples/wasm && npm install
	@echo "Dependencies installed successfully"

# Setup complete WASM development environment
setup-wasm: wasm-node install-wasm-deps
	@echo "WASM development environment setup complete!"
	@echo "You can now run: cd examples/wasm && node scanner.js --help"

# Test the CLI after building
test-cli: wasm-node install-wasm-deps
	@echo "Testing WASM CLI..."
	cd examples/wasm && node scanner.js --help
	@echo "CLI test completed successfully"

# Clean generated WASM packages
clean:
	@echo "Cleaning WASM packages..."
	rm -rf examples/wasm/pkg_node
	rm -rf examples/wasm/pkg_web
	@echo "WASM packages cleaned"

# Clean everything including node_modules
clean-all: clean
	@echo "Cleaning all generated files..."
	rm -rf examples/wasm/node_modules
	rm -rf examples/wasm/package-lock.json
	@echo "All generated files cleaned"

# Show detailed help with examples
help:
	@echo "Tari Wallet WASM Build System"
	@echo "============================="
	@echo ""
	@echo "Available targets:"
	@echo "  wasm-node      - Build WASM for Node.js environment with scanner CLI"
	@echo "  wasm-web       - Build WASM for web environment (browser)"
	@echo "  wasm-all       - Build both WASM targets"
	@echo "  test-wasm      - Run WASM-specific unit tests"
	@echo "  install-wasm-deps - Install Node.js dependencies for CLI"
	@echo "  setup-wasm     - Complete setup (build + install deps)"
	@echo "  test-cli       - Build and test the Node.js CLI"
	@echo "  clean          - Remove generated WASM packages"
	@echo "  clean-all      - Remove all generated files including node_modules"
	@echo "  help           - Show this help message"
	@echo ""
	@echo "Quick Start:"
	@echo "  make setup-wasm              # Setup everything"
	@echo "  cd examples/wasm             # Enter CLI directory"
	@echo "  ./scanner.js --help          # Show CLI help"
	@echo ""
	@echo "CLI Usage Examples:"
	@echo "  ./scanner.js --seed-phrase \"your seed phrase here\""
	@echo "  ./scanner.js --view-key \"64char_hex_view_key\""
	@echo "  ./scanner.js --view-key \"key\" --from-block 1000 --to-block 2000"
	@echo ""
	@echo "Features used:"
	@echo "  wasm-node: wasm-node feature (Node.js environment)"
	@echo "  wasm-web:  wasm-web feature (browser environment)"

# Default target - setup everything for development
all: setup-wasm 