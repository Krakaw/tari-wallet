.PHONY: wasm-node wasm-web wasm-all clean help

# Build WASM for Node.js environment
wasm-node:
	wasm-pack build --target nodejs --out-dir examples/wasm/pkg_node --features http,wasm-node

# Build WASM for web environment
wasm-web:
	wasm-pack build --target web --out-dir examples/wasm/pkg_web --features http,wasm-web

# Build both WASM targets
wasm-all: wasm-node wasm-web

# Clean generated WASM packages
clean:
	rm -rf examples/wasm/pkg_node
	rm -rf examples/wasm/pkg_web

# Show help
help:
	@echo "Available targets:"
	@echo "  wasm-node  - Build WASM for Node.js environment"
	@echo "  wasm-web   - Build WASM for web environment"
	@echo "  wasm-all   - Build both WASM targets"
	@echo "  clean      - Remove generated WASM packages"
	@echo "  help       - Show this help message"

# Default target
all: wasm-all 