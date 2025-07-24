# Tari WASM Scanner - Build Documentation

This document describes how to build and use the WASM-based Tari wallet scanner for Node.js environments.

## Prerequisites

### Required Tools
- **Rust**: 1.70+ (tested with 1.90.0-nightly)
- **wasm-pack**: 0.13.1+ (`cargo install wasm-pack`)
- **Node.js**: 16.0+ (for CLI functionality)
- **npm**: Latest version

### Installation
```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install wasm-pack
cargo install wasm-pack

# Verify installations
rustc --version
wasm-pack --version
node --version
npm --version
```

## Quick Start

### 1. Complete Setup (Recommended)
```bash
# From repository root
make setup-wasm
```

This command will:
- Build the WASM package for Node.js
- Install all Node.js dependencies
- Verify the CLI is working

### 2. Manual Step-by-Step Build

#### Build WASM Package
```bash
# From repository root
make wasm-node
# OR manually:
# wasm-pack build --target nodejs --out-dir examples/wasm/pkg_node --features wasm-node
```

#### Install Node.js Dependencies
```bash
# From repository root
make install-wasm-deps
# OR manually:
# cd examples/wasm && npm install
```

## Available Make Targets

| Target | Description |
|--------|-------------|
| `setup-wasm` | Complete setup (build + install deps) |
| `wasm-node` | Build WASM for Node.js environment |
| `wasm-web` | Build WASM for browser environment |  
| `wasm-all` | Build both Node.js and web targets |
| `test-wasm` | Run WASM-specific unit tests |
| `test-cli` | Build and test the CLI |
| `install-wasm-deps` | Install Node.js dependencies |
| `clean` | Remove generated WASM packages |
| `clean-all` | Remove all generated files |
| `help` | Show detailed help with examples |

## Usage Examples

### Basic CLI Usage
```bash
cd examples/wasm

# Show help and available options
./scanner.js --help

# Scan with seed phrase (full wallet functionality)
./scanner.js --seed-phrase "your twelve word seed phrase goes here today"

# Scan with view key (view-only, 64 hex characters)
./scanner.js --view-key "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab"

# Scan specific block range
./scanner.js --view-key "your_view_key" --from-block 1000 --to-block 2000

# Scan specific blocks only
./scanner.js --seed-phrase "your seed phrase" --blocks 1000,2000,5000

# Use custom base node URL
./scanner.js --seed-phrase "your seed phrase" --base-url "http://192.168.1.100:18142"

# Quiet mode with JSON output
./scanner.js --view-key "your_view_key" --quiet --format json

# Batch processing with custom settings
./scanner.js --seed-phrase "your seed phrase" --batch-size 20 --progress-frequency 25
```

### Programmatic Usage (JavaScript API)
```javascript
import init, { 
    wasm_scan_with_seed_phrase, 
    wasm_scan_with_view_key,
    wasm_generate_seed_phrase,
    wasm_validate_seed_phrase 
} from './pkg_node/lightweight_wallet_libs.js';

// Initialize WASM module
await init();

// Generate and validate seed phrase
const seedPhrase = wasm_generate_seed_phrase();
const isValid = wasm_validate_seed_phrase(seedPhrase);

// Create scan configuration
const config = {
    base_url: "http://127.0.0.1:18142",
    from_block: 1000,
    to_block: 2000,
    batch_size: 10,
    progress_frequency: 10,
    quiet: false
};

// Progress callback
const progressCallback = (progress) => {
    console.log(`Progress: ${progress.percentage}% - Block ${progress.current_height}`);
};

// Scan with seed phrase
try {
    const results = await wasm_scan_with_seed_phrase(seedPhrase, config, progressCallback);
    console.log(`Found ${results.outputs_found} outputs, balance: ${results.total_balance}`);
} catch (error) {
    console.error('Scan failed:', error);
}
```

## Feature Flags

The WASM build uses these Cargo feature flags:

- **`wasm`**: Core WASM functionality with console error hooks
- **`wasm-node`**: Node.js-specific features (extends `wasm`)
- **`wasm-web`**: Browser-specific features (extends `wasm`)
- **`http`**: HTTP-based blockchain scanning
- **`console_error_panic_hook`**: Better panic messages in WASM

## Build Outputs

### Node.js Target (`make wasm-node`)
- **Output Directory**: `examples/wasm/pkg_node/`
- **Main Files**:
  - `lightweight_wallet_libs.js` - ES6 module exports
  - `lightweight_wallet_libs_bg.wasm` - WebAssembly binary
  - `package.json` - NPM package metadata

### Web Target (`make wasm-web`)
- **Output Directory**: `examples/wasm/pkg_web/`
- **Main Files**:
  - `lightweight_wallet_libs.js` - Web-compatible module
  - `lightweight_wallet_libs_bg.wasm` - WebAssembly binary
  - Browser-compatible bundler integration

## Troubleshooting

### Common Issues

#### 1. "wasm-pack not found"
```bash
cargo install wasm-pack
```

#### 2. "Module not found" errors in Node.js
```bash
# Ensure you built the Node.js target
make wasm-node

# Check that package.json has "type": "module"
cd examples/wasm && cat package.json | grep '"type"'
```

#### 3. Import/Export errors
- Ensure you're using ES6 import syntax with Node.js 16+
- Verify the WASM module is properly initialized with `await init()`

#### 4. Network connection errors
- Check that the base node URL is correct and accessible
- Verify the base node is running and accepting connections
- Try the default URL: `http://127.0.0.1:18142`

### Debug Mode
```bash
# Build with debug info
wasm-pack build --dev --target nodejs --out-dir examples/wasm/pkg_node --features wasm-node

# Run with debug logging
cd examples/wasm
DEBUG=* node scanner.js --help
```

### Performance Tips
- Use larger batch sizes (10-50) for better throughput
- Reduce progress frequency for faster scanning
- Use specific block ranges instead of full chain scans
- Consider using view keys for monitoring-only use cases

## Testing

### Unit Tests
```bash
# Run WASM-specific tests
make test-wasm

# Or manually
wasm-pack test --node --features wasm-node
```

### CLI Testing
```bash
# Build and test CLI functionality
make test-cli

# Manual CLI testing
cd examples/wasm
./scanner.js --help
./scanner.js --seed-phrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --from-block 1 --to-block 10
```

### Integration Testing
```bash
# Test with real seed phrase (be cautious with real keys)
cd examples/wasm
./scanner.js --seed-phrase "your test seed phrase"

# Test with view key
./scanner.js --view-key "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

## Development Workflow

1. **Make changes** to Rust code in `src/`
2. **Rebuild WASM**: `make wasm-node`
3. **Test changes**: `cd examples/wasm && ./scanner.js --help`
4. **Run tests**: `make test-wasm`
5. **Commit changes**

## Deployment

The generated WASM package can be published to NPM or distributed as a standalone CLI tool:

```bash
# Package for distribution
cd examples/wasm
npm pack

# Or publish to NPM (if configured)
npm publish
```
