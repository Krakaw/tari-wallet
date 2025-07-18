# Tari WASM Scanner Examples

This directory contains examples demonstrating how to use the Tari WASM Scanner in different environments, including both legacy and enhanced scanning functionality.

## Files

### Enhanced Scanning (NEW! 🚀)
- **`enhanced_scanner.js`** - Node.js example using lib's enhanced scanning functionality
- **`enhanced_scanner.html`** - Interactive browser example with progress bars and cancellation
- **`package.json`** - NPM configuration with enhanced build scripts

### Legacy Scanning  
- **`scanner.js`** - Original Node.js example (legacy)
- **`scanner.html`** - Original browser example (legacy)
- **`README.md`** - This documentation

## 🚀 Enhanced Scanner Features

The enhanced scanner brings the lib's advanced scanning functionality to WASM:

### ✨ Key Features
- **🎯 Real-time Progress Tracking** - Live progress bars with block/second rates
- **🛑 Cancellation Support** - WASM-compatible cancellation tokens  
- **💾 Memory-Only Storage** - No database dependencies, perfect for WASM
- **📊 Comprehensive Error Handling** - Interactive error recovery strategies
- **🔄 Batch Processing** - Configurable batch sizes for optimal performance
- **🌐 Cross-Platform** - Works in Node.js and browsers identically

### 🎨 Enhanced Examples

#### Interactive Browser Example
The `enhanced_scanner.html` provides a beautiful web interface featuring:
- Animated progress bars with real-time updates
- Interactive configuration forms
- Live statistics display
- Cancellation support via buttons or Ctrl+C
- Comprehensive result visualization

#### Node.js Command Line Example  
The `enhanced_scanner.js` provides a feature-rich CLI experience:
- Animated progress bars in terminal
- Real-time scanning statistics
- Graceful cancellation handling
- Auto-detection of input type (seed phrase vs view key)
- Comprehensive error reporting

## Quick Start

### 1. Prerequisites

Install the required tools:

```bash
# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Install the wasm32 target
rustup target add wasm32-unknown-unknown
```

### 2. Build the WASM Package

From this directory:

```bash
npm run setup
```

Or manually:

```bash
cd ../..
wasm-pack build --target nodejs --out-dir examples/wasm/pkg --example wasm_scanner
```

### 3. Run the Example

```bash
# Run with default view key
npm start

# Run with view key explicitly
npm run test

# Run with seed phrase
npm run test-seed

# Run with custom seed phrase
node scanner.js seed_phrase "your seed phrase here"

# Run with custom view key
node scanner.js view_key "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab"
```

## Example Output

When you run the example, you'll see:

```
🌟 Tari WASM Scanner - Node.js Example
=======================================
🚀 Initializing Tari WASM Scanner...
✅ WASM module loaded successfully
📊 Features enabled: none
🏷️  Version: 0.1.0

🔧 Creating scanner with view_key...
   Using view key: a1b2c3d4e5f6789abc...
✅ Scanner created successfully

🎯 FEATURE DEMONSTRATION
=========================

1. Testing View Key Scanner

🧪 Running scanner test...
✅ Test completed successfully
📊 Test result: { ... }

2. Testing Seed Phrase Scanner

🔧 Creating scanner with seed_phrase...
   Using seed phrase: abandon abandon aban...
✅ Scanner created successfully

... (continues with block scanning and performance tests)
```

## What the Example Demonstrates

The Node.js example showcases:

1. **Scanner Creation** - Both seed phrase and view key methods
2. **Block Scanning** - Processing multiple blocks with outputs and inputs
3. **Transaction Detection** - Finding wallet transactions in blockchain data
4. **State Management** - Tracking wallet balance and transaction history
5. **Error Handling** - Comprehensive error catching and reporting
6. **Performance Testing** - Basic benchmarking of scan operations
7. **Real-world Data** - Example blockchain data structures

## Example Blockchain Data

The example includes realistic test data:

- **3 blocks** with different transaction patterns
- **Multiple outputs** with encrypted data and commitments
- **Spending transactions** showing outputs being consumed
- **Proper hex formatting** for all cryptographic data

## Integration Tips

To integrate with real blockchain data:

1. **Fetch block data** from a Tari base node or explorer API
2. **Convert the data** to the format expected by the scanner
3. **Process blocks sequentially** to maintain transaction state
4. **Handle errors gracefully** for network or parsing issues

## Performance Notes

The example includes a basic performance test that shows:

- **Scan speed** per block
- **Memory usage** patterns
- **Reset performance** for state management

Typical performance (varies by hardware):
- **~1-10ms** per block scan (empty blocks)
- **~100-1000 scans/second** depending on block complexity
- **Minimal memory growth** due to WASM efficiency

## Troubleshooting

### "WASM module not found"

Run the build command:

```bash
npm run setup
```

### "Invalid scanner type"

Use either `"seed_phrase"` or `"view_key"` as the first argument.

### Node.js version issues

Ensure you're using Node.js 14.0.0 or later:

```bash
node --version
```

## Browser Usage

For browser usage, build with the web target:

```bash
wasm-pack build --target web --out-dir pkg --example wasm_scanner
```

Then use ES6 imports in your JavaScript:

```javascript
import init, { create_wasm_scanner } from './pkg/wasm_scanner.js';
await init();
```

## Next Steps

- Integrate with real blockchain APIs
- Add more sophisticated error handling
- Implement batch processing for large ranges
- Add progress tracking for long scans
- Create web-based examples 