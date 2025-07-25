# Product Requirements Document: Node.js WASM Scanner

## Introduction/Overview

Create a Node.js-compatible WASM scanner that provides a thin JavaScript wrapper around the existing Rust blockchain scanning libraries. This scanner will enable blockchain scanning functionality in Node.js environments where Rust binaries are not available, serving as a foundation for future web-based implementations.

**Goal:** Enable Tari wallet blockchain scanning functionality in Node.js environments through a lightweight WASM interface that reuses existing Rust library components.

## Goals

1. **Portability**: Enable blockchain scanning in Node.js environments without requiring Rust binary compilation
2. **Reusability**: Create a thin wrapper that maximizes reuse of existing Rust library code
3. **Feature Parity**: Implement all scanner.rs functionality except storage (phase one limitation)
4. **Future-Ready**: Design architecture to support web browser deployment in phase two
5. **Developer Experience**: Provide familiar command-line interface matching the Rust scanner

## User Stories

1. **As a Node.js developer**, I want to scan the Tari blockchain for wallet outputs using JavaScript/TypeScript so that I can integrate scanning into my applications without Rust dependencies.

2. **As an exchange developer**, I want to use the same scanning functionality in Node.js as the Rust binary provides so that I can maintain consistency across different deployment environments.

3. **As a wallet integrator**, I want to scan specific block ranges using a view key in Node.js so that I can implement view-only wallet functionality.

4. **As a developer**, I want to scan from seed phrase in Node.js so that I can build full wallet applications that don't require native Rust compilation.

5. **As a system administrator**, I want command-line arguments that match the Rust scanner so that deployment scripts don't need modification between implementations.

## Functional Requirements

### Core Scanning Functionality
1. **The system must support seed phrase scanning mode** with automatic wallet birthday detection (matching scanner.rs behavior)
2. **The system must support view key scanning mode** with 64-character hex view keys (matching scanner.rs behavior)
3. **The system must support block range scanning** with `--from-block` and `--to-block` parameters
4. **The system must support specific block scanning** with comma-separated block heights via `--blocks` parameter
5. **The system must use HTTP blockchain scanning** exclusively (no GRPC support required)
6. **The system must output discovered UTXOs and transactions** in the same format as the Rust scanner

### Configuration & Interface
7. **The system must accept command-line arguments** identical to scanner.rs (excluding storage-related options)
8. **The system must support custom base node URL** configuration via `--base-url` parameter
9. **The system must provide batch size configuration** via `--batch-size` parameter (default: 10)
10. **The system must support progress update frequency** via `--progress-frequency` parameter (default: 10)
11. **The system must support quiet mode** via `--quiet` flag for minimal output
12. **The system must support output format selection** via `--format` parameter (detailed, summary, json)

### JavaScript API
13. **The system must expose a JavaScript API** that can be imported and used programmatically
14. **The system must provide the same scanning functions** as library calls, not just CLI
15. **The system must return JavaScript objects** for programmatic consumption of scan results
16. **The system must handle Node.js async/await patterns** for all scanning operations

### Error Handling
17. **The system must provide identical error handling** to the Rust scanner implementation
18. **The system must display specific block heights and error details** when HTTP errors occur
19. **The system must support graceful Ctrl+C interruption** with partial results preservation
20. **The system must offer interactive error recovery options** (Continue, Skip block, Abort)

### WASM Integration
21. **The system must use wasm-node feature** for Node.js compatibility
22. **The system must use http feature** for blockchain scanning (no GRPC dependency)
23. **The system must build with wasm-pack** targeting Node.js environment
24. **The system must handle WASM memory management** properly for long-running scans

## Non-Goals (Out of Scope)

1. **Storage functionality**: Phase one will not implement database storage (sqlite storage feature)
2. **GRPC scanning**: Only HTTP scanning will be supported initially
3. **Background writer service**: No persistent storage means no background writing needed
4. **Interactive wallet selection**: No database means no stored wallets to select from
5. **Resume functionality**: Without storage, scanning always starts fresh
6. **Web browser compatibility**: Phase one targets Node.js only (web support in phase two)

## Design Considerations

### File Structure
- **Location**: `examples/wasm/scanner.js`
- **Package structure**: Generated WASM package in `examples/wasm/pkg/`
- **Build target**: Node.js with `wasm-pack build --target nodejs`

### Command Line Interface
The CLI should mirror scanner.rs exactly, with these supported arguments:
```bash
node scanner.js --seed-phrase "your seed phrase here"
node scanner.js --view-key "64_char_hex" --from-block 1000 --to-block 2000
node scanner.js --seed-phrase "phrase" --blocks 1000,2000,5000
node scanner.js --view-key "key" --base-url "http://custom-node:18142"
node scanner.js --seed-phrase "phrase" --quiet --format json
```

### JavaScript API Design
```javascript
import { scan_with_seed_phrase, scan_with_view_key } from './pkg/scanner.js';

// API should expose the same functionality as CLI
const results = await scan_with_seed_phrase("seed phrase", {
  base_url: "http://127.0.0.1:18142",
  from_block: 1000,
  to_block: 2000,
  format: "json"
});
```

## Technical Considerations

### Dependencies
- **Build tool**: wasm-pack 0.13.1+
- **Target features**: `wasm`, `http` (not `grpc-storage`)
- **HTTP client**: web-sys Request/Response for WASM compatibility
- **Async runtime**: wasm-bindgen-futures for Promise handling

### Library Integration
- **Base implementation**: Reuse `src/scanning/http_scanner.rs` functionality
- **Wallet integration**: Use existing `Wallet` struct for key management
- **Output extraction**: Leverage existing `extraction` module for UTXO processing
- **Data structures**: Reuse all existing data structure definitions

### WASM-Specific Adaptations
- **Console output**: Use `console.log!` macro instead of `println!`
- **HTTP client**: Use web-sys instead of reqwest
- **Error handling**: Convert Rust errors to JavaScript exceptions appropriately
- **Memory management**: Ensure proper cleanup of WASM memory allocations

## Success Metrics

1. **Functional parity**: All non-storage scanner.rs functionality works identically in Node.js
2. **Performance**: WASM scanner completes scans within 20% of native Rust performance
3. **Compatibility**: Scanner runs on Node.js 16+ without additional native dependencies
4. **Developer adoption**: Can be used as drop-in replacement for environments where Rust binaries unavailable
5. **Build reliability**: wasm-pack build succeeds on all supported platforms (linux, macOS, Windows)

## Open Questions

1. **Memory limits**: Are there specific memory constraints for long blockchain scans in WASM?
2. **Progress reporting**: Should progress updates use Node.js streams or simple console output?
3. **Configuration**: Should we support environment variable configuration like the Rust version?
4. **Error serialization**: How should complex Rust error types be represented in JavaScript?
5. **Async patterns**: Should we use callbacks, Promises, or async iterators for progress updates?
6. **Testing strategy**: How should we test WASM functionality without duplicating all scanner.rs tests?

---

**Implementation Priority**: High
**Timeline**: Phase 1 implementation
**Dependencies**: Existing HTTP scanner and wallet libraries
**Risk Level**: Medium (WASM cross-compilation complexity)
