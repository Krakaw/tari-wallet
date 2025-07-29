# Tari Lightweight Wallet Libraries - Enhanced Agent Instructions

## Build/Test Commands

### Core Commands
- `cargo test` - Run all unit tests
- `cargo test --all-features` - Run tests with all features enabled
- `cargo test --features grpc-storage` - Most comprehensive test suite (scanning + persistence)
- `cargo test --features grpc` - Run tests with GRPC blockchain scanning
- `cargo test --features storage` - Run tests with database storage
- `cargo test test_name` - Run specific test by name
- `cargo check` - Fast compile check without building
- `cargo build --release` - Production build

### WASM Commands
- `wasm-pack test --node --features wasm` - WASM-specific tests
- `wasm-pack build --target web --out-dir examples/wasm/pkg --features http` - Build WASM module for web
- `wasm-pack build --target nodejs --out-dir examples/wasm/pkg --features http` - Build WASM module for node

### CLI Usage
- `cargo run --bin scanner --features grpc-storage` - Refactored blockchain scanner (now uses library API)
- `cargo run --bin wallet --features storage` - Wallet management CLI

### Scanner Binary (Refactored)
The scanner binary is now a lightweight wrapper around the scanning library:
- **~700 lines** of CLI-specific code (down from 2,895 lines)
- **Clean separation** between business logic (library) and UI (binary)
- **Full functionality preserved** while using the new library API
- **Better testability** with library components being unit-testable

### Quality & Dependencies
- `cargo clippy --all-features -- -D warnings` - Enforce strict linting across all features
- `cargo machete` - Detect unused dependencies (configured in Cargo.toml)
- `cargo +nightly fmt` - Format code with nightly formatter features

## Environment Setup

### Prerequisites
- **Rust**: 1.70+ (tested with 1.90.0-nightly)
- **Tools**: `wasm-pack` (0.13.1+), `cargo machete`
- **Platform**: Cross-platform (native + WASM)

### Dependencies
- **Tari ecosystem**: tari_crypto 0.22, tari_utilities 0.8, tari_script 1.0.0-rc.5
- **Crypto**: chacha20poly1305, curve25519-dalek, blake2
- **Platform-specific**: reqwest (native), web-sys (WASM)

## Architecture & Structure

### Libraries and Binaries
 - **Primary Focus** - This repository is primarily a library implementation. The binaries should always be lightweight wrappers around the library functionality.
 - **Scanner Refactoring** - The scanner binary has been successfully refactored from a 2,895-line monolith into a clean library-based architecture.
 
### Core Modules
- **wallet/**: Master keys, addresses, metadata management
- **key_management/**: Tari Index based key generation, seed phrases
- **data_structures/**: Addresses, transactions, outputs, encrypted data (13 modules)
- **validation/**: Range proofs, commitments, signatures, batch processing (9 modules)
- **scanning/**: Blockchain scanning library with refactored scanner components
  - `scan_config.rs`: Configuration structures for binary operations
  - `storage_manager.rs`: Storage abstraction layer (memory/database)
  - `background_writer.rs`: Async database operations (non-WASM32)
  - `wallet_scanner.rs`: Core scanning implementation and public API
  - `progress.rs`: Progress tracking utilities and display functions
  - `grpc_scanner.rs`: GRPC blockchain scanner implementation
  - `http_scanner.rs`: HTTP blockchain scanner implementation
- **extraction/**: UTXO processing and wallet output reconstruction
- **storage/**: Optional SQLite database support

### Feature Flags & Targets
- **Default**: `http` - Basic wallet functionality with HTTP scanning
- **grpc**: GRPC blockchain scanning with rayon parallel processing
- **storage**: SQLite persistence with async support
- **wasm**: WebAssembly compatibility with web-sys bindings
- **Combined**: `grpc-storage`, `http-storage` for full functionality



### Database Architecture
- **File**: `wallet.db` (SQLite)
- **Tables**: wallets, transactions, outputs, metadata
- **Features**: Async operations via tokio-rusqlite
- **Threading**: Connection pooling for concurrent access

## Security Patterns & Requirements

### Critical Security Practices (NON-NEGOTIABLE)
1. **Zeroize sensitive data**: All private keys, seed phrases, transaction components
2. **No secrets in logs**: Use `console_log!` in WASM, avoid Debug on sensitive types
3. **Real crypto validation**: Replace TODO stubs with actual verification
4. **Memory protection**: Use `SafeArray<N>` for fixed-size sensitive data
5. **Feature gating**: Security-critical code must not depend on optional features



### Zeroize Implementation Patterns
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct SensitiveData {
    private_key: PrivateKey,
    #[zeroize(skip)]  // Skip non-sensitive fields
    public_data: PublicKey,
}

// Manual implementation for complex types
impl Zeroize for Wallet {
    fn zeroize(&mut self) {
        self.master_key.zeroize();
        // Zeroize all sensitive fields
    }
}
```

## Code Quality Standards

### Linting Configuration (Enforced via .cargo/config.toml)
- **Enforced**: `clippy::all`, `clippy::pedantic`
- **Warnings**: `clippy::nursery`
- **Allowed exceptions**: missing_errors_doc, missing_panics_doc, must_use_candidate, module_name_repetitions
- **Dead code**: `-D dead_code`, `-D unused_imports`, `-D unused_variables`

### Complexity Thresholds
- **Max function length**: 50 lines (current avg: 18 lines)
- **Max parameters**: 7 (use `#[allow(clippy::too_many_arguments)]` sparingly)
- **Cyclomatic complexity**: Keep functions simple, extract helpers

### Current Quality Issues
- **Improved**: Reduced from 9 to 3 instances of `#[allow(clippy::too_many_arguments)]`
- **Limited dead code**: Only 2 functions in types.rs marked `#[allow(dead_code)]` remain
- **Monster functions**: Some test functions >300 lines

## Performance-Critical Code Paths



### Batch Validation Duplication
- **File**: `src/validation/batch.rs`
- **Issue**: `validate_output_batch` and `validate_output_batch_parallel` are copy-paste with only iterator changed
- **Fix needed**: Extract `validate_single_output` function

### Crypto Validation Performance
- **Range proofs**: BulletProofPlus verification is computationally expensive
- **Signature validation**: EdDSA signature checks in metadata validation
- **Batching opportunity**: Use rayon for parallel validation where cryptographically safe

## Error Handling Patterns

### Hierarchical Error Design
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LightweightWalletError {
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),
    
    #[error("Data structure error: {0}")]
    DataStructure(#[from] DataStructureError),
}
```

### Error Propagation
- Use `?` operator throughout
- Provide context with `map_err()` when crossing module boundaries
- Replace `unwrap()` with `expect("descriptive message")`

## Development Workflow Patterns

### Testing Strategy
- **Unit tests**: Per module in same file
- **Integration tests**: `tests/` directory for end-to-end workflows  
- **Feature tests**: Test feature flag combinations
- **WASM tests**: Use `wasm-bindgen-test` for browser/node compatibility

### CLI Testing Commands
```bash
# Test specific scanner scenarios
cargo run --bin scanner --features grpc-storage -- --seed-phrase "your seed phrase"
cargo run --bin scanner --features grpc-storage -- --view-key "64_char_hex" --from-block 1000

# Test wallet operations
cargo run --bin wallet --features storage generate
cargo run --bin wallet --features storage query balance
```

## Scanning Library Usage

### Basic Scanning API Examples

The refactored scanning library provides a clean API for blockchain scanning operations. Here are common usage patterns:

#### Basic Wallet Scanning
```rust
use lightweight_wallet_libs::scanning::{
    WalletScanner, BinaryScanConfig, ScanContext, ScannerStorage
};

// Create scanner with default configuration
let mut scanner = WalletScanner::new()
    .with_batch_size(20)
    .with_verbose_logging(true);

// Create scan context from wallet
let wallet = Wallet::generate_new_with_seed_phrase(None)?;
let scan_context = ScanContext::from_wallet(&wallet)?;

// Configure scanning parameters
let config = BinaryScanConfig::new(1000, 2000)
    .with_progress_frequency(10)
    .with_batch_size(50);

// Set up storage (memory or database)
let mut storage = ScannerStorage::new_memory();

// Perform the scan
let mut grpc_scanner = GrpcBlockchainScanner::new("http://localhost:18142".to_string()).await?;
let mut cancel_rx = tokio::sync::watch::channel(false).1;
let result = scanner.scan(&mut grpc_scanner, &scan_context, &config, &mut storage, &mut cancel_rx).await?;
```

#### Scanning with Progress Tracking
```rust
use lightweight_wallet_libs::scanning::{WalletScanner, ProgressInfo};

// Create scanner with progress callback
let mut scanner = WalletScanner::new()
    .with_progress_callback(|info: &ProgressInfo| {
        println!("Progress: {:.2}% ({}/{} blocks, {} outputs found)",
                 info.progress_percent,
                 info.blocks_processed,
                 info.total_blocks,
                 info.outputs_found);
    })
    .with_batch_size(25);

// Scanner will automatically report progress during scanning
```

#### Performance-Optimized Scanning
```rust
use lightweight_wallet_libs::scanning::WalletScanner;
use std::time::Duration;

// Create performance-optimized scanner
let mut scanner = WalletScanner::performance_optimized();

// Or customize for specific needs
let mut scanner = WalletScanner::new()
    .with_batch_size(100)
    .with_timeout(Duration::from_secs(60))
    .with_retry_config(RetryConfig::default().with_max_retries(3));
```

#### Database-Backed Scanning
```rust
use lightweight_wallet_libs::scanning::{ScannerStorage, BackgroundWriter};

// Create database-backed storage
let mut storage = ScannerStorage::new_with_database("wallet.db").await?;

// Storage automatically manages background writer for async operations
// Supports resume functionality from last scanned block
let result = scanner.scan(&mut grpc_scanner, &scan_context, &config, &mut storage, &mut cancel_rx).await?;
```

### Scanner Binary Integration

The refactored scanner binary demonstrates library usage:

#### Creating Scan Context
```rust
use lightweight_wallet_libs::scanning::{
    create_wallet_from_seed_phrase, 
    create_wallet_from_view_key
};

// From seed phrase (recommended)
let (scan_context, birthday) = create_wallet_from_seed_phrase("your 24 words...")?;

// From view key (view-only scanning)
let (scan_context, birthday) = create_wallet_from_view_key("9d84cc4795b509dadae90bd68b42f7d630a6a3d56281c0b5dd1c0ed36390e70a")?;
```

#### Configuration Patterns
```rust
use lightweight_wallet_libs::scanning::{BinaryScanConfig, OutputFormat};

// Range scanning
let config = BinaryScanConfig::new(from_block, to_block)
    .with_output_format(OutputFormat::Json)
    .with_quiet_mode(true)
    .with_database_path("scan_results.db");

// Specific block scanning
let config = BinaryScanConfig::new(0, 1000)
    .with_specific_blocks(vec![1500, 1501, 1502]);
```

### Error Handling Patterns

```rust
use lightweight_wallet_libs::scanning::{ScanResult, ScannerConfigError};

match scanner.scan(&mut grpc_scanner, &scan_context, &config, &mut storage, &mut cancel_rx).await {
    Ok(ScanResult::Completed(wallet_state, metadata)) => {
        println!("Scan completed successfully");
        if let Some(meta) = metadata {
            println!("Processed {} blocks", meta.blocks_processed);
        }
    }
    Ok(ScanResult::Interrupted(wallet_state, metadata)) => {
        println!("Scan was interrupted, can be resumed");
    }
    Err(e) => {
        eprintln!("Scan failed: {}", e);
    }
}
```

### Testing Patterns

```rust
#[cfg(test)]
mod scanning_tests {
    use super::*;
    use lightweight_wallet_libs::scanning::{MockBlockchainScanner, WalletScanner};

    #[tokio::test]
    async fn test_wallet_scanning_workflow() {
        // Use mock scanner for deterministic testing
        let mut mock_scanner = MockBlockchainScanner::new();
        mock_scanner.add_test_blocks(1000..2000);
        
        let mut scanner = WalletScanner::new().with_batch_size(10);
        let scan_context = create_test_scan_context();
        let config = BinaryScanConfig::new(1000, 2000);
        let mut storage = ScannerStorage::new_memory();
        let mut cancel_rx = tokio::sync::watch::channel(false).1;
        
        let result = scanner.scan(&mut mock_scanner, &scan_context, &config, &mut storage, &mut cancel_rx).await?;
        
        match result {
            ScanResult::Completed(wallet_state, _) => {
                assert!(!wallet_state.transactions.is_empty());
            }
            _ => panic!("Expected completed scan"),
        }
    }
}
```

### Debugging Performance Issues
```bash
# Profile memory usage
cargo build --release
valgrind --tool=massif target/release/scanner

# Profile CPU usage  
cargo build --release
perf record target/release/scanner
perf report
```

## Platform-Specific Considerations

### WASM Specifics
- **HTTP client**: Use web-sys instead of reqwest
- **Logging**: Use `console_log!` macro, not println!
- **Async**: wasm-bindgen-futures for Promise compatibility
- **RNG**: getrandom with "js" feature for browser entropy

### Native vs WASM Dependencies
```toml
# Native (full featured)
[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
reqwest = { version = "0.12", features = ["json", "stream"] }
tokio = { version = "1.0", features = ["full"] }

# WASM (browser compatible)  
[target.'cfg(target_arch = "wasm32")'.dependencies]
web-sys = { version = "0.3", features = ["console", "Request"] }
getrandom = { version = "0.2", features = ["js"] }
```

## Debugging & Troubleshooting

### Common Build Failures
1. **Feature flag issues**: Missing feature dependencies in Cargo.toml
2. **WASM build errors**: Missing web-sys features for browser APIs
3. **Crypto dependency conflicts**: Incompatible tari_crypto versions
4. **Circular dependency**: Compilation hangs due to module cycles

### Development Anti-Patterns (🚫 AVOID)
- **Code duplication**: 3.7% of codebase currently duplicated
- **Monolithic functions**: >50 line functions should be split
- **Feature coupling**: Don't make security depend on optional features

### Integration Testing Patterns
```rust
#[cfg(test)]
mod integration_tests {
    use crate::wallet::Wallet;
    
    #[tokio::test]
    async fn test_full_wallet_workflow() {
        let wallet = Wallet::generate_new_with_seed_phrase(None)?;
        let address = wallet.get_dual_address(features, None)?;
        // Test complete flow end-to-end
    }
}
```

## Technical Debt Priority

### Critical (Fix Immediately)
1. **Testing**: Break down monster test functions (16 hours)

### High Priority (Fix This Quarter)
1. **Duplication**: Extract duplicate primitives (20 hours)
2. **Validation**: Implement missing abstractions (20 hours)

### Maintenance Tasks
- **Weekly**: Run `cargo machete` to detect unused dependencies
- **Monthly**: Review complexity metrics and refactor >50 line functions
- **Quarterly**: Security audit of crypto validation implementation

## Memory Management

### Sensitive Data Lifecycle
1. **Creation**: Use secure random generation
2. **Processing**: Minimize lifetime, use references where possible
3. **Storage**: Encrypt at rest, use zeroize-compatible types
4. **Destruction**: Explicit zeroize before drop

### Performance Guidelines
- Use `Arc<T>` for shared read-only data
- Use `Cow<T>` for conditional cloning
- Prefer `&str` over `String` in function signatures
- Use `Vec::with_capacity()` when size is known

This enhanced AGENT.md provides comprehensive guidance for navigating the Tari Lightweight Wallet codebase efficiently while maintaining security and performance standards.
