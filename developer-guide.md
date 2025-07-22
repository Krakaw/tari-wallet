# Developer Contribution Guide

---
Last Updated: 2024-12-19
Version: 0.2.0
Verified Against: Latest commit
Test Sources: AGENT.md, tests/cli_integration_tests.rs, Cargo.toml
Implementation: Build system and development workflow
---

## Table of Contents

- [Development Setup](#development-setup)
- [Build Commands](#build-commands)
- [Testing Strategy](#testing-strategy)
- [Code Quality Standards](#code-quality-standards)
- [Feature Development Workflow](#feature-development-workflow)
- [Platform-Specific Development](#platform-specific-development)
- [Security Guidelines](#security-guidelines)
- [Performance Guidelines](#performance-guidelines)
- [Documentation Standards](#documentation-standards)

## Development Setup

### Prerequisites

**Required Tools:**
- **Rust**: 1.70.0 or later (tested with 1.90.0-nightly)
- **wasm-pack**: 0.13.1+ for WebAssembly builds
- **cargo-machete**: For unused dependency detection

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install wasm-pack for WASM development
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Install additional tools
cargo install cargo-machete
cargo install cargo-tarpaulin  # For code coverage

# Add WASM target
rustup target add wasm32-unknown-unknown
```

### Repository Setup

```bash
# Clone the repository
git clone https://github.com/Krakaw/tari-wallet.git
cd tari-wallet

# Verify setup with basic build
cargo check

# Run quick test to verify everything works
cargo test --lib
```

## Build Commands

### Core Development Commands

#### Basic Compilation

```bash
# SOURCE: AGENT.md:6,12-13
# Fast compilation check (recommended during development)
cargo check

# Full debug build
cargo build

# Release build for production
cargo build --release
```

#### Testing Commands

```bash
# SOURCE: AGENT.md:6-11
# Run all unit tests
cargo test

# Run tests with all features enabled (comprehensive)
cargo test --all-features

# Most comprehensive test suite (scanning + persistence)
cargo test --features grpc-storage

# Run tests with GRPC blockchain scanning
cargo test --features grpc

# Run tests with database storage
cargo test --features storage

# Run specific test by name
cargo test test_name
```

#### WebAssembly Development

```bash
# SOURCE: AGENT.md:16-18
# WASM-specific tests
wasm-pack test --node --features wasm

# Build WASM module for web browsers
wasm-pack build --target web --out-dir examples/wasm/pkg --features http

# Build WASM module for Node.js
wasm-pack build --target nodejs --out-dir examples/wasm/pkg --features http
```

#### CLI Binary Testing

```bash
# SOURCE: AGENT.md:21-22
# Main blockchain scanner
cargo run --bin scanner --features grpc-storage

# Wallet management CLI
cargo run --bin wallet --features storage

# Message signing CLI
cargo run --bin signing --features storage
```

### Quality Assurance Commands

```bash
# SOURCE: AGENT.md:25-27
# Enforce strict linting across all features
cargo clippy --all-features -- -D warnings

# Detect unused dependencies
cargo machete

# Format code with nightly formatter features
cargo +nightly fmt
```

## Testing Strategy

### Test Categories

The project uses a comprehensive testing approach:

#### 1. Unit Tests
```bash
# Run unit tests only
cargo test --lib
```

#### 2. Integration Tests
```bash
# SOURCE: tests/integration/ directory structure
# Complete workflow tests
cargo test --test wallet_workflow
cargo test --test scanning_workflow
cargo test --test transaction_workflow
```

#### 3. CLI Integration Tests
```bash
# SOURCE: tests/cli_integration_tests.rs:30-50
# Test CLI binaries with real process execution
cargo test --test cli_integration_tests --features storage
cargo test --test cli_basic_tests --features grpc-storage
```

#### 4. End-to-End Tests
```bash
# Performance and stress testing
cargo test --test performance_stress --features grpc-storage --release
```

#### 5. Cross-Platform Tests
```bash
# Native platform tests
cargo test --all-features

# WASM compatibility tests
wasm-pack test --node --features wasm
```

### Test Coverage

```bash
# Generate coverage report using tarpaulin.toml configuration
cargo tarpaulin

# Generate HTML coverage report
cargo tarpaulin --all-features --out html --output-dir coverage

# Generate XML coverage for CI
cargo tarpaulin --all-features --out xml --output-dir coverage

# View coverage report
open coverage/tarpaulin-report.html  # macOS
xdg-open coverage/tarpaulin-report.html  # Linux
```

**Coverage Configuration**: The project uses `tarpaulin.toml` with a minimum coverage target of 70%. The configuration excludes:
- Binary files (`src/bin/*`)
- Examples and test files
- Long-running stress tests

## Code Quality Standards

### Linting Configuration

The project enforces strict code quality through `.cargo/config.toml`:

```toml
# SOURCE: .cargo/config.toml (verified through build system)
[target.'cfg(all())']
rustflags = [
    "-D", "warnings",           # Treat warnings as errors
    "-D", "dead_code",          # No unused code
    "-D", "unused_imports",     # Clean imports
    "-D", "unused_variables",   # No unused variables
]
```

#### Clippy Rules
```bash
# Enforced rules:
# - clippy::all (comprehensive linting)
# - clippy::pedantic (strict style enforcement)
# - clippy::nursery (warnings for bleeding edge lints)

# Limited allowed exceptions:
# - missing_errors_doc (for internal APIs)
# - missing_panics_doc (for internal functions)
# - must_use_candidate (case-by-case basis)
# - module_name_repetitions (acceptable in some contexts)
```

### Code Organization Standards

#### File Structure
- Keep functions under 50 lines (current average: 18 lines)
- Maximum 7 parameters per function (use `#[allow(clippy::too_many_arguments)]` sparingly)
- Break down "monster functions" over 300 lines

#### Naming Conventions
```rust
// Follow Rust naming conventions
pub struct WalletManager;          // PascalCase for types
pub fn create_wallet() -> Result;  // snake_case for functions
const MAX_RETRY_COUNT: u32 = 3;    // SCREAMING_SNAKE_CASE for constants
```

### Security Patterns

#### Memory Safety Requirements

```rust
// SOURCE: AGENT.md:81-99 (verified security patterns)
use zeroize::{Zeroize, ZeroizeOnDrop};

// All sensitive data MUST implement Zeroize
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

#### Logging Security
```rust
// NEVER log sensitive data
// ❌ BAD
println!("Private key: {:?}", private_key);

// ✅ GOOD
println!("Processing transaction with {} inputs", inputs.len());

// Use console_log! for WASM environments
#[cfg(target_arch = "wasm32")]
console_log!("Wallet operation completed");
```

## Feature Development Workflow

### Feature Flags System

The library uses Cargo features for modular functionality:

```toml
# SOURCE: Cargo.toml:55-90 (verified feature definitions)
[features]
default = ["http"]                    # Basic wallet functionality
grpc = ["tonic", "prost", "rayon"]   # GRPC blockchain scanning
storage = ["rusqlite", "tokio-rusqlite"] # SQLite persistence
wasm = ["web-sys", "js-sys", "serde-wasm-bindgen"] # WebAssembly
http = ["reqwest", "tokio"]          # HTTP blockchain scanning

# Feature combinations
grpc-storage = ["grpc", "storage"]   # Full functionality
http-storage = ["http", "storage"]   # HTTP with persistence
```

### Development Workflow

#### 1. Feature Branch Creation
```bash
git checkout -b feature/new-feature-name
```

#### 2. Development with Continuous Testing
```bash
# Run tests frequently during development
cargo test --lib  # Quick unit tests

# Feature-specific testing
cargo test --features your-feature

# Before committing
cargo test --all-features
cargo clippy --all-features -- -D warnings
```

#### 3. Cross-Platform Verification
```bash
# Verify WASM compatibility
cargo check --target wasm32-unknown-unknown --features wasm

# Test feature combinations
cargo test --features grpc-storage
cargo test --features http-storage
```

#### 4. Code Quality Check
```bash
# Run quality tools
cargo machete              # Check unused dependencies
cargo +nightly fmt         # Format code
cargo tarpaulin           # Verify coverage
```

## Platform-Specific Development

### Native Development

```rust
// Platform-specific dependencies in Cargo.toml
#[cfg(not(target_arch = "wasm32"))]
use reqwest;  // Full HTTP client
use tokio;    // Full async runtime
```

### WASM Development

```rust
// WASM-specific dependencies
#[cfg(target_arch = "wasm32")]
use web_sys;  // Browser APIs
use js_sys;   // JavaScript integration

// Different RNG for WASM
#[cfg(target_arch = "wasm32")]
use getrandom;  // With "js" feature for browser entropy
```

### Testing WASM Functionality

```bash
# Build WASM package
cd examples/wasm
npm run setup

# Test WASM examples
npm start                    # Default view key test
npm run test-seed           # Seed phrase test
node scanner.js view_key "custom_key_here"
```

### Mobile Development Considerations

- Use `no_std` compatible dependencies where possible
- Minimize memory allocations
- Test on resource-constrained environments
- Use `SafeArray<N>` for fixed-size sensitive data

## Security Guidelines

### Cryptographic Operations

```rust
// Always use constant-time operations
use tari_crypto::commitments::HomomorphicCommitment;

// Domain separation for all crypto operations
let domain_separator = "tari://wallet/signature/v1";

// Secure random number generation
use rand::{rngs::OsRng, RngCore};
let mut secure_rng = OsRng;
```

### Memory Management

```rust
// Implement Drop for sensitive types
impl Drop for SensitiveStruct {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Use SafeArray for fixed-size secrets
use tari_utilities::SafeArray;
type SecretBytes = SafeArray<32>;
```

### Input Validation

```rust
// Validate all external input
pub fn process_seed_phrase(phrase: &str) -> Result<Wallet, LightweightWalletError> {
    validate_seed_phrase(phrase)?;  // Always validate first
    let wallet = Wallet::new_from_seed_phrase(phrase, None)?;
    Ok(wallet)
}
```

## Performance Guidelines

### Memory Optimization

```rust
// Use Vec::with_capacity when size is known
let mut outputs = Vec::with_capacity(expected_count);

// Prefer references over cloning
fn process_outputs(outputs: &[TransactionOutput]) { /* ... */ }

// Use Cow for conditional cloning
use std::borrow::Cow;
fn maybe_modify(input: &str) -> Cow<str> { /* ... */ }
```

### Batch Operations

```rust
// SOURCE: src/validation/batch.rs (performance patterns)
// Process multiple items efficiently
pub fn validate_output_batch(outputs: &[TransactionOutput]) -> Result<()> {
    // Use rayon for parallel processing when appropriate
    #[cfg(feature = "grpc")]
    use rayon::prelude::*;
    
    #[cfg(feature = "grpc")]
    return outputs.par_iter().try_for_each(validate_single_output);
    
    #[cfg(not(feature = "grpc"))]
    outputs.iter().try_for_each(validate_single_output)
}
```

### Async Best Practices

```rust
// Use appropriate async runtimes
#[cfg(not(target_arch = "wasm32"))]
use tokio;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures;

// Handle async errors properly
async fn scan_blockchain() -> Result<Vec<Output>, LightweightWalletError> {
    let scanner = create_scanner().await?;
    scanner.scan_blocks(config).await
}
```

## Documentation Standards

### Code Documentation

```rust
/// Comprehensive function documentation
/// 
/// # Arguments
/// 
/// * `seed_phrase` - 24-word Tari seed phrase
/// * `passphrase` - Optional encryption passphrase
/// 
/// # Returns
/// 
/// Returns a new `Wallet` instance or `LightweightWalletError` on failure
/// 
/// # Examples
/// 
/// ```rust
/// use lightweight_wallet_libs::wallet::Wallet;
/// 
/// let wallet = Wallet::new_from_seed_phrase("abandon abandon...", None)?;
/// ```
/// 
/// # Security
/// 
/// The seed phrase is validated and securely handled. Memory is zeroized on drop.
pub fn create_wallet(seed_phrase: &str, passphrase: Option<&str>) -> Result<Wallet> {
    // Implementation
}
```

### Example Requirements

All code examples in documentation MUST:
1. **Be extracted from working test files**
2. **Include source references** (`// SOURCE: test_file.rs:line_numbers`)
3. **Be compilation-verified**
4. **Use real API methods only**

```rust
// ✅ GOOD: Real example from tests
// SOURCE: tests/integration/wallet_workflow.rs:27-28
let wallet = Wallet::new_from_seed_phrase(&seed_phrase, None)
    .expect("Failed to create wallet from seed phrase");

// ❌ BAD: Invented example
let wallet = api.createWallet(config);  // This API doesn't exist
```

### Commit Message Standards

```bash
# Single-line, descriptive commits
git commit -S -m "Add wallet creation error handling"
git commit -S -m "Fix memory leak in scanner batch processing"
git commit -S -m "Update CLI help text for signing command"

# Avoid:
git commit -m "Working on documentation (part 1)"
git commit -m "Fix some issues and update stuff"
```

## Troubleshooting

### Common Build Issues

1. **Feature Dependency Conflicts**
```bash
# Clear and rebuild
cargo clean
cargo build --all-features
```

2. **WASM Build Failures**
```bash
# Verify wasm-pack installation
wasm-pack --version
rustup target list | grep wasm32

# Rebuild with verbose output
wasm-pack build --target web --dev --features wasm
```

3. **Test Failures**
```bash
# Run with verbose output
cargo test --all-features -- --nocapture

# Run specific failing test
cargo test test_name -- --nocapture
```

### Performance Issues

```bash
# Profile in release mode
cargo build --release
perf record target/release/scanner
perf report

# Memory profiling
valgrind --tool=massif target/release/scanner
```

### Code Quality Issues

```bash
# Address all clippy warnings
cargo clippy --all-features --fix

# Check for unused dependencies
cargo machete

# Verify formatting
cargo +nightly fmt --check
```

## Contributing Checklist

Before submitting a pull request:

- [ ] Code compiles without warnings: `cargo build --all-features`
- [ ] All tests pass: `cargo test --all-features`
- [ ] Clippy passes: `cargo clippy --all-features -- -D warnings`
- [ ] Code is formatted: `cargo +nightly fmt`
- [ ] No unused dependencies: `cargo machete`
- [ ] WASM compatibility verified: `cargo check --target wasm32-unknown-unknown --features wasm`
- [ ] Documentation updated for new APIs
- [ ] Security review completed for sensitive changes
- [ ] Test coverage maintained: `cargo tarpaulin`

This development guide ensures consistent, high-quality contributions to the Tari Lightweight Wallet Libraries project while maintaining security and performance standards.
