# Tari Lightweight Wallet Libraries
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

A standalone, minimal dependency implementation of core Tari wallet functionality designed for lightweight applications, mobile wallets, web applications, and embedded systems.

## 🚀 **What is this?**

The Tari Lightweight Wallet Libraries provide essential wallet functionality extracted from the main Tari codebase, designed to be:

- **🪶 Lightweight**: Minimal dependencies, optimized for resource-constrained environments
- **🌐 Cross-platform**: Native Rust, WASM, mobile, and web compatibility
- **🔒 Secure**: Industry-standard cryptography with secure memory handling
- **🔧 Modular**: Use only the components you need
- **✅ Compatible**: 100% compatible with main Tari wallet key derivation and address generation

## 🎯 **Key Features**

### 💼 **Wallet Operations**
- ✅ Create wallets from seed phrases (24-word Tari CipherSeed format)
- ✅ Generate new wallets with cryptographically secure entropy
- ✅ Master key derivation following Tari specification
- ✅ Wallet metadata management and secure storage

### 🔑 **Key Management**
- ✅ BIP39-like mnemonic generation and validation (Tari format)
- ✅ Hierarchical deterministic key derivation
- ✅ View and spend key generation
- ✅ Stealth address support
- ✅ Secure key zeroization and memory protection

### 🏠 **Address Generation**
- ✅ Dual addresses (view + spend keys) for advanced features
- ✅ Single addresses (spend key only) for simplified use
- ✅ Multiple formats: Emoji 🦀, Base58, and Hex
- ✅ Payment ID embedding and extraction
- ✅ Network support (MainNet, StageNet, Esmeralda, LocalNet)

### 🔍 **Blockchain Scanning**
- ✅ GRPC-based blockchain scanning with Tari base nodes
- ✅ UTXO discovery and wallet output reconstruction
- ✅ Progress tracking and interactive error handling
- ✅ Batch processing with configurable block ranges
- ✅ Multiple scanning strategies (one-sided, recoverable, coinbase)
- ✅ Resume functionality for interrupted scans
- ✅ Multiple output formats (detailed, summary, JSON)

### 🔒 **Cryptographic Validation**
- ✅ Range proof validation and rewinding
- ✅ Encrypted data decryption using view keys
- ✅ Commitment validation and verification
- ✅ Payment ID extraction and decoding
- ✅ Stealth address key recovery

## 📦 **Installation**

Add to your `Cargo.toml`:

```toml
[dependencies]
lightweight_wallet_libs = "0.1"

# Optional features
lightweight_wallet_libs = { version = "0.1", features = ["wasm", "grpc"] }
```

### Feature Flags

- `default`: Core wallet functionality
- `wasm`: WASM compatibility and JavaScript bindings
- `grpc`: GRPC blockchain scanning support

## 🏗️ **Quick Start**

### Create a New Wallet

```rust
use lightweight_wallet_libs::wallet::Wallet;
use lightweight_wallet_libs::data_structures::address::TariAddressFeatures;

// Generate a new wallet with a 24-word seed phrase
let wallet = Wallet::generate_new_with_seed_phrase(None)?;

// Export the seed phrase for backup
let seed_phrase = wallet.export_seed_phrase()?;
println!("Backup this seed phrase: {}", seed_phrase);

// Generate a dual Tari address (supports both interactive and one-sided payments)
let features = TariAddressFeatures::create_interactive_and_one_sided();
let address = wallet.get_dual_address(features, None)?;

println!("Your Tari address (emoji): {}", address.to_emoji_string());
println!("Your Tari address (base58): {}", address.to_base58());

// Generate a single address (spend key only, simpler)
let single_features = TariAddressFeatures::create_one_sided_only();
let single_address = wallet.get_single_address(single_features)?;
println!("Single address: {}", single_address.to_base58());
```

### Restore Wallet from Seed Phrase

```rust
use lightweight_wallet_libs::wallet::Wallet;

// Restore wallet from existing seed phrase
let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
let wallet = Wallet::new_from_seed_phrase(seed_phrase, None)?;

// Generate the same address as before
let address = wallet.get_dual_address(
    TariAddressFeatures::create_interactive_and_one_sided(),
    None
)?;
```

### Key Management

```rust
use lightweight_wallet_libs::key_management::{
    generate_seed_phrase,
    validate_seed_phrase,
    seed_phrase::{CipherSeed, mnemonic_to_bytes},
};

// Generate a new 24-word seed phrase
let seed_phrase = generate_seed_phrase()?;
println!("Generated seed phrase: {}", seed_phrase);

// Validate an existing seed phrase
validate_seed_phrase(&seed_phrase)?;
println!("Seed phrase is valid!");

// Work with CipherSeed for advanced operations
let cipher_seed = CipherSeed::new(); // Creates with random entropy
let encrypted_bytes = cipher_seed.encipher(Some("optional_passphrase"))?;

// Convert bytes back to mnemonic
let encrypted_bytes = mnemonic_to_bytes(&seed_phrase)?;
let cipher_seed = CipherSeed::from_enciphered_bytes(&encrypted_bytes, Some("optional_passphrase"))?;
let entropy = cipher_seed.entropy();
println!("Extracted entropy: {:?}", entropy);
```

### Blockchain Scanning

```rust
use lightweight_wallet_libs::scanning::{GrpcScannerBuilder, BlockchainScanner};
use lightweight_wallet_libs::wallet::Wallet;

// Connect to a Tari base node
let mut scanner = GrpcScannerBuilder::new()
    .with_base_url("http://127.0.0.1:18142".to_string())
    .with_timeout(std::time::Duration::from_secs(30))
    .build().await?;

// Create wallet for scanning
let wallet = Wallet::new_from_seed_phrase("your seed phrase here", None)?;

// Get blockchain tip and scan from wallet birthday
let tip_info = scanner.get_tip_info().await?;
let from_block = wallet.birthday();
let to_block = tip_info.best_block_height;

// Scan specific block range
let block_info = scanner.get_block_by_height(12345).await?;
if let Some(block) = block_info {
    println!("Block {} has {} outputs", block.height, block.outputs.len());
}
```

### Advanced Blockchain Scanning

The scanner provides comprehensive blockchain analysis with multiple scanning modes:

```rust
// The scanner example demonstrates advanced features like:
// 
// 1. Seed phrase OR view key scanning
// cargo run --bin scanner --features grpc -- --seed-phrase "your seed phrase"
// cargo run --bin scanner --features grpc -- --view-key "64_char_hex_view_key"
//
// 2. Flexible block range scanning
// cargo run --bin scanner --features grpc -- --from-block 1000 --to-block 2000
// cargo run --bin scanner --features grpc -- --blocks 1000,1500,2000,2500
//
// 3. Multiple output formats
// cargo run --bin scanner --features grpc -- --format detailed  # Full transaction history
// cargo run --bin scanner --features grpc -- --format summary   # Compact overview  
// cargo run --bin scanner --features grpc -- --format json      # Machine-readable
//
// 4. Error recovery and resume functionality
// When errors occur, the scanner provides interactive options and resume commands
//
// 5. Progress tracking with real-time statistics
// Shows blocks/second, outputs found, balance changes, etc.
```

**Scanner Features:**
- **Dual Input Methods**: Use seed phrase (full wallet) or view key (view-only)  
- **Interactive Error Handling**: Continue, skip, or abort on GRPC errors with resume commands
- **Transaction History**: Complete chronological transaction listing with spent/unspent tracking
- **Payment ID Decoding**: Automatic extraction and UTF-8 decoding of payment IDs
- **Balance Analysis**: Running balances, net flow calculations, and transaction breakdowns
- **Maturity Tracking**: Coinbase output maturity detection and immature balance warnings

## 🏛️ **Architecture**

```
lightweight_wallet_libs/
├── wallet/           # Core wallet operations
├── key_management/   # Key derivation and mnemonics  
├── data_structures/  # Wallet data types
├── validation/       # Cryptographic validation
├── extraction/       # UTXO processing
├── scanning/         # Blockchain scanning
├── crypto/           # Independent crypto primitives
└── errors/           # Comprehensive error handling
```

### Core Components

- **`Wallet`**: Main wallet struct for key management and address generation
- **`CipherSeed`**: Tari's encrypted seed format with birthday tracking
- **`TariAddress`**: Dual and single address types with multiple encoding formats
- **`BlockchainScanner`**: GRPC-based scanning for wallet output discovery
- **`ValidationEngine`**: Cryptographic proof and signature validation

## 🌐 **Cross-Platform Support**

### Native Rust
```rust
// Standard Rust usage
let wallet = Wallet::generate_new_with_seed_phrase(None)?;
```

### WASM (Web Assembly)
```rust
// WASM-compatible with feature flag
#[cfg(target_arch = "wasm32")]
use lightweight_wallet_libs::wasm::*;
```

### Mobile Development
- Android: Use via JNI bindings
- iOS: Use via C FFI or Swift Package Manager
- React Native: Use via WASM bindings

## 🧪 **Examples**

Check out the [`examples/`](examples/) directory for complete working examples:

- [`wallet.rs`](examples/wallet.rs) - Complete wallet CLI with address generation
- [`scanner.rs`](examples/scanner.rs) - Advanced blockchain scanner with comprehensive features

Run examples:
```bash
# Create new wallet with seed phrase
cargo run --bin wallet new-wallet

# Generate address from existing seed phrase
cargo run --bin wallet new-address "your 24-word seed phrase here"

# Create wallet with payment ID and custom network
cargo run --bin wallet new-wallet --network stagenet --payment-id "my-payment-123"

# Comprehensive blockchain scanning (requires running Tari base node)
cargo run --bin scanner --features grpc -- --seed-phrase "your seed phrase"

# Scan specific block range with view key
cargo run --bin scanner --features grpc -- --view-key "your_64_char_hex_view_key" --from-block 1000 --to-block 2000

# Scan with multiple output formats
cargo run --bin scanner --features grpc -- --seed-phrase "your seed phrase" --format summary --quiet
```

## 🔒 **Security Features**

- **Secure Memory**: Automatic zeroization of sensitive data
- **Constant-time Operations**: Timing attack resistant comparisons
- **Domain Separation**: Cryptographic domain separation for security
- **Memory Safety**: Rust's memory safety guarantees
- **Secure Randomness**: Cryptographically secure random number generation

## ⚡ **Performance**

- **Batch Operations**: Optimized for processing multiple UTXOs
- **Parallel Processing**: Optional parallel validation (with `parallel` feature)
- **Memory Efficient**: Minimal memory footprint for mobile/embedded use
- **Fast Scanning**: Efficient blockchain scanning with progress tracking

## 🧰 **Use Cases**

### ✅ **Perfect For**
- 📱 Mobile wallet applications
- 🌐 Web wallets and browser extensions
- 🔧 Hardware wallet firmware
- 📡 Lightweight desktop applications
- 🚀 DeFi integrations requiring Tari addresses
- 🔍 Blockchain analysis tools

### ❌ **Not Suitable For**
- ⛏️ Running Tari base nodes
- 🏭 Mining operations
- 🌐 Peer-to-peer networking
- 💾 Full blockchain storage
- 🏛️ Consensus mechanisms

## 🆚 **vs. Main Tari Project**

| Feature | Main Tari | Lightweight Libs |
|---------|-----------|------------------|
| **Purpose** | Full blockchain protocol | Wallet functionality only |
| **Dependencies** | Heavy (tari-* crates) | Minimal (crypto only) |
| **Size** | ~100MB+ | ~5MB |
| **Platforms** | Desktop/Server | All platforms + WASM |
| **Use Case** | Run nodes/miners | Build wallet apps |

## 🤝 **Contributing**

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Krakaw/tari-wallet.git
cd tari-wallet

# Run tests
cargo test

# Run with all features
cargo test --all-features

# Check WASM compatibility
cargo check --target wasm32-unknown-unknown --features wasm
```

### Testing

```bash
# Unit tests
cargo test

# Integration tests with GRPC (requires base node)
cargo test --features grpc

# WASM tests
wasm-pack test --node --features wasm
```

## 📋 **Compatibility**

- **Rust**: 1.70.0 or later
- **WASM**: All major browsers
- **Mobile**: iOS 12+, Android API 21+
- **Tari**: Compatible with main Tari wallet key derivation

## 📄 **License**

This project is licensed under the [BSD 3-Clause License](LICENSE).
