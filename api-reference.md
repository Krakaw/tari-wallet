# Tari Lightweight Wallet Libraries - API Reference

---
Last Updated: 2024-12-19
Version: 0.2.0
Verified Against: Latest commit
Test Sources: tests/integration/wallet_workflow.rs, tests/integration/scanning_workflow.rs, tests/cli_integration_tests.rs
Implementation: src/wallet/mod.rs, src/key_management/mod.rs, src/scanning/mod.rs, src/crypto/signing.rs
---

## Table of Contents

- [Core Wallet API](#core-wallet-api)
- [Key Management API](#key-management-api)
- [Address Generation API](#address-generation-api)
- [Blockchain Scanning API](#blockchain-scanning-api)
- [Message Signing API](#message-signing-api)
- [Storage API](#storage-api)
- [Error Handling](#error-handling)

## Core Wallet API

### Wallet Creation

#### `Wallet::generate_new_with_seed_phrase(passphrase: Option<&str>) -> Result<Wallet, LightweightWalletError>`

Creates a new wallet with a randomly generated 24-word seed phrase.

```rust
// SOURCE: tests/integration/wallet_workflow.rs:20-28
use lightweight_wallet_libs::wallet::Wallet;

let wallet = Wallet::generate_new_with_seed_phrase(None)
    .expect("Failed to generate new wallet");

// Verify wallet creation
assert!(wallet.birthday() > 0);
assert_eq!(wallet.current_key_index(), 0);
```

#### `Wallet::new_from_seed_phrase(seed_phrase: &str, passphrase: Option<&str>) -> Result<Wallet, LightweightWalletError>`

Creates a wallet from an existing 24-word seed phrase.

```rust
// SOURCE: tests/integration/wallet_workflow.rs:27-28
use lightweight_wallet_libs::key_management::generate_seed_phrase;
use lightweight_wallet_libs::wallet::Wallet;

let seed_phrase = generate_seed_phrase().expect("Failed to generate seed phrase");
let wallet = Wallet::new_from_seed_phrase(&seed_phrase, None)
    .expect("Failed to create wallet from seed phrase");

// Verify same seed phrase generates identical wallet
let exported_seed = wallet.export_seed_phrase()
    .expect("Failed to export seed phrase");
assert_eq!(exported_seed, seed_phrase);
```

### Wallet Properties

#### `Wallet::export_seed_phrase() -> Result<String, LightweightWalletError>`

Exports the wallet's seed phrase as a 24-word string.

```rust
// SOURCE: tests/integration/wallet_workflow.rs:37-40
let exported_seed = wallet.export_seed_phrase()
    .expect("Failed to export seed phrase");
assert_eq!(exported_seed.split_whitespace().count(), 24);
```

#### `Wallet::birthday() -> u64`

Returns the wallet's birthday (creation block height).

```rust
// SOURCE: tests/integration/wallet_workflow.rs:31
assert!(wallet.birthday() > 0);
```

#### `Wallet::current_key_index() -> u64`

Returns the current key derivation index.

```rust
// SOURCE: tests/integration/wallet_workflow.rs:32
assert_eq!(wallet.current_key_index(), 0);
```

#### `Wallet::network() -> &str`

Returns the wallet's configured network.

```rust
// SOURCE: tests/integration/wallet_workflow.rs:33-34, 44
assert_eq!(wallet.network(), ""); // Default empty network

// Set network
wallet.set_network("mainnet".to_string());
```

#### `Wallet::label() -> Option<&str>`

Returns the wallet's optional label.

```rust
// SOURCE: tests/integration/wallet_workflow.rs:34, 45
assert!(wallet.label().is_none()); // Default no label

// Set label
wallet.set_label(Some("Test Integration Wallet".to_string()));
```

## Address Generation API

### Address Types

The library supports two address types:
- **Dual Address**: Contains both view and spend keys (supports all transaction types)
- **Single Address**: Contains only spend key (simplified, interactive transactions only)

### `TariAddressFeatures`

Address feature configuration for different transaction types.

```rust
// SOURCE: tests/integration/wallet_workflow.rs:50-51, 68, 92
use lightweight_wallet_libs::data_structures::address::TariAddressFeatures;

// Create features for interactive and one-sided payments
let features = TariAddressFeatures::create_interactive_and_one_sided();

// Create features for interactive-only payments
let features = TariAddressFeatures::create_interactive_only();

// Create features for one-sided payments only
let features = TariAddressFeatures::create_one_sided_only();
```

### Dual Address Generation

#### `Wallet::get_dual_address(features: TariAddressFeatures, payment_id: Option<Vec<u8>>) -> Result<TariAddress, LightweightWalletError>`

Generates a dual address with both view and spend keys.

```rust
// SOURCE: tests/integration/wallet_workflow.rs:48-53
use lightweight_wallet_libs::data_structures::address::TariAddressFeatures;
use lightweight_wallet_libs::data_structures::{TariAddress, Network};

let dual_address = wallet.get_dual_address(
    TariAddressFeatures::create_interactive_and_one_sided(),
    None,
).expect("Failed to generate dual address");

// Verify dual address properties
assert!(matches!(dual_address, TariAddress::Dual(_)));
assert!(dual_address.public_view_key().is_some());
assert_eq!(dual_address.network(), Network::MainNet);
```

### Single Address Generation

#### `Wallet::get_single_address(features: TariAddressFeatures) -> Result<TariAddress, LightweightWalletError>`

Generates a single address with only a spend key.

```rust
// SOURCE: tests/integration/wallet_workflow.rs:67-70
let single_address = wallet.get_single_address(
    TariAddressFeatures::create_interactive_only()
).expect("Failed to generate single address");

// Verify single address properties
assert!(matches!(single_address, TariAddress::Single(_)));
assert!(single_address.public_view_key().is_none());
```

### Address with Payment ID

```rust
// SOURCE: tests/integration/wallet_workflow.rs:89-95
let payment_id = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
let address_with_payment = wallet.get_dual_address(
    TariAddressFeatures::create_interactive_only(),
    Some(payment_id.clone()),
).expect("Failed to generate address with payment ID");

// Verify payment ID is included
assert!(address_with_payment.features().contains(TariAddressFeatures::PAYMENT_ID));
```

### Address Format Methods

All address types support multiple encoding formats:

```rust
// Convert to different formats
let emoji_string = address.to_emoji_string();
let base58_string = address.to_base58();
let hex_string = address.to_hex();

// Network and feature inspection
let network = address.network();
let features = address.features();
let view_key = address.public_view_key(); // Some(key) for dual, None for single
```

## Key Management API

### Seed Phrase Operations

#### `generate_seed_phrase() -> Result<String, LightweightWalletError>`

Generates a new 24-word seed phrase with cryptographically secure randomness.

```rust
// SOURCE: tests/integration/wallet_workflow.rs:20
use lightweight_wallet_libs::key_management::generate_seed_phrase;

let seed_phrase = generate_seed_phrase().expect("Failed to generate seed phrase");
assert_eq!(seed_phrase.split_whitespace().count(), 24);
```

#### `validate_seed_phrase(seed_phrase: &str) -> Result<(), LightweightWalletError>`

Validates the format and checksum of a seed phrase.

```rust
// SOURCE: tests/integration/wallet_workflow.rs:23
use lightweight_wallet_libs::key_management::validate_seed_phrase;

validate_seed_phrase(&seed_phrase).expect("Generated seed phrase is invalid");
```

### CipherSeed Operations

For advanced seed phrase operations:

```rust
use lightweight_wallet_libs::key_management::seed_phrase::{CipherSeed, mnemonic_to_bytes};

// Create new CipherSeed with random entropy
let cipher_seed = CipherSeed::new();

// Encrypt with optional passphrase
let encrypted_bytes = cipher_seed.encipher(Some("optional_passphrase"))
    .expect("Failed to encrypt seed");

// Convert mnemonic to bytes
let seed_bytes = mnemonic_to_bytes(&seed_phrase)
    .expect("Failed to convert mnemonic to bytes");

// Recreate from encrypted bytes
let cipher_seed = CipherSeed::from_enciphered_bytes(&seed_bytes, Some("optional_passphrase"))
    .expect("Failed to decrypt seed");

// Extract entropy
let entropy = cipher_seed.entropy();
```

## Blockchain Scanning API

### Scanner Setup

#### `GrpcScannerBuilder`

Builder for creating GRPC blockchain scanners.

```rust
// SOURCE: README.md:205-208 (verified against src/scanning/mod.rs)
use lightweight_wallet_libs::scanning::{GrpcScannerBuilder, BlockchainScanner};
use std::time::Duration;

let mut scanner = GrpcScannerBuilder::new()
    .with_base_url("http://127.0.0.1:18142".to_string())
    .with_timeout(Duration::from_secs(30))
    .build().await
    .expect("Failed to build scanner");
```

### Scanner Operations

#### `BlockchainScanner::get_tip_info() -> Result<TipInfo, LightweightWalletError>`

Gets information about the blockchain tip.

```rust
// SOURCE: tests/integration/scanning_workflow.rs:73-80
let tip_info = scanner.get_tip_info().await
    .expect("Failed to get tip info");

// TipInfo contains:
// - best_block_height: u64
// - best_block_hash: Vec<u8>
// - accumulated_difficulty: Vec<u8>
// - pruned_height: u64
// - timestamp: u64
```

#### `BlockchainScanner::scan_blocks(config: ScanConfig) -> Result<Vec<BlockScanResult>, LightweightWalletError>`

Scans blocks for wallet outputs.

```rust
// SOURCE: tests/integration/scanning_workflow.rs:61-71
use lightweight_wallet_libs::scanning::ScanConfig;

let scan_results = scanner.scan_blocks(config).await
    .expect("Failed to scan blocks");

// Process scan results
for result in scan_results {
    println!("Block {}: {} outputs found", result.height, result.outputs.len());
}
```

### Scanning Configuration

```rust
// Create scan configuration
let config = ScanConfig {
    view_key: wallet.get_view_key(),
    from_height: wallet.birthday(),
    to_height: tip_info.best_block_height,
    scanning_keys: wallet.get_scanning_keys(),
};
```

## Message Signing API

### Key Derivation for Signing

#### `derive_tari_signing_key(seed_phrase: &str, passphrase: Option<&str>) -> Result<RistrettoSecretKey, LightweightWalletError>`

Derives the Tari communication signing key from a seed phrase (exactly as Tari wallet does).

```rust
// SOURCE: README.md:181-182 (verified against src/crypto/signing.rs)
use lightweight_wallet_libs::crypto::signing::derive_tari_signing_key;
use tari_crypto::keys::PublicKey;
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};

let tari_signing_key = derive_tari_signing_key(seed_phrase, None)
    .expect("Failed to derive signing key");
let tari_public_key = RistrettoPublicKey::from_secret_key(&tari_signing_key);
```

### Message Signing

#### `sign_message_with_hex_output(secret_key: &RistrettoSecretKey, message: &str) -> Result<(String, String), LightweightWalletError>`

Signs a message and returns hex-encoded signature and nonce.

```rust
// SOURCE: README.md:174 (verified against src/crypto/signing.rs)
use lightweight_wallet_libs::crypto::signing::sign_message_with_hex_output;
use tari_crypto::ristretto::RistrettoSecretKey;
use rand::rngs::OsRng;

let secret_key = RistrettoSecretKey::random(&mut OsRng);
let message = "Hello, Tari! This message is cryptographically signed.";
let (signature_hex, nonce_hex) = sign_message_with_hex_output(&secret_key, message)
    .expect("Failed to sign message");
```

#### `sign_message_with_tari_wallet(seed_phrase: &str, message: &str, passphrase: Option<&str>) -> Result<(String, String), LightweightWalletError>`

Signs a message using Tari wallet-compatible key derivation.

```rust
// SOURCE: README.md:185 (verified against src/crypto/signing.rs)
use lightweight_wallet_libs::crypto::signing::sign_message_with_tari_wallet;

let seed_phrase = "your 24-word seed phrase here...";
let message = "Hello, Tari! Signed with real wallet key.";

let (tari_sig_hex, tari_nonce_hex) = sign_message_with_tari_wallet(seed_phrase, message, None)
    .expect("Failed to sign with Tari wallet");
```

### Message Verification

#### `verify_message_from_hex(public_key: &RistrettoPublicKey, message: &str, signature_hex: &str, nonce_hex: &str) -> Result<bool, LightweightWalletError>`

Verifies a message signature from hex-encoded components.

```rust
// SOURCE: README.md:192 (verified against src/crypto/signing.rs)
use lightweight_wallet_libs::crypto::signing::verify_message_from_hex;

let is_valid = verify_message_from_hex(&tari_public_key, message, &tari_sig_hex, &tari_nonce_hex)
    .expect("Failed to verify signature");
assert!(is_valid);
```

## Storage API

*Requires the `storage` feature flag*

### Stored Wallet Operations

```rust
// SOURCE: tests/storage_connection_tests.rs (requires storage feature)
use lightweight_wallet_libs::storage::StoredWallet;
use tari_crypto::ristretto::RistrettoSecretKey;

// Create wallet from keys
let view_key = RistrettoSecretKey::random(&mut OsRng);
let spend_key = RistrettoSecretKey::random(&mut OsRng);
let stored_wallet = StoredWallet::from_keys(
    "my_wallet".to_string(),
    view_key,
    spend_key,
    12345, // birthday height
).expect("Failed to create stored wallet");

// Database operations (async)
stored_wallet.save_to_database(&db_connection).await
    .expect("Failed to save wallet");
```

## Error Handling

The library uses a comprehensive error hierarchy:

```rust
use lightweight_wallet_libs::errors::{LightweightWalletError, ValidationError};
use lightweight_wallet_libs::LightweightWalletResult;

// Type alias for convenience
type Result<T> = LightweightWalletResult<T>;

// Main error types
match wallet_operation() {
    Ok(result) => println!("Success: {:?}", result),
    Err(LightweightWalletError::Validation(e)) => {
        eprintln!("Validation error: {}", e);
    },
    Err(LightweightWalletError::DataStructure(e)) => {
        eprintln!("Data structure error: {}", e);
    },
    Err(e) => {
        eprintln!("Other error: {}", e);
    }
}
```

### Common Error Types

- `ValidationError`: Cryptographic validation failures
- `DataStructureError`: Invalid data format or structure
- `KeyManagementError`: Key derivation or management issues
- `ScanningError`: Blockchain scanning failures
- `StorageError`: Database operation failures (with storage feature)

## Feature Flags

Enable optional functionality with feature flags in `Cargo.toml`:

```toml
[dependencies]
lightweight_wallet_libs = { version = "0.2", features = ["grpc", "storage", "wasm"] }
```

### Available Features

- `default`: Basic wallet functionality with HTTP scanning
- `grpc`: GRPC blockchain scanning support
- `storage`: SQLite database persistence
- `wasm`: WebAssembly compatibility
- `http`: HTTP-based blockchain scanning (included in default)

### Feature Combinations

- `grpc-storage`: Full functionality with GRPC scanning and database storage
- `http-storage`: HTTP scanning with database storage
- `wasm`: Web browser compatibility

## Thread Safety and Async Support

The library supports both synchronous and asynchronous operations:

- Core wallet operations are synchronous
- Blockchain scanning operations are async (requires `tokio` runtime)
- Database operations are async when using the `storage` feature
- All types implement `Send` and `Sync` where appropriate for thread safety

## Security Considerations

- All sensitive data (private keys, seed phrases) implements `Zeroize` for secure memory clearing
- Cryptographic operations use constant-time implementations to prevent timing attacks
- Random number generation uses cryptographically secure sources
- Domain separation is used for all cryptographic operations to prevent signature reuse

For complete implementation details and advanced usage, see the source code and additional test files in the repository.
