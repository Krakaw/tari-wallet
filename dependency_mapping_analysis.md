# Scanner Refactoring: Dependency Mapping Analysis

## Current Scanner Binary Dependencies (2,895 lines)

### Core Dependencies
**Scanner binary currently uses:**
- `clap` - CLI argument parsing (binary-only)
- `tokio` - Async runtime and signal handling (shared)
- `tari_utilities::ByteArray` - Utility functions (shared)
- `lightweight_wallet_libs::*` - Core library functionality (shared)

### Feature-Gated Dependencies

#### GRPC Feature (`feature = "grpc"`)
- `GrpcBlockchainScanner`, `GrpcScannerBuilder` - GRPC scanning (moves to library)
- `BlockchainScanner` trait - Core scanning interface (stays in library)
- All scanning logic and types (moves to library)

#### Storage Feature (`feature = "storage"`)
- `SqliteStorage`, `WalletStorage` - Database operations (moves to library)
- `StoredOutput`, `StoredWallet` - Storage data structures (moves to library)
- `OutputStatus` - Storage enums (moves to library)

#### Background Writer (`grpc + storage + !wasm32`)
- `tokio::sync::{mpsc, oneshot}` - Async communication (moves to library)
- Background database operations (moves to library)

## Dependency Split Plan

### Library Components (src/scanning/)
**Dependencies that move to library modules:**

#### Core Scanning (wallet_scanner.rs)
```rust
use lightweight_wallet_libs::{
    data_structures::{
        block::Block,
        payment_id::PaymentId,
        transaction::TransactionDirection,
        transaction_output::LightweightTransactionOutput,
        wallet_transaction::WalletState,
    },
    errors::{LightweightWalletResult, LightweightWalletError, KeyManagementError},
    key_management::{
        key_derivation,
        seed_phrase::{mnemonic_to_bytes, CipherSeed},
    },
    scanning::{BlockchainScanner, GrpcBlockchainScanner, GrpcScannerBuilder},
    wallet::Wallet,
};
use tari_utilities::ByteArray;
use tokio::time::Instant;
```

#### Configuration (scan_config.rs) 
```rust
use lightweight_wallet_libs::data_structures::types::PrivateKey;
use lightweight_wallet_libs::errors::LightweightWalletResult;
use std::str::FromStr;
```

#### Storage Management (storage_manager.rs)
```rust
#[cfg(feature = "storage")]
use lightweight_wallet_libs::storage::{
    WalletStorage, StoredOutput, StoredWallet, SqliteStorage, OutputStatus
};
use lightweight_wallet_libs::errors::LightweightWalletResult;
use super::background_writer::BackgroundWriter;
use super::scan_config::{ScanConfig, ScanContext};
```

#### Background Writer (background_writer.rs)
```rust
#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use lightweight_wallet_libs::storage::{WalletStorage, StoredOutput};
use lightweight_wallet_libs::data_structures::{
    types::CompressedCommitment,
    wallet_transaction::WalletTransaction,
};
use lightweight_wallet_libs::errors::LightweightWalletResult;
```

#### Progress Tracking (progress.rs)
```rust
use lightweight_wallet_libs::common::format_number;
use tokio::time::Instant;
use super::OutputFormat;
```

### Binary Components (src/bin/scanner.rs)
**Dependencies that stay in binary (~200 lines):**

```rust
use clap::Parser;
use lightweight_wallet_libs::scanning::*;  // Import library API
use tokio::signal;  // For Ctrl+C handling
```

## Feature Flag Strategy

### Library Module Gating
```rust
// In src/scanning/mod.rs
#[cfg(feature = "grpc")]
pub mod scan_config;

#[cfg(all(feature = "grpc", feature = "storage"))]
pub mod storage_manager;

#[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
pub mod background_writer;

#[cfg(feature = "grpc")]
pub mod wallet_scanner;

#[cfg(feature = "grpc")]
pub mod progress;
```

### Public API Exports
```rust
// Re-export scanner refactoring types
#[cfg(feature = "grpc")]
pub use scan_config::*;

#[cfg(feature = "grpc")]
pub use wallet_scanner::{WalletScanner, ScanResult};

#[cfg(all(feature = "grpc", feature = "storage"))]
pub use storage_manager::ScannerStorage;

#[cfg(feature = "grpc")]
pub use progress::ProgressTracker;
```

## Architecture Compatibility

### WASM32 Support
- Background writer disabled on WASM32: `not(target_arch = "wasm32")`
- Storage operations use sync API fallbacks on WASM32
- All crypto and scanning logic remains WASM32 compatible

### Platform-Specific Dependencies
- **Non-WASM32**: Full `tokio`, `rusqlite`, background operations
- **WASM32**: Web-compatible alternatives, sync-only storage

## Cargo.toml Requirements

### Binary Requirements
```toml
[[bin]]
name = "scanner"
required-features = ["grpc-storage"]  # No change needed
```

### Feature Definitions
```toml
[features]
grpc = ["rayon", "tonic", "prost", "async-trait", "tokio", "tracing", "tracing-subscriber"]
storage = ["rusqlite", "tokio-rusqlite", "async-trait", "tokio"]
grpc-storage = ["grpc", "storage"]  # No change needed
```

## Summary

**Library Gets:**
- All core scanning logic and types
- Configuration structures and parsing 
- Storage management and background operations
- Progress tracking utilities
- Public API with builder patterns

**Binary Keeps:**
- CLI argument parsing (`clap`)
- User interaction and prompts
- Output formatting and display
- Signal handling (Ctrl+C)
- Command-line specific error handling

**Result:**
- Binary reduces from 2,895 lines to ~200 lines
- All business logic moves to reusable library
- Feature flag compatibility maintained
- Platform-specific optimizations preserved
