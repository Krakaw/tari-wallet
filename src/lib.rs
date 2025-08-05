//! Wallet libraries for Tari
//!
//! This crate provides wallet functionality for the Tari blockchain,
//! including UTXO management, transaction validation, and key management.
//!
//! ## Features
//!
//! This crate provides several optional features:
//!
//! - `storage`: Enables SQLite database storage for wallets and events
//! - `grpc`: Enables gRPC blockchain scanning with parallel processing  
//! - `http`: Enables HTTP blockchain scanning and web compatibility
//! - `wasm`: Enables WebAssembly compilation support
//!
//! ### Storage Feature
//!
//! The `storage` feature enables:
//! - SQLite database persistence for wallet data
//! - Event storage with append-only logging
//! - Database-backed event listeners
//! - Connection pooling and performance optimizations
//!
//! Enable it in your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! lightweight_wallet_libs = { version = "0.2", features = ["storage"] }
//! ```
//!
//! Without the `storage` feature, wallets operate in memory-only mode.

pub mod common;
pub mod crypto;
pub mod data_structures;
pub mod errors;
pub mod events;
pub mod extraction;
pub mod hex_utils;
pub mod key_management;
pub mod scanning;

pub mod storage;
pub mod utils;
pub mod validation;
pub mod wallet;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

// Include generated GRPC code when the feature is enabled
#[cfg(feature = "grpc")]
pub mod tari_rpc {
    tonic::include_proto!("tari.rpc");
}

pub use errors::*;
pub use extraction::*;
pub use hex_utils::*;
pub use key_management::*;
pub use scanning::*;

#[cfg(feature = "storage")]
pub use storage::*;
pub use validation::*;
pub use wallet::*;
