//! Lightweight wallet libraries for Tari
//!
//! This crate provides lightweight wallet functionality for the Tari blockchain,
//! including UTXO management, transaction validation, and key management.

pub mod common;
pub mod crypto;
pub mod data_structures;
pub mod errors;
pub mod extraction;
pub mod hex_utils;
pub mod key_management;
#[cfg(any(feature = "grpc", feature = "http"))]
pub mod scanning;
#[cfg(feature = "storage")]
pub mod storage;
pub mod utils;
pub mod validation;
pub mod wallet;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
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
#[cfg(feature = "grpc")]
pub use scanning::*;
#[cfg(feature = "storage")]
pub use storage::*;
pub use validation::*;
pub use wallet::*;
