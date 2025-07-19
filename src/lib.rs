//! Lightweight wallet libraries for Tari
//!
//! This crate provides lightweight wallet functionality for the Tari blockchain,
//! including UTXO management, transaction validation, and key management.

pub mod common;
pub mod crypto;
pub mod data_structures;
pub mod errors;
pub mod hex_utils;
pub mod validation;
pub mod extraction;
pub mod key_management;
#[cfg(any(feature = "grpc", feature = "http"))]
pub mod scanning;
#[cfg(feature = "storage")]
pub mod storage;
pub mod wallet;
pub mod utils;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

// Include WASM service modules when both WASM and HTTP features are available
#[cfg(all(target_arch = "wasm32", feature = "http"))]
pub mod wasm_service;

// Include generated GRPC code when the feature is enabled
#[cfg(feature = "grpc")]
pub mod tari_rpc {
    tonic::include_proto!("tari.rpc");
}

pub use errors::*;
pub use hex_utils::*;
pub use validation::*;
pub use extraction::*;
pub use key_management::*;
#[cfg(any(feature = "grpc", feature = "http"))]
pub use scanning::*;
#[cfg(feature = "storage")]
pub use storage::*;
pub use wallet::*; 