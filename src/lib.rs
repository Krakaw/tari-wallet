//! Wallet libraries for Tari
//!
//! This crate provides wallet functionality for the Tari blockchain,
//! including UTXO management, transaction validation, and key management.

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

pub use storage::*;
pub use validation::*;
pub use wallet::*;
