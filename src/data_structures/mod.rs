//! Core data structures for wallets
//!
//! This module contains the essential data structures needed for
//! wallet operations, including UTXOs, transactions,
//! and cryptographic primitives.

pub mod address;
pub mod block;
pub mod encrypted_data;
pub mod payment_id;
pub mod transaction;
pub mod transaction_input;
pub mod transaction_kernel;
pub mod transaction_output;
pub mod types;
pub mod wallet_output;
pub mod wallet_transaction;

#[cfg(test)]
pub mod serialization_tests;

pub use address::*;
pub use block::{Block, BlockSummary};
pub use encrypted_data::*;
pub use payment_id::*;
pub use transaction::*;
pub use transaction_input::TransactionInput;
pub use transaction_kernel::TransactionKernel;
pub use transaction_output::*;
pub use types::*;
pub use wallet_output::*;
pub use wallet_transaction::*;
