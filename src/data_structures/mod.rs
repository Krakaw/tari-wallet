//! Core data structures for lightweight wallets
//!
//! This module contains the essential data structures needed for
//! lightweight wallet operations, including UTXOs, transactions,
//! and cryptographic primitives.

pub mod types;
pub mod payment_id;
pub mod encrypted_data;
pub mod wallet_output;
pub mod transaction_output;
pub mod address;
pub mod transaction_input;
pub mod transaction_kernel;
pub mod transaction;
pub mod wallet_transaction;

#[cfg(test)]
pub mod serialization_tests;

pub use types::*;
pub use payment_id::*;
pub use encrypted_data::*;
pub use wallet_output::*;
pub use transaction_output::*;
pub use address::*;
pub use transaction_input::TransactionInput;
pub use transaction_kernel::TransactionKernel;
pub use transaction::*;
pub use wallet_transaction::*; 