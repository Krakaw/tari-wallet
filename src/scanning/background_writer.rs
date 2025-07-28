//! Background database writer for non-WASM32 architectures.
//!
//! This module provides asynchronous database operations through a background
//! worker thread, improving scanning performance by decoupling database writes
//! from the main scanning loop.
//!
//! This module is part of the scanner.rs binary refactoring effort.

#[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
use tokio::sync::oneshot;
#[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
use crate::{
    data_structures::{
        types::CompressedCommitment,
        wallet_transaction::WalletTransaction,
    },
    errors::LightweightWalletResult,
    storage::StoredOutput,
};

/// Background writer commands for non-WASM32 architectures
///
/// These commands are sent through a channel to the background writer thread
/// to perform database operations asynchronously without blocking the main
/// scanning thread.
#[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
#[derive(Debug)]
pub enum BackgroundWriterCommand {
    /// Save wallet transactions to the database
    SaveTransactions {
        /// Wallet ID to associate transactions with
        wallet_id: u32,
        /// List of transactions to save
        transactions: Vec<WalletTransaction>,
        /// Response channel for operation result
        response_tx: oneshot::Sender<LightweightWalletResult<()>>,
    },
    /// Save outputs to the database
    SaveOutputs {
        /// List of outputs to save
        outputs: Vec<StoredOutput>,
        /// Response channel returning saved output IDs
        response_tx: oneshot::Sender<LightweightWalletResult<Vec<u32>>>,
    },
    /// Update the last scanned block height for a wallet
    UpdateWalletScannedBlock {
        /// Wallet ID to update
        wallet_id: u32,
        /// New block height that was scanned
        block_height: u64,
        /// Response channel for operation result
        response_tx: oneshot::Sender<LightweightWalletResult<()>>,
    },
    /// Mark a single transaction as spent
    MarkTransactionSpent {
        /// Commitment of the transaction to mark as spent
        commitment: CompressedCommitment,
        /// Block height where it was spent
        block_height: u64,
        /// Input index within the block
        input_index: usize,
        /// Response channel returning whether transaction was found and marked
        response_tx: oneshot::Sender<LightweightWalletResult<bool>>,
    },
    /// Mark multiple transactions as spent in a batch operation
    MarkTransactionsSpentBatch {
        /// List of commitments with their spending details (commitment, block_height, input_index)
        commitments: Vec<(CompressedCommitment, u64, usize)>,
        /// Response channel returning number of transactions marked as spent
        response_tx: oneshot::Sender<LightweightWalletResult<usize>>,
    },
    /// Shutdown the background writer thread
    Shutdown {
        /// Response channel to confirm shutdown completion
        response_tx: oneshot::Sender<()>,
    },
}

// TODO: Move BackgroundWriter struct and implementation from scanner.rs
