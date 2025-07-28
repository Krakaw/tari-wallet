//! Background database writer for non-WASM32 architectures.
//!
//! This module provides asynchronous database operations through a background
//! worker thread, improving scanning performance by decoupling database writes
//! from the main scanning loop.
//!
//! This module is part of the scanner.rs binary refactoring effort.

#[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
use crate::{
    data_structures::{types::CompressedCommitment, wallet_transaction::WalletTransaction},
    errors::LightweightWalletResult,
    storage::{StoredOutput, WalletStorage},
};
#[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
use tokio::sync::{mpsc, oneshot};

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

/// Background writer service for non-WASM32 architectures
///
/// This struct manages a background thread for performing database operations
/// asynchronously, improving scanning performance by decoupling writes from
/// the main scanning loop.
#[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
pub struct BackgroundWriter {
    /// Command sender for communicating with the background writer thread
    pub command_tx: mpsc::UnboundedSender<BackgroundWriterCommand>,
    /// Join handle for the background writer task
    pub join_handle: tokio::task::JoinHandle<()>,
}

#[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
impl BackgroundWriter {
    /// Background writer main loop (non-WASM32 only)
    ///
    /// This function runs in a background task and processes commands from the
    /// command receiver. It handles all database operations asynchronously,
    /// including saving transactions, outputs, updating scan progress, and
    /// marking transactions as spent.
    ///
    /// # Arguments
    ///
    /// * `storage` - Database storage interface for performing operations
    /// * `command_rx` - Receiver for background writer commands
    pub async fn background_writer_loop(
        storage: Box<dyn WalletStorage>,
        command_rx: &mut mpsc::UnboundedReceiver<BackgroundWriterCommand>,
    ) {
        while let Some(command) = command_rx.recv().await {
            match command {
                BackgroundWriterCommand::SaveTransactions {
                    wallet_id,
                    transactions,
                    response_tx,
                } => {
                    let result = storage.save_transactions(wallet_id, &transactions).await;
                    let _ = response_tx.send(result);
                }
                BackgroundWriterCommand::SaveOutputs {
                    outputs,
                    response_tx,
                } => {
                    let result = storage.save_outputs(&outputs).await;
                    let _ = response_tx.send(result);
                }
                BackgroundWriterCommand::UpdateWalletScannedBlock {
                    wallet_id,
                    block_height,
                    response_tx,
                } => {
                    let result = storage
                        .update_wallet_scanned_block(wallet_id, block_height)
                        .await;
                    let _ = response_tx.send(result);
                }
                BackgroundWriterCommand::MarkTransactionSpent {
                    commitment,
                    block_height,
                    input_index,
                    response_tx,
                } => {
                    let result = storage
                        .mark_transaction_spent(&commitment, block_height, input_index)
                        .await;
                    let _ = response_tx.send(result);
                }
                BackgroundWriterCommand::MarkTransactionsSpentBatch {
                    commitments,
                    response_tx,
                } => {
                    let result = storage.mark_transactions_spent_batch(&commitments).await;
                    let _ = response_tx.send(result);
                }
                BackgroundWriterCommand::Shutdown { response_tx } => {
                    let _ = response_tx.send(());
                    break;
                }
            }
        }
    }
}
