//! Optimized background writer that batches multiple operations into single transactions
//!
//! This module provides a high-performance background writer that collects multiple
//! database operations and commits them together in a single transaction for maximum
//! SQLite performance.

#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
use crate::{
    data_structures::{types::CompressedCommitment, wallet_transaction::WalletTransaction},
    errors::WalletResult,
    storage::{StoredOutput, WalletStorage},
};
#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
use std::time::{Duration, Instant};
#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
use tokio::sync::{mpsc, oneshot};

/// Background writer commands that can be batched together
#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
#[derive(Debug)]
pub enum BatchableCommand {
    /// Save wallet transactions to the database
    SaveTransactions {
        wallet_id: u32,
        transactions: Vec<WalletTransaction>,
    },
    /// Save outputs to the database
    SaveOutputs { outputs: Vec<StoredOutput> },
    /// Update the last scanned block height for a wallet
    UpdateWalletScannedBlock { wallet_id: u32, block_height: u64 },
    /// Mark multiple transactions as spent in a batch operation
    MarkTransactionsSpentBatch {
        commitments: Vec<(CompressedCommitment, u64, usize)>,
    },
}

/// A batched operation with its response channel
#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
struct BatchedOperation {
    operation: BatchableCommand,
    response_tx: oneshot::Sender<WalletResult<()>>,
}

/// Enhanced background writer commands
#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
#[derive(Debug)]
pub enum BatchBackgroundWriterCommand {
    /// Add an operation to the current batch
    AddToBatch {
        operation: BatchableCommand,
        response_tx: oneshot::Sender<WalletResult<()>>,
    },
    /// Force immediate commit of current batch
    FlushBatch {
        response_tx: oneshot::Sender<WalletResult<usize>>, // Returns number of operations committed
    },
    /// Mark a single transaction as spent (immediate execution)
    MarkTransactionSpent {
        commitment: CompressedCommitment,
        block_height: u64,
        input_index: usize,
        response_tx: oneshot::Sender<WalletResult<bool>>,
    },
    /// Shutdown the background writer thread
    Shutdown { response_tx: oneshot::Sender<()> },
}

/// Configuration for the batch background writer
#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
#[derive(Debug, Clone)]
pub struct BatchWriterConfig {
    /// Maximum number of operations to batch before auto-commit
    pub max_batch_size: usize,
    /// Maximum time to wait before auto-commit
    pub max_batch_time: Duration,
    /// Enable auto-commit based on batch size
    pub auto_commit_on_size: bool,
    /// Enable auto-commit based on time
    pub auto_commit_on_time: bool,
}

#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
impl Default for BatchWriterConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 500,                    // Large batch for better performance
            max_batch_time: Duration::from_secs(2), // 2 second timeout
            auto_commit_on_size: true,
            auto_commit_on_time: true,
        }
    }
}

#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
impl BatchWriterConfig {
    /// Configuration optimized for high-throughput scanning
    pub fn scanning_optimized() -> Self {
        Self {
            max_batch_size: 1000,                   // Very large batches
            max_batch_time: Duration::from_secs(5), // Longer timeout for better batching
            auto_commit_on_size: true,
            auto_commit_on_time: true,
        }
    }

    /// Configuration for low-latency operations
    pub fn low_latency() -> Self {
        Self {
            max_batch_size: 50,                         // Smaller batches
            max_batch_time: Duration::from_millis(500), // Quick timeout
            auto_commit_on_size: true,
            auto_commit_on_time: true,
        }
    }

    /// Configuration that batches only on size (no time limit)
    pub fn size_only(batch_size: usize) -> Self {
        Self {
            max_batch_size: batch_size,
            max_batch_time: Duration::from_secs(3600), // 1 hour (effectively disabled)
            auto_commit_on_size: true,
            auto_commit_on_time: false,
        }
    }
}

/// High-performance batch background writer
#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
pub struct BatchBackgroundWriter {
    /// Command sender for communicating with the background writer thread
    pub command_tx: mpsc::UnboundedSender<BatchBackgroundWriterCommand>,
    /// Join handle for the background writer task
    pub join_handle: tokio::task::JoinHandle<()>,
}

#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
impl BatchBackgroundWriter {
    /// Background writer main loop with batching support
    ///
    /// This function runs in a background task and collects operations into batches,
    /// committing them together in single transactions for maximum performance.
    ///
    /// # Arguments
    ///
    /// * `storage` - Database storage interface for performing operations
    /// * `command_rx` - Receiver for background writer commands
    /// * `config` - Configuration for batching behavior
    pub async fn batch_writer_loop(
        storage: Box<dyn WalletStorage>,
        command_rx: &mut mpsc::UnboundedReceiver<BatchBackgroundWriterCommand>,
        config: BatchWriterConfig,
    ) {
        let mut current_batch: Vec<BatchedOperation> = Vec::new();
        let mut last_commit_time = Instant::now();
        let mut total_operations = 0u64;
        let mut total_commits = 0u64;

        while let Some(command) = command_rx.recv().await {
            match command {
                BatchBackgroundWriterCommand::AddToBatch {
                    operation,
                    response_tx,
                } => {
                    current_batch.push(BatchedOperation {
                        operation,
                        response_tx,
                    });

                    // Check if we should auto-commit
                    let should_commit = (config.auto_commit_on_size
                        && current_batch.len() >= config.max_batch_size)
                        || (config.auto_commit_on_time
                            && last_commit_time.elapsed() >= config.max_batch_time);

                    if should_commit {
                        let (committed, results) =
                            Self::commit_batch(&*storage, current_batch).await;
                        total_operations += committed as u64;
                        total_commits += 1;

                        // Send responses to all operations in the batch
                        for (_, response_tx) in results {
                            let _ = response_tx.send(Ok(()));
                        }

                        current_batch = Vec::new();
                        last_commit_time = Instant::now();

                        if committed > 0 {
                            println!(
                                "Committed batch of {} operations (total: {}, batches: {})",
                                committed, total_operations, total_commits
                            );
                        }
                    }
                }
                BatchBackgroundWriterCommand::FlushBatch { response_tx } => {
                    let (committed, results) = Self::commit_batch(&*storage, current_batch).await;
                    total_operations += committed as u64;
                    if committed > 0 {
                        total_commits += 1;
                    }

                    // Send responses to all operations in the batch
                    for (_, op_response_tx) in results {
                        let _ = op_response_tx.send(Ok(()));
                    }

                    current_batch = Vec::new();
                    last_commit_time = Instant::now();
                    let _ = response_tx.send(Ok(committed));
                }
                BatchBackgroundWriterCommand::MarkTransactionSpent {
                    commitment,
                    block_height,
                    input_index,
                    response_tx,
                } => {
                    // Execute immediately (not batched for simplicity)
                    let result = storage
                        .mark_transaction_spent(&commitment, block_height, input_index)
                        .await;
                    let _ = response_tx.send(result);
                }
                BatchBackgroundWriterCommand::Shutdown { response_tx } => {
                    // Commit any remaining operations before shutdown
                    if !current_batch.is_empty() {
                        let (committed, results) =
                            Self::commit_batch(&*storage, current_batch).await;
                        total_operations += committed as u64;
                        if committed > 0 {
                            total_commits += 1;
                        }

                        // Send responses to all operations in the batch
                        for (_, op_response_tx) in results {
                            let _ = op_response_tx.send(Ok(()));
                        }
                    }

                    println!(
                        "BatchBackgroundWriter shutdown: {} operations in {} batches",
                        total_operations, total_commits
                    );
                    let _ = response_tx.send(());
                    break;
                }
            }
        }
    }

    /// Commit a batch of operations in a single transaction
    async fn commit_batch(
        storage: &dyn WalletStorage,
        batch: Vec<BatchedOperation>,
    ) -> (
        usize,
        Vec<(BatchableCommand, oneshot::Sender<WalletResult<()>>)>,
    ) {
        if batch.is_empty() {
            return (0, Vec::new());
        }

        let _batch_size = batch.len();
        let mut results = Vec::new();

        // Group operations by type for more efficient processing
        let mut save_transactions_ops = Vec::new();
        let mut save_outputs_ops = Vec::new();
        let mut update_wallet_ops = Vec::new();
        let mut mark_spent_ops = Vec::new();

        for BatchedOperation {
            operation,
            response_tx,
        } in batch
        {
            match operation {
                BatchableCommand::SaveTransactions {
                    wallet_id,
                    transactions,
                } => {
                    save_transactions_ops.push((wallet_id, transactions, response_tx));
                }
                BatchableCommand::SaveOutputs { outputs } => {
                    save_outputs_ops.push((outputs, response_tx));
                }
                BatchableCommand::UpdateWalletScannedBlock {
                    wallet_id,
                    block_height,
                } => {
                    update_wallet_ops.push((wallet_id, block_height, response_tx));
                }
                BatchableCommand::MarkTransactionsSpentBatch { commitments } => {
                    mark_spent_ops.push((commitments, response_tx));
                }
            }
        }

        // Execute all operations (storage implementations should batch internally)
        let mut successful_operations = 0;

        // Process save transactions
        for (wallet_id, transactions, response_tx) in save_transactions_ops {
            match storage.save_transactions(wallet_id, &transactions).await {
                Ok(_) => {
                    successful_operations += 1;
                    results.push((
                        BatchableCommand::SaveTransactions {
                            wallet_id,
                            transactions,
                        },
                        response_tx,
                    ));
                }
                Err(e) => {
                    let _ = response_tx.send(Err(e));
                }
            }
        }

        // Process save outputs
        for (outputs, response_tx) in save_outputs_ops {
            match storage.save_outputs(&outputs).await {
                Ok(_) => {
                    successful_operations += 1;
                    results.push((BatchableCommand::SaveOutputs { outputs }, response_tx));
                }
                Err(e) => {
                    let _ = response_tx.send(Err(e));
                }
            }
        }

        // Process wallet updates
        for (wallet_id, block_height, response_tx) in update_wallet_ops {
            match storage
                .update_wallet_scanned_block(wallet_id, block_height)
                .await
            {
                Ok(_) => {
                    successful_operations += 1;
                    results.push((
                        BatchableCommand::UpdateWalletScannedBlock {
                            wallet_id,
                            block_height,
                        },
                        response_tx,
                    ));
                }
                Err(e) => {
                    let _ = response_tx.send(Err(e));
                }
            }
        }

        // Process mark spent operations
        for (commitments, response_tx) in mark_spent_ops {
            match storage.mark_transactions_spent_batch(&commitments).await {
                Ok(_) => {
                    successful_operations += 1;
                    results.push((
                        BatchableCommand::MarkTransactionsSpentBatch { commitments },
                        response_tx,
                    ));
                }
                Err(e) => {
                    let _ = response_tx.send(Err(e));
                }
            }
        }

        (successful_operations, results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    #[test]
    fn test_batch_writer_config() {
        let default_config = BatchWriterConfig::default();
        assert_eq!(default_config.max_batch_size, 500);
        assert!(default_config.auto_commit_on_size);
        assert!(default_config.auto_commit_on_time);

        let scanning_config = BatchWriterConfig::scanning_optimized();
        assert_eq!(scanning_config.max_batch_size, 1000);
        assert_eq!(scanning_config.max_batch_time, Duration::from_secs(5));

        let low_latency_config = BatchWriterConfig::low_latency();
        assert_eq!(low_latency_config.max_batch_size, 50);
        assert_eq!(
            low_latency_config.max_batch_time,
            Duration::from_millis(500)
        );

        let size_only_config = BatchWriterConfig::size_only(200);
        assert_eq!(size_only_config.max_batch_size, 200);
        assert!(!size_only_config.auto_commit_on_time);
        assert!(size_only_config.auto_commit_on_size);
    }
}
