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
/// asynchronously, significantly improving scanning performance by decoupling
/// database writes from the main scanning loop.
///
/// # Features
/// - **Asynchronous I/O**: Database operations run in a separate task
/// - **Command Queue**: Uses unbounded channels for reliable command delivery
/// - **Error Handling**: Each operation returns results via oneshot channels
/// - **Graceful Shutdown**: Supports clean termination of background operations
/// - **Sequential Processing**: Commands are processed in order for consistency
///
/// # Architecture
/// The background writer uses a command-based architecture where the main thread
/// sends `BackgroundWriterCommand` messages through an unbounded channel. The
/// background task processes these commands sequentially while maintaining
/// database consistency and transaction integrity.
///
/// # Platform Support
/// This component is only available on non-WASM32 architectures where full
/// threading and async I/O are supported. For WASM32 builds, database operations
/// are performed synchronously to maintain compatibility with browser limitations.
///
/// # Lifecycle
/// 1. **Creation**: Spawned by `ScannerStorage` when database mode is enabled
/// 2. **Operation**: Processes commands throughout the scanning operation
/// 3. **Shutdown**: Gracefully terminated when scanning completes or errors occur
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    use crate::data_structures::WalletState;
    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    use crate::storage::{OutputFilter, StorageStats, StoredWallet, TransactionFilter};
    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    use async_trait::async_trait;
    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    use std::sync::{Arc, Mutex};

    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    #[derive(Debug, Clone)]
    struct MockStorage {
        transactions_saved: Arc<Mutex<Vec<(u32, Vec<WalletTransaction>)>>>,
        outputs_saved: Arc<Mutex<Vec<Vec<StoredOutput>>>>,
        wallets_updated: Arc<Mutex<Vec<(u32, u64)>>>,
        transactions_marked: Arc<Mutex<Vec<(CompressedCommitment, u64, usize)>>>,
        batch_marked: Arc<Mutex<Vec<Vec<(CompressedCommitment, u64, usize)>>>>,
        should_fail: Arc<Mutex<bool>>,
    }

    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    impl MockStorage {
        fn new() -> Self {
            Self {
                transactions_saved: Arc::new(Mutex::new(Vec::new())),
                outputs_saved: Arc::new(Mutex::new(Vec::new())),
                wallets_updated: Arc::new(Mutex::new(Vec::new())),
                transactions_marked: Arc::new(Mutex::new(Vec::new())),
                batch_marked: Arc::new(Mutex::new(Vec::new())),
                should_fail: Arc::new(Mutex::new(false)),
            }
        }

        fn set_should_fail(&self, fail: bool) {
            *self.should_fail.lock().unwrap() = fail;
        }

        fn get_transactions_saved(&self) -> Vec<(u32, Vec<WalletTransaction>)> {
            self.transactions_saved.lock().unwrap().clone()
        }

        fn get_outputs_saved(&self) -> Vec<Vec<StoredOutput>> {
            self.outputs_saved.lock().unwrap().clone()
        }

        fn get_wallets_updated(&self) -> Vec<(u32, u64)> {
            self.wallets_updated.lock().unwrap().clone()
        }

        fn get_transactions_marked(&self) -> Vec<(CompressedCommitment, u64, usize)> {
            self.transactions_marked.lock().unwrap().clone()
        }

        fn get_batch_marked(&self) -> Vec<Vec<(CompressedCommitment, u64, usize)>> {
            self.batch_marked.lock().unwrap().clone()
        }
    }

    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    #[async_trait]
    impl WalletStorage for MockStorage {
        async fn initialize(&self) -> LightweightWalletResult<()> {
            if *self.should_fail.lock().unwrap() {
                Err(crate::errors::LightweightWalletError::StorageError(
                    "Mock failure".to_string(),
                ))
            } else {
                Ok(())
            }
        }

        async fn save_wallet(&self, _wallet: &StoredWallet) -> LightweightWalletResult<u32> {
            if *self.should_fail.lock().unwrap() {
                Err(crate::errors::LightweightWalletError::StorageError(
                    "Mock failure".to_string(),
                ))
            } else {
                Ok(1)
            }
        }

        async fn get_wallet_by_id(
            &self,
            _id: u32,
        ) -> LightweightWalletResult<Option<StoredWallet>> {
            if *self.should_fail.lock().unwrap() {
                Err(crate::errors::LightweightWalletError::StorageError(
                    "Mock failure".to_string(),
                ))
            } else {
                Ok(None)
            }
        }

        async fn get_wallet_by_name(
            &self,
            _name: &str,
        ) -> LightweightWalletResult<Option<StoredWallet>> {
            if *self.should_fail.lock().unwrap() {
                Err(crate::errors::LightweightWalletError::StorageError(
                    "Mock failure".to_string(),
                ))
            } else {
                Ok(None)
            }
        }

        async fn list_wallets(&self) -> LightweightWalletResult<Vec<StoredWallet>> {
            if *self.should_fail.lock().unwrap() {
                Err(crate::errors::LightweightWalletError::StorageError(
                    "Mock failure".to_string(),
                ))
            } else {
                Ok(Vec::new())
            }
        }

        async fn save_transactions(
            &self,
            wallet_id: u32,
            transactions: &[WalletTransaction],
        ) -> LightweightWalletResult<()> {
            if *self.should_fail.lock().unwrap() {
                Err(crate::errors::LightweightWalletError::StorageError(
                    "Mock failure".to_string(),
                ))
            } else {
                self.transactions_saved
                    .lock()
                    .unwrap()
                    .push((wallet_id, transactions.to_vec()));
                Ok(())
            }
        }

        async fn save_outputs(
            &self,
            outputs: &[StoredOutput],
        ) -> LightweightWalletResult<Vec<u32>> {
            if *self.should_fail.lock().unwrap() {
                Err(crate::errors::LightweightWalletError::StorageError(
                    "Mock failure".to_string(),
                ))
            } else {
                self.outputs_saved.lock().unwrap().push(outputs.to_vec());
                Ok((0..outputs.len()).map(|i| i as u32).collect())
            }
        }

        async fn get_unspent_outputs(
            &self,
            _wallet_id: u32,
        ) -> LightweightWalletResult<Vec<StoredOutput>> {
            if *self.should_fail.lock().unwrap() {
                Err(crate::errors::LightweightWalletError::StorageError(
                    "Mock failure".to_string(),
                ))
            } else {
                Ok(Vec::new())
            }
        }

        async fn update_wallet_scanned_block(
            &self,
            wallet_id: u32,
            block_height: u64,
        ) -> LightweightWalletResult<()> {
            if *self.should_fail.lock().unwrap() {
                Err(crate::errors::LightweightWalletError::StorageError(
                    "Mock failure".to_string(),
                ))
            } else {
                self.wallets_updated
                    .lock()
                    .unwrap()
                    .push((wallet_id, block_height));
                Ok(())
            }
        }

        async fn mark_transaction_spent(
            &self,
            commitment: &CompressedCommitment,
            block_height: u64,
            input_index: usize,
        ) -> LightweightWalletResult<bool> {
            if *self.should_fail.lock().unwrap() {
                Err(crate::errors::LightweightWalletError::StorageError(
                    "Mock failure".to_string(),
                ))
            } else {
                self.transactions_marked.lock().unwrap().push((
                    commitment.clone(),
                    block_height,
                    input_index,
                ));
                Ok(true)
            }
        }

        async fn mark_transactions_spent_batch(
            &self,
            commitments: &[(CompressedCommitment, u64, usize)],
        ) -> LightweightWalletResult<usize> {
            if *self.should_fail.lock().unwrap() {
                Err(crate::errors::LightweightWalletError::StorageError(
                    "Mock failure".to_string(),
                ))
            } else {
                self.batch_marked.lock().unwrap().push(commitments.to_vec());
                Ok(commitments.len())
            }
        }

        async fn get_wallet_statistics(
            &self,
            _wallet_id: Option<u32>,
        ) -> LightweightWalletResult<StorageStats> {
            if *self.should_fail.lock().unwrap() {
                Err(crate::errors::LightweightWalletError::StorageError(
                    "Mock failure".to_string(),
                ))
            } else {
                Ok(StorageStats {
                    total_transactions: 0,
                    inbound_count: 0,
                    outbound_count: 0,
                    unspent_count: 0,
                    spent_count: 0,
                    total_received: 0,
                    total_spent: 0,
                    current_balance: 0,
                    lowest_block: None,
                    highest_block: None,
                    latest_scanned_block: None,
                })
            }
        }

        // Minimal implementations for unused methods
        async fn delete_wallet(&self, _wallet_id: u32) -> LightweightWalletResult<bool> {
            Ok(false)
        }
        async fn wallet_name_exists(&self, _name: &str) -> LightweightWalletResult<bool> {
            Ok(false)
        }
        async fn save_transaction(
            &self,
            _wallet_id: u32,
            _transaction: &WalletTransaction,
        ) -> LightweightWalletResult<()> {
            Ok(())
        }
        async fn update_transaction(
            &self,
            _transaction: &WalletTransaction,
        ) -> LightweightWalletResult<()> {
            Ok(())
        }
        async fn get_transaction_by_commitment(
            &self,
            _commitment: &CompressedCommitment,
        ) -> LightweightWalletResult<Option<WalletTransaction>> {
            Ok(None)
        }
        async fn get_transactions(
            &self,
            _filter: Option<TransactionFilter>,
        ) -> LightweightWalletResult<Vec<WalletTransaction>> {
            Ok(Vec::new())
        }
        async fn load_wallet_state(&self, _wallet_id: u32) -> LightweightWalletResult<WalletState> {
            Ok(WalletState::new())
        }
        async fn get_statistics(&self) -> LightweightWalletResult<StorageStats> {
            Ok(StorageStats {
                total_transactions: 0,
                inbound_count: 0,
                outbound_count: 0,
                unspent_count: 0,
                spent_count: 0,
                total_received: 0,
                total_spent: 0,
                current_balance: 0,
                lowest_block: None,
                highest_block: None,
                latest_scanned_block: None,
            })
        }
        async fn get_transactions_by_block_range(
            &self,
            _from_block: u64,
            _to_block: u64,
        ) -> LightweightWalletResult<Vec<WalletTransaction>> {
            Ok(Vec::new())
        }
        async fn get_unspent_transactions(
            &self,
        ) -> LightweightWalletResult<Vec<WalletTransaction>> {
            Ok(Vec::new())
        }
        async fn get_spent_transactions(&self) -> LightweightWalletResult<Vec<WalletTransaction>> {
            Ok(Vec::new())
        }
        async fn has_commitment(
            &self,
            _commitment: &CompressedCommitment,
        ) -> LightweightWalletResult<bool> {
            Ok(false)
        }
        async fn get_highest_block(&self) -> LightweightWalletResult<Option<u64>> {
            Ok(None)
        }
        async fn get_lowest_block(&self) -> LightweightWalletResult<Option<u64>> {
            Ok(None)
        }
        async fn clear_all_transactions(&self) -> LightweightWalletResult<()> {
            Ok(())
        }
        async fn get_transaction_count(&self) -> LightweightWalletResult<usize> {
            Ok(0)
        }
        async fn close(&self) -> LightweightWalletResult<()> {
            Ok(())
        }
        async fn save_output(&self, _output: &StoredOutput) -> LightweightWalletResult<u32> {
            Ok(1)
        }
        async fn update_output(&self, _output: &StoredOutput) -> LightweightWalletResult<()> {
            Ok(())
        }
        async fn mark_output_spent(
            &self,
            _output_id: u32,
            _spent_in_tx_id: u64,
        ) -> LightweightWalletResult<()> {
            Ok(())
        }
        async fn get_output_by_id(
            &self,
            _output_id: u32,
        ) -> LightweightWalletResult<Option<StoredOutput>> {
            Ok(None)
        }
        async fn get_output_by_commitment(
            &self,
            _commitment: &[u8],
        ) -> LightweightWalletResult<Option<StoredOutput>> {
            Ok(None)
        }
        async fn get_outputs(
            &self,
            _filter: Option<OutputFilter>,
        ) -> LightweightWalletResult<Vec<StoredOutput>> {
            Ok(Vec::new())
        }
        async fn get_spendable_outputs(
            &self,
            _wallet_id: u32,
            _block_height: u64,
        ) -> LightweightWalletResult<Vec<StoredOutput>> {
            Ok(Vec::new())
        }
        async fn get_spendable_balance(
            &self,
            _wallet_id: u32,
            _block_height: u64,
        ) -> LightweightWalletResult<u64> {
            Ok(0)
        }
        async fn delete_output(&self, _output_id: u32) -> LightweightWalletResult<bool> {
            Ok(false)
        }
        async fn clear_outputs(&self, _wallet_id: u32) -> LightweightWalletResult<()> {
            Ok(())
        }
        async fn get_output_count(&self, _wallet_id: u32) -> LightweightWalletResult<usize> {
            Ok(0)
        }
    }

    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_background_writer_save_transactions_success() {
        let mock_storage = MockStorage::new();
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();

        // Spawn the background writer task
        let storage_clone = mock_storage.clone();
        let writer_task = tokio::spawn(async move {
            BackgroundWriter::background_writer_loop(Box::new(storage_clone), &mut command_rx)
                .await;
        });

        // Send a save transactions command
        let (response_tx, response_rx) = oneshot::channel();
        let wallet_id = 42;
        let transactions = vec![]; // Empty for simplicity

        command_tx
            .send(BackgroundWriterCommand::SaveTransactions {
                wallet_id,
                transactions: transactions.clone(),
                response_tx,
            })
            .unwrap();

        // Wait for response
        let result = response_rx.await.unwrap();
        assert!(result.is_ok());

        // Verify the transaction was recorded
        let saved = mock_storage.get_transactions_saved();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].0, wallet_id);

        // Shutdown the writer
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        command_tx
            .send(BackgroundWriterCommand::Shutdown {
                response_tx: shutdown_tx,
            })
            .unwrap();
        shutdown_rx.await.unwrap();
        writer_task.await.unwrap();
    }

    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_background_writer_save_transactions_failure() {
        let mock_storage = MockStorage::new();
        mock_storage.set_should_fail(true);
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();

        // Spawn the background writer task
        let storage_clone = mock_storage.clone();
        let writer_task = tokio::spawn(async move {
            BackgroundWriter::background_writer_loop(Box::new(storage_clone), &mut command_rx)
                .await;
        });

        // Send a save transactions command
        let (response_tx, response_rx) = oneshot::channel();

        command_tx
            .send(BackgroundWriterCommand::SaveTransactions {
                wallet_id: 42,
                transactions: vec![],
                response_tx,
            })
            .unwrap();

        // Wait for response
        let result = response_rx.await.unwrap();
        assert!(result.is_err());

        // Shutdown the writer
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        command_tx
            .send(BackgroundWriterCommand::Shutdown {
                response_tx: shutdown_tx,
            })
            .unwrap();
        shutdown_rx.await.unwrap();
        writer_task.await.unwrap();
    }

    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_background_writer_save_outputs_success() {
        let mock_storage = MockStorage::new();
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();

        // Spawn the background writer task
        let storage_clone = mock_storage.clone();
        let writer_task = tokio::spawn(async move {
            BackgroundWriter::background_writer_loop(Box::new(storage_clone), &mut command_rx)
                .await;
        });

        // Send a save outputs command
        let (response_tx, response_rx) = oneshot::channel();
        let outputs = vec![]; // Empty for simplicity

        command_tx
            .send(BackgroundWriterCommand::SaveOutputs {
                outputs: outputs.clone(),
                response_tx,
            })
            .unwrap();

        // Wait for response
        let result = response_rx.await.unwrap();
        assert!(result.is_ok());
        let output_ids = result.unwrap();
        assert!(output_ids.is_empty());

        // Verify the outputs were recorded
        let saved = mock_storage.get_outputs_saved();
        assert_eq!(saved.len(), 1);

        // Shutdown the writer
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        command_tx
            .send(BackgroundWriterCommand::Shutdown {
                response_tx: shutdown_tx,
            })
            .unwrap();
        shutdown_rx.await.unwrap();
        writer_task.await.unwrap();
    }

    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_background_writer_update_wallet_scanned_block() {
        let mock_storage = MockStorage::new();
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();

        // Spawn the background writer task
        let storage_clone = mock_storage.clone();
        let writer_task = tokio::spawn(async move {
            BackgroundWriter::background_writer_loop(Box::new(storage_clone), &mut command_rx)
                .await;
        });

        // Send an update wallet command
        let (response_tx, response_rx) = oneshot::channel();
        let wallet_id = 123;
        let block_height = 5000;

        command_tx
            .send(BackgroundWriterCommand::UpdateWalletScannedBlock {
                wallet_id,
                block_height,
                response_tx,
            })
            .unwrap();

        // Wait for response
        let result = response_rx.await.unwrap();
        assert!(result.is_ok());

        // Verify the wallet update was recorded
        let updated = mock_storage.get_wallets_updated();
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0], (wallet_id, block_height));

        // Shutdown the writer
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        command_tx
            .send(BackgroundWriterCommand::Shutdown {
                response_tx: shutdown_tx,
            })
            .unwrap();
        shutdown_rx.await.unwrap();
        writer_task.await.unwrap();
    }

    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_background_writer_mark_transaction_spent() {
        let mock_storage = MockStorage::new();
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();

        // Spawn the background writer task
        let storage_clone = mock_storage.clone();
        let writer_task = tokio::spawn(async move {
            BackgroundWriter::background_writer_loop(Box::new(storage_clone), &mut command_rx)
                .await;
        });

        // Send a mark transaction spent command
        let (response_tx, response_rx) = oneshot::channel();
        let commitment = CompressedCommitment::new([1u8; 32]);
        let block_height = 2000;
        let input_index = 5;

        command_tx
            .send(BackgroundWriterCommand::MarkTransactionSpent {
                commitment: commitment.clone(),
                block_height,
                input_index,
                response_tx,
            })
            .unwrap();

        // Wait for response
        let result = response_rx.await.unwrap();
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should return true from mock

        // Verify the transaction marking was recorded
        let marked = mock_storage.get_transactions_marked();
        assert_eq!(marked.len(), 1);
        assert_eq!(marked[0], (commitment, block_height, input_index));

        // Shutdown the writer
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        command_tx
            .send(BackgroundWriterCommand::Shutdown {
                response_tx: shutdown_tx,
            })
            .unwrap();
        shutdown_rx.await.unwrap();
        writer_task.await.unwrap();
    }

    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_background_writer_mark_transactions_spent_batch() {
        let mock_storage = MockStorage::new();
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();

        // Spawn the background writer task
        let storage_clone = mock_storage.clone();
        let writer_task = tokio::spawn(async move {
            BackgroundWriter::background_writer_loop(Box::new(storage_clone), &mut command_rx)
                .await;
        });

        // Send a batch mark command
        let (response_tx, response_rx) = oneshot::channel();
        let commitments = vec![
            (CompressedCommitment::new([1u8; 32]), 1000, 0),
            (CompressedCommitment::new([2u8; 32]), 1001, 1),
        ];

        command_tx
            .send(BackgroundWriterCommand::MarkTransactionsSpentBatch {
                commitments: commitments.clone(),
                response_tx,
            })
            .unwrap();

        // Wait for response
        let result = response_rx.await.unwrap();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2); // Should return count from mock

        // Verify the batch marking was recorded
        let batch_marked = mock_storage.get_batch_marked();
        assert_eq!(batch_marked.len(), 1);
        assert_eq!(batch_marked[0], commitments);

        // Shutdown the writer
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        command_tx
            .send(BackgroundWriterCommand::Shutdown {
                response_tx: shutdown_tx,
            })
            .unwrap();
        shutdown_rx.await.unwrap();
        writer_task.await.unwrap();
    }

    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_background_writer_shutdown() {
        let mock_storage = MockStorage::new();
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();

        // Spawn the background writer task
        let storage_clone = mock_storage.clone();
        let writer_task = tokio::spawn(async move {
            BackgroundWriter::background_writer_loop(Box::new(storage_clone), &mut command_rx)
                .await;
        });

        // Send shutdown command
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        command_tx
            .send(BackgroundWriterCommand::Shutdown {
                response_tx: shutdown_tx,
            })
            .unwrap();

        // Wait for shutdown confirmation
        shutdown_rx.await.unwrap();

        // Task should complete
        writer_task.await.unwrap();
    }

    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_background_writer_multiple_commands() {
        let mock_storage = MockStorage::new();
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();

        // Spawn the background writer task
        let storage_clone = mock_storage.clone();
        let writer_task = tokio::spawn(async move {
            BackgroundWriter::background_writer_loop(Box::new(storage_clone), &mut command_rx)
                .await;
        });

        // Send multiple commands
        let (tx1, rx1) = oneshot::channel();
        command_tx
            .send(BackgroundWriterCommand::SaveTransactions {
                wallet_id: 1,
                transactions: vec![],
                response_tx: tx1,
            })
            .unwrap();

        let (tx2, rx2) = oneshot::channel();
        command_tx
            .send(BackgroundWriterCommand::UpdateWalletScannedBlock {
                wallet_id: 1,
                block_height: 100,
                response_tx: tx2,
            })
            .unwrap();

        let (tx3, rx3) = oneshot::channel();
        command_tx
            .send(BackgroundWriterCommand::SaveOutputs {
                outputs: vec![],
                response_tx: tx3,
            })
            .unwrap();

        // Wait for all responses
        assert!(rx1.await.unwrap().is_ok());
        assert!(rx2.await.unwrap().is_ok());
        assert!(rx3.await.unwrap().is_ok());

        // Verify all operations were recorded
        assert_eq!(mock_storage.get_transactions_saved().len(), 1);
        assert_eq!(mock_storage.get_wallets_updated().len(), 1);
        assert_eq!(mock_storage.get_outputs_saved().len(), 1);

        // Shutdown the writer
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        command_tx
            .send(BackgroundWriterCommand::Shutdown {
                response_tx: shutdown_tx,
            })
            .unwrap();
        shutdown_rx.await.unwrap();
        writer_task.await.unwrap();
    }

    #[cfg(all(feature = "grpc", feature = "storage", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_background_writer_channel_closed() {
        let mock_storage = MockStorage::new();
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();

        // Spawn the background writer task
        let storage_clone = mock_storage.clone();
        let writer_task = tokio::spawn(async move {
            BackgroundWriter::background_writer_loop(Box::new(storage_clone), &mut command_rx)
                .await;
        });

        // Close the sender - this should cause the loop to exit
        drop(command_tx);

        // Task should complete when channel is closed
        writer_task.await.unwrap();
    }
}
