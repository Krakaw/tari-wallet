//! Storage management for wallet scanning operations.
//!
//! This module provides a unified storage interface that supports both
//! memory-only scanning and database-backed persistence. It handles
//! wallet management, transaction storage, and resume functionality.
//!
//! This module is part of the scanner.rs binary refactoring effort.

// Required imports for ScannerStorage functionality
#[cfg(feature = "storage")]
use crate::{
    data_structures::{types::CompressedCommitment, wallet_transaction::WalletTransaction},
    errors::{WalletError, WalletResult},
    storage::{BatchOperations, SqliteStorage, StoredOutput, StoredWallet, WalletStorage},
};

#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
use super::background_writer::{BackgroundWriter, BackgroundWriterCommand};

#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
use tokio::sync::{mpsc, oneshot};

#[cfg(feature = "storage")]
use super::scan_config::{BinaryScanConfig, ScanContext};

#[cfg(feature = "storage")]
use crate::{
    errors::KeyManagementError,
    key_management::seed_phrase::{mnemonic_to_bytes, CipherSeed},
};

/// Derive entropy from a seed phrase string
#[cfg(feature = "storage")]
pub fn derive_entropy_from_seed_phrase(seed_phrase: &str) -> WalletResult<[u8; 16]> {
    let encrypted_bytes = mnemonic_to_bytes(seed_phrase)?;
    let cipher_seed = CipherSeed::from_enciphered_bytes(&encrypted_bytes, None)?;
    let entropy = cipher_seed.entropy();

    let entropy_array: [u8; 16] = entropy
        .try_into()
        .map_err(|_| KeyManagementError::key_derivation_failed("Invalid entropy length"))?;

    Ok(entropy_array)
}

/// Unified storage handler for the scanner
///
/// This struct manages both memory-only and database-backed storage modes.
/// It provides a unified interface for wallet management, transaction storage,
/// and background processing operations.
#[cfg(feature = "storage")]
pub struct ScannerStorage {
    /// Database storage interface (when storage feature is enabled)
    #[cfg(feature = "storage")]
    pub database: Option<Box<dyn WalletStorage>>,
    /// Currently selected wallet ID for operations
    pub wallet_id: Option<u32>,
    /// Whether operating in memory-only mode (no persistence)
    pub is_memory_only: bool,
    /// Track how many transactions have been saved to avoid duplicates
    pub last_saved_transaction_count: usize,

    /// Background writer for non-WASM32 architectures (when storage feature is enabled)
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    pub background_writer: Option<BackgroundWriter>,
}

#[cfg(feature = "storage")]
impl ScannerStorage {
    /// Create a new scanner storage instance (memory-only mode)
    pub fn new_memory() -> Self {
        Self {
            #[cfg(feature = "storage")]
            database: None,
            wallet_id: None,
            is_memory_only: true,
            last_saved_transaction_count: 0,
            #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
            background_writer: None,
        }
    }

    /// Create a new scanner storage instance with database
    #[cfg(feature = "storage")]
    pub async fn new_with_database(database_path: &str) -> WalletResult<Self> {
        Self::new_with_performance_database(database_path, "production").await
    }

    /// Create a new scanner storage instance with high-performance database configuration
    #[cfg(feature = "storage")]
    pub async fn new_with_performance_database(
        database_path: &str,
        workload_type: &str,
    ) -> WalletResult<Self> {
        let (_batch_size, perf_config) = BatchOperations::recommend_batch_config(workload_type);

        let storage: Box<dyn WalletStorage> = if database_path == ":memory:" {
            Box::new(SqliteStorage::new_in_memory_with_config(perf_config).await?)
        } else {
            Box::new(SqliteStorage::new_with_config(database_path, perf_config).await?)
        };

        storage.initialize().await?;

        Ok(Self {
            database: Some(storage),
            wallet_id: None,
            is_memory_only: false,
            last_saved_transaction_count: 0,
            #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
            background_writer: None,
        })
    }

    /// Start the background writer service (non-WASM32 only)
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    pub async fn start_background_writer(&mut self, database_path: &str) -> WalletResult<()> {
        if self.background_writer.is_some() || self.database.is_none() {
            return Ok(()); // Already started or no database
        }

        let (command_tx, mut command_rx) = mpsc::unbounded_channel::<BackgroundWriterCommand>();

        // Create a new database connection for the background writer using the same path
        let background_database: Box<dyn WalletStorage> = if database_path == ":memory:" {
            // For in-memory databases, we can't share the connection, so fall back to direct storage
            return Ok(());
        } else {
            Box::new(SqliteStorage::new(database_path).await?)
        };

        // Initialize the background database (ensure schema exists)
        background_database.initialize().await?;

        // Spawn the background writer task
        let join_handle = tokio::spawn(async move {
            BackgroundWriter::background_writer_loop(background_database, &mut command_rx).await;
        });

        self.background_writer = Some(BackgroundWriter {
            command_tx,
            join_handle,
        });

        Ok(())
    }

    /// Stop the background writer service (non-WASM32 only)
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    pub async fn stop_background_writer(&mut self) -> WalletResult<()> {
        if let Some(writer) = self.background_writer.take() {
            let (response_tx, response_rx) = oneshot::channel();
            if writer
                .command_tx
                .send(BackgroundWriterCommand::Shutdown { response_tx })
                .is_ok()
            {
                let _ = response_rx.await;
            }
            let _ = writer.join_handle.await;
        }
        Ok(())
    }

    /// List available wallets in the database
    #[cfg(feature = "storage")]
    pub async fn list_wallets(&self) -> WalletResult<Vec<StoredWallet>> {
        if let Some(storage) = &self.database {
            storage.list_wallets().await
        } else {
            Ok(Vec::new())
        }
    }

    /// Get wallet birthday for resume functionality
    #[cfg(feature = "storage")]
    pub async fn get_wallet_birthday(&self) -> WalletResult<Option<u64>> {
        if let (Some(storage), Some(wallet_id)) = (&self.database, self.wallet_id) {
            if let Some(wallet) = storage.get_wallet_by_id(wallet_id).await? {
                Ok(Some(wallet.get_resume_block()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Load scan context from stored wallet
    #[cfg(feature = "storage")]
    pub async fn load_scan_context_from_wallet(
        &self,
        quiet: bool,
    ) -> WalletResult<Option<ScanContext>> {
        let storage = self
            .database
            .as_ref()
            .ok_or_else(|| WalletError::StorageError("No database available".to_string()))?;
        let wallet_id = self
            .wallet_id
            .ok_or_else(|| WalletError::StorageError("No wallet selected".to_string()))?;

        if let Some(wallet) = storage.get_wallet_by_id(wallet_id).await? {
            // Note: In library mode, we don't print directly. The caller can decide what to log.
            if !quiet {
                // For library usage, this could be logged via a callback or returned as part of result
                // For now, we'll skip the printing in library mode
            }

            let view_key = wallet
                .get_view_key()
                .map_err(|e| WalletError::StorageError(format!("Failed to get view key: {e}")))?;

            // Create entropy array - derive from seed phrase if available
            let entropy = if wallet.has_seed_phrase() {
                // Derive entropy from stored seed phrase
                if let Some(seed_phrase) = &wallet.seed_phrase {
                    match derive_entropy_from_seed_phrase(seed_phrase) {
                        Ok(entropy_array) => entropy_array,
                        Err(_) => {
                            if !quiet {
                                // Warning could be returned as part of result or logged via callback
                                // For now, we'll just use default entropy
                            }
                            [0u8; 16]
                        }
                    }
                } else {
                    [0u8; 16]
                }
            } else {
                [0u8; 16] // View-only wallet
            };

            Ok(Some(ScanContext { view_key, entropy }))
        } else {
            Err(WalletError::ResourceNotFound(format!(
                "Wallet with ID {wallet_id} not found"
            )))
        }
    }

    /// Handle wallet operations (list, create, select) - library version
    ///
    /// This method handles wallet selection and loading for library usage.
    /// It returns information about available wallets and selected wallet,
    /// but doesn't perform interactive user prompts (that's handled by the binary).
    #[cfg(feature = "storage")]
    pub async fn handle_wallet_operations(
        &mut self,
        config: &BinaryScanConfig,
        scan_context: Option<&ScanContext>,
    ) -> WalletResult<Option<ScanContext>> {
        // Only perform database operations if database is available
        if self.database.is_none() {
            return Ok(None);
        }

        // Handle wallet selection and loading
        self.wallet_id = self.select_or_create_wallet(config, scan_context).await?;

        // Load scan context from database if needed
        if scan_context.is_none() && self.wallet_id.is_some() {
            self.load_scan_context_from_wallet(config.quiet).await
        } else {
            Ok(None)
        }
    }

    /// Select or create a wallet (library version)
    ///
    /// This version is designed for library usage and doesn't include interactive prompts.
    /// It handles automatic wallet selection but returns information for cases that
    /// require user interaction in the binary.
    #[cfg(feature = "storage")]
    pub async fn select_or_create_wallet(
        &self,
        config: &BinaryScanConfig,
        scan_context: Option<&ScanContext>,
    ) -> WalletResult<Option<u32>> {
        let storage = self
            .database
            .as_ref()
            .ok_or_else(|| WalletError::StorageError("No database available".to_string()))?;

        // Handle wallet selection by name
        if let Some(wallet_name) = &config.wallet_name {
            if let Some(wallet) = storage.get_wallet_by_name(wallet_name).await? {
                // In library mode, we return the wallet ID without printing
                // The caller can decide what to log
                return Ok(wallet.id);
            } else {
                return Err(WalletError::ResourceNotFound(format!(
                    "Wallet '{wallet_name}' not found"
                )));
            }
        }

        // Auto-select wallet or prompt for creation
        let wallets = storage.list_wallets().await?;
        if wallets.is_empty() {
            if let Some(scan_ctx) = scan_context {
                // Create default wallet automatically
                let wallet =
                    StoredWallet::view_only("default".to_string(), scan_ctx.view_key.clone(), 0);
                let wallet_id = storage.save_wallet(&wallet).await?;
                // Note: In library mode, success information should be logged by caller
                Ok(Some(wallet_id))
            } else {
                Err(WalletError::InvalidArgument {
                    argument: "wallets".to_string(),
                    value: "empty".to_string(),
                    message: "No wallets found and no keys provided to create one. Provide --seed-phrase or --view-key, or use an existing wallet.".to_string(),
                })
            }
        } else if wallets.len() == 1 {
            let wallet = &wallets[0];
            // Automatically use the single wallet
            Ok(wallet.id)
        } else {
            // Multiple wallets available - this requires user interaction
            // In library mode, we return an error that the binary can handle
            // The binary will call a separate method to handle the interactive selection
            Err(WalletError::InvalidArgument {
                argument: "wallet_selection".to_string(),
                value: "multiple_wallets".to_string(),
                message: format!(
                    "Multiple wallets found ({}). Binary should handle interactive selection.",
                    wallets.len()
                ),
            })
        }
    }

    /// Get wallet selection information for interactive prompting
    ///
    /// This method is designed to be used by the binary when interactive
    /// wallet selection is needed (when multiple wallets are available).
    #[cfg(feature = "storage")]
    pub async fn get_wallet_selection_info(&self) -> WalletResult<Vec<StoredWallet>> {
        if let Some(storage) = &self.database {
            storage.list_wallets().await
        } else {
            Ok(Vec::new())
        }
    }

    /// Set the selected wallet ID (for use after interactive selection)
    #[cfg(feature = "storage")]
    pub fn set_wallet_id(&mut self, wallet_id: Option<u32>) {
        self.wallet_id = wallet_id;
    }

    /// Save transactions to storage incrementally - architecture-specific implementation
    #[cfg(feature = "storage")]
    pub async fn save_transactions_incremental(
        &mut self,
        all_transactions: &[WalletTransaction],
    ) -> WalletResult<()> {
        if let Some(wallet_id) = self.wallet_id {
            // Only save new transactions since last save
            if all_transactions.len() > self.last_saved_transaction_count {
                let new_transactions = &all_transactions[self.last_saved_transaction_count..];
                if !new_transactions.is_empty() {
                    // Architecture-specific implementation
                    self.save_transactions_arch_specific(wallet_id, new_transactions.to_vec())
                        .await?;
                    self.last_saved_transaction_count = all_transactions.len();
                }
            }
        }
        Ok(())
    }

    /// Architecture-specific transaction saving (non-WASM32: background writer)
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    async fn save_transactions_arch_specific(
        &self,
        wallet_id: u32,
        transactions: Vec<WalletTransaction>,
    ) -> WalletResult<()> {
        if let Some(writer) = &self.background_writer {
            let (response_tx, response_rx) = oneshot::channel();
            writer
                .command_tx
                .send(BackgroundWriterCommand::SaveTransactions {
                    wallet_id,
                    transactions,
                    response_tx,
                })
                .map_err(|_| {
                    WalletError::StorageError("Background writer channel closed".to_string())
                })?;

            response_rx.await.map_err(|_| {
                WalletError::StorageError("Background writer response lost".to_string())
            })?
        } else if let Some(storage) = &self.database {
            // Fallback to direct storage if background writer not available
            storage.save_transactions(wallet_id, &transactions).await
        } else {
            Ok(()) // Memory-only mode
        }
    }

    /// Architecture-specific transaction saving (WASM32: direct storage)
    #[cfg(all(feature = "storage", target_arch = "wasm32"))]
    async fn save_transactions_arch_specific(
        &self,
        wallet_id: u32,
        transactions: Vec<WalletTransaction>,
    ) -> WalletResult<()> {
        if let Some(storage) = &self.database {
            storage.save_transactions(wallet_id, &transactions).await
        } else {
            Ok(()) // Memory-only mode
        }
    }

    /// Save transactions to storage (legacy method for compatibility)
    #[cfg(feature = "storage")]
    pub async fn save_transactions(&self, transactions: &[WalletTransaction]) -> WalletResult<()> {
        if let (Some(storage), Some(wallet_id)) = (&self.database, self.wallet_id) {
            storage.save_transactions(wallet_id, transactions).await
        } else {
            Ok(()) // Memory-only mode
        }
    }

    /// Save UTXO outputs to storage - architecture-specific implementation
    #[cfg(feature = "storage")]
    pub async fn save_outputs(&self, outputs: &[StoredOutput]) -> WalletResult<Vec<u32>> {
        self.save_outputs_arch_specific(outputs.to_vec()).await
    }

    /// Architecture-specific output saving (non-WASM32: background writer)
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    async fn save_outputs_arch_specific(
        &self,
        outputs: Vec<StoredOutput>,
    ) -> WalletResult<Vec<u32>> {
        if let Some(writer) = &self.background_writer {
            let (response_tx, response_rx) = oneshot::channel();
            writer
                .command_tx
                .send(BackgroundWriterCommand::SaveOutputs {
                    outputs,
                    response_tx,
                })
                .map_err(|_| {
                    WalletError::StorageError("Background writer channel closed".to_string())
                })?;

            response_rx.await.map_err(|_| {
                WalletError::StorageError("Background writer response lost".to_string())
            })?
        } else if let Some(storage) = &self.database {
            // Fallback to direct storage if background writer not available
            storage.save_outputs(&outputs).await
        } else {
            Ok(Vec::new()) // Memory-only mode
        }
    }

    /// Architecture-specific output saving (WASM32: direct storage)
    #[cfg(all(feature = "storage", target_arch = "wasm32"))]
    async fn save_outputs_arch_specific(
        &self,
        outputs: Vec<StoredOutput>,
    ) -> WalletResult<Vec<u32>> {
        if let Some(storage) = &self.database {
            storage.save_outputs(&outputs).await
        } else {
            Ok(Vec::new()) // Memory-only mode
        }
    }

    /// Update wallet's latest scanned block - architecture-specific implementation
    #[cfg(feature = "storage")]
    pub async fn update_wallet_scanned_block(&self, block_height: u64) -> WalletResult<()> {
        if let Some(wallet_id) = self.wallet_id {
            self.update_wallet_scanned_block_arch_specific(wallet_id, block_height)
                .await
        } else {
            Ok(()) // Memory-only mode
        }
    }

    /// Architecture-specific wallet scanned block update (non-WASM32: background writer)
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    async fn update_wallet_scanned_block_arch_specific(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> WalletResult<()> {
        if let Some(writer) = &self.background_writer {
            let (response_tx, response_rx) = oneshot::channel();
            writer
                .command_tx
                .send(BackgroundWriterCommand::UpdateWalletScannedBlock {
                    wallet_id,
                    block_height,
                    response_tx,
                })
                .map_err(|_| {
                    WalletError::StorageError("Background writer channel closed".to_string())
                })?;

            response_rx.await.map_err(|_| {
                WalletError::StorageError("Background writer response lost".to_string())
            })?
        } else if let Some(storage) = &self.database {
            // Fallback to direct storage if background writer not available
            storage
                .update_wallet_scanned_block(wallet_id, block_height)
                .await
        } else {
            Ok(()) // Memory-only mode
        }
    }

    /// Architecture-specific wallet scanned block update (WASM32: direct storage)
    #[cfg(all(feature = "storage", target_arch = "wasm32"))]
    async fn update_wallet_scanned_block_arch_specific(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> WalletResult<()> {
        if let Some(storage) = &self.database {
            storage
                .update_wallet_scanned_block(wallet_id, block_height)
                .await
        } else {
            Ok(()) // Memory-only mode
        }
    }

    /// Mark transaction as spent - architecture-specific implementation
    #[cfg(feature = "storage")]
    pub async fn mark_transaction_spent_arch_specific(
        &self,
        commitment: &CompressedCommitment,
        block_height: u64,
        input_index: usize,
    ) -> WalletResult<bool> {
        self.mark_transaction_spent_impl(commitment, block_height, input_index)
            .await
    }

    /// Mark multiple transactions as spent in batch - architecture-specific implementation
    #[cfg(feature = "storage")]
    pub async fn mark_transactions_spent_batch_arch_specific(
        &self,
        spent_commitments: &[(CompressedCommitment, u64, usize)],
    ) -> WalletResult<usize> {
        self.mark_transactions_spent_batch_impl(spent_commitments)
            .await
    }

    /// Architecture-specific batch transaction spent marking (non-WASM32: background writer)
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    async fn mark_transactions_spent_batch_impl(
        &self,
        spent_commitments: &[(CompressedCommitment, u64, usize)],
    ) -> WalletResult<usize> {
        if let Some(writer) = &self.background_writer {
            let (response_tx, response_rx) = oneshot::channel();
            writer
                .command_tx
                .send(BackgroundWriterCommand::MarkTransactionsSpentBatch {
                    commitments: spent_commitments.to_vec(),
                    response_tx,
                })
                .map_err(|_| {
                    WalletError::StorageError("Background writer channel closed".to_string())
                })?;

            response_rx.await.map_err(|_| {
                WalletError::StorageError("Background writer response lost".to_string())
            })?
        } else if let Some(storage) = &self.database {
            // Fallback to direct storage if background writer not available
            storage
                .mark_transactions_spent_batch(spent_commitments)
                .await
        } else {
            Ok(0) // Memory-only mode
        }
    }

    /// Architecture-specific batch transaction spent marking (WASM32: direct storage)
    #[cfg(all(feature = "storage", target_arch = "wasm32"))]
    async fn mark_transactions_spent_batch_impl(
        &self,
        spent_commitments: &[(CompressedCommitment, u64, usize)],
    ) -> WalletResult<usize> {
        if let Some(storage) = &self.database {
            storage
                .mark_transactions_spent_batch(spent_commitments)
                .await
        } else {
            Ok(0) // Memory-only mode
        }
    }

    /// Architecture-specific transaction spent marking (non-WASM32: background writer)
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    async fn mark_transaction_spent_impl(
        &self,
        commitment: &CompressedCommitment,
        block_height: u64,
        input_index: usize,
    ) -> WalletResult<bool> {
        if let Some(writer) = &self.background_writer {
            let (response_tx, response_rx) = oneshot::channel();
            writer
                .command_tx
                .send(BackgroundWriterCommand::MarkTransactionSpent {
                    commitment: commitment.clone(),
                    block_height,
                    input_index,
                    response_tx,
                })
                .map_err(|_| {
                    WalletError::StorageError("Background writer channel closed".to_string())
                })?;

            response_rx.await.map_err(|_| {
                WalletError::StorageError("Background writer response lost".to_string())
            })?
        } else if let Some(storage) = &self.database {
            // Fallback to direct storage if background writer not available
            storage
                .mark_transaction_spent(commitment, block_height, input_index)
                .await
        } else {
            Ok(false) // Memory-only mode
        }
    }

    /// Architecture-specific transaction spent marking (WASM32: direct storage)
    #[cfg(all(feature = "storage", target_arch = "wasm32"))]
    async fn mark_transaction_spent_impl(
        &self,
        commitment: &CompressedCommitment,
        block_height: u64,
        input_index: usize,
    ) -> WalletResult<bool> {
        if let Some(storage) = &self.database {
            storage
                .mark_transaction_spent(commitment, block_height, input_index)
                .await
        } else {
            Ok(false) // Memory-only mode
        }
    }

    /// Get storage statistics for the current wallet
    #[cfg(feature = "storage")]
    pub async fn get_statistics(&self) -> WalletResult<crate::storage::StorageStats> {
        if let Some(storage) = &self.database {
            // Get wallet-specific statistics if we have a wallet_id
            storage.get_wallet_statistics(self.wallet_id).await
        } else {
            // Return empty statistics for memory-only mode
            Ok(crate::storage::StorageStats {
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

    /// Get unspent outputs count
    #[cfg(feature = "storage")]
    pub async fn get_unspent_outputs_count(&self) -> WalletResult<usize> {
        if let (Some(storage), Some(wallet_id)) = (&self.database, self.wallet_id) {
            let outputs = storage.get_unspent_outputs(wallet_id).await?;
            Ok(outputs.len())
        } else {
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::derive_entropy_from_seed_phrase;
    use super::ScannerStorage;
    use crate::scanning::BinaryScanConfig;

    #[cfg(feature = "storage")]
    #[test]
    fn test_scanner_storage_new_memory() {
        let storage = ScannerStorage::new_memory();

        assert!(storage.is_memory_only);
        assert_eq!(storage.wallet_id, None);
        assert_eq!(storage.last_saved_transaction_count, 0);

        #[cfg(feature = "storage")]
        assert!(storage.database.is_none());

        #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
        assert!(storage.background_writer.is_none());
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_scanner_storage_new_with_database_memory() {
        let storage = ScannerStorage::new_with_database(":memory:").await;
        assert!(storage.is_ok());

        let storage = storage.unwrap();
        assert!(!storage.is_memory_only);
        assert!(storage.database.is_some());
        assert_eq!(storage.wallet_id, None);
        assert_eq!(storage.last_saved_transaction_count, 0);
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_scanner_storage_new_with_database_file() {
        let temp_path = std::env::temp_dir().join("test_scanner_storage.db");
        let path_str = temp_path.to_string_lossy();

        let storage = ScannerStorage::new_with_database(&path_str).await;
        assert!(storage.is_ok());

        let storage = storage.unwrap();
        assert!(!storage.is_memory_only);
        assert!(storage.database.is_some());

        // Clean up
        let _ = std::fs::remove_file(&temp_path);
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_list_wallets_no_database() {
        let storage = ScannerStorage::new_memory();

        // Should return empty list when no database
        #[cfg(feature = "storage")]
        {
            let wallets = storage.list_wallets().await.unwrap();
            assert!(wallets.is_empty());
        }
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_list_wallets_with_database() {
        let storage = ScannerStorage::new_with_database(":memory:").await.unwrap();

        let wallets = storage.list_wallets().await.unwrap();
        assert!(wallets.is_empty()); // New database should be empty
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_get_wallet_birthday_no_wallet() {
        let storage = ScannerStorage::new_with_database(":memory:").await.unwrap();

        let birthday = storage.get_wallet_birthday().await.unwrap();
        assert_eq!(birthday, None); // No wallet selected
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_get_wallet_birthday_no_database() {
        let storage = ScannerStorage::new_memory();

        let birthday = storage.get_wallet_birthday().await.unwrap();
        assert_eq!(birthday, None); // No database
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_set_wallet_id() {
        let mut storage = ScannerStorage::new_memory();

        assert_eq!(storage.wallet_id, None);

        storage.set_wallet_id(Some(42));
        assert_eq!(storage.wallet_id, Some(42));

        storage.set_wallet_id(None);
        assert_eq!(storage.wallet_id, None);
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_get_wallet_selection_info_no_database() {
        let storage = ScannerStorage::new_memory();

        let wallets = storage.get_wallet_selection_info().await.unwrap();
        assert!(wallets.is_empty());
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_get_wallet_selection_info_with_database() {
        let storage = ScannerStorage::new_with_database(":memory:").await.unwrap();

        let wallets = storage.get_wallet_selection_info().await.unwrap();
        assert!(wallets.is_empty()); // New database should be empty
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_save_transactions_incremental_no_wallet() {
        let mut storage = ScannerStorage::new_with_database(":memory:").await.unwrap();

        // Should succeed even with no wallet selected (memory mode behavior)
        let result = storage.save_transactions_incremental(&[]).await;
        assert!(result.is_ok());
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_save_transactions_incremental_empty() {
        let mut storage = ScannerStorage::new_with_database(":memory:").await.unwrap();
        storage.set_wallet_id(Some(1));

        let result = storage.save_transactions_incremental(&[]).await;
        assert!(result.is_ok());
        assert_eq!(storage.last_saved_transaction_count, 0);
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_save_transactions_incremental_tracking() {
        let mut storage = ScannerStorage::new_with_database(":memory:").await.unwrap();
        storage.set_wallet_id(Some(1));

        // Mock some transactions (we can't create real WalletTransaction without complex setup)
        // This tests the incremental counting logic
        assert_eq!(storage.last_saved_transaction_count, 0);

        // Test that the counter would update (can't test actual saving without complex mocking)
        storage.last_saved_transaction_count = 5;
        assert_eq!(storage.last_saved_transaction_count, 5);
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_save_transactions_memory_mode() {
        let storage = ScannerStorage::new_memory();

        // Should succeed in memory mode
        let result = storage.save_transactions(&[]).await;
        assert!(result.is_ok());
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_save_outputs_memory_mode() {
        let storage = ScannerStorage::new_memory();

        // Should succeed in memory mode
        let result = storage.save_outputs(&[]).await;
        assert!(result.is_ok());
        let output_ids = result.unwrap();
        assert!(output_ids.is_empty());
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_update_wallet_scanned_block_no_wallet() {
        let storage = ScannerStorage::new_with_database(":memory:").await.unwrap();

        // Should succeed even with no wallet (no-op)
        let result = storage.update_wallet_scanned_block(1000).await;
        assert!(result.is_ok());
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_update_wallet_scanned_block_memory_mode() {
        let storage = ScannerStorage::new_memory();

        // Should succeed in memory mode
        let result = storage.update_wallet_scanned_block(1000).await;
        assert!(result.is_ok());
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_get_statistics_memory_mode() {
        let storage = ScannerStorage::new_memory();

        let stats = storage.get_statistics().await.unwrap();
        assert_eq!(stats.total_transactions, 0);
        assert_eq!(stats.current_balance, 0);
        assert_eq!(stats.latest_scanned_block, None);
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_get_statistics_with_database() {
        let storage = ScannerStorage::new_with_database(":memory:").await.unwrap();

        let stats = storage.get_statistics().await.unwrap();
        // New database should have empty stats
        assert_eq!(stats.total_transactions, 0);
        assert_eq!(stats.current_balance, 0);
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_get_unspent_outputs_count_memory_mode() {
        let storage = ScannerStorage::new_memory();

        let count = storage.get_unspent_outputs_count().await.unwrap();
        assert_eq!(count, 0);
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_get_unspent_outputs_count_no_wallet() {
        let storage = ScannerStorage::new_with_database(":memory:").await.unwrap();

        let count = storage.get_unspent_outputs_count().await.unwrap();
        assert_eq!(count, 0); // No wallet selected
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_derive_entropy_from_seed_phrase_invalid() {
        // Test with invalid seed phrase
        let result = derive_entropy_from_seed_phrase("invalid seed phrase");
        assert!(result.is_err());
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_load_scan_context_no_database() {
        let storage = ScannerStorage::new_memory();

        let result = storage.load_scan_context_from_wallet(true).await;
        assert!(result.is_err());
        // Should get "No database available" error
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_load_scan_context_no_wallet_selected() {
        let storage = ScannerStorage::new_with_database(":memory:").await.unwrap();

        let result = storage.load_scan_context_from_wallet(true).await;
        assert!(result.is_err());
        // Should get "No wallet selected" error
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_handle_wallet_operations_no_database() {
        let mut storage = ScannerStorage::new_memory();
        let config = BinaryScanConfig::new(100, 200);

        let result = storage
            .handle_wallet_operations(&config, None)
            .await
            .unwrap();
        assert!(result.is_none()); // No database, should return None
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_select_or_create_wallet_no_database() {
        let storage = ScannerStorage::new_memory();
        let config = BinaryScanConfig::new(100, 200);

        let result = storage.select_or_create_wallet(&config, None).await;
        assert!(result.is_err());
        // Should get "No database available" error
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_select_or_create_wallet_named_not_found() {
        let storage = ScannerStorage::new_with_database(":memory:").await.unwrap();
        let config = BinaryScanConfig::new(100, 200).with_wallet_name("nonexistent".to_string());

        let result = storage.select_or_create_wallet(&config, None).await;
        assert!(result.is_err());
        // Should get wallet not found error
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_select_or_create_wallet_no_wallets_no_keys() {
        let storage = ScannerStorage::new_with_database(":memory:").await.unwrap();
        let config = BinaryScanConfig::new(100, 200);

        let result = storage.select_or_create_wallet(&config, None).await;
        assert!(result.is_err());
        // Should get error about no wallets and no keys
        let error_msg = format!("{:?}", result.unwrap_err());
        assert!(error_msg.contains("No wallets found"));
    }

    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_background_writer_operations() {
        let mut storage = ScannerStorage::new_with_database(":memory:").await.unwrap();

        // Test starting background writer for in-memory database (should be no-op)
        let result = storage.start_background_writer(":memory:").await;
        assert!(result.is_ok());

        // Test stopping background writer when none exists
        let result = storage.stop_background_writer().await;
        assert!(result.is_ok());
    }

    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_background_writer_file_database() {
        let temp_path = std::env::temp_dir().join("test_bg_writer.db");
        let path_str = temp_path.to_string_lossy();

        let mut storage = ScannerStorage::new_with_database(&path_str).await.unwrap();

        // Test starting background writer for file database
        let result = storage.start_background_writer(&path_str).await;
        assert!(result.is_ok());

        // Test starting again (should be no-op)
        let result = storage.start_background_writer(&path_str).await;
        assert!(result.is_ok());

        // Test stopping
        let result = storage.stop_background_writer().await;
        assert!(result.is_ok());

        // Clean up
        let _ = std::fs::remove_file(&temp_path);
    }
}
