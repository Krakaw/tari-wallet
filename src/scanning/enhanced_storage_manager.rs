//! Enhanced storage manager with high-performance batch background writer
//!
//! This module provides an enhanced version of ScannerStorage that uses the
//! BatchBackgroundWriter for maximum database performance during scanning operations.

#[cfg(feature = "storage")]
use crate::{
    errors::WalletResult,
    storage::{EnhancedSqliteStorage, WalletStorage},
};

#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
use crate::scanning::{
    batch_background_writer::{
        BatchBackgroundWriter, BatchBackgroundWriterCommand, BatchWriterConfig, BatchableCommand,
    },
    storage_manager::ScannerStorage,
};

#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
use tokio::sync::{mpsc, oneshot};

/// Enhanced scanner storage that uses batch background writer for maximum performance
#[cfg(feature = "storage")]
pub struct EnhancedScannerStorage {
    /// Base scanner storage for fallback operations
    base_storage: ScannerStorage,
    /// Enhanced SQLite storage for high-performance batch operations
    enhanced_storage: Option<EnhancedSqliteStorage>,
    /// Batch background writer for ultra-high performance operations
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    batch_writer: Option<BatchBackgroundWriter>,
    /// Configuration for batch operations
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    batch_config: BatchWriterConfig,
}

#[cfg(feature = "storage")]
impl EnhancedScannerStorage {
    /// Create a new enhanced scanner storage with high-performance batching
    pub async fn new_high_performance_database(
        database_path: &str,
        performance_preset: &str,
    ) -> WalletResult<Self> {
        let base_storage =
            ScannerStorage::new_with_performance_database(database_path, performance_preset)
                .await?;

        // Create enhanced storage for batch operations
        let enhanced_storage = if database_path == ":memory:" {
            Some(EnhancedSqliteStorage::new_in_memory().await?)
        } else {
            Some(EnhancedSqliteStorage::new(database_path).await?)
        };

        Ok(Self {
            base_storage,
            enhanced_storage,
            #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
            batch_writer: None,
            #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
            batch_config: BatchWriterConfig::scanning_optimized(),
        })
    }

    /// Create memory-only enhanced storage
    pub fn new_memory() -> Self {
        Self {
            base_storage: ScannerStorage::new_memory(),
            enhanced_storage: None,
            #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
            batch_writer: None,
            #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
            batch_config: BatchWriterConfig::scanning_optimized(),
        }
    }

    /// Start the high-performance batch background writer
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    pub async fn start_batch_background_writer(&mut self, database_path: &str) -> WalletResult<()> {
        if self.batch_writer.is_some() || self.enhanced_storage.is_none() {
            return Ok(()); // Already started or no enhanced storage
        }

        let (command_tx, mut command_rx) =
            mpsc::unbounded_channel::<BatchBackgroundWriterCommand>();

        // Create a new enhanced database connection for the batch writer
        let background_database: Box<dyn WalletStorage> = if database_path == ":memory:" {
            // For in-memory databases, fall back to regular background writer
            return self
                .base_storage
                .start_background_writer(database_path)
                .await;
        } else {
            Box::new(EnhancedSqliteStorage::new(database_path).await?)
        };

        // Initialize the background database
        background_database.initialize().await?;

        // Spawn the batch background writer task with optimized configuration
        let batch_config = self.batch_config.clone();
        let join_handle = tokio::spawn(async move {
            BatchBackgroundWriter::batch_writer_loop(
                background_database,
                &mut command_rx,
                batch_config,
            )
            .await;
        });

        self.batch_writer = Some(BatchBackgroundWriter {
            command_tx,
            join_handle,
        });

        Ok(())
    }

    /// Stop the batch background writer
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    pub async fn stop_batch_background_writer(&mut self) -> WalletResult<()> {
        if let Some(writer) = self.batch_writer.take() {
            let (response_tx, response_rx) = oneshot::channel();
            if writer
                .command_tx
                .send(BatchBackgroundWriterCommand::Shutdown { response_tx })
                .is_ok()
            {
                let _ = response_rx.await;
            }
            let _ = writer.join_handle.await;
        }

        // Also stop the base storage background writer
        self.base_storage.stop_background_writer().await
    }

    /// Save multiple transaction batches using enhanced performance
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    pub async fn save_transaction_batches_enhanced(
        &self,
        batches: &[(
            u32,
            Vec<crate::data_structures::wallet_transaction::WalletTransaction>,
        )],
    ) -> WalletResult<()> {
        if let Some(enhanced_storage) = &self.enhanced_storage {
            enhanced_storage.save_all_batches(batches).await
        } else {
            // Fall back to individual batch processing
            for (_wallet_id, transactions) in batches {
                self.base_storage.save_transactions(transactions).await?;
            }
            Ok(())
        }
    }

    /// Flush any pending batch operations
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    pub async fn flush_batch_operations(&self) -> WalletResult<usize> {
        if let Some(writer) = &self.batch_writer {
            let (response_tx, response_rx) = oneshot::channel();
            if writer
                .command_tx
                .send(BatchBackgroundWriterCommand::FlushBatch { response_tx })
                .is_ok()
            {
                match response_rx.await {
                    Ok(result) => result,
                    Err(_) => Ok(0),
                }
            } else {
                Ok(0)
            }
        } else {
            Ok(0)
        }
    }

    /// Send a batchable command to the batch writer
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    pub async fn send_batch_command(&self, command: BatchableCommand) -> WalletResult<()> {
        if let Some(writer) = &self.batch_writer {
            let (response_tx, response_rx) = oneshot::channel();
            if writer
                .command_tx
                .send(BatchBackgroundWriterCommand::AddToBatch {
                    operation: command,
                    response_tx,
                })
                .is_ok()
            {
                match response_rx.await {
                    Ok(result) => result,
                    Err(_) => Ok(()),
                }
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    /// Check if using high-performance batch writer
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    pub fn is_using_batch_writer(&self) -> bool {
        self.batch_writer.is_some()
    }

    #[cfg(not(all(feature = "storage", not(target_arch = "wasm32"))))]
    pub fn is_using_batch_writer(&self) -> bool {
        false
    }

    /// Delegate all other operations to base storage
    pub fn is_memory_only(&self) -> bool {
        self.base_storage.is_memory_only
    }

    pub fn wallet_id(&self) -> Option<u32> {
        self.base_storage.wallet_id
    }

    pub fn set_wallet_id(&mut self, wallet_id: Option<u32>) {
        self.base_storage.set_wallet_id(wallet_id);
    }

    pub async fn handle_wallet_operations(
        &mut self,
        config: &crate::scanning::BinaryScanConfig,
        scan_context: Option<&crate::scanning::ScanContext>,
    ) -> WalletResult<Option<crate::scanning::ScanContext>> {
        self.base_storage
            .handle_wallet_operations(config, scan_context)
            .await
    }

    pub async fn load_scan_context_from_wallet(
        &self,
        quiet: bool,
    ) -> WalletResult<Option<crate::scanning::ScanContext>> {
        self.base_storage.load_scan_context_from_wallet(quiet).await
    }

    pub async fn get_wallet_birthday(&self) -> WalletResult<Option<u64>> {
        self.base_storage.get_wallet_birthday().await
    }

    pub async fn get_wallet_selection_info(
        &self,
    ) -> WalletResult<Vec<crate::storage::StoredWallet>> {
        self.base_storage.get_wallet_selection_info().await
    }

    pub async fn get_statistics(&self) -> WalletResult<crate::storage::StorageStats> {
        self.base_storage.get_statistics().await
    }

    pub async fn get_unspent_outputs_count(&self) -> WalletResult<usize> {
        self.base_storage.get_unspent_outputs_count().await
    }

    pub async fn save_transactions(
        &self,
        transactions: &[crate::data_structures::wallet_transaction::WalletTransaction],
    ) -> WalletResult<()> {
        self.base_storage.save_transactions(transactions).await
    }

    /// Start background writer (delegates to appropriate writer based on configuration)
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    pub async fn start_background_writer(&mut self, database_path: &str) -> WalletResult<()> {
        // Start the high-performance batch writer if enhanced storage is available
        if self.enhanced_storage.is_some() {
            self.start_batch_background_writer(database_path).await
        } else {
            // Fall back to regular background writer
            self.base_storage
                .start_background_writer(database_path)
                .await
        }
    }

    /// Stop background writer (delegates to appropriate writer)
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    pub async fn stop_background_writer(&mut self) -> WalletResult<()> {
        if self.batch_writer.is_some() {
            self.stop_batch_background_writer().await
        } else {
            self.base_storage.stop_background_writer().await
        }
    }

    /// Start background writer (no-op for WASM32)
    #[cfg(not(all(feature = "storage", not(target_arch = "wasm32"))))]
    pub async fn start_background_writer(&mut self, _database_path: &str) -> WalletResult<()> {
        Ok(())
    }

    /// Stop background writer (no-op for WASM32)
    #[cfg(not(all(feature = "storage", not(target_arch = "wasm32"))))]
    pub async fn stop_background_writer(&mut self) -> WalletResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_enhanced_scanner_storage_creation() {
        let storage = EnhancedScannerStorage::new_memory();
        assert!(storage.is_memory_only());
        assert!(!storage.is_using_batch_writer());
    }

    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_batch_writer_lifecycle() {
        let mut storage =
            EnhancedScannerStorage::new_high_performance_database(":memory:", "scanning")
                .await
                .unwrap();

        // Test starting and stopping batch writer
        storage.start_background_writer(":memory:").await.unwrap();
        storage.stop_background_writer().await.unwrap();
    }
}
