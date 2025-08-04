//! Database data processor implementation
//!
//! This module provides a DataProcessor implementation that stores scan results
//! to a SQLite database, maintaining compatibility with the existing storage
//! infrastructure while using the new callback-based approach.

#[cfg(feature = "storage")]
use crate::{
    errors::WalletResult,
    scanning::{
        data_processor::{BlockData, CompletionData, DataProcessor, ProgressData},
        ScannerStorage,
    },
};

#[cfg(feature = "storage")]
use async_trait::async_trait;

/// Database data processor that stores scan results to SQLite
///
/// This processor wraps the existing ScannerStorage functionality and provides
/// a bridge between the new callback-based scanning approach and the existing
/// database storage infrastructure.
#[cfg(feature = "storage")]
pub struct DatabaseDataProcessor {
    /// The underlying storage backend
    storage: ScannerStorage,
}

#[cfg(feature = "storage")]
impl DatabaseDataProcessor {
    /// Create a new database data processor with the given storage backend
    pub fn new(storage: ScannerStorage) -> Self {
        Self { storage }
    }

    /// Create a new database data processor with in-memory storage
    pub fn new_memory() -> Self {
        Self {
            storage: ScannerStorage::new_memory(),
        }
    }

    /// Create a new database data processor with SQLite database
    pub async fn new_with_database(database_path: &str) -> WalletResult<Self> {
        let storage = ScannerStorage::new_with_database(database_path).await?;
        Ok(Self { storage })
    }

    /// Get a reference to the underlying storage
    pub fn storage(&self) -> &ScannerStorage {
        &self.storage
    }

    /// Get a mutable reference to the underlying storage
    pub fn storage_mut(&mut self) -> &mut ScannerStorage {
        &mut self.storage
    }

    /// Check if this processor is using memory-only storage
    pub fn is_memory_only(&self) -> bool {
        self.storage.is_memory_only
    }

    /// Set the wallet ID for the storage backend
    pub fn set_wallet_id(&mut self, wallet_id: Option<u32>) {
        self.storage.set_wallet_id(wallet_id);
    }

    /// Get storage statistics
    pub async fn get_statistics(
        &self,
    ) -> WalletResult<crate::storage::storage_trait::StorageStats> {
        self.storage.get_statistics().await
    }

    /// Get unspent outputs count
    pub async fn get_unspent_outputs_count(&self) -> WalletResult<usize> {
        self.storage.get_unspent_outputs_count().await
    }

    /// Start background writer (for non-memory storage)
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn start_background_writer(&mut self, database_path: &str) -> WalletResult<()> {
        if !self.storage.is_memory_only {
            self.storage.start_background_writer(database_path).await
        } else {
            Ok(())
        }
    }

    /// Stop background writer (for non-memory storage)
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn stop_background_writer(&mut self) -> WalletResult<()> {
        if !self.storage.is_memory_only {
            self.storage.stop_background_writer().await
        } else {
            Ok(())
        }
    }

    /// Handle wallet operations (compatibility method)
    pub async fn handle_wallet_operations(
        &mut self,
        config: &crate::scanning::BinaryScanConfig,
        scan_context: Option<&crate::scanning::ScanContext>,
    ) -> WalletResult<Option<crate::scanning::ScanContext>> {
        self.storage
            .handle_wallet_operations(config, scan_context)
            .await
    }

    /// Load scan context from wallet
    pub async fn load_scan_context_from_wallet(
        &mut self,
        quiet: bool,
    ) -> WalletResult<Option<crate::scanning::ScanContext>> {
        self.storage.load_scan_context_from_wallet(quiet).await
    }

    /// Get wallet birthday
    pub async fn get_wallet_birthday(&self) -> WalletResult<Option<u64>> {
        self.storage.get_wallet_birthday().await
    }

    /// Get wallet selection info (placeholder - actual implementation depends on storage interface)
    pub async fn get_wallet_selection_info(&self) -> WalletResult<Vec<String>> {
        // This is a placeholder - the actual storage interface may differ
        // For now, return empty vector
        Ok(Vec::new())
    }
}

#[cfg(feature = "storage")]
#[async_trait]
impl DataProcessor for DatabaseDataProcessor {
    async fn process_block(&mut self, block_data: BlockData) -> WalletResult<()> {
        // Only save transactions if we found any wallet activity
        if block_data.has_activity() {
            // Save transactions incrementally
            self.storage
                .save_transactions_incremental(&block_data.transactions)
                .await?;
        }

        Ok(())
    }

    async fn process_progress(&mut self, _progress_data: ProgressData) -> WalletResult<()> {
        // Progress updates don't need to be stored to database
        Ok(())
    }

    async fn process_completion(&mut self, completion_data: CompletionData) -> WalletResult<()> {
        // Update the wallet's latest scanned block if scan completed successfully
        if completion_data.is_completed() && !self.storage.is_memory_only {
            self.storage
                .update_wallet_scanned_block(completion_data.to_block)
                .await?;
        }

        Ok(())
    }

    async fn initialize(&mut self) -> WalletResult<()> {
        // Initialize storage if needed
        // The storage should already be initialized by this point
        Ok(())
    }

    async fn finalize(&mut self) -> WalletResult<()> {
        // Finalize storage operations
        // Any cleanup needed can be done here
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// In-memory data processor that just collects transactions
///
/// This is a simple implementation that can be used when you don't need
/// database persistence but want to collect the scanning results.
#[derive(Debug, Default)]
pub struct MemoryStorageProcessor {
    /// All transactions found during scanning
    pub transactions: Vec<crate::data_structures::wallet_transaction::WalletTransaction>,
    /// Latest block scanned
    pub latest_block: Option<u64>,
}

impl MemoryStorageProcessor {
    /// Create a new memory storage processor
    pub fn new() -> Self {
        Self {
            transactions: Vec::new(),
            latest_block: None,
        }
    }

    /// Get all transactions
    pub fn get_transactions(
        &self,
    ) -> &[crate::data_structures::wallet_transaction::WalletTransaction] {
        &self.transactions
    }

    /// Get the latest scanned block
    pub fn get_latest_block(&self) -> Option<u64> {
        self.latest_block
    }

    /// Clear all stored data
    pub fn clear(&mut self) {
        self.transactions.clear();
        self.latest_block = None;
    }

    /// Get transaction count
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
}

#[async_trait]
impl DataProcessor for MemoryStorageProcessor {
    async fn process_block(&mut self, block_data: BlockData) -> WalletResult<()> {
        // Store all transactions from this block
        if block_data.has_activity() {
            self.transactions.extend(block_data.transactions);
        }

        // Track latest block
        if self
            .latest_block
            .map_or(true, |latest| block_data.height > latest)
        {
            self.latest_block = Some(block_data.height);
        }

        Ok(())
    }

    async fn process_completion(&mut self, _completion_data: CompletionData) -> WalletResult<()> {
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanning::data_processor::{BlockData, CompletionData};

    #[tokio::test]
    async fn test_memory_storage_processor() {
        let mut processor = MemoryStorageProcessor::new();

        // Process a block with no activity
        let empty_block = BlockData::empty(1000, "hash1".to_string(), 1234567890);
        processor.process_block(empty_block).await.unwrap();

        assert_eq!(processor.transaction_count(), 0);
        assert_eq!(processor.get_latest_block(), Some(1000));

        // Process completion
        let completion = CompletionData::new(1000, 2000, 1001, false, None, 0);
        processor.process_completion(completion).await.unwrap();
    }

    #[tokio::test]
    async fn test_memory_storage_processor_clear() {
        let mut processor = MemoryStorageProcessor::new();

        // Add some data
        let empty_block = BlockData::empty(1000, "hash1".to_string(), 1234567890);
        processor.process_block(empty_block).await.unwrap();

        // Clear data
        processor.clear();

        assert_eq!(processor.transaction_count(), 0);
        assert_eq!(processor.get_latest_block(), None);
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_database_processor_memory_only() {
        let processor = DatabaseDataProcessor::new_memory();

        assert!(processor.is_memory_only());
    }
}
