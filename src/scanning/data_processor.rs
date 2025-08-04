//! Generic data processing callback interface for wallet scanning
//!
//! This module defines a trait-based approach to handle data processing during wallet
//! scanning operations. Instead of coupling the scanner to a specific storage backend,
//! the scanner accepts callback functions that can handle different types of data.

use crate::{data_structures::wallet_transaction::WalletTransaction, errors::WalletResult};
use async_trait::async_trait;

/// Block data that can be processed during scanning
#[derive(Debug, Clone)]
pub struct BlockData {
    /// Block height being processed
    pub height: u64,
    /// Hash of the block
    pub hash: String,
    /// Timestamp of the block
    pub timestamp: u64,
    /// Transactions found in this block for the wallet
    pub transactions: Vec<WalletTransaction>,
    /// Whether this block completed processing (vs. was interrupted)
    pub completed: bool,
}

impl BlockData {
    /// Create new block data
    pub fn new(
        height: u64,
        hash: String,
        timestamp: u64,
        transactions: Vec<WalletTransaction>,
        completed: bool,
    ) -> Self {
        Self {
            height,
            hash,
            timestamp,
            transactions,
            completed,
        }
    }

    /// Create empty block data (no wallet activity found)
    pub fn empty(height: u64, hash: String, timestamp: u64) -> Self {
        Self::new(height, hash, timestamp, Vec::new(), true)
    }

    /// Check if this block has any wallet activity
    pub fn has_activity(&self) -> bool {
        !self.transactions.is_empty()
    }

    /// Get the number of transactions in this block
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
}

/// Progress data that can be processed during scanning
#[derive(Debug, Clone)]
pub struct ProgressData {
    /// Current block being processed
    pub current_block: u64,
    /// Total blocks to be processed
    pub total_blocks: u64,
    /// Number of blocks processed so far
    pub blocks_processed: u64,
    /// Total outputs found so far
    pub outputs_found: usize,
    /// Total inputs found so far  
    pub inputs_found: usize,
    /// Current scanning speed in blocks per second
    pub blocks_per_sec: f64,
    /// Estimated time remaining
    pub eta: Option<std::time::Duration>,
}

impl ProgressData {
    /// Create new progress data
    pub fn new(
        current_block: u64,
        total_blocks: u64,
        blocks_processed: u64,
        outputs_found: usize,
        inputs_found: usize,
        blocks_per_sec: f64,
        eta: Option<std::time::Duration>,
    ) -> Self {
        Self {
            current_block,
            total_blocks,
            blocks_processed,
            outputs_found,
            inputs_found,
            blocks_per_sec,
            eta,
        }
    }

    /// Calculate progress percentage
    pub fn progress_percent(&self) -> f64 {
        if self.total_blocks == 0 {
            0.0
        } else {
            (self.blocks_processed as f64 / self.total_blocks as f64) * 100.0
        }
    }
}

/// Scan completion data
#[derive(Debug, Clone)]
pub struct CompletionData {
    /// Range of blocks that were scanned
    pub from_block: u64,
    pub to_block: u64,
    /// Total blocks processed
    pub blocks_processed: usize,
    /// Whether the scan completed successfully or was interrupted
    pub interrupted: bool,
    /// Total time taken for the scan
    pub duration: Option<std::time::Duration>,
    /// Final transaction count
    pub total_transactions: usize,
}

impl CompletionData {
    /// Create new completion data
    pub fn new(
        from_block: u64,
        to_block: u64,
        blocks_processed: usize,
        interrupted: bool,
        duration: Option<std::time::Duration>,
        total_transactions: usize,
    ) -> Self {
        Self {
            from_block,
            to_block,
            blocks_processed,
            interrupted,
            duration,
            total_transactions,
        }
    }

    /// Check if scan completed successfully
    pub fn is_completed(&self) -> bool {
        !self.interrupted
    }
}

/// Generic data processor trait for handling scanning data
///
/// This trait allows different implementations to handle the data generated
/// during wallet scanning operations. Implementations can:
/// - Store data to a database
/// - Write data to files  
/// - Send data over a network
/// - Process data in memory only
/// - Forward data to multiple processors
///
/// # Examples
///
/// ```rust,ignore
/// use crate::scanning::{DataProcessor, BlockData};
///
/// struct DatabaseProcessor {
///     // database connection
/// }
///
/// impl DataProcessor for DatabaseProcessor {
///     async fn process_block(&mut self, block_data: BlockData) -> LightweightWalletResult<()> {
///         // Save transactions to database
///         for transaction in block_data.transactions {
///             self.save_transaction(transaction).await?;
///         }
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait DataProcessor: Send + Sync {
    /// Process block data (transactions found in a block)
    ///
    /// This method is called for each block processed during scanning,
    /// regardless of whether wallet activity was found.
    async fn process_block(&mut self, block_data: BlockData) -> WalletResult<()>;

    /// Process progress updates (optional)
    ///
    /// This method is called periodically to report scanning progress.
    /// The default implementation does nothing.
    async fn process_progress(&mut self, _progress_data: ProgressData) -> WalletResult<()> {
        Ok(())
    }

    /// Process scan completion (optional)
    ///
    /// This method is called when scanning completes or is interrupted.
    /// The default implementation does nothing.
    async fn process_completion(&mut self, _completion_data: CompletionData) -> WalletResult<()> {
        Ok(())
    }

    /// Initialize the processor (optional)
    ///
    /// This method is called before scanning begins.
    /// The default implementation does nothing.
    async fn initialize(&mut self) -> WalletResult<()> {
        Ok(())
    }

    /// Finalize the processor (optional)
    ///
    /// This method is called after scanning ends, regardless of success or failure.
    /// The default implementation does nothing.
    async fn finalize(&mut self) -> WalletResult<()> {
        Ok(())
    }

    /// Allow downcasting to concrete types
    ///
    /// This enables type-specific operations during post-processing.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// A simple in-memory data processor that collects all data
///
/// Useful for testing or when you want to collect all scan results in memory.
#[derive(Debug, Default)]
pub struct MemoryDataProcessor {
    /// All block data processed
    pub blocks: Vec<BlockData>,
    /// All progress updates received
    pub progress_updates: Vec<ProgressData>,
    /// Completion data if available
    pub completion: Option<CompletionData>,
}

impl MemoryDataProcessor {
    /// Create a new memory data processor
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all transactions from processed blocks
    pub fn get_all_transactions(&self) -> Vec<&WalletTransaction> {
        self.blocks
            .iter()
            .flat_map(|block| &block.transactions)
            .collect()
    }

    /// Get total number of transactions processed
    pub fn total_transactions(&self) -> usize {
        self.blocks
            .iter()
            .map(|block| block.transactions.len())
            .sum()
    }

    /// Get blocks with wallet activity
    pub fn get_active_blocks(&self) -> Vec<&BlockData> {
        self.blocks
            .iter()
            .filter(|block| block.has_activity())
            .collect()
    }

    /// Clear all collected data
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.progress_updates.clear();
        self.completion = None;
    }
}

#[async_trait]
impl DataProcessor for MemoryDataProcessor {
    async fn process_block(&mut self, block_data: BlockData) -> WalletResult<()> {
        self.blocks.push(block_data);
        Ok(())
    }

    async fn process_progress(&mut self, progress_data: ProgressData) -> WalletResult<()> {
        self.progress_updates.push(progress_data);
        Ok(())
    }

    async fn process_completion(&mut self, completion_data: CompletionData) -> WalletResult<()> {
        self.completion = Some(completion_data);
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A no-op data processor that discards all data
///
/// Useful for benchmarking or when you only care about the side effects of scanning.
#[derive(Debug, Default)]
pub struct NoOpDataProcessor;

impl NoOpDataProcessor {
    /// Create a new no-op data processor
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl DataProcessor for NoOpDataProcessor {
    async fn process_block(&mut self, _block_data: BlockData) -> WalletResult<()> {
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A composition processor that forwards data to multiple processors
///
/// Useful when you want to process data in multiple ways simultaneously
/// (e.g., save to database AND log to file).
pub struct CompositeDataProcessor {
    processors: Vec<Box<dyn DataProcessor>>,
}

impl CompositeDataProcessor {
    /// Create a new composite processor
    pub fn new() -> Self {
        Self {
            processors: Vec::new(),
        }
    }

    /// Add a processor to the composition
    pub fn add_processor(mut self, processor: Box<dyn DataProcessor>) -> Self {
        self.processors.push(processor);
        self
    }

    /// Add multiple processors to the composition
    pub fn add_processors(mut self, processors: Vec<Box<dyn DataProcessor>>) -> Self {
        self.processors.extend(processors);
        self
    }
}

#[async_trait]
impl DataProcessor for CompositeDataProcessor {
    async fn process_block(&mut self, block_data: BlockData) -> WalletResult<()> {
        for processor in &mut self.processors {
            processor.process_block(block_data.clone()).await?;
        }
        Ok(())
    }

    async fn process_progress(&mut self, progress_data: ProgressData) -> WalletResult<()> {
        for processor in &mut self.processors {
            processor.process_progress(progress_data.clone()).await?;
        }
        Ok(())
    }

    async fn process_completion(&mut self, completion_data: CompletionData) -> WalletResult<()> {
        for processor in &mut self.processors {
            processor
                .process_completion(completion_data.clone())
                .await?;
        }
        Ok(())
    }

    async fn initialize(&mut self) -> WalletResult<()> {
        for processor in &mut self.processors {
            processor.initialize().await?;
        }
        Ok(())
    }

    async fn finalize(&mut self) -> WalletResult<()> {
        for processor in &mut self.processors {
            processor.finalize().await?;
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Default for CompositeDataProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_data_creation() {
        let block_data = BlockData::new(1000, "hash123".to_string(), 1234567890, Vec::new(), true);

        assert_eq!(block_data.height, 1000);
        assert_eq!(block_data.hash, "hash123");
        assert_eq!(block_data.timestamp, 1234567890);
        assert!(!block_data.has_activity());
        assert_eq!(block_data.transaction_count(), 0);
        assert!(block_data.completed);
    }

    #[test]
    fn test_block_data_empty() {
        let block_data = BlockData::empty(1000, "hash123".to_string(), 1234567890);

        assert_eq!(block_data.height, 1000);
        assert!(!block_data.has_activity());
        assert!(block_data.completed);
    }

    #[test]
    fn test_progress_data_creation() {
        let progress_data = ProgressData::new(1000, 2000, 500, 10, 5, 2.5, None);

        assert_eq!(progress_data.current_block, 1000);
        assert_eq!(progress_data.total_blocks, 2000);
        assert_eq!(progress_data.blocks_processed, 500);
        assert_eq!(progress_data.progress_percent(), 25.0);
    }

    #[test]
    fn test_progress_data_zero_total() {
        let progress_data = ProgressData::new(0, 0, 0, 0, 0, 0.0, None);
        assert_eq!(progress_data.progress_percent(), 0.0);
    }

    #[test]
    fn test_completion_data_creation() {
        let completion_data = CompletionData::new(1000, 2000, 1001, false, None, 42);

        assert_eq!(completion_data.from_block, 1000);
        assert_eq!(completion_data.to_block, 2000);
        assert_eq!(completion_data.blocks_processed, 1001);
        assert!(!completion_data.interrupted);
        assert!(completion_data.is_completed());
        assert_eq!(completion_data.total_transactions, 42);
    }

    #[tokio::test]
    async fn test_memory_data_processor() {
        let mut processor = MemoryDataProcessor::new();

        // Test block processing
        let block_data = BlockData::empty(1000, "hash123".to_string(), 1234567890);
        processor.process_block(block_data).await.unwrap();

        assert_eq!(processor.blocks.len(), 1);
        assert_eq!(processor.total_transactions(), 0);

        // Test progress processing
        let progress_data = ProgressData::new(1000, 2000, 500, 10, 5, 2.5, None);
        processor.process_progress(progress_data).await.unwrap();

        assert_eq!(processor.progress_updates.len(), 1);

        // Test completion processing
        let completion_data = CompletionData::new(1000, 2000, 1001, false, None, 0);
        processor.process_completion(completion_data).await.unwrap();

        assert!(processor.completion.is_some());
        assert!(processor.completion.as_ref().unwrap().is_completed());
    }

    #[tokio::test]
    async fn test_no_op_data_processor() {
        let mut processor = NoOpDataProcessor::new();

        // Should not fail and do nothing
        let block_data = BlockData::empty(1000, "hash123".to_string(), 1234567890);
        processor.process_block(block_data).await.unwrap();

        let progress_data = ProgressData::new(1000, 2000, 500, 10, 5, 2.5, None);
        processor.process_progress(progress_data).await.unwrap();

        let completion_data = CompletionData::new(1000, 2000, 1001, false, None, 0);
        processor.process_completion(completion_data).await.unwrap();
    }

    #[tokio::test]
    async fn test_composite_data_processor() {
        let mut processor = CompositeDataProcessor::new()
            .add_processor(Box::new(MemoryDataProcessor::new()))
            .add_processor(Box::new(NoOpDataProcessor::new()));

        let block_data = BlockData::empty(1000, "hash123".to_string(), 1234567890);
        processor.process_block(block_data).await.unwrap();

        // Should succeed for all processors
    }
}
