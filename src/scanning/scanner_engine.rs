//! Core scanning engine that orchestrates blockchain scanning operations
//!
//! This module provides the `ScannerEngine` struct which acts as the main interface
//! for coordinating wallet initialization, blockchain scanning, and result aggregation.

use crate::data_structures::wallet_transaction::WalletState;
use crate::errors::{LightweightWalletError, LightweightWalletResult};
use crate::extraction::ExtractionConfig;
#[cfg(target_arch = "wasm32")]
use js_sys;
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;

#[cfg(feature = "storage")]
use super::storage_manager::{ScannerStorageConfig, StorageManager};

/// Get current time for timing measurements
#[cfg(not(target_arch = "wasm32"))]
fn get_current_time() -> Instant {
    Instant::now()
}

/// Get current time for timing measurements (WASM version)
#[cfg(target_arch = "wasm32")]
fn get_current_time() -> f64 {
    js_sys::Date::now()
}

/// Error recovery strategy for handling scanning errors
#[derive(Debug, Clone, PartialEq)]
pub enum ErrorRecoveryStrategy {
    /// Continue scanning despite errors
    Continue,
    /// Skip the current batch/block and continue
    Skip,
    /// Abort the entire scan
    Abort,
}

/// Error context information for recovery decisions
#[derive(Debug, Clone)]
pub struct ScanErrorContext {
    /// Block height where error occurred
    pub block_height: u64,
    /// Error that occurred
    pub error: String,
    /// Whether scanning specific blocks or a range
    pub has_specific_blocks: bool,
    /// Remaining blocks to scan
    pub remaining_blocks: Vec<u64>,
    /// End block of the scan range
    pub to_block: u64,
}

/// Trait for handling scan errors and recovery
pub trait ErrorHandler: Send + Sync {
    /// Handle a scan error and return recovery strategy
    fn handle_scan_error(&self, context: &ScanErrorContext) -> ErrorRecoveryStrategy;

    /// Handle block processing error and return recovery strategy
    fn handle_block_error(&self, block_height: u64, error: &str) -> ErrorRecoveryStrategy;

    /// Generate resume command for interrupted scans
    fn generate_resume_command(&self, context: &ScanErrorContext) -> String;
}

/// Default error handler that continues on errors without interaction
pub struct DefaultErrorHandler;

impl ErrorHandler for DefaultErrorHandler {
    fn handle_scan_error(&self, context: &ScanErrorContext) -> ErrorRecoveryStrategy {
        eprintln!(
            "Error scanning batch starting at block {}: {}",
            context.block_height, context.error
        );
        eprintln!("Continuing to next batch...");
        ErrorRecoveryStrategy::Continue
    }

    fn handle_block_error(&self, block_height: u64, error: &str) -> ErrorRecoveryStrategy {
        eprintln!("Error processing block {}: {}", block_height, error);
        eprintln!("Continuing to next block...");
        ErrorRecoveryStrategy::Continue
    }

    fn generate_resume_command(&self, context: &ScanErrorContext) -> String {
        if context.has_specific_blocks && context.remaining_blocks.len() <= 20 {
            let remaining_blocks_str: Vec<String> = context
                .remaining_blocks
                .iter()
                .map(|b| b.to_string())
                .collect();
            format!("cargo run --bin scanner --features grpc-storage -- --seed-phrase \"your seed phrase\" --blocks {}", 
                remaining_blocks_str.join(","))
        } else {
            format!("cargo run --bin scanner --features grpc-storage -- --seed-phrase \"your seed phrase\" --from-block {} --to-block {}", 
                context.block_height, context.to_block)
        }
    }
}

/// Interactive error handler that prompts user for recovery decisions (CLI-compatible)
/// Note: In WASM, this behaves like DefaultErrorHandler since there's no stdin/stdout
pub struct InteractiveErrorHandler;

impl ErrorHandler for InteractiveErrorHandler {
    fn handle_scan_error(&self, context: &ScanErrorContext) -> ErrorRecoveryStrategy {
        #[cfg(not(target_arch = "wasm32"))]
        {
            println!(
                "❌ Error scanning batch starting at block {}: {}",
                context.block_height, context.error
            );
            println!(
                "   Batch heights: {:?}",
                context.remaining_blocks.iter().take(10).collect::<Vec<_>>()
            );

            print!("   Continue scanning remaining blocks? (y/n/s=skip this batch/block): ");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();

            let mut input = String::new();
            if std::io::stdin().read_line(&mut input).is_err() {
                return ErrorRecoveryStrategy::Abort;
            }
            let choice = input.trim().to_lowercase();

            match choice.as_str() {
                "y" | "yes" => {
                    println!("   ✅ Continuing scan from next batch/block...");
                    ErrorRecoveryStrategy::Continue
                }
                "s" | "skip" => {
                    println!("   ⏭️  Skipping problematic batch/block and continuing...");
                    ErrorRecoveryStrategy::Skip
                }
                _ => {
                    println!(
                        "   🛑 Scan aborted by user at block {}",
                        context.block_height
                    );
                    println!("\n💡 To resume from this point, run:");
                    println!("   {}", self.generate_resume_command(context));
                    ErrorRecoveryStrategy::Abort
                }
            }
        }

        #[cfg(target_arch = "wasm32")]
        {
            // In WASM, fall back to default behavior (continue on errors)
            DefaultErrorHandler.handle_scan_error(context)
        }
    }

    fn handle_block_error(&self, block_height: u64, error: &str) -> ErrorRecoveryStrategy {
        eprintln!("Error processing block {}: {}", block_height, error);
        ErrorRecoveryStrategy::Continue // Default to continue for block errors
    }

    fn generate_resume_command(&self, context: &ScanErrorContext) -> String {
        if context.has_specific_blocks && context.remaining_blocks.len() <= 20 {
            let remaining_blocks_str: Vec<String> = context
                .remaining_blocks
                .iter()
                .map(|b| b.to_string())
                .collect();
            format!("cargo run --bin scanner --features grpc-storage -- --seed-phrase \"your seed phrase\" --blocks {}", 
                remaining_blocks_str.join(","))
        } else {
            let first_block = context
                .remaining_blocks
                .first()
                .unwrap_or(&context.block_height);
            format!("cargo run --bin scanner --features grpc-storage -- --seed-phrase \"your seed phrase\" --from-block {} --to-block {}", 
                first_block, context.to_block)
        }
    }
}

#[cfg(feature = "grpc")]
use crate::data_structures::{block::Block, transaction::TransactionDirection};

#[cfg(any(feature = "grpc", feature = "http", target_arch = "wasm32"))]
use super::BlockchainScanner;

use super::{
    output_formatter::{OutputConfig, OutputFormatter},
    progress_reporter::{ProgressReportConfig, ProgressReporter},
    scan_results::{BlockScanResult, ScanConfigSummary, ScanPhase, ScanProgress, ScanResults},
    wallet_source::{WalletContext, WalletSource},
    ScanConfig, ScanConfiguration,
};

/// Core scanning engine that orchestrates all scanning operations
#[cfg(any(feature = "grpc", feature = "http", target_arch = "wasm32"))]
pub struct ScannerEngine {
    /// Blockchain scanner implementation
    scanner: Box<dyn BlockchainScanner>,
    /// Wallet context (optional, initialized during scanning)
    wallet_context: Option<WalletContext>,
    /// Scan configuration
    configuration: ScanConfiguration,
    /// Storage manager for persisting scan results (optional)
    #[cfg(feature = "storage")]
    storage_manager: Option<Box<dyn StorageManager>>,
    /// Storage configuration
    #[cfg(feature = "storage")]
    storage_config: ScannerStorageConfig,
    /// Progress reporter for displaying scan progress (optional)
    progress_reporter: Option<Box<dyn ProgressReporter>>,
    /// Progress reporting configuration
    progress_config: ProgressReportConfig,
    /// Output formatter for displaying results (optional)
    output_formatter: Option<Box<dyn OutputFormatter>>,
    /// Output formatting configuration
    output_config: OutputConfig,
    /// Error handler for scan error recovery (optional)
    error_handler: Option<Box<dyn ErrorHandler>>,
}

#[cfg(any(feature = "grpc", feature = "http", target_arch = "wasm32"))]
impl ScannerEngine {
    /// Create a new scanner engine with a blockchain scanner
    pub fn new(scanner: Box<dyn BlockchainScanner>, configuration: ScanConfiguration) -> Self {
        Self {
            scanner,
            wallet_context: None,
            configuration,
            #[cfg(feature = "storage")]
            storage_manager: None,
            #[cfg(feature = "storage")]
            storage_config: ScannerStorageConfig::default(),
            progress_reporter: None,
            progress_config: ProgressReportConfig::default(),
            output_formatter: None,
            output_config: OutputConfig::default(),
            error_handler: None,
        }
    }

    /// Create a new scanner engine with storage support
    #[cfg(feature = "storage")]
    pub fn new_with_storage(
        scanner: Box<dyn BlockchainScanner>,
        configuration: ScanConfiguration,
        storage_manager: Box<dyn StorageManager>,
        storage_config: ScannerStorageConfig,
    ) -> Self {
        Self {
            scanner,
            wallet_context: None,
            configuration,
            storage_manager: Some(storage_manager),
            storage_config,
            progress_reporter: None,
            progress_config: ProgressReportConfig::default(),
            output_formatter: None,
            output_config: OutputConfig::default(),
            error_handler: None,
        }
    }

    /// Set the error handler for scan error recovery
    pub fn with_error_handler(mut self, error_handler: Box<dyn ErrorHandler>) -> Self {
        self.error_handler = Some(error_handler);
        self
    }

    /// Set interactive error handler (CLI-compatible)
    pub fn with_interactive_error_handling(mut self) -> Self {
        self.error_handler = Some(Box::new(InteractiveErrorHandler));
        self
    }

    /// Set default error handler (continue on errors)
    pub fn with_default_error_handling(mut self) -> Self {
        self.error_handler = Some(Box::new(DefaultErrorHandler));
        self
    }

    /// Initialize the wallet context from the configuration
    /// Currently handles wallet sources (seed phrase, view key) from configuration.
    /// TODO: Future task should extract database wallet loading from scanner.rs
    /// to ScannerEngine for better organization (without creating new wallets)
    pub async fn initialize_wallet(&mut self) -> LightweightWalletResult<()> {
        if let Some(wallet_context) = self.configuration.initialize_wallet()? {
            self.wallet_context = Some(wallet_context);
        }
        Ok(())
    }

    /// Get a reference to the wallet context (if initialized)
    pub fn wallet_context(&self) -> Option<&WalletContext> {
        self.wallet_context.as_ref()
    }

    /// Get a mutable reference to the blockchain scanner
    pub fn scanner_mut(&mut self) -> &mut dyn BlockchainScanner {
        self.scanner.as_mut()
    }

    /// Get the current blockchain tip information
    pub async fn get_tip_info(&mut self) -> LightweightWalletResult<super::TipInfo> {
        self.scanner.get_tip_info().await
    }

    /// Scan a range of blocks using the configured parameters
    pub async fn scan_range(&mut self) -> LightweightWalletResult<ScanResults> {
        self.scan_range_with_progress(None).await
    }

    /// Scan a range of blocks with full coordination logic including storage, batch processing, and cancellation support
    #[cfg(feature = "grpc")]
    pub async fn scan_range_with_coordination(
        &mut self,
        progress_callback: Option<Arc<dyn Fn(ScanProgress) + Send + Sync>>,
        cancellation_receiver: Option<&mut tokio::sync::watch::Receiver<bool>>,
    ) -> LightweightWalletResult<ScanResults> {
        let start_time = get_current_time();

        // Determine the block range to scan
        let (start_height, end_height) = self.determine_scan_range().await?;

        // Initialize progress tracking
        let mut progress = ScanProgress::new(start_height, Some(end_height));
        progress.phase = ScanPhase::Initializing;

        // Report initial progress
        if let Some(callback) = &progress_callback {
            callback(progress.clone());
        }

        // Ensure wallet is initialized if needed
        if self.wallet_context.is_none() && self.configuration.wallet_source.is_some() {
            progress.phase = ScanPhase::Connecting;
            if let Some(callback) = &progress_callback {
                callback(progress.clone());
            }

            self.initialize_wallet().await?;
        }

        // Set up extraction config if wallet context is available
        if let Some(wallet_context) = &self.wallet_context {
            self.configuration.extraction_config =
                ExtractionConfig::with_private_key(wallet_context.view_key.clone());
        }

        // Get wallet context for scanning
        let scan_context = self.wallet_context.as_ref().ok_or_else(|| {
            LightweightWalletError::ConfigurationError(
                "No wallet context available for scanning".to_string(),
            )
        })?;

        // Create block height range
        let block_heights: Vec<u64> = (start_height..=end_height).collect();

        // Initialize wallet state for this scan
        let mut wallet_state = WalletState::new();

        // Process blocks in batches with coordination logic
        let batch_size = self.configuration.batch_size as usize;
        let mut last_saved_transaction_count = 0;

        for (batch_index, batch_heights) in block_heights.chunks(batch_size).enumerate() {
            // Check for cancellation at the start of each batch
            if let Some(ref cancel_rx) = cancellation_receiver {
                if *cancel_rx.borrow() {
                    if let Some(callback) = &progress_callback {
                        progress.phase = ScanPhase::Completed;
                        callback(progress);
                    }
                    return self.create_interrupted_results(
                        wallet_state,
                        start_height,
                        end_height,
                        start_time,
                    );
                }
            }

            let batch_start_index = batch_index * batch_size;

            // Update progress for batch scanning
            progress.phase = ScanPhase::Scanning {
                batch_index: batch_index + 1,
                total_batches: Some((block_heights.len() + batch_size - 1) / batch_size),
            };
            progress.current_height = batch_heights[0];
            if let Some(callback) = &progress_callback {
                callback(progress.clone());
            }

            // Fetch blocks via scanner
            let batch_results = match self
                .scanner
                .get_blocks_by_heights(batch_heights.to_vec())
                .await
            {
                Ok(blocks) => blocks,
                Err(e) => {
                    // Use error handler for scan error recovery
                    let remaining_blocks = block_heights[batch_start_index..].to_vec();
                    let context = ScanErrorContext {
                        block_height: batch_heights[0],
                        error: e.to_string(),
                        has_specific_blocks: false, // TODO: Extract from configuration
                        remaining_blocks,
                        to_block: end_height,
                    };

                    let strategy = if let Some(error_handler) = &self.error_handler {
                        error_handler.handle_scan_error(&context)
                    } else {
                        // Fallback to default behavior
                        DefaultErrorHandler.handle_scan_error(&context)
                    };

                    match strategy {
                        ErrorRecoveryStrategy::Continue => continue,
                        ErrorRecoveryStrategy::Skip => continue,
                        ErrorRecoveryStrategy::Abort => {
                            return Err(e);
                        }
                    }
                }
            };

            // Process each block in the batch
            for block_height in batch_heights.iter() {
                // Find the corresponding block info from the batch results
                let block_info = match batch_results.iter().find(|b| b.height == *block_height) {
                    Some(block) => block.clone(),
                    None => {
                        eprintln!("Block {} not found in batch, skipping...", block_height);
                        continue;
                    }
                };

                // Process block using the Block struct
                let block = Block::from_block_info(block_info);

                // Convert 32-byte entropy to 16-byte for block processing
                let mut entropy_16 = [0u8; 16];
                entropy_16.copy_from_slice(&scan_context.entropy[..16]);

                let found_outputs =
                    block.process_outputs(&scan_context.view_key, &entropy_16, &mut wallet_state);
                let spent_outputs = block.process_inputs(&mut wallet_state);

                let scan_result = match (found_outputs, spent_outputs) {
                    (Ok(found), Ok(spent)) => Ok((found, spent)),
                    (Err(e), _) | (_, Err(e)) => Err(e),
                };

                match scan_result {
                    Ok(_result) => {
                        // Handle storage operations if storage manager is available
                        #[cfg(feature = "storage")]
                        if let Some(storage_manager) = &mut self.storage_manager {
                            if let Some(wallet_id) = self.storage_config.wallet_id {
                                // Save transactions incrementally
                                let all_transactions: Vec<_> = wallet_state.transactions.to_vec();
                                if all_transactions.len() > last_saved_transaction_count {
                                    let new_transactions =
                                        &all_transactions[last_saved_transaction_count..];
                                    if !new_transactions.is_empty() {
                                        if let Err(e) = storage_manager
                                            .save_transactions_incremental(
                                                wallet_id,
                                                new_transactions,
                                                None,
                                            )
                                            .await
                                        {
                                            eprintln!("Warning: Failed to save transactions to storage: {}", e);
                                        } else {
                                            last_saved_transaction_count = all_transactions.len();
                                        }
                                    }
                                }

                                // Mark spent outputs in storage
                                let wallet_has_spent_transactions =
                                    wallet_state.transactions.iter().any(|tx| tx.is_spent);
                                if wallet_has_spent_transactions && !block.inputs.is_empty() {
                                    let wallet_commitments: std::collections::HashSet<_> =
                                        wallet_state
                                            .transactions
                                            .iter()
                                            .filter(|tx| tx.is_spent)
                                            .map(|tx| tx.commitment.as_bytes().to_vec())
                                            .collect();

                                    let mut batch_spent_commitments = Vec::new();
                                    for input in &block.inputs {
                                        let input_commitment = input.commitment.to_vec();
                                        if wallet_commitments.contains(&input_commitment) {
                                            batch_spent_commitments
                                                .push((input_commitment, *block_height));
                                        }
                                    }

                                    if !batch_spent_commitments.is_empty() {
                                        if let Err(e) = storage_manager
                                            .mark_outputs_spent_batch(&batch_spent_commitments)
                                            .await
                                        {
                                            eprintln!(
                                                "Warning: Failed to mark outputs as spent: {}",
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // Use error handler for block processing error recovery
                        let strategy = if let Some(error_handler) = &self.error_handler {
                            error_handler.handle_block_error(*block_height, &e.to_string())
                        } else {
                            // Fallback to default behavior
                            DefaultErrorHandler.handle_block_error(*block_height, &e.to_string())
                        };

                        match strategy {
                            ErrorRecoveryStrategy::Continue => continue,
                            ErrorRecoveryStrategy::Skip => continue,
                            ErrorRecoveryStrategy::Abort => {
                                return Err(e);
                            }
                        }
                    }
                }
            }

            // Update storage with latest scanned block
            #[cfg(feature = "storage")]
            if let Some(storage_manager) = &mut self.storage_manager {
                if let (Some(wallet_id), Some(last_block_height)) =
                    (self.storage_config.wallet_id, batch_heights.last())
                {
                    if let Err(e) = storage_manager
                        .update_scanned_block(wallet_id, *last_block_height)
                        .await
                    {
                        eprintln!("Warning: Failed to update scanned block: {}", e);
                    }
                }
            }

            // Update progress after processing batch
            progress.current_height = *batch_heights.last().unwrap_or(&start_height);
            progress.blocks_scanned = (batch_start_index + batch_heights.len()) as u64;
            if let Some(callback) = &progress_callback {
                callback(progress.clone());
            }
        }

        // Final storage update
        #[cfg(feature = "storage")]
        if let Some(storage_manager) = &mut self.storage_manager {
            if let Some(wallet_id) = self.storage_config.wallet_id {
                if let Err(e) = storage_manager
                    .update_scanned_block(wallet_id, end_height)
                    .await
                {
                    eprintln!("Warning: Failed to final update scanned block: {}", e);
                }
            }
        }

        // Create final scan results
        let scan_results = self.aggregate_results(
            start_height,
            Some(end_height),
            None,
            vec![], // TODO: Convert wallet_state to BlockScanResult
            start_time,
        )?;

        // Final progress update
        progress.current_height = end_height;
        progress.phase = ScanPhase::Completed;
        if let Some(callback) = &progress_callback {
            callback(progress);
        }

        Ok(scan_results)
    }

    /// Scan a range of blocks with progress reporting
    pub async fn scan_range_with_progress(
        &mut self,
        progress_callback: Option<Arc<dyn Fn(ScanProgress) + Send + Sync>>,
    ) -> LightweightWalletResult<ScanResults> {
        let start_time = get_current_time();

        // Determine the block range to scan
        let (start_height, end_height) = self.determine_scan_range().await?;

        // Initialize progress tracking
        let mut progress = ScanProgress::new(start_height, Some(end_height));
        progress.phase = ScanPhase::Initializing;

        // Report initial progress
        if let Some(callback) = &progress_callback {
            callback(progress.clone());
        }

        // Ensure wallet is initialized if needed
        if self.wallet_context.is_none() && self.configuration.wallet_source.is_some() {
            progress.phase = ScanPhase::Connecting;
            if let Some(callback) = &progress_callback {
                callback(progress.clone());
            }

            self.initialize_wallet().await?;
        }

        // Set up extraction config if wallet context is available
        if let Some(wallet_context) = &self.wallet_context {
            self.configuration.extraction_config =
                ExtractionConfig::with_private_key(wallet_context.view_key.clone());
        }

        // Create scan config for the blockchain scanner
        let scan_config = self.create_scan_config(start_height, Some(end_height))?;

        // Perform the actual scanning
        progress.phase = ScanPhase::Scanning {
            batch_index: 0,
            total_batches: None,
        };
        if let Some(callback) = &progress_callback {
            callback(progress.clone());
        }

        let block_results = self
            .scan_with_progress(scan_config, progress_callback.clone())
            .await?;

        // Aggregate results
        progress.phase = ScanPhase::Processing;
        if let Some(callback) = &progress_callback {
            callback(progress.clone());
        }

        let scan_results = self.aggregate_results(
            start_height,
            Some(end_height),
            None,
            block_results,
            start_time,
        )?;

        // Final progress update
        progress.current_height = end_height;
        progress.phase = ScanPhase::Completed;
        if let Some(callback) = &progress_callback {
            callback(progress);
        }

        Ok(scan_results)
    }

    /// Scan specific blocks
    pub async fn scan_blocks(&mut self, heights: Vec<u64>) -> LightweightWalletResult<ScanResults> {
        self.scan_blocks_with_progress(heights, None).await
    }

    /// Scan specific blocks with full coordination logic including storage, progress reporting, and cancellation support
    #[cfg(feature = "grpc")]
    pub async fn scan_blocks_with_coordination(
        &mut self,
        heights: Vec<u64>,
        progress_callback: Option<Arc<dyn Fn(ScanProgress) + Send + Sync>>,
        cancellation_receiver: Option<&mut tokio::sync::watch::Receiver<bool>>,
    ) -> LightweightWalletResult<ScanResults> {
        let start_time = get_current_time();

        if heights.is_empty() {
            return Err(LightweightWalletError::InvalidArgument {
                argument: "heights".to_string(),
                value: "empty_vec".to_string(),
                message: "No block heights provided for scanning".to_string(),
            });
        }

        let start_height = *heights.iter().min().unwrap();
        let end_height = *heights.iter().max().unwrap();

        // Initialize progress tracking
        let mut progress = ScanProgress::new(start_height, Some(end_height));
        progress.phase = ScanPhase::Initializing;

        // Report initial progress
        if let Some(callback) = &progress_callback {
            callback(progress.clone());
        }

        // Ensure wallet is initialized if needed
        if self.wallet_context.is_none() && self.configuration.wallet_source.is_some() {
            self.initialize_wallet().await?;
        }

        // Set up extraction config if wallet context is available
        if let Some(wallet_context) = &self.wallet_context {
            self.configuration.extraction_config =
                ExtractionConfig::with_private_key(wallet_context.view_key.clone());
        }

        // Get wallet context for scanning
        let scan_context = self.wallet_context.as_ref().ok_or_else(|| {
            LightweightWalletError::ConfigurationError(
                "No wallet context available for scanning".to_string(),
            )
        })?;

        // Initialize wallet state for this scan
        let mut wallet_state = WalletState::new();

        // Process blocks in batches with coordination logic
        let batch_size = self.configuration.batch_size as usize;
        let mut last_saved_transaction_count = 0;

        for (batch_index, batch_heights) in heights.chunks(batch_size).enumerate() {
            // Check for cancellation at the start of each batch
            if let Some(ref cancel_rx) = cancellation_receiver {
                if *cancel_rx.borrow() {
                    if let Some(callback) = &progress_callback {
                        progress.phase = ScanPhase::Completed;
                        callback(progress);
                    }
                    return self.create_interrupted_results(
                        wallet_state,
                        start_height,
                        end_height,
                        start_time,
                    );
                }
            }

            // Update progress for batch scanning
            progress.phase = ScanPhase::Scanning {
                batch_index: batch_index + 1,
                total_batches: Some((heights.len() + batch_size - 1) / batch_size),
            };
            progress.current_height = batch_heights[0];
            if let Some(callback) = &progress_callback {
                callback(progress.clone());
            }

            // Fetch blocks via scanner
            let batch_results = match self
                .scanner
                .get_blocks_by_heights(batch_heights.to_vec())
                .await
            {
                Ok(blocks) => blocks,
                Err(e) => {
                    // Use error handler for scan error recovery
                    let batch_start_index = batch_index * batch_size;
                    let remaining_blocks = heights[batch_start_index..].to_vec();
                    let context = ScanErrorContext {
                        block_height: batch_heights[0],
                        error: e.to_string(),
                        has_specific_blocks: true, // scan_blocks is for specific blocks
                        remaining_blocks,
                        to_block: end_height,
                    };

                    let strategy = if let Some(error_handler) = &self.error_handler {
                        error_handler.handle_scan_error(&context)
                    } else {
                        // Fallback to default behavior
                        DefaultErrorHandler.handle_scan_error(&context)
                    };

                    match strategy {
                        ErrorRecoveryStrategy::Continue => continue,
                        ErrorRecoveryStrategy::Skip => continue,
                        ErrorRecoveryStrategy::Abort => {
                            return Err(e);
                        }
                    }
                }
            };

            // Process each block in the batch
            for block_height in batch_heights.iter() {
                // Find the corresponding block info from the batch results
                let block_info = match batch_results.iter().find(|b| b.height == *block_height) {
                    Some(block) => block.clone(),
                    None => {
                        eprintln!("Block {} not found in batch, skipping...", block_height);
                        continue;
                    }
                };

                // Process block using the Block struct
                let block = Block::from_block_info(block_info);

                // Convert 32-byte entropy to 16-byte for block processing
                let mut entropy_16 = [0u8; 16];
                entropy_16.copy_from_slice(&scan_context.entropy[..16]);

                let found_outputs =
                    block.process_outputs(&scan_context.view_key, &entropy_16, &mut wallet_state);
                let spent_outputs = block.process_inputs(&mut wallet_state);

                let scan_result = match (found_outputs, spent_outputs) {
                    (Ok(found), Ok(spent)) => Ok((found, spent)),
                    (Err(e), _) | (_, Err(e)) => Err(e),
                };

                match scan_result {
                    Ok(_result) => {
                        // Handle storage operations if storage manager is available
                        #[cfg(feature = "storage")]
                        if let Some(storage_manager) = &mut self.storage_manager {
                            if let Some(wallet_id) = self.storage_config.wallet_id {
                                // Save transactions incrementally
                                let all_transactions: Vec<_> = wallet_state.transactions.to_vec();
                                if all_transactions.len() > last_saved_transaction_count {
                                    let new_transactions =
                                        &all_transactions[last_saved_transaction_count..];
                                    if !new_transactions.is_empty() {
                                        if let Err(e) = storage_manager
                                            .save_transactions_incremental(
                                                wallet_id,
                                                new_transactions,
                                                None,
                                            )
                                            .await
                                        {
                                            eprintln!("Warning: Failed to save transactions to storage: {}", e);
                                        } else {
                                            last_saved_transaction_count = all_transactions.len();
                                        }
                                    }
                                }

                                // Mark spent outputs in storage
                                let wallet_has_spent_transactions =
                                    wallet_state.transactions.iter().any(|tx| tx.is_spent);
                                if wallet_has_spent_transactions && !block.inputs.is_empty() {
                                    let wallet_commitments: std::collections::HashSet<_> =
                                        wallet_state
                                            .transactions
                                            .iter()
                                            .filter(|tx| tx.is_spent)
                                            .map(|tx| tx.commitment.as_bytes().to_vec())
                                            .collect();

                                    let mut batch_spent_commitments = Vec::new();
                                    for input in &block.inputs {
                                        let input_commitment = input.commitment.to_vec();
                                        if wallet_commitments.contains(&input_commitment) {
                                            batch_spent_commitments
                                                .push((input_commitment, *block_height));
                                        }
                                    }

                                    if !batch_spent_commitments.is_empty() {
                                        if let Err(e) = storage_manager
                                            .mark_outputs_spent_batch(&batch_spent_commitments)
                                            .await
                                        {
                                            eprintln!(
                                                "Warning: Failed to mark outputs as spent: {}",
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // Use error handler for block processing error recovery
                        let strategy = if let Some(error_handler) = &self.error_handler {
                            error_handler.handle_block_error(*block_height, &e.to_string())
                        } else {
                            // Fallback to default behavior
                            DefaultErrorHandler.handle_block_error(*block_height, &e.to_string())
                        };

                        match strategy {
                            ErrorRecoveryStrategy::Continue => continue,
                            ErrorRecoveryStrategy::Skip => continue,
                            ErrorRecoveryStrategy::Abort => {
                                return Err(e);
                            }
                        }
                    }
                }
            }

            // Update progress after processing batch
            progress.current_height = *batch_heights.last().unwrap_or(&start_height);
            progress.blocks_scanned = ((batch_index + 1) * batch_size).min(heights.len()) as u64;
            if let Some(callback) = &progress_callback {
                callback(progress.clone());
            }
        }

        // Final storage update
        #[cfg(feature = "storage")]
        if let Some(storage_manager) = &mut self.storage_manager {
            if let Some(wallet_id) = self.storage_config.wallet_id {
                if let Err(e) = storage_manager
                    .update_scanned_block(wallet_id, end_height)
                    .await
                {
                    eprintln!("Warning: Failed to final update scanned block: {}", e);
                }
            }
        }

        // Create final scan results
        let scan_results = self.aggregate_results(
            start_height,
            Some(end_height),
            Some(heights),
            vec![], // TODO: Convert wallet_state to BlockScanResult
            start_time,
        )?;

        // Final progress update
        progress.current_height = end_height;
        progress.phase = ScanPhase::Completed;
        if let Some(callback) = &progress_callback {
            callback(progress);
        }

        Ok(scan_results)
    }

    /// Scan specific blocks with progress reporting
    pub async fn scan_blocks_with_progress(
        &mut self,
        heights: Vec<u64>,
        progress_callback: Option<Arc<dyn Fn(ScanProgress) + Send + Sync>>,
    ) -> LightweightWalletResult<ScanResults> {
        let start_time = get_current_time();

        if heights.is_empty() {
            eprintln!("DEBUG: ScannerEngine.scan_blocks_with_progress - no heights provided");
            return Err(LightweightWalletError::InvalidArgument {
                argument: "heights".to_string(),
                value: "empty_vec".to_string(),
                message: "No block heights provided for scanning".to_string(),
            });
        }

        eprintln!(
            "DEBUG: ScannerEngine.scan_blocks_with_progress - scanning {} heights from {} to {}",
            heights.len(),
            heights.iter().min().unwrap(),
            heights.iter().max().unwrap()
        );

        let start_height = *heights.iter().min().unwrap();
        let end_height = *heights.iter().max().unwrap();

        // Initialize progress tracking
        let mut progress = ScanProgress::new(start_height, Some(end_height));
        progress.phase = ScanPhase::Initializing;

        // Report initial progress
        if let Some(callback) = &progress_callback {
            callback(progress.clone());
        }

        // Ensure wallet is initialized if needed
        if self.wallet_context.is_none() && self.configuration.wallet_source.is_some() {
            self.initialize_wallet().await?;
        }

        // Set up extraction config if wallet context is available
        if let Some(wallet_context) = &self.wallet_context {
            self.configuration.extraction_config =
                ExtractionConfig::with_private_key(wallet_context.view_key.clone());
        }

        // Get blocks from the blockchain scanner
        progress.phase = ScanPhase::Connecting;
        if let Some(callback) = &progress_callback {
            callback(progress.clone());
        }

        let blocks = self.scanner.get_blocks_by_heights(heights.clone()).await?;

        // Process the blocks
        progress.phase = ScanPhase::Processing;
        if let Some(callback) = &progress_callback {
            callback(progress.clone());
        }

        let scanner_results = super::DefaultScanningLogic::process_blocks(
            blocks,
            &self.configuration.extraction_config,
        )?;

        // Convert scanner BlockScanResult to scan_results BlockScanResult
        let block_results = scanner_results
            .into_iter()
            .map(|scanner_result| {
                BlockScanResult {
                    height: scanner_result.height,
                    block_hash: scanner_result.block_hash,
                    outputs: scanner_result.outputs,
                    wallet_outputs: scanner_result.wallet_outputs,
                    mined_timestamp: scanner_result.mined_timestamp,
                    transaction_count: 0, // Not provided by scanner
                    #[cfg(target_arch = "wasm32")]
                    processing_time_seconds: None, // Not tracked yet
                    #[cfg(not(target_arch = "wasm32"))]
                    processing_time: None, // Not tracked yet
                    errors: vec![],       // Not tracked yet
                }
            })
            .collect();

        // Aggregate results
        let scan_results = self.aggregate_results(
            start_height,
            Some(end_height),
            Some(heights),
            block_results,
            start_time,
        )?;

        // Final progress update
        progress.current_height = end_height;
        progress.phase = ScanPhase::Completed;
        if let Some(callback) = &progress_callback {
            callback(progress);
        }

        Ok(scan_results)
    }

    /// Scan for specific UTXOs by commitment
    pub async fn search_utxos(
        &mut self,
        commitments: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<ScanResults> {
        let start_time = get_current_time();

        let scanner_results = self.scanner.search_utxos(commitments).await?;

        // Convert scanner BlockScanResult to scan_results BlockScanResult
        let block_results = scanner_results
            .into_iter()
            .map(|scanner_result| {
                BlockScanResult {
                    height: scanner_result.height,
                    block_hash: scanner_result.block_hash,
                    outputs: scanner_result.outputs,
                    wallet_outputs: scanner_result.wallet_outputs,
                    mined_timestamp: scanner_result.mined_timestamp,
                    transaction_count: 0, // Not provided by scanner
                    #[cfg(target_arch = "wasm32")]
                    processing_time_seconds: None, // Not tracked yet
                    #[cfg(not(target_arch = "wasm32"))]
                    processing_time: None, // Not tracked yet
                    errors: vec![],       // Not tracked yet
                }
            })
            .collect();

        // For UTXO search, we don't have a specific height range
        let scan_results = self.aggregate_results(0, None, None, block_results, start_time)?;

        Ok(scan_results)
    }

    /// Determine the scan range based on configuration
    async fn determine_scan_range(&mut self) -> LightweightWalletResult<(u64, u64)> {
        let start_height = self.configuration.start_height;

        let end_height = match self.configuration.end_height {
            Some(end) => end,
            None => {
                // Get current tip if no end height specified
                let tip_info = self.scanner.get_tip_info().await?;
                tip_info.best_block_height
            }
        };

        if start_height > end_height {
            return Err(LightweightWalletError::InvalidArgument {
                argument: "start_height".to_string(),
                value: start_height.to_string(),
                message: format!(
                    "Start height {} is greater than end height {}",
                    start_height, end_height
                ),
            });
        }

        Ok((start_height, end_height))
    }

    /// Create a scan config for the blockchain scanner
    fn create_scan_config(
        &self,
        start_height: u64,
        end_height: Option<u64>,
    ) -> LightweightWalletResult<ScanConfig> {
        Ok(ScanConfig {
            start_height,
            end_height,
            batch_size: self.configuration.batch_size,
            request_timeout: self.configuration.request_timeout,
            extraction_config: self.configuration.extraction_config.clone(),
        })
    }

    /// Perform scanning with progress reporting
    async fn scan_with_progress(
        &mut self,
        scan_config: ScanConfig,
        progress_callback: Option<Arc<dyn Fn(ScanProgress) + Send + Sync>>,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
        // Convert Arc callback to the format expected by the scanner
        let callback_fn: Option<super::ProgressCallback> = progress_callback.map(|cb| {
            Box::new(move |old_progress: super::ScanProgress| {
                // Convert simple scanning::ScanProgress to comprehensive scan_results::ScanProgress
                let new_progress = ScanProgress {
                    current_height: old_progress.current_height,
                    target_height: Some(old_progress.target_height),
                    blocks_scanned: 0,  // Not available in simple version
                    total_blocks: None, // Will be calculated
                    outputs_found: old_progress.outputs_found,
                    outputs_spent: 0, // Not available in simple version
                    total_value: old_progress.total_value,
                    scan_rate: 0.0, // Not available in simple version
                    #[cfg(target_arch = "wasm32")]
                    elapsed_seconds: old_progress.elapsed.as_secs_f64(),
                    #[cfg(not(target_arch = "wasm32"))]
                    elapsed: old_progress.elapsed,
                    #[cfg(target_arch = "wasm32")]
                    estimated_remaining_seconds: None, // Not available in simple version
                    #[cfg(not(target_arch = "wasm32"))]
                    estimated_remaining: None, // Not available in simple version
                    phase: ScanPhase::Scanning {
                        batch_index: 0,
                        total_batches: None,
                    },
                };
                cb(new_progress);
            }) as super::ProgressCallback
        });

        let config_with_callback = if let Some(callback) = callback_fn {
            scan_config.with_progress_callback(callback)
        } else {
            super::ScanConfigWithCallback {
                config: scan_config,
                progress_callback: None,
            }
        };

        let scanner_results = self
            .scanner
            .scan_blocks(config_with_callback.config)
            .await?;

        // Convert scanner BlockScanResult to scan_results BlockScanResult
        let converted_results = scanner_results
            .into_iter()
            .map(|scanner_result| {
                BlockScanResult {
                    height: scanner_result.height,
                    block_hash: scanner_result.block_hash,
                    outputs: scanner_result.outputs,
                    wallet_outputs: scanner_result.wallet_outputs,
                    mined_timestamp: scanner_result.mined_timestamp,
                    transaction_count: 0, // Not provided by scanner
                    #[cfg(target_arch = "wasm32")]
                    processing_time_seconds: None, // Not tracked yet
                    #[cfg(not(target_arch = "wasm32"))]
                    processing_time: None, // Not tracked yet
                    errors: vec![],       // Not tracked yet
                }
            })
            .collect();

        Ok(converted_results)
    }

    /// Aggregate scan results from block results
    fn aggregate_results(
        &self,
        start_height: u64,
        end_height: Option<u64>,
        specific_blocks: Option<Vec<u64>>,
        block_results: Vec<BlockScanResult>,
        #[cfg(target_arch = "wasm32")] start_time: f64,
        #[cfg(not(target_arch = "wasm32"))] start_time: Instant,
    ) -> LightweightWalletResult<ScanResults> {
        // Calculate summary statistics
        let total_outputs = block_results
            .iter()
            .map(|r| r.wallet_outputs.len() as u64)
            .sum();

        let total_value = block_results
            .iter()
            .flat_map(|r| &r.wallet_outputs)
            .map(|wo| wo.value().as_u64())
            .sum();

        let blocks_scanned = block_results.len() as u64;

        // Create configuration summary
        let config_summary = ScanConfigSummary {
            start_height,
            end_height,
            specific_blocks,
            batch_size: self.configuration.batch_size,
            total_blocks_scanned: blocks_scanned,
        };

        // Create wallet state from results
        let wallet_state = WalletState::new();
        // TODO: Implement proper wallet state integration with scan results
        // This requires extending LightweightWalletOutput to include commitment information
        // or creating a mapping between wallet outputs and transactions

        // Create final progress
        let current_height = end_height.unwrap_or(start_height);
        let mut progress = ScanProgress::new(start_height, end_height);
        progress.current_height = current_height;
        progress.outputs_found = total_outputs;
        progress.total_value = total_value;
        progress.blocks_scanned = blocks_scanned;
        progress.phase = ScanPhase::Completed;

        // Create and return scan results
        let mut scan_results = ScanResults::new(config_summary, wallet_state, progress, start_time);

        // Add block results
        scan_results.add_block_results(block_results);

        Ok(scan_results)
    }

    /// Create scan results for interrupted scans
    #[cfg(feature = "grpc")]
    fn create_interrupted_results(
        &self,
        wallet_state: WalletState,
        start_height: u64,
        end_height: u64,
        start_time: Instant,
    ) -> LightweightWalletResult<ScanResults> {
        // Calculate partial results from the wallet state
        let total_outputs = wallet_state.transactions.len() as u64;
        let total_value = wallet_state
            .transactions
            .iter()
            .filter(|tx| tx.transaction_direction == TransactionDirection::Inbound)
            .map(|tx| tx.value)
            .sum();

        // Create configuration summary
        let config_summary = super::scan_results::ScanConfigSummary {
            start_height,
            end_height: Some(end_height),
            specific_blocks: None,
            batch_size: self.configuration.batch_size,
            total_blocks_scanned: 0, // Will be updated based on progress
        };

        // Create progress for interrupted scan
        let mut progress = ScanProgress::new(start_height, Some(end_height));
        progress.outputs_found = total_outputs;
        progress.total_value = total_value;
        progress.phase = ScanPhase::Completed; // Mark as completed (interrupted)

        // Create and return scan results
        let scan_results = ScanResults::new(config_summary, wallet_state, progress, start_time);

        Ok(scan_results)
    }

    /// Update the scanner configuration
    pub fn update_configuration(&mut self, configuration: ScanConfiguration) {
        self.configuration = configuration;
        // Reset wallet context if wallet source changed
        if self.configuration.wallet_source.is_some() {
            self.wallet_context = None;
        }
    }

    /// Get a reference to the current configuration
    pub fn configuration(&self) -> &ScanConfiguration {
        &self.configuration
    }

    /// Set storage manager for persistence operations
    #[cfg(feature = "storage")]
    pub fn set_storage_manager(
        &mut self,
        storage_manager: Box<dyn StorageManager>,
        storage_config: ScannerStorageConfig,
    ) {
        self.storage_manager = Some(storage_manager);
        self.storage_config = storage_config;
    }

    /// Get a reference to the storage configuration
    #[cfg(feature = "storage")]
    pub fn storage_config(&self) -> &ScannerStorageConfig {
        &self.storage_config
    }

    /// Set progress reporter for scanning operations
    pub fn set_progress_reporter(
        &mut self,
        progress_reporter: Box<dyn ProgressReporter>,
        progress_config: ProgressReportConfig,
    ) {
        self.progress_reporter = Some(progress_reporter);
        self.progress_config = progress_config;
    }

    /// Set output formatter for displaying results
    pub fn set_output_formatter(
        &mut self,
        output_formatter: Box<dyn OutputFormatter>,
        output_config: OutputConfig,
    ) {
        self.output_formatter = Some(output_formatter);
        self.output_config = output_config;
    }

    /// Get a reference to the progress configuration
    pub fn progress_config(&self) -> &ProgressReportConfig {
        &self.progress_config
    }

    /// Get a reference to the output configuration
    pub fn output_config(&self) -> &OutputConfig {
        &self.output_config
    }
}

/// Builder for constructing ScannerEngine instances
#[cfg(any(feature = "grpc", feature = "http", target_arch = "wasm32"))]
pub struct ScannerEngineBuilder {
    scanner: Option<Box<dyn BlockchainScanner>>,
    configuration: Option<ScanConfiguration>,
    wallet_source: Option<WalletSource>,
}

#[cfg(any(feature = "grpc", feature = "http", target_arch = "wasm32"))]
impl ScannerEngineBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            scanner: None,
            configuration: None,
            wallet_source: None,
        }
    }

    /// Set the blockchain scanner
    pub fn with_scanner(mut self, scanner: Box<dyn BlockchainScanner>) -> Self {
        self.scanner = Some(scanner);
        self
    }

    /// Set the scan configuration
    pub fn with_configuration(mut self, configuration: ScanConfiguration) -> Self {
        self.configuration = Some(configuration);
        self
    }

    /// Set the wallet source
    pub fn with_wallet_source(mut self, wallet_source: WalletSource) -> Self {
        self.wallet_source = Some(wallet_source);
        self
    }

    /// Set start and end heights
    pub fn with_height_range(mut self, start_height: u64, end_height: Option<u64>) -> Self {
        if let Some(ref mut config) = self.configuration {
            config.start_height = start_height;
            config.end_height = end_height;
        } else {
            let mut config = ScanConfiguration::new(start_height);
            config.end_height = end_height;
            self.configuration = Some(config);
        }
        self
    }

    /// Set specific blocks to scan
    pub fn with_specific_blocks(mut self, blocks: Vec<u64>) -> Self {
        if let Some(ref mut config) = self.configuration {
            config.specific_blocks = Some(blocks);
        } else {
            self.configuration = Some(ScanConfiguration::new_specific_blocks(blocks));
        }
        self
    }

    /// Set batch size
    pub fn with_batch_size(mut self, batch_size: u64) -> Self {
        if let Some(ref mut config) = self.configuration {
            config.batch_size = batch_size;
        } else {
            let mut config = ScanConfiguration::default();
            config.batch_size = batch_size;
            self.configuration = Some(config);
        }
        self
    }

    /// Build the scanner engine
    pub fn build(self) -> LightweightWalletResult<ScannerEngine> {
        let scanner = self.scanner.ok_or_else(|| {
            LightweightWalletError::ConfigurationError("Blockchain scanner is required".to_string())
        })?;

        let mut configuration = self.configuration.unwrap_or_default();

        // Set wallet source if provided
        if let Some(wallet_source) = self.wallet_source {
            configuration = configuration.with_wallet_source(wallet_source);
        }

        Ok(ScannerEngine::new(scanner, configuration))
    }
}

#[cfg(any(feature = "grpc", feature = "http", target_arch = "wasm32"))]
impl Default for ScannerEngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::scanning::{MockBlockchainScanner, TipInfo};

    #[tokio::test]
    async fn test_scanner_engine_creation() {
        let scanner = Box::new(MockBlockchainScanner::new());
        let config = ScanConfiguration::new(1000);
        let engine = ScannerEngine::new(scanner, config);

        assert!(engine.wallet_context().is_none());
        assert_eq!(engine.configuration().start_height, 1000);
    }

    #[tokio::test]
    async fn test_scanner_engine_builder() {
        let scanner = Box::new(MockBlockchainScanner::new());
        let engine = ScannerEngineBuilder::new()
            .with_scanner(scanner)
            .with_height_range(1000, Some(2000))
            .with_batch_size(50)
            .build()
            .unwrap();

        assert_eq!(engine.configuration().start_height, 1000);
        assert_eq!(engine.configuration().end_height, Some(2000));
        assert_eq!(engine.configuration().batch_size, 50);
    }

    #[tokio::test]
    async fn test_scanner_engine_tip_info() {
        let mut scanner = MockBlockchainScanner::new();
        scanner.set_tip_info(TipInfo {
            best_block_height: 5000,
            best_block_hash: vec![1, 2, 3, 4],
            accumulated_difficulty: vec![5, 6, 7, 8],
            pruned_height: 2500,
            timestamp: 1234567890,
        });

        let config = ScanConfiguration::new(1000);
        let mut engine = ScannerEngine::new(Box::new(scanner), config);

        let tip_info = engine.get_tip_info().await.unwrap();
        assert_eq!(tip_info.best_block_height, 5000);
        assert_eq!(tip_info.pruned_height, 2500);
    }

    #[tokio::test]
    async fn test_determine_scan_range() {
        let mut scanner = MockBlockchainScanner::new();
        scanner.set_tip_info(TipInfo {
            best_block_height: 5000,
            best_block_hash: vec![1, 2, 3, 4],
            accumulated_difficulty: vec![5, 6, 7, 8],
            pruned_height: 2500,
            timestamp: 1234567890,
        });

        let config = ScanConfiguration::new_range(1000, 2000);
        let mut engine = ScannerEngine::new(Box::new(scanner), config);

        let (start, end) = engine.determine_scan_range().await.unwrap();
        assert_eq!(start, 1000);
        assert_eq!(end, 2000);
    }

    #[tokio::test]
    async fn test_determine_scan_range_no_end() {
        let mut scanner = MockBlockchainScanner::new();
        scanner.set_tip_info(TipInfo {
            best_block_height: 5000,
            best_block_hash: vec![1, 2, 3, 4],
            accumulated_difficulty: vec![5, 6, 7, 8],
            pruned_height: 2500,
            timestamp: 1234567890,
        });

        let config = ScanConfiguration::new(1000);
        let mut engine = ScannerEngine::new(Box::new(scanner), config);

        let (start, end) = engine.determine_scan_range().await.unwrap();
        assert_eq!(start, 1000);
        assert_eq!(end, 5000); // Should use tip height
    }

    #[tokio::test]
    async fn test_scan_blocks_empty_heights() {
        let scanner = Box::new(MockBlockchainScanner::new());
        let config = ScanConfiguration::new(1000);
        let mut engine = ScannerEngine::new(scanner, config);

        let result = engine.scan_blocks(vec![]).await;
        assert!(result.is_err());

        if let Err(LightweightWalletError::InvalidArgument { argument, .. }) = result {
            assert_eq!(argument, "heights");
        } else {
            panic!("Expected InvalidArgument error");
        }
    }

    #[test]
    fn test_default_error_handler() {
        let handler = DefaultErrorHandler;
        let context = ScanErrorContext {
            block_height: 1000,
            error: "Test error".to_string(),
            has_specific_blocks: false,
            remaining_blocks: vec![1001, 1002, 1003],
            to_block: 2000,
        };

        let strategy = handler.handle_scan_error(&context);
        assert_eq!(strategy, ErrorRecoveryStrategy::Continue);

        let block_strategy = handler.handle_block_error(1000, "Test block error");
        assert_eq!(block_strategy, ErrorRecoveryStrategy::Continue);

        let resume_cmd = handler.generate_resume_command(&context);
        assert!(resume_cmd.contains("--from-block 1000"));
        assert!(resume_cmd.contains("--to-block 2000"));
    }

    #[test]
    fn test_error_recovery_strategy_eq() {
        assert_eq!(
            ErrorRecoveryStrategy::Continue,
            ErrorRecoveryStrategy::Continue
        );
        assert_eq!(ErrorRecoveryStrategy::Skip, ErrorRecoveryStrategy::Skip);
        assert_eq!(ErrorRecoveryStrategy::Abort, ErrorRecoveryStrategy::Abort);
        assert_ne!(ErrorRecoveryStrategy::Continue, ErrorRecoveryStrategy::Skip);
    }

    #[test]
    fn test_specific_blocks_resume_command() {
        let handler = DefaultErrorHandler;
        let context = ScanErrorContext {
            block_height: 1000,
            error: "Test error".to_string(),
            has_specific_blocks: true,
            remaining_blocks: vec![1000, 1001, 1002],
            to_block: 2000,
        };

        let resume_cmd = handler.generate_resume_command(&context);
        assert!(resume_cmd.contains("--blocks 1000,1001,1002"));
    }
}
