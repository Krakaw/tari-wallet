//! Event emitter for wallet scanner integration
//!
//! This module provides the integration layer between the wallet scanner and the event system.
//! It contains utilities for creating scan events from scanner operations and emitting them
//! through the event dispatcher.
//!
//! # Key Components
//!
//! - [`ScanEventEmitter`]: Main integration point for emitting events from scanner operations
//! - Helper functions for creating events from scanner data
//! - Integration utilities for existing scanner components
//!
//! # Usage
//!
//! The event emitter is designed to be used within the wallet scanner to emit events
//! at key points in the scanning process:
//!
//! ```rust,no_run
//! use lightweight_wallet_libs::scanning::event_emitter::ScanEventEmitter;
//! use lightweight_wallet_libs::events::EventDispatcher;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create event dispatcher with listeners
//! let mut dispatcher = EventDispatcher::new();
//! // ... register listeners ...
//!
//! // Create event emitter
//! let emitter = ScanEventEmitter::new(dispatcher, "wallet_scanner".to_string());
//!
//! // Use emitter in scanning operations
//! // emitter.emit_scan_started(...).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::data_structures::{
    block::Block,
    transaction_output::LightweightTransactionOutput,
    wallet_transaction::{WalletState, WalletTransaction},
};
use crate::errors::LightweightWalletError;
use crate::events::{
    types::{
        AddressInfo, BlockInfo, CancellationInfo, CompletionStatistics, ErrorInfo, Event,
        EventMetadata, OutputData, ProgressData, ScanConfig,
    },
    EventDispatcher,
};
use crate::scanning::{BinaryScanConfig, ScanContext, ScanMetadata};

/// Event emitter for wallet scanner integration
///
/// This struct provides a bridge between the wallet scanner and the event system,
/// allowing scanner operations to emit structured events that can be handled
/// by registered listeners.
#[derive(Debug)]
pub struct ScanEventEmitter {
    /// Event dispatcher for sending events to listeners
    dispatcher: EventDispatcher,
    /// Source identifier for events emitted by this instance
    source: String,
    /// Optional correlation ID for tracking related events across a scan session
    correlation_id: Option<String>,
    /// Scan start time for duration calculations
    scan_start_time: Option<SystemTime>,
    /// Current scan configuration for reference
    current_config: Option<BinaryScanConfig>,
    /// Current scan context for reference
    current_context: Option<ScanContext>,
}

impl ScanEventEmitter {
    /// Create a new event emitter with the given dispatcher and source identifier
    pub fn new(dispatcher: EventDispatcher, source: String) -> Self {
        Self {
            dispatcher,
            source,
            correlation_id: None,
            scan_start_time: None,
            current_config: None,
            current_context: None,
        }
    }

    /// Create a new event emitter with a correlation ID for tracking related events
    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Set the current scan configuration for reference in events
    pub fn set_scan_config(&mut self, config: BinaryScanConfig) {
        self.current_config = Some(config);
    }

    /// Set the current scan context for reference in events
    pub fn set_scan_context(&mut self, context: ScanContext) {
        self.current_context = Some(context);
    }

    /// Get a reference to the event dispatcher
    pub fn dispatcher(&self) -> &EventDispatcher {
        &self.dispatcher
    }

    /// Get a mutable reference to the event dispatcher
    pub fn dispatcher_mut(&mut self) -> &mut EventDispatcher {
        &mut self.dispatcher
    }

    /// Emit a scan started event
    ///
    /// This should be called at the beginning of a scan operation to notify
    /// listeners that scanning has begun.
    pub async fn emit_scan_started(
        &mut self,
        config: &BinaryScanConfig,
        context: &ScanContext,
        block_range: (u64, u64),
        wallet_context: HashMap<String, String>,
    ) -> Result<(), LightweightWalletError> {
        self.scan_start_time = Some(SystemTime::now());
        self.current_config = Some(config.clone());
        self.current_context = Some(context.clone());

        let metadata = self.create_metadata();
        let scan_config = ScanConfig {
            batch_size: Some(config.batch_size),
            timeout_seconds: Some(30), // Default timeout
            retry_attempts: Some(3),   // Default retry attempts
            scan_mode: Some("standard".to_string()),
            filters: HashMap::new(),
        };

        let event = Event::ScanStarted {
            metadata,
            scan_config,
            block_range,
            wallet_context,
        };

        self.dispatcher.dispatch(Arc::new(event)).await;
        Ok(())
    }

    /// Emit a block processed event
    ///
    /// This should be called after each block is successfully processed during scanning.
    pub async fn emit_block_processed(
        &self,
        block: &Block,
        processing_duration: Duration,
        outputs_found: usize,
        transactions_found: usize,
    ) -> Result<(), LightweightWalletError> {
        let metadata = self.create_metadata();
        let block_info = BlockInfo {
            height: block.height,
            hash: block.hash.clone(),
            timestamp: block.timestamp,
            output_count: block.outputs.len(),
            input_count: block.inputs.len(),
            merkle_root: None,   // Not available in current Block struct
            previous_hash: None, // Not available in current Block struct
        };

        let event = Event::BlockProcessed {
            metadata,
            block_info,
            processing_duration,
            outputs_found,
            transactions_found,
        };

        self.dispatcher.dispatch(Arc::new(event)).await;
        Ok(())
    }

    /// Emit an output found event
    ///
    /// This should be called when a wallet output is discovered during scanning.
    pub async fn emit_output_found(
        &self,
        output: &LightweightTransactionOutput,
        block_info: &BlockInfo,
        address_info: &AddressInfo,
        transaction: &WalletTransaction,
    ) -> Result<(), LightweightWalletError> {
        let metadata = self.create_metadata();
        let output_data = OutputData {
            commitment: hex::encode(&output.commitment.as_bytes()),
            range_proof: hex::encode(&output.range_proof),
            encrypted_value: output.encrypted_value.clone(),
            script: output.script.as_ref().map(|s| hex::encode(&s.bytes)),
            features: output.features.bits(),
            maturity_height: output.minimum_value_promise,
            amount: Some(transaction.amount),
            is_ours: true,
        };

        let event = Event::OutputFound {
            metadata,
            output_data,
            block_info: block_info.clone(),
            address_info: address_info.clone(),
        };

        self.dispatcher.dispatch(Arc::new(event)).await;
        Ok(())
    }

    /// Emit a scan progress event
    ///
    /// This should be called periodically during scanning to update progress.
    pub async fn emit_scan_progress(
        &self,
        current_block: u64,
        total_blocks: u64,
        blocks_processed: usize,
        outputs_found: usize,
        processing_rate: Option<f64>,
        estimated_completion: Option<SystemTime>,
    ) -> Result<(), LightweightWalletError> {
        let metadata = self.create_metadata();
        let progress_data = ProgressData {
            current_block,
            total_blocks,
            blocks_processed,
            percentage: (blocks_processed as f64 / total_blocks as f64 * 100.0),
            outputs_found,
            processing_rate,
            estimated_completion,
            elapsed_time: self
                .scan_start_time
                .map(|start| SystemTime::now().duration_since(start).unwrap_or_default()),
        };

        let event = Event::ScanProgress {
            metadata,
            progress_data,
        };

        self.dispatcher.dispatch(Arc::new(event)).await;
        Ok(())
    }

    /// Emit a scan completed event
    ///
    /// This should be called when scanning completes successfully.
    pub async fn emit_scan_completed(
        &self,
        final_stats: &ScanMetadata,
        wallet_state: &WalletState,
        success: bool,
    ) -> Result<(), LightweightWalletError> {
        let metadata = self.create_metadata();
        let statistics = CompletionStatistics {
            total_blocks_scanned: final_stats.blocks_processed,
            total_outputs_found: wallet_state.outputs.len(),
            total_transactions_found: wallet_state.transactions.len(),
            scan_duration: final_stats.duration().unwrap_or_default(),
            average_block_time: final_stats
                .blocks_per_second()
                .map(|rate| Duration::from_secs_f64(1.0 / rate)),
            final_balance: wallet_state.get_summary().0, // Available balance
            final_block_height: final_stats.to_block,
            errors_encountered: 0, // Not tracked in current ScanMetadata
        };

        let event = Event::ScanCompleted {
            metadata,
            statistics,
            success,
        };

        self.dispatcher.dispatch(Arc::new(event)).await;
        Ok(())
    }

    /// Emit a scan error event
    ///
    /// This should be called when an error occurs during scanning.
    pub async fn emit_scan_error(
        &self,
        error: &LightweightWalletError,
        current_block: Option<u64>,
        can_retry: bool,
        retry_count: u32,
    ) -> Result<(), LightweightWalletError> {
        let metadata = self.create_metadata();
        let error_info = ErrorInfo {
            error_type: format!("{:?}", error), // Simple error type classification
            error_message: error.to_string(),
            error_code: None, // Not available in current error types
            block_height: current_block,
            component: Some(self.source.clone()),
            stack_trace: None, // Not available
            recovery_suggestion: if can_retry {
                Some("Scan can be retried from the current position".to_string())
            } else {
                Some("Manual intervention may be required".to_string())
            },
        };

        let event = Event::ScanError {
            metadata,
            error_info,
            can_retry,
            retry_count,
        };

        self.dispatcher.dispatch(Arc::new(event)).await;
        Ok(())
    }

    /// Emit a scan cancelled event
    ///
    /// This should be called when scanning is cancelled by user request.
    pub async fn emit_scan_cancelled(
        &self,
        reason: String,
        current_block: u64,
        partial_stats: Option<&ScanMetadata>,
    ) -> Result<(), LightweightWalletError> {
        let metadata = self.create_metadata();
        let cancellation_info = CancellationInfo {
            reason,
            initiated_by: "user".to_string(), // Could be enhanced to track actual source
            current_block,
            blocks_completed: partial_stats.map(|s| s.blocks_processed).unwrap_or(0),
            can_resume: true, // Always true for user-initiated cancellation
            resume_instruction: Some(format!("Resume from block {}", current_block + 1)),
        };

        let event = Event::ScanCancelled {
            metadata,
            cancellation_info,
        };

        self.dispatcher.dispatch(Arc::new(event)).await;
        Ok(())
    }

    /// Create event metadata with consistent source and correlation ID
    fn create_metadata(&self) -> EventMetadata {
        match &self.correlation_id {
            Some(id) => EventMetadata::with_correlation(&self.source, id.clone()),
            None => EventMetadata::new(&self.source),
        }
    }
}

/// Helper function to create AddressInfo from scan context and transaction
pub fn create_address_info_from_transaction(
    context: &ScanContext,
    transaction: &WalletTransaction,
) -> AddressInfo {
    AddressInfo {
        address: transaction.address.clone(),
        address_type: "dual".to_string(), // Assuming dual address type
        key_index: None,                  // Not directly available in current structure
        derivation_path: None,            // Could be derived from context if needed
        script_hash: None,                // Not available in current structure
    }
}

/// Helper function to create BlockInfo from Block
pub fn create_block_info_from_block(block: &Block) -> BlockInfo {
    BlockInfo {
        height: block.height,
        hash: block.hash.clone(),
        timestamp: block.timestamp,
        output_count: block.outputs.len(),
        input_count: block.inputs.len(),
        merkle_root: None,   // Not available in current Block struct
        previous_hash: None, // Not available in current Block struct
    }
}

/// Create a ScanEventEmitter with commonly used listeners
///
/// This is a convenience function for setting up an event emitter with
/// standard listeners for progress tracking and console logging.
pub fn create_default_event_emitter(
    source: String,
    correlation_id: Option<String>,
) -> Result<ScanEventEmitter, LightweightWalletError> {
    use crate::events::listeners::{ConsoleLoggingListener, ProgressTrackingListener};

    let mut dispatcher = EventDispatcher::new();

    // Add default progress tracking listener
    let progress_listener = ProgressTrackingListener::new();
    dispatcher.register(Box::new(progress_listener));

    // Add default console logging listener
    let console_listener = ConsoleLoggingListener::new();
    dispatcher.register(Box::new(console_listener));

    let mut emitter = ScanEventEmitter::new(dispatcher, source);
    if let Some(id) = correlation_id {
        emitter = emitter.with_correlation_id(id);
    }

    Ok(emitter)
}

/// Create a ScanEventEmitter with database storage listener
///
/// This is a convenience function for setting up an event emitter with
/// a database storage listener for persistence.
#[cfg(feature = "storage")]
pub fn create_database_event_emitter(
    source: String,
    correlation_id: Option<String>,
    database_path: Option<String>,
) -> Result<ScanEventEmitter, LightweightWalletError> {
    use crate::events::listeners::{DatabaseStorageListener, ProgressTrackingListener};

    let mut dispatcher = EventDispatcher::new();

    // Add database storage listener
    let db_listener = if let Some(path) = database_path {
        DatabaseStorageListener::with_database_path(path)?
    } else {
        DatabaseStorageListener::new()?
    };
    dispatcher.register(Box::new(db_listener));

    // Add progress tracking listener
    let progress_listener = ProgressTrackingListener::new();
    dispatcher.register(Box::new(progress_listener));

    let mut emitter = ScanEventEmitter::new(dispatcher, source);
    if let Some(id) = correlation_id {
        emitter = emitter.with_correlation_id(id);
    }

    Ok(emitter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::listeners::MockEventListener;
    use tokio::time::{sleep, Duration as TokioDuration};

    fn create_test_emitter() -> ScanEventEmitter {
        let mut dispatcher = EventDispatcher::new();
        let mock_listener = MockEventListener::new();
        dispatcher.register(Box::new(mock_listener));
        ScanEventEmitter::new(dispatcher, "test_scanner".to_string())
    }

    #[tokio::test]
    async fn test_scan_started_event() {
        let mut emitter = create_test_emitter();
        let config = BinaryScanConfig::new(1000, 2000);
        let context = create_test_scan_context();
        let wallet_context = HashMap::new();

        let result = emitter
            .emit_scan_started(&config, &context, (1000, 2000), wallet_context)
            .await;
        assert!(result.is_ok());
        assert!(emitter.scan_start_time.is_some());
    }

    #[tokio::test]
    async fn test_event_correlation() {
        let correlation_id = "test-scan-123".to_string();
        let emitter = create_test_emitter().with_correlation_id(correlation_id.clone());

        let metadata = emitter.create_metadata();
        assert_eq!(metadata.correlation_id, Some(correlation_id));
        assert_eq!(metadata.source, "test_scanner");
    }

    #[tokio::test]
    async fn test_progress_event_timing() {
        let mut emitter = create_test_emitter();
        emitter.scan_start_time = Some(SystemTime::now() - Duration::from_secs(10));

        let result = emitter
            .emit_scan_progress(1500, 2000, 500, 10, Some(50.0), None)
            .await;
        assert!(result.is_ok());
    }

    // Helper function to create a test scan context
    fn create_test_scan_context() -> ScanContext {
        use crate::data_structures::types::PrivateKey;
        use crate::key_management::key_derivation::derive_spend_key;

        // Create a test private key (this is just for testing)
        let entropy = [0u8; 32]; // Not secure, just for testing
        let view_key = derive_spend_key(&entropy, 0).expect("Failed to derive test key");

        ScanContext {
            view_key,
            entropy,
            start_block: 0,
        }
    }
}
