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
use tokio::sync::Mutex;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures;

#[cfg(target_arch = "wasm32")]
use js_sys;

use crate::data_structures::{
    block::Block,
    transaction_output::TransactionOutput,
    wallet_transaction::{WalletState, WalletTransaction},
};
use crate::errors::WalletError;
use crate::events::{
    types::{
        AddressInfo, BlockInfo, EventMetadata, OutputData, ScanConfig, SpentOutputData,
        TransactionData, WalletScanEvent,
    },
    EventDispatcher,
};
use crate::hex_utils::HexEncodable;
use crate::scanning::{BinaryScanConfig, ScanContext, ScanMetadata};

/// Event emitter for wallet scanner integration
///
/// This struct provides a bridge between the wallet scanner and the event system,
/// allowing scanner operations to emit structured events that can be handled
/// by registered listeners.
pub struct ScanEventEmitter {
    /// Event dispatcher for sending events to listeners (wrapped in Arc<Mutex> for fire-and-forget sharing)
    dispatcher: Arc<Mutex<EventDispatcher>>,
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
    /// Whether to use fire-and-forget mode for event emission (non-blocking)
    fire_and_forget: bool,
}

impl ScanEventEmitter {
    /// Create a new event emitter with the given dispatcher and source identifier
    pub fn new(dispatcher: EventDispatcher, source: String) -> Self {
        Self {
            dispatcher: Arc::new(Mutex::new(dispatcher)),
            source,
            correlation_id: None,
            scan_start_time: None,
            current_config: None,
            current_context: None,
            fire_and_forget: true,
        }
    }

    /// Create a new event emitter with a correlation ID for tracking related events
    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Enable fire-and-forget mode for non-blocking event emission
    ///
    /// When enabled, event emission will not block the scanner waiting for
    /// listeners to complete processing. This is critical for scanning performance
    /// when slow listeners (like database operations) are registered.
    pub fn with_fire_and_forget(mut self, enabled: bool) -> Self {
        self.fire_and_forget = enabled;
        self
    }

    /// Set fire-and-forget mode for non-blocking event emission
    pub fn set_fire_and_forget(&mut self, enabled: bool) {
        self.fire_and_forget = enabled;
    }

    /// Set the current scan configuration for reference in events
    pub fn set_scan_config(&mut self, config: BinaryScanConfig) {
        self.current_config = Some(config);
    }

    /// Set the current scan context for reference in events
    pub fn set_scan_context(&mut self, context: ScanContext) {
        self.current_context = Some(context);
    }

    /// Get a reference to the event dispatcher (requires locking)
    pub fn dispatcher(&self) -> Arc<Mutex<EventDispatcher>> {
        Arc::clone(&self.dispatcher)
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
    ) -> Result<(), WalletError> {
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

        let event = WalletScanEvent::ScanStarted {
            metadata,
            config: scan_config,
            block_range,
            wallet_context: format!("{wallet_context:?}"),
        };

        self.dispatch_event(event).await;
        Ok(())
    }

    /// Emit a block processed event
    ///
    /// This should be called after each block is successfully processed during scanning.
    pub async fn emit_block_processed(
        &mut self,
        block: &Block,
        processing_duration: Duration,
        outputs_found: usize,
        spent_outputs_count: usize,
    ) -> Result<(), WalletError> {
        let metadata = self.create_metadata();
        let event = WalletScanEvent::BlockProcessed {
            metadata,
            height: block.height,
            hash: hex::encode(&block.hash),
            timestamp: block.timestamp,
            processing_duration,
            outputs_count: outputs_found,
            spent_outputs_count,
        };

        self.dispatch_event(event).await;
        Ok(())
    }

    /// Emit an output found event
    ///
    /// This should be called when a wallet output is discovered during scanning.
    pub async fn emit_output_found(
        &mut self,
        output: &TransactionOutput,
        block_info: &BlockInfo,
        address_info: &AddressInfo,
        transaction: &WalletTransaction,
    ) -> Result<(), WalletError> {
        let metadata = self.create_metadata();
        let output_data = OutputData {
            commitment: hex::encode(output.commitment.as_bytes()),
            range_proof: hex::encode(output.proof.as_ref().map_or(vec![], |p| p.bytes.clone())),
            encrypted_value: Some(output.encrypted_data.to_byte_vec()),
            script: Some(hex::encode(output.script.bytes.clone())),
            features: output.features.bytes().len() as u32, // Use bytes length as substitute
            maturity_height: Some(output.features.maturity),
            amount: Some(transaction.value),
            is_mine: true,
            key_index: None,
        };

        let block_info = BlockInfo::new(
            block_info.height,
            block_info.hash.clone(),
            block_info.timestamp,
            transaction.output_index.unwrap_or(0),
        );

        let transaction_data = TransactionData::new(
            transaction.value,
            format!("{:?}", transaction.transaction_status),
            format!("{:?}", transaction.transaction_direction),
            block_info.timestamp,
        )
        .with_output_index(transaction.output_index.unwrap_or(0))
        .with_payment_id(transaction.payment_id.to_hex());

        let event = WalletScanEvent::OutputFound {
            metadata,
            output_data,
            block_info,
            address_info: address_info.clone(),
            transaction_data,
        };

        self.dispatch_event(event).await;
        Ok(())
    }

    /// Emit a spent output found event
    ///
    /// This should be called when a previously found output is detected as spent (input found).
    pub async fn emit_spent_output_found(
        &mut self,
        spent_output: &WalletTransaction,
        spending_block: &Block,
        input_index: usize,
        match_method: &str,
        original_block_info: &BlockInfo,
    ) -> Result<(), WalletError> {
        let metadata = self.create_metadata();

        // Create spent output data
        let spent_output_data = SpentOutputData::new(
            hex::encode(spent_output.commitment.as_bytes()),
            input_index,
            original_block_info.height,
            spending_block.height,
            match_method.to_string(),
        )
        .with_spent_amount(spent_output.value)
        .with_output_hash(
            spent_output
                .output_hash
                .as_ref()
                .map(hex::encode)
                .unwrap_or_default(),
        );

        // Create spending block info
        let spending_block_info = BlockInfo::new(
            spending_block.height,
            hex::encode(&spending_block.hash),
            spending_block.timestamp,
            input_index,
        );

        // Create original output info
        let original_output_info = OutputData::new(
            hex::encode(spent_output.commitment.as_bytes()),
            String::new(), // range_proof not needed for spent events
            0,             // features not needed for spent events
            true,          // is_mine (we only track our own outputs)
        )
        .with_amount(spent_output.value)
        .with_maturity_height(0); // maturity not relevant for spent outputs

        // Create spending transaction data
        let spending_transaction_data = TransactionData::new(
            spent_output.value,
            format!("{:?}", spent_output.transaction_status),
            "Outbound".to_string(), // Spending is always outbound
            spending_block.timestamp,
        )
        .with_output_index(input_index)
        .with_payment_id(spent_output.payment_id.to_hex());

        let event = WalletScanEvent::SpentOutputFound {
            metadata,
            spent_output_data,
            spending_block_info,
            original_output_info,
            spending_transaction_data,
        };

        self.dispatch_event(event).await;
        Ok(())
    }

    /// Emit a scan progress event
    ///
    /// This should be called periodically during scanning to update progress.
    pub async fn emit_scan_progress(
        &mut self,
        blocks_processed: u64,
        total_blocks: u64,
        current_block_height: u64,
        _outputs_found: usize,
        processing_rate: Option<f64>,
        estimated_completion: Option<SystemTime>,
    ) -> Result<(), WalletError> {
        let metadata = self.create_metadata();
        let percentage = if total_blocks > 0 {
            (blocks_processed as f64 / total_blocks as f64 * 100.0).min(100.0)
        } else {
            0.0
        };

        let estimated_time_remaining = estimated_completion
            .and_then(|completion| SystemTime::now().duration_since(completion).ok());

        // Include both blocks_processed (for percentage calculation) and current_block_height (for display)
        let event = WalletScanEvent::ScanProgress {
            metadata,
            current_block: blocks_processed,
            total_blocks,
            current_block_height,
            percentage,
            speed_blocks_per_second: processing_rate.unwrap_or(0.0),
            estimated_time_remaining,
        };

        self.dispatch_event(event).await;
        Ok(())
    }

    /// Emit a scan completed event
    ///
    /// This should be called when scanning completes successfully.
    pub async fn emit_scan_completed(
        &mut self,
        final_stats: &ScanMetadata,
        wallet_state: &WalletState,
        success: bool,
    ) -> Result<(), WalletError> {
        let metadata = self.create_metadata();
        let mut final_statistics = HashMap::new();
        final_statistics.insert(
            "total_blocks_scanned".to_string(),
            final_stats.blocks_processed as u64,
        );
        final_statistics.insert(
            "total_transactions_found".to_string(),
            wallet_state.transactions.len() as u64,
        );
        final_statistics.insert("final_block_height".to_string(), final_stats.to_block);

        let total_duration = final_stats.duration().unwrap_or_default();

        let event = WalletScanEvent::ScanCompleted {
            metadata,
            final_statistics,
            success,
            total_duration,
        };

        self.dispatch_event(event).await;
        Ok(())
    }

    /// Emit a scan error event
    ///
    /// This should be called when an error occurs during scanning.
    pub async fn emit_scan_error(
        &mut self,
        error: &WalletError,
        current_block: Option<u64>,
        can_retry: bool,
        retry_count: u32,
    ) -> Result<(), WalletError> {
        let metadata = self.create_metadata();
        let retry_info = if can_retry {
            if let Some(block) = current_block {
                Some(format!(
                    "Retry attempt {} - scan can be resumed from block {block}",
                    retry_count + 1,
                ))
            } else {
                Some(format!("Retry attempt {}", retry_count + 1))
            }
        } else {
            None
        };

        let event = WalletScanEvent::ScanError {
            metadata,
            error_message: error.to_string(),
            error_code: Some(format!("{error:?}")),
            block_height: current_block,
            retry_info,
            is_recoverable: can_retry,
        };

        self.dispatch_event(event).await;
        Ok(())
    }

    /// Emit a scan cancelled event
    ///
    /// This should be called when scanning is cancelled by user request.
    pub async fn emit_scan_cancelled(
        &mut self,
        reason: String,
        current_block: u64,
        partial_stats: Option<&ScanMetadata>,
    ) -> Result<(), WalletError> {
        let metadata = self.create_metadata();
        let mut final_statistics = HashMap::new();
        if let Some(stats) = partial_stats {
            final_statistics.insert(
                "blocks_processed".to_string(),
                stats.blocks_processed as u64,
            );
            final_statistics.insert("from_block".to_string(), stats.from_block);
            final_statistics.insert("to_block".to_string(), stats.to_block);
        }
        final_statistics.insert("current_block".to_string(), current_block);

        let partial_completion = partial_stats.and_then(|stats| {
            if stats.to_block > stats.from_block {
                let total = stats.to_block - stats.from_block + 1;
                let completed = current_block.saturating_sub(stats.from_block);
                Some((completed as f64 / total as f64) * 100.0)
            } else {
                None
            }
        });

        let event = WalletScanEvent::ScanCancelled {
            metadata,
            reason,
            final_statistics,
            partial_completion,
        };

        self.dispatch_event(event).await;
        Ok(())
    }

    /// Handle event dispatch based on fire-and-forget mode
    async fn dispatch_event(&mut self, event: WalletScanEvent) {
        if self.fire_and_forget {
            // For fire-and-forget mode, spawn the dispatch operation in the background
            let dispatcher = Arc::clone(&self.dispatcher);

            #[cfg(not(target_arch = "wasm32"))]
            {
                // Spawn the dispatch in the background and don't wait for it
                tokio::spawn(async move {
                    let mut disp = dispatcher.lock().await;
                    disp.dispatch(event).await;
                });
                // Return immediately without waiting for the spawned task
            }

            #[cfg(target_arch = "wasm32")]
            {
                // Use spawn_local for WASM
                wasm_bindgen_futures::spawn_local(async move {
                    let mut disp = dispatcher.lock().await;
                    disp.dispatch(event).await;
                });
                // Return immediately without waiting for the spawned task
            }
        } else {
            // Standard blocking dispatch
            let mut disp = self.dispatcher.lock().await;
            disp.dispatch(event).await;
        }
    }

    /// Create event metadata with consistent source and correlation ID
    fn create_metadata(&self) -> EventMetadata {
        match &self.correlation_id {
            Some(id) => EventMetadata::with_correlation(&self.source, "unknown", id.clone()),
            None => EventMetadata::new(&self.source, "unknown"),
        }
    }

    /// Try to load existing wallet state from database if database storage is available
    /// This method checks if a DatabaseStorageListener is registered and attempts to query existing transactions
    #[cfg(feature = "storage")]
    pub async fn try_load_existing_wallet_state(
        &self,
        database_path: &str,
        wallet_id: Option<u32>,
    ) -> Result<Option<WalletState>, WalletError> {
        use crate::storage::{SqliteStorage, WalletStorage};

        if let Some(wallet_id) = wallet_id {
            // Try to connect to the database and load wallet state
            match SqliteStorage::new(database_path).await {
                Ok(storage) => match storage.load_wallet_state(wallet_id).await {
                    Ok(wallet_state) => {
                        if !wallet_state.transactions.is_empty() {
                            Ok(Some(wallet_state))
                        } else {
                            Ok(None)
                        }
                    }
                    Err(_) => Ok(None),
                },
                Err(_) => Ok(None),
            }
        } else {
            Ok(None)
        }
    }
}

/// Helper function to create AddressInfo from scan context and transaction
pub fn create_address_info_from_transaction(
    context: &ScanContext,
    _transaction: &WalletTransaction,
) -> AddressInfo {
    AddressInfo {
        address: "derived".to_string(), // Would be derived from context in real implementation
        address_type: "dual".to_string(),
        network: "localnet".to_string(), // Default for testing
        derivation_path: None,
        public_spend_key: Some(hex::encode(context.view_key.as_bytes())),
        view_key: Some(hex::encode(context.view_key.as_bytes())),
    }
}

/// Helper function to create BlockInfo from Block
pub fn create_block_info_from_block(block: &Block) -> BlockInfo {
    BlockInfo::new(
        block.height,
        hex::encode(&block.hash),
        block.timestamp,
        0, // output index - would need to be provided by caller
    )
}

/// Create a ScanEventEmitter with commonly used listeners
///
/// This is a convenience function for setting up an event emitter with
/// standard listeners for progress tracking and console logging.
pub fn create_default_event_emitter(
    source: String,
    correlation_id: Option<String>,
) -> Result<ScanEventEmitter, WalletError> {
    use crate::events::listeners::{ConsoleLoggingListener, ProgressTrackingListener};

    let mut dispatcher = EventDispatcher::new();

    // Add default progress tracking listener
    let progress_listener = ProgressTrackingListener::new();
    dispatcher
        .register(Box::new(progress_listener))
        .map_err(|e| WalletError::from(format!("Failed to register progress listener: {e}")))?;

    // Add default console logging listener
    let console_listener = ConsoleLoggingListener::new();
    dispatcher
        .register(Box::new(console_listener))
        .map_err(|e| WalletError::from(format!("Failed to register console listener: {e}")))?;

    let mut emitter = ScanEventEmitter::new(dispatcher, source).with_fire_and_forget(true); // Enable fire-and-forget by default for scanning performance

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
pub async fn create_database_event_emitter(
    source: String,
    correlation_id: Option<String>,
    database_path: Option<String>,
) -> Result<ScanEventEmitter, WalletError> {
    use crate::events::listeners::{DatabaseStorageListener, ProgressTrackingListener};

    let mut dispatcher = EventDispatcher::new();

    // Add database storage listener
    if let Some(path) = database_path {
        let db_listener = DatabaseStorageListener::new(&path).await?;
        dispatcher
            .register(Box::new(db_listener))
            .map_err(|e| WalletError::from(format!("Failed to register database listener: {e}")))?;
    }

    // Add progress tracking listener
    let progress_listener = ProgressTrackingListener::new();
    dispatcher
        .register(Box::new(progress_listener))
        .map_err(|e| WalletError::from(format!("Failed to register progress listener: {e}")))?;

    let mut emitter = ScanEventEmitter::new(dispatcher, source);
    if let Some(id) = correlation_id {
        emitter = emitter.with_correlation_id(id);
    }

    Ok(emitter)
}

impl std::fmt::Debug for ScanEventEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanEventEmitter")
            .field("source", &self.source)
            .field("correlation_id", &self.correlation_id)
            .field("scan_start_time", &self.scan_start_time)
            .field("current_config", &self.current_config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::listeners::MockEventListener;

    fn create_test_emitter() -> ScanEventEmitter {
        let mut dispatcher = EventDispatcher::new();
        let mock_listener = MockEventListener::new();
        let _ = dispatcher.register(Box::new(mock_listener));
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
            .emit_scan_progress(1500, 2000, 16500, 10, Some(50.0), None)
            .await;
        assert!(result.is_ok());
    }

    // Helper function to create a test scan context
    fn create_test_scan_context() -> ScanContext {
        use crate::data_structures::types::PrivateKey;

        // Create a test private key (this is just for testing)
        let entropy = [0u8; 16]; // Fixed to match expected size
        let view_key = PrivateKey::new([1u8; 32]);

        ScanContext { view_key, entropy }
    }
}
