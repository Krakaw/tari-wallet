//! Event type definitions and data structures for wallet scanning operations
//!
//! This module defines the core event types and shared traits used throughout
//! the wallet scanner event system. Events are designed to be efficiently
//! shared between listeners using Arc<Event> pattern.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Shared event metadata present in all events
#[derive(Debug, Clone)]
pub struct EventMetadata {
    /// Unique identifier for this event
    pub event_id: String,
    /// Timestamp when the event was created
    pub timestamp: SystemTime,
    /// Optional correlation ID for tracking related events
    pub correlation_id: Option<String>,
    /// Source component that emitted this event
    pub source: String,
}

impl EventMetadata {
    /// Create new event metadata with generated ID
    pub fn new(source: &str) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: SystemTime::now(),
            correlation_id: None,
            source: source.to_string(),
        }
    }

    /// Create new event metadata with correlation ID
    pub fn with_correlation(source: &str, correlation_id: String) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: SystemTime::now(),
            correlation_id: Some(correlation_id),
            source: source.to_string(),
        }
    }
}

/// Trait for events that can provide their type name
pub trait EventType {
    /// Get the string name of this event type
    fn event_type(&self) -> &'static str;

    /// Get metadata associated with this event
    fn metadata(&self) -> &EventMetadata;

    /// Get optional serialized data for debugging
    fn debug_data(&self) -> Option<String> {
        None
    }
}

/// Trait for events that can be serialized for debugging/logging
pub trait SerializableEvent {
    /// Serialize event to JSON string for debugging
    fn to_debug_json(&self) -> Result<String, String>;

    /// Get human-readable summary of the event
    fn summary(&self) -> String;
}

/// Configuration data for scanning operations
#[derive(Debug, Clone, Default)]
pub struct ScanConfig {
    pub batch_size: Option<usize>,
    pub timeout_seconds: Option<u64>,
    pub retry_attempts: Option<u32>,
    pub scan_mode: Option<String>,
    pub filters: HashMap<String, String>,
}

impl ScanConfig {
    /// Create a new scan configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set batch size for processing
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = Some(batch_size);
        self
    }

    /// Set timeout for operations
    pub fn with_timeout_seconds(mut self, timeout: u64) -> Self {
        self.timeout_seconds = Some(timeout);
        self
    }

    /// Set retry attempts for failed operations
    pub fn with_retry_attempts(mut self, attempts: u32) -> Self {
        self.retry_attempts = Some(attempts);
        self
    }

    /// Add a filter parameter
    pub fn with_filter(mut self, key: String, value: String) -> Self {
        self.filters.insert(key, value);
        self
    }
}

/// Core event types emitted during wallet scanning operations
#[derive(Debug, Clone)]
pub enum WalletScanEvent {
    /// Emitted when a scan operation begins
    ScanStarted {
        metadata: EventMetadata,
        config: ScanConfig,
        block_range: (u64, u64),
        wallet_context: String,
    },
    /// Emitted when a block is processed
    BlockProcessed {
        metadata: EventMetadata,
        height: u64,
        hash: String,
        timestamp: u64,
        processing_duration: Duration,
        outputs_count: usize,
    },
    /// Emitted when an output is found for the wallet
    OutputFound {
        metadata: EventMetadata,
        output_data: String, // Placeholder for actual output data structure
        block_height: u64,
        address_info: String,
    },
    /// Emitted periodically to report scan progress
    ScanProgress {
        metadata: EventMetadata,
        current_block: u64,
        total_blocks: u64,
        percentage: f64,
        speed_blocks_per_second: f64,
        estimated_time_remaining: Option<Duration>,
    },
    /// Emitted when scan completes successfully
    ScanCompleted {
        metadata: EventMetadata,
        final_statistics: HashMap<String, u64>,
        success: bool,
        total_duration: Duration,
    },
    /// Emitted when an error occurs during scanning
    ScanError {
        metadata: EventMetadata,
        error_message: String,
        error_code: Option<String>,
        block_height: Option<u64>,
        retry_info: Option<String>,
        is_recoverable: bool,
    },
    /// Emitted when scanning is cancelled
    ScanCancelled {
        metadata: EventMetadata,
        reason: String,
        final_statistics: HashMap<String, u64>,
        partial_completion: Option<f64>,
    },
}

impl EventType for WalletScanEvent {
    fn event_type(&self) -> &'static str {
        match self {
            WalletScanEvent::ScanStarted { .. } => "ScanStarted",
            WalletScanEvent::BlockProcessed { .. } => "BlockProcessed",
            WalletScanEvent::OutputFound { .. } => "OutputFound",
            WalletScanEvent::ScanProgress { .. } => "ScanProgress",
            WalletScanEvent::ScanCompleted { .. } => "ScanCompleted",
            WalletScanEvent::ScanError { .. } => "ScanError",
            WalletScanEvent::ScanCancelled { .. } => "ScanCancelled",
        }
    }

    fn metadata(&self) -> &EventMetadata {
        match self {
            WalletScanEvent::ScanStarted { metadata, .. } => metadata,
            WalletScanEvent::BlockProcessed { metadata, .. } => metadata,
            WalletScanEvent::OutputFound { metadata, .. } => metadata,
            WalletScanEvent::ScanProgress { metadata, .. } => metadata,
            WalletScanEvent::ScanCompleted { metadata, .. } => metadata,
            WalletScanEvent::ScanError { metadata, .. } => metadata,
            WalletScanEvent::ScanCancelled { metadata, .. } => metadata,
        }
    }

    fn debug_data(&self) -> Option<String> {
        // Provide basic debug information for each event type
        match self {
            WalletScanEvent::ScanStarted {
                block_range,
                wallet_context,
                ..
            } => Some(format!(
                "blocks: {}-{}, wallet: {}",
                block_range.0, block_range.1, wallet_context
            )),
            WalletScanEvent::BlockProcessed {
                height,
                outputs_count,
                ..
            } => Some(format!("height: {}, outputs: {}", height, outputs_count)),
            WalletScanEvent::OutputFound { block_height, .. } => {
                Some(format!("block: {}", block_height))
            }
            WalletScanEvent::ScanProgress {
                current_block,
                total_blocks,
                percentage,
                ..
            } => Some(format!(
                "{}/{} ({:.1}%)",
                current_block, total_blocks, percentage
            )),
            WalletScanEvent::ScanCompleted { success, .. } => Some(format!("success: {}", success)),
            WalletScanEvent::ScanError {
                error_message,
                block_height,
                ..
            } => Some(format!(
                "error: {}, block: {:?}",
                error_message, block_height
            )),
            WalletScanEvent::ScanCancelled { reason, .. } => Some(format!("reason: {}", reason)),
        }
    }
}

impl SerializableEvent for WalletScanEvent {
    fn to_debug_json(&self) -> Result<String, String> {
        // Simplified JSON serialization for debugging
        // In a real implementation, you might use serde_json
        let json = match self {
            WalletScanEvent::ScanStarted {
                metadata,
                config,
                block_range,
                wallet_context,
            } => {
                format!(
                    "{{\"type\":\"ScanStarted\",\"event_id\":\"{}\",\"block_range\":[{},{}],\"wallet_context\":\"{}\",\"batch_size\":{}}}",
                    metadata.event_id,
                    block_range.0,
                    block_range.1,
                    wallet_context,
                    config.batch_size.unwrap_or(0)
                )
            }
            WalletScanEvent::BlockProcessed {
                metadata,
                height,
                hash,
                outputs_count,
                ..
            } => {
                format!(
                    "{{\"type\":\"BlockProcessed\",\"event_id\":\"{}\",\"height\":{},\"hash\":\"{}\",\"outputs_count\":{}}}",
                    metadata.event_id,
                    height,
                    hash,
                    outputs_count
                )
            }
            WalletScanEvent::OutputFound {
                metadata,
                block_height,
                ..
            } => {
                format!(
                    "{{\"type\":\"OutputFound\",\"event_id\":\"{}\",\"block_height\":{}}}",
                    metadata.event_id, block_height
                )
            }
            WalletScanEvent::ScanProgress {
                metadata,
                current_block,
                total_blocks,
                percentage,
                ..
            } => {
                format!(
                    "{{\"type\":\"ScanProgress\",\"event_id\":\"{}\",\"current_block\":{},\"total_blocks\":{},\"percentage\":{:.2}}}",
                    metadata.event_id,
                    current_block,
                    total_blocks,
                    percentage
                )
            }
            WalletScanEvent::ScanCompleted {
                metadata, success, ..
            } => {
                format!(
                    "{{\"type\":\"ScanCompleted\",\"event_id\":\"{}\",\"success\":{}}}",
                    metadata.event_id, success
                )
            }
            WalletScanEvent::ScanError {
                metadata,
                error_message,
                block_height,
                ..
            } => {
                format!(
                    "{{\"type\":\"ScanError\",\"event_id\":\"{}\",\"error_message\":\"{}\",\"block_height\":{}}}",
                    metadata.event_id,
                    error_message,
                    block_height.map_or("null".to_string(), |h| h.to_string())
                )
            }
            WalletScanEvent::ScanCancelled {
                metadata, reason, ..
            } => {
                format!(
                    "{{\"type\":\"ScanCancelled\",\"event_id\":\"{}\",\"reason\":\"{}\"}}",
                    metadata.event_id, reason
                )
            }
        };
        Ok(json)
    }

    fn summary(&self) -> String {
        match self {
            WalletScanEvent::ScanStarted {
                block_range,
                wallet_context,
                ..
            } => {
                format!(
                    "Scan started for wallet '{}' on blocks {}-{}",
                    wallet_context, block_range.0, block_range.1
                )
            }
            WalletScanEvent::BlockProcessed {
                height,
                outputs_count,
                ..
            } => {
                format!("Processed block {} with {} outputs", height, outputs_count)
            }
            WalletScanEvent::OutputFound { block_height, .. } => {
                format!("Found output at block {}", block_height)
            }
            WalletScanEvent::ScanProgress {
                current_block,
                total_blocks,
                percentage,
                ..
            } => {
                format!(
                    "Scan progress: {}/{} blocks ({:.1}%)",
                    current_block, total_blocks, percentage
                )
            }
            WalletScanEvent::ScanCompleted { success, .. } => {
                format!("Scan completed (success: {})", success)
            }
            WalletScanEvent::ScanError {
                error_message,
                block_height,
                ..
            } => match block_height {
                Some(height) => format!("Scan error at block {}: {}", height, error_message),
                None => format!("Scan error: {}", error_message),
            },
            WalletScanEvent::ScanCancelled { reason, .. } => {
                format!("Scan cancelled: {}", reason)
            }
        }
    }
}

/// Type alias for efficiently shared events
pub type SharedEvent = Arc<WalletScanEvent>;

/// Helper functions for creating events with proper metadata
impl WalletScanEvent {
    /// Create a new ScanStarted event
    pub fn scan_started(
        config: ScanConfig,
        block_range: (u64, u64),
        wallet_context: String,
    ) -> Self {
        Self::ScanStarted {
            metadata: EventMetadata::new("wallet_scanner"),
            config,
            block_range,
            wallet_context,
        }
    }

    /// Create a new BlockProcessed event
    pub fn block_processed(
        height: u64,
        hash: String,
        timestamp: u64,
        processing_duration: Duration,
        outputs_count: usize,
    ) -> Self {
        Self::BlockProcessed {
            metadata: EventMetadata::new("wallet_scanner"),
            height,
            hash,
            timestamp,
            processing_duration,
            outputs_count,
        }
    }

    /// Create a new OutputFound event
    pub fn output_found(output_data: String, block_height: u64, address_info: String) -> Self {
        Self::OutputFound {
            metadata: EventMetadata::new("wallet_scanner"),
            output_data,
            block_height,
            address_info,
        }
    }

    /// Create a new ScanProgress event
    pub fn scan_progress(
        current_block: u64,
        total_blocks: u64,
        percentage: f64,
        speed_blocks_per_second: f64,
        estimated_time_remaining: Option<Duration>,
    ) -> Self {
        Self::ScanProgress {
            metadata: EventMetadata::new("wallet_scanner"),
            current_block,
            total_blocks,
            percentage,
            speed_blocks_per_second,
            estimated_time_remaining,
        }
    }

    /// Create a new ScanCompleted event
    pub fn scan_completed(
        final_statistics: HashMap<String, u64>,
        success: bool,
        total_duration: Duration,
    ) -> Self {
        Self::ScanCompleted {
            metadata: EventMetadata::new("wallet_scanner"),
            final_statistics,
            success,
            total_duration,
        }
    }

    /// Create a new ScanError event
    pub fn scan_error(
        error_message: String,
        error_code: Option<String>,
        block_height: Option<u64>,
        retry_info: Option<String>,
        is_recoverable: bool,
    ) -> Self {
        Self::ScanError {
            metadata: EventMetadata::new("wallet_scanner"),
            error_message,
            error_code,
            block_height,
            retry_info,
            is_recoverable,
        }
    }

    /// Create a new ScanCancelled event
    pub fn scan_cancelled(
        reason: String,
        final_statistics: HashMap<String, u64>,
        partial_completion: Option<f64>,
    ) -> Self {
        Self::ScanCancelled {
            metadata: EventMetadata::new("wallet_scanner"),
            reason,
            final_statistics,
            partial_completion,
        }
    }
}
