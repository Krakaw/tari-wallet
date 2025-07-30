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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn test_scan_started_event_creation() {
        let config = ScanConfig::new()
            .with_batch_size(10)
            .with_timeout_seconds(30)
            .with_retry_attempts(3);

        let event = WalletScanEvent::scan_started(
            config.clone(),
            (1000, 2000),
            "test_wallet_context".to_string(),
        );

        match &event {
            WalletScanEvent::ScanStarted {
                metadata,
                config: event_config,
                block_range,
                wallet_context,
            } => {
                assert!(!metadata.event_id.is_empty());
                assert_eq!(metadata.source, "wallet_scanner");
                assert!(metadata.timestamp <= SystemTime::now());
                assert_eq!(event_config.batch_size, Some(10));
                assert_eq!(event_config.timeout_seconds, Some(30));
                assert_eq!(event_config.retry_attempts, Some(3));
                assert_eq!(*block_range, (1000, 2000));
                assert_eq!(wallet_context, "test_wallet_context");
            }
            _ => panic!("Expected ScanStarted event"),
        }
    }

    #[test]
    fn test_scan_started_event_traits() {
        let config = ScanConfig::default();
        let event = WalletScanEvent::scan_started(config, (0, 100), "wallet_123".to_string());

        // Test EventType trait
        assert_eq!(event.event_type(), "ScanStarted");
        assert!(event.debug_data().is_some());
        assert!(event.debug_data().unwrap().contains("blocks: 0-100"));
        assert!(event.debug_data().unwrap().contains("wallet: wallet_123"));

        // Test SerializableEvent trait
        let summary = event.summary();
        assert!(summary.contains("Scan started"));
        assert!(summary.contains("wallet_123"));
        assert!(summary.contains("blocks 0-100"));

        let json = event.to_debug_json().unwrap();
        assert!(json.contains("\"type\":\"ScanStarted\""));
        assert!(json.contains("\"block_range\":[0,100]"));
        assert!(json.contains("\"wallet_context\":\"wallet_123\""));
    }

    #[test]
    fn test_scan_started_with_correlation_id() {
        let metadata =
            EventMetadata::with_correlation("wallet_scanner", "scan_session_123".to_string());
        let config = ScanConfig::default();

        let event = WalletScanEvent::ScanStarted {
            metadata,
            config,
            block_range: (500, 1500),
            wallet_context: "test_wallet".to_string(),
        };

        match &event {
            WalletScanEvent::ScanStarted { metadata, .. } => {
                assert_eq!(
                    metadata.correlation_id,
                    Some("scan_session_123".to_string())
                );
                assert_eq!(metadata.source, "wallet_scanner");
            }
            _ => panic!("Expected ScanStarted event"),
        }
    }

    #[test]
    fn test_scan_config_builder_pattern() {
        let config = ScanConfig::new()
            .with_batch_size(25)
            .with_timeout_seconds(60)
            .with_retry_attempts(5)
            .with_filter("output_type".to_string(), "utxo".to_string())
            .with_filter("min_value".to_string(), "1000".to_string());

        assert_eq!(config.batch_size, Some(25));
        assert_eq!(config.timeout_seconds, Some(60));
        assert_eq!(config.retry_attempts, Some(5));
        assert_eq!(config.filters.get("output_type"), Some(&"utxo".to_string()));
        assert_eq!(config.filters.get("min_value"), Some(&"1000".to_string()));
        assert_eq!(config.filters.len(), 2);
    }

    #[test]
    fn test_block_processed_event_creation() {
        let processing_duration = Duration::from_millis(250);
        let event = WalletScanEvent::block_processed(
            12345,
            "0x1234567890abcdef".to_string(),
            1697123456,
            processing_duration,
            5,
        );

        match &event {
            WalletScanEvent::BlockProcessed {
                metadata,
                height,
                hash,
                timestamp,
                processing_duration: duration,
                outputs_count,
            } => {
                assert!(!metadata.event_id.is_empty());
                assert_eq!(metadata.source, "wallet_scanner");
                assert!(metadata.timestamp <= SystemTime::now());
                assert_eq!(*height, 12345);
                assert_eq!(hash, "0x1234567890abcdef");
                assert_eq!(*timestamp, 1697123456);
                assert_eq!(*duration, processing_duration);
                assert_eq!(*outputs_count, 5);
            }
            _ => panic!("Expected BlockProcessed event"),
        }
    }

    #[test]
    fn test_block_processed_event_traits() {
        let event = WalletScanEvent::block_processed(
            98765,
            "0xabcdef1234567890".to_string(),
            1697123999,
            Duration::from_millis(180),
            3,
        );

        // Test EventType trait
        assert_eq!(event.event_type(), "BlockProcessed");
        assert!(event.debug_data().is_some());
        let debug_data = event.debug_data().unwrap();
        assert!(debug_data.contains("height: 98765"));
        assert!(debug_data.contains("outputs: 3"));

        // Test SerializableEvent trait
        let summary = event.summary();
        assert!(summary.contains("Processed block 98765"));
        assert!(summary.contains("with 3 outputs"));

        let json = event.to_debug_json().unwrap();
        assert!(json.contains("\"type\":\"BlockProcessed\""));
        assert!(json.contains("\"height\":98765"));
        assert!(json.contains("\"hash\":\"0xabcdef1234567890\""));
        assert!(json.contains("\"outputs_count\":3"));
    }

    #[test]
    fn test_block_processed_zero_outputs() {
        let event = WalletScanEvent::block_processed(
            100,
            "0x0000000000000000".to_string(),
            1697000000,
            Duration::from_millis(50),
            0,
        );

        match &event {
            WalletScanEvent::BlockProcessed { outputs_count, .. } => {
                assert_eq!(*outputs_count, 0);
            }
            _ => panic!("Expected BlockProcessed event"),
        }

        let summary = event.summary();
        assert!(summary.contains("with 0 outputs"));
    }

    #[test]
    fn test_block_processed_with_correlation_id() {
        let metadata =
            EventMetadata::with_correlation("wallet_scanner", "block_batch_123".to_string());
        let event = WalletScanEvent::BlockProcessed {
            metadata,
            height: 54321,
            hash: "0xdeadbeef".to_string(),
            timestamp: 1697987654,
            processing_duration: Duration::from_millis(300),
            outputs_count: 10,
        };

        match &event {
            WalletScanEvent::BlockProcessed { metadata, .. } => {
                assert_eq!(metadata.correlation_id, Some("block_batch_123".to_string()));
                assert_eq!(metadata.source, "wallet_scanner");
            }
            _ => panic!("Expected BlockProcessed event"),
        }
    }

    #[test]
    fn test_block_processed_duration_handling() {
        // Test various processing durations
        let durations = vec![
            Duration::from_nanos(1),
            Duration::from_micros(1),
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_secs(60),
        ];

        for (i, duration) in durations.iter().enumerate() {
            let event = WalletScanEvent::block_processed(
                i as u64,
                format!("0x{:016x}", i),
                1697000000 + i as u64,
                *duration,
                i,
            );

            match &event {
                WalletScanEvent::BlockProcessed {
                    processing_duration,
                    ..
                } => {
                    assert_eq!(processing_duration, duration);
                }
                _ => panic!("Expected BlockProcessed event"),
            }
        }
    }
}

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
