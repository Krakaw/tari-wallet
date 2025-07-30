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

/// Complete output data information for OutputFound events
#[derive(Debug, Clone)]
pub struct OutputData {
    /// The commitment value of the output
    pub commitment: String,
    /// The range proof associated with the output
    pub range_proof: String,
    /// The encrypted value of the output (if available)
    pub encrypted_value: Option<Vec<u8>>,
    /// The script associated with the output (if any)
    pub script: Option<String>,
    /// Features flags for this output
    pub features: u32,
    /// Maturity height (if applicable)
    pub maturity_height: Option<u64>,
    /// The amount value (if decrypted successfully)
    pub amount: Option<u64>,
    /// Whether this output belongs to our wallet
    pub is_mine: bool,
    /// Spending key index used (if this is our output)
    pub key_index: Option<u64>,
}

impl OutputData {
    /// Create a new OutputData with required fields
    pub fn new(commitment: String, range_proof: String, features: u32, is_mine: bool) -> Self {
        Self {
            commitment,
            range_proof,
            encrypted_value: None,
            script: None,
            features,
            maturity_height: None,
            amount: None,
            is_mine,
            key_index: None,
        }
    }

    /// Set the decrypted amount
    pub fn with_amount(mut self, amount: u64) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Set the key index for owned outputs
    pub fn with_key_index(mut self, key_index: u64) -> Self {
        self.key_index = Some(key_index);
        self
    }

    /// Set the maturity height
    pub fn with_maturity_height(mut self, height: u64) -> Self {
        self.maturity_height = Some(height);
        self
    }

    /// Set the script
    pub fn with_script(mut self, script: String) -> Self {
        self.script = Some(script);
        self
    }

    /// Set encrypted value
    pub fn with_encrypted_value(mut self, encrypted_value: Vec<u8>) -> Self {
        self.encrypted_value = Some(encrypted_value);
        self
    }
}

/// Block information associated with an output
#[derive(Debug, Clone)]
pub struct BlockInfo {
    /// Block height where the output was found
    pub height: u64,
    /// Block hash
    pub hash: String,
    /// Block timestamp
    pub timestamp: u64,
    /// Transaction index within the block
    pub transaction_index: Option<usize>,
    /// Output index within the transaction
    pub output_index: usize,
    /// Block difficulty (if available)
    pub difficulty: Option<u64>,
}

impl BlockInfo {
    /// Create new block info with required fields
    pub fn new(height: u64, hash: String, timestamp: u64, output_index: usize) -> Self {
        Self {
            height,
            hash,
            timestamp,
            transaction_index: None,
            output_index,
            difficulty: None,
        }
    }

    /// Set the transaction index
    pub fn with_transaction_index(mut self, tx_index: usize) -> Self {
        self.transaction_index = Some(tx_index);
        self
    }

    /// Set the block difficulty
    pub fn with_difficulty(mut self, difficulty: u64) -> Self {
        self.difficulty = Some(difficulty);
        self
    }
}

/// Address information for the output
#[derive(Debug, Clone)]
pub struct AddressInfo {
    /// The address that can spend this output
    pub address: String,
    /// Address type (e.g., "stealth", "standard", "script")
    pub address_type: String,
    /// Network type (e.g., "mainnet", "testnet", "localnet")
    pub network: String,
    /// Derivation path for deterministic wallets
    pub derivation_path: Option<String>,
    /// Public spend key (if applicable)
    pub public_spend_key: Option<String>,
    /// View key used for scanning (if applicable)
    pub view_key: Option<String>,
}

impl AddressInfo {
    /// Create new address info with required fields
    pub fn new(address: String, address_type: String, network: String) -> Self {
        Self {
            address,
            address_type,
            network,
            derivation_path: None,
            public_spend_key: None,
            view_key: None,
        }
    }

    /// Set the derivation path
    pub fn with_derivation_path(mut self, path: String) -> Self {
        self.derivation_path = Some(path);
        self
    }

    /// Set the public spend key
    pub fn with_public_spend_key(mut self, key: String) -> Self {
        self.public_spend_key = Some(key);
        self
    }

    /// Set the view key
    pub fn with_view_key(mut self, key: String) -> Self {
        self.view_key = Some(key);
        self
    }
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
        output_data: OutputData,
        block_info: BlockInfo,
        address_info: AddressInfo,
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
            WalletScanEvent::OutputFound {
                block_info,
                output_data,
                ..
            } => Some(format!(
                "block: {}, amount: {}, mine: {}",
                block_info.height,
                output_data
                    .amount
                    .map_or("unknown".to_string(), |a| a.to_string()),
                output_data.is_mine
            )),
            WalletScanEvent::ScanProgress {
                current_block,
                total_blocks,
                percentage,
                speed_blocks_per_second,
                estimated_time_remaining,
                ..
            } => Some(format!(
                "{}/{} ({:.1}%), speed: {:.1} bps, ETA: {}",
                current_block,
                total_blocks,
                percentage,
                speed_blocks_per_second,
                estimated_time_remaining
                    .map_or("unknown".to_string(), |dur| format!("{}s", dur.as_secs()))
            )),
            WalletScanEvent::ScanCompleted {
                success,
                final_statistics,
                total_duration,
                ..
            } => Some(format!(
                "success: {}, duration: {:?}, stats: {} items",
                success,
                total_duration,
                final_statistics.len()
            )),
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
                block_info,
                output_data,
                address_info,
            } => {
                format!(
                    "{{\"type\":\"OutputFound\",\"event_id\":\"{}\",\"block_height\":{},\"amount\":{},\"is_mine\":{},\"address\":\"{}\",\"commitment\":\"{}\"}}",
                    metadata.event_id,
                    block_info.height,
                    output_data.amount.map_or("null".to_string(), |a| a.to_string()),
                    output_data.is_mine,
                    address_info.address,
                    output_data.commitment
                )
            }
            WalletScanEvent::ScanProgress {
                metadata,
                current_block,
                total_blocks,
                percentage,
                speed_blocks_per_second,
                estimated_time_remaining,
            } => {
                let eta_seconds = estimated_time_remaining
                    .map_or("null".to_string(), |dur| dur.as_secs().to_string());
                format!(
                    "{{\"type\":\"ScanProgress\",\"event_id\":\"{}\",\"current_block\":{},\"total_blocks\":{},\"percentage\":{:.2},\"speed_bps\":{:.2},\"eta_seconds\":{}}}",
                    metadata.event_id,
                    current_block,
                    total_blocks,
                    percentage,
                    speed_blocks_per_second,
                    eta_seconds
                )
            }
            WalletScanEvent::ScanCompleted {
                metadata,
                final_statistics,
                success,
                total_duration,
            } => {
                let stats_count = final_statistics.len();
                let duration_secs = total_duration.as_secs();
                format!(
                    "{{\"type\":\"ScanCompleted\",\"event_id\":\"{}\",\"success\":{},\"duration_seconds\":{},\"stats_count\":{}}}",
                    metadata.event_id, success, duration_secs, stats_count
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
            WalletScanEvent::OutputFound {
                block_info,
                output_data,
                address_info,
                ..
            } => {
                let amount_str = output_data
                    .amount
                    .map_or("unknown amount".to_string(), |a| format!("{} units", a));
                let mine_str = if output_data.is_mine {
                    "mine"
                } else {
                    "not mine"
                };
                format!(
                    "Found output at block {} ({}, {}, addr: {})",
                    block_info.height, amount_str, mine_str, address_info.address
                )
            }
            WalletScanEvent::ScanProgress {
                current_block,
                total_blocks,
                percentage,
                speed_blocks_per_second,
                estimated_time_remaining,
                ..
            } => {
                let eta_str = estimated_time_remaining.map_or("unknown ETA".to_string(), |dur| {
                    let secs = dur.as_secs();
                    if secs < 60 {
                        format!("{}s", secs)
                    } else if secs < 3600 {
                        format!("{}m {}s", secs / 60, secs % 60)
                    } else {
                        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
                    }
                });
                format!(
                    "Scan progress: {}/{} blocks ({:.1}%) at {:.1} blocks/sec, {}",
                    current_block, total_blocks, percentage, speed_blocks_per_second, eta_str
                )
            }
            WalletScanEvent::ScanCompleted {
                success,
                final_statistics,
                total_duration,
                ..
            } => {
                let duration_str = {
                    let secs = total_duration.as_secs();
                    if secs < 60 {
                        format!("{}s", secs)
                    } else if secs < 3600 {
                        format!("{}m {}s", secs / 60, secs % 60)
                    } else {
                        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
                    }
                };

                let key_stats = [
                    ("blocks_processed", "blocks"),
                    ("outputs_found", "outputs"),
                    ("transactions_found", "transactions"),
                    ("errors_encountered", "errors"),
                ]
                .iter()
                .filter_map(|(key, unit)| {
                    final_statistics
                        .get(*key)
                        .map(|value| format!("{} {}", value, unit))
                })
                .collect::<Vec<_>>()
                .join(", ");

                if key_stats.is_empty() {
                    format!("Scan completed (success: {}) in {}", success, duration_str)
                } else {
                    format!(
                        "Scan completed (success: {}) in {} - {}",
                        success, duration_str, key_stats
                    )
                }
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

    #[test]
    fn test_output_found_event_creation() {
        let output_data = OutputData::new(
            "0x1234567890abcdef".to_string(),
            "range_proof_data".to_string(),
            1,    // features
            true, // is_mine
        )
        .with_amount(1000)
        .with_key_index(5);

        let block_info = BlockInfo::new(
            12345,
            "0xabcdef1234567890".to_string(),
            1697123456,
            2, // output_index
        )
        .with_transaction_index(1);

        let address_info = AddressInfo::new(
            "tari1xyz123...".to_string(),
            "stealth".to_string(),
            "mainnet".to_string(),
        )
        .with_derivation_path("m/44'/0'/0'/0/5".to_string());

        let event = WalletScanEvent::output_found(output_data, block_info, address_info);

        match &event {
            WalletScanEvent::OutputFound {
                metadata,
                output_data,
                block_info,
                address_info,
            } => {
                assert!(!metadata.event_id.is_empty());
                assert_eq!(metadata.source, "wallet_scanner");

                // Test output data
                assert_eq!(output_data.commitment, "0x1234567890abcdef");
                assert_eq!(output_data.range_proof, "range_proof_data");
                assert_eq!(output_data.features, 1);
                assert!(output_data.is_mine);
                assert_eq!(output_data.amount, Some(1000));
                assert_eq!(output_data.key_index, Some(5));

                // Test block info
                assert_eq!(block_info.height, 12345);
                assert_eq!(block_info.hash, "0xabcdef1234567890");
                assert_eq!(block_info.timestamp, 1697123456);
                assert_eq!(block_info.output_index, 2);
                assert_eq!(block_info.transaction_index, Some(1));

                // Test address info
                assert_eq!(address_info.address, "tari1xyz123...");
                assert_eq!(address_info.address_type, "stealth");
                assert_eq!(address_info.network, "mainnet");
                assert_eq!(
                    address_info.derivation_path,
                    Some("m/44'/0'/0'/0/5".to_string())
                );
            }
            _ => panic!("Expected OutputFound event"),
        }
    }

    #[test]
    fn test_output_found_event_traits() {
        let output_data = OutputData::new(
            "0xcommitment123".to_string(),
            "proof_data".to_string(),
            0,
            false, // not mine
        );

        let block_info = BlockInfo::new(98765, "0xblockhash456".to_string(), 1697999999, 0);

        let address_info = AddressInfo::new(
            "tari1abc456...".to_string(),
            "standard".to_string(),
            "testnet".to_string(),
        );

        let event = WalletScanEvent::output_found(output_data, block_info, address_info);

        // Test EventType trait
        assert_eq!(event.event_type(), "OutputFound");
        assert!(event.debug_data().is_some());
        let debug_data = event.debug_data().unwrap();
        assert!(debug_data.contains("block: 98765"));
        assert!(debug_data.contains("mine: false"));
        assert!(debug_data.contains("amount: unknown"));

        // Test SerializableEvent trait
        let summary = event.summary();
        assert!(summary.contains("Found output at block 98765"));
        assert!(summary.contains("not mine"));
        assert!(summary.contains("tari1abc456..."));

        let json = event.to_debug_json().unwrap();
        assert!(json.contains("\"type\":\"OutputFound\""));
        assert!(json.contains("\"block_height\":98765"));
        assert!(json.contains("\"is_mine\":false"));
        assert!(json.contains("\"address\":\"tari1abc456...\""));
        assert!(json.contains("\"commitment\":\"0xcommitment123\""));
    }

    #[test]
    fn test_output_data_builder_pattern() {
        let output_data = OutputData::new("commitment".to_string(), "proof".to_string(), 1, true)
            .with_amount(500)
            .with_key_index(10)
            .with_maturity_height(1000)
            .with_script("script".to_string())
            .with_encrypted_value(vec![1, 2, 3]);

        assert_eq!(output_data.commitment, "commitment");
        assert_eq!(output_data.range_proof, "proof");
        assert_eq!(output_data.features, 1);
        assert!(output_data.is_mine);
        assert_eq!(output_data.amount, Some(500));
        assert_eq!(output_data.key_index, Some(10));
        assert_eq!(output_data.maturity_height, Some(1000));
        assert_eq!(output_data.script, Some("script".to_string()));
        assert_eq!(output_data.encrypted_value, Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_scan_progress_event_creation() {
        let event =
            WalletScanEvent::scan_progress(750, 1000, 75.0, 5.5, Some(Duration::from_secs(45)));

        match &event {
            WalletScanEvent::ScanProgress {
                metadata,
                current_block,
                total_blocks,
                percentage,
                speed_blocks_per_second,
                estimated_time_remaining,
            } => {
                assert!(!metadata.event_id.is_empty());
                assert_eq!(metadata.source, "wallet_scanner");
                assert_eq!(*current_block, 750);
                assert_eq!(*total_blocks, 1000);
                assert_eq!(*percentage, 75.0);
                assert_eq!(*speed_blocks_per_second, 5.5);
                assert_eq!(*estimated_time_remaining, Some(Duration::from_secs(45)));
            }
            _ => panic!("Expected ScanProgress event"),
        }
    }

    #[test]
    fn test_scan_progress_event_traits() {
        let event =
            WalletScanEvent::scan_progress(500, 2000, 25.0, 10.0, Some(Duration::from_secs(150)));

        // Test EventType trait
        assert_eq!(event.event_type(), "ScanProgress");
        assert!(event.debug_data().is_some());
        let debug_data = event.debug_data().unwrap();
        assert!(debug_data.contains("500/2000"));
        assert!(debug_data.contains("25.0%"));
        assert!(debug_data.contains("speed: 10.0 bps"));
        assert!(debug_data.contains("ETA: 150s"));

        // Test SerializableEvent trait
        let summary = event.summary();
        assert!(summary.contains("Scan progress: 500/2000 blocks"));
        assert!(summary.contains("25.0%"));
        assert!(summary.contains("10.0 blocks/sec"));
        assert!(summary.contains("2m 30s"));

        let json = event.to_debug_json().unwrap();
        assert!(json.contains("\"type\":\"ScanProgress\""));
        assert!(json.contains("\"current_block\":500"));
        assert!(json.contains("\"total_blocks\":2000"));
        assert!(json.contains("\"percentage\":25.00"));
        assert!(json.contains("\"speed_bps\":10.00"));
        assert!(json.contains("\"eta_seconds\":150"));
    }

    #[test]
    fn test_scan_progress_no_eta() {
        let event = WalletScanEvent::scan_progress(100, 500, 20.0, 2.0, None);

        match &event {
            WalletScanEvent::ScanProgress {
                estimated_time_remaining,
                ..
            } => {
                assert_eq!(*estimated_time_remaining, None);
            }
            _ => panic!("Expected ScanProgress event"),
        }

        // Test serialization handles None ETA
        let debug_data = event.debug_data().unwrap();
        assert!(debug_data.contains("ETA: unknown"));

        let summary = event.summary();
        assert!(summary.contains("unknown ETA"));

        let json = event.to_debug_json().unwrap();
        assert!(json.contains("\"eta_seconds\":null"));
    }

    #[test]
    fn test_scan_progress_eta_formatting() {
        // Test different ETA durations
        let test_cases = vec![
            (Duration::from_secs(30), "30s"),
            (Duration::from_secs(90), "1m 30s"),
            (Duration::from_secs(3661), "1h 1m"),
            (Duration::from_secs(7200), "2h 0m"),
        ];

        for (duration, expected_format) in test_cases {
            let event = WalletScanEvent::scan_progress(100, 200, 50.0, 1.0, Some(duration));
            let summary = event.summary();
            assert!(
                summary.contains(expected_format),
                "Expected '{}' in summary: {}",
                expected_format,
                summary
            );
        }
    }

    #[test]
    fn test_scan_progress_edge_cases() {
        // Test 0% progress
        let event = WalletScanEvent::scan_progress(0, 1000, 0.0, 0.0, None);
        match &event {
            WalletScanEvent::ScanProgress {
                current_block,
                percentage,
                speed_blocks_per_second,
                ..
            } => {
                assert_eq!(*current_block, 0);
                assert_eq!(*percentage, 0.0);
                assert_eq!(*speed_blocks_per_second, 0.0);
            }
            _ => panic!("Expected ScanProgress event"),
        }

        // Test 100% progress
        let event = WalletScanEvent::scan_progress(1000, 1000, 100.0, 5.0, Some(Duration::ZERO));
        match &event {
            WalletScanEvent::ScanProgress {
                current_block,
                total_blocks,
                percentage,
                estimated_time_remaining,
                ..
            } => {
                assert_eq!(*current_block, 1000);
                assert_eq!(*total_blocks, 1000);
                assert_eq!(*percentage, 100.0);
                assert_eq!(*estimated_time_remaining, Some(Duration::ZERO));
            }
            _ => panic!("Expected ScanProgress event"),
        }
    }

    #[test]
    fn test_scan_progress_with_correlation_id() {
        let metadata =
            EventMetadata::with_correlation("wallet_scanner", "scan_batch_456".to_string());
        let event = WalletScanEvent::ScanProgress {
            metadata,
            current_block: 300,
            total_blocks: 600,
            percentage: 50.0,
            speed_blocks_per_second: 8.0,
            estimated_time_remaining: Some(Duration::from_secs(37)),
        };

        match &event {
            WalletScanEvent::ScanProgress { metadata, .. } => {
                assert_eq!(metadata.correlation_id, Some("scan_batch_456".to_string()));
                assert_eq!(metadata.source, "wallet_scanner");
            }
            _ => panic!("Expected ScanProgress event"),
        }
    }

    #[test]
    fn test_scan_completed_event_creation() {
        let mut final_stats = HashMap::new();
        final_stats.insert("blocks_processed".to_string(), 1000);
        final_stats.insert("outputs_found".to_string(), 25);
        final_stats.insert("transactions_found".to_string(), 15);
        final_stats.insert("errors_encountered".to_string(), 0);

        let event =
            WalletScanEvent::scan_completed(final_stats.clone(), true, Duration::from_secs(300));

        match &event {
            WalletScanEvent::ScanCompleted {
                metadata,
                final_statistics,
                success,
                total_duration,
            } => {
                assert!(!metadata.event_id.is_empty());
                assert_eq!(metadata.source, "wallet_scanner");
                assert_eq!(*success, true);
                assert_eq!(*total_duration, Duration::from_secs(300));
                assert_eq!(final_statistics.len(), 4);
                assert_eq!(final_statistics.get("blocks_processed"), Some(&1000));
                assert_eq!(final_statistics.get("outputs_found"), Some(&25));
                assert_eq!(final_statistics.get("transactions_found"), Some(&15));
                assert_eq!(final_statistics.get("errors_encountered"), Some(&0));
            }
            _ => panic!("Expected ScanCompleted event"),
        }
    }

    #[test]
    fn test_scan_completed_event_traits() {
        let mut final_stats = HashMap::new();
        final_stats.insert("blocks_processed".to_string(), 500);
        final_stats.insert("outputs_found".to_string(), 10);

        let event = WalletScanEvent::scan_completed(final_stats, true, Duration::from_secs(150));

        // Test EventType trait
        assert_eq!(event.event_type(), "ScanCompleted");
        assert!(event.debug_data().is_some());
        let debug_data = event.debug_data().unwrap();
        assert!(debug_data.contains("success: true"));
        assert!(debug_data.contains("duration: 150s"));
        assert!(debug_data.contains("stats: 2 items"));

        // Test SerializableEvent trait
        let summary = event.summary();
        assert!(summary.contains("Scan completed (success: true)"));
        assert!(summary.contains("2m 30s"));
        assert!(summary.contains("500 blocks"));
        assert!(summary.contains("10 outputs"));

        let json = event.to_debug_json().unwrap();
        assert!(json.contains("\"type\":\"ScanCompleted\""));
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"duration_seconds\":150"));
        assert!(json.contains("\"stats_count\":2"));
    }

    #[test]
    fn test_scan_completed_failure() {
        let mut final_stats = HashMap::new();
        final_stats.insert("blocks_processed".to_string(), 750);
        final_stats.insert("errors_encountered".to_string(), 5);

        let event = WalletScanEvent::scan_completed(final_stats, false, Duration::from_secs(45));

        match &event {
            WalletScanEvent::ScanCompleted { success, .. } => {
                assert_eq!(*success, false);
            }
            _ => panic!("Expected ScanCompleted event"),
        }

        let summary = event.summary();
        assert!(summary.contains("success: false"));
        assert!(summary.contains("45s"));
        assert!(summary.contains("750 blocks"));
        assert!(summary.contains("5 errors"));
    }

    #[test]
    fn test_scan_completed_empty_stats() {
        let empty_stats = HashMap::new();
        let event = WalletScanEvent::scan_completed(empty_stats, true, Duration::from_secs(30));

        // Test with empty statistics
        let debug_data = event.debug_data().unwrap();
        assert!(debug_data.contains("stats: 0 items"));

        let summary = event.summary();
        assert!(summary.contains("Scan completed (success: true) in 30s"));
        // Should not contain additional stats when empty
        assert!(!summary.contains(" - "));
    }

    #[test]
    fn test_scan_completed_duration_formatting() {
        // Test different duration formats
        let test_cases = vec![
            (Duration::from_secs(30), "30s"),
            (Duration::from_secs(90), "1m 30s"),
            (Duration::from_secs(3661), "1h 1m"),
            (Duration::from_secs(7200), "2h 0m"),
        ];

        for (duration, expected_format) in test_cases {
            let event = WalletScanEvent::scan_completed(HashMap::new(), true, duration);
            let summary = event.summary();
            assert!(
                summary.contains(expected_format),
                "Expected '{}' in summary: {}",
                expected_format,
                summary
            );
        }
    }

    #[test]
    fn test_scan_completed_with_correlation_id() {
        let metadata =
            EventMetadata::with_correlation("wallet_scanner", "final_scan_789".to_string());
        let mut stats = HashMap::new();
        stats.insert("blocks_processed".to_string(), 100);

        let event = WalletScanEvent::ScanCompleted {
            metadata,
            final_statistics: stats,
            success: true,
            total_duration: Duration::from_secs(60),
        };

        match &event {
            WalletScanEvent::ScanCompleted { metadata, .. } => {
                assert_eq!(metadata.correlation_id, Some("final_scan_789".to_string()));
                assert_eq!(metadata.source, "wallet_scanner");
            }
            _ => panic!("Expected ScanCompleted event"),
        }
    }

    #[test]
    fn test_scan_completed_comprehensive_stats() {
        let mut comprehensive_stats = HashMap::new();
        comprehensive_stats.insert("blocks_processed".to_string(), 2000);
        comprehensive_stats.insert("outputs_found".to_string(), 150);
        comprehensive_stats.insert("transactions_found".to_string(), 75);
        comprehensive_stats.insert("errors_encountered".to_string(), 3);
        comprehensive_stats.insert("average_block_time_ms".to_string(), 250);
        comprehensive_stats.insert("total_value_found".to_string(), 50000);

        let event = WalletScanEvent::scan_completed(
            comprehensive_stats,
            true,
            Duration::from_secs(1800), // 30 minutes
        );

        let summary = event.summary();
        assert!(summary.contains("2000 blocks"));
        assert!(summary.contains("150 outputs"));
        assert!(summary.contains("75 transactions"));
        assert!(summary.contains("3 errors"));
        assert!(summary.contains("30m 0s"));

        // Should only include the key stats, not all stats
        assert!(!summary.contains("average_block_time_ms"));
        assert!(!summary.contains("total_value_found"));
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
    pub fn output_found(
        output_data: OutputData,
        block_info: BlockInfo,
        address_info: AddressInfo,
    ) -> Self {
        Self::OutputFound {
            metadata: EventMetadata::new("wallet_scanner"),
            output_data,
            block_info,
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
