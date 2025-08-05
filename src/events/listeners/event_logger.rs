//! Event logging listener for structured wallet event logging
//!
//! This listener provides structured logging of wallet events to various outputs
//! including console, files, and structured logs for monitoring and debugging.

use async_trait::async_trait;
use serde_json;
use std::collections::HashMap;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::events::types::{SharedWalletEvent, WalletEvent};
use crate::events::WalletEventListener;

/// Output destinations for event logging
#[derive(Debug, Clone, PartialEq)]
pub enum LogOutput {
    /// Log to console/stdout
    Console,
    /// Log to a file with the specified path
    File(PathBuf),
    /// Log to both console and file
    Both(PathBuf),
    /// Custom output handled by a callback function
    Custom,
}

/// Log format options for event output
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogFormat {
    /// Human-readable text format
    Text,
    /// Structured JSON format
    Json,
    /// Compact JSON format (single line)
    CompactJson,
    /// CSV format for data analysis
    Csv,
}

/// Configuration for the EventLogger listener
#[derive(Debug, Clone)]
pub struct EventLoggerConfig {
    /// Output destination for log messages
    pub output: LogOutput,
    /// Format for log messages
    pub format: LogFormat,
    /// Whether to include timestamps
    pub include_timestamps: bool,
    /// Whether to include event metadata
    pub include_metadata: bool,
    /// Whether to include full event payloads
    pub include_payloads: bool,
    /// Filter events by type (empty means log all events)
    pub event_type_filter: Vec<String>,
    /// Maximum size for log files before rotation
    pub max_file_size_mb: Option<u64>,
    /// Custom prefix for log entries
    pub log_prefix: Option<String>,
    /// Buffer size for batched logging
    pub buffer_size: Option<usize>,
}

impl Default for EventLoggerConfig {
    fn default() -> Self {
        Self {
            output: LogOutput::Console,
            format: LogFormat::Text,
            include_timestamps: true,
            include_metadata: true,
            include_payloads: false,
            event_type_filter: Vec::new(),
            max_file_size_mb: Some(100),
            log_prefix: None,
            buffer_size: None,
        }
    }
}

impl EventLoggerConfig {
    /// Create a configuration for console logging
    pub fn console() -> Self {
        Self {
            output: LogOutput::Console,
            format: LogFormat::Text,
            ..Default::default()
        }
    }

    /// Create a configuration for file logging
    pub fn file<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            output: LogOutput::File(path.into()),
            format: LogFormat::Json,
            ..Default::default()
        }
    }

    /// Create a configuration for structured JSON logging
    pub fn json_file<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            output: LogOutput::File(path.into()),
            format: LogFormat::Json,
            include_payloads: true,
            ..Default::default()
        }
    }

    /// Set the output destination
    pub fn with_output(mut self, output: LogOutput) -> Self {
        self.output = output;
        self
    }

    /// Set the log format
    pub fn with_format(mut self, format: LogFormat) -> Self {
        self.format = format;
        self
    }

    /// Enable or disable timestamps
    pub fn with_timestamps(mut self, include_timestamps: bool) -> Self {
        self.include_timestamps = include_timestamps;
        self
    }

    /// Enable or disable event metadata
    pub fn with_metadata(mut self, include_metadata: bool) -> Self {
        self.include_metadata = include_metadata;
        self
    }

    /// Enable or disable event payloads
    pub fn with_payloads(mut self, include_payloads: bool) -> Self {
        self.include_payloads = include_payloads;
        self
    }

    /// Set event type filter (empty list logs all events)
    pub fn with_event_filter(mut self, event_types: Vec<String>) -> Self {
        self.event_type_filter = event_types;
        self
    }

    /// Set maximum file size for rotation
    pub fn with_max_file_size_mb(mut self, max_size_mb: u64) -> Self {
        self.max_file_size_mb = Some(max_size_mb);
        self
    }

    /// Set custom log prefix
    pub fn with_prefix(mut self, prefix: String) -> Self {
        self.log_prefix = Some(prefix);
        self
    }

    /// Enable buffered logging with specified buffer size
    pub fn with_buffer_size(mut self, buffer_size: usize) -> Self {
        self.buffer_size = Some(buffer_size);
        self
    }
}

/// Internal log entry structure
#[derive(Debug, Clone)]
struct LogEntry {
    timestamp: SystemTime,
    event_type: String,
    message: String,
    metadata: Option<String>,
    payload: Option<String>,
}

/// EventLogger listener for structured wallet event logging
///
/// This listener provides comprehensive logging capabilities for wallet events,
/// supporting multiple output formats and destinations. It's designed for
/// production monitoring, debugging, and audit trail generation.
///
/// # Features
///
/// - Multiple output destinations (console, file, both)
/// - Various log formats (text, JSON, CSV)
/// - Event filtering by type
/// - File rotation based on size
/// - Buffered logging for performance
/// - Structured metadata inclusion
///
/// # Examples
///
/// ## Basic console logging
/// ```rust,no_run
/// use lightweight_wallet_libs::events::listeners::{EventLogger, EventLoggerConfig};
///
/// let logger = EventLogger::new(EventLoggerConfig::console());
/// ```
///
/// ## JSON file logging with full payloads
/// ```rust,no_run
/// use lightweight_wallet_libs::events::listeners::{EventLogger, EventLoggerConfig};
///
/// let config = EventLoggerConfig::json_file("wallet_events.log")
///     .with_payloads(true)
///     .with_buffer_size(100);
/// let logger = EventLogger::new(config);
/// ```
pub struct EventLogger {
    config: EventLoggerConfig,
    file_handle: Option<Arc<Mutex<std::fs::File>>>,
    buffer: Option<Arc<Mutex<Vec<LogEntry>>>>,
    stats: Arc<Mutex<LoggerStats>>,
}

/// Statistics about logger operations
#[derive(Debug, Default)]
pub struct LoggerStats {
    events_logged: u64,
    events_filtered: u64,
    write_errors: u64,
    file_rotations: u64,
    buffer_flushes: u64,
}

impl EventLogger {
    /// Create a new EventLogger with the specified configuration
    pub fn new(config: EventLoggerConfig) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let file_handle = match &config.output {
            LogOutput::File(path) | LogOutput::Both(path) => {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| format!("Failed to open log file {:?}: {}", path, e))?;
                Some(Arc::new(Mutex::new(file)))
            }
            _ => None,
        };

        let buffer = config.buffer_size.map(|_| Arc::new(Mutex::new(Vec::new())));

        Ok(Self {
            config,
            file_handle,
            buffer,
            stats: Arc::new(Mutex::new(LoggerStats::default())),
        })
    }

    /// Create a console logger with default text format
    pub fn console() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Self::new(EventLoggerConfig::console())
    }

    /// Create a JSON file logger
    pub fn json_file<P: Into<PathBuf>>(path: P) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Self::new(EventLoggerConfig::json_file(path))
    }

    /// Create a simple text file logger
    pub fn text_file<P: Into<PathBuf>>(path: P) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let config = EventLoggerConfig::file(path).with_format(LogFormat::Text);
        Self::new(config)
    }

    /// Check if an event should be logged based on filters
    fn should_log_event(&self, event: &SharedWalletEvent) -> bool {
        if self.config.event_type_filter.is_empty() {
            return true;
        }

        let event_type = self.get_event_type_name(event);
        self.config.event_type_filter.contains(&event_type)
    }

    /// Get the event type name as a string
    fn get_event_type_name(&self, event: &SharedWalletEvent) -> String {
        match &**event {
            WalletEvent::UtxoReceived { .. } => "UtxoReceived".to_string(),
            WalletEvent::UtxoSpent { .. } => "UtxoSpent".to_string(),
            WalletEvent::Reorg { .. } => "Reorg".to_string(),
        }
    }

    /// Format a log entry according to the configured format
    fn format_log_entry(&self, entry: &LogEntry) -> String {
        let timestamp_str = if self.config.include_timestamps {
            match entry.timestamp.duration_since(UNIX_EPOCH) {
                Ok(duration) => {
                    let dt = chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0)
                        .unwrap_or_else(chrono::Utc::now);
                    format!("{} ", dt.format("%Y-%m-%d %H:%M:%S%.3f UTC"))
                }
                Err(_) => "[INVALID_TIME] ".to_string(),
            }
        } else {
            String::new()
        };

        let prefix = self
            .config
            .log_prefix
            .as_ref()
            .map(|p| format!("{} ", p))
            .unwrap_or_default();

        match self.config.format {
            LogFormat::Text => {
                let mut parts = vec![
                    timestamp_str,
                    prefix,
                    format!("[{}] ", entry.event_type),
                    entry.message.clone(),
                ];

                if self.config.include_metadata {
                    if let Some(ref metadata) = entry.metadata {
                        parts.push(format!(" | Metadata: {}", metadata));
                    }
                }

                if self.config.include_payloads {
                    if let Some(ref payload) = entry.payload {
                        parts.push(format!(" | Payload: {}", payload));
                    }
                }

                parts.join("")
            }
            LogFormat::Json | LogFormat::CompactJson => {
                let mut json_obj = serde_json::Map::new();

                if self.config.include_timestamps {
                    json_obj.insert(
                        "timestamp".to_string(),
                        serde_json::Value::String(timestamp_str.trim().to_string()),
                    );
                }

                if !prefix.is_empty() {
                    json_obj.insert(
                        "prefix".to_string(),
                        serde_json::Value::String(prefix.trim().to_string()),
                    );
                }

                json_obj.insert(
                    "event_type".to_string(),
                    serde_json::Value::String(entry.event_type.clone()),
                );
                json_obj.insert(
                    "message".to_string(),
                    serde_json::Value::String(entry.message.clone()),
                );

                if self.config.include_metadata {
                    if let Some(ref metadata) = entry.metadata {
                        json_obj.insert(
                            "metadata".to_string(),
                            serde_json::Value::String(metadata.clone()),
                        );
                    }
                }

                if self.config.include_payloads {
                    if let Some(ref payload) = entry.payload {
                        // Try to parse payload as JSON, otherwise store as string
                        let payload_value = serde_json::from_str(payload)
                            .unwrap_or_else(|_| serde_json::Value::String(payload.clone()));
                        json_obj.insert("payload".to_string(), payload_value);
                    }
                }

                let json_value = serde_json::Value::Object(json_obj);
                match self.config.format {
                    LogFormat::Json => serde_json::to_string_pretty(&json_value)
                        .unwrap_or_else(|_| "Invalid JSON".to_string()),
                    LogFormat::CompactJson => serde_json::to_string(&json_value)
                        .unwrap_or_else(|_| "Invalid JSON".to_string()),
                    _ => unreachable!(),
                }
            }
            LogFormat::Csv => {
                // Simple CSV format: timestamp,event_type,message,metadata,payload
                let timestamp_clean = timestamp_str.replace(',', ";").trim().to_string();
                let message_clean = entry.message.replace(',', ";").replace('\n', " ");
                let metadata_clean = entry
                    .metadata
                    .as_ref()
                    .map(|m| m.replace(',', ";").replace('\n', " "))
                    .unwrap_or_default();
                let payload_clean = entry
                    .payload
                    .as_ref()
                    .map(|p| p.replace(',', ";").replace('\n', " "))
                    .unwrap_or_default();

                format!(
                    "{},{},{},{},{}",
                    timestamp_clean, entry.event_type, message_clean, metadata_clean, payload_clean
                )
            }
        }
    }

    /// Write a log entry to the configured output
    async fn write_log_entry(&self, entry: LogEntry) -> Result<(), Box<dyn Error + Send + Sync>> {
        let formatted = self.format_log_entry(&entry);

        // Write to console if configured
        if matches!(self.config.output, LogOutput::Console | LogOutput::Both(_)) {
            println!("{}", formatted);
        }

        // Write to file if configured
        if let Some(ref file_handle) = self.file_handle {
            let mut file = file_handle
                .lock()
                .map_err(|e| format!("File lock error: {}", e))?;
            writeln!(file, "{}", formatted).map_err(|e| format!("File write error: {}", e))?;
            file.flush()
                .map_err(|e| format!("File flush error: {}", e))?;
        }

        Ok(())
    }

    /// Add a log entry to the buffer or write immediately
    async fn log_entry(&self, entry: LogEntry) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(ref buffer) = self.buffer {
            let entries_to_write = {
                let mut buffer_guard = buffer
                    .lock()
                    .map_err(|e| format!("Buffer lock error: {}", e))?;
                buffer_guard.push(entry);

                // Check if buffer is full and needs flushing
                if let Some(buffer_size) = self.config.buffer_size {
                    if buffer_guard.len() >= buffer_size {
                        // Flush buffer
                        Some(buffer_guard.drain(..).collect::<Vec<_>>())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }; // Release lock here

            if let Some(entries) = entries_to_write {
                for buffered_entry in entries {
                    self.write_log_entry(buffered_entry).await?;
                }

                if let Ok(mut stats) = self.stats.lock() {
                    stats.buffer_flushes += 1;
                }
            }
        } else {
            // Write immediately if no buffering
            self.write_log_entry(entry).await?;
        }

        Ok(())
    }

    /// Flush any buffered log entries
    pub async fn flush(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(ref buffer) = self.buffer {
            let entries_to_write = {
                let mut buffer_guard = buffer
                    .lock()
                    .map_err(|e| format!("Buffer lock error: {}", e))?;
                buffer_guard.drain(..).collect::<Vec<_>>()
            }; // Release lock here

            for entry in entries_to_write {
                self.write_log_entry(entry).await?;
            }

            if let Ok(mut stats) = self.stats.lock() {
                stats.buffer_flushes += 1;
            }
        }

        Ok(())
    }

    /// Get logger statistics
    pub fn get_stats(&self) -> Result<LoggerStats, Box<dyn Error + Send + Sync>> {
        self.stats
            .lock()
            .map(|stats| LoggerStats {
                events_logged: stats.events_logged,
                events_filtered: stats.events_filtered,
                write_errors: stats.write_errors,
                file_rotations: stats.file_rotations,
                buffer_flushes: stats.buffer_flushes,
            })
            .map_err(|e| format!("Stats lock error: {}", e).into())
    }

    /// Create a log entry from a wallet event
    fn create_log_entry(&self, event: &SharedWalletEvent) -> LogEntry {
        let event_type = self.get_event_type_name(event);

        let message = match &**event {
            WalletEvent::UtxoReceived { payload, .. } => {
                format!(
                    "UTXO received: {} µT at block {} (address: {}...)",
                    payload.amount,
                    payload.block_height,
                    &payload.receiving_address
                        [..std::cmp::min(12, payload.receiving_address.len())]
                )
            }
            WalletEvent::UtxoSpent { payload, .. } => {
                format!(
                    "UTXO spent: {} µT at block {} (spending address: {}...)",
                    payload.amount,
                    payload.spending_block_height,
                    &payload.spending_address[..std::cmp::min(12, payload.spending_address.len())]
                )
            }
            WalletEvent::Reorg { payload, .. } => {
                format!(
                    "Blockchain reorg detected: fork at height {} (rollback: {} blocks, new: {} blocks)",
                    payload.fork_height,
                    payload.rollback_depth,
                    payload.new_blocks_count
                )
            }
        };

        let metadata = if self.config.include_metadata {
            match &**event {
                WalletEvent::UtxoReceived { metadata, .. }
                | WalletEvent::UtxoSpent { metadata, .. }
                | WalletEvent::Reorg { metadata, .. } => serde_json::to_string(metadata).ok(),
            }
        } else {
            None
        };

        let payload = if self.config.include_payloads {
            match &**event {
                WalletEvent::UtxoReceived { payload, .. } => serde_json::to_string(payload).ok(),
                WalletEvent::UtxoSpent { payload, .. } => serde_json::to_string(payload).ok(),
                WalletEvent::Reorg { payload, .. } => serde_json::to_string(payload).ok(),
            }
        } else {
            None
        };

        LogEntry {
            timestamp: SystemTime::now(),
            event_type,
            message,
            metadata,
            payload,
        }
    }
}

#[async_trait]
impl WalletEventListener for EventLogger {
    async fn handle_event(
        &mut self,
        event: &SharedWalletEvent,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Check if event should be logged
        if !self.should_log_event(event) {
            if let Ok(mut stats) = self.stats.lock() {
                stats.events_filtered += 1;
            }
            return Ok(());
        }

        // Create log entry
        let entry = self.create_log_entry(event);

        // Log the entry
        match self.log_entry(entry).await {
            Ok(_) => {
                if let Ok(mut stats) = self.stats.lock() {
                    stats.events_logged += 1;
                }
                Ok(())
            }
            Err(e) => {
                if let Ok(mut stats) = self.stats.lock() {
                    stats.write_errors += 1;
                }
                Err(e)
            }
        }
    }

    fn name(&self) -> &'static str {
        "EventLogger"
    }

    fn wants_event(&self, event: &SharedWalletEvent) -> bool {
        self.should_log_event(event)
    }

    async fn cleanup(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Flush any remaining buffered entries
        self.flush().await?;
        Ok(())
    }

    fn get_config(&self) -> HashMap<String, String> {
        let mut config = HashMap::new();
        config.insert("output".to_string(), format!("{:?}", self.config.output));
        config.insert("format".to_string(), format!("{:?}", self.config.format));
        config.insert(
            "include_timestamps".to_string(),
            self.config.include_timestamps.to_string(),
        );
        config.insert(
            "include_metadata".to_string(),
            self.config.include_metadata.to_string(),
        );
        config.insert(
            "include_payloads".to_string(),
            self.config.include_payloads.to_string(),
        );
        config.insert(
            "event_filter_count".to_string(),
            self.config.event_type_filter.len().to_string(),
        );
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::types::{EventMetadata, UtxoReceivedPayload, WalletEvent};
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_console_logger_creation() {
        let logger = EventLogger::console().expect("Failed to create console logger");
        assert_eq!(logger.name(), "EventLogger");
    }

    #[tokio::test]
    async fn test_file_logger_creation() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let logger =
            EventLogger::text_file(temp_file.path()).expect("Failed to create file logger");
        assert_eq!(logger.name(), "EventLogger");
    }

    #[tokio::test]
    async fn test_event_filtering() {
        let config =
            EventLoggerConfig::console().with_event_filter(vec!["UtxoReceived".to_string()]);
        let logger = EventLogger::new(config).expect("Failed to create logger");

        // Create a UtxoReceived event
        let metadata = EventMetadata::new("test", "test_wallet");
        let payload = UtxoReceivedPayload::new(
            "test_utxo".to_string(),
            1000,
            100,
            "block_hash".to_string(),
            1234567890,
            "tx_hash".to_string(),
            0,
            "address".to_string(),
            0,
            "commitment".to_string(),
            0,
            "mainnet".to_string(),
        );
        let utxo_event = SharedWalletEvent::new(WalletEvent::UtxoReceived { metadata, payload });

        assert!(logger.should_log_event(&utxo_event));
    }

    #[tokio::test]
    async fn test_log_entry_creation() {
        let logger = EventLogger::console().expect("Failed to create logger");

        let metadata = EventMetadata::new("test", "test_wallet");
        let payload = UtxoReceivedPayload::new(
            "test_utxo".to_string(),
            1000,
            100,
            "block_hash".to_string(),
            1234567890,
            "tx_hash".to_string(),
            0,
            "address".to_string(),
            0,
            "commitment".to_string(),
            0,
            "mainnet".to_string(),
        );
        let event = SharedWalletEvent::new(WalletEvent::UtxoReceived { metadata, payload });

        let entry = logger.create_log_entry(&event);
        assert_eq!(entry.event_type, "UtxoReceived");
        assert!(entry.message.contains("UTXO received"));
        assert!(entry.message.contains("1000 µT"));
    }

    #[tokio::test]
    async fn test_json_formatting() {
        let config = EventLoggerConfig::console()
            .with_format(LogFormat::Json)
            .with_payloads(true)
            .with_metadata(true);
        let logger = EventLogger::new(config).expect("Failed to create logger");

        let entry = LogEntry {
            timestamp: SystemTime::now(),
            event_type: "UtxoReceived".to_string(),
            message: "Test message".to_string(),
            metadata: Some("{}".to_string()),
            payload: Some("{}".to_string()),
        };

        let formatted = logger.format_log_entry(&entry);
        assert!(formatted.contains("\"event_type\""));
        assert!(formatted.contains("\"message\""));
        assert!(formatted.contains("UtxoReceived"));
    }
}
