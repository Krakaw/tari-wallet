//! Console logging listener for development and debugging wallet scan events
//!
//! This listener provides comprehensive console output for all wallet scanning events,
//! with configurable formatting, verbosity levels, and color support for enhanced
//! development and debugging experience.

use async_trait::async_trait;
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::events::types::{BlockInfo, EventType, OutputData, SpentOutputData};
use crate::events::{EventListener, SerializableEvent, SharedEvent, WalletScanEvent};

/// Verbosity levels for console logging
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Only log critical events (errors, completion)
    Minimal,
    /// Log important events (start, completion, errors, major progress)
    Normal,
    /// Log all events with basic information
    Verbose,
    /// Log all events with full details and debug information
    Debug,
}

impl LogLevel {
    /// Check if an event should be logged at this level
    pub fn should_log(&self, event: &WalletScanEvent) -> bool {
        match (self, event) {
            (LogLevel::Minimal, WalletScanEvent::ScanError { .. }) => true,
            (LogLevel::Minimal, WalletScanEvent::ScanCompleted { .. }) => true,
            (LogLevel::Minimal, WalletScanEvent::ScanCancelled { .. }) => true,
            (LogLevel::Minimal, _) => false,

            (LogLevel::Normal, WalletScanEvent::ScanStarted { .. }) => true,
            (LogLevel::Normal, WalletScanEvent::ScanCompleted { .. }) => true,
            (LogLevel::Normal, WalletScanEvent::ScanError { .. }) => true,
            (LogLevel::Normal, WalletScanEvent::ScanCancelled { .. }) => true,
            (LogLevel::Normal, WalletScanEvent::ScanProgress { .. }) => true,
            (LogLevel::Normal, WalletScanEvent::OutputFound { .. }) => true,
            (LogLevel::Normal, WalletScanEvent::SpentOutputFound { .. }) => true,
            (LogLevel::Normal, _) => false,

            (LogLevel::Verbose, _) => true,
            (LogLevel::Debug, _) => true,
        }
    }
}

/// Color codes for console output (ANSI escape sequences)
#[derive(Debug, Clone)]
pub struct ConsoleColors {
    pub info: &'static str,
    pub success: &'static str,
    pub warning: &'static str,
    pub error: &'static str,
    pub debug: &'static str,
    pub reset: &'static str,
    pub bold: &'static str,
    pub dim: &'static str,
}

impl ConsoleColors {
    /// Create color codes for colored output
    pub fn colored() -> Self {
        Self {
            info: "\x1b[36m",    // Cyan
            success: "\x1b[32m", // Green
            warning: "\x1b[33m", // Yellow
            error: "\x1b[31m",   // Red
            debug: "\x1b[35m",   // Magenta
            reset: "\x1b[0m",    // Reset
            bold: "\x1b[1m",     // Bold
            dim: "\x1b[2m",      // Dim
        }
    }

    /// Create empty color codes for plain text output
    pub fn plain() -> Self {
        Self {
            info: "",
            success: "",
            warning: "",
            error: "",
            debug: "",
            reset: "",
            bold: "",
            dim: "",
        }
    }
}

/// Configuration for console logging output
#[derive(Debug, Clone)]
pub struct ConsoleLoggingConfig {
    /// Verbosity level for logging
    pub log_level: LogLevel,
    /// Whether to use colors in output
    pub use_colors: bool,
    /// Whether to include timestamps
    pub include_timestamps: bool,
    /// Whether to include event IDs
    pub include_event_ids: bool,
    /// Whether to include correlation IDs when available
    pub include_correlation_ids: bool,
    /// Whether to include JSON debug data for debug level
    pub include_json_debug: bool,
    /// Custom prefix for all log messages
    pub log_prefix: Option<String>,
    /// Maximum length for truncating long messages
    pub max_message_length: Option<usize>,
}

impl Default for ConsoleLoggingConfig {
    fn default() -> Self {
        Self {
            log_level: LogLevel::Normal,
            use_colors: true,
            include_timestamps: true,
            include_event_ids: false,
            include_correlation_ids: true,
            include_json_debug: false,
            log_prefix: None,
            max_message_length: None,
        }
    }
}

impl ConsoleLoggingConfig {
    /// Create a new configuration with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the log level
    pub fn with_log_level(mut self, level: LogLevel) -> Self {
        self.log_level = level;
        self
    }

    /// Enable or disable colors
    pub fn with_colors(mut self, use_colors: bool) -> Self {
        self.use_colors = use_colors;
        self
    }

    /// Enable or disable timestamps
    pub fn with_timestamps(mut self, include_timestamps: bool) -> Self {
        self.include_timestamps = include_timestamps;
        self
    }

    /// Enable or disable event IDs
    pub fn with_event_ids(mut self, include_event_ids: bool) -> Self {
        self.include_event_ids = include_event_ids;
        self
    }

    /// Enable or disable correlation IDs
    pub fn with_correlation_ids(mut self, include_correlation_ids: bool) -> Self {
        self.include_correlation_ids = include_correlation_ids;
        self
    }

    /// Enable or disable JSON debug output
    pub fn with_json_debug(mut self, include_json_debug: bool) -> Self {
        self.include_json_debug = include_json_debug;
        self
    }

    /// Set a custom log prefix
    pub fn with_prefix(mut self, prefix: String) -> Self {
        self.log_prefix = Some(prefix);
        self
    }

    /// Set maximum message length for truncation
    pub fn with_max_message_length(mut self, max_length: usize) -> Self {
        self.max_message_length = Some(max_length);
        self
    }

    /// Create a minimal configuration for CI/production
    pub fn minimal() -> Self {
        Self {
            log_level: LogLevel::Minimal,
            use_colors: false,
            include_timestamps: false,
            include_event_ids: false,
            include_correlation_ids: false,
            include_json_debug: false,
            log_prefix: None,
            max_message_length: Some(200),
        }
    }

    /// Create a debug configuration for development
    pub fn debug() -> Self {
        Self {
            log_level: LogLevel::Debug,
            use_colors: true,
            include_timestamps: true,
            include_event_ids: true,
            include_correlation_ids: true,
            include_json_debug: true,
            log_prefix: Some("[WALLET_SCAN]".to_string()),
            max_message_length: None,
        }
    }
}

/// Internal state for tracking scan statistics
#[derive(Debug, Clone, Default)]
struct ScanStats {
    outputs_found: usize,
    blocks_processed: usize,
    errors_encountered: usize,
    start_timestamp: Option<SystemTime>,
    last_progress_percent: f64,
}

/// Console logging listener for wallet scanning events
///
/// This listener outputs formatted log messages to the console for all wallet
/// scanning events, providing real-time visibility into the scanning process.
/// It supports various verbosity levels, color coding, and customizable formatting.
///
/// # Examples
///
/// ## Basic Usage
/// ```rust,ignore
/// use lightweight_wallet_libs::events::listeners::{ConsoleLoggingListener, LogLevel};
///
/// let listener = ConsoleLoggingListener::new();
/// // Uses default configuration (Normal level, colors enabled)
/// ```
///
/// ## Custom Configuration
/// ```rust,ignore
/// use lightweight_wallet_libs::events::listeners::{
///     ConsoleLoggingListener, ConsoleLoggingConfig, LogLevel
/// };
///
/// let config = ConsoleLoggingConfig::new()
///     .with_log_level(LogLevel::Debug)
///     .with_prefix("[SCAN]".to_string())
///     .with_json_debug(true);
///     
/// let listener = ConsoleLoggingListener::with_config(config);
/// ```
///
/// ## Production Configuration
/// ```rust,ignore
/// let listener = ConsoleLoggingListener::minimal();
/// // Only logs errors and completion, no colors, short messages
/// ```
pub struct ConsoleLoggingListener {
    config: ConsoleLoggingConfig,
    colors: ConsoleColors,
    stats: Arc<Mutex<ScanStats>>,
}

impl ConsoleLoggingListener {
    /// Create a new console logging listener with default configuration
    pub fn new() -> Self {
        let config = ConsoleLoggingConfig::default();
        let colors = if config.use_colors {
            ConsoleColors::colored()
        } else {
            ConsoleColors::plain()
        };

        Self {
            config,
            colors,
            stats: Arc::new(Mutex::new(ScanStats::default())),
        }
    }

    /// Create a console logging listener with custom configuration
    pub fn with_config(config: ConsoleLoggingConfig) -> Self {
        let colors = if config.use_colors {
            ConsoleColors::colored()
        } else {
            ConsoleColors::plain()
        };

        Self {
            config,
            colors,
            stats: Arc::new(Mutex::new(ScanStats::default())),
        }
    }

    /// Create a minimal console logging listener for production use
    pub fn minimal() -> Self {
        Self::with_config(ConsoleLoggingConfig::minimal())
    }

    /// Create a debug console logging listener for development
    pub fn debug() -> Self {
        Self::with_config(ConsoleLoggingConfig::debug())
    }

    /// Create a builder for configuring the console logging listener
    pub fn builder() -> ConsoleLoggingListenerBuilder {
        ConsoleLoggingListenerBuilder::new()
    }

    /// Format a timestamp for display
    fn format_timestamp(&self, timestamp: SystemTime) -> String {
        if !self.config.include_timestamps {
            return String::new();
        }

        match timestamp.duration_since(UNIX_EPOCH) {
            Ok(duration) => {
                let secs = duration.as_secs();
                let millis = duration.subsec_millis();
                let dt = chrono::DateTime::from_timestamp(secs as i64, 0)
                    .unwrap_or_else(chrono::Utc::now);
                format!(
                    "{}{}[{}]{} ",
                    self.colors.dim,
                    dt.format("%H:%M:%S"),
                    millis,
                    self.colors.reset
                )
            }
            Err(_) => {
                format!("{}[INVALID_TIME]{} ", self.colors.dim, self.colors.reset)
            }
        }
    }

    /// Format event metadata information
    fn format_metadata(&self, event: &WalletScanEvent) -> String {
        let metadata = event.metadata();
        let mut parts = Vec::new();

        if self.config.include_event_ids {
            parts.push(format!("id:{}", &metadata.event_id[..8])); // First 8 chars
        }

        if self.config.include_correlation_ids {
            if let Some(ref correlation_id) = metadata.correlation_id {
                parts.push(format!("corr:{}", correlation_id));
            }
        }

        if parts.is_empty() {
            String::new()
        } else {
            format!(
                "{}[{}]{} ",
                self.colors.dim,
                parts.join(","),
                self.colors.reset
            )
        }
    }

    /// Truncate message if needed
    fn truncate_message(&self, message: String) -> String {
        match self.config.max_message_length {
            Some(max_len) if message.len() > max_len => {
                format!("{}...", &message[..max_len.saturating_sub(3)])
            }
            _ => message,
        }
    }

    /// Format and print a log message
    fn log_message(
        &self,
        event: &WalletScanEvent,
        level_color: &str,
        level_name: &str,
        message: String,
    ) {
        let timestamp = self.format_timestamp(event.metadata().timestamp);
        let metadata = self.format_metadata(event);
        let prefix = self.config.log_prefix.as_deref().unwrap_or("");
        let message = self.truncate_message(message);

        let formatted = format!(
            "{}{}{}[{}]{} {}{}{}",
            timestamp,
            prefix,
            level_color,
            level_name,
            self.colors.reset,
            metadata,
            message,
            self.colors.reset
        );

        // Use appropriate output stream based on event type
        match event {
            WalletScanEvent::ScanError { .. } => eprintln!("{formatted}"),
            _ => println!("{formatted}"),
        }
    }

    /// Handle ScanStarted events
    fn handle_scan_started(
        &self,
        config: &crate::events::types::ScanConfig,
        block_range: &(u64, u64),
        wallet_context: &str,
    ) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.start_timestamp = Some(SystemTime::now());
            stats.outputs_found = 0;
            stats.blocks_processed = 0;
            stats.errors_encountered = 0;
            stats.last_progress_percent = 0.0;
        }

        let batch_size = config
            .batch_size
            .map_or("default".to_string(), |s| s.to_string());
        let timeout = config
            .timeout_seconds
            .map_or("none".to_string(), |t| format!("{}s", t));
        let block_count = block_range.1.saturating_sub(block_range.0) + 1;

        let message = format!(
            "{bold}Starting scan{reset} for '{context}' - blocks {start}-{end} ({count} blocks) [batch: {batch}, timeout: {timeout}]",
            bold = self.colors.bold,
            reset = self.colors.reset,
            context = wallet_context,
            start = block_range.0,
            end = block_range.1,
            count = block_count,
            batch = batch_size,
            timeout = timeout
        );

        self.log_message(
            &WalletScanEvent::ScanStarted {
                metadata: crate::events::types::EventMetadata::new("console_logger"),
                config: config.clone(),
                block_range: *block_range,
                wallet_context: wallet_context.to_string(),
            },
            self.colors.info,
            "INFO",
            message,
        );
    }

    /// Handle BlockProcessed events
    fn handle_block_processed(
        &self,
        height: u64,
        hash: &str,
        processing_duration: &std::time::Duration,
        outputs_count: usize,
    ) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.blocks_processed += 1;
        }

        if self.config.log_level >= LogLevel::Debug {
            let message = format!(
                "Block {} processed in {:?} - {} outputs (hash: {}...)",
                height,
                processing_duration,
                outputs_count,
                &hash[..std::cmp::min(8, hash.len())]
            );

            self.log_message(
                &WalletScanEvent::BlockProcessed {
                    metadata: crate::events::types::EventMetadata::new("console_logger"),
                    height,
                    hash: hash.to_string(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    processing_duration: *processing_duration,
                    outputs_count,
                    spent_outputs_count: 0,
                },
                self.colors.debug,
                "DEBUG",
                message,
            );
        }
    }

    /// Handle OutputFound events
    fn handle_output_found(
        &self,
        output_data: &crate::events::types::OutputData,
        block_info: &crate::events::types::BlockInfo,
        address_info: &crate::events::types::AddressInfo,
    ) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.outputs_found += 1;
        }

        let amount_str = output_data
            .amount
            .map_or("unknown".to_string(), |a| format!("{}", a));
        let mine_str = if output_data.is_mine { "MINE" } else { "OTHER" };
        let color = if output_data.is_mine {
            self.colors.success
        } else {
            self.colors.info
        };

        let message = format!(
            "{}Found output{} at block {} - {} amount: {} ({}...)",
            color,
            self.colors.reset,
            block_info.height,
            mine_str,
            amount_str,
            &address_info.address[..std::cmp::min(12, address_info.address.len())]
        );

        self.log_message(
            &WalletScanEvent::OutputFound {
                metadata: crate::events::types::EventMetadata::new("console_logger"),
                output_data: output_data.clone(),
                block_info: block_info.clone(),
                address_info: address_info.clone(),
                transaction_data: crate::events::types::TransactionData::new(
                    output_data.amount.unwrap_or(0),
                    "Found".to_string(),
                    "Inbound".to_string(),
                    block_info.timestamp,
                ),
            },
            color,
            "OUTPUT",
            message,
        );
    }

    /// Handle SpentOutputFound events
    ///
    /// Log information about spent outputs
    fn handle_spent_output_found(
        &mut self,
        spent_output_data: &SpentOutputData,
        spending_block_info: &BlockInfo,
    ) {
        let amount_str = spent_output_data
            .spent_amount
            .map_or("unknown".to_string(), |a| format!("{}", a));

        let message = format!(
            "Spent output {} (amount: {}) at block {} via {} (input #{})",
            spent_output_data.spent_commitment,
            amount_str,
            spending_block_info.height,
            spent_output_data.match_method,
            spent_output_data.input_index
        );

        self.log_message(
            &WalletScanEvent::SpentOutputFound {
                metadata: crate::events::types::EventMetadata::new("console_logger"),
                spent_output_data: spent_output_data.clone(),
                spending_block_info: spending_block_info.clone(),
                original_output_info: OutputData::new(
                    spent_output_data.spent_commitment.clone(),
                    String::new(),
                    0,
                    true,
                ),
                spending_transaction_data: crate::events::types::TransactionData::new(
                    spent_output_data.spent_amount.unwrap_or(0),
                    "Spent".to_string(),
                    "Outbound".to_string(),
                    spending_block_info.timestamp,
                ),
            },
            "",
            "SPENT",
            message,
        );
    }

    /// Handle ScanProgress events
    fn handle_scan_progress(
        &self,
        current_block: u64,
        total_blocks: u64,
        percentage: f64,
        speed_blocks_per_second: f64,
        estimated_time_remaining: &Option<std::time::Duration>,
    ) {
        if let Ok(mut stats) = self.stats.lock() {
            // Only log progress if it's a significant change (>= 1%) or every 1000 blocks for debug
            let percent_diff = (percentage - stats.last_progress_percent).abs();
            let should_log = match self.config.log_level {
                LogLevel::Debug => percent_diff >= 0.1 || current_block % 100 == 0,
                LogLevel::Verbose => percent_diff >= 0.5,
                _ => percent_diff >= 1.0,
            };

            if !should_log {
                return;
            }

            stats.last_progress_percent = percentage;
        }

        let eta_str = estimated_time_remaining.map_or("unknown".to_string(), |eta| {
            let secs = eta.as_secs();
            if secs < 60 {
                format!("{}s", secs)
            } else if secs < 3600 {
                format!("{}m{}s", secs / 60, secs % 60)
            } else {
                format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
            }
        });

        let progress_bar = if self.config.use_colors {
            let filled = (percentage / 5.0) as usize; // 20 character bar
            let empty = 20 - filled;
            format!(
                "{}[{}{}{}]{}",
                self.colors.dim,
                "=".repeat(filled),
                if filled < 20 { ">" } else { "" },
                " ".repeat(empty.saturating_sub(if filled < 20 { 1 } else { 0 })),
                self.colors.reset
            )
        } else {
            String::new()
        };

        let message = format!(
            "{}Progress{}: {:.1}% ({}/{}) {} {:.1} blocks/sec, ETA: {}",
            self.colors.info,
            self.colors.reset,
            percentage,
            current_block,
            total_blocks,
            progress_bar,
            speed_blocks_per_second,
            eta_str
        );

        self.log_message(
            &WalletScanEvent::ScanProgress {
                metadata: crate::events::types::EventMetadata::new("console_logger"),
                current_block,
                total_blocks,
                percentage,
                speed_blocks_per_second,
                estimated_time_remaining: *estimated_time_remaining,
            },
            self.colors.info,
            "PROGRESS",
            message,
        );
    }

    /// Handle ScanCompleted events
    fn handle_scan_completed(
        &self,
        final_statistics: &HashMap<String, u64>,
        success: bool,
        total_duration: &std::time::Duration,
    ) {
        let stats = self.stats.lock().unwrap();
        let color = if success {
            self.colors.success
        } else {
            self.colors.warning
        };
        let status = if success {
            "COMPLETED"
        } else {
            "FINISHED WITH ISSUES"
        };

        let duration_str = {
            let secs = total_duration.as_secs();
            if secs < 60 {
                format!("{}s", secs)
            } else if secs < 3600 {
                format!("{}m{}s", secs / 60, secs % 60)
            } else {
                format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
            }
        };

        let mut stats_parts = Vec::new();
        if let Some(blocks) = final_statistics.get("blocks_processed") {
            stats_parts.push(format!("{} blocks", blocks));
        }
        if let Some(outputs) = final_statistics.get("outputs_found") {
            stats_parts.push(format!("{} outputs", outputs));
        }
        if let Some(errors) = final_statistics.get("errors_encountered") {
            if *errors > 0 {
                stats_parts.push(format!("{} errors", errors));
            }
        }

        let stats_str = if stats_parts.is_empty() {
            format!(
                "{} blocks, {} outputs",
                stats.blocks_processed, stats.outputs_found
            )
        } else {
            stats_parts.join(", ")
        };

        let message = format!(
            "{}Scan {}{} in {} - {}",
            color, status, self.colors.reset, duration_str, stats_str
        );

        self.log_message(
            &WalletScanEvent::ScanCompleted {
                metadata: crate::events::types::EventMetadata::new("console_logger"),
                final_statistics: final_statistics.clone(),
                success,
                total_duration: *total_duration,
            },
            color,
            "COMPLETE",
            message,
        );
    }

    /// Handle ScanError events
    fn handle_scan_error(
        &self,
        error_message: &str,
        error_code: &Option<String>,
        block_height: &Option<u64>,
        is_recoverable: bool,
    ) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.errors_encountered += 1;
        }

        let recoverable_str = if is_recoverable {
            "recoverable"
        } else {
            "fatal"
        };
        let block_str = block_height.map_or(String::new(), |h| format!(" at block {}", h));
        let code_str = error_code
            .as_ref()
            .map_or(String::new(), |c| format!(" [{}]", c));

        let message = format!(
            "{}Scan error{} ({}){}{}: {}",
            self.colors.error,
            self.colors.reset,
            recoverable_str,
            block_str,
            code_str,
            error_message
        );

        self.log_message(
            &WalletScanEvent::ScanError {
                metadata: crate::events::types::EventMetadata::new("console_logger"),
                error_message: error_message.to_string(),
                error_code: error_code.clone(),
                block_height: *block_height,
                retry_info: None,
                is_recoverable,
            },
            self.colors.error,
            "ERROR",
            message,
        );
    }

    /// Handle ScanCancelled events
    fn handle_scan_cancelled(
        &self,
        reason: &str,
        final_statistics: &HashMap<String, u64>,
        partial_completion: &Option<f64>,
    ) {
        let completion_str =
            partial_completion.map_or(String::new(), |p| format!(" ({:.1}% complete)", p));

        let stats_summary = final_statistics
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect::<Vec<_>>()
            .join(", ");

        let message = format!(
            "{}Scan cancelled{}{} - {} [{}]",
            self.colors.warning, self.colors.reset, completion_str, reason, stats_summary
        );

        self.log_message(
            &WalletScanEvent::ScanCancelled {
                metadata: crate::events::types::EventMetadata::new("console_logger"),
                reason: reason.to_string(),
                final_statistics: final_statistics.clone(),
                partial_completion: *partial_completion,
            },
            self.colors.warning,
            "CANCELLED",
            message,
        );
    }

    /// Log JSON debug information for an event
    fn log_json_debug(&self, event: &WalletScanEvent) {
        if !self.config.include_json_debug || self.config.log_level < LogLevel::Debug {
            return;
        }

        match event.to_debug_json() {
            Ok(json) => {
                println!(
                    "{}[JSON_DEBUG]{} {}",
                    self.colors.dim, self.colors.reset, json
                );
            }
            Err(e) => {
                eprintln!(
                    "{}[JSON_ERROR]{} Failed to serialize event: {}",
                    self.colors.error, self.colors.reset, e
                );
            }
        }
    }
}

impl Default for ConsoleLoggingListener {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for configuring ConsoleLoggingListener with fluent interface
///
/// This builder provides a convenient way to construct a ConsoleLoggingListener
/// with custom configuration options. It follows the same pattern as other
/// event listener builders in the system.
///
/// # Examples
///
/// ## Basic Usage
/// ```rust,ignore
/// use lightweight_wallet_libs::events::listeners::{ConsoleLoggingListener, LogLevel};
///
/// let listener = ConsoleLoggingListener::builder()
///     .log_level(LogLevel::Debug)
///     .with_colors(true)
///     .with_prefix("[SCAN]".to_string())
///     .build();
/// ```
///
/// ## Production Configuration
/// ```rust,ignore
/// let listener = ConsoleLoggingListener::builder()
///     .minimal_preset()
///     .with_prefix("[PROD]".to_string())
///     .build();
/// ```
///
/// ## Development Configuration
/// ```rust,ignore
/// let listener = ConsoleLoggingListener::builder()
///     .debug_preset()
///     .max_message_length(1000)
///     .build();
/// ```
pub struct ConsoleLoggingListenerBuilder {
    config: ConsoleLoggingConfig,
}

impl ConsoleLoggingListenerBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: ConsoleLoggingConfig::default(),
        }
    }

    /// Set the log level for filtering events
    ///
    /// # Arguments
    /// * `level` - The minimum log level to display
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ConsoleLoggingListener::builder()
    ///     .log_level(LogLevel::Verbose)
    ///     .build();
    /// ```
    pub fn log_level(mut self, level: LogLevel) -> Self {
        self.config.log_level = level;
        self
    }

    /// Enable or disable colored output
    ///
    /// # Arguments
    /// * `use_colors` - Whether to use ANSI color codes in output
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ConsoleLoggingListener::builder()
    ///     .with_colors(false)  // Disable colors for CI
    ///     .build();
    /// ```
    pub fn with_colors(mut self, use_colors: bool) -> Self {
        self.config.use_colors = use_colors;
        self
    }

    /// Enable or disable timestamp inclusion
    ///
    /// # Arguments
    /// * `include_timestamps` - Whether to include timestamps in log output
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ConsoleLoggingListener::builder()
    ///     .with_timestamps(true)
    ///     .build();
    /// ```
    pub fn with_timestamps(mut self, include_timestamps: bool) -> Self {
        self.config.include_timestamps = include_timestamps;
        self
    }

    /// Enable or disable event ID inclusion
    ///
    /// # Arguments
    /// * `include_event_ids` - Whether to include event IDs in log output
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ConsoleLoggingListener::builder()
    ///     .with_event_ids(true)  // Useful for debugging
    ///     .build();
    /// ```
    pub fn with_event_ids(mut self, include_event_ids: bool) -> Self {
        self.config.include_event_ids = include_event_ids;
        self
    }

    /// Enable or disable correlation ID inclusion
    ///
    /// # Arguments
    /// * `include_correlation_ids` - Whether to include correlation IDs when available
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ConsoleLoggingListener::builder()
    ///     .with_correlation_ids(true)
    ///     .build();
    /// ```
    pub fn with_correlation_ids(mut self, include_correlation_ids: bool) -> Self {
        self.config.include_correlation_ids = include_correlation_ids;
        self
    }

    /// Enable or disable JSON debug output
    ///
    /// # Arguments
    /// * `include_json_debug` - Whether to include full JSON event data in debug mode
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ConsoleLoggingListener::builder()
    ///     .with_json_debug(true)  // Full JSON output for deep debugging
    ///     .build();
    /// ```
    pub fn with_json_debug(mut self, include_json_debug: bool) -> Self {
        self.config.include_json_debug = include_json_debug;
        self
    }

    /// Set a custom prefix for all log messages
    ///
    /// # Arguments
    /// * `prefix` - The prefix string to prepend to all log messages
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ConsoleLoggingListener::builder()
    ///     .with_prefix("[WALLET_SCAN]".to_string())
    ///     .build();
    /// ```
    pub fn with_prefix(mut self, prefix: String) -> Self {
        self.config.log_prefix = Some(prefix);
        self
    }

    /// Set maximum message length for truncation
    ///
    /// # Arguments
    /// * `max_length` - Maximum characters before truncating messages
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ConsoleLoggingListener::builder()
    ///     .max_message_length(200)  // Limit for CI environments
    ///     .build();
    /// ```
    pub fn max_message_length(mut self, max_length: usize) -> Self {
        self.config.max_message_length = Some(max_length);
        self
    }

    /// Apply minimal preset configuration for production/CI use
    ///
    /// This preset:
    /// - Sets log level to Minimal (errors and completion only)
    /// - Disables colors
    /// - Disables timestamps
    /// - Disables event IDs and correlation IDs
    /// - Disables JSON debug output
    /// - Sets message length limit to 200 characters
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ConsoleLoggingListener::builder()
    ///     .minimal_preset()
    ///     .build();
    /// ```
    pub fn minimal_preset(mut self) -> Self {
        self.config = ConsoleLoggingConfig::minimal();
        self
    }

    /// Apply debug preset configuration for development use
    ///
    /// This preset:
    /// - Sets log level to Debug (all events)
    /// - Enables colors
    /// - Enables timestamps
    /// - Enables event IDs and correlation IDs
    /// - Enables JSON debug output
    /// - Sets default prefix to "[WALLET_SCAN]"
    /// - No message length limit
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ConsoleLoggingListener::builder()
    ///     .debug_preset()
    ///     .build();
    /// ```
    pub fn debug_preset(mut self) -> Self {
        self.config = ConsoleLoggingConfig::debug();
        self
    }

    /// Apply verbose preset configuration for detailed monitoring
    ///
    /// This preset:
    /// - Sets log level to Verbose
    /// - Enables colors
    /// - Enables timestamps
    /// - Enables correlation IDs but not event IDs
    /// - Disables JSON debug output
    /// - No message length limit
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ConsoleLoggingListener::builder()
    ///     .verbose_preset()
    ///     .build();
    /// ```
    pub fn verbose_preset(mut self) -> Self {
        self.config = ConsoleLoggingConfig::new()
            .with_log_level(LogLevel::Verbose)
            .with_colors(true)
            .with_timestamps(true)
            .with_event_ids(false)
            .with_correlation_ids(true)
            .with_json_debug(false);
        self
    }

    /// Apply CI-friendly preset configuration
    ///
    /// This preset:
    /// - Sets log level to Normal
    /// - Disables colors (CI-friendly)
    /// - Enables timestamps for log correlation
    /// - Disables event IDs but enables correlation IDs
    /// - Disables JSON debug output
    /// - Sets message length limit to 300 characters
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ConsoleLoggingListener::builder()
    ///     .ci_preset()
    ///     .build();
    /// ```
    pub fn ci_preset(mut self) -> Self {
        self.config = ConsoleLoggingConfig::new()
            .with_log_level(LogLevel::Normal)
            .with_colors(false)
            .with_timestamps(true)
            .with_event_ids(false)
            .with_correlation_ids(true)
            .with_json_debug(false)
            .with_max_message_length(300);
        self
    }

    /// Apply console-only preset configuration (no file/network output)
    ///
    /// This preset is optimized for interactive console use:
    /// - Sets log level to Normal
    /// - Enables colors for better readability
    /// - Enables timestamps
    /// - Disables event IDs (too verbose for console)
    /// - Enables correlation IDs for flow tracking
    /// - Disables JSON debug output
    /// - No message length limit
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ConsoleLoggingListener::builder()
    ///     .console_preset()
    ///     .build();
    /// ```
    pub fn console_preset(mut self) -> Self {
        self.config = ConsoleLoggingConfig::new()
            .with_log_level(LogLevel::Normal)
            .with_colors(true)
            .with_timestamps(true)
            .with_event_ids(false)
            .with_correlation_ids(true)
            .with_json_debug(false);
        self
    }

    /// Build the configured ConsoleLoggingListener
    ///
    /// # Returns
    /// A fully configured ConsoleLoggingListener instance
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ConsoleLoggingListener::builder()
    ///     .log_level(LogLevel::Verbose)
    ///     .with_colors(true)
    ///     .build();
    /// ```
    pub fn build(self) -> ConsoleLoggingListener {
        ConsoleLoggingListener::with_config(self.config)
    }
}

impl Default for ConsoleLoggingListenerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventListener for ConsoleLoggingListener {
    async fn handle_event(
        &mut self,
        event: &SharedEvent,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Check if this event should be logged at the current level
        if !self.config.log_level.should_log(&event) {
            return Ok(());
        }

        // Handle each event type specifically
        match event.as_ref() {
            WalletScanEvent::ScanStarted {
                config,
                block_range,
                wallet_context,
                ..
            } => {
                self.handle_scan_started(config, block_range, wallet_context);
            }
            WalletScanEvent::BlockProcessed {
                height,
                hash,
                processing_duration,
                outputs_count,
                ..
            } => {
                self.handle_block_processed(*height, hash, processing_duration, *outputs_count);
            }
            WalletScanEvent::OutputFound {
                output_data,
                block_info,
                address_info,
                ..
            } => {
                self.handle_output_found(output_data, block_info, address_info);
            }
            WalletScanEvent::SpentOutputFound {
                spent_output_data,
                spending_block_info,
                ..
            } => {
                self.handle_spent_output_found(spent_output_data, spending_block_info);
            }
            WalletScanEvent::ScanProgress {
                current_block,
                total_blocks,
                percentage,
                speed_blocks_per_second,
                estimated_time_remaining,
                ..
            } => {
                self.handle_scan_progress(
                    *current_block,
                    *total_blocks,
                    *percentage,
                    *speed_blocks_per_second,
                    estimated_time_remaining,
                );
            }
            WalletScanEvent::ScanCompleted {
                final_statistics,
                success,
                total_duration,
                ..
            } => {
                self.handle_scan_completed(final_statistics, *success, total_duration);
            }
            WalletScanEvent::ScanError {
                error_message,
                error_code,
                block_height,
                is_recoverable,
                ..
            } => {
                self.handle_scan_error(error_message, error_code, block_height, *is_recoverable);
            }
            WalletScanEvent::ScanCancelled {
                reason,
                final_statistics,
                partial_completion,
                ..
            } => {
                self.handle_scan_cancelled(reason, final_statistics, partial_completion);
            }
        }

        // Log JSON debug information if enabled
        self.log_json_debug(&event);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::types::{AddressInfo, BlockInfo, EventMetadata, OutputData, ScanConfig};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_console_logging_listener_creation() {
        let listener = ConsoleLoggingListener::new();
        assert_eq!(listener.config.log_level, LogLevel::Normal);
        assert!(listener.config.use_colors);
        assert!(listener.config.include_timestamps);
        assert!(!listener.config.include_event_ids);
        assert!(listener.config.include_correlation_ids);
    }

    #[test]
    fn test_console_logging_config_builder() {
        let config = ConsoleLoggingConfig::new()
            .with_log_level(LogLevel::Debug)
            .with_colors(false)
            .with_prefix("[TEST]".to_string())
            .with_max_message_length(100);

        assert_eq!(config.log_level, LogLevel::Debug);
        assert!(!config.use_colors);
        assert_eq!(config.log_prefix, Some("[TEST]".to_string()));
        assert_eq!(config.max_message_length, Some(100));
    }

    #[test]
    fn test_minimal_config() {
        let config = ConsoleLoggingConfig::minimal();
        assert_eq!(config.log_level, LogLevel::Minimal);
        assert!(!config.use_colors);
        assert!(!config.include_timestamps);
        assert_eq!(config.max_message_length, Some(200));
    }

    #[test]
    fn test_debug_config() {
        let config = ConsoleLoggingConfig::debug();
        assert_eq!(config.log_level, LogLevel::Debug);
        assert!(config.use_colors);
        assert!(config.include_timestamps);
        assert!(config.include_event_ids);
        assert!(config.include_json_debug);
    }

    #[test]
    fn test_log_level_filtering() {
        let error_event = WalletScanEvent::ScanError {
            metadata: EventMetadata::new("test"),
            error_message: "Test error".to_string(),
            error_code: None,
            block_height: None,
            retry_info: None,
            is_recoverable: false,
        };

        let progress_event = WalletScanEvent::ScanProgress {
            metadata: EventMetadata::new("test"),
            current_block: 100,
            total_blocks: 1000,
            percentage: 10.0,
            speed_blocks_per_second: 5.0,
            estimated_time_remaining: None,
        };

        // Minimal level should log errors but not progress
        assert!(LogLevel::Minimal.should_log(&error_event));
        assert!(!LogLevel::Minimal.should_log(&progress_event));

        // Normal level should log both
        assert!(LogLevel::Normal.should_log(&error_event));
        assert!(LogLevel::Normal.should_log(&progress_event));

        // Debug level should log everything
        assert!(LogLevel::Debug.should_log(&error_event));
        assert!(LogLevel::Debug.should_log(&progress_event));
    }

    #[test]
    fn test_colored_vs_plain_colors() {
        let colored = ConsoleColors::colored();
        let plain = ConsoleColors::plain();

        assert!(!colored.error.is_empty());
        assert!(!colored.success.is_empty());
        assert!(!colored.info.is_empty());

        assert!(plain.error.is_empty());
        assert!(plain.success.is_empty());
        assert!(plain.info.is_empty());
    }

    #[tokio::test]
    async fn test_handle_scan_started_event() {
        let mut listener = ConsoleLoggingListener::new();
        let config = ScanConfig::new().with_batch_size(25);

        let event = Arc::new(WalletScanEvent::ScanStarted {
            metadata: EventMetadata::new("test"),
            config,
            block_range: (1000, 2000),
            wallet_context: "test_wallet".to_string(),
        });

        // Should not panic and should update internal stats
        let result = listener.handle_event(&event).await;
        assert!(result.is_ok());

        let stats = listener.stats.lock().unwrap();
        assert!(stats.start_timestamp.is_some());
        assert_eq!(stats.outputs_found, 0);
        assert_eq!(stats.blocks_processed, 0);
    }

    #[tokio::test]
    async fn test_handle_output_found_event() {
        let mut listener = ConsoleLoggingListener::new();

        let output_data = OutputData::new(
            "commitment_123".to_string(),
            "proof_456".to_string(),
            1,
            true,
        )
        .with_amount(1000);

        let block_info = BlockInfo::new(12345, "block_hash_abc".to_string(), 1697123456, 0);

        let address_info = AddressInfo::new(
            "tari1xyz123...".to_string(),
            "stealth".to_string(),
            "mainnet".to_string(),
        );

        let transaction_data = crate::events::types::TransactionData::new(
            1000,
            "MinedConfirmed".to_string(),
            "Inbound".to_string(),
            1697123456,
        );

        let event = Arc::new(WalletScanEvent::OutputFound {
            metadata: EventMetadata::new("test"),
            output_data,
            block_info,
            address_info,
            transaction_data,
        });

        let result = listener.handle_event(&event).await;
        assert!(result.is_ok());

        let stats = listener.stats.lock().unwrap();
        assert_eq!(stats.outputs_found, 1);
    }

    #[tokio::test]
    async fn test_handle_scan_completed_event() {
        let mut listener = ConsoleLoggingListener::new();
        let mut final_stats = HashMap::new();
        final_stats.insert("blocks_processed".to_string(), 1000);
        final_stats.insert("outputs_found".to_string(), 5);

        let event = Arc::new(WalletScanEvent::ScanCompleted {
            metadata: EventMetadata::new("test"),
            final_statistics: final_stats,
            success: true,
            total_duration: Duration::from_secs(120),
        });

        let result = listener.handle_event(&event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_scan_error_event() {
        let mut listener = ConsoleLoggingListener::new();

        let event = Arc::new(WalletScanEvent::ScanError {
            metadata: EventMetadata::new("test"),
            error_message: "Connection timeout".to_string(),
            error_code: Some("TIMEOUT".to_string()),
            block_height: Some(12345),
            retry_info: None,
            is_recoverable: true,
        });

        let result = listener.handle_event(&event).await;
        assert!(result.is_ok());

        let stats = listener.stats.lock().unwrap();
        assert_eq!(stats.errors_encountered, 1);
    }

    #[tokio::test]
    async fn test_log_level_filtering_in_handler() {
        let mut minimal_listener = ConsoleLoggingListener::with_config(
            ConsoleLoggingConfig::new().with_log_level(LogLevel::Minimal),
        );

        // Progress event should be filtered out at minimal level
        let progress_event = Arc::new(WalletScanEvent::ScanProgress {
            metadata: EventMetadata::new("test"),
            current_block: 100,
            total_blocks: 1000,
            percentage: 10.0,
            speed_blocks_per_second: 5.0,
            estimated_time_remaining: None,
        });

        let result = minimal_listener.handle_event(&progress_event).await;
        assert!(result.is_ok());
        // Should return early due to log level filtering
    }

    #[test]
    fn test_message_truncation() {
        let config = ConsoleLoggingConfig::new().with_max_message_length(20);
        let listener = ConsoleLoggingListener::with_config(config);

        let long_message = "This is a very long message that should be truncated".to_string();
        let truncated = listener.truncate_message(long_message);

        assert_eq!(truncated.len(), 20);
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn test_timestamp_formatting() {
        let listener = ConsoleLoggingListener::new();
        let timestamp = SystemTime::now();
        let formatted = listener.format_timestamp(timestamp);

        // Should contain timestamp format when timestamps are enabled
        assert!(!formatted.is_empty());
        assert!(formatted.contains("["));
        assert!(formatted.contains("]"));
    }

    #[test]
    fn test_timestamp_formatting_disabled() {
        let config = ConsoleLoggingConfig::new().with_timestamps(false);
        let listener = ConsoleLoggingListener::with_config(config);
        let timestamp = SystemTime::now();
        let formatted = listener.format_timestamp(timestamp);

        // Should be empty when timestamps are disabled
        assert!(formatted.is_empty());
    }

    #[tokio::test]
    async fn test_console_logging_with_correlation_id() {
        let mut listener = ConsoleLoggingListener::with_config(
            ConsoleLoggingConfig::new().with_correlation_ids(true),
        );

        let metadata = EventMetadata::with_correlation("test", "scan_123".to_string());
        let event = Arc::new(WalletScanEvent::ScanError {
            metadata,
            error_message: "Test error".to_string(),
            error_code: None,
            block_height: None,
            retry_info: None,
            is_recoverable: false,
        });

        let result = listener.handle_event(&event).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_stats_state_management() {
        let listener = ConsoleLoggingListener::new();

        // Initial state
        {
            let stats = listener.stats.lock().unwrap();
            assert_eq!(stats.outputs_found, 0);
            assert_eq!(stats.blocks_processed, 0);
            assert_eq!(stats.errors_encountered, 0);
        }

        // Simulate scan started
        listener.handle_scan_started(&ScanConfig::default(), &(1000, 2000), "test_wallet");

        {
            let stats = listener.stats.lock().unwrap();
            assert!(stats.start_timestamp.is_some());
            assert_eq!(stats.outputs_found, 0);
        }
    }

    #[test]
    fn test_console_logging_listener_builder_basic() {
        let listener = ConsoleLoggingListener::builder()
            .log_level(LogLevel::Debug)
            .with_colors(false)
            .with_timestamps(true)
            .build();

        assert_eq!(listener.config.log_level, LogLevel::Debug);
        assert!(!listener.config.use_colors);
        assert!(listener.config.include_timestamps);
    }

    #[test]
    fn test_console_logging_listener_builder_advanced() {
        let listener = ConsoleLoggingListener::builder()
            .with_event_ids(true)
            .with_correlation_ids(false)
            .with_json_debug(true)
            .with_prefix("[TEST]".to_string())
            .max_message_length(500)
            .build();

        assert!(listener.config.include_event_ids);
        assert!(!listener.config.include_correlation_ids);
        assert!(listener.config.include_json_debug);
        assert_eq!(listener.config.log_prefix, Some("[TEST]".to_string()));
        assert_eq!(listener.config.max_message_length, Some(500));
    }

    #[test]
    fn test_console_logging_listener_builder_presets() {
        // Test minimal preset
        let minimal_listener = ConsoleLoggingListener::builder().minimal_preset().build();
        assert_eq!(minimal_listener.config.log_level, LogLevel::Minimal);
        assert!(!minimal_listener.config.use_colors);
        assert!(!minimal_listener.config.include_timestamps);
        assert_eq!(minimal_listener.config.max_message_length, Some(200));

        // Test debug preset
        let debug_listener = ConsoleLoggingListener::builder().debug_preset().build();
        assert_eq!(debug_listener.config.log_level, LogLevel::Debug);
        assert!(debug_listener.config.use_colors);
        assert!(debug_listener.config.include_timestamps);
        assert!(debug_listener.config.include_event_ids);
        assert!(debug_listener.config.include_json_debug);

        // Test verbose preset
        let verbose_listener = ConsoleLoggingListener::builder().verbose_preset().build();
        assert_eq!(verbose_listener.config.log_level, LogLevel::Verbose);
        assert!(verbose_listener.config.use_colors);
        assert!(verbose_listener.config.include_timestamps);
        assert!(!verbose_listener.config.include_event_ids);
        assert!(verbose_listener.config.include_correlation_ids);
        assert!(!verbose_listener.config.include_json_debug);

        // Test CI preset
        let ci_listener = ConsoleLoggingListener::builder().ci_preset().build();
        assert_eq!(ci_listener.config.log_level, LogLevel::Normal);
        assert!(!ci_listener.config.use_colors);
        assert!(ci_listener.config.include_timestamps);
        assert!(!ci_listener.config.include_event_ids);
        assert!(ci_listener.config.include_correlation_ids);
        assert_eq!(ci_listener.config.max_message_length, Some(300));

        // Test console preset
        let console_listener = ConsoleLoggingListener::builder().console_preset().build();
        assert_eq!(console_listener.config.log_level, LogLevel::Normal);
        assert!(console_listener.config.use_colors);
        assert!(console_listener.config.include_timestamps);
        assert!(!console_listener.config.include_event_ids);
        assert!(console_listener.config.include_correlation_ids);
        assert!(!console_listener.config.include_json_debug);
    }

    #[test]
    fn test_console_logging_listener_builder_chaining() {
        let listener = ConsoleLoggingListener::builder()
            .verbose_preset() // Start with verbose preset
            .log_level(LogLevel::Minimal) // Override log level
            .with_colors(false) // Override colors
            .with_prefix("[CUSTOM]".to_string()) // Add custom prefix
            .build();

        // Should have the overridden values
        assert_eq!(listener.config.log_level, LogLevel::Minimal);
        assert!(!listener.config.use_colors);
        assert_eq!(listener.config.log_prefix, Some("[CUSTOM]".to_string()));

        // Should retain other preset values
        assert!(listener.config.include_timestamps);
        assert!(listener.config.include_correlation_ids);
    }

    #[test]
    fn test_console_logging_listener_builder_default() {
        let builder = ConsoleLoggingListenerBuilder::default();
        let listener = builder.build();

        // Should match the default ConsoleLoggingListener configuration
        assert_eq!(listener.config.log_level, LogLevel::Normal);
        assert!(listener.config.use_colors);
        assert!(listener.config.include_timestamps);
        assert!(!listener.config.include_event_ids);
        assert!(listener.config.include_correlation_ids);
        assert!(!listener.config.include_json_debug);
        assert_eq!(listener.config.log_prefix, None);
        assert_eq!(listener.config.max_message_length, None);
    }
}
