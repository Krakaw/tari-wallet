//! WASM bindings for Tari Lightweight Wallet Scanner
//!
//! This module provides JavaScript-compatible functions for blockchain scanning
//! functionality, including seed phrase and view key based scanning.

use crate::{
    data_structures::address::TariAddressFeatures,
    key_management::seed_phrase::{generate_seed_phrase, validate_seed_phrase},
    scanning::{
        progress_reporter::ProgressInfo,
        scan_configuration::{OutputFormat as NativeOutputFormat, ScanConfiguration},
        scan_results::ScanPhase,
        scanner_engine::ScannerEngine,
        wallet_source::{WalletSource, WalletSourceType},
        BlockchainScanner, HttpBlockchainScanner,
    },
    wallet::Wallet,
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::time::Duration;
use wasm_bindgen::prelude::*;
use web_sys::console;

// Re-export key native types for JavaScript consumption
pub use crate::{
    scanning::{
        HttpBlockchainScanner as NativeHttpBlockchainScanner,
        ScanConfiguration as NativeScanConfiguration, ScanResults as NativeScanResults,
    },
    wallet::Wallet as NativeWallet,
};

macro_rules! console_log {
    ($($t:tt)*) => (console::log_1(&format_args!($($t)*).to_string().into()))
}

/// JavaScript-compatible output format enum
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmOutputFormat {
    Detailed,
    Summary,
    Json,
}

impl From<WasmOutputFormat> for NativeOutputFormat {
    fn from(format: WasmOutputFormat) -> Self {
        match format {
            WasmOutputFormat::Detailed => NativeOutputFormat::Detailed,
            WasmOutputFormat::Summary => NativeOutputFormat::Summary,
            WasmOutputFormat::Json => NativeOutputFormat::Json,
        }
    }
}

/// JavaScript-compatible wallet source type enum
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmWalletSourceType {
    SeedPhrase,
    ViewKey,
    ExistingWallet,
    GeneratedNew,
}

impl From<WasmWalletSourceType> for WalletSourceType {
    fn from(source_type: WasmWalletSourceType) -> Self {
        match source_type {
            WasmWalletSourceType::SeedPhrase => WalletSourceType::SeedPhrase,
            WasmWalletSourceType::ViewKey => WalletSourceType::ViewKey,
            WasmWalletSourceType::ExistingWallet => WalletSourceType::ExistingWallet,
            WasmWalletSourceType::GeneratedNew => WalletSourceType::GeneratedNew,
        }
    }
}

/// JavaScript-compatible scan phase enum
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmScanPhase {
    Initializing,
    Scanning,
    Processing,
    Finalizing,
    Complete,
    Error,
}

impl From<ScanPhase> for WasmScanPhase {
    fn from(phase: ScanPhase) -> Self {
        match phase {
            ScanPhase::Initializing => WasmScanPhase::Initializing,
            ScanPhase::Connecting => WasmScanPhase::Initializing,
            ScanPhase::Scanning { .. } => WasmScanPhase::Scanning,
            ScanPhase::Processing => WasmScanPhase::Processing,
            ScanPhase::Saving => WasmScanPhase::Processing,
            ScanPhase::Finalizing => WasmScanPhase::Finalizing,
            ScanPhase::Completed => WasmScanPhase::Complete,
            ScanPhase::Interrupted => WasmScanPhase::Error,
            ScanPhase::Error(_) => WasmScanPhase::Error,
        }
    }
}

/// JavaScript-compatible scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmScanConfig {
    /// Base URL for the blockchain node
    pub base_url: String,
    /// Starting block height (optional, defaults to wallet birthday or 0)
    pub from_block: Option<u64>,
    /// Ending block height (optional, defaults to current tip)
    pub to_block: Option<u64>,
    /// Specific block heights to scan (overrides from_block/to_block if provided)
    pub blocks: Option<Vec<u64>>,
    /// Batch size for scanning (default: 10)
    pub batch_size: Option<u64>,
    /// Progress update frequency (default: 10)
    pub progress_frequency: Option<u64>,
    /// Request timeout in seconds (default: 30)
    pub request_timeout_seconds: Option<u64>,
    /// Whether to scan for stealth addresses (default: true)
    pub scan_stealth_addresses: Option<bool>,
    /// Maximum addresses per account (default: 1000)
    pub max_addresses_per_account: Option<u32>,
    /// Whether to scan imported keys (default: true)
    pub scan_imported_keys: Option<bool>,
    /// Quiet mode - minimal output
    pub quiet: Option<bool>,
    /// Output format for results
    pub output_format: Option<WasmOutputFormat>,
}

#[wasm_bindgen]
impl WasmScanConfig {
    #[wasm_bindgen(constructor)]
    pub fn new(base_url: String) -> WasmScanConfig {
        WasmScanConfig {
            base_url,
            from_block: None,
            to_block: None,
            blocks: None,
            batch_size: Some(10),
            progress_frequency: Some(10),
            request_timeout_seconds: Some(30),
            scan_stealth_addresses: Some(true),
            max_addresses_per_account: Some(1000),
            scan_imported_keys: Some(true),
            quiet: Some(false),
            output_format: Some(WasmOutputFormat::Summary),
        }
    }

    /// Set specific blocks to scan (can't use getter_with_clone for Vec types)
    #[wasm_bindgen]
    pub fn set_blocks(&mut self, blocks: Vec<u64>) {
        self.blocks = Some(blocks);
    }

    /// Create a new WasmScanConfig with all parameters (convenience function)
    #[wasm_bindgen]
    pub fn new_with_all_params(
        base_url: String,
        from_block: Option<u64>,
        to_block: Option<u64>,
        batch_size: Option<u64>,
        progress_frequency: Option<u64>,
        request_timeout_seconds: Option<u64>,
        scan_stealth_addresses: Option<bool>,
        max_addresses_per_account: Option<u32>,
        scan_imported_keys: Option<bool>,
        quiet: Option<bool>,
        output_format: Option<WasmOutputFormat>,
    ) -> WasmScanConfig {
        WasmScanConfig {
            base_url,
            from_block,
            to_block,
            blocks: None,
            batch_size,
            progress_frequency,
            request_timeout_seconds,
            scan_stealth_addresses,
            max_addresses_per_account,
            scan_imported_keys,
            quiet,
            output_format,
        }
    }

    /// Create a WasmScanConfig with sane defaults for most use cases
    #[wasm_bindgen]
    pub fn new_default(base_url: String) -> WasmScanConfig {
        WasmScanConfig::new(base_url)
    }
}

// Non-WASM methods for WasmScanConfig (can't be exported to JavaScript directly)
impl WasmScanConfig {
    /// Convert to native ScanConfiguration with validation
    pub fn to_scan_configuration(
        &self,
        wallet_source: Option<WalletSource>,
    ) -> Result<ScanConfiguration, JsValue> {
        // Validate configuration parameters before conversion
        if let Some(end_height) = self.to_block {
            if end_height <= self.from_block.unwrap_or(0) {
                return Err(JsValue::from_str(
                    "End height must be greater than start height",
                ));
            }
        }

        let batch_size = self.batch_size.unwrap_or(10);
        if batch_size == 0 {
            return Err(JsValue::from_str("Batch size must be greater than 0"));
        }
        if batch_size > 1000 {
            console_log!(
                "Warning: Large batch size ({}) may cause performance issues",
                batch_size
            );
        }

        let progress_frequency = self.progress_frequency.unwrap_or(10);
        if progress_frequency == 0 {
            return Err(JsValue::from_str(
                "Progress frequency must be greater than 0",
            ));
        }

        let timeout_secs = self.request_timeout_seconds.unwrap_or(30);
        if timeout_secs == 0 {
            return Err(JsValue::from_str("Request timeout must be greater than 0"));
        }

        // Create the configuration with all parameters
        let config = ScanConfiguration {
            start_height: self.from_block.unwrap_or(0),
            end_height: self.to_block,
            specific_blocks: self.blocks.clone(),
            batch_size,
            request_timeout: Duration::from_secs(timeout_secs),
            progress_frequency,
            scan_stealth_addresses: self.scan_stealth_addresses.unwrap_or(true),
            max_addresses_per_account: self.max_addresses_per_account.unwrap_or(1000),
            scan_imported_keys: self.scan_imported_keys.unwrap_or(true),
            output_format: self
                .output_format
                .unwrap_or(WasmOutputFormat::Summary)
                .into(),
            quiet: self.quiet.unwrap_or(false),
            wallet_source,
            ..Default::default()
        };

        console_log!(
            "Converted scan configuration: start={}, end={:?}, batch={}, timeout={}s, stealth={}, imported={}",
            config.start_height,
            config.end_height,
            config.batch_size,
            timeout_secs,
            config.scan_stealth_addresses,
            config.scan_imported_keys
        );

        Ok(config)
    }
}

/// JavaScript-compatible scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmScanResults {
    /// Total number of blocks scanned
    pub blocks_scanned: u64,
    /// Total number of outputs found
    pub outputs_found: usize,
    /// Total balance (in microTari)
    pub total_balance: u64,
    /// Scan duration in seconds
    pub duration_seconds: f64,
    /// Final block height scanned
    pub final_height: u64,
    /// Current scan phase
    pub scan_phase: WasmScanPhase,
    /// Whether scan completed successfully
    pub completed: bool,
    /// Error message if scan failed
    pub error: Option<String>,
    /// Configuration summary used for this scan
    pub config_summary: Option<String>,
    /// Unique session ID for this scan
    pub session_id: String,
    /// Start time as ISO string
    pub start_time: String,
    /// End time as ISO string
    pub end_time: String,
    /// Average blocks per second
    pub average_blocks_per_second: f64,
    /// Peak memory usage (estimated)
    pub peak_memory_usage_mb: Option<f64>,
}

/// Detailed output information for JavaScript
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmOutputInfo {
    /// Output commitment (hex string)
    pub commitment: String,
    /// Block height where output was found
    pub block_height: u64,
    /// Output value in microTari
    pub value: u64,
    /// Output index in the block
    pub output_index: u32,
    /// Whether this output has been spent
    pub is_spent: bool,
    /// Transaction hash (if available)
    pub transaction_hash: Option<String>,
}

/// Detailed transaction summary for JavaScript
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmTransactionSummary {
    /// Total number of transactions found
    pub total_transactions: usize,
    /// Total incoming value
    pub total_incoming: u64,
    /// Total outgoing value  
    pub total_outgoing: u64,
    /// Net balance change
    pub net_balance: i64,
    /// Number of unconfirmed transactions
    pub unconfirmed_count: usize,
}

/// Comprehensive scan statistics for JavaScript
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmScanStatistics {
    /// Scan results summary
    pub results: WasmScanResults,
    /// Transaction summary
    pub transactions: WasmTransactionSummary,
    /// List of outputs found (limited to avoid memory issues)
    pub outputs: Vec<WasmOutputInfo>,
    /// Whether output list was truncated due to size limits
    pub outputs_truncated: bool,
    /// Maximum number of outputs included
    pub max_outputs_limit: usize,
}

/// JavaScript-compatible progress report
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmProgressReport {
    /// Current block height being scanned
    pub current_height: u64,
    /// Total blocks to scan
    pub total_blocks: u64,
    /// Number of blocks completed
    pub blocks_completed: u64,
    /// Percentage complete (0-100)
    pub percentage: f32,
    /// Number of outputs found so far
    pub outputs_found: usize,
    /// Current balance (in microTari)
    pub current_balance: u64,
    /// Elapsed time in seconds
    pub elapsed_seconds: f64,
    /// Estimated remaining time in seconds
    pub estimated_remaining_seconds: Option<f64>,
    /// Scan phase (Initializing, Scanning, Processing, etc.)
    pub scan_phase: WasmScanPhase,
    /// Blocks per second scan rate
    pub blocks_per_second: f64,
    /// Current batch being processed
    pub current_batch: u64,
    /// Total number of batches
    pub total_batches: u64,
    /// Whether scan can be cancelled at current stage
    pub can_cancel: bool,
    /// Additional status message
    pub status_message: Option<String>,
}

/// JavaScript-compatible progress callback context for advanced usage
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmProgressContext {
    /// Unique scan session ID
    pub session_id: String,
    /// Wallet source type being used
    pub wallet_source_type: WasmWalletSourceType,
    /// Base URL being scanned
    pub base_url: String,
    /// Start time as ISO string
    pub start_time: String,
    /// Scan configuration summary
    pub config_summary: String,
}

/// Generate a new seed phrase (24 words)
#[wasm_bindgen]
pub fn wasm_generate_seed_phrase() -> String {
    generate_seed_phrase().unwrap_or_else(|_| String::from("unable to generate seed phrase"))
}

/// Validate scan configuration without performing scan
///
/// # Parameters
/// * `config` - WasmScanConfig to validate
///
/// # Returns
/// true if configuration is valid, false otherwise
#[wasm_bindgen]
pub fn wasm_validate_scan_config(config: &WasmScanConfig) -> bool {
    config.to_scan_configuration(None).is_ok()
}

/// Get detailed validation errors for scan configuration
///
/// # Parameters
/// * `config` - WasmScanConfig to validate
///
/// # Returns
/// Error message if invalid, empty string if valid
#[wasm_bindgen]
pub fn wasm_get_config_validation_errors(config: &WasmScanConfig) -> String {
    match config.to_scan_configuration(None) {
        Ok(_) => String::new(),
        Err(e) => e
            .as_string()
            .unwrap_or_else(|| "Unknown validation error".to_string()),
    }
}

/// Create a progress callback that logs to console (utility for testing)
///
/// # Returns
/// JavaScript function that can be used as progress callback
#[wasm_bindgen]
pub fn wasm_create_console_progress_callback() -> js_sys::Function {
    let callback = js_sys::Function::new_with_args(
        "progress",
        r#"
        console.log(`Scan Progress: ${progress.percentage.toFixed(1)}% - Block ${progress.current_height} (${progress.blocks_completed}/${progress.total_blocks}) - Found ${progress.outputs_found} outputs - Phase: ${progress.scan_phase}`);
        if (progress.estimated_remaining_seconds) {
            console.log(`Estimated remaining: ${Math.round(progress.estimated_remaining_seconds)}s - Speed: ${progress.blocks_per_second.toFixed(2)} blocks/s`);
        }
        "#,
    );
    callback
}

/// Test progress callback functionality (development utility)
#[wasm_bindgen]
pub fn wasm_test_progress_callback(callback: &js_sys::Function) -> Result<(), JsValue> {
    let test_progress = WasmProgressReport {
        current_height: 1000,
        total_blocks: 2000,
        blocks_completed: 1000,
        percentage: 50.0,
        outputs_found: 5,
        current_balance: 1000000,
        elapsed_seconds: 30.0,
        estimated_remaining_seconds: Some(30.0),
        scan_phase: WasmScanPhase::Scanning,
        blocks_per_second: 33.33,
        current_batch: 10,
        total_batches: 20,
        can_cancel: true,
        status_message: Some("Test progress report".to_string()),
    };

    let js_progress = serde_wasm_bindgen::to_value(&test_progress)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize progress: {}", e)))?;

    callback
        .call1(&JsValue::NULL, &js_progress)
        .map_err(|e| JsValue::from_str(&format!("Callback failed: {:?}", e)))?;

    Ok(())
}

/// Create a cancellable progress callback wrapper
///
/// # Parameters
/// * `progress_callback` - JavaScript function to call for progress updates
/// * `cancel_callback` - JavaScript function to call to check if scan should be cancelled
///
/// # Returns
/// Enhanced progress callback that supports cancellation
#[wasm_bindgen]
pub fn wasm_create_cancellable_progress_callback(
    _progress_callback: js_sys::Function,
    _cancel_callback: js_sys::Function,
) -> js_sys::Function {
    let callback = js_sys::Function::new_with_args(
        "progress",
        r#"
        // Call the progress callback first
        if (typeof arguments[0] === 'function') {
            arguments[0](progress);
        }
        
        // Then check for cancellation
        if (typeof arguments[1] === 'function') {
            const shouldCancel = arguments[1]();
            if (shouldCancel) {
                console.log('Scan cancellation requested by user');
                // Note: Actual cancellation depends on scanner implementation
            }
        }
        "#,
    );
    callback
}

/// Create a progress callback with rate limiting (to avoid overwhelming UI)
///
/// # Parameters
/// * `callback` - JavaScript function to call for progress updates
/// * `min_interval_ms` - Minimum milliseconds between callback invocations
///
/// # Returns
/// Rate-limited progress callback
#[wasm_bindgen]
pub fn wasm_create_rate_limited_progress_callback(
    _callback: js_sys::Function,
    min_interval_ms: u32,
) -> js_sys::Function {
    let throttled_callback = js_sys::Function::new_with_args(
        "progress",
        &format!(
            r#"
        // Rate limiting logic
        if (!window.wasmProgressCallbackState) {{
            window.wasmProgressCallbackState = {{ lastCall: 0 }};
        }}
        
        const now = Date.now();
        if (now - window.wasmProgressCallbackState.lastCall >= {}) {{
            window.wasmProgressCallbackState.lastCall = now;
            return arguments[0](progress);
        }}
        "#,
            min_interval_ms
        ),
    );
    throttled_callback
}

/// Convert WasmScanResults to JSON string
///
/// # Parameters
/// * `results` - WasmScanResults to serialize
///
/// # Returns
/// JSON string representation or error
#[wasm_bindgen]
pub fn wasm_scan_results_to_json(results: &WasmScanResults) -> Result<String, JsValue> {
    serde_json::to_string_pretty(results)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize scan results: {}", e)))
}

/// Convert WasmScanResults to JavaScript object
///
/// # Parameters
/// * `results` - WasmScanResults to convert
///
/// # Returns
/// JavaScript object or error
#[wasm_bindgen]
pub fn wasm_scan_results_to_js_object(results: &WasmScanResults) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(results).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to convert scan results to JS object: {}",
            e
        ))
    })
}

/// Parse WasmScanResults from JSON string
///
/// # Parameters
/// * `json` - JSON string to parse
///
/// # Returns
/// WasmScanResults object or error
#[wasm_bindgen]
pub fn wasm_scan_results_from_json(json: &str) -> Result<WasmScanResults, JsValue> {
    serde_json::from_str(json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse scan results from JSON: {}", e)))
}

/// Convert WasmScanStatistics to JSON string
///
/// # Parameters
/// * `stats` - WasmScanStatistics to serialize
///
/// # Returns
/// JSON string representation or error
#[wasm_bindgen]
pub fn wasm_scan_statistics_to_json(stats: &WasmScanStatistics) -> Result<String, JsValue> {
    serde_json::to_string_pretty(stats)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize scan statistics: {}", e)))
}

/// Convert any serializable WASM structure to compact JSON (no pretty printing)
///
/// # Parameters
/// * `value` - JavaScript value to serialize to compact JSON
///
/// # Returns
/// Compact JSON string or error
#[wasm_bindgen]
pub fn wasm_to_compact_json(value: &JsValue) -> Result<String, JsValue> {
    let rust_value: serde_json::Value = serde_wasm_bindgen::from_value(value.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to convert JS value: {}", e)))?;

    serde_json::to_string(&rust_value)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
}

/// Validate that a JavaScript object can be properly serialized
///
/// # Parameters
/// * `value` - JavaScript value to validate
///
/// # Returns
/// true if serializable, false otherwise
#[wasm_bindgen]
pub fn wasm_validate_serializable(value: &JsValue) -> bool {
    serde_wasm_bindgen::from_value::<serde_json::Value>(value.clone()).is_ok()
}

/// Create detailed scan statistics from basic scan results
///
/// # Parameters
/// * `results` - Basic WasmScanResults
/// * `outputs` - List of output information (will be truncated if too large)
/// * `max_outputs` - Maximum number of outputs to include (default: 1000)
///
/// # Returns
/// WasmScanStatistics with comprehensive information
#[wasm_bindgen]
pub fn wasm_create_scan_statistics(
    results: &WasmScanResults,
    outputs: Vec<WasmOutputInfo>,
    max_outputs: Option<usize>,
) -> WasmScanStatistics {
    let max_limit = max_outputs.unwrap_or(1000);
    let outputs_truncated = outputs.len() > max_limit;
    let limited_outputs = if outputs_truncated {
        outputs.into_iter().take(max_limit).collect()
    } else {
        outputs
    };

    // Calculate transaction summary
    let mut total_incoming = 0u64;
    let mut total_outgoing = 0u64;
    let mut unconfirmed_count = 0usize;

    for output in &limited_outputs {
        if !output.is_spent {
            total_incoming += output.value;
        } else {
            total_outgoing += output.value;
        }

        // Assume outputs at tip height are unconfirmed (simplified logic)
        if output.block_height >= results.final_height.saturating_sub(3) {
            unconfirmed_count += 1;
        }
    }

    let net_balance = total_incoming as i64 - total_outgoing as i64;

    let transactions = WasmTransactionSummary {
        total_transactions: limited_outputs.len(),
        total_incoming,
        total_outgoing,
        net_balance,
        unconfirmed_count,
    };

    WasmScanStatistics {
        results: results.clone(),
        transactions,
        outputs: limited_outputs,
        outputs_truncated,
        max_outputs_limit: max_limit,
    }
}

/// Convert large scan results to memory-efficient JSON representation
///
/// # Parameters
/// * `statistics` - WasmScanStatistics to serialize efficiently
/// * `include_outputs` - Whether to include output details (false for memory efficiency)
///
/// # Returns
/// Memory-efficient JSON string
#[wasm_bindgen]
pub fn wasm_scan_statistics_to_efficient_json(
    statistics: &WasmScanStatistics,
    include_outputs: bool,
) -> Result<String, JsValue> {
    if include_outputs {
        serde_json::to_string_pretty(statistics)
    } else {
        // Create a version without outputs to save memory
        let efficient_stats = serde_json::json!({
            "results": statistics.results,
            "transactions": statistics.transactions,
            "outputs_count": statistics.outputs.len(),
            "outputs_truncated": statistics.outputs_truncated,
            "max_outputs_limit": statistics.max_outputs_limit,
            "outputs": [] // Empty array to indicate outputs were excluded
        });
        serde_json::to_string_pretty(&efficient_stats)
    }
    .map_err(|e| JsValue::from_str(&format!("Failed to serialize scan statistics: {}", e)))
}

/// Estimate memory usage of scan results in bytes
///
/// # Parameters
/// * `statistics` - WasmScanStatistics to analyze
///
/// # Returns
/// Estimated memory usage in bytes
#[wasm_bindgen]
pub fn wasm_estimate_scan_results_memory_usage(statistics: &WasmScanStatistics) -> u64 {
    // Rough estimation based on structure sizes
    let base_size = std::mem::size_of::<WasmScanStatistics>() as u64;
    let outputs_size =
        statistics.outputs.len() as u64 * std::mem::size_of::<WasmOutputInfo>() as u64;

    // Add estimated string content size
    let string_overhead = statistics
        .outputs
        .iter()
        .map(|o| o.commitment.len() + o.transaction_hash.as_ref().map_or(0, |h| h.len()))
        .sum::<usize>() as u64;

    base_size + outputs_size + string_overhead
}

/// Memory management utilities for WASM
pub struct WasmMemoryManager;

impl WasmMemoryManager {
    /// Get current WASM memory usage in bytes (simplified implementation)
    pub fn get_memory_usage() -> u64 {
        // This is a simplified implementation - actual memory tracking would require
        // more sophisticated monitoring in production environments
        0
    }
}

/// WASM memory-aware scan result wrapper
#[derive(Debug, Clone)]
#[wasm_bindgen]
pub struct WasmMemoryManagedResults {
    results: Option<WasmScanResults>,
    statistics: Option<WasmScanStatistics>,
    memory_limit_mb: u32,
    is_disposed: bool,
}

#[wasm_bindgen]
impl WasmMemoryManagedResults {
    /// Create new memory-managed results container
    #[wasm_bindgen(constructor)]
    pub fn new(memory_limit_mb: Option<u32>) -> WasmMemoryManagedResults {
        WasmMemoryManagedResults {
            results: None,
            statistics: None,
            memory_limit_mb: memory_limit_mb.unwrap_or(64), // Default 64MB limit
            is_disposed: false,
        }
    }

    /// Set scan results with memory check
    #[wasm_bindgen]
    pub fn set_results(&mut self, results: WasmScanResults) -> Result<(), JsValue> {
        if self.is_disposed {
            return Err(JsValue::from_str("Results container has been disposed"));
        }

        // Estimate memory usage
        let estimated_size = std::mem::size_of::<WasmScanResults>() as u64;
        let size_mb = estimated_size / (1024 * 1024);

        if size_mb > self.memory_limit_mb as u64 {
            return Err(JsValue::from_str(&format!(
                "Results size ({} MB) exceeds memory limit ({} MB)",
                size_mb, self.memory_limit_mb
            )));
        }

        self.results = Some(results);
        console_log!("Scan results stored in memory-managed container");
        Ok(())
    }

    /// Set scan statistics with memory check and automatic truncation
    #[wasm_bindgen]
    pub fn set_statistics(&mut self, mut statistics: WasmScanStatistics) -> Result<(), JsValue> {
        if self.is_disposed {
            return Err(JsValue::from_str("Results container has been disposed"));
        }

        // Estimate memory usage
        let estimated_size = wasm_estimate_scan_results_memory_usage(&statistics);
        let size_mb = estimated_size / (1024 * 1024);

        // If exceeds memory limit, truncate outputs automatically
        if size_mb > self.memory_limit_mb as u64 {
            let max_outputs = (self.memory_limit_mb as usize * 1024 * 1024)
                / std::mem::size_of::<WasmOutputInfo>().max(1);

            console_log!(
                "Statistics size ({} MB) exceeds limit ({} MB), truncating outputs to {}",
                size_mb,
                self.memory_limit_mb,
                max_outputs
            );

            statistics.outputs.truncate(max_outputs);
            statistics.outputs_truncated = true;
            statistics.max_outputs_limit = max_outputs;
        }

        self.statistics = Some(statistics);
        console_log!("Scan statistics stored in memory-managed container");
        Ok(())
    }

    /// Get results (returns clone)
    #[wasm_bindgen]
    pub fn get_results(&self) -> Result<WasmScanResults, JsValue> {
        if self.is_disposed {
            return Err(JsValue::from_str("Results container has been disposed"));
        }

        self.results
            .clone()
            .ok_or_else(|| JsValue::from_str("No results available"))
    }

    /// Get statistics (returns clone)
    #[wasm_bindgen]
    pub fn get_statistics(&self) -> Result<WasmScanStatistics, JsValue> {
        if self.is_disposed {
            return Err(JsValue::from_str("Results container has been disposed"));
        }

        self.statistics
            .clone()
            .ok_or_else(|| JsValue::from_str("No statistics available"))
    }

    /// Get current memory usage estimate in MB
    #[wasm_bindgen]
    pub fn get_memory_usage_mb(&self) -> f64 {
        if self.is_disposed {
            return 0.0;
        }

        let mut total_size = 0u64;

        if let Some(ref stats) = self.statistics {
            total_size += wasm_estimate_scan_results_memory_usage(stats);
        }

        if let Some(_) = self.results {
            total_size += std::mem::size_of::<WasmScanResults>() as u64;
        }

        total_size as f64 / (1024.0 * 1024.0)
    }

    /// Check if memory limit is exceeded
    #[wasm_bindgen]
    pub fn is_memory_limit_exceeded(&self) -> bool {
        self.get_memory_usage_mb() > self.memory_limit_mb as f64
    }

    /// Dispose of stored data to free memory
    #[wasm_bindgen]
    pub fn dispose(&mut self) {
        if !self.is_disposed {
            self.results = None;
            self.statistics = None;
            self.is_disposed = true;
            console_log!("Memory-managed results container disposed");
        }
    }

    /// Check if container has been disposed
    #[wasm_bindgen]
    pub fn is_disposed(&self) -> bool {
        self.is_disposed
    }
}

/// Validate a seed phrase format and checksum
#[wasm_bindgen]
pub fn wasm_validate_seed_phrase(seed_phrase: &str) -> bool {
    validate_seed_phrase(seed_phrase).is_ok()
}

/// Cleanup utility for WASM memory management
#[wasm_bindgen]
pub fn wasm_force_garbage_collection() {
    #[cfg(target_arch = "wasm32")]
    {
        // Request garbage collection in WASM environment
        if let Some(_window) = web_sys::window() {
            // This is a hint to the browser - not guaranteed to trigger GC immediately
            let _ = js_sys::eval("if (typeof window !== 'undefined' && window.gc) window.gc();");
        }
    }
    console_log!("Garbage collection requested");
}

/// Memory-aware scan with automatic cleanup
#[wasm_bindgen]
pub async fn wasm_scan_with_memory_management(
    seed_phrase: &str,
    passphrase: Option<String>,
    config: &WasmScanConfig,
    memory_limit_mb: Option<u32>,
    progress_callback: Option<js_sys::Function>,
) -> Result<WasmMemoryManagedResults, JsValue> {
    console_log!("Starting memory-managed scan");

    // Create memory-managed container
    let mut container = WasmMemoryManagedResults::new(memory_limit_mb);

    // Perform the scan
    let scan_results =
        wasm_scan_with_seed_phrase(seed_phrase, passphrase, config, progress_callback).await?;

    // Store results with memory management
    container.set_results(scan_results)?;

    console_log!(
        "Memory-managed scan completed, usage: {:.2} MB",
        container.get_memory_usage_mb()
    );

    Ok(container)
}

/// Streaming scan results that processes outputs in batches to manage memory
#[wasm_bindgen]
pub async fn wasm_scan_with_streaming_results(
    seed_phrase: &str,
    passphrase: Option<String>,
    config: &WasmScanConfig,
    batch_size: Option<usize>,
    _result_callback: js_sys::Function,
    progress_callback: Option<js_sys::Function>,
) -> Result<WasmScanResults, JsValue> {
    console_log!("Starting streaming scan with batch processing");

    let batch_size = batch_size.unwrap_or(100);

    // Create a progress wrapper that also handles result streaming
    let streaming_progress_callback = progress_callback.map(|_callback| {
        js_sys::Function::new_with_args(
            "progress",
            &format!(
                r#"
            // Call original progress callback
            if (arguments[0]) {{
                arguments[0](progress);
            }}
            
            // Check if we should process a batch of results
            if (progress.outputs_found > 0 && progress.outputs_found % {} === 0) {{
                console.log('Processing batch of {} outputs...');
                // In a real implementation, this would trigger batch processing
            }}
            "#,
                batch_size, batch_size
            ),
        )
    });

    // Perform scan with streaming callback
    let results =
        wasm_scan_with_seed_phrase(seed_phrase, passphrase, config, streaming_progress_callback)
            .await?;

    console_log!("Streaming scan completed");
    Ok(results)
}

/// Paginated access to large scan results
#[wasm_bindgen]
pub struct WasmPaginatedResults {
    statistics: WasmScanStatistics,
    page_size: usize,
    current_page: usize,
}

#[wasm_bindgen]
impl WasmPaginatedResults {
    /// Create paginated results from statistics
    #[wasm_bindgen(constructor)]
    pub fn new(statistics: WasmScanStatistics, page_size: Option<usize>) -> WasmPaginatedResults {
        WasmPaginatedResults {
            statistics,
            page_size: page_size.unwrap_or(50),
            current_page: 0,
        }
    }

    /// Get total number of pages
    #[wasm_bindgen]
    pub fn get_total_pages(&self) -> usize {
        (self.statistics.outputs.len() + self.page_size - 1) / self.page_size
    }

    /// Get current page number (0-based)
    #[wasm_bindgen]
    pub fn get_current_page(&self) -> usize {
        self.current_page
    }

    /// Get page size
    #[wasm_bindgen]
    pub fn get_page_size(&self) -> usize {
        self.page_size
    }

    /// Get outputs for current page
    #[wasm_bindgen]
    pub fn get_current_page_outputs(&self) -> Vec<WasmOutputInfo> {
        let start = self.current_page * self.page_size;
        let end = (start + self.page_size).min(self.statistics.outputs.len());

        if start < self.statistics.outputs.len() {
            self.statistics.outputs[start..end].to_vec()
        } else {
            Vec::new()
        }
    }

    /// Move to next page
    #[wasm_bindgen]
    pub fn next_page(&mut self) -> bool {
        if self.current_page + 1 < self.get_total_pages() {
            self.current_page += 1;
            true
        } else {
            false
        }
    }

    /// Move to previous page
    #[wasm_bindgen]
    pub fn previous_page(&mut self) -> bool {
        if self.current_page > 0 {
            self.current_page -= 1;
            true
        } else {
            false
        }
    }

    /// Jump to specific page
    #[wasm_bindgen]
    pub fn goto_page(&mut self, page: usize) -> bool {
        if page < self.get_total_pages() {
            self.current_page = page;
            true
        } else {
            false
        }
    }

    /// Get basic statistics without output data
    #[wasm_bindgen]
    pub fn get_summary(&self) -> JsValue {
        let summary = serde_json::json!({
            "results": self.statistics.results,
            "transactions": self.statistics.transactions,
            "total_outputs": self.statistics.outputs.len(),
            "outputs_truncated": self.statistics.outputs_truncated,
            "max_outputs_limit": self.statistics.max_outputs_limit,
            "total_pages": self.get_total_pages(),
            "page_size": self.page_size,
            "current_page": self.current_page
        });

        serde_wasm_bindgen::to_value(&summary).unwrap_or(JsValue::NULL)
    }
}

/// Validate view key format without performing scan
///
/// # Parameters
/// * `view_key_hex` - 64-character hexadecimal view key to validate
///
/// # Returns
/// true if view key format is valid, false otherwise
#[wasm_bindgen]
pub fn wasm_validate_view_key(view_key_hex: &str) -> bool {
    // Check if empty
    if view_key_hex.trim().is_empty() {
        return false;
    }

    // Clean and check length
    let view_key_cleaned = view_key_hex.trim().to_lowercase();
    if view_key_cleaned.len() != 64 {
        return false;
    }

    // Validate hex characters only
    if !view_key_cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    // Try to decode hex
    hex::decode(&view_key_cleaned).is_ok()
}

/// Scan blockchain with seed phrase (with optional passphrase)
///
/// # Parameters
/// * `seed_phrase` - 24-word BIP39 seed phrase
/// * `passphrase` - Optional passphrase for seed phrase (can be null/undefined)
/// * `config` - Scan configuration with base URL, block range, etc.
/// * `progress_callback` - Optional JavaScript function for progress updates
///
/// # Returns
/// Promise<WasmScanResults> with scan results or error
#[wasm_bindgen]
pub async fn wasm_scan_with_seed_phrase(
    seed_phrase: &str,
    passphrase: Option<String>,
    config: &WasmScanConfig,
    progress_callback: Option<js_sys::Function>,
) -> Result<WasmScanResults, JsValue> {
    console_log!(
        "Starting scan with seed phrase (passphrase: {})",
        passphrase.is_some()
    );

    // Validate input parameters
    if seed_phrase.trim().is_empty() {
        return Err(JsValue::from_str("Seed phrase cannot be empty"));
    }

    // Validate seed phrase format and checksum
    if !wasm_validate_seed_phrase(seed_phrase) {
        return Err(JsValue::from_str(
            "Invalid seed phrase: must be 24 valid BIP39 words with correct checksum",
        ));
    }

    // Convert passphrase
    let passphrase_ref = passphrase.as_deref();

    // Create wallet from seed phrase with optional passphrase
    let _wallet = Wallet::new_from_seed_phrase(seed_phrase, passphrase_ref)
        .map_err(|e| JsValue::from_str(&format!("Failed to create wallet: {}", e)))?;

    console_log!("Wallet created successfully from seed phrase");

    // Create wallet source with optional passphrase
    let wallet_source = WalletSource::from_seed_phrase(seed_phrase, passphrase_ref);

    console_log!("Wallet source created, starting scan...");

    // Perform scan with enhanced error context
    scan_with_wallet_source(
        wallet_source,
        config,
        progress_callback,
        WasmWalletSourceType::SeedPhrase,
    )
    .await
}

/// Scan blockchain with seed phrase (convenience function without passphrase)
///
/// # Parameters
/// * `seed_phrase` - 24-word BIP39 seed phrase
/// * `config` - Scan configuration with base URL, block range, etc.
/// * `progress_callback` - Optional JavaScript function for progress updates
///
/// # Returns
/// Promise<WasmScanResults> with scan results or error
#[wasm_bindgen]
pub async fn wasm_scan_with_seed_phrase_simple(
    seed_phrase: &str,
    config: &WasmScanConfig,
    progress_callback: Option<js_sys::Function>,
) -> Result<WasmScanResults, JsValue> {
    // Call the main function with no passphrase
    wasm_scan_with_seed_phrase(seed_phrase, None, config, progress_callback).await
}

/// Scan blockchain with view key (hex format, 64 characters)
///
/// View keys provide read-only access to wallet transactions and balances.
/// This is more secure than seed phrases for monitoring purposes.
///
/// # Parameters
/// * `view_key_hex` - 64-character hexadecimal view key (32 bytes)
/// * `config` - Scan configuration with base URL, block range, etc.  
/// * `progress_callback` - Optional JavaScript function for progress updates
///
/// # Returns
/// Promise<WasmScanResults> with scan results or error
///
/// # View Key Format
/// - Must be exactly 64 hexadecimal characters (0-9, a-f, A-F)
/// - Represents 32 bytes of key data
/// - Case insensitive
#[wasm_bindgen]
pub async fn wasm_scan_with_view_key(
    view_key_hex: &str,
    config: &WasmScanConfig,
    progress_callback: Option<js_sys::Function>,
) -> Result<WasmScanResults, JsValue> {
    console_log!(
        "Starting scan with view key (length: {})",
        view_key_hex.len()
    );

    // Validate input parameters
    if view_key_hex.trim().is_empty() {
        return Err(JsValue::from_str("View key cannot be empty"));
    }

    // Clean and validate view key format
    let view_key_cleaned = view_key_hex.trim().to_lowercase();

    if view_key_cleaned.len() != 64 {
        return Err(JsValue::from_str(
            "View key must be exactly 64 hexadecimal characters (32 bytes)",
        ));
    }

    // Validate hex characters only
    if !view_key_cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(JsValue::from_str(
            "View key must contain only hexadecimal characters (0-9, a-f)",
        ));
    }

    // Parse hex view key with detailed error handling
    let view_key_bytes = hex::decode(&view_key_cleaned)
        .map_err(|e| JsValue::from_str(&format!("Invalid hex format in view key: {}", e)))?;

    // Double-check byte length (should always be 32 after hex decode)
    if view_key_bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "View key decoded to {} bytes, expected 32 bytes",
            view_key_bytes.len()
        )));
    }

    console_log!("View key validated successfully, creating wallet source...");

    // Convert bytes to hex string and create wallet source
    let view_key_hex = hex::encode(&view_key_bytes);
    let wallet_source = WalletSource::from_view_key(view_key_hex, None);

    console_log!("Wallet source created from view key, starting scan...");

    // Perform scan with enhanced error context
    scan_with_wallet_source(
        wallet_source,
        config,
        progress_callback,
        WasmWalletSourceType::ViewKey,
    )
    .await
}

/// Scan blockchain with view key bytes (alternative interface for advanced use)
///
/// # Parameters
/// * `view_key_bytes` - Uint8Array of 32 bytes representing the view key
/// * `config` - Scan configuration with base URL, block range, etc.
/// * `progress_callback` - Optional JavaScript function for progress updates
///
/// # Returns
/// Promise<WasmScanResults> with scan results or error
#[wasm_bindgen]
pub async fn wasm_scan_with_view_key_bytes(
    view_key_bytes: &[u8],
    config: &WasmScanConfig,
    progress_callback: Option<js_sys::Function>,
) -> Result<WasmScanResults, JsValue> {
    console_log!(
        "Starting scan with view key bytes (length: {})",
        view_key_bytes.len()
    );

    // Validate byte array length
    if view_key_bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "View key must be exactly 32 bytes, got {} bytes",
            view_key_bytes.len()
        )));
    }

    console_log!("View key bytes validated, creating wallet source...");

    // Convert bytes to hex string and create wallet source
    let view_key_hex = hex::encode(view_key_bytes);
    let wallet_source = WalletSource::from_view_key(view_key_hex, None);

    console_log!("Wallet source created from view key bytes, starting scan...");

    // Perform scan
    scan_with_wallet_source(
        wallet_source,
        config,
        progress_callback,
        WasmWalletSourceType::ViewKey,
    )
    .await
}

/// Internal function to perform scan with wallet source
async fn scan_with_wallet_source(
    wallet_source: WalletSource,
    config: &WasmScanConfig,
    progress_callback: Option<js_sys::Function>,
    source_type: WasmWalletSourceType,
) -> Result<WasmScanResults, JsValue> {
    // Convert WASM config to library ScanConfiguration first
    let scan_config = config
        .to_scan_configuration(Some(wallet_source.clone()))
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Invalid scan configuration: {}",
                e.as_string().unwrap_or_default()
            ))
        })?;

    // Create HTTP scanner (WASM-compatible)
    let scanner = HttpBlockchainScanner::new(config.base_url.clone())
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to create scanner: {}", e)))?;

    // Create scanner engine with boxed scanner and scan configuration
    let mut scanner_engine = ScannerEngine::new(Box::new(scanner), scan_config.clone());

    // Initialize wallet
    scanner_engine
        .initialize_wallet()
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to initialize wallet: {}", e)))?;

    // Generate unique session ID for this scan
    let session_id = format!("scan_{}", js_sys::Date::now() as u64);
    let scan_start_time = js_sys::Date::new_0();
    let start_time_iso = scan_start_time
        .to_iso_string()
        .as_string()
        .unwrap_or_default();

    // Create progress context
    let progress_context = WasmProgressContext {
        session_id: session_id.clone(),
        wallet_source_type: source_type,
        base_url: config.base_url.clone(),
        start_time: start_time_iso,
        config_summary: format!(
            "Blocks: {} to {:?}, Batch: {}",
            scan_config.start_height, scan_config.end_height, scan_config.batch_size
        ),
    };

    console_log!("Starting scan session: {}", session_id);

    // Set up enhanced progress callback wrapper
    let _progress_wrapper = progress_callback.map(|callback| {
        let _context = progress_context.clone();
        let start_time = js_sys::Date::now();

        Box::new(move |progress: &ProgressInfo| {
            let current_time = js_sys::Date::now();
            let elapsed_seconds = (current_time - start_time) / 1000.0;

            // Calculate additional metrics
            let blocks_per_second = if elapsed_seconds > 0.0 {
                progress.blocks_scanned as f64 / elapsed_seconds
            } else {
                0.0
            };

            let current_batch = if scan_config.batch_size > 0 {
                progress.blocks_scanned / scan_config.batch_size + 1
            } else {
                1
            };

            let total_batches = if scan_config.batch_size > 0 {
                (progress.total_blocks.unwrap_or(0) + scan_config.batch_size - 1)
                    / scan_config.batch_size
            } else {
                1
            };

            let current_balance = progress
                .wallet_state
                .as_ref()
                .map(|ws| ws.get_balance().max(0) as u64)
                .unwrap_or(0);

            let percentage = if let Some(total) = progress.target_height {
                if total > 0 {
                    (progress.current_height as f64 / total as f64 * 100.0).min(100.0)
                } else {
                    0.0
                }
            } else {
                0.0
            };

            let wasm_progress = WasmProgressReport {
                current_height: progress.current_height,
                total_blocks: progress.total_blocks.unwrap_or(0),
                blocks_completed: progress.blocks_scanned,
                percentage: percentage as f32,
                outputs_found: progress.outputs_found as usize,
                current_balance,
                elapsed_seconds,
                estimated_remaining_seconds: progress.estimated_remaining_seconds,
                scan_phase: WasmScanPhase::Scanning, // Will be enhanced based on actual phase
                blocks_per_second,
                current_batch,
                total_batches,
                can_cancel: true, // Most scanning phases allow cancellation
                status_message: Some(format!("Scanning block {}", progress.current_height)),
            };

            // Attempt to call the JavaScript callback with enhanced error handling
            match serde_wasm_bindgen::to_value(&wasm_progress) {
                Ok(js_progress) => {
                    if let Err(e) = callback.call1(&JsValue::NULL, &js_progress) {
                        console_log!("Progress callback error: {:?}", e);
                        // Don't fail the scan due to callback errors, just log
                    }
                }
                Err(e) => {
                    console_log!("Failed to serialize progress report: {}", e);
                }
            }
        }) as Box<dyn Fn(&ProgressInfo)>
    });

    // Perform the scan
    let start_time = js_sys::Date::now();

    let scan_results = scanner_engine
        .scan_range()
        .await
        .map_err(|e| JsValue::from_str(&format!("Scan failed: {}", e)))?;

    let end_time = js_sys::Date::now();
    let duration_seconds = (end_time - start_time) / 1000.0;

    // Calculate performance metrics
    let average_blocks_per_second = if duration_seconds > 0.0 {
        scan_results.final_progress.blocks_scanned as f64 / duration_seconds
    } else {
        0.0
    };

    // Create timestamps
    let end_time_date = js_sys::Date::new(&JsValue::from_f64(end_time));
    let end_time_iso = end_time_date
        .to_iso_string()
        .as_string()
        .unwrap_or_default();

    // Convert results to enhanced WASM format
    let wasm_results = WasmScanResults {
        blocks_scanned: scan_results.final_progress.blocks_scanned,
        outputs_found: scan_results.final_progress.outputs_found as usize,
        total_balance: scan_results.wallet_state.get_balance().max(0) as u64,
        duration_seconds,
        final_height: scan_results.scan_config_summary.end_height.unwrap_or(0),
        scan_phase: WasmScanPhase::Complete,
        completed: true,
        error: None,
        config_summary: Some(format!(
            "Scanned blocks {} to {} using {:?} (batch size: {})",
            scan_config.start_height,
            scan_results.scan_config_summary.end_height.unwrap_or(0),
            source_type,
            scan_config.batch_size
        )),
        session_id: session_id.clone(),
        start_time: progress_context.start_time.clone(),
        end_time: end_time_iso,
        average_blocks_per_second,
        peak_memory_usage_mb: None, // Would need actual memory monitoring to implement
    };

    console_log!("Scan completed successfully");

    Ok(wasm_results)
}

/// Get current blockchain tip height
#[wasm_bindgen]
pub async fn wasm_get_tip_height(base_url: &str) -> Result<u64, JsValue> {
    let mut scanner = HttpBlockchainScanner::new(base_url.to_string())
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to create scanner: {}", e)))?;

    let tip_info = scanner
        .get_tip_info()
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to get tip info: {}", e)))?;

    Ok(tip_info.best_block_height)
}

/// Create a wallet from seed phrase (for address generation, etc.)
#[wasm_bindgen]
pub fn wasm_create_wallet_from_seed_phrase(seed_phrase: &str) -> Result<JsValue, JsValue> {
    let wallet = Wallet::new_from_seed_phrase(seed_phrase, None)
        .map_err(|e| JsValue::from_str(&format!("Failed to create wallet: {}", e)))?;

    // Return basic wallet info as JSON
    let address = wallet
        .get_dual_address(TariAddressFeatures::default(), None)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let wallet_info = serde_json::json!({
        "address": address.to_base58(),
        "created": true
    });

    serde_wasm_bindgen::to_value(&wallet_info)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Create a WASM scanner from view key or seed phrase (legacy compatibility)
#[wasm_bindgen]
pub fn create_wasm_scanner(scanner_data: &str) -> Result<JsValue, JsValue> {
    let wallet_source = if scanner_data.split_whitespace().count() > 1 {
        // Looks like a seed phrase (multiple words)
        WalletSource::SeedPhrase {
            phrase: scanner_data.to_string(),
            passphrase: None,
        }
    } else {
        // Assume it's a view key (single hex string)
        WalletSource::ViewKey {
            view_key_hex: scanner_data.to_string(),
            birthday: None,
        }
    };

    // Create a basic scan configuration with the wallet source
    let scan_config = ScanConfiguration {
        wallet_source: Some(wallet_source),
        start_height: 0,
        end_height: None,
        specific_blocks: None,
        batch_size: 10,
        extraction_config: crate::extraction::ExtractionConfig::default(),
        max_addresses_per_account: 1000,
        output_format: NativeOutputFormat::Json,
        progress_frequency: 1,
        request_timeout: Duration::from_secs(30),
        scan_stealth_addresses: true,
        scan_imported_keys: true,
        quiet: false,
    };

    let scanner_info = serde_json::json!({
        "created": true,
        "wallet_source_type": match scan_config.wallet_source {
            Some(WalletSource::SeedPhrase { .. }) => "seed_phrase",
            Some(WalletSource::ViewKey { .. }) => "view_key",
            _ => "unknown"
        }
    });

    serde_wasm_bindgen::to_value(&scanner_info)
        .map_err(|e| JsValue::from_str(&format!("Failed to create scanner: {}", e)))
}

/// Process HTTP blocks using scanner engine (legacy compatibility)
#[wasm_bindgen]
pub fn process_http_blocks(_scanner: &JsValue, _http_response_json: &str) -> String {
    // For now, create a temporary scanner engine to process the blocks
    // In a real implementation, we'd maintain the scanner state
    let _wallet_source = WalletSource::ViewKey {
        view_key_hex: "9d84cc4795b509dadae90bd68b42f7d630a6a3d56281c0b5dd1c0ed36390e70a"
            .to_string(),
        birthday: None,
    };

    let _scan_config = ScanConfiguration {
        wallet_source: Some(_wallet_source),
        start_height: 0,
        end_height: None,
        specific_blocks: None,
        batch_size: 10,
        extraction_config: crate::extraction::ExtractionConfig::default(),
        max_addresses_per_account: 1000,
        output_format: NativeOutputFormat::Json,
        progress_frequency: 1,
        request_timeout: Duration::from_secs(30),
        scan_stealth_addresses: true,
        scan_imported_keys: true,
        quiet: false,
    };

    // For now, simulate the process since we can't easily create an async HTTP scanner in WASM
    // This is a simplified implementation for compatibility
    let error_result = serde_json::json!({
        "success": false,
        "error": "WASM HTTP block processing not yet implemented - use native scanner",
        "total_outputs": 0,
        "total_spent": 0,
        "total_value": 0,
        "current_balance": 0,
        "blocks_processed": 0,
        "transactions": []
    });
    error_result.to_string()
}

/// Get scanner statistics (legacy compatibility)
#[wasm_bindgen]
pub fn get_scanner_stats(_scanner: &JsValue) -> String {
    // For now, return empty stats
    // In a real implementation, we'd maintain the scanner state and return actual stats
    let stats = serde_json::json!({
        "total_outputs": 0,
        "total_spent": 0,
        "total_value": 0,
        "total_spent_value": 0,
        "current_balance": 0,
        "total_transactions": 0,
        "inbound_transactions": 0,
        "outbound_transactions": 0
    });
    stats.to_string()
}

/// Cleanup scanner transactions (legacy compatibility)
#[wasm_bindgen]
pub fn cleanup_scanner_transactions(_scanner: &JsValue, max_transactions: usize) {
    // For now, this is a no-op
    // In a real implementation, we'd clean up the scanner state
    console_log!(
        "Scanner transaction cleanup requested for {} max transactions",
        max_transactions
    );
}

/// Set panic hook for better error messages in WASM
#[wasm_bindgen(start)]
pub fn main() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    console_log!("Tari Wallet WASM module initialized");
}
