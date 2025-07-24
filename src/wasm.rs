//! WASM bindings for Tari Lightweight Wallet Scanner
//!
//! This module provides JavaScript-compatible functions for blockchain scanning
//! functionality, including seed phrase and view key based scanning.

use crate::{
    errors::LightweightWalletError,
    key_management::seed_phrase::{
        generate_seed_phrase, mnemonic_to_master_key, validate_seed_phrase,
    },
    scanning::{
        output_formatter::{OutputConfig, OutputFormat as FormatterOutputFormat},
        progress_reporter::{ProgressReportConfig, ProgressReportType},
        scan_configuration::{OutputFormat as NativeOutputFormat, ScanBlocks, ScanConfiguration},
        scan_results::{ScanConfigSummary, ScanPhase, ScanResults},
        scanner_engine::{ErrorRecoveryStrategy, ScannerEngine},
        wallet_source::{WalletSource, WalletSourceType},
        HttpBlockchainScanner, ProgressReport,
    },
    wallet::Wallet,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use wasm_bindgen::prelude::*;

// Re-export key native types for JavaScript consumption
pub use crate::{
    scanning::{
        HttpBlockchainScanner as NativeHttpBlockchainScanner,
        ScanConfiguration as NativeScanConfiguration, ScanResults as NativeScanResults,
    },
    wallet::Wallet as NativeWallet,
};

// Enable logging for WASM environments
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
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
    Existing,
    Generated,
}

impl From<WasmWalletSourceType> for WalletSourceType {
    fn from(source_type: WasmWalletSourceType) -> Self {
        match source_type {
            WasmWalletSourceType::SeedPhrase => WalletSourceType::SeedPhrase,
            WasmWalletSourceType::ViewKey => WalletSourceType::ViewKey,
            WasmWalletSourceType::Existing => WalletSourceType::Existing,
            WasmWalletSourceType::Generated => WalletSourceType::Generated,
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
            ScanPhase::Scanning => WasmScanPhase::Scanning,
            ScanPhase::Processing => WasmScanPhase::Processing,
            ScanPhase::Finalizing => WasmScanPhase::Finalizing,
            ScanPhase::Complete => WasmScanPhase::Complete,
            ScanPhase::Error => WasmScanPhase::Error,
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

    /// Set starting block height
    #[wasm_bindgen(setter)]
    pub fn set_from_block(&mut self, height: u64) {
        self.from_block = Some(height);
    }

    /// Set ending block height
    #[wasm_bindgen(setter)]
    pub fn set_to_block(&mut self, height: u64) {
        self.to_block = Some(height);
    }

    /// Set specific blocks to scan
    #[wasm_bindgen]
    pub fn set_blocks(&mut self, blocks: Vec<u64>) {
        self.blocks = Some(blocks);
    }

    /// Set batch size
    #[wasm_bindgen(setter)]
    pub fn set_batch_size(&mut self, size: u64) {
        self.batch_size = Some(size);
    }

    /// Set progress frequency
    #[wasm_bindgen(setter)]
    pub fn set_progress_frequency(&mut self, frequency: u64) {
        self.progress_frequency = Some(frequency);
    }

    /// Set request timeout in seconds
    #[wasm_bindgen(setter)]
    pub fn set_request_timeout_seconds(&mut self, timeout: u64) {
        self.request_timeout_seconds = Some(timeout);
    }

    /// Set whether to scan stealth addresses
    #[wasm_bindgen(setter)]
    pub fn set_scan_stealth_addresses(&mut self, scan: bool) {
        self.scan_stealth_addresses = Some(scan);
    }

    /// Set maximum addresses per account
    #[wasm_bindgen(setter)]
    pub fn set_max_addresses_per_account(&mut self, max: u32) {
        self.max_addresses_per_account = Some(max);
    }

    /// Set whether to scan imported keys
    #[wasm_bindgen(setter)]
    pub fn set_scan_imported_keys(&mut self, scan: bool) {
        self.scan_imported_keys = Some(scan);
    }

    /// Set quiet mode
    #[wasm_bindgen(setter)]
    pub fn set_quiet(&mut self, quiet: bool) {
        self.quiet = Some(quiet);
    }

    /// Set output format
    #[wasm_bindgen(setter)]
    pub fn set_output_format(&mut self, format: WasmOutputFormat) {
        self.output_format = Some(format);
    }

    /// Convert to native ScanConfiguration with validation
    pub fn to_scan_configuration(&self, wallet_source: Option<WalletSource>) -> Result<ScanConfiguration, JsValue> {
        // Validate configuration parameters before conversion
        if let Some(end_height) = self.to_block {
            if end_height <= self.from_block.unwrap_or(0) {
                return Err(JsValue::from_str("End height must be greater than start height"));
            }
        }

        let batch_size = self.batch_size.unwrap_or(10);
        if batch_size == 0 {
            return Err(JsValue::from_str("Batch size must be greater than 0"));
        }
        if batch_size > 1000 {
            console_log!("Warning: Large batch size ({}) may cause performance issues", batch_size);
        }

        let progress_frequency = self.progress_frequency.unwrap_or(10);
        if progress_frequency == 0 {
            return Err(JsValue::from_str("Progress frequency must be greater than 0"));
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
            output_format: self.output_format.unwrap_or(WasmOutputFormat::Summary).into(),
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
}

/// Generate a new seed phrase (24 words)
#[wasm_bindgen]
pub fn wasm_generate_seed_phrase() -> String {
    generate_seed_phrase()
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
        Err(e) => e.as_string().unwrap_or_else(|| "Unknown validation error".to_string()),
    }
}

/// Validate a seed phrase format and checksum
#[wasm_bindgen]
pub fn wasm_validate_seed_phrase(seed_phrase: &str) -> bool {
    validate_seed_phrase(seed_phrase).is_ok()
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
    let wallet = Wallet::new_from_seed_phrase(seed_phrase, passphrase_ref)
        .map_err(|e| JsValue::from_str(&format!("Failed to create wallet: {}", e)))?;

    console_log!("Wallet created successfully from seed phrase");

    // Create wallet source with optional passphrase
    let wallet_source = WalletSource::from_seed_phrase(seed_phrase, passphrase_ref)
        .map_err(|e| JsValue::from_str(&format!("Failed to create wallet source: {}", e)))?;

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
    console_log!("Starting scan with view key (length: {})", view_key_hex.len());

    // Validate input parameters
    if view_key_hex.trim().is_empty() {
        return Err(JsValue::from_str("View key cannot be empty"));
    }

    // Clean and validate view key format
    let view_key_cleaned = view_key_hex.trim().to_lowercase();
    
    if view_key_cleaned.len() != 64 {
        return Err(JsValue::from_str(
            "View key must be exactly 64 hexadecimal characters (32 bytes)"
        ));
    }

    // Validate hex characters only
    if !view_key_cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(JsValue::from_str(
            "View key must contain only hexadecimal characters (0-9, a-f)"
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

    // Create wallet source from view key with enhanced error context
    let wallet_source = WalletSource::from_view_key(&view_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to create wallet source from view key: {}", e)))?;

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
    console_log!("Starting scan with view key bytes (length: {})", view_key_bytes.len());

    // Validate byte array length
    if view_key_bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "View key must be exactly 32 bytes, got {} bytes",
            view_key_bytes.len()
        )));
    }

    console_log!("View key bytes validated, creating wallet source...");

    // Create wallet source from view key bytes
    let wallet_source = WalletSource::from_view_key(view_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to create wallet source from view key bytes: {}", e)))?;

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
    // Create HTTP scanner (WASM-compatible)
    let scanner = HttpBlockchainScanner::new(&config.base_url)
        .map_err(|e| JsValue::from_str(&format!("Failed to create scanner: {}", e)))?;

    // Convert WASM config to library ScanConfiguration using the conversion method
    let scan_config = config.to_scan_configuration(Some(wallet_source.clone()))
        .map_err(|e| JsValue::from_str(&format!("Invalid scan configuration: {}", e.as_string().unwrap_or_default())))?;

    // Create scanner engine
    let mut scanner_engine = ScannerEngine::new();

    // Initialize with wallet source
    scanner_engine
        .initialize_wallet_from_source(wallet_source)
        .map_err(|e| JsValue::from_str(&format!("Failed to initialize wallet: {}", e)))?;

    // Set up progress callback wrapper
    let progress_wrapper = progress_callback.map(|callback| {
        Box::new(move |progress: &ProgressReport| {
            let wasm_progress = WasmProgressReport {
                current_height: progress.current_height,
                total_blocks: progress.total_blocks,
                blocks_completed: progress.blocks_completed,
                percentage: progress.percentage,
                outputs_found: progress.outputs_found,
                current_balance: progress.current_balance,
                elapsed_seconds: progress.elapsed_seconds,
                estimated_remaining_seconds: progress.estimated_remaining_seconds,
            };

            if let Ok(js_progress) = serde_wasm_bindgen::to_value(&wasm_progress) {
                let _ = callback.call1(&JsValue::NULL, &js_progress);
            }
        }) as Box<dyn Fn(&ProgressReport)>
    });

    // Perform the scan
    let start_time = js_sys::Date::now();

    let scan_results = scanner_engine
        .scan_range(&scan_config, progress_wrapper.as_deref())
        .await
        .map_err(|e| JsValue::from_str(&format!("Scan failed: {}", e)))?;

    let end_time = js_sys::Date::now();
    let duration_seconds = (end_time - start_time) / 1000.0;

    // Convert results to WASM format
    let wasm_results = WasmScanResults {
        blocks_scanned: scan_results.blocks_scanned,
        outputs_found: scan_results.outputs_found,
        total_balance: scan_results.total_balance,
        duration_seconds,
        final_height: scan_results.final_height,
        scan_phase: WasmScanPhase::Complete,
        completed: true,
        error: None,
        config_summary: Some(format!(
            "Scanned blocks {} to {} using {:?} (batch size: {})",
            scan_config.start_height,
            scan_results.final_height,
            source_type,
            scan_config.batch_size
        )),
    };

    console_log!("Scan completed successfully");

    Ok(wasm_results)
}

/// Get current blockchain tip height
#[wasm_bindgen]
pub async fn wasm_get_tip_height(base_url: &str) -> Result<u64, JsValue> {
    let scanner = HttpBlockchainScanner::new(base_url)
        .map_err(|e| JsValue::from_str(&format!("Failed to create scanner: {}", e)))?;

    let tip_info = scanner
        .get_tip_info()
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to get tip info: {}", e)))?;

    Ok(tip_info.height)
}

/// Create a wallet from seed phrase (for address generation, etc.)
#[wasm_bindgen]
pub fn wasm_create_wallet_from_seed_phrase(seed_phrase: &str) -> Result<JsValue, JsValue> {
    let wallet = Wallet::new_from_seed_phrase(seed_phrase, None)
        .map_err(|e| JsValue::from_str(&format!("Failed to create wallet: {}", e)))?;

    // Return basic wallet info as JSON
    let wallet_info = serde_json::json!({
        "address": wallet.get_dual_address(0, None).map_err(|e| JsValue::from_str(&e.to_string()))?.to_string(),
        "created": true
    });

    serde_wasm_bindgen::to_value(&wallet_info)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Set panic hook for better error messages in WASM
#[wasm_bindgen(start)]
pub fn main() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    console_log!("Tari Wallet WASM module initialized");
}
