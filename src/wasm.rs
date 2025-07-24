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
    /// Batch size for scanning
    pub batch_size: Option<usize>,
    /// Progress update frequency
    pub progress_frequency: Option<usize>,
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
    pub fn set_batch_size(&mut self, size: usize) {
        self.batch_size = Some(size);
    }

    /// Set progress frequency
    #[wasm_bindgen(setter)]
    pub fn set_progress_frequency(&mut self, frequency: usize) {
        self.progress_frequency = Some(frequency);
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

/// Validate a seed phrase format and checksum
#[wasm_bindgen]
pub fn wasm_validate_seed_phrase(seed_phrase: &str) -> bool {
    validate_seed_phrase(seed_phrase).is_ok()
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
#[wasm_bindgen]
pub async fn wasm_scan_with_view_key(
    view_key_hex: &str,
    config: &WasmScanConfig,
    progress_callback: Option<js_sys::Function>,
) -> Result<WasmScanResults, JsValue> {
    console_log!("Starting scan with view key");

    // Validate view key format
    if view_key_hex.len() != 64 {
        return Err(JsValue::from_str("View key must be 64 hex characters"));
    }

    // Parse hex view key
    let view_key_bytes = hex::decode(view_key_hex)
        .map_err(|_| JsValue::from_str("Invalid hex format in view key"))?;

    if view_key_bytes.len() != 32 {
        return Err(JsValue::from_str("View key must be 32 bytes"));
    }

    // Create wallet source from view key
    let wallet_source = WalletSource::from_view_key(&view_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to create wallet source: {}", e)))?;

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

    // Convert WASM config to library ScanConfiguration
    let output_format = config.output_format.unwrap_or(WasmOutputFormat::Summary);
    let mut scan_config = ScanConfiguration {
        base_url: config.base_url.clone(),
        start_height: config.from_block.unwrap_or(0),
        end_height: config.to_block,
        specific_blocks: config.blocks.clone(),
        batch_size: config.batch_size.unwrap_or(10),
        progress_frequency: config.progress_frequency.unwrap_or(10),
        quiet: config.quiet.unwrap_or(false),
        output_format: output_format.into(),
        ..Default::default()
    };

    console_log!(
        "Scan configuration: {} to {}, batch size: {}, format: {:?}",
        scan_config.start_height,
        scan_config.end_height.unwrap_or(0),
        scan_config.batch_size,
        output_format
    );

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
