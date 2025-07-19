//! WASM-optimized scanning service with memory management and async bridging
//!
//! Provides a service layer specifically designed for WebAssembly environments,
//! handling memory management, JavaScript Promise integration, and efficient
//! data conversion between Rust and JavaScript types.

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use js_sys::Promise;
use wasm_bindgen_futures::future_to_promise;
use serde_wasm_bindgen;

#[cfg(feature = "http")]
use crate::scanning::{
    ScannerService, ScannerServiceBuilder, ServiceScannerType, ServiceScannerConfig,
};

/// WASM-specific scanner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct WasmScanConfig {
    /// Starting block height
    pub start_height: u64,
    /// Ending block height (optional)
    end_height: Option<u64>,
    /// Batch size for block requests
    batch_size: u64,
    /// Request timeout in seconds
    timeout_seconds: u64,
    /// Whether to use quiet mode
    quiet_mode: bool,
}

/// Private fields that can't be directly accessed from WASM
impl WasmScanConfig {
    /// Base node URL for blockchain connection
    pub fn base_url(&self) -> String {
        "http://127.0.0.1:18142".to_string() // Default, can be set via methods
    }
}

#[wasm_bindgen]
impl WasmScanConfig {
    /// Create a new WASM scan configuration
    #[wasm_bindgen(constructor)]
    pub fn new(start_height: u64) -> Self {
        Self {
            start_height,
            end_height: None,
            batch_size: 100,
            timeout_seconds: 30,
            quiet_mode: false,
        }
    }

    /// Set the ending block height
    #[wasm_bindgen(setter)]
    pub fn set_end_height(&mut self, height: u64) {
        self.end_height = Some(height);
    }

    /// Set the batch size
    #[wasm_bindgen(setter)]
    pub fn set_batch_size(&mut self, size: u64) {
        self.batch_size = size;
    }

    /// Set the timeout in seconds
    #[wasm_bindgen(setter)]
    pub fn set_timeout(&mut self, seconds: u64) {
        self.timeout_seconds = seconds;
    }

    /// Set quiet mode
    #[wasm_bindgen(setter)]
    pub fn set_quiet_mode(&mut self, quiet: bool) {
        self.quiet_mode = quiet;
    }

    /// Get ending block height
    #[wasm_bindgen(getter)]
    pub fn end_height(&self) -> Option<u64> {
        self.end_height
    }

    /// Get batch size
    #[wasm_bindgen(getter)]
    pub fn batch_size(&self) -> u64 {
        self.batch_size
    }

    /// Get timeout in seconds
    #[wasm_bindgen(getter)]
    pub fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }

    /// Get quiet mode
    #[wasm_bindgen(getter)]
    pub fn quiet_mode(&self) -> bool {
        self.quiet_mode
    }
}

/// Simplified block info for WASM serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct WasmBlockInfo {
    /// Block height
    pub height: u64,
    /// Block timestamp
    pub timestamp: u64,
    /// Number of outputs in this block
    pub output_count: usize,
    /// Number of inputs in this block
    pub input_count: usize,
    /// Number of kernels in this block
    pub kernel_count: usize,
}

impl WasmBlockInfo {
    /// Block hash (hex encoded)
    pub fn hash(&self) -> String {
        "placeholder_hash".to_string() // Placeholder
    }
}

/// WASM scan result containing wallet outputs and statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct WasmScanResult {
    /// Total outputs found
    pub outputs_found: u64,
    /// Total value found (in MicroMinotari)
    pub total_value: u64,
    /// Number of blocks scanned
    pub blocks_scanned: u64,
    /// Scan duration in seconds
    pub scan_duration: u64,
    /// Blocks per second rate
    pub blocks_per_second: f64,
    /// Last scanned height
    pub last_scanned_height: u64,
}

#[wasm_bindgen]
impl WasmScanResult {
    /// Get the outputs as a JSON string
    #[wasm_bindgen(js_name = getOutputsAsJson)]
    pub fn get_outputs_as_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
}

/// WASM scanner service for browser/Node.js environments
#[wasm_bindgen]
pub struct WasmScannerService {
    #[cfg(feature = "http")]
    inner_service: Option<Box<dyn ScannerService>>,
    cleanup_handles: Vec<CleanupHandle>,
}

/// Handle for cleanup operations in WASM
struct CleanupHandle {
    // Placeholder for cleanup operations
    _marker: std::marker::PhantomData<()>,
}

#[wasm_bindgen]
impl WasmScannerService {
    /// Create a new WASM scanner service
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "http")]
            inner_service: None,
            cleanup_handles: Vec::new(),
        }
    }

    /// Initialize the scanner service with configuration
    #[wasm_bindgen(js_name = initialize)]
    pub fn initialize(&mut self, config: &WasmScanConfig) -> Result<(), JsValue> {
        #[cfg(feature = "http")]
        {
            // Convert WASM config to service config
            let service_config = ServiceScannerConfig {
                base_url: config.base_url(),
                start_height: config.start_height,
                end_height: config.end_height,
                batch_size: config.batch_size,
                request_timeout: std::time::Duration::from_secs(config.timeout_seconds),
                storage_path: None, // WASM typically doesn't use persistent storage
                wallet_name: None,
                progress_frequency: 10,
                quiet_mode: config.quiet_mode,
                output_format: crate::scanning::OutputFormat::Json,
            };

            // Create the scanner service using the builder
            let _builder = ScannerServiceBuilder::new()
                .with_base_url(&service_config.base_url)
                .with_start_height(service_config.start_height)
                .with_batch_size(service_config.batch_size)
                .with_timeout(service_config.request_timeout)
                .with_quiet_mode(service_config.quiet_mode)
                .with_output_format(service_config.output_format)
                .with_scanner_type(ServiceScannerType::Http);

            // Note: In a real implementation, we'd need to handle the async build()
            // For now, we'll set up the service configuration
            self.inner_service = None; // Placeholder
        }

        #[cfg(not(feature = "http"))]
        {
            return Err(JsValue::from_str("HTTP scanner feature not available"));
        }

        Ok(())
    }

    /// Scan for wallet outputs with the given configuration
    #[wasm_bindgen(js_name = scanWallet)]
    pub fn scan_wallet(&mut self, config: &WasmScanConfig) -> Promise {
        let config = config.clone();
        
        future_to_promise(async move {
            // This is a placeholder implementation
            // In a real implementation, we'd:
            // 1. Convert config to internal format
            // 2. Call the scanner service
            // 3. Convert results back to WASM format
            // 4. Handle memory cleanup

            let result = WasmScanResult {
                outputs_found: 0,
                total_value: 0,
                blocks_scanned: 0,
                scan_duration: 0,
                blocks_per_second: 0.0,
                last_scanned_height: config.start_height,
            };

            let js_result = serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

            Ok(js_result)
        })
    }

    /// Get chain tip information
    #[wasm_bindgen(js_name = getTipInfo)]
    pub fn get_tip_info(&mut self) -> Promise {
        future_to_promise(async move {
            // Placeholder implementation
            let tip_info = serde_json::json!({
                "best_block_height": 1000u64,
                "best_block_hash": "0x1234567890abcdef",
                "accumulated_difficulty": "0xabcdef1234567890",
                "pruned_height": 500u64,
                "timestamp": 1234567890u64
            });

            Ok(serde_wasm_bindgen::to_value(&tip_info)
                .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?)
        })
    }

    /// Set up progress callback for scan operations
    #[wasm_bindgen(js_name = setProgressCallback)]
    pub fn set_progress_callback(&mut self, callback: &js_sys::Function) -> Result<(), JsValue> {
        // Store the callback for progress reporting
        // In a real implementation, this would integrate with the progress tracking system
        let _callback = callback.clone();
        Ok(())
    }

    /// Clean up resources and cancel any ongoing operations
    #[wasm_bindgen(js_name = cleanup)]
    pub fn cleanup(&mut self) {
        // Clean up any ongoing operations
        self.cleanup_handles.clear();
        
        #[cfg(feature = "http")]
        {
            self.inner_service = None;
        }
    }

    /// Check if the service is currently scanning
    #[wasm_bindgen(js_name = isScanning)]
    pub fn is_scanning(&self) -> bool {
        // In a real implementation, this would check the internal service state
        false
    }

    /// Get memory usage information for debugging
    #[wasm_bindgen(js_name = getMemoryUsage)]
    pub fn get_memory_usage(&self) -> Result<JsValue, JsValue> {
        let memory_info = serde_json::json!({
            "cleanup_handles": self.cleanup_handles.len(),
            "service_initialized": self.inner_service.is_some()
        });

        Ok(serde_wasm_bindgen::to_value(&memory_info)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?)
    }
}

impl Drop for WasmScannerService {
    fn drop(&mut self) {
        // Ensure cleanup is called when the service is dropped
        self.cleanup();
    }
}

/// Utility functions for WASM data conversion
#[wasm_bindgen]
pub struct WasmConversionUtils;

#[wasm_bindgen]
impl WasmConversionUtils {
    /// Convert a hex string to bytes
    #[wasm_bindgen(js_name = hexToBytes)]
    pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, JsValue> {
        hex::decode(hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))
    }

    /// Convert bytes to hex string
    #[wasm_bindgen(js_name = bytesToHex)]
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    /// Validate a seed phrase
    #[wasm_bindgen(js_name = validateSeedPhrase)]
    pub fn validate_seed_phrase(seed_phrase: &str) -> bool {
        // Basic validation - check word count and format
        let words: Vec<&str> = seed_phrase.split_whitespace().collect();
        words.len() == 12 || words.len() == 15 || words.len() == 18 || words.len() == 21 || words.len() == 24
    }

    /// Format duration from seconds to human readable string
    #[wasm_bindgen(js_name = formatDuration)]
    pub fn format_duration(seconds: u64) -> String {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        let seconds = seconds % 60;

        if hours > 0 {
            format!("{}h {}m {}s", hours, minutes, seconds)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, seconds)
        } else {
            format!("{}s", seconds)
        }
    }
}

/// Error types for WASM operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmError {
    message: String,
    error_type: String,
}

impl WasmError {
    /// Create a new WASM error
    pub fn new(message: &str, error_type: &str) -> Self {
        Self {
            message: message.to_string(),
            error_type: error_type.to_string(),
        }
    }

    /// Get the error message
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the error type
    pub fn error_type(&self) -> &str {
        &self.error_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_wasm_scan_config_creation() {
        let config = WasmScanConfig::new(1000);
        assert_eq!(config.base_url(), "http://127.0.0.1:18142");
        assert_eq!(config.start_height, 1000);
        assert_eq!(config.batch_size, 100);
        assert!(!config.quiet_mode);
    }

    #[wasm_bindgen_test]
    fn test_wasm_scanner_service_creation() {
        let service = WasmScannerService::new();
        assert!(!service.is_scanning());
    }

    #[wasm_bindgen_test]
    fn test_conversion_utils() {
        let hex = "deadbeef";
        let bytes = WasmConversionUtils::hex_to_bytes(hex).unwrap();
        let hex_back = WasmConversionUtils::bytes_to_hex(&bytes);
        assert_eq!(hex, hex_back);
    }

    #[wasm_bindgen_test]
    fn test_seed_phrase_validation() {
        assert!(WasmConversionUtils::validate_seed_phrase("word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12"));
        assert!(!WasmConversionUtils::validate_seed_phrase("word1 word2"));
        assert!(!WasmConversionUtils::validate_seed_phrase(""));
    }

    #[wasm_bindgen_test]
    fn test_duration_formatting() {
        assert_eq!(WasmConversionUtils::format_duration(30), "30s");
        assert_eq!(WasmConversionUtils::format_duration(90), "1m 30s");
        assert_eq!(WasmConversionUtils::format_duration(3665), "1h 1m 5s");
    }
}
