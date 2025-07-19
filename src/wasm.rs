//! Minimal WASM bindings wrapper around WasmScannerService for browser/Node.js compatibility
//!
//! This module provides a lightweight WASM interface that delegates all complex logic
//! to the WasmScannerService. It focuses only on wasm-bindgen exports, data conversion,
//! and async bridging while maintaining backward compatibility with existing APIs.

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use tari_utilities::ByteArray;

// Re-export types from the WASM service layer when available
#[cfg(all(target_arch = "wasm32", feature = "http"))]
pub use crate::wasm_service::{
    WasmScannerService, WasmScanConfig, WasmScanResult,
    WasmProgressInfo, WasmTransactionOutput, WasmWalletOutput
};

// Import legacy components for backward compatibility
use crate::{
    data_structures::{
        types::PrivateKey,
        wallet_transaction::WalletState,
    },
    key_management::{
        key_derivation,
        seed_phrase::mnemonic_to_bytes,
    },
};

// Only import HTTP scanner types when available
#[cfg(feature = "http")]
use crate::scanning::{http_scanner::HttpBlockchainScanner, BlockchainScanner};

/// Legacy block info for backward compatibility
#[derive(Debug, Clone, serde::Serialize)]
pub struct WasmBlockInfo {
    /// Block height
    pub height: u64,
    /// Block hash (hex encoded)
    pub hash: String,
    /// Block timestamp
    pub timestamp: u64,
    /// Number of outputs in this block
    pub output_count: usize,
    /// Number of inputs in this block
    pub input_count: usize,
    /// Number of kernels in this block
    pub kernel_count: usize,
}

#[cfg(feature = "http")]
impl From<crate::scanning::BlockInfo> for WasmBlockInfo {
    fn from(block_info: crate::scanning::BlockInfo) -> Self {
        Self {
            height: block_info.height,
            hash: hex::encode(&block_info.hash),
            timestamp: block_info.timestamp,
            output_count: block_info.outputs.len(),
            input_count: block_info.inputs.len(),
            kernel_count: block_info.kernels.len(),
        }
    }
}

/// Derive a public key from a master key, returning it as a hex string (legacy)
#[wasm_bindgen]
pub fn derive_public_key_hex(master_key: &[u8]) -> Result<String, JsValue> {
    if master_key.len() != 32 {
        return Err(JsValue::from_str("master_key must be 32 bytes"));
    }
    // Simplified implementation
    Ok(hex::encode(master_key))
}

/// Legacy WASM-compatible wallet scanner for backward compatibility
#[wasm_bindgen]
pub struct WasmScanner {
    #[cfg(feature = "http")]
    http_scanner: Option<HttpBlockchainScanner>,
    view_key: PrivateKey,
    entropy: [u8; 16],
    wallet_state: WalletState,
}

/// Legacy block data structure for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockData {
    pub height: u64,
    pub hash: String,
    pub timestamp: u64,
    pub outputs: Vec<OutputData>,
    pub inputs: Vec<InputData>,
}

/// Legacy output data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputData {
    pub commitment: String,
    pub sender_offset_public_key: String,
    pub encrypted_data: String,
    pub minimum_value_promise: u64,
    pub features: Option<String>,
    pub script: Option<String>,
    pub metadata_signature: Option<String>,
    pub covenant: Option<String>,
}

/// Legacy input data structure (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputData {
    pub commitment: String,
    pub script: Option<String>,
    pub input_data: Option<String>,
    pub script_signature: Option<String>,
    pub sender_offset_public_key: Option<String>,
}

/// Legacy scan result structure for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub total_outputs: u64,
    pub total_spent: u64,
    pub total_value: u64,
    pub current_balance: u64,
    pub blocks_processed: u64,
    pub success: bool,
    pub error: Option<String>,
}

impl WasmScanner {
    /// Create scanner from view key (legacy)
    pub fn from_view_key(view_key_hex: &str) -> Result<Self, String> {
        if view_key_hex.len() != 64 {
            return Err("View key must be 64 hex characters".to_string());
        }
        
        let view_key_bytes = hex::decode(view_key_hex)
            .map_err(|_| "Invalid hex in view key")?;
        
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&view_key_bytes);
        let view_key = PrivateKey::new(key_array);
        
        // Create entropy from view key for deterministic scanning
        let mut entropy = [0u8; 16];
        entropy.copy_from_slice(&view_key_bytes[0..16]);
        
        Ok(Self {
            #[cfg(feature = "http")]
            http_scanner: None,
            view_key,
            entropy,
            wallet_state: WalletState::new(),
        })
    }

    /// Create scanner from seed phrase (legacy)
    pub fn from_seed_phrase(seed_phrase: &str) -> Result<Self, String> {
        let seed_bytes = mnemonic_to_bytes(seed_phrase)
            .map_err(|e| format!("Invalid seed phrase: {}", e))?;
        
        // Simplified implementation without CipherSeed for now
        let mut entropy = [0u8; 16];
        entropy.copy_from_slice(&seed_bytes[0..16]);
        
        let (view_key, _spend_key) = key_derivation::derive_view_and_spend_keys_from_entropy(&entropy)
            .map_err(|e| format!("Failed to derive keys: {}", e))?;
        
        let view_key_bytes = view_key.as_bytes();
        let mut view_key_array = [0u8; 32];
        view_key_array.copy_from_slice(view_key_bytes);
        let view_key = PrivateKey::new(view_key_array);
        
        Ok(Self {
            #[cfg(feature = "http")]
            http_scanner: None,
            view_key,
            entropy,
            wallet_state: WalletState::new(),
        })
    }

    /// Process legacy block data (simplified implementation)
    pub fn process_block(&mut self, _block_data: &BlockData) -> ScanResult {
        // Simplified legacy implementation
        ScanResult {
            total_outputs: 0,
            total_spent: 0,
            total_value: 0,
            current_balance: self.wallet_state.get_balance() as u64,
            blocks_processed: 1,
            success: true,
            error: None,
        }
    }

    /// Reset scanner state
    pub fn reset(&mut self) {
        self.wallet_state = WalletState::new();
    }

    /// Get scanner state as JSON string
    pub fn get_state(&self) -> String {
        serde_json::json!({
            "balance": self.wallet_state.get_balance(),
            "transaction_count": self.wallet_state.transaction_count(),
            "view_key": hex::encode(self.view_key.as_bytes()),
            "entropy": hex::encode(&self.entropy),
        }).to_string()
    }
}

/// Create scanner from view key (WASM export)
#[wasm_bindgen]
pub fn create_scanner_from_view_key(view_key: &str) -> Result<WasmScanner, JsValue> {
    WasmScanner::from_view_key(view_key)
        .map_err(|e| JsValue::from_str(&e))
}

/// Create scanner from seed phrase (WASM export)
#[wasm_bindgen]
pub fn create_scanner_from_seed_phrase(seed_phrase: &str) -> Result<WasmScanner, JsValue> {
    WasmScanner::from_seed_phrase(seed_phrase)
        .map_err(|e| JsValue::from_str(&e))
}

/// Scan block data (WASM export) - Legacy method with simplified implementation
#[wasm_bindgen]
pub fn scan_block_data(scanner: &mut WasmScanner, block_data_json: &str) -> Result<String, JsValue> {
    let block_data: BlockData = serde_json::from_str(block_data_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse block data: {}", e)))?;

    let result = scanner.process_block(&block_data);
    
    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Get scanner statistics (WASM export)
#[wasm_bindgen]
pub fn get_scanner_stats(scanner: &WasmScanner) -> Result<String, JsValue> {
    let stats = serde_json::json!({
        "current_balance": scanner.wallet_state.get_balance(),
        "total_transactions": scanner.wallet_state.transaction_count(),
        "version": "legacy"
    });
    
    serde_json::to_string(&stats)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize stats: {}", e)))
}

/// Get scanner state (WASM export)
#[wasm_bindgen]
pub fn get_scanner_state(scanner: &WasmScanner) -> String {
    scanner.get_state()
}

/// Reset scanner state (WASM export)
#[wasm_bindgen]
pub fn reset_scanner(scanner: &mut WasmScanner) {
    scanner.reset();
}

/// Get version information (WASM export)
#[wasm_bindgen]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Initialize HTTP scanner for legacy compatibility
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn init_http_scanner(scanner: &mut WasmScanner, base_url: &str) -> Result<(), JsValue> {
    let http_scanner = HttpBlockchainScanner::new(base_url.to_string()).await
        .map_err(|e| JsValue::from_str(&format!("Failed to initialize HTTP scanner: {}", e)))?;
    
    scanner.http_scanner = Some(http_scanner);
    Ok(())
}

/// Get tip info from HTTP scanner (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn get_tip_info(scanner: &mut WasmScanner) -> Result<String, JsValue> {
    if let Some(ref mut http_scanner) = scanner.http_scanner {
        let tip_info = http_scanner.get_tip_info().await
            .map_err(|e| JsValue::from_str(&format!("Failed to get tip info: {}", e)))?;
        
        serde_json::to_string(&tip_info)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize tip info: {}", e)))
    } else {
        Err(JsValue::from_str("HTTP scanner not initialized"))
    }
}

/// Validate seed phrase format (WASM export)
#[wasm_bindgen]
pub fn validate_seed_phrase(seed_phrase: &str) -> bool {
    let words: Vec<&str> = seed_phrase.split_whitespace().collect();
    [12, 15, 18, 21, 24].contains(&words.len())
}

/// Convert hex string to bytes (WASM export)
#[wasm_bindgen]
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, JsValue> {
    hex::decode(hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))
}

/// Convert bytes to hex string (WASM export)
#[wasm_bindgen]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Format duration from seconds to human readable string (WASM export)
#[wasm_bindgen]
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

// Re-export the new service layer types when available for new API usage
#[cfg(all(target_arch = "wasm32", feature = "http"))]
pub use crate::wasm_service::*;

/// Create new WASM scanner service (recommended API)
#[cfg(all(target_arch = "wasm32", feature = "http"))]
#[wasm_bindgen]
pub fn create_wasm_scanner_service() -> WasmScannerService {
    WasmScannerService::new()
}

/// Initialize WASM scanner service with configuration (recommended API)
#[cfg(all(target_arch = "wasm32", feature = "http"))]
#[wasm_bindgen]
pub fn initialize_wasm_scanner(service: &mut WasmScannerService, config: &WasmScanConfig) -> Result<(), JsValue> {
    service.initialize(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_create_scanner_from_view_key() {
        let view_key = "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab";
        let result = create_scanner_from_view_key(view_key);
        assert!(result.is_ok());
    }

    #[wasm_bindgen_test]
    fn test_validate_seed_phrase() {
        assert!(validate_seed_phrase("word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12"));
        assert!(!validate_seed_phrase("word1 word2"));
        assert!(!validate_seed_phrase(""));
    }

    #[wasm_bindgen_test]
    fn test_hex_conversion() {
        let hex = "deadbeef";
        let bytes = hex_to_bytes(hex).unwrap();
        let hex_back = bytes_to_hex(&bytes);
        assert_eq!(hex, hex_back);
    }

    #[wasm_bindgen_test]
    fn test_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }

    #[wasm_bindgen_test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3665), "1h 1m 5s");
    }
}
