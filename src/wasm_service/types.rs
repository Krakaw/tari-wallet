//! WASM-specific type definitions for JavaScript interoperability
//!
//! This module provides type definitions optimized for WebAssembly environments,
//! with proper serialization support and memory-efficient structures.

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};

/// WASM-compatible progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct WasmProgressInfo {
    /// Current block height being scanned
    pub current_height: u64,
    /// Target block height to scan to
    pub target_height: u64,
    /// Number of outputs found so far
    pub outputs_found: u64,
    /// Total value of outputs found (in MicroMinotari)
    pub total_value: u64,
    /// Time elapsed since scan started (in seconds)
    pub elapsed_seconds: u64,
    /// Completion percentage (0.0 to 100.0)
    pub completion_percentage: f64,
    /// Estimated time remaining (in seconds)
    estimated_time_remaining: Option<u64>,
}

#[wasm_bindgen]
impl WasmProgressInfo {
    /// Create a new progress info
    #[wasm_bindgen(constructor)]
    pub fn new(
        current_height: u64,
        target_height: u64,
        outputs_found: u64,
        total_value: u64,
        elapsed_seconds: u64,
    ) -> Self {
        let completion_percentage = if target_height > 0 {
            (current_height as f64 / target_height as f64) * 100.0
        } else {
            0.0
        };

        Self {
            current_height,
            target_height,
            outputs_found,
            total_value,
            elapsed_seconds,
            completion_percentage,
            estimated_time_remaining: None,
        }
    }

    /// Set estimated time remaining
    #[wasm_bindgen(setter)]
    pub fn set_estimated_time_remaining(&mut self, seconds: u64) {
        self.estimated_time_remaining = Some(seconds);
    }

    /// Get estimated time remaining
    #[wasm_bindgen(getter)]
    pub fn estimated_time_remaining(&self) -> Option<u64> {
        self.estimated_time_remaining
    }

    /// Get progress as a JSON string
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
}

/// WASM-compatible transaction output
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct WasmTransactionOutput {
    /// Value (in MicroMinotari, if known)
    value: Option<u64>,
    /// Block height where this output was found
    pub block_height: u64,
    /// Timestamp when the block was mined
    pub timestamp: u64,
}

impl WasmTransactionOutput {
    /// Output hash (hex encoded)
    pub fn output_hash(&self) -> String {
        "placeholder_hash".to_string()
    }

    /// Commitment (hex encoded)
    pub fn commitment(&self) -> String {
        "placeholder_commitment".to_string()
    }
}

#[wasm_bindgen]
impl WasmTransactionOutput {
    /// Create a new transaction output
    #[wasm_bindgen(constructor)]
    pub fn new(
        block_height: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            value: None,
            block_height,
            timestamp,
        }
    }

    /// Set the value
    #[wasm_bindgen(setter)]
    pub fn set_value(&mut self, value: u64) {
        self.value = Some(value);
    }

    /// Get the value
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> Option<u64> {
        self.value
    }

    /// Get the value as a string (for JavaScript compatibility)
    #[wasm_bindgen(js_name = getValueString)]
    pub fn get_value_string(&self) -> String {
        match self.value {
            Some(value) => value.to_string(),
            None => "unknown".to_string(),
        }
    }

    /// Convert to JSON string
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
}

/// WASM-compatible wallet output
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct WasmWalletOutput {
    /// Transaction output information
    output: WasmTransactionOutput,
    /// Whether this output is spendable
    pub spendable: bool,
    /// Whether this output is confirmed
    pub confirmed: bool,
}

impl WasmWalletOutput {
    /// Payment ID (hex encoded, if present)
    pub fn payment_id(&self) -> Option<String> {
        None // Placeholder
    }
}

#[wasm_bindgen]
impl WasmWalletOutput {
    /// Create a new wallet output
    #[wasm_bindgen(constructor)]
    pub fn new(
        block_height: u64,
        timestamp: u64,
        spendable: bool,
        confirmed: bool,
    ) -> Self {
        let output = WasmTransactionOutput::new(block_height, timestamp);
        
        Self {
            output,
            spendable,
            confirmed,
        }
    }

    /// Get the output hash
    #[wasm_bindgen(getter, js_name = outputHash)]
    pub fn output_hash(&self) -> String {
        self.output.output_hash()
    }

    /// Get the commitment
    #[wasm_bindgen(getter)]
    pub fn commitment(&self) -> String {
        self.output.commitment()
    }

    /// Get the value (if known)
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> Option<u64> {
        self.output.value
    }

    /// Set the value
    #[wasm_bindgen(setter)]
    pub fn set_value(&mut self, value: u64) {
        self.output.set_value(value);
    }

    /// Get the block height
    #[wasm_bindgen(getter, js_name = blockHeight)]
    pub fn block_height(&self) -> u64 {
        self.output.block_height
    }

    /// Get the timestamp
    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> u64 {
        self.output.timestamp
    }

    /// Set payment ID (placeholder)
    #[wasm_bindgen(setter, js_name = setPaymentId)]
    pub fn set_payment_id(&mut self, _payment_id: String) {
        // Placeholder implementation
    }

    /// Get payment ID
    #[wasm_bindgen(getter, js_name = paymentId)]
    pub fn get_payment_id(&self) -> Option<String> {
        self.payment_id()
    }

    /// Get the value as a formatted string
    #[wasm_bindgen(js_name = getFormattedValue)]
    pub fn get_formatted_value(&self) -> String {
        match self.output.value {
            Some(value) => format!("{} µT", value),
            None => "unknown".to_string(),
        }
    }

    /// Convert to JSON string
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
}

/// WASM-compatible scan summary
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct WasmScanSummary {
    /// Total number of blocks scanned
    pub blocks_scanned: u64,
    /// Total number of outputs found
    pub outputs_found: u64,
    /// Total value found (in MicroMinotari)
    pub total_value: u64,
    /// Scan duration in seconds
    pub scan_duration: u64,
    /// Average blocks per second
    pub blocks_per_second: f64,
    /// Height range scanned
    pub start_height: u64,
    /// End height scanned
    pub end_height: u64,
}

#[wasm_bindgen]
impl WasmScanSummary {
    /// Create a new scan summary
    #[wasm_bindgen(constructor)]
    pub fn new(
        blocks_scanned: u64,
        outputs_found: u64,
        total_value: u64,
        scan_duration: u64,
        start_height: u64,
        end_height: u64,
    ) -> Self {
        let blocks_per_second = if scan_duration > 0 {
            blocks_scanned as f64 / scan_duration as f64
        } else {
            0.0
        };

        Self {
            blocks_scanned,
            outputs_found,
            total_value,
            scan_duration,
            blocks_per_second,
            start_height,
            end_height,
        }
    }

    /// Get formatted total value
    #[wasm_bindgen(js_name = getFormattedTotalValue)]
    pub fn get_formatted_total_value(&self) -> String {
        format!("{} µT", self.total_value)
    }

    /// Get formatted scan duration
    #[wasm_bindgen(js_name = getFormattedDuration)]
    pub fn get_formatted_duration(&self) -> String {
        let hours = self.scan_duration / 3600;
        let minutes = (self.scan_duration % 3600) / 60;
        let seconds = self.scan_duration % 60;

        if hours > 0 {
            format!("{}h {}m {}s", hours, minutes, seconds)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, seconds)
        } else {
            format!("{}s", seconds)
        }
    }

    /// Convert to JSON string
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
}

/// Collection of wallet outputs for WASM
#[wasm_bindgen]
pub struct WasmWalletOutputCollection {
    outputs: Vec<WasmWalletOutput>,
}

#[wasm_bindgen]
impl WasmWalletOutputCollection {
    /// Create a new empty collection
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            outputs: Vec::new(),
        }
    }

    /// Add an output to the collection
    #[wasm_bindgen(js_name = addOutput)]
    pub fn add_output(&mut self, output: WasmWalletOutput) {
        self.outputs.push(output);
    }

    /// Get the number of outputs
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        self.outputs.len()
    }

    /// Get an output by index
    #[wasm_bindgen(js_name = getOutput)]
    pub fn get_output(&self, index: usize) -> Option<WasmWalletOutput> {
        self.outputs.get(index).cloned()
    }

    /// Get total value of all outputs
    #[wasm_bindgen(js_name = getTotalValue)]
    pub fn get_total_value(&self) -> u64 {
        self.outputs.iter()
            .filter_map(|output| output.value())
            .sum()
    }

    /// Get spendable outputs only
    #[wasm_bindgen(js_name = getSpendableOutputs)]
    pub fn get_spendable_outputs(&self) -> WasmWalletOutputCollection {
        let spendable_outputs: Vec<WasmWalletOutput> = self.outputs.iter()
            .filter(|output| output.spendable)
            .cloned()
            .collect();

        WasmWalletOutputCollection {
            outputs: spendable_outputs,
        }
    }

    /// Get confirmed outputs only
    #[wasm_bindgen(js_name = getConfirmedOutputs)]
    pub fn get_confirmed_outputs(&self) -> WasmWalletOutputCollection {
        let confirmed_outputs: Vec<WasmWalletOutput> = self.outputs.iter()
            .filter(|output| output.confirmed)
            .cloned()
            .collect();

        WasmWalletOutputCollection {
            outputs: confirmed_outputs,
        }
    }

    /// Convert to JSON array string
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.outputs)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Clear all outputs
    #[wasm_bindgen]
    pub fn clear(&mut self) {
        self.outputs.clear();
    }
}

impl Default for WasmWalletOutputCollection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_wasm_progress_info() {
        let progress = WasmProgressInfo::new(500, 1000, 10, 5000, 120);
        assert_eq!(progress.current_height, 500);
        assert_eq!(progress.target_height, 1000);
        assert_eq!(progress.completion_percentage, 50.0);
    }

    #[wasm_bindgen_test]
    fn test_wasm_transaction_output() {
        let output = WasmTransactionOutput::new(
            1000,
            1234567890,
        );
        assert_eq!(output.output_hash(), "placeholder_hash");
        assert_eq!(output.commitment(), "placeholder_commitment");
        assert_eq!(output.block_height, 1000);
    }

    #[wasm_bindgen_test]
    fn test_wasm_wallet_output() {
        let mut output = WasmWalletOutput::new(
            1000,
            1234567890,
            true,
            true,
        );
        
        output.set_value(5000);
        assert_eq!(output.value(), Some(5000));
        assert_eq!(output.get_formatted_value(), "5000 µT");
    }

    #[wasm_bindgen_test]
    fn test_wasm_wallet_output_collection() {
        let mut collection = WasmWalletOutputCollection::new();
        assert_eq!(collection.length(), 0);

        let mut output1 = WasmWalletOutput::new(
            1000,
            1234567890,
            true,
            true,
        );
        output1.set_value(1000);

        let mut output2 = WasmWalletOutput::new(
            1001,
            1234567891,
            false,
            true,
        );
        output2.set_value(2000);

        collection.add_output(output1);
        collection.add_output(output2);

        assert_eq!(collection.length(), 2);
        assert_eq!(collection.get_total_value(), 3000);

        let spendable = collection.get_spendable_outputs();
        assert_eq!(spendable.length(), 1);
    }

    #[wasm_bindgen_test]
    fn test_wasm_scan_summary() {
        let summary = WasmScanSummary::new(100, 5, 10000, 60, 1000, 1100);
        assert_eq!(summary.blocks_scanned, 100);
        assert_eq!(summary.outputs_found, 5);
        assert!((summary.blocks_per_second - 1.666).abs() < 0.01);
        assert_eq!(summary.get_formatted_duration(), "1m 0s");
    }
}
