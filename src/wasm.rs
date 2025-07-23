use serde::{Deserialize, Serialize};
use tari_utilities::ByteArray;
use wasm_bindgen::prelude::*;

use crate::{
    data_structures::{
        block::Block,
        encrypted_data::EncryptedData,
        payment_id::PaymentId,
        transaction::TransactionDirection,
        transaction_input::LightweightExecutionStack,
        transaction_input::TransactionInput,
        transaction_output::LightweightTransactionOutput,
        types::{CompressedCommitment, CompressedPublicKey, MicroMinotari, PrivateKey},
        wallet_output::{
            LightweightCovenant, LightweightOutputFeatures, LightweightOutputType,
            LightweightScript, LightweightSignature,
        },
        wallet_transaction::WalletState,
    },
    key_management::{
        key_derivation,
        seed_phrase::{mnemonic_to_bytes, CipherSeed},
    },
};

// Import scanner library components for HTTP scanning
#[cfg(feature = "http")]
use crate::scanning::{
    http_scanner::{HttpBlockData, HttpBlockResponse, HttpBlockchainScanner, HttpOutputData},
    scan_results::ScanResults as LibScanResults,
    ScanConfig, ScanConfiguration, ScannerEngine, WalletContext, WalletSource,
};

#[cfg(feature = "http")]
use crate::extraction::ExtractionConfig;

/// Simplified block info for WASM serialization
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

// HTTP data structures for WASM (when HTTP scanner is not available or for legacy compatibility)
#[cfg(not(feature = "http"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlockResponse {
    pub blocks: Vec<HttpBlockData>,
    pub has_next_page: bool,
}

#[cfg(not(feature = "http"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlockData {
    pub header_hash: Vec<u8>,
    pub height: u64,
    pub outputs: Vec<HttpOutputData>,
    /// Inputs are now just arrays of 32-byte hashes (commitments) that have been spent
    /// This matches the actual API response format
    #[serde(default)]
    pub inputs: Option<Vec<Vec<u8>>>,
    pub mined_timestamp: u64,
}

#[cfg(not(feature = "http"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpOutputData {
    pub output_hash: Vec<u8>,
    pub commitment: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub sender_offset_public_key: Vec<u8>,
}

/// Derive a public key from a master key, returning it as a hex string.
#[wasm_bindgen]
pub fn derive_public_key_hex(master_key: &[u8]) -> Result<String, JsValue> {
    if master_key.len() != 32 {
        return Err(JsValue::from_str("master_key must be 32 bytes"));
    }
    // Simplified implementation - just return the master key as hex for now
    Ok(hex::encode(master_key))
}

/// WASM-compatible wallet scanner
#[wasm_bindgen]
pub struct WasmScanner {
    #[cfg(feature = "http")]
    scanner_engine: Option<ScannerEngine>,
    #[cfg(feature = "http")]
    wallet_context: Option<WalletContext>,
    // Legacy fields for backward compatibility during transition
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

/// Block-specific scan result structure (only data found in this block)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockScanResult {
    pub block_height: u64,
    pub block_hash: String,
    pub outputs_found: u64,
    pub inputs_spent: u64,
    pub value_found: u64,
    pub value_spent: u64,
    pub transactions: Vec<TransactionSummary>,
    pub success: bool,
    pub error: Option<String>,
}

/// Scan result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub total_outputs: u64,
    pub total_spent: u64,
    pub total_value: u64,
    pub current_balance: u64,
    pub blocks_processed: u64,
    pub transactions: Vec<TransactionSummary>,
    pub success: bool,
    pub error: Option<String>,
}

/// Transaction summary for results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSummary {
    pub hash: String,
    pub block_height: u64,
    pub value: u64,
    pub direction: String,
    pub status: String,
    pub is_spent: bool,
    pub payment_id: Option<String>,
}

impl WasmScanner {
    /// Create scanner from string input (automatically detects view key or seed phrase)
    pub fn from_str(data: &str) -> Result<Self, String> {
        // Try view key first
        match Self::from_view_key(data) {
            Ok(scanner) => Ok(scanner),
            Err(view_key_error) => {
                // If view key fails, try seed phrase
                match Self::from_seed_phrase(data) {
                    Ok(scanner) => Ok(scanner),
                    Err(seed_phrase_error) => {
                        // Both failed, return combined error message
                        Err(format!(
                            "Failed to create scanner. View key error: {}. Seed phrase error: {}",
                            view_key_error, seed_phrase_error
                        ))
                    }
                }
            }
        }
    }

    /// Cleanup old transactions to prevent memory leaks during large scans
    /// Keeps only the most recent transactions while preserving balance calculation
    pub fn cleanup_old_transactions(&mut self, max_transactions: usize) {
        if self.wallet_state.transactions.len() <= max_transactions {
            return; // No cleanup needed
        }

        // Sort transactions by block height to keep the most recent ones
        self.wallet_state
            .transactions
            .sort_by_key(|tx| tx.block_height);

        // Calculate how many to remove
        let to_remove = self.wallet_state.transactions.len() - max_transactions;

        // Remove oldest transactions
        self.wallet_state.transactions.drain(0..to_remove);

        // Rebuild the commitment indices after cleanup
        self.wallet_state.rebuild_commitment_index();

        // Note: This cleanup only removes transaction history for memory management.
        // The balance calculations remain correct as they're based on the summary counters
        // which are not affected by this cleanup.
    }

    /// Create scanner from seed phrase
    pub fn from_seed_phrase(seed_phrase: &str) -> Result<Self, String> {
        // Convert seed phrase to bytes
        let encrypted_bytes = mnemonic_to_bytes(seed_phrase)
            .map_err(|e| format!("Failed to convert seed phrase: {}", e))?;

        let cipher_seed = CipherSeed::from_enciphered_bytes(&encrypted_bytes, None)
            .map_err(|e| format!("Failed to create cipher seed: {}", e))?;

        let entropy = cipher_seed.entropy();
        let entropy_array: [u8; 16] = entropy
            .try_into()
            .map_err(|_| "Invalid entropy length".to_string())?;

        // Derive view key from entropy
        let view_key_raw =
            key_derivation::derive_private_key_from_entropy(&entropy_array, "data encryption", 0)
                .map_err(|e| format!("Failed to derive view key: {}", e))?;

        let view_key = PrivateKey::new(
            view_key_raw
                .as_bytes()
                .try_into()
                .map_err(|_| "Failed to convert view key".to_string())?,
        );

        // Create wallet context using the new library components
        #[cfg(feature = "http")]
        let wallet_context = {
            let wallet_source = WalletSource::from_seed_phrase(seed_phrase, None::<String>);
            match wallet_source.initialize_wallet() {
                Ok(context) => Some(context),
                Err(e) => return Err(format!("Failed to initialize wallet context: {}", e)),
            }
        };

        Ok(Self {
            #[cfg(feature = "http")]
            scanner_engine: None, // Will be initialized when needed
            #[cfg(feature = "http")]
            wallet_context,
            view_key,
            entropy: entropy_array,
            wallet_state: WalletState::new(),
        })
    }

    /// Create scanner from view key
    pub fn from_view_key(view_key_hex: &str) -> Result<Self, String> {
        let view_key_bytes =
            hex::decode(view_key_hex).map_err(|e| format!("Invalid hex format: {}", e))?;

        if view_key_bytes.len() != 32 {
            return Err("View key must be exactly 32 bytes (64 hex characters)".to_string());
        }

        let view_key_array: [u8; 32] = view_key_bytes
            .try_into()
            .map_err(|_| "Failed to convert view key to array".to_string())?;

        let view_key = PrivateKey::new(view_key_array);
        let entropy = [0u8; 16]; // Default entropy for view-key only mode

        // Create wallet context using the new library components
        #[cfg(feature = "http")]
        let wallet_context = {
            let wallet_source = WalletSource::from_view_key(view_key_hex, None);
            match wallet_source.initialize_wallet() {
                Ok(context) => Some(context),
                Err(e) => return Err(format!("Failed to initialize wallet context: {}", e)),
            }
        };

        Ok(Self {
            #[cfg(feature = "http")]
            scanner_engine: None, // Will be initialized when needed
            #[cfg(feature = "http")]
            wallet_context,
            view_key,
            entropy,
            wallet_state: WalletState::new(),
        })
    }

    /// Initialize scanner engine with base URL (if not already initialized)
    #[cfg(feature = "http")]
    pub async fn initialize_scanner_engine(&mut self, base_url: &str) -> Result<(), String> {
        if self.scanner_engine.is_none() {
            let http_scanner = HttpBlockchainScanner::new(base_url.to_string())
                .await
                .map_err(|e| format!("Failed to initialize HTTP scanner: {}", e))?;

            // Create scanner configuration with the wallet context we have
            let mut config = ScanConfiguration::default();

            // Set the wallet source based on our current wallet context
            if let Some(wallet_context) = &self.wallet_context {
                // Create a wallet source from the existing context
                let wallet_source = WalletSource::from_view_key(
                    &hex::encode(wallet_context.view_key.as_bytes()),
                    None,
                );
                config.wallet_source = Some(wallet_source);
            }

            // Create scanner engine with the HTTP scanner and configured wallet source
            let scanner_engine = ScannerEngine::new(Box::new(http_scanner), config);

            self.scanner_engine = Some(scanner_engine);
        }
        Ok(())
    }

    /// Initialize HTTP scanner with base URL (LEGACY - for backward compatibility)
    #[cfg(feature = "http")]
    pub async fn initialize_http_scanner(&mut self, base_url: &str) -> Result<(), String> {
        self.initialize_scanner_engine(base_url).await
    }

    /// Process HTTP block response using the scanner engine
    #[cfg(feature = "http")]
    pub async fn process_http_blocks_async(
        &mut self,
        http_response_json: &str,
        base_url: Option<&str>,
    ) -> ScanResult {
        // Initialize scanner engine if needed
        if let Some(url) = base_url {
            if let Err(e) = self.initialize_scanner_engine(url).await {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(e),
                };
            }
        }

        // Try using the scanner engine for processing if available
        if self.scanner_engine.is_some() {
            self.process_http_blocks_with_scanner_engine(http_response_json)
                .await
        } else {
            // Fallback to legacy processing
            self.process_http_blocks_internal(http_response_json)
        }
    }

    /// Process HTTP blocks using the new scanner engine library
    #[cfg(feature = "http")]
    async fn process_http_blocks_with_scanner_engine(
        &mut self,
        http_response_json: &str,
    ) -> ScanResult {
        // Parse HTTP response to extract block heights
        let http_response: HttpBlockResponse = match serde_json::from_str(http_response_json) {
            Ok(response) => response,
            Err(e) => {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(format!("Failed to parse HTTP response: {}", e)),
                };
            }
        };

        // Extract block heights for scanning
        let block_heights: Vec<u64> = http_response.blocks.iter().map(|b| b.height).collect();

        if block_heights.is_empty() {
            return ScanResult {
                total_outputs: 0,
                total_spent: 0,
                total_value: 0,
                current_balance: 0,
                blocks_processed: 0,
                transactions: Vec::new(),
                success: true,
                error: None,
            };
        }

        // Ensure wallet is properly initialized in the scanner engine
        if let Err(e) = self.ensure_wallet_initialized_in_scanner().await {
            return ScanResult {
                total_outputs: 0,
                total_spent: 0,
                total_value: 0,
                current_balance: 0,
                blocks_processed: 0,
                transactions: Vec::new(),
                success: false,
                error: Some(format!(
                    "Failed to initialize wallet in scanner engine: {}",
                    e
                )),
            };
        }

        // Use the scanner engine to scan specific blocks
        let scan_result = {
            let scanner_engine = match self.scanner_engine.as_mut() {
                Some(engine) => engine,
                None => {
                    return ScanResult {
                        total_outputs: 0,
                        total_spent: 0,
                        total_value: 0,
                        current_balance: 0,
                        blocks_processed: 0,
                        transactions: Vec::new(),
                        success: false,
                        error: Some("Scanner engine not initialized".to_string()),
                    };
                }
            };

            scanner_engine.scan_blocks(block_heights).await
        };

        match scan_result {
            Ok(scan_results) => {
                // Convert library ScanResults to WASM ScanResult and update local wallet state
                self.process_scanner_results_and_update_state(scan_results)
            }
            Err(e) => ScanResult {
                total_outputs: 0,
                total_spent: 0,
                total_value: 0,
                current_balance: 0,
                blocks_processed: 0,
                transactions: Vec::new(),
                success: false,
                error: Some(format!("Scanner engine scan failed: {}", e)),
            },
        }
    }

    /// Ensure wallet is properly initialized in the scanner engine
    #[cfg(feature = "http")]
    async fn ensure_wallet_initialized_in_scanner(&mut self) -> Result<(), String> {
        let scanner_engine = self
            .scanner_engine
            .as_mut()
            .ok_or("Scanner engine not initialized")?;

        // Initialize wallet if needed - the scanner engine will use its configuration's wallet_source
        if scanner_engine.wallet_context().is_none() {
            scanner_engine
                .initialize_wallet()
                .await
                .map_err(|e| format!("Failed to initialize wallet: {}", e))?;
        }

        Ok(())
    }

    /// Process scanner results and update local wallet state for WASM compatibility
    #[cfg(feature = "http")]
    fn process_scanner_results_and_update_state(
        &mut self,
        lib_results: LibScanResults,
    ) -> ScanResult {
        // Update local wallet state from scanner results for backward compatibility
        for block_result in &lib_results.block_results {
            for (output_index, wallet_output) in block_result.wallet_outputs.iter().enumerate() {
                // Get commitment from corresponding transaction output if available
                let commitment = if output_index < block_result.outputs.len() {
                    block_result.outputs[output_index].commitment().clone()
                } else {
                    // Fallback: create a placeholder commitment (this shouldn't happen in normal operation)
                    CompressedCommitment::new([0u8; 32])
                };

                // Add the wallet output to local state to maintain WASM compatibility
                self.wallet_state.add_received_output(
                    block_result.height,
                    output_index,
                    commitment,
                    None, // output_hash not available from library results
                    wallet_output.value().as_u64(),
                    wallet_output.payment_id().clone(),
                    crate::data_structures::transaction::TransactionStatus::MinedConfirmed,
                    crate::data_structures::transaction::TransactionDirection::Inbound,
                    true,
                );
            }
        }

        // Convert library results to WASM format
        self.convert_lib_scan_results_to_wasm_complete(lib_results)
    }

    /// Convert library ScanResults to WASM ScanResult format using complete wallet state
    #[cfg(feature = "http")]
    fn convert_lib_scan_results_to_wasm_complete(&self, lib_results: LibScanResults) -> ScanResult {
        // Extract all transactions from the wallet state which contains complete information
        let transactions: Vec<TransactionSummary> = self
            .wallet_state
            .transactions
            .iter()
            .map(|tx| TransactionSummary {
                hash: tx.output_hash_hex().unwrap_or_else(|| tx.commitment_hex()),
                block_height: tx.block_height,
                value: tx.value,
                direction: match tx.transaction_direction {
                    crate::data_structures::transaction::TransactionDirection::Inbound => {
                        "inbound".to_string()
                    }
                    crate::data_structures::transaction::TransactionDirection::Outbound => {
                        "outbound".to_string()
                    }
                    crate::data_structures::transaction::TransactionDirection::Unknown => {
                        "unknown".to_string()
                    }
                },
                status: format!("{:?}", tx.transaction_status),
                is_spent: tx.is_spent,
                payment_id: match &tx.payment_id {
                    PaymentId::Empty => None,
                    _ => Some(tx.payment_id.user_data_as_string()),
                },
            })
            .collect();

        // Use wallet state summary for accurate counts and values
        let (total_received, _total_spent, balance, unspent_count, spent_count) =
            self.wallet_state.get_summary();

        ScanResult {
            total_outputs: unspent_count as u64,
            total_spent: spent_count as u64,
            total_value: total_received,
            current_balance: balance as u64,
            blocks_processed: lib_results.scan_config_summary.total_blocks_scanned,
            transactions,
            success: lib_results.completed_successfully,
            error: lib_results.error_message,
        }
    }

    /// Process HTTP block response - LEGACY METHOD maintained for compatibility
    pub fn process_http_blocks(&mut self, http_response_json: &str) -> ScanResult {
        // For now, use the legacy internal method for synchronous calls
        // In the future, we could spawn a blocking async operation here
        self.process_http_blocks_internal(http_response_json)
    }

    /// Internal method to process HTTP blocks
    fn process_http_blocks_internal(&mut self, http_response_json: &str) -> ScanResult {
        // Parse HTTP response
        let http_response: HttpBlockResponse = match serde_json::from_str(http_response_json) {
            Ok(response) => response,
            Err(e) => {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(format!("Failed to parse HTTP response: {}", e)),
                };
            }
        };

        let mut _total_found_outputs = 0;
        let mut _total_spent_outputs = 0;
        let mut blocks_processed = 0;
        let mut batch_transactions = Vec::new();

        // Track initial transaction count to identify new transactions
        let _initial_transaction_count = self.wallet_state.transactions.len();

        // Process each block and collect block-specific transactions
        for http_block in http_response.blocks {
            let block_start_tx_count = self.wallet_state.transactions.len();

            match self.process_single_http_block(&http_block) {
                Ok((found_outputs, spent_outputs)) => {
                    _total_found_outputs += found_outputs;
                    _total_spent_outputs += spent_outputs;
                    blocks_processed += 1;

                    // Get transactions added in this block
                    let block_transactions: Vec<TransactionSummary> = self
                        .wallet_state
                        .transactions
                        .iter()
                        .skip(block_start_tx_count)
                        .map(|tx| TransactionSummary {
                            hash: tx.output_hash_hex().unwrap_or_else(|| tx.commitment_hex()),
                            block_height: tx.block_height,
                            value: tx.value,
                            direction: match tx.transaction_direction {
                                TransactionDirection::Inbound => "inbound".to_string(),
                                TransactionDirection::Outbound => "outbound".to_string(),
                                TransactionDirection::Unknown => "unknown".to_string(),
                            },
                            status: format!("{:?}", tx.transaction_status),
                            is_spent: tx.is_spent,
                            payment_id: match &tx.payment_id {
                                PaymentId::Empty => None,
                                _ => Some(tx.payment_id.user_data_as_string()),
                            },
                        })
                        .collect();

                    batch_transactions.extend(block_transactions);
                }
                Err(e) => {
                    return ScanResult {
                        total_outputs: 0,
                        total_spent: 0,
                        total_value: 0,
                        current_balance: 0,
                        blocks_processed,
                        transactions: batch_transactions,
                        success: false,
                        error: Some(format!(
                            "Failed to process block {}: {}",
                            http_block.height, e
                        )),
                    };
                }
            }
        }

        // Create result with all transactions found in this batch
        let (total_received, _total_spent, balance, unspent_count, spent_count) =
            self.wallet_state.get_summary();

        ScanResult {
            total_outputs: unspent_count as u64,
            total_spent: spent_count as u64,
            total_value: total_received,
            current_balance: balance as u64,
            blocks_processed: blocks_processed as u64,
            transactions: batch_transactions,
            success: true,
            error: None,
        }
    }

    /// Process single HTTP block - LEGACY METHOD for backward compatibility
    fn process_single_http_block(
        &mut self,
        http_block: &HttpBlockData,
    ) -> Result<(usize, usize), String> {
        // This is a legacy method for backward compatibility only.
        // New code should use the scanner engine via process_http_blocks_async for complete
        // transaction extraction using the library components.
        self.process_single_http_block_minimal(http_block)
    }

    /// Minimal processing for single HTTP block (used only when scanner engine batch processing is not available)
    fn process_single_http_block_minimal(
        &mut self,
        http_block: &HttpBlockData,
    ) -> Result<(usize, usize), String> {
        // Convert HTTP block to internal Block format for proper processing
        let outputs = self.convert_http_outputs_to_lib_outputs(http_block)?;
        let inputs = self.convert_http_inputs_to_lib_inputs(http_block)?;

        let block_hash = http_block.header_hash.clone();

        // Create Block using the same constructor as the scanner engine
        let block = Block::new(
            http_block.height,
            block_hash,
            http_block.mined_timestamp,
            outputs,
            inputs,
        );

        // Process the block properly to update wallet state
        let found_outputs = block
            .process_outputs(&self.view_key, &self.entropy, &mut self.wallet_state)
            .map_err(|e| format!("Failed to process outputs: {}", e))?;

        let spent_outputs = block
            .process_inputs(&mut self.wallet_state)
            .map_err(|e| format!("Failed to process inputs: {}", e))?;

        Ok((found_outputs, spent_outputs))
    }

    /// Convert HTTP outputs to library format
    fn convert_http_outputs_to_lib_outputs(
        &self,
        http_block: &HttpBlockData,
    ) -> Result<Vec<LightweightTransactionOutput>, String> {
        let mut outputs = Vec::new();
        for output_data in &http_block.outputs {
            let output = self.convert_http_output_data(output_data)?;
            outputs.push(output);
        }
        Ok(outputs)
    }

    /// Convert HTTP inputs to library format
    fn convert_http_inputs_to_lib_inputs(
        &self,
        http_block: &HttpBlockData,
    ) -> Result<Vec<TransactionInput>, String> {
        let mut inputs = Vec::new();
        if let Some(input_hashes) = &http_block.inputs {
            for (index, commitment_hash) in input_hashes.iter().enumerate() {
                let input = self.convert_http_input_hash(commitment_hash, index)?;
                inputs.push(input);
            }
        }
        Ok(inputs)
    }

    /// Convert HTTP output data to LightweightTransactionOutput
    fn convert_http_output_data(
        &self,
        output_data: &HttpOutputData,
    ) -> Result<LightweightTransactionOutput, String> {
        // Parse commitment
        let commitment = CompressedCommitment::new(
            output_data
                .commitment
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid commitment length".to_string())?,
        );

        // Parse sender offset public key
        let sender_offset_public_key = CompressedPublicKey::new(
            output_data
                .sender_offset_public_key
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid sender offset public key length".to_string())?,
        );

        // Parse encrypted data
        let encrypted_data = EncryptedData::from_bytes(&output_data.encrypted_data)
            .map_err(|e| format!("Invalid encrypted data: {}", e))?;

        // Parse features or use default
        let features = if let Some(http_features) = &output_data.features {
            LightweightOutputFeatures {
                output_type: match http_features.output_type {
                    0 => LightweightOutputType::Payment,
                    1 => LightweightOutputType::Coinbase,
                    _ => LightweightOutputType::Payment,
                },
                maturity: http_features.maturity,
                ..Default::default()
            }
        } else {
            LightweightOutputFeatures::default()
        };

        // Create output with available data
        Ok(LightweightTransactionOutput::new_current_version(
            features,
            commitment,
            None, // Range proof not provided in HTTP API
            LightweightScript::default(),
            sender_offset_public_key,
            LightweightSignature::default(),
            LightweightCovenant::default(),
            encrypted_data,
            MicroMinotari::new(output_data.minimum_value_promise.unwrap_or(0)),
        ))
    }

    /// Convert HTTP input hash to TransactionInput following original implementation
    fn convert_http_input_hash(
        &self,
        output_hash_bytes: &[u8],
        _index: usize,
    ) -> Result<TransactionInput, String> {
        // Following the original convert_http_input_to_lightweight implementation:
        // - Use ZERO commitment as placeholder (HTTP API doesn't provide commitments)
        // - Use actual output hash from HTTP API (this is the key for spending detection)
        if output_hash_bytes.len() != 32 {
            return Err("Invalid output hash length, expected 32 bytes".to_string());
        }

        let mut output_hash = [0u8; 32];
        output_hash.copy_from_slice(output_hash_bytes);

        // Create minimal TransactionInput with the output hash (original pattern)
        Ok(TransactionInput::new(
            1,                                // version
            0,                                // features (default)
            [0u8; 32], // commitment (not available from HTTP API, use placeholder)
            [0u8; 64], // script_signature (not available)
            CompressedPublicKey::default(), // sender_offset_public_key (not available)
            Vec::new(), // covenant (not available)
            LightweightExecutionStack::new(), // input_data (not available)
            output_hash, // output_hash (this is the actual data from HTTP API)
            0,         // output_features (not available)
            [0u8; 64], // output_metadata_signature (not available)
            0,         // maturity (not available)
            MicroMinotari::new(0), // value (not available)
        ))
    }

    // NOTE: The extract_synthetic_inputs_from_payment_ids method has been removed
    // as we now use the simplified HTTP inputs structure directly.
    // Spent output tracking is now handled by the simplified inputs which contain
    // just the 32-byte commitment hashes of outputs that have been spent.

    /// Process block data (LEGACY METHOD for backward compatibility)
    pub fn process_block(&mut self, block_data: &BlockData) -> ScanResult {
        // Convert legacy format to internal format
        let outputs = match self.convert_legacy_outputs(block_data) {
            Ok(outputs) => outputs,
            Err(e) => {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(e),
                };
            }
        };

        let inputs = match self.convert_legacy_inputs(block_data) {
            Ok(inputs) => inputs,
            Err(e) => {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(e),
                };
            }
        };

        let block_hash = match hex::decode(&block_data.hash) {
            Ok(hash) => hash,
            Err(e) => {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(format!("Invalid block hash: {}", e)),
                };
            }
        };

        // Create Block using the same constructor as scanner.rs
        let block = Block::new(
            block_data.height,
            block_hash,
            block_data.timestamp,
            outputs,
            inputs,
        );

        // Use the exact same processing methods as scanner.rs
        let found_outputs =
            match block.process_outputs(&self.view_key, &self.entropy, &mut self.wallet_state) {
                Ok(count) => count,
                Err(e) => {
                    return ScanResult {
                        total_outputs: 0,
                        total_spent: 0,
                        total_value: 0,
                        current_balance: 0,
                        blocks_processed: 0,
                        transactions: Vec::new(),
                        success: false,
                        error: Some(format!("Failed to process outputs: {}", e)),
                    };
                }
            };

        let spent_outputs = match block.process_inputs(&mut self.wallet_state) {
            Ok(count) => count,
            Err(e) => {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(format!("Failed to process inputs: {}", e)),
                };
            }
        };

        self.create_scan_result(found_outputs, spent_outputs, 1)
    }

    /// Process single block and return only block-specific results (LEGACY METHOD)
    pub fn process_single_block(&mut self, block_data: &BlockData) -> BlockScanResult {
        // Get wallet state before processing
        let (
            prev_total_received,
            prev_total_spent,
            _prev_balance,
            _prev_unspent_count,
            _prev_spent_count,
        ) = self.wallet_state.get_summary();
        let prev_transaction_count = self.wallet_state.transactions.len();

        // Convert legacy format to internal format
        let outputs = match self.convert_legacy_outputs(block_data) {
            Ok(outputs) => outputs,
            Err(e) => {
                return BlockScanResult {
                    block_height: block_data.height,
                    block_hash: block_data.hash.clone(),
                    outputs_found: 0,
                    inputs_spent: 0,
                    value_found: 0,
                    value_spent: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(e),
                };
            }
        };

        let inputs = match self.convert_legacy_inputs(block_data) {
            Ok(inputs) => inputs,
            Err(e) => {
                return BlockScanResult {
                    block_height: block_data.height,
                    block_hash: block_data.hash.clone(),
                    outputs_found: 0,
                    inputs_spent: 0,
                    value_found: 0,
                    value_spent: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(e),
                };
            }
        };

        let block_hash = match hex::decode(&block_data.hash) {
            Ok(hash) => hash,
            Err(e) => {
                return BlockScanResult {
                    block_height: block_data.height,
                    block_hash: block_data.hash.clone(),
                    outputs_found: 0,
                    inputs_spent: 0,
                    value_found: 0,
                    value_spent: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(format!("Invalid block hash: {}", e)),
                };
            }
        };

        // Create Block using the same constructor as scanner.rs
        let block = Block::new(
            block_data.height,
            block_hash.clone(),
            block_data.timestamp,
            outputs,
            inputs,
        );

        // Use the exact same processing methods as scanner.rs
        let found_outputs =
            match block.process_outputs(&self.view_key, &self.entropy, &mut self.wallet_state) {
                Ok(count) => count,
                Err(e) => {
                    return BlockScanResult {
                        block_height: block_data.height,
                        block_hash: block_data.hash.clone(),
                        outputs_found: 0,
                        inputs_spent: 0,
                        value_found: 0,
                        value_spent: 0,
                        transactions: Vec::new(),
                        success: false,
                        error: Some(format!("Failed to process outputs: {}", e)),
                    };
                }
            };

        let spent_outputs = match block.process_inputs(&mut self.wallet_state) {
            Ok(count) => count,
            Err(e) => {
                return BlockScanResult {
                    block_height: block_data.height,
                    block_hash: block_data.hash.clone(),
                    outputs_found: 0,
                    inputs_spent: 0,
                    value_found: 0,
                    value_spent: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(format!("Failed to process inputs: {}", e)),
                };
            }
        };

        // Get wallet state after processing
        let (
            new_total_received,
            new_total_spent,
            _new_balance,
            _new_unspent_count,
            _new_spent_count,
        ) = self.wallet_state.get_summary();

        // Calculate block-specific values
        let value_found = new_total_received - prev_total_received;
        let value_spent = new_total_spent - prev_total_spent;

        // Get transactions added in this block
        let block_transactions: Vec<TransactionSummary> = self
            .wallet_state
            .transactions
            .iter()
            .skip(prev_transaction_count)
            .filter(|tx| tx.block_height == block_data.height)
            .map(|tx| TransactionSummary {
                hash: tx.output_hash_hex().unwrap_or_else(|| tx.commitment_hex()),
                block_height: tx.block_height,
                value: tx.value,
                direction: match tx.transaction_direction {
                    TransactionDirection::Inbound => "inbound".to_string(),
                    TransactionDirection::Outbound => "outbound".to_string(),
                    TransactionDirection::Unknown => "unknown".to_string(),
                },
                status: format!("{:?}", tx.transaction_status),
                is_spent: tx.is_spent,
                payment_id: match &tx.payment_id {
                    PaymentId::Empty => None,
                    _ => Some(tx.payment_id.user_data_as_string()),
                },
            })
            .collect();

        BlockScanResult {
            block_height: block_data.height,
            block_hash: block_data.hash.clone(),
            outputs_found: found_outputs as u64,
            inputs_spent: spent_outputs as u64,
            value_found,
            value_spent,
            transactions: block_transactions,
            success: true,
            error: None,
        }
    }

    /// Convert legacy OutputData to LightweightTransactionOutput
    fn convert_legacy_outputs(
        &self,
        block_data: &BlockData,
    ) -> Result<Vec<LightweightTransactionOutput>, String> {
        let mut outputs = Vec::new();
        for output_data in &block_data.outputs {
            let output = self.convert_legacy_output_data(output_data)?;
            outputs.push(output);
        }
        Ok(outputs)
    }

    /// Convert legacy InputData to TransactionInput
    fn convert_legacy_inputs(
        &self,
        block_data: &BlockData,
    ) -> Result<Vec<TransactionInput>, String> {
        let mut inputs = Vec::new();
        for input_data in &block_data.inputs {
            let input = self.convert_legacy_input_data(input_data)?;
            inputs.push(input);
        }
        Ok(inputs)
    }

    /// Convert OutputData to LightweightTransactionOutput (LEGACY)
    fn convert_legacy_output_data(
        &self,
        output_data: &OutputData,
    ) -> Result<LightweightTransactionOutput, String> {
        // Parse commitment
        let commitment = CompressedCommitment::from_hex(&output_data.commitment)
            .map_err(|e| format!("Invalid commitment hex: {}", e))?;

        // Parse sender offset public key
        let sender_offset_public_key =
            CompressedPublicKey::from_hex(&output_data.sender_offset_public_key)
                .map_err(|e| format!("Invalid sender offset public key hex: {}", e))?;

        // Parse encrypted data
        let encrypted_data = EncryptedData::from_hex(&output_data.encrypted_data)
            .map_err(|e| format!("Invalid encrypted data hex: {}", e))?;

        // Create output with available data
        Ok(LightweightTransactionOutput::new_current_version(
            LightweightOutputFeatures::default(), // Use default features
            commitment,
            None,                         // Range proof not provided in UTXO sync
            LightweightScript::default(), // Script not provided or use default
            sender_offset_public_key,
            LightweightSignature::default(), // Metadata signature not provided or use default
            LightweightCovenant::default(),  // Covenant not provided or use default
            encrypted_data,
            MicroMinotari::from(output_data.minimum_value_promise),
        ))
    }

    /// Convert InputData to TransactionInput (LEGACY)
    fn convert_legacy_input_data(
        &self,
        input_data: &InputData,
    ) -> Result<TransactionInput, String> {
        use crate::data_structures::transaction_input::LightweightExecutionStack;

        // Parse commitment
        let commitment_bytes = hex::decode(&input_data.commitment)
            .map_err(|e| format!("Invalid input commitment hex: {}", e))?;

        if commitment_bytes.len() != 32 {
            return Err("Commitment must be exactly 32 bytes".to_string());
        }

        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&commitment_bytes);

        // Parse sender offset public key if provided
        let sender_offset_public_key = if let Some(ref pk_hex) = input_data.sender_offset_public_key
        {
            CompressedPublicKey::from_hex(pk_hex)
                .map_err(|e| format!("Invalid sender offset public key hex: {}", e))?
        } else {
            CompressedPublicKey::default()
        };

        // Create input with available data
        Ok(TransactionInput {
            version: 1,
            features: 0, // Default features
            commitment,
            script_signature: [0u8; 64], // Not provided in UTXO sync
            sender_offset_public_key,
            covenant: Vec::new(),                         // Not provided
            input_data: LightweightExecutionStack::new(), // Not provided
            output_hash: [0u8; 32],                       // Not provided in UTXO sync
            output_features: 0,                           // Not provided
            output_metadata_signature: [0u8; 64],         // Not provided
            maturity: 0,                                  // Not provided
            value: MicroMinotari::from(0u64),             // Not provided in UTXO sync
        })
    }

    /// Create scan result from processing results
    fn create_scan_result(
        &self,
        _found_outputs: usize,
        _spent_outputs: usize,
        blocks_processed: usize,
    ) -> ScanResult {
        let (total_received, _total_spent, balance, unspent_count, spent_count) =
            self.wallet_state.get_summary();

        // Convert transactions to summary format
        let transactions: Vec<TransactionSummary> = self
            .wallet_state
            .transactions
            .iter()
            .map(|tx| TransactionSummary {
                hash: tx.output_hash_hex().unwrap_or_else(|| tx.commitment_hex()),
                block_height: tx.block_height,
                value: tx.value,
                direction: match tx.transaction_direction {
                    TransactionDirection::Inbound => "inbound".to_string(),
                    TransactionDirection::Outbound => "outbound".to_string(),
                    TransactionDirection::Unknown => "unknown".to_string(),
                },
                status: format!("{:?}", tx.transaction_status),
                is_spent: tx.is_spent,
                payment_id: match &tx.payment_id {
                    PaymentId::Empty => None,
                    _ => Some(tx.payment_id.user_data_as_string()),
                },
            })
            .collect();

        ScanResult {
            total_outputs: unspent_count as u64,
            total_spent: spent_count as u64,
            total_value: total_received,
            current_balance: balance as u64,
            blocks_processed: blocks_processed as u64,
            transactions,
            success: true,
            error: None,
        }
    }

    /// Get current wallet state
    pub fn get_state(&self) -> String {
        match serde_json::to_string(&self.wallet_state) {
            Ok(json) => json,
            Err(_) => "{}".to_string(),
        }
    }

    /// Reset wallet state
    pub fn reset(&mut self) {
        self.wallet_state = WalletState::new();
    }

    /// Create a new WasmScanner with scanner engine initialized (convenience method)
    #[cfg(feature = "http")]
    pub async fn new_with_scanner_engine(
        seed_phrase: &str,
        base_url: &str,
    ) -> Result<WasmScanner, String> {
        let mut scanner = Self::from_seed_phrase(seed_phrase)?;
        scanner.initialize_scanner_engine(base_url).await?;
        Ok(scanner)
    }

    /// Create a new WasmScanner from view key with scanner engine initialized (convenience method)
    #[cfg(feature = "http")]
    pub async fn new_from_view_key_with_scanner_engine(
        view_key_hex: &str,
        base_url: &str,
    ) -> Result<WasmScanner, String> {
        let mut scanner = Self::from_view_key(view_key_hex)?;
        scanner.initialize_scanner_engine(base_url).await?;
        Ok(scanner)
    }

    /// Scan a range of blocks using the scanner engine (new simplified API)
    #[cfg(feature = "http")]
    pub async fn scan_block_range(
        &mut self,
        from_height: u64,
        to_height: u64,
        base_url: Option<&str>,
    ) -> ScanResult {
        // Initialize scanner engine if needed
        if let Some(url) = base_url {
            if let Err(e) = self.initialize_scanner_engine(url).await {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(e),
                };
            }
        }

        let scanner_engine = match self.scanner_engine.as_mut() {
            Some(engine) => engine,
            None => {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some("Scanner engine not initialized".to_string()),
                };
            }
        };

        // Initialize wallet context in the scanner engine if we have one
        if scanner_engine.wallet_context().is_none() && self.wallet_context.is_some() {
            if let Err(e) = scanner_engine.initialize_wallet().await {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(format!(
                        "Failed to initialize wallet in scanner engine: {}",
                        e
                    )),
                };
            }
        }

        // For now, collect all heights in the range and scan them as specific blocks
        let block_heights: Vec<u64> = (from_height..=to_height).collect();

        match scanner_engine.scan_blocks(block_heights).await {
            Ok(scan_results) => self.convert_lib_scan_results_to_wasm_complete(scan_results),
            Err(e) => ScanResult {
                total_outputs: 0,
                total_spent: 0,
                total_value: 0,
                current_balance: 0,
                blocks_processed: 0,
                transactions: Vec::new(),
                success: false,
                error: Some(format!("Scanner engine scan failed: {}", e)),
            },
        }
    }
}

/// Create a scanner from view key or seed phrase (WASM export)
/// Automatically detects the input type by trying view key first, then seed phrase
#[wasm_bindgen]
pub fn create_wasm_scanner(data: &str) -> Result<WasmScanner, JsValue> {
    WasmScanner::from_str(data).map_err(|e| JsValue::from_str(&e))
}

/// Initialize HTTP scanner (WASM export) - Returns a Promise
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn initialize_http_scanner(
    scanner: &mut WasmScanner,
    base_url: &str,
) -> Result<(), JsValue> {
    scanner
        .initialize_http_scanner(base_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Process HTTP block response with async support (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn process_http_blocks_async(
    scanner: &mut WasmScanner,
    http_response_json: &str,
    base_url: Option<String>,
) -> Result<String, JsValue> {
    let result = scanner
        .process_http_blocks_async(http_response_json, base_url.as_deref())
        .await;

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Create a scanner with scanner engine initialized from seed phrase (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn create_wasm_scanner_with_engine_from_seed_phrase(
    seed_phrase: &str,
    base_url: &str,
) -> Result<WasmScanner, JsValue> {
    WasmScanner::new_with_scanner_engine(seed_phrase, base_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Create a scanner with scanner engine initialized from view key (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn create_wasm_scanner_with_engine_from_view_key(
    view_key_hex: &str,
    base_url: &str,
) -> Result<WasmScanner, JsValue> {
    WasmScanner::new_from_view_key_with_scanner_engine(view_key_hex, base_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Scan a range of blocks using the scanner engine (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn scan_block_range_with_engine(
    scanner: &mut WasmScanner,
    from_height: u64,
    to_height: u64,
    base_url: Option<String>,
) -> Result<String, JsValue> {
    let result = scanner
        .scan_block_range(from_height, to_height, base_url.as_deref())
        .await;

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Process HTTP block response (WASM export) - LEGACY METHOD for backward compatibility
#[wasm_bindgen]
pub fn process_http_blocks(
    scanner: &mut WasmScanner,
    http_response_json: &str,
) -> Result<String, JsValue> {
    let result = scanner.process_http_blocks(http_response_json);

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Scan block data (WASM export) - LEGACY METHOD for backward compatibility
#[wasm_bindgen]
pub fn scan_block_data(
    scanner: &mut WasmScanner,
    block_data_json: &str,
) -> Result<String, JsValue> {
    let block_data: BlockData = serde_json::from_str(block_data_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse block data: {}", e)))?;

    let result = scanner.process_block(&block_data);

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Scan single block and return only block-specific data (WASM export) - LEGACY METHOD  
#[wasm_bindgen]
pub fn scan_single_block(
    scanner: &mut WasmScanner,
    block_data_json: &str,
) -> Result<String, JsValue> {
    let block_data: BlockData = serde_json::from_str(block_data_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse block data: {}", e)))?;

    let result = scanner.process_single_block(&block_data);

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Get cumulative scanner statistics (WASM export)
#[wasm_bindgen]
pub fn get_scanner_stats(scanner: &WasmScanner) -> Result<String, JsValue> {
    let (total_received, total_spent, balance, unspent_count, spent_count) =
        scanner.wallet_state.get_summary();
    let (inbound_count, outbound_count, _unknown_count) =
        scanner.wallet_state.get_direction_counts();

    let stats = serde_json::json!({
        "total_outputs": unspent_count,
        "total_spent": spent_count,
        "total_value": total_received,
        "total_spent_value": total_spent,
        "current_balance": balance,
        "total_transactions": scanner.wallet_state.transactions.len(),
        "inbound_transactions": inbound_count,
        "outbound_transactions": outbound_count,
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

/// Cleanup old transactions to prevent memory leaks (WASM export)
#[wasm_bindgen]
pub fn cleanup_scanner_transactions(scanner: &mut WasmScanner, max_transactions: u32) {
    scanner.cleanup_old_transactions(max_transactions as usize);
}

/// Get tip info from scanner engine (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn get_tip_info(scanner: &mut WasmScanner) -> Result<String, JsValue> {
    if let Some(ref mut scanner_engine) = scanner.scanner_engine {
        let tip_info = scanner_engine
            .get_tip_info()
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to get tip info: {}", e)))?;

        serde_json::to_string(&tip_info)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize tip info: {}", e)))
    } else {
        Err(JsValue::from_str("Scanner engine not initialized"))
    }
}
/// Fetch specific blocks by height using scanner engine (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn fetch_blocks_by_heights(
    scanner: &mut WasmScanner,
    heights_json: &str,
) -> Result<String, JsValue> {
    if let Some(ref mut scanner_engine) = scanner.scanner_engine {
        let heights: Vec<u64> = serde_json::from_str(heights_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse heights: {}", e)))?;

        let blocks = scanner_engine
            .scanner_mut()
            .get_blocks_by_heights(heights)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to fetch blocks: {}", e)))?;

        // Convert to WASM-serializable format
        let wasm_blocks: Vec<WasmBlockInfo> =
            blocks.into_iter().map(|block| block.into()).collect();

        serde_json::to_string(&wasm_blocks)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize blocks: {}", e)))
    } else {
        Err(JsValue::from_str("Scanner engine not initialized"))
    }
}

/// Search for UTXOs by commitment using scanner engine (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn search_utxos(
    scanner: &mut WasmScanner,
    commitments_json: &str,
) -> Result<String, JsValue> {
    if let Some(ref mut scanner_engine) = scanner.scanner_engine {
        let commitments: Vec<Vec<u8>> = serde_json::from_str(commitments_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse commitments: {}", e)))?;

        let results = scanner_engine
            .scanner_mut()
            .search_utxos(commitments)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to search UTXOs: {}", e)))?;

        serde_json::to_string(&results)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize search results: {}", e)))
    } else {
        Err(JsValue::from_str("Scanner engine not initialized"))
    }
}

/// Create scan config for HTTP scanner (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub fn create_scan_config(
    scanner: &WasmScanner,
    start_height: u64,
    end_height: Option<u64>,
) -> Result<String, JsValue> {
    let scan_config = ScanConfig {
        start_height,
        end_height,
        batch_size: 100,
        request_timeout: std::time::Duration::from_secs(30),
        extraction_config: ExtractionConfig::with_private_key(scanner.view_key.clone()),
    };

    serde_json::to_string(&scan_config)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize scan config: {}", e)))
}

/// Get version information (WASM export)
#[wasm_bindgen]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
