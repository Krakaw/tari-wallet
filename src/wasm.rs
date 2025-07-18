use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use tari_utilities::ByteArray;

#[cfg(feature = "http")]
use crate::scanning::cancellation::CancellationToken;

use crate::{
    data_structures::{
        types::{PrivateKey, CompressedCommitment, CompressedPublicKey, MicroMinotari},
        payment_id::PaymentId,
        wallet_transaction::WalletState,
        transaction::TransactionDirection,
        block::Block,
        transaction_output::LightweightTransactionOutput,
        transaction_input::TransactionInput,
        encrypted_data::EncryptedData,
        wallet_output::{LightweightOutputFeatures, LightweightScript, LightweightSignature, LightweightCovenant},
    },
    key_management::{
        key_derivation,
        seed_phrase::{mnemonic_to_bytes, CipherSeed},
    },
};

// Only import HTTP scanner types when available
#[cfg(feature = "http")]
use crate::scanning::{
    http_scanner::{HttpBlockchainScanner, HttpBlockResponse, HttpBlockData, HttpOutputData},
    ScanConfig, BlockchainScanner,
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
        self.wallet_state.transactions.sort_by_key(|tx| tx.block_height);
        
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
        let entropy_array: [u8; 16] = entropy.try_into()
            .map_err(|_| "Invalid entropy length".to_string())?;
        
        // Derive view key from entropy
        let view_key_raw = key_derivation::derive_private_key_from_entropy(
            &entropy_array,
            "data encryption",
            0,
        ).map_err(|e| format!("Failed to derive view key: {}", e))?;
        
        let view_key = PrivateKey::new(view_key_raw.as_bytes().try_into()
            .map_err(|_| "Failed to convert view key".to_string())?);
        
        Ok(Self {
            #[cfg(feature = "http")]
            http_scanner: None, // Will be initialized when needed
            view_key,
            entropy: entropy_array,
            wallet_state: WalletState::new(),
        })
    }

    /// Create scanner from view key
    pub fn from_view_key(view_key_hex: &str) -> Result<Self, String> {
        let view_key_bytes = hex::decode(view_key_hex)
            .map_err(|e| format!("Invalid hex format: {}", e))?;
        
        if view_key_bytes.len() != 32 {
            return Err("View key must be exactly 32 bytes (64 hex characters)".to_string());
        }

        let view_key_array: [u8; 32] = view_key_bytes.try_into()
            .map_err(|_| "Failed to convert view key to array".to_string())?;
        
        let view_key = PrivateKey::new(view_key_array);
        let entropy = [0u8; 16]; // Default entropy for view-key only mode
        
        Ok(Self {
            #[cfg(feature = "http")]
            http_scanner: None, // Will be initialized when needed
            view_key,
            entropy,
            wallet_state: WalletState::new(),
        })
    }

    /// Initialize HTTP scanner with base URL (if not already initialized)
    #[cfg(feature = "http")]
    pub async fn initialize_http_scanner(&mut self, base_url: &str) -> Result<(), String> {
        if self.http_scanner.is_none() {
            let scanner = HttpBlockchainScanner::new(base_url.to_string()).await
                .map_err(|e| format!("Failed to initialize HTTP scanner: {}", e))?;
            self.http_scanner = Some(scanner);
        }
        Ok(())
    }

    /// Process HTTP block response using the new HTTP scanner
    #[cfg(feature = "http")]
    pub async fn process_http_blocks_async(&mut self, http_response_json: &str, base_url: Option<&str>) -> ScanResult {
        // Initialize scanner if needed
        if let Some(url) = base_url {
            if let Err(e) = self.initialize_http_scanner(url).await {
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

        // Process blocks using the new method
        self.process_http_blocks_internal(http_response_json)
    }

    /// Process HTTP block response - LEGACY METHOD maintained for compatibility
    pub fn process_http_blocks(&mut self, http_response_json: &str) -> ScanResult {
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
                    let block_transactions: Vec<TransactionSummary> = self.wallet_state.transactions
                        .iter()
                        .skip(block_start_tx_count)
                        .map(|tx| {
                            TransactionSummary {
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
                            }
                        }).collect();

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
                        error: Some(format!("Failed to process block {}: {}", http_block.height, e)),
                    };
                }
            }
        }

        // Create result with all transactions found in this batch
        let (total_received, _total_spent, balance, unspent_count, spent_count) = self.wallet_state.get_summary();
        
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

    /// Process single HTTP block using the new HTTP scanner if available, otherwise fallback to legacy method
    fn process_single_http_block(&mut self, http_block: &HttpBlockData) -> Result<(usize, usize), String> {
        // If we have an HTTP scanner, try to use it for better integration
        #[cfg(feature = "http")]
        if self.http_scanner.is_some() {
            return self.process_single_http_block_with_scanner(http_block);
        }
        
        // Fallback to legacy processing
        self.process_single_http_block_legacy(http_block)
    }

    /// Process single HTTP block using HTTP scanner (new method)
    #[cfg(feature = "http")]
    fn process_single_http_block_with_scanner(&mut self, http_block: &HttpBlockData) -> Result<(usize, usize), String> {
        // Convert HTTP block to our internal format and process
        // For now, use the same conversion logic but with better integration potential
        self.process_single_http_block_legacy(http_block)
    }

    /// Process single HTTP block using legacy method
    /// 
    /// This method converts HTTP block data to the Block struct and uses the same
    /// `process_outputs()` method. For inputs, it now handles the simplified structure
    /// where inputs are just arrays of 32-byte commitment hashes.
    fn process_single_http_block_legacy(&mut self, http_block: &HttpBlockData) -> Result<(usize, usize), String> {
        // Convert HTTP outputs to LightweightTransactionOutput (same as scanner.rs expects)
        let outputs = self.convert_http_outputs_to_lightweight(&http_block.outputs)?;
        
        // Handle simplified inputs structure - just convert the commitment hashes to TransactionInput objects
        let inputs = self.convert_simplified_inputs_to_lightweight(&http_block.inputs)?;

        // Process outputs manually to preserve output_hash from HTTP response
        // CRITICAL: We must use the exact output_hash from HTTP API for later spent detection
        let mut found_outputs = 0;
        for (output_index, (http_output, lightweight_output)) in http_block.outputs.iter().zip(outputs.iter()).enumerate() {
            let output_hash_hex = hex::encode(&http_output.output_hash);
            
            // Try to decrypt and extract wallet output
            if let Ok((value, _mask, payment_id)) = crate::data_structures::encrypted_data::EncryptedData::decrypt_data(
                &self.view_key,
                &lightweight_output.commitment,
                &lightweight_output.encrypted_data,
            ) {
                // Add to wallet state with the original output_hash from HTTP response
                self.wallet_state.add_received_output(
                    http_block.height,
                    output_index,
                    lightweight_output.commitment.clone(),
                    Some(http_output.output_hash.clone()), // CRITICAL: Preserve exact output_hash from HTTP
                    value.as_u64(),
                    payment_id,
                    crate::data_structures::transaction::TransactionStatus::MinedConfirmed,
                    crate::data_structures::transaction::TransactionDirection::Inbound,
                    true,
                );
                found_outputs += 1;
                continue;
            }

            // Try one-sided decryption if available
            if !lightweight_output.sender_offset_public_key.as_bytes().iter().all(|&b| b == 0) {
                if let Ok((value, _mask, payment_id)) = crate::data_structures::encrypted_data::EncryptedData::decrypt_one_sided_data(
                    &self.view_key,
                    &lightweight_output.commitment,
                    &lightweight_output.sender_offset_public_key,
                    &lightweight_output.encrypted_data,
                ) {
                    // Add to wallet state with the original output_hash from HTTP response
                    self.wallet_state.add_received_output(
                        http_block.height,
                        output_index,
                        lightweight_output.commitment.clone(),
                        Some(http_output.output_hash.clone()), // CRITICAL: Preserve exact output_hash from HTTP
                        value.as_u64(),
                        payment_id,
                        crate::data_structures::transaction::TransactionStatus::OneSidedConfirmed,
                        crate::data_structures::transaction::TransactionDirection::Inbound,
                        true,
                    );
                    found_outputs += 1;
                }
            }
        }

        // Process inputs for spent detection
        // CRITICAL: HTTP API provides OUTPUT HASHES - we must match these exactly to track spending
        let mut spent_outputs = 0;
        for (input_index, input) in inputs.iter().enumerate() {
            let input_hash_hex = hex::encode(&input.output_hash);
            
            // Try to match by output hash - this is the primary method for HTTP API
            if self.wallet_state.mark_output_spent_by_hash(&input.output_hash, http_block.height, input_index) {
                spent_outputs += 1;
            } 
        }

        Ok((found_outputs, spent_outputs))
    }

    // NOTE: The extract_synthetic_inputs_from_payment_ids method has been removed
    // as we now use the simplified HTTP inputs structure directly.
    // Spent output tracking is now handled by the simplified inputs which contain
    // just the 32-byte commitment hashes of outputs that have been spent.

    /// Convert HTTP output data to LightweightTransactionOutput (minimal viable format)
    fn convert_http_outputs_to_lightweight(&self, http_outputs: &[HttpOutputData]) -> Result<Vec<LightweightTransactionOutput>, String> {
        let mut outputs = Vec::new();

        for http_output in http_outputs {
            // Parse commitment
            if http_output.commitment.len() != 32 {
                return Err("Invalid commitment length, expected 32 bytes".to_string());
            }
            let commitment = CompressedCommitment::new(
                http_output.commitment.clone().try_into()
                    .map_err(|_| "Failed to convert commitment")?
            );

            // Parse sender offset public key
            if http_output.sender_offset_public_key.len() != 32 {
                return Err("Invalid sender offset public key length, expected 32 bytes".to_string());
            }
            let sender_offset_public_key = CompressedPublicKey::new(
                http_output.sender_offset_public_key.clone().try_into()
                    .map_err(|_| "Failed to convert sender offset public key")?
            );

            // Parse encrypted data
            let encrypted_data = EncryptedData::from_bytes(&http_output.encrypted_data)
                .map_err(|e| format!("Invalid encrypted data: {}", e))?;

            // Create LightweightTransactionOutput with minimal viable data
            // HTTP API provides limited data, so we use defaults for missing fields
            let output = LightweightTransactionOutput::new_current_version(
                LightweightOutputFeatures::default(), // Default features (will be 0/Standard)
                commitment,
                None, // Range proof not provided in HTTP API
                LightweightScript::default(), // Script not provided, use empty/default
                sender_offset_public_key,
                LightweightSignature::default(), // Metadata signature not provided, use default
                LightweightCovenant::default(), // Covenant not provided, use default
                encrypted_data,
                MicroMinotari::from(0u64), // Minimum value promise not provided, use 0
            );

            outputs.push(output);
        }

        Ok(outputs)
    }

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
        let found_outputs = match block.process_outputs(&self.view_key, &self.entropy, &mut self.wallet_state) {
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
        let (prev_total_received, prev_total_spent, _prev_balance, _prev_unspent_count, _prev_spent_count) = self.wallet_state.get_summary();
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
        let found_outputs = match block.process_outputs(&self.view_key, &self.entropy, &mut self.wallet_state) {
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
        let (new_total_received, new_total_spent, _new_balance, _new_unspent_count, _new_spent_count) = self.wallet_state.get_summary();

        // Calculate block-specific values
        let value_found = new_total_received - prev_total_received;
        let value_spent = new_total_spent - prev_total_spent;

        // Get transactions added in this block
        let block_transactions: Vec<TransactionSummary> = self.wallet_state.transactions
            .iter()
            .skip(prev_transaction_count)
            .filter(|tx| tx.block_height == block_data.height)
            .map(|tx| {
                TransactionSummary {
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
                }
            }).collect();

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
    fn convert_legacy_outputs(&self, block_data: &BlockData) -> Result<Vec<LightweightTransactionOutput>, String> {
        let mut outputs = Vec::new();
        for output_data in &block_data.outputs {
            let output = self.convert_legacy_output_data(output_data)?;
            outputs.push(output);
        }
        Ok(outputs)
    }

    /// Convert legacy InputData to TransactionInput
    fn convert_legacy_inputs(&self, block_data: &BlockData) -> Result<Vec<TransactionInput>, String> {
        let mut inputs = Vec::new();
        for input_data in &block_data.inputs {
            let input = self.convert_legacy_input_data(input_data)?;
            inputs.push(input);
        }
        Ok(inputs)
    }

    /// Convert OutputData to LightweightTransactionOutput (LEGACY)
    fn convert_legacy_output_data(&self, output_data: &OutputData) -> Result<LightweightTransactionOutput, String> {
        // Parse commitment
        let commitment = CompressedCommitment::from_hex(&output_data.commitment)
            .map_err(|e| format!("Invalid commitment hex: {}", e))?;

        // Parse sender offset public key
        let sender_offset_public_key = CompressedPublicKey::from_hex(&output_data.sender_offset_public_key)
            .map_err(|e| format!("Invalid sender offset public key hex: {}", e))?;

        // Parse encrypted data
        let encrypted_data = EncryptedData::from_hex(&output_data.encrypted_data)
            .map_err(|e| format!("Invalid encrypted data hex: {}", e))?;

        // Create output with available data
        Ok(LightweightTransactionOutput::new_current_version(
            LightweightOutputFeatures::default(), // Use default features
            commitment,
            None, // Range proof not provided in UTXO sync
            LightweightScript::default(), // Script not provided or use default
            sender_offset_public_key,
            LightweightSignature::default(), // Metadata signature not provided or use default
            LightweightCovenant::default(), // Covenant not provided or use default
            encrypted_data,
            MicroMinotari::from(output_data.minimum_value_promise),
        ))
    }

    /// Convert InputData to TransactionInput (LEGACY)
    fn convert_legacy_input_data(&self, input_data: &InputData) -> Result<TransactionInput, String> {
        use crate::data_structures::{
            transaction_input::LightweightExecutionStack,
        };

        // Parse commitment
        let commitment_bytes = hex::decode(&input_data.commitment)
            .map_err(|e| format!("Invalid input commitment hex: {}", e))?;
        
        if commitment_bytes.len() != 32 {
            return Err("Commitment must be exactly 32 bytes".to_string());
        }
        
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&commitment_bytes);

        // Parse sender offset public key if provided
        let sender_offset_public_key = if let Some(ref pk_hex) = input_data.sender_offset_public_key {
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
            covenant: Vec::new(), // Not provided
            input_data: LightweightExecutionStack::new(), // Not provided
            output_hash: [0u8; 32], // Not provided in UTXO sync
            output_features: 0, // Not provided
            output_metadata_signature: [0u8; 64], // Not provided
            maturity: 0, // Not provided
            value: MicroMinotari::from(0u64), // Not provided in UTXO sync
        })
    }

    /// Convert simplified inputs structure to TransactionInput objects
    /// 
    /// The HTTP API returns inputs as arrays of 32-byte OUTPUT HASHES.
    /// We convert these to minimal TransactionInput objects for spent output tracking.
    /// CRITICAL: We must preserve the output hashes exactly as provided for accurate spent detection.
    fn convert_simplified_inputs_to_lightweight(
        &self,
        inputs: &Option<Vec<Vec<u8>>>,
    ) -> Result<Vec<TransactionInput>, String> {
        use crate::data_structures::{
            transaction_input::{TransactionInput, LightweightExecutionStack},
            types::{CompressedPublicKey, MicroMinotari},
        };

        let mut transaction_inputs = Vec::new();

        if let Some(input_hashes) = inputs {
            for input_hash in input_hashes {
                // Validate output hash length
                if input_hash.len() != 32 {
                    return Err(format!("Invalid output hash length: expected 32 bytes, got {}", input_hash.len()));
                }

                // Convert to 32-byte array for output_hash - PRESERVE EXACTLY AS PROVIDED
                let mut output_hash = [0u8; 32];
                output_hash.copy_from_slice(input_hash);

                // Create minimal TransactionInput with the output hash
                // The output_hash field is what we use for spent detection
                let transaction_input = TransactionInput::new(
                    1, // version
                    0, // features (default)
                    [0u8; 32], // commitment (not available from HTTP API, use placeholder)
                    [0u8; 64], // script_signature (not available)
                    CompressedPublicKey::default(), // sender_offset_public_key (not available)
                    Vec::new(), // covenant (not available)
                    LightweightExecutionStack::new(), // input_data (not available)
                    output_hash, // output_hash (CRITICAL: this is the actual data from HTTP API)
                    0, // output_features (not available)
                    [0u8; 64], // output_metadata_signature (not available)
                    0, // maturity (not available)
                    MicroMinotari::from(0u64), // value (not available)
                );

                transaction_inputs.push(transaction_input);
            }
        }

        Ok(transaction_inputs)
    }

    /// Create scan result from processing results
    fn create_scan_result(&self, _found_outputs: usize, _spent_outputs: usize, blocks_processed: usize) -> ScanResult {
        let (total_received, _total_spent, balance, unspent_count, spent_count) = self.wallet_state.get_summary();
        
        // Convert transactions to summary format
        let transactions: Vec<TransactionSummary> = self.wallet_state.transactions.iter().map(|tx| {
            TransactionSummary {
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
            }
        }).collect();

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
pub async fn initialize_http_scanner(scanner: &mut WasmScanner, base_url: &str) -> Result<(), JsValue> {
    scanner.initialize_http_scanner(base_url).await
        .map_err(|e| JsValue::from_str(&e))
}

/// Process HTTP block response with async support (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen] 
pub async fn process_http_blocks_async(scanner: &mut WasmScanner, http_response_json: &str, base_url: Option<String>) -> Result<String, JsValue> {
    let result = scanner.process_http_blocks_async(http_response_json, base_url.as_deref()).await;
    
    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Process HTTP block response (WASM export) - LEGACY METHOD for backward compatibility
#[wasm_bindgen]
pub fn process_http_blocks(scanner: &mut WasmScanner, http_response_json: &str) -> Result<String, JsValue> {
    let result = scanner.process_http_blocks(http_response_json);
    
    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Scan block data (WASM export) - LEGACY METHOD for backward compatibility
#[wasm_bindgen]
pub fn scan_block_data(scanner: &mut WasmScanner, block_data_json: &str) -> Result<String, JsValue> {
    let block_data: BlockData = serde_json::from_str(block_data_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse block data: {}", e)))?;

    let result = scanner.process_block(&block_data);
    
    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Scan single block and return only block-specific data (WASM export) - LEGACY METHOD  
#[wasm_bindgen]
pub fn scan_single_block(scanner: &mut WasmScanner, block_data_json: &str) -> Result<String, JsValue> {
    let block_data: BlockData = serde_json::from_str(block_data_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse block data: {}", e)))?;

    let result = scanner.process_single_block(&block_data);
    
    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Get cumulative scanner statistics (WASM export)
#[wasm_bindgen]
pub fn get_scanner_stats(scanner: &WasmScanner) -> Result<String, JsValue> {
    let (total_received, total_spent, balance, unspent_count, spent_count) = scanner.wallet_state.get_summary();
    let (inbound_count, outbound_count, _unknown_count) = scanner.wallet_state.get_direction_counts();
    
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
/// Fetch specific blocks by height using HTTP scanner (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn fetch_blocks_by_heights(scanner: &mut WasmScanner, heights_json: &str) -> Result<String, JsValue> {
    if let Some(ref mut http_scanner) = scanner.http_scanner {
        let heights: Vec<u64> = serde_json::from_str(heights_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse heights: {}", e)))?;
        
        let blocks = http_scanner.get_blocks_by_heights(heights).await
            .map_err(|e| JsValue::from_str(&format!("Failed to fetch blocks: {}", e)))?;
        
        // Convert to WASM-serializable format
        let wasm_blocks: Vec<WasmBlockInfo> = blocks.into_iter().map(|block| block.into()).collect();
        
        serde_json::to_string(&wasm_blocks)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize blocks: {}", e)))
    } else {
        Err(JsValue::from_str("HTTP scanner not initialized"))
    }
}

/// Search for UTXOs by commitment using HTTP scanner (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn search_utxos(scanner: &mut WasmScanner, commitments_json: &str) -> Result<String, JsValue> {
    if let Some(ref mut http_scanner) = scanner.http_scanner {
        let commitments: Vec<Vec<u8>> = serde_json::from_str(commitments_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse commitments: {}", e)))?;
        
        let results = http_scanner.search_utxos(commitments).await
            .map_err(|e| JsValue::from_str(&format!("Failed to search UTXOs: {}", e)))?;
        
        serde_json::to_string(&results)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize search results: {}", e)))
    } else {
        Err(JsValue::from_str("HTTP scanner not initialized"))
    }
}

/// Create scan config for HTTP scanner (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub fn create_scan_config(scanner: &WasmScanner, start_height: u64, end_height: Option<u64>) -> Result<String, JsValue> {
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

//=============================================================================
// ENHANCED WASM SCANNING FUNCTIONALITY
//=============================================================================

/// Enhanced WASM Scanner that uses the lib's new enhanced scanning functionality
/// Only available when HTTP scanning is enabled (WASM doesn't support gRPC)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub struct EnhancedWasmScanner {
    scan_context: Option<crate::scanning::WalletScanContext>,
    scanner: Option<crate::scanning::HttpBlockchainScanner>,
    config: Option<crate::scanning::EnhancedScanConfig>,
    cancellation_token: Option<crate::scanning::WasmCancellationToken>,
}

/// WASM-compatible progress callback
/// Only available when HTTP scanning is enabled (WASM doesn't support gRPC)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub struct WasmProgressCallback {
    callback: js_sys::Function,
}

/// Thread-safe wrapper for WASM callback (WASM is single-threaded so this is safe)
#[cfg(feature = "http")]
struct WasmProgressCallbackWrapper {
    callback: js_sys::Function,
}

#[cfg(feature = "http")]
unsafe impl Send for WasmProgressCallbackWrapper {}
#[cfg(feature = "http")]
unsafe impl Sync for WasmProgressCallbackWrapper {}

/// WASM-compatible progress information
#[wasm_bindgen]
#[derive(Serialize)]
pub struct WasmProgressInfo {
    /// Current block being processed
    pub current_block: u64,
    /// Total blocks to process
    pub total_blocks: usize,
    /// Blocks processed so far
    pub blocks_processed: usize,
    /// Outputs found
    pub outputs_found: usize,
    /// Spent outputs found
    pub inputs_found: usize,
    /// Progress percentage (0-100)
    pub progress_percent: f64,
    /// Blocks per second
    pub blocks_per_second: f64,
    /// Elapsed time in seconds
    pub elapsed_seconds: f64,
    /// Estimated remaining seconds
    pub remaining_seconds: Option<f64>,
    // Private field for phase - accessed via getter
    phase_str: String,
}

#[wasm_bindgen]
impl WasmProgressInfo {
    /// Get the current phase as a string
    #[wasm_bindgen(getter)]
    pub fn phase(&self) -> String {
        self.phase_str.clone()
    }
}

/// WASM-compatible scan results
#[wasm_bindgen]
#[derive(Serialize)]
pub struct WasmScanResult {
    /// Whether scan completed successfully
    pub completed: bool,
    /// Whether scan was interrupted
    pub interrupted: bool,
    /// Total transactions found
    pub transaction_count: usize,
    /// Total received amount (microTari)
    pub total_received: u64,
    /// Total spent amount (microTari)
    pub total_spent: u64,
    /// Current balance (microTari)
    pub current_balance: u64,
    /// Unspent outputs count
    pub unspent_count: usize,
    /// Spent outputs count
    pub spent_count: usize,
    /// Scan duration in seconds
    pub duration_seconds: f64,
    // Private field for error - accessed via getter
    error_msg: Option<String>,
}

#[wasm_bindgen]
impl WasmScanResult {
    /// Get the error message if any
    #[wasm_bindgen(getter)]
    pub fn error(&self) -> Option<String> {
        self.error_msg.clone()
    }
}

#[wasm_bindgen]
impl EnhancedWasmScanner {
    /// Create a new enhanced WASM scanner from seed phrase
    #[wasm_bindgen(constructor)]
    pub fn new_from_seed_phrase(seed_phrase: &str) -> Result<EnhancedWasmScanner, JsValue> {
        use crate::wallet::Wallet;
        use crate::scanning::WalletScanContext;
        
        let wallet = Wallet::new_from_seed_phrase(seed_phrase, None)
            .map_err(|e| JsValue::from_str(&format!("Failed to create wallet: {}", e)))?;
            
        let scan_context = WalletScanContext::from_wallet(&wallet)
            .map_err(|e| JsValue::from_str(&format!("Failed to create scan context: {}", e)))?;
        
        Ok(EnhancedWasmScanner {
            scan_context: Some(scan_context),
            scanner: None,
            config: None,
            cancellation_token: None,
        })
    }

    /// Create a new enhanced WASM scanner from view key
    #[wasm_bindgen]
    pub fn new_from_view_key(view_key_hex: &str) -> Result<EnhancedWasmScanner, JsValue> {
        use crate::scanning::WalletScanContext;
        
        let scan_context = WalletScanContext::from_view_key(view_key_hex)
            .map_err(|e| JsValue::from_str(&format!("Failed to create scan context: {}", e)))?;
        
        Ok(EnhancedWasmScanner {
            scan_context: Some(scan_context),
            scanner: None,
            config: None,
            cancellation_token: None,
        })
    }

    /// Initialize the HTTP scanner
    #[wasm_bindgen]
    pub async fn initialize_scanner(&mut self, base_url: &str) -> Result<(), JsValue> {
        use crate::scanning::HttpScannerBuilder;
        use std::time::Duration;
        
        let scanner = HttpScannerBuilder::new()
            .with_base_url(base_url.to_string())
            .with_timeout(Duration::from_secs(30))
            .build()
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to create scanner: {}", e)))?;
            
        self.scanner = Some(scanner);
        Ok(())
    }

    /// Configure the scan parameters
    #[wasm_bindgen]
    pub fn configure_scan(&mut self, from_block: u64, to_block: Option<u64>, batch_size: Option<usize>) -> Result<(), JsValue> {
        use crate::scanning::{EnhancedScanConfig, OutputFormat};
        use std::time::Duration;
        
        let actual_to_block = to_block.unwrap_or(from_block + 1000); // Default range
        let actual_batch_size = batch_size.unwrap_or(10);
        
        let config = EnhancedScanConfig::new(from_block, actual_to_block)
            .with_batch_size(actual_batch_size)
            .with_progress_frequency(1) // Update every block for WASM
            .with_output_format(OutputFormat::Summary)
            .with_request_timeout(Duration::from_secs(30));
            
        self.config = Some(config);
        Ok(())
    }

    /// Configure the scan for specific blocks
    #[wasm_bindgen]
    pub fn configure_scan_blocks(&mut self, blocks_json: &str, batch_size: Option<usize>) -> Result<(), JsValue> {
        use crate::scanning::{EnhancedScanConfig, OutputFormat};
        use std::time::Duration;
        
        let blocks: Vec<u64> = serde_json::from_str(blocks_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse blocks: {}", e)))?;
        
        let actual_batch_size = batch_size.unwrap_or(10);
        
        let config = EnhancedScanConfig::for_specific_blocks(blocks)
            .with_batch_size(actual_batch_size)
            .with_progress_frequency(1) // Update every block for WASM
            .with_output_format(OutputFormat::Summary)
            .with_request_timeout(Duration::from_secs(30));
            
        self.config = Some(config);
        Ok(())
    }

    /// Create a cancellation token for the scan
    #[wasm_bindgen]
    pub fn create_cancellation_token(&mut self) -> Result<(), JsValue> {
        use crate::scanning::WasmCancellationToken;
        
        self.cancellation_token = Some(WasmCancellationToken::new());
        Ok(())
    }

    /// Cancel the current scan
    #[wasm_bindgen]
    pub fn cancel_scan(&self) -> Result<(), JsValue> {
        if let Some(token) = &self.cancellation_token {
            token.cancel();
            Ok(())
        } else {
            Err(JsValue::from_str("No cancellation token available"))
        }
    }

    /// Check if scan is cancelled
    #[wasm_bindgen]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation_token
            .as_ref()
            .map(|token| token.is_cancelled())
            .unwrap_or(false)
    }

    /// Perform the enhanced scan with progress callback
    #[wasm_bindgen]
    pub async fn scan_wallet(&mut self, progress_callback: Option<js_sys::Function>) -> Result<JsValue, JsValue> {
        use crate::scanning::{EnhancedScannerBuilder, CancellationToken};
        
        // Validate prerequisites
        let scan_context = self.scan_context.clone()
            .ok_or_else(|| JsValue::from_str("No scan context available"))?;
        let scanner = self.scanner.take()
            .ok_or_else(|| JsValue::from_str("Scanner not initialized"))?;
        let config = self.config.clone()
            .ok_or_else(|| JsValue::from_str("Scan not configured"))?;

        // Create enhanced scanner
        let mut enhanced_scanner = EnhancedScannerBuilder::new()
            .with_scanner(scanner)
            .with_scan_config(config.clone())
            .build()
            .map_err(|e| JsValue::from_str(&format!("Failed to build enhanced scanner: {}", e)))?
            .with_scan_context(scan_context);

        // Create WASM progress callback wrapper
        let wasm_progress_callback = progress_callback.map(|cb| WasmProgressCallbackWrapper { callback: cb });

        // Setup cancellation
        let cancellation_token = self.cancellation_token.as_ref()
            .map(|token| token as &dyn CancellationToken);

        let start_time = std::time::Instant::now();

        // Perform the scan
        let scan_result = enhanced_scanner.scan_wallet(
            wasm_progress_callback.as_ref().map(|cb| cb as &dyn crate::scanning::EnhancedProgressCallback),
            None, // No error callback for now
            cancellation_token,
        ).await;

        let duration = start_time.elapsed();

        // Process results
        match scan_result {
            Ok(result) => {
                use crate::scanning::EnhancedScanResult;
                
                let (completed, interrupted, wallet_state) = match result {
                    EnhancedScanResult::Completed(state) => (true, false, state),
                    EnhancedScanResult::Interrupted(state) => (false, true, state),
                    EnhancedScanResult::Failed(error) => {
                        return Ok(serde_wasm_bindgen::to_value(&WasmScanResult {
                            completed: false,
                            interrupted: false,
                            error_msg: Some(error.to_string()),
                            transaction_count: 0,
                            total_received: 0,
                            total_spent: 0,
                            current_balance: 0,
                            unspent_count: 0,
                            spent_count: 0,
                            duration_seconds: duration.as_secs_f64(),
                        })?);
                    }
                };

                let (total_received, total_spent, current_balance, unspent_count, spent_count) = wallet_state.get_summary();

                let result = WasmScanResult {
                    completed,
                    interrupted,
                    error_msg: None,
                    transaction_count: wallet_state.transactions.len(),
                    total_received,
                    total_spent,
                    current_balance: current_balance.max(0) as u64,
                    unspent_count,
                    spent_count,
                    duration_seconds: duration.as_secs_f64(),
                };

                Ok(serde_wasm_bindgen::to_value(&result)?)
            }
            Err(e) => {
                let result = WasmScanResult {
                    completed: false,
                    interrupted: false,
                    error_msg: Some(e.to_string()),
                    transaction_count: 0,
                    total_received: 0,
                    total_spent: 0,
                    current_balance: 0,
                    unspent_count: 0,
                    spent_count: 0,
                    duration_seconds: duration.as_secs_f64(),
                };

                Ok(serde_wasm_bindgen::to_value(&result)?)
            }
        }
    }
}

/// Implementation of ProgressCallback for WASM wrapper
#[cfg(feature = "http")]
impl crate::scanning::callbacks::ProgressCallback for WasmProgressCallbackWrapper {
    fn on_progress(&self, progress: &crate::scanning::callbacks::ScanProgress) {
        let progress_info = WasmProgressInfo {
            current_block: progress.current_block,
            total_blocks: progress.total_blocks,
            blocks_processed: progress.blocks_processed,
            outputs_found: progress.outputs_found,
            inputs_found: progress.inputs_found,
            progress_percent: progress.progress_percentage() * 100.0,
            blocks_per_second: progress.blocks_per_second(),
            elapsed_seconds: progress.elapsed().as_secs_f64(),
            remaining_seconds: progress.estimated_remaining().map(|d| d.as_secs_f64()),
            phase_str: format!("{:?}", progress.phase),
        };

        if let Ok(js_value) = serde_wasm_bindgen::to_value(&progress_info) {
            let _ = self.callback.call1(&JsValue::NULL, &js_value);
        }
    }

    fn on_phase_change(&self, _old_phase: crate::scanning::callbacks::ScanPhase, _new_phase: crate::scanning::callbacks::ScanPhase) {
        // Phase changes can be handled in the progress callback
    }

    fn on_scan_start(&self, _total_blocks: usize) {
        // Could add a specific callback for scan start
    }

    fn on_scan_complete(&self, _final_state: &crate::data_structures::wallet_transaction::WalletState, _stats: &crate::scanning::callbacks::ScanProgress) {
        // Could add a specific callback for scan complete
    }

    fn on_scan_interrupted(&self, _partial_state: &crate::data_structures::wallet_transaction::WalletState, _stats: &crate::scanning::callbacks::ScanProgress) {
        // Could add a specific callback for scan interrupted
    }
}
