//! GRPC-based blockchain scanner implementation
//!
//! This module provides a GRPC implementation of the BlockchainScanner trait
//! that connects to a Tari base node via GRPC to scan for wallet outputs.
//!
//! ## Wallet Key Integration
//!
//! The GRPC scanner supports wallet key integration for identifying outputs that belong
//! to a specific wallet.

#[cfg(feature = "grpc")]
use async_trait::async_trait;
#[cfg(feature = "grpc")]
use std::time::Duration;
#[cfg(feature = "grpc")]
use tari_utilities::ByteArray;
#[cfg(feature = "grpc")]
use tonic::{transport::Channel, Request};
#[cfg(feature = "grpc")]
use tracing::{debug, info};

#[cfg(feature = "grpc")]
use crate::{
    data_structures::{
        encrypted_data::EncryptedData,
        transaction_output::LightweightTransactionOutput,
        types::{CompressedCommitment, CompressedPublicKey, MicroMinotari, PrivateKey},
        wallet_output::{
            LightweightCovenant, LightweightOutputFeatures, LightweightRangeProof,
            LightweightScript, LightweightSignature, LightweightWalletOutput,
        },
        LightweightOutputType, LightweightRangeProofType,
    },
    errors::{DataStructureError, LightweightWalletError, LightweightWalletResult},
    extraction::{extract_wallet_output, ExtractionConfig},
    scanning::{
        BlockInfo, BlockScanResult, BlockchainScanner, DefaultScanningLogic, ProgressCallback,
        ScanConfig, TipInfo, WalletScanConfig, WalletScanResult, WalletScanner,
    },
    wallet::Wallet,
};

#[cfg(feature = "grpc")]
use crate::tari_rpc;

/// GRPC client for connecting to Tari base node
#[cfg(feature = "grpc")]
pub struct GrpcBlockchainScanner {
    /// GRPC channel to the base node
    client: tari_rpc::base_node_client::BaseNodeClient<Channel>,
    /// Connection timeout
    timeout: Duration,
    /// Base URL for the GRPC connection
    base_url: String,
}

#[cfg(feature = "grpc")]
impl GrpcBlockchainScanner {
    /// Create a new GRPC scanner with the given base URL
    pub async fn new(base_url: String) -> LightweightWalletResult<Self> {
        let timeout = Duration::from_secs(30);
        let channel = Channel::from_shared(base_url.clone())
            .map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Invalid URL: {e}"
                    )),
                )
            })?
            .timeout(timeout)
            .connect()
            .await
            .map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Connection failed: {e}"
                    )),
                )
            })?;

        // Set message size limits on the client to handle large blocks (16MB should be sufficient)
        let client = tari_rpc::base_node_client::BaseNodeClient::new(channel)
            .max_decoding_message_size(16 * 1024 * 1024) // 16MB
            .max_encoding_message_size(16 * 1024 * 1024); // 16MB

        Ok(Self {
            client,
            timeout,
            base_url,
        })
    }

    /// Create a new GRPC scanner with custom timeout
    pub async fn with_timeout(
        base_url: String,
        timeout: Duration,
    ) -> LightweightWalletResult<Self> {
        let channel = Channel::from_shared(base_url.clone())
            .map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Invalid URL: {e}"
                    )),
                )
            })?
            .timeout(timeout)
            .connect()
            .await
            .map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Connection failed: {e}"
                    )),
                )
            })?;

        // Set message size limits on the client to handle large blocks (16MB should be sufficient)
        let client = tari_rpc::base_node_client::BaseNodeClient::new(channel)
            .max_decoding_message_size(16 * 1024 * 1024) // 16MB
            .max_encoding_message_size(16 * 1024 * 1024); // 16MB

        Ok(Self {
            client,
            timeout,
            base_url,
        })
    }

    /// Convert GRPC transaction output to lightweight transaction output
    fn convert_transaction_output(
        grpc_output: &tari_rpc::TransactionOutput,
    ) -> LightweightWalletResult<LightweightTransactionOutput> {
        // Convert OutputFeatures
        let features = grpc_output
            .features
            .as_ref()
            .map(|f| LightweightOutputFeatures {
                output_type: match f.output_type {
                    0 => LightweightOutputType::Payment,
                    1 => LightweightOutputType::Coinbase,
                    2 => LightweightOutputType::Burn,
                    3 => LightweightOutputType::ValidatorNodeRegistration,
                    4 => LightweightOutputType::CodeTemplateRegistration,
                    _ => LightweightOutputType::Payment,
                },
                maturity: f.maturity,
                range_proof_type: match f.range_proof_type {
                    0 => LightweightRangeProofType::BulletProofPlus,
                    1 => LightweightRangeProofType::RevealedValue,
                    _ => LightweightRangeProofType::BulletProofPlus,
                },
            })
            .unwrap_or_default();

        // Convert Commitment - Tari GRPC returns 32-byte commitments, need to add compression prefix
        let commitment_bytes = if grpc_output.commitment.len() == 32 {
            match grpc_output.commitment.as_bytes()[..32].try_into() {
                Ok(bytes) => CompressedCommitment::new(bytes),
                Err(_) => {
                    // Invalid commitment bytes format - return error instead of fallback
                    return Err(LightweightWalletError::DataStructureError(
                        DataStructureError::InvalidCommitment(
                            "Invalid commitment bytes format in GRPC output".to_string(),
                        ),
                    ));
                }
            }
        } else {
            // Unexpected commitment size - return error instead of fallback
            return Err(LightweightWalletError::DataStructureError(
                DataStructureError::InvalidCommitment(format!(
                    "Invalid commitment size in GRPC output: expected 32, got {}",
                    grpc_output.commitment.len()
                )),
            ));
        };

        // Convert RangeProof
        let proof = grpc_output
            .range_proof
            .as_ref()
            .map(|rp| LightweightRangeProof {
                bytes: rp.proof_bytes.clone(),
            });

        // Convert Script
        let script = LightweightScript {
            bytes: grpc_output.script.clone(),
        };

        // Convert Sender Offset Public Key - need to handle the 32-byte array properly
        let sender_offset_public_key = if grpc_output.sender_offset_public_key.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&grpc_output.sender_offset_public_key);
            CompressedPublicKey::new(bytes)
        } else {
            // Invalid sender offset public key size - return error instead of fallback
            return Err(LightweightWalletError::DataStructureError(
                DataStructureError::InvalidCommitment(format!(
                    "Invalid sender offset public key size in GRPC output: expected 32, got {}",
                    grpc_output.sender_offset_public_key.len()
                )),
            ));
        };

        // Convert Metadata Signature
        let metadata_signature = grpc_output
            .metadata_signature
            .as_ref()
            .map(|sig| LightweightSignature {
                bytes: sig.u_a.clone(),
            })
            .unwrap_or_default();

        // Convert Covenant
        let covenant = LightweightCovenant {
            bytes: grpc_output.covenant.clone(),
        };

        // Convert Encrypted Data
        let encrypted_data =
            EncryptedData::from_bytes(&grpc_output.encrypted_data).unwrap_or_default();

        // Convert Minimum Value Promise
        let minimum_value_promise = MicroMinotari::new(grpc_output.minimum_value_promise);

        Ok(LightweightTransactionOutput {
            version: grpc_output.version as u8,
            features,
            commitment: commitment_bytes,
            proof,
            script,
            sender_offset_public_key,
            metadata_signature,
            covenant,
            encrypted_data,
            minimum_value_promise,
        })
    }

    /// Convert GRPC block to lightweight block info
    fn convert_block(
        grpc_block: &tari_rpc::HistoricalBlock,
    ) -> LightweightWalletResult<Option<BlockInfo>> {
        let block = match grpc_block.block.as_ref() {
            Some(block) => block,
            None => return Ok(None),
        };
        let header = match block.header.as_ref() {
            Some(header) => header,
            None => return Ok(None),
        };
        let body = match block.body.as_ref() {
            Some(body) => body,
            None => return Ok(None),
        };
        let outputs: LightweightWalletResult<Vec<_>> = body
            .outputs
            .iter()
            .map(Self::convert_transaction_output)
            .collect();
        let outputs = outputs?;

        // Extract inputs and kernels too
        let inputs = body
            .inputs
            .iter()
            .map(Self::convert_transaction_input)
            .collect();
        let kernels = body
            .kernels
            .iter()
            .map(Self::convert_transaction_kernel)
            .collect();

        Ok(Some(BlockInfo {
            height: header.height,
            hash: header.hash.clone(),
            timestamp: header.timestamp,
            outputs,
            inputs,
            kernels,
        }))
    }

    /// Convert GRPC transaction input to lightweight transaction input
    fn convert_transaction_input(
        grpc_input: &tari_rpc::TransactionInput,
    ) -> crate::data_structures::transaction_input::TransactionInput {
        // Convert commitment
        let mut commitment = [0u8; 32];
        if grpc_input.commitment.len() >= 32 {
            commitment.copy_from_slice(&grpc_input.commitment[..32]);
        }

        // Convert script (not script_signature for inputs)
        let mut script_signature = [0u8; 64];
        if !grpc_input.script.is_empty() && grpc_input.script.len() >= 64 {
            script_signature.copy_from_slice(&grpc_input.script[..64]);
        }

        // Convert sender offset public key (use features field as placeholder since the exact field name may vary)
        let sender_offset_public_key = CompressedPublicKey::new([0u8; 32]);

        // Convert input data to execution stack
        let input_data = crate::data_structures::transaction_input::LightweightExecutionStack {
            items: vec![grpc_input.input_data.clone()],
        };

        // Convert output hash (use hash field)
        let mut output_hash = [0u8; 32];
        if grpc_input.hash.len() >= 32 {
            output_hash.copy_from_slice(&grpc_input.hash[..32]);
        }

        // Convert metadata signature if available
        let output_metadata_signature = [0u8; 64];
        // Note: metadata_signature might not be available for inputs

        crate::data_structures::transaction_input::TransactionInput::new(
            grpc_input.version as u8,
            grpc_input
                .features
                .as_ref()
                .map(|f| f.output_type as u8)
                .unwrap_or(0),
            commitment,
            script_signature,
            sender_offset_public_key,
            grpc_input.covenant.clone(),
            input_data,
            output_hash,
            0, // output_features placeholder
            output_metadata_signature,
            0,                     // maturity placeholder
            MicroMinotari::new(0), // value placeholder
        )
    }

    /// Convert GRPC transaction kernel to lightweight transaction kernel
    fn convert_transaction_kernel(
        grpc_kernel: &tari_rpc::TransactionKernel,
    ) -> crate::data_structures::TransactionKernel {
        // Convert excess
        let mut excess = [0u8; 32];
        if grpc_kernel.excess.len() >= 32 {
            excess.copy_from_slice(&grpc_kernel.excess[..32]);
        }

        // Convert excess signature
        let mut excess_sig = [0u8; 64];
        if let Some(sig) = &grpc_kernel.excess_sig {
            if sig.public_nonce.len() >= 32 {
                excess_sig[..32].copy_from_slice(&sig.public_nonce[..32]);
            }
            if sig.signature.len() >= 32 {
                excess_sig[32..].copy_from_slice(&sig.signature[..32]);
            }
        }

        crate::data_structures::TransactionKernel {
            version: grpc_kernel.version as u8,
            features: grpc_kernel.features as u8,
            fee: MicroMinotari::new(grpc_kernel.fee),
            lock_height: grpc_kernel.lock_height,
            excess: CompressedPublicKey::new(excess),
            excess_sig,
            hash_type: 0, // placeholder since hash_type field doesn't exist
            burn_commitment: if !grpc_kernel.burn_commitment.is_empty() {
                let mut commitment = [0u8; 32];
                if grpc_kernel.burn_commitment.len() >= 32 {
                    commitment.copy_from_slice(&grpc_kernel.burn_commitment[..32]);
                }
                Some(CompressedCommitment::new(commitment))
            } else {
                None
            },
        }
    }

    /// Convert GRPC tip info to lightweight tip info
    fn convert_tip_info(grpc_tip: &tari_rpc::TipInfoResponse) -> TipInfo {
        let metadata = grpc_tip.metadata.as_ref();
        TipInfo {
            best_block_height: metadata.map(|m| m.best_block_height).unwrap_or(0),
            best_block_hash: metadata
                .map(|m| m.best_block_hash.clone())
                .unwrap_or_default(),
            accumulated_difficulty: metadata
                .map(|m| m.accumulated_difficulty.clone())
                .unwrap_or_default(),
            pruned_height: metadata.map(|m| m.pruned_height).unwrap_or(0),
            timestamp: metadata.map(|m| m.timestamp).unwrap_or(0),
        }
    }

    /// Create a scan config with wallet keys for block scanning
    pub fn create_scan_config_with_wallet_keys(
        &self,
        wallet: &Wallet,
        start_height: u64,
        end_height: Option<u64>,
    ) -> LightweightWalletResult<ScanConfig> {
        // Get the master key from the wallet for scanning
        let master_key_bytes = wallet.master_key_bytes();

        // Use the first 16 bytes of the master key as entropy (following Tari CipherSeed pattern)
        let mut entropy = [0u8; 16];
        entropy.copy_from_slice(&master_key_bytes[..16]);

        // Derive the proper view key using Tari's key derivation specification
        // This uses the "data encryption" branch seed which is the correct key for decrypting encrypted data
        let (view_key, _spend_key) =
            crate::key_management::key_derivation::derive_view_and_spend_keys_from_entropy(
                &entropy,
            )
            .map_err(LightweightWalletError::KeyManagementError)?;

        // Convert RistrettoSecretKey to PrivateKey
        let view_key_bytes = view_key.as_bytes();
        let mut view_key_array = [0u8; 32];
        view_key_array.copy_from_slice(view_key_bytes);
        let view_private_key = PrivateKey::new(view_key_array);

        let extraction_config = ExtractionConfig::with_private_key(view_private_key);

        Ok(ScanConfig {
            start_height,
            end_height,
            batch_size: 100,
            request_timeout: self.timeout,
            extraction_config,
        })
    }

    /// Create a scan config with just private keys for basic wallet scanning
    pub fn create_scan_config_with_keys(
        &self,
        view_key: PrivateKey,
        start_height: u64,
        end_height: Option<u64>,
    ) -> ScanConfig {
        let extraction_config = ExtractionConfig::with_private_key(view_key);

        ScanConfig {
            start_height,
            end_height,
            batch_size: 100,
            request_timeout: self.timeout,
            extraction_config,
        }
    }

    /// Scan for regular recoverable outputs using encrypted data decryption (GRPC version)
    fn scan_for_recoverable_output_grpc(
        output: &LightweightTransactionOutput,
        extraction_config: &ExtractionConfig,
    ) -> LightweightWalletResult<Option<LightweightWalletOutput>> {
        // Skip non-payment outputs for this scan type
        if !matches!(
            output.features().output_type,
            crate::data_structures::wallet_output::LightweightOutputType::Payment
        ) {
            return Ok(None);
        }

        // Use the standard extraction logic - the view key should be correctly derived already
        match extract_wallet_output(output, extraction_config) {
            Ok(wallet_output) => Ok(Some(wallet_output)),
            Err(_) => Ok(None), // Not a wallet output or decryption failed
        }
    }

    /// Scan for one-sided payments (GRPC version)
    fn scan_for_one_sided_payment_grpc(
        output: &LightweightTransactionOutput,
        extraction_config: &ExtractionConfig,
    ) -> LightweightWalletResult<Option<LightweightWalletOutput>> {
        // Skip non-payment outputs for this scan type
        if !matches!(
            output.features().output_type,
            crate::data_structures::wallet_output::LightweightOutputType::Payment
        ) {
            return Ok(None);
        }

        // For one-sided payments, use the same extraction logic
        // The difference is in how the outputs are created, not how they're decrypted
        match extract_wallet_output(output, extraction_config) {
            Ok(wallet_output) => Ok(Some(wallet_output)),
            Err(_) => Ok(None), // Not a wallet output or decryption failed
        }
    }

    /// Scan for coinbase outputs (GRPC version)
    fn scan_for_coinbase_output_grpc(
        output: &LightweightTransactionOutput,
    ) -> LightweightWalletResult<Option<LightweightWalletOutput>> {
        // Only handle coinbase outputs
        if !matches!(
            output.features().output_type,
            crate::data_structures::wallet_output::LightweightOutputType::Coinbase
        ) {
            return Ok(None);
        }

        // For coinbase outputs, the value is typically revealed in the minimum value promise
        if output.minimum_value_promise().as_u64() > 0 {
            let wallet_output = LightweightWalletOutput::new(
                output.version(),
                output.minimum_value_promise(),
                crate::data_structures::wallet_output::LightweightKeyId::Zero,
                output.features().clone(),
                output.script().clone(),
                crate::data_structures::wallet_output::LightweightExecutionStack::default(),
                crate::data_structures::wallet_output::LightweightKeyId::Zero,
                output.sender_offset_public_key().clone(),
                output.metadata_signature().clone(),
                0,
                output.covenant().clone(),
                output.encrypted_data().clone(),
                output.minimum_value_promise(),
                output.proof().cloned(),
                crate::data_structures::payment_id::PaymentId::Empty,
            );

            return Ok(Some(wallet_output));
        }

        Ok(None)
    }

    /// Get all outputs from a specific block
    pub async fn get_outputs_from_block(
        &mut self,
        block_height: u64,
    ) -> LightweightWalletResult<Vec<LightweightTransactionOutput>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "GRPC error: {e}"
                    )),
                )
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Stream error: {e}"
                )),
            )
        })? {
            if let Some(block_info) = Self::convert_block(&grpc_block)? {
                return Ok(block_info.outputs);
            }
        }

        Ok(Vec::new())
    }

    /// Get all inputs from a specific block
    pub async fn get_inputs_from_block(
        &mut self,
        block_height: u64,
    ) -> LightweightWalletResult<Vec<crate::data_structures::transaction_input::TransactionInput>>
    {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "GRPC error: {e}"
                    )),
                )
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Stream error: {e}"
                )),
            )
        })? {
            if let Some(block_info) = Self::convert_block(&grpc_block)? {
                return Ok(block_info.inputs);
            }
        }

        Ok(Vec::new())
    }

    /// Get all kernels from a specific block
    pub async fn get_kernels_from_block(
        &mut self,
        block_height: u64,
    ) -> LightweightWalletResult<Vec<crate::data_structures::TransactionKernel>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "GRPC error: {e}"
                    )),
                )
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Stream error: {e}"
                )),
            )
        })? {
            if let Some(block_info) = Self::convert_block(&grpc_block)? {
                return Ok(block_info.kernels);
            }
        }

        Ok(Vec::new())
    }

    /// Get complete block data including outputs, inputs, and kernels
    pub async fn get_complete_block_data(
        &mut self,
        block_height: u64,
    ) -> LightweightWalletResult<Option<crate::scanning::BlockInfo>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "GRPC error: {e}"
                    )),
                )
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Stream error: {e}"
                )),
            )
        })? {
            return Self::convert_block(&grpc_block);
        }

        Ok(None)
    }

    /// Scan a single block for wallet outputs using the provided entropy
    pub async fn scan_block(
        &mut self,
        block_height: u64,
        entropy: &[u8; 16],
    ) -> LightweightWalletResult<Vec<LightweightWalletOutput>> {
        let mut wallet_outputs = Vec::new();

        // Get all outputs from the block
        let outputs = self.get_outputs_from_block(block_height).await?;
        info!("Found {} outputs in block {}", outputs.len(), block_height);

        if outputs.is_empty() {
            return Ok(wallet_outputs);
        }

        // Create scanning logic with entropy
        let scanning_logic = DefaultScanningLogic::new(*entropy);

        // Process each output
        for output in outputs {
            // Try to extract wallet output using reference-compatible approach
            if let Some(wallet_output) = scanning_logic.extract_wallet_output(&output)? {
                info!(
                    "Found wallet output in block {}: value={}, payment_id={:?}",
                    block_height,
                    wallet_output.value().as_u64(),
                    wallet_output.payment_id()
                );
                wallet_outputs.push(wallet_output);
            }
        }

        info!(
            "Extracted {} wallet outputs from block {}",
            wallet_outputs.len(),
            block_height
        );
        Ok(wallet_outputs)
    }

    /// Get blocks by their heights in a batch
    pub async fn get_blocks_by_heights(
        &mut self,
        heights: Vec<u64>,
    ) -> LightweightWalletResult<Vec<BlockInfo>> {
        if heights.is_empty() {
            return Ok(Vec::new());
        }

        let request = tari_rpc::GetBlocksRequest { heights };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "GRPC error: {e}"
                    )),
                )
            })?
            .into_inner();

        let mut blocks = Vec::new();
        while let Some(grpc_block) = stream.message().await.map_err(|e| {
            LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC stream error: {e}"
                )),
            )
        })? {
            if let Some(block_info) = Self::convert_block(&grpc_block)? {
                blocks.push(block_info);
            }
        }

        Ok(blocks)
    }
}

#[cfg(feature = "grpc")]
#[async_trait(?Send)]
impl BlockchainScanner for GrpcBlockchainScanner {
    async fn scan_blocks(
        &mut self,
        config: ScanConfig,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
        debug!(
            "Starting GRPC block scan from height {} to {:?}",
            config.start_height, config.end_height
        );

        // Get tip info to determine end height
        let tip_info = self.get_tip_info().await?;
        let end_height = config.end_height.unwrap_or(tip_info.best_block_height);

        if config.start_height > end_height {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        let mut current_height = config.start_height;

        while current_height <= end_height {
            let batch_end = std::cmp::min(current_height + config.batch_size - 1, end_height);
            let heights: Vec<u64> = (current_height..=batch_end).collect();
            // Get blocks for this batch
            let request = tari_rpc::GetBlocksRequest { heights };

            let mut stream = self
                .client
                .clone()
                .get_blocks(Request::new(request))
                .await
                .map_err(|e| {
                    LightweightWalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(&format!(
                            "GRPC error: {e}"
                        )),
                    )
                })?
                .into_inner();

            let mut batch_results = Vec::new();
            while let Some(grpc_block) = stream.message().await.map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Stream error: {e}"
                    )),
                )
            })? {
                if let Some(block_info) = Self::convert_block(&grpc_block)? {
                    let mut wallet_outputs = Vec::new();

                    // Process outputs without debug output - let caller decide what to log
                    for output in &block_info.outputs {
                        // Use enhanced multi-strategy scanning instead of basic extraction
                        let mut found_output = false;

                        // Strategy 1: Regular recoverable outputs (encrypted data decryption)
                        if !found_output {
                            if let Some(wallet_output) = Self::scan_for_recoverable_output_grpc(
                                output,
                                &config.extraction_config,
                            )? {
                                wallet_outputs.push(wallet_output);
                                found_output = true;
                            }
                        }

                        // Strategy 2: One-sided payments (different detection logic)
                        if !found_output {
                            if let Some(wallet_output) = Self::scan_for_one_sided_payment_grpc(
                                output,
                                &config.extraction_config,
                            )? {
                                wallet_outputs.push(wallet_output);
                                found_output = true;
                            }
                        }

                        // Strategy 3: Coinbase outputs (special handling)
                        if !found_output {
                            if let Some(wallet_output) =
                                Self::scan_for_coinbase_output_grpc(output)?
                            {
                                wallet_outputs.push(wallet_output);
                                // found_output = true;
                            }
                        }
                    }

                    batch_results.push(BlockScanResult {
                        height: block_info.height,
                        block_hash: block_info.hash,
                        outputs: block_info.outputs,
                        wallet_outputs,
                        mined_timestamp: block_info.timestamp,
                    });
                }
            }

            results.extend(batch_results);
            current_height = batch_end + 1;
        }

        debug!(
            "GRPC scan completed, found {} blocks with wallet outputs",
            results.len()
        );
        Ok(results)
    }

    async fn get_tip_info(&mut self) -> LightweightWalletResult<TipInfo> {
        let request = Request::new(tari_rpc::Empty {});

        let response = self
            .client
            .clone()
            .get_tip_info(request)
            .await
            .map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "GRPC error: {e}"
                    )),
                )
            })?;

        let tip_info = response.into_inner();
        Ok(Self::convert_tip_info(&tip_info))
    }

    async fn search_utxos(
        &mut self,
        commitments: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
        let request = tari_rpc::SearchUtxosRequest { commitments };

        let mut stream = self
            .client
            .clone()
            .search_utxos(Request::new(request))
            .await
            .map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "GRPC error: {e}"
                    )),
                )
            })?
            .into_inner();

        let mut results = Vec::new();
        while let Some(grpc_block) = stream.message().await.map_err(|e| {
            LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Stream error: {e}"
                )),
            )
        })? {
            if let Some(block_info) = Self::convert_block(&grpc_block)? {
                let mut wallet_outputs = Vec::new();
                for output in &block_info.outputs {
                    // Use default extraction config with no keys for commitment search
                    // This method is typically used for searching specific commitments
                    // where wallet ownership is already known
                    match extract_wallet_output(output, &ExtractionConfig::default()) {
                        Ok(wallet_output) => wallet_outputs.push(wallet_output),
                        Err(e) => {
                            debug!(
                                "Failed to extract wallet output during commitment search: {}",
                                e
                            );
                        }
                    }
                }
                results.push(BlockScanResult {
                    height: block_info.height,
                    block_hash: block_info.hash,
                    outputs: block_info.outputs,
                    wallet_outputs,
                    mined_timestamp: block_info.timestamp,
                });
            }
        }

        Ok(results)
    }

    async fn fetch_utxos(
        &mut self,
        hashes: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<Vec<LightweightTransactionOutput>> {
        let request = tari_rpc::FetchMatchingUtxosRequest { hashes };

        let mut stream = self
            .client
            .clone()
            .fetch_matching_utxos(Request::new(request))
            .await
            .map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "GRPC error: {e}"
                    )),
                )
            })?
            .into_inner();

        let mut results = Vec::new();
        while let Some(response) = stream.message().await.map_err(|e| {
            LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Stream error: {e}"
                )),
            )
        })? {
            if let Some(output) = response.output {
                results.push(Self::convert_transaction_output(&output)?);
            }
        }

        Ok(results)
    }

    async fn get_blocks_by_heights(
        &mut self,
        heights: Vec<u64>,
    ) -> LightweightWalletResult<Vec<BlockInfo>> {
        if heights.is_empty() {
            return Ok(Vec::new());
        }

        let request = tari_rpc::GetBlocksRequest { heights };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "GRPC error: {e}"
                    )),
                )
            })?
            .into_inner();

        let mut blocks = Vec::new();
        while let Some(grpc_block) = stream.message().await.map_err(|e| {
            LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC stream error: {e}"
                )),
            )
        })? {
            if let Some(block_info) = Self::convert_block(&grpc_block)? {
                blocks.push(block_info);
            }
        }

        Ok(blocks)
    }

    async fn get_block_by_height(
        &mut self,
        height: u64,
    ) -> LightweightWalletResult<Option<BlockInfo>> {
        let blocks = self.get_blocks_by_heights(vec![height]).await?;
        Ok(blocks.into_iter().next())
    }
}

#[cfg(feature = "grpc")]
impl std::fmt::Debug for GrpcBlockchainScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcBlockchainScanner")
            .field("base_url", &self.base_url)
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[cfg(feature = "grpc")]
impl Clone for GrpcBlockchainScanner {
    fn clone(&self) -> Self {
        // Note: This creates a new connection, which is expensive
        // In practice, you might want to use connection pooling
        panic!("GrpcBlockchainScanner cannot be cloned - create a new instance instead");
    }
}

/// Builder for creating GRPC blockchain scanners
#[cfg(feature = "grpc")]
pub struct GrpcScannerBuilder {
    base_url: Option<String>,
    timeout: Option<Duration>,
}

#[cfg(feature = "grpc")]
impl GrpcScannerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            base_url: None,
            timeout: None,
        }
    }

    /// Set the base URL for the GRPC connection
    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = Some(base_url);
        self
    }

    /// Set the timeout for GRPC operations
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Build the GRPC scanner
    pub async fn build(self) -> LightweightWalletResult<GrpcBlockchainScanner> {
        let base_url = self.base_url.ok_or_else(|| {
            LightweightWalletError::ConfigurationError("Base URL not specified".to_string())
        })?;

        match self.timeout {
            Some(timeout) => GrpcBlockchainScanner::with_timeout(base_url, timeout).await,
            None => GrpcBlockchainScanner::new(base_url).await,
        }
    }
}

#[cfg(feature = "grpc")]
impl Default for GrpcScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// Placeholder module for when GRPC feature is not enabled
#[cfg(not(feature = "grpc"))]
pub struct GrpcBlockchainScanner;

#[cfg(not(feature = "grpc"))]
impl GrpcBlockchainScanner {
    pub async fn new(_base_url: String) -> crate::errors::LightweightWalletResult<Self> {
        Err(
            crate::errors::LightweightWalletError::OperationNotSupported(
                "GRPC feature not enabled".to_string(),
            ),
        )
    }
}

#[cfg(not(feature = "grpc"))]
pub struct GrpcScannerBuilder;

#[cfg(not(feature = "grpc"))]
impl GrpcScannerBuilder {
    pub fn new() -> Self {
        Self
    }

    pub async fn build(self) -> crate::errors::LightweightWalletResult<GrpcBlockchainScanner> {
        Err(
            crate::errors::LightweightWalletError::OperationNotSupported(
                "GRPC feature not enabled".to_string(),
            ),
        )
    }
}

#[cfg(feature = "grpc")]
#[async_trait(?Send)]
impl WalletScanner for GrpcBlockchainScanner {
    async fn scan_wallet(
        &mut self,
        config: WalletScanConfig,
    ) -> LightweightWalletResult<WalletScanResult> {
        self.scan_wallet_with_progress(config, None).await
    }

    async fn scan_wallet_with_progress(
        &mut self,
        config: WalletScanConfig,
        progress_callback: Option<&ProgressCallback>,
    ) -> LightweightWalletResult<WalletScanResult> {
        // Validate that we have key management set up
        if config.key_manager.is_none() && config.key_store.is_none() {
            return Err(LightweightWalletError::ConfigurationError(
                "No key manager or key store provided for wallet scanning".to_string(),
            ));
        }

        // Use the default scanning logic with proper wallet key integration
        DefaultScanningLogic::scan_wallet_with_progress(self, config, progress_callback).await
    }

    fn blockchain_scanner(&mut self) -> &mut dyn BlockchainScanner {
        self
    }
}

#[cfg(test)]
#[cfg(not(feature = "grpc"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_grpc_feature_disabled() {
        let result = GrpcBlockchainScanner::new("http://127.0.0.1:18142".to_string()).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::errors::LightweightWalletError::OperationNotSupported(_)
        ));
    }

    #[tokio::test]
    async fn test_grpc_builder_feature_disabled() {
        let builder = GrpcScannerBuilder::new();
        let result = builder.build().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::errors::LightweightWalletError::OperationNotSupported(_)
        ));
    }
}
