//! HTTP-based blockchain scanner implementation
//! 
//! This module provides an HTTP implementation of the BlockchainScanner trait
//! that connects to a Tari base node via HTTP API to scan for wallet outputs.
//! 
//! ## Wallet Key Integration
//! 
//! The HTTP scanner supports wallet key integration for identifying outputs that belong
//! to a specific wallet. To use wallet functionality:
//! 
//! ```rust,no_run
//! use lightweight_wallet_libs::scanning::{HttpBlockchainScanner, ScanConfig, BlockchainScanner};
//! use lightweight_wallet_libs::wallet::Wallet;
//! 
//! async fn scan_with_wallet() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut scanner = HttpBlockchainScanner::new("http://127.0.0.1:18142".to_string()).await?;
//!     let wallet = Wallet::generate_new_with_seed_phrase(None)?;
//!     
//!     // Create scan config with wallet keys
//!     let config = scanner.create_scan_config_with_wallet_keys(&wallet, 0, None)?;
//!     
//!     // Scan for blocks with wallet key integration
//!     let results = scanner.scan_blocks(config).await?;
//!     println!("Found {} blocks with wallet outputs", results.len());
//!     
//!     Ok(())
//! }
//! ```

// Native targets use reqwest
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
use std::time::Duration;
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
use reqwest::Client;

// WASM targets use web-sys
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use std::time::Duration;
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use web_sys::{window, Request, RequestInit, RequestMode, Response};

// WASM-compatible constant Duration (30 seconds)
#[cfg(all(feature = "http", target_arch = "wasm32"))]
const WASM_DEFAULT_TIMEOUT: Duration = Duration::new(30, 0);

#[cfg(all(feature = "http", target_arch = "wasm32"))]
use wasm_bindgen::prelude::*;
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use wasm_bindgen_futures::JsFuture;
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use serde_wasm_bindgen;

#[cfg(feature = "http")]
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
#[cfg(all(feature = "http", feature = "tracing"))]
use tracing::debug;
#[cfg(feature = "http")]
use tari_utilities::ByteArray;

use crate::{
    data_structures::{
        transaction_output::LightweightTransactionOutput,
        wallet_output::{
            LightweightWalletOutput, LightweightOutputFeatures, LightweightRangeProof,
            LightweightScript, LightweightSignature, LightweightCovenant
        },
        types::{CompressedCommitment, CompressedPublicKey, MicroMinotari, PrivateKey},
        encrypted_data::EncryptedData,
        transaction_input::TransactionInput,
        LightweightOutputType,
        LightweightRangeProofType,
    },
    errors::{LightweightWalletError, LightweightWalletResult},
    extraction::{extract_wallet_output, ExtractionConfig},
    scanning::{BlockInfo, BlockScanResult, BlockchainScanner, ScanConfig, TipInfo, WalletScanner, WalletScanConfig, WalletScanResult, ProgressCallback, DefaultScanningLogic},
    wallet::Wallet,
};

/// HTTP API block response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlockResponse {
    pub blocks: Vec<HttpBlockData>,
    pub has_next_page: bool,
}

/// HTTP API block data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlockData {
    pub header_hash: Vec<u8>,
    pub height: u64,
    pub outputs: Vec<HttpOutputData>,
    /// Inputs are arrays of 32-byte hashes (commitments) that have been spent
    #[serde(default)]
    pub inputs: Option<Vec<Vec<u8>>>,
    pub mined_timestamp: u64,
}

/// HTTP API output data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpOutputData {
    pub output_hash: Vec<u8>,
    pub commitment: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub sender_offset_public_key: Vec<u8>,
    pub features: Option<HttpOutputFeatures>,
    pub script: Option<Vec<u8>>,
    pub metadata_signature: Option<Vec<u8>>,
    pub covenant: Option<Vec<u8>>,
    pub minimum_value_promise: Option<u64>,
    pub range_proof: Option<Vec<u8>>,
}

/// HTTP API output features structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpOutputFeatures {
    pub output_type: u8,
    pub maturity: u64,
    pub range_proof_type: u8,
}

/// HTTP API tip info response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTipInfoResponse {
    pub metadata: HttpChainMetadata,
}

/// HTTP API chain metadata structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpChainMetadata {
    pub best_block_height: u64,
    pub best_block_hash: Vec<u8>,
    pub accumulated_difficulty: Vec<u8>,
    pub pruned_height: u64,
    pub timestamp: u64,
}

/// HTTP API block header response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeaderResponse {
    pub hash: Vec<u8>,
    pub height: u64,
    pub timestamp: u64,
}

/// HTTP client for connecting to Tari base node
#[cfg(feature = "http")]
pub struct HttpBlockchainScanner {
    /// HTTP client for making requests (native targets)
    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    client: Client,
    /// Base URL for the HTTP API
    base_url: String,
    /// Request timeout (native targets only)
    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    timeout: Duration,
}

impl HttpBlockchainScanner {
    /// Create a new HTTP scanner with the given base URL
    pub async fn new(base_url: String) -> LightweightWalletResult<Self> {
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let timeout = Duration::from_secs(30);
            let client = Client::builder()
                .timeout(timeout)
                .build()
                .map_err(|e| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("Failed to create HTTP client: {}", e))
                ))?;

            // Test the connection
            let test_url = format!("{}/get_tip_info", base_url);
            let response = client.get(&test_url).send().await;
            if response.is_err() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("Failed to connect to {}", base_url))
                ));
            }

            Ok(Self {
                client,
                base_url,
                timeout,
            })
        }
        
        #[cfg(all(feature = "http", target_arch = "wasm32"))]
        {
            // For WASM, test the connection with a simple GET request
            let test_url = format!("{}/get_tip_info", base_url);
            
            let opts = RequestInit::new();
            opts.set_method("GET");
            opts.set_mode(RequestMode::Cors);
            
            let request = Request::new_with_str_and_init(&test_url, &opts)?;
            
            let window = window().ok_or_else(|| LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed("No window object available")
            ))?;
            
            let resp_value = JsFuture::from(window.fetch_with_request(&request)).await
                .map_err(|_| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("Failed to connect to {}", base_url))
                ))?;
            
            let _resp: Response = resp_value.dyn_into()
                .map_err(|_| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed("Invalid response type")
                ))?;

            Ok(Self {
                base_url,
            })
        }
    }

    /// Create a new HTTP scanner with custom timeout (native only)
    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    pub async fn with_timeout(base_url: String, timeout: Duration) -> LightweightWalletResult<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!("Failed to create HTTP client: {}", e))
            ))?;

        // Test the connection
        let test_url = format!("{}/get_tip_info", base_url);
        let response = client.get(&test_url).send().await;
        if response.is_err() {
            return Err(LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!("Failed to connect to {}", base_url))
            ));
        }

        Ok(Self {
            client,
            base_url,
            timeout,
        })
    }
    
    /// Create a new HTTP scanner with custom timeout (WASM - timeout ignored)
    #[cfg(all(feature = "http", target_arch = "wasm32"))]
    pub async fn with_timeout(base_url: String, _timeout: Duration) -> LightweightWalletResult<Self> {
        // WASM doesn't support timeouts in the same way, so we ignore the timeout parameter
        Self::new(base_url).await
    }

    /// Get block header by height - following the JavaScript API pattern
    async fn get_header_by_height(&self, height: u64) -> LightweightWalletResult<HttpHeaderResponse> {
        let url = format!("{}/get_header_by_height?height={}", self.base_url, height);

        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let response = self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("HTTP request failed: {}", e))
                ))?;

            if !response.status().is_success() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("HTTP error: {}", response.status()))
                ));
            }

            let header_response: HttpHeaderResponse = response.json().await
                .map_err(|e| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("Failed to parse response: {}", e))
                ))?;

            Ok(header_response)
        }

        #[cfg(all(feature = "http", target_arch = "wasm32"))]
        {
            let opts = RequestInit::new();
            opts.set_method("GET");
            opts.set_mode(RequestMode::Cors);
            
            let request = Request::new_with_str_and_init(&url, &opts)?;
            
            let window = window().ok_or_else(|| LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed("No window object available")
            ))?;
            
            let resp_value = JsFuture::from(window.fetch_with_request(&request)).await
                .map_err(|_| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed("HTTP request failed")
                ))?;
            
            let response: Response = resp_value.dyn_into()
                .map_err(|_| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed("Invalid response type")
                ))?;

            if !response.ok() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("HTTP error: {}", response.status()))
                ));
            }

            let json_promise = response.json()
                .map_err(|_| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed("Failed to get JSON response")
                ))?;
                
            let json_value = JsFuture::from(json_promise).await
                .map_err(|_| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed("Failed to parse JSON response")
                ))?;

            let header_response: HttpHeaderResponse = serde_wasm_bindgen::from_value(json_value)
                .map_err(|e| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("Failed to deserialize response: {}", e))
                ))?;

            Ok(header_response)
        }
    }

    /// Sync UTXOs by block range using hash - following the JavaScript API pattern
    async fn sync_utxos_by_block(&self, start_header_hash: String, end_header_hash: String, limit: u64, page: u64) -> LightweightWalletResult<HttpBlockResponse> {
        let url = format!("{}/sync_utxos_by_block?start_header_hash={}&end_header_hash={}&limit={}&page={}", 
                         self.base_url, start_header_hash, end_header_hash, limit, page);

        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let response = self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("HTTP request failed: {}", e))
                ))?;

            if !response.status().is_success() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("HTTP error: {}", response.status()))
                ));
            }

            let http_response: HttpBlockResponse = response.json().await
                .map_err(|e| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("Failed to parse response: {}", e))
                ))?;

            Ok(http_response)
        }

        #[cfg(all(feature = "http", target_arch = "wasm32"))]
        {
            let opts = RequestInit::new();
            opts.set_method("GET");
            opts.set_mode(RequestMode::Cors);
            
            let request = Request::new_with_str_and_init(&url, &opts)?;
            
            let window = window().ok_or_else(|| LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed("No window object available")
            ))?;
            
            let resp_value = JsFuture::from(window.fetch_with_request(&request)).await
                .map_err(|_| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed("HTTP request failed")
                ))?;
            
            let response: Response = resp_value.dyn_into()
                .map_err(|_| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed("Invalid response type")
                ))?;

            if !response.ok() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("HTTP error: {}", response.status()))
                ));
            }

            let json_promise = response.json()
                .map_err(|_| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed("Failed to get JSON response")
                ))?;
                
            let json_value = JsFuture::from(json_promise).await
                .map_err(|_| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed("Failed to parse JSON response")
                ))?;

            let http_response: HttpBlockResponse = serde_wasm_bindgen::from_value(json_value)
                .map_err(|e| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("Failed to deserialize response: {}", e))
                ))?;

            Ok(http_response)
        }
    }

    /// Fetch blocks by heights using the correct API flow - get headers first, then sync by hash range
    async fn fetch_blocks_by_heights(&self, heights: Vec<u64>) -> LightweightWalletResult<HttpBlockResponse> {
        if heights.is_empty() {
            return Ok(HttpBlockResponse {
                blocks: Vec::new(),
                has_next_page: false,
            });
        }

        let start_height = *heights.iter().min().unwrap();
        let end_height = *heights.iter().max().unwrap();

        // Get start and end headers
        let start_header = self.get_header_by_height(start_height).await?;
        let end_header = self.get_header_by_height(end_height).await?;

        // Convert hashes to hex strings
        let start_hash = hex::encode(&start_header.hash);
        let end_hash = hex::encode(&end_header.hash);

        // Use sync_utxos_by_block with hash range
        let limit = heights.len() as u64;
        let mut all_blocks = Vec::new();
        let mut page = 0;
        let mut has_next_page = true;
        const MAX_PAGES: u64 = 1000; // Safety limit to prevent infinite loops

        while has_next_page && page < MAX_PAGES {
            let response = self.sync_utxos_by_block(start_hash.clone(), end_hash.clone(), limit, page).await?;
            all_blocks.extend(response.blocks);
            has_next_page = response.has_next_page;
            page += 1;
        }

        // Log if we hit the maximum page limit
        if page >= MAX_PAGES && has_next_page {
            #[cfg(target_arch = "wasm32")]
            {
                // For WASM, we can't use console_log! directly here since it's defined in wasm.rs
                // Instead, we'll let the calling code handle this error case
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                eprintln!("Warning: Hit maximum page limit ({}) while fetching blocks, some blocks may be missing", MAX_PAGES);
            }
        }

        // Filter blocks to only include requested heights
        let requested_heights: std::collections::HashSet<u64> = heights.into_iter().collect();
        let filtered_blocks: Vec<HttpBlockData> = all_blocks
            .into_iter()
            .filter(|block| requested_heights.contains(&block.height))
            .collect();

        Ok(HttpBlockResponse {
            blocks: filtered_blocks,
            has_next_page: false,
        })
    }

    /// Fetch specific block heights efficiently without using range API
    /// This method fetches only the requested heights to avoid unnecessary data transfer
    async fn fetch_specific_heights_directly(&self, heights: Vec<u64>) -> LightweightWalletResult<HttpBlockResponse> {
        if heights.is_empty() {
            return Ok(HttpBlockResponse {
                blocks: Vec::new(),
                has_next_page: false,
            });
        }

        // For specific heights, fetch each block individually to avoid pagination overhead
        // This is much more efficient than fetching entire ranges when only specific heights are needed
        let mut all_blocks = Vec::new();

        // Process heights in small batches to avoid overwhelming the API
        const DIRECT_FETCH_BATCH_SIZE: usize = 10;
        for height_batch in heights.chunks(DIRECT_FETCH_BATCH_SIZE) {
            for &height in height_batch {
                // Get the header first to get the block hash
                let header = self.get_header_by_height(height).await?;
                let block_hash = hex::encode(&header.hash);
                
                // Fetch the specific block using a single-block range
                let response = self.sync_utxos_by_block(
                    block_hash.clone(), 
                    block_hash, // Same start and end hash for single block
                    1, // Limit to 1 block
                    0  // Page 0
                ).await?;
                
                // Add any blocks returned (should be just the one we requested)
                for block in response.blocks {
                    if block.height == height {
                        all_blocks.push(block);
                        break; // Found our block, move to next
                    }
                }
            }
        }

        Ok(HttpBlockResponse {
            blocks: all_blocks,
            has_next_page: false,
        })
    }

    /// Convert HTTP output data to LightweightTransactionOutput
    fn convert_http_output_to_lightweight(http_output: &HttpOutputData) -> LightweightWalletResult<LightweightTransactionOutput> {
        // Parse commitment
        if http_output.commitment.len() != 32 {
            return Err(LightweightWalletError::ConversionError(
                "Invalid commitment length, expected 32 bytes".to_string()
            ));
        }
        let commitment = CompressedCommitment::new(
            http_output.commitment.clone().try_into()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to convert commitment".to_string()))?
        );

        // Parse sender offset public key
        if http_output.sender_offset_public_key.len() != 32 {
            return Err(LightweightWalletError::ConversionError(
                "Invalid sender offset public key length, expected 32 bytes".to_string()
            ));
        }
        let sender_offset_public_key = CompressedPublicKey::new(
            http_output.sender_offset_public_key.clone().try_into()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to convert sender offset public key".to_string()))?
        );

        // Parse encrypted data
        let encrypted_data = EncryptedData::from_bytes(&http_output.encrypted_data)
            .map_err(|e| LightweightWalletError::ConversionError(format!("Invalid encrypted data: {}", e)))?;

        // Convert features
        let features = http_output.features.as_ref().map(|f| {
            LightweightOutputFeatures {
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
            }
        }).unwrap_or_default();

        // Convert range proof
        let proof = http_output.range_proof.as_ref().map(|rp| LightweightRangeProof { bytes: rp.clone() });

        // Convert script
        let script = LightweightScript { 
            bytes: http_output.script.clone().unwrap_or_default() 
        };

        // Convert metadata signature
        let metadata_signature = http_output.metadata_signature.as_ref()
            .map(|sig| LightweightSignature { bytes: sig.clone() })
            .unwrap_or_default();

        // Convert covenant
        let covenant = LightweightCovenant { 
            bytes: http_output.covenant.clone().unwrap_or_default() 
        };

        // Convert minimum value promise
        let minimum_value_promise = MicroMinotari::new(http_output.minimum_value_promise.unwrap_or(0));

        Ok(LightweightTransactionOutput::new_current_version(
            features,
            commitment,
            proof,
            script,
            sender_offset_public_key,
            metadata_signature,
            covenant,
            encrypted_data,
            minimum_value_promise,
        ))
    }

    /// Convert HTTP input data to TransactionInput
    fn convert_http_input_to_lightweight(output_hash_bytes: &[u8]) -> LightweightWalletResult<TransactionInput> {
        // Parse output hash
        if output_hash_bytes.len() != 32 {
            return Err(LightweightWalletError::ConversionError(
                "Invalid output hash length, expected 32 bytes".to_string()
            ));
        }
        let mut output_hash = [0u8; 32];
        output_hash.copy_from_slice(output_hash_bytes);

        // Create minimal TransactionInput with the output hash
        Ok(TransactionInput::new(
            1, // version
            0, // features (default)
            [0u8; 32], // commitment (not available from HTTP API, use placeholder)
            [0u8; 64], // script_signature (not available)
            CompressedPublicKey::default(), // sender_offset_public_key (not available)
            Vec::new(), // covenant (not available)
            crate::data_structures::transaction_input::LightweightExecutionStack::new(), // input_data (not available)
            output_hash, // output_hash (this is the actual data from HTTP API)
            0, // output_features (not available)
            [0u8; 64], // output_metadata_signature (not available)
            0, // maturity (not available)
            MicroMinotari::new(0), // value (not available)
        ))
    }

    /// Convert HTTP block data to BlockInfo
    fn convert_http_block_to_block_info(http_block: &HttpBlockData) -> LightweightWalletResult<BlockInfo> {
        let outputs = http_block.outputs.iter()
            .map(Self::convert_http_output_to_lightweight)
            .collect::<LightweightWalletResult<Vec<_>>>()?;

        // Handle simplified inputs structure
        let inputs = http_block.inputs.as_ref()
            .map(|input_hashes| input_hashes.iter()
                .map(|hash_bytes| Self::convert_http_input_to_lightweight(hash_bytes))
                .collect::<LightweightWalletResult<Vec<_>>>())
            .transpose()?
            .unwrap_or_default();

        Ok(BlockInfo {
            height: http_block.height,
            hash: http_block.header_hash.clone(),
            timestamp: http_block.mined_timestamp,
            outputs,
            inputs,
            kernels: Vec::new(), // HTTP API doesn't provide kernels in this format
        })
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
        let (view_key, _spend_key) = crate::key_management::key_derivation::derive_view_and_spend_keys_from_entropy(&entropy)
            .map_err(|e| LightweightWalletError::KeyManagementError(e))?;
            
        // Convert RistrettoSecretKey to PrivateKey
        let view_key_bytes = view_key.as_bytes();
        let mut view_key_array = [0u8; 32];
        view_key_array.copy_from_slice(view_key_bytes);
        let view_private_key = PrivateKey::new(view_key_array);
        
        let extraction_config = ExtractionConfig::with_private_key(view_private_key);

        Ok(ScanConfig {
            start_height,
            end_height,
            specific_heights: None,
            batch_size: 100,
            #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
            request_timeout: self.timeout,
            #[cfg(all(feature = "http", target_arch = "wasm32"))]
            request_timeout: WASM_DEFAULT_TIMEOUT,
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
            specific_heights: None,
            batch_size: 100,
            #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
            request_timeout: self.timeout,
            #[cfg(all(feature = "http", target_arch = "wasm32"))]
            request_timeout: WASM_DEFAULT_TIMEOUT,
            extraction_config,
        }
    }

    /// Scan for regular recoverable outputs using encrypted data decryption
    fn scan_for_recoverable_output(
        output: &LightweightTransactionOutput,
        extraction_config: &ExtractionConfig,
    ) -> LightweightWalletResult<Option<LightweightWalletOutput>> {
        // Skip non-payment outputs for this scan type
        if !matches!(output.features().output_type, LightweightOutputType::Payment) {
            return Ok(None);
        }
        
        // Use the standard extraction logic
        match extract_wallet_output(output, extraction_config) {
            Ok(wallet_output) => Ok(Some(wallet_output)),
            Err(_) => Ok(None), // Not a wallet output or decryption failed
        }
    }

    /// Scan for one-sided payments
    fn scan_for_one_sided_payment(
        output: &LightweightTransactionOutput,
        extraction_config: &ExtractionConfig,
    ) -> LightweightWalletResult<Option<LightweightWalletOutput>> {
        // Skip non-payment outputs for this scan type
        if !matches!(output.features().output_type, LightweightOutputType::Payment) {
            return Ok(None);
        }
        
        // Use the same extraction logic - the difference is in creation, not detection
        match extract_wallet_output(output, extraction_config) {
            Ok(wallet_output) => Ok(Some(wallet_output)),
            Err(_) => Ok(None),
        }
    }

    /// Scan for coinbase outputs
    fn scan_for_coinbase_output(
        output: &LightweightTransactionOutput,
    ) -> LightweightWalletResult<Option<LightweightWalletOutput>> {
        // Only handle coinbase outputs
        if !matches!(output.features().output_type, LightweightOutputType::Coinbase) {
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

    /// Helper method to process HTTP response into block scan results
    async fn process_http_response_to_block_scan_results(&self, http_response: HttpBlockResponse) -> LightweightWalletResult<Vec<BlockScanResult>> {
        let mut results = Vec::new();
        for http_block in http_response.blocks {
            let block_info = Self::convert_http_block_to_block_info(&http_block)?;
            let mut wallet_outputs = Vec::new();
            
            for output in &block_info.outputs {
                // Use default extraction for commitment search
                match extract_wallet_output(output, &ExtractionConfig::default()) {
                    Ok(wallet_output) => wallet_outputs.push(wallet_output),
                    Err(_e) => {
                        #[cfg(feature = "tracing")]
                        debug!("Failed to extract wallet output during commitment search: {}", _e);
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

        Ok(results)
    }

    async fn get_blocks_by_heights(
        &mut self,
        heights: Vec<u64>,
    ) -> LightweightWalletResult<Vec<BlockInfo>> {
        if heights.is_empty() {
            return Ok(Vec::new());
        }
        
        let http_response = self.fetch_blocks_by_heights(heights).await?;
        let mut blocks = Vec::new();
        for http_block in http_response.blocks {
            let block_info = Self::convert_http_block_to_block_info(&http_block)?;
            blocks.push(block_info);
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

#[cfg(feature = "http")]
#[async_trait(?Send)]
impl BlockchainScanner for HttpBlockchainScanner {
    async fn scan_blocks(
        &mut self,
        config: ScanConfig,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
        #[cfg(feature = "tracing")]
        debug!("Starting HTTP block scan from height {} to {:?}", config.start_height, config.end_height);
        
        let mut results = Vec::new();

        // Handle specific heights differently - no pagination required
        if config.is_scanning_specific_heights() {
            let specific_heights = config.specific_heights.as_ref().unwrap();
            #[cfg(feature = "tracing")]
            debug!("Scanning {} specific heights: {:?}", specific_heights.len(), specific_heights);
            
            // Use direct fetching for specific heights - more efficient, no pagination
            let http_response = self.fetch_specific_heights_directly(specific_heights.clone()).await?;
            
            for http_block in http_response.blocks {
                let block_info = Self::convert_http_block_to_block_info(&http_block)?;
                let mut wallet_outputs = Vec::new();
                
                for output in &block_info.outputs {
                    let mut found_output = false;
                    
                    // Strategy 1: Regular recoverable outputs
                    if !found_output {
                        if let Some(wallet_output) = Self::scan_for_recoverable_output(output, &config.extraction_config)? {
                            wallet_outputs.push(wallet_output);
                            found_output = true;
                        }
                    }
                    
                    // Strategy 2: One-sided payments
                    if !found_output {
                        if let Some(wallet_output) = Self::scan_for_one_sided_payment(output, &config.extraction_config)? {
                            wallet_outputs.push(wallet_output);
                            found_output = true;
                        }
                    }
                    
                    // Strategy 3: Coinbase outputs
                    if !found_output {
                        if let Some(wallet_output) = Self::scan_for_coinbase_output(output)? {
                            wallet_outputs.push(wallet_output);
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
            
            #[cfg(feature = "tracing")]
            debug!("HTTP scan completed for specific heights, found {} blocks with wallet outputs", results.len());
            return Ok(results);
        }

        // Handle range scanning with pagination (existing logic)
        let tip_info = self.get_tip_info().await?;
        let end_height = config.end_height.unwrap_or(tip_info.best_block_height);

        if config.start_height > end_height {
            return Ok(Vec::new());
        }

        let mut current_height = config.start_height;

        while current_height <= end_height {
            let batch_end = std::cmp::min(current_height + config.batch_size - 1, end_height);
            let heights: Vec<u64> = (current_height..=batch_end).collect();

            // Fetch blocks for this batch using the range-based method
            let http_response = self.fetch_blocks_by_heights(heights).await?;

            for http_block in http_response.blocks {
                let block_info = Self::convert_http_block_to_block_info(&http_block)?;
                let mut wallet_outputs = Vec::new();
                
                for output in &block_info.outputs {
                    let mut found_output = false;
                    
                    // Strategy 1: Regular recoverable outputs
                    if !found_output {
                        if let Some(wallet_output) = Self::scan_for_recoverable_output(output, &config.extraction_config)? {
                            wallet_outputs.push(wallet_output);
                            found_output = true;
                        }
                    }
                    
                    // Strategy 2: One-sided payments
                    if !found_output {
                        if let Some(wallet_output) = Self::scan_for_one_sided_payment(output, &config.extraction_config)? {
                            wallet_outputs.push(wallet_output);
                            found_output = true;
                        }
                    }
                    
                    // Strategy 3: Coinbase outputs
                    if !found_output {
                        if let Some(wallet_output) = Self::scan_for_coinbase_output(output)? {
                            wallet_outputs.push(wallet_output);
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

            current_height = batch_end + 1;
        }

        #[cfg(feature = "tracing")]
        debug!("HTTP scan completed, found {} blocks with wallet outputs", results.len());
        Ok(results)
    }

    async fn get_tip_info(&mut self) -> LightweightWalletResult<TipInfo> {
        let url = format!("{}/get_tip_info", self.base_url);
        
        // Native implementation using reqwest
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let response = self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("HTTP request failed: {}", e))
                ))?;

            if !response.status().is_success() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("HTTP error: {}", response.status()))
                ));
            }

            let tip_response: HttpTipInfoResponse = response.json().await
                .map_err(|e| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("Failed to parse response: {}", e))
                ))?;

            Ok(TipInfo {
                best_block_height: tip_response.metadata.best_block_height,
                best_block_hash: tip_response.metadata.best_block_hash,
                accumulated_difficulty: tip_response.metadata.accumulated_difficulty,
                pruned_height: tip_response.metadata.pruned_height,
                timestamp: tip_response.metadata.timestamp,
            })
        }

        // WASM implementation using web-sys
        #[cfg(all(feature = "http", target_arch = "wasm32"))]
        {
            let opts = RequestInit::new();
            opts.set_method("GET");
            opts.set_mode(RequestMode::Cors);
            
            let request = Request::new_with_str_and_init(&url, &opts)?;
            
            let window = window().ok_or_else(|| LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed("No window object available")
            ))?;
            
            let resp_value = JsFuture::from(window.fetch_with_request(&request)).await
                .map_err(|_| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed("HTTP request failed")
                ))?;
            
            let response: Response = resp_value.dyn_into()
                .map_err(|_| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed("Invalid response type")
                ))?;

            if !response.ok() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("HTTP error: {}", response.status()))
                ));
            }

            // Get JSON response
            let json_promise = response.json()
                .map_err(|_| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed("Failed to get JSON response")
                ))?;
                
            let json_value = JsFuture::from(json_promise).await
                .map_err(|_| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed("Failed to parse JSON response")
                ))?;

            let tip_response: HttpTipInfoResponse = serde_wasm_bindgen::from_value(json_value)
                .map_err(|e| LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!("Failed to deserialize response: {}", e))
                ))?;

            Ok(TipInfo {
                best_block_height: tip_response.metadata.best_block_height,
                best_block_hash: tip_response.metadata.best_block_hash,
                accumulated_difficulty: tip_response.metadata.accumulated_difficulty,
                pruned_height: tip_response.metadata.pruned_height,
                timestamp: tip_response.metadata.timestamp,
            })
        }
    }

    async fn search_utxos(
        &mut self,
        _commitments: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
        // This endpoint doesn't exist in the actual API
        Err(LightweightWalletError::OperationNotSupported(
            "search_utxos endpoint not available in HTTP API".to_string()
        ))
    }

    async fn fetch_utxos(
        &mut self,
        _hashes: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<Vec<LightweightTransactionOutput>> {
        // This endpoint doesn't exist in the actual API
        Err(LightweightWalletError::OperationNotSupported(
            "fetch_utxos endpoint not available in HTTP API".to_string()
        ))
    }

    async fn get_blocks_by_heights(
        &mut self,
        heights: Vec<u64>,
    ) -> LightweightWalletResult<Vec<BlockInfo>> {
        if heights.is_empty() {
            return Ok(Vec::new());
        }
        
        let http_response = self.fetch_blocks_by_heights(heights).await?;
        let mut blocks = Vec::new();
        for http_block in http_response.blocks {
            let block_info = Self::convert_http_block_to_block_info(&http_block)?;
            blocks.push(block_info);
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

#[cfg(feature = "http")]
impl std::fmt::Debug for HttpBlockchainScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("HttpBlockchainScanner");
        debug_struct.field("base_url", &self.base_url);
        
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        debug_struct.field("timeout", &self.timeout);
        
        debug_struct.finish()
    }
}

/// Builder for creating HTTP blockchain scanners
#[cfg(feature = "http")]
pub struct HttpScannerBuilder {
    base_url: Option<String>,
    timeout: Option<Duration>,
}

#[cfg(feature = "http")]
impl HttpScannerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            base_url: None,
            timeout: None,
        }
    }

    /// Set the base URL for the HTTP connection
    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = Some(base_url);
        self
    }

    /// Set the timeout for HTTP operations
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Build the HTTP scanner
    pub async fn build(self) -> LightweightWalletResult<HttpBlockchainScanner> {
        let base_url = self.base_url
            .ok_or_else(|| LightweightWalletError::ConfigurationError(
                "Base URL not specified".to_string()
            ))?;

        match self.timeout {
            Some(timeout) => HttpBlockchainScanner::with_timeout(base_url, timeout).await,
            None => HttpBlockchainScanner::new(base_url).await,
        }
    }
}

#[cfg(feature = "http")]
impl Default for HttpScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "http")]
#[async_trait(?Send)]
impl WalletScanner for HttpBlockchainScanner {
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
                "No key manager or key store provided for wallet scanning".to_string()
            ));
        }

        // Use the default scanning logic with proper wallet key integration
        DefaultScanningLogic::scan_wallet_with_progress(self, config, progress_callback).await
    }

    fn blockchain_scanner(&mut self) -> &mut dyn BlockchainScanner {
        self
    }
}

// Placeholder module for when HTTP feature is not enabled
#[cfg(not(feature = "http"))]
pub struct HttpBlockchainScanner;

#[cfg(not(feature = "http"))]
impl HttpBlockchainScanner {
    pub async fn new(_base_url: String) -> crate::errors::LightweightWalletResult<Self> {
        Err(crate::errors::LightweightWalletError::OperationNotSupported(
            "HTTP feature not enabled".to_string()
        ))
    }
}

#[cfg(not(feature = "http"))]
pub struct HttpScannerBuilder;

#[cfg(not(feature = "http"))]
impl HttpScannerBuilder {
    pub fn new() -> Self {
        Self
    }

    pub async fn build(self) -> crate::errors::LightweightWalletResult<HttpBlockchainScanner> {
        Err(crate::errors::LightweightWalletError::OperationNotSupported(
            "HTTP feature not enabled".to_string()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extraction::ExtractionConfig;
    use std::time::Duration;

    #[cfg(feature = "http")]
    #[tokio::test]
    async fn test_http_scanner_builder() {
        let builder = HttpScannerBuilder::new()
            .with_base_url("https://rpc.tari.com".to_string())
            .with_timeout(Duration::from_secs(10));
            
        let scanner = builder.build().await;
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_http_output_conversion() {
        let http_output = HttpOutputData {
            output_hash: vec![1u8; 32],
            commitment: vec![2u8; 32],
            encrypted_data: vec![3u8; 24], // Minimum 24 bytes for EncryptedData
            sender_offset_public_key: vec![4u8; 32],
            features: None,
            script: None,
            metadata_signature: None,
            covenant: None,
            minimum_value_promise: Some(1000),
            range_proof: None,
        };

        let result = HttpBlockchainScanner::convert_http_output_to_lightweight(&http_output);
        assert!(result.is_ok());
    }

    #[test]
    fn test_http_block_data_json_parsing_without_inputs() {
        let json = r#"{
            "header_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "height": 100,
            "outputs": [],
            "mined_timestamp": 1234567890
        }"#;

        let result: Result<HttpBlockData, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let block_data = result.unwrap();
        assert_eq!(block_data.height, 100);
        assert!(block_data.inputs.is_none());
    }

    #[test]
    fn test_http_block_data_json_parsing_with_inputs() {
        let json = r#"{
            "header_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "height": 100,
            "outputs": [],
            "inputs": [
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
            ],
            "mined_timestamp": 1234567890
        }"#;

        let result: Result<HttpBlockData, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let block_data = result.unwrap();
        assert_eq!(block_data.height, 100);
        assert!(block_data.inputs.is_some());
        assert_eq!(block_data.inputs.unwrap().len(), 1);
    }

    #[test]
    fn test_http_tip_info_parsing() {
        let json = r#"{
            "metadata": {
                "best_block_height": 12345,
                "best_block_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "accumulated_difficulty": "1000000",
                "pruned_height": 10000,
                "timestamp": 1234567890
            }
        }"#;

        let result: Result<HttpTipInfoResponse, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let tip_info = result.unwrap();
        assert_eq!(tip_info.metadata.best_block_height, 12345);
    }

    #[test]
    fn test_scan_config_specific_heights() {
        let heights = vec![100, 200, 300];
        let config = ScanConfig::for_specific_heights(heights.clone(), ExtractionConfig::default());
        
        assert!(config.is_scanning_specific_heights());
        assert_eq!(config.get_heights_to_scan(), heights);
        assert_eq!(config.start_height, 100);
        assert_eq!(config.end_height, Some(300));
    }

    #[test]
    fn test_scan_config_range_scanning() {
        let config = ScanConfig {
            start_height: 100,
            end_height: Some(105),
            specific_heights: None,
            batch_size: 10,
            request_timeout: Duration::from_secs(30),
            extraction_config: ExtractionConfig::default(),
        };
        
        assert!(!config.is_scanning_specific_heights());
        assert_eq!(config.get_heights_to_scan(), vec![100, 101, 102, 103, 104, 105]);
    }
} 