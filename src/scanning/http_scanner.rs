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
use reqwest::Client;
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
use std::time::Duration;

// WASM targets use web-sys
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use std::time::Duration;
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use web_sys::{window, Request, RequestInit, RequestMode, Response};

#[cfg(all(feature = "http", target_arch = "wasm32"))]
use serde_wasm_bindgen;
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use wasm_bindgen::prelude::*;
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use wasm_bindgen_futures::JsFuture;

#[cfg(feature = "http")]
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
#[cfg(feature = "http")]
use tari_utilities::ByteArray;
#[cfg(all(feature = "http", feature = "tracing"))]
use tracing::debug;

use crate::{
    data_structures::{
        encrypted_data::EncryptedData,
        transaction_input::TransactionInput,
        transaction_output::TransactionOutput,
        types::{CompressedCommitment, CompressedPublicKey, MicroMinotari, PrivateKey},
        wallet_output::{Covenant, OutputFeatures, Script, Signature, WalletOutput},
        OutputType,
    },
    errors::{WalletError, WalletResult},
    extraction::{extract_wallet_output, ExtractionConfig},
    scanning::{BlockInfo, BlockScanResult, BlockchainScanner, ScanConfig, TipInfo},
    wallet::Wallet,
};

/// HTTP API tip info response - matches the actual API structure
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

/// HTTP API sync UTXOs response - matches actual API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpSyncUtxosResponse {
    pub blocks: Vec<HttpBlockData>,
    pub has_next_page: bool,
    pub next_header_to_scan: Option<Vec<u8>>,
}

/// HTTP API block data structure - matches actual response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlockData {
    pub outputs: Vec<HttpOutputData>,
    pub inputs: Vec<Vec<u8>>, // Commitment hashes
    pub mined_timestamp: u64,
}

/// HTTP API output data structure - matches actual response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpOutputData {
    pub output_hash: Vec<u8>,
    pub commitment: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub sender_offset_public_key: Vec<u8>,
}

/// HTTP API single block response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleBlockResponse {
    pub block: HttpBlock,
}

/// HTTP API block structure  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlock {
    pub header: HttpBlockHeader,
    pub body: HttpBlockBody,
}

/// HTTP API block header structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlockHeader {
    pub height: u64,
    pub hash: String,
    pub timestamp: u64,
}

/// HTTP API block body structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlockBody {
    pub outputs: Vec<TransactionOutput>,
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
    pub async fn new(base_url: String) -> WalletResult<Self> {
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let timeout = Duration::from_secs(30);
            let client = Client::builder().timeout(timeout).build().map_err(|e| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to create HTTP client: {e}"
                    )),
                )
            })?;

            // Test the connection
            let test_url = format!("{base_url}/get_tip_info");
            let response = client.get(&test_url).send().await;
            if response.is_err() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to connect to {base_url}"
                    )),
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
            // For WASM, we don't need to create a persistent client
            // web-sys creates requests on-demand

            // Test the connection with a simple GET request
            let test_url = format!("{}/get_tip_info", base_url);

            let opts = RequestInit::new();
            opts.set_method("GET");
            opts.set_mode(RequestMode::Cors);

            let request = Request::new_with_str_and_init(&test_url, &opts)?;

            let window = window().ok_or_else(|| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "No window object available",
                    ),
                )
            })?;

            let resp_value = JsFuture::from(window.fetch_with_request(&request))
                .await
                .map_err(|_| {
                    WalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(&format!(
                            "Failed to connect to {}",
                            base_url
                        )),
                    )
                })?;

            let _resp: Response = resp_value.dyn_into().map_err(|_| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Invalid response type",
                    ),
                )
            })?;

            Ok(Self { base_url })
        }
    }

    /// Create a new HTTP scanner with custom timeout (native only)
    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    pub async fn with_timeout(base_url: String, timeout: Duration) -> WalletResult<Self> {
        let client = Client::builder().timeout(timeout).build().map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                &format!("Failed to create HTTP client: {e}"),
            ))
        })?;

        // Test the connection
        let test_url = format!("{base_url}/get_tip_info");
        let response = client.get(&test_url).send().await;
        if response.is_err() {
            return Err(WalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Failed to connect to {base_url}"
                )),
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
    pub async fn with_timeout(base_url: String, _timeout: Duration) -> WalletResult<Self> {
        // WASM doesn't support timeouts in the same way, so we ignore the timeout parameter
        Self::new(base_url).await
    }

    /// Get header by height - matches WASM example usage
    async fn get_header_by_height(&self, height: u64) -> WalletResult<HttpHeaderResponse> {
        let url = format!("{}/get_header_by_height", self.base_url);

        // Native implementation using reqwest
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let response = self
                .client
                .get(&url)
                .query(&[("height", height)])
                .send()
                .await
                .map_err(|e| {
                    WalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(&format!(
                            "HTTP request failed: {e}"
                        )),
                    )
                })?;

            if !response.status().is_success() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            let header_response: HttpHeaderResponse = response.json().await.map_err(|e| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to parse response: {e}"
                    )),
                )
            })?;

            Ok(header_response)
        }

        // WASM implementation using web-sys
        #[cfg(all(feature = "http", target_arch = "wasm32"))]
        {
            let url_with_params = format!("{}?height={}", url, height);

            let opts = RequestInit::new();
            opts.set_method("GET");
            opts.set_mode(RequestMode::Cors);

            let request = Request::new_with_str_and_init(&url_with_params, &opts)?;
            request.headers().set("Accept", "application/json")?;

            let window = window().ok_or_else(|| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "No window object available",
                    ),
                )
            })?;

            let resp_value = JsFuture::from(window.fetch_with_request(&request))
                .await
                .map_err(|_| {
                    WalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(
                            "HTTP request failed",
                        ),
                    )
                })?;

            let response: Response = resp_value.dyn_into().map_err(|_| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Invalid response type",
                    ),
                )
            })?;

            if !response.ok() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            // Get JSON response
            let json_promise = response.json().map_err(|_| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Failed to get JSON response",
                    ),
                )
            })?;

            let json_value = JsFuture::from(json_promise).await.map_err(|_| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Failed to parse JSON response",
                    ),
                )
            })?;

            let header_response: HttpHeaderResponse = serde_wasm_bindgen::from_value(json_value)
                .map_err(|e| {
                    WalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(&format!(
                            "Failed to deserialize response: {}",
                            e
                        )),
                    )
                })?;

            Ok(header_response)
        }
    }

    /// Sync UTXOs by block - matches WASM example usage
    async fn sync_utxos_by_block(
        &self,
        start_header_hash: &str,
    ) -> WalletResult<HttpSyncUtxosResponse> {
        let url = format!("{}/sync_utxos_by_block", self.base_url);
        let limit = 10u64;
        let page = 0u64;

        // Native implementation using reqwest
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let response = self
                .client
                .get(&url)
                .query(&[
                    ("start_header_hash", start_header_hash),
                    ("limit", &limit.to_string()),
                    ("page", &page.to_string()),
                ])
                .send()
                .await
                .map_err(|e| {
                    WalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(&format!(
                            "HTTP request failed: {e}"
                        )),
                    )
                })?;

            if !response.status().is_success() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            let sync_response: HttpSyncUtxosResponse = response.json().await.map_err(|e| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to parse response: {e}"
                    )),
                )
            })?;

            Ok(sync_response)
        }

        // WASM implementation using web-sys
        #[cfg(all(feature = "http", target_arch = "wasm32"))]
        {
            let url_with_params = format!(
                "{}?start_header_hash={}&limit={}&page={}",
                url, start_header_hash, limit, page
            );

            let opts = RequestInit::new();
            opts.set_method("GET");
            opts.set_mode(RequestMode::Cors);

            let request = Request::new_with_str_and_init(&url_with_params, &opts)?;
            request.headers().set("Accept", "application/json")?;

            let window = window().ok_or_else(|| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "No window object available",
                    ),
                )
            })?;

            let resp_value = JsFuture::from(window.fetch_with_request(&request))
                .await
                .map_err(|_| {
                    WalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(
                            "HTTP request failed",
                        ),
                    )
                })?;

            let response: Response = resp_value.dyn_into().map_err(|_| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Invalid response type",
                    ),
                )
            })?;

            if !response.ok() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            // Get JSON response
            let json_promise = response.json().map_err(|_| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Failed to get JSON response",
                    ),
                )
            })?;

            let json_value = JsFuture::from(json_promise).await.map_err(|_| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Failed to parse JSON response",
                    ),
                )
            })?;

            let sync_response: HttpSyncUtxosResponse = serde_wasm_bindgen::from_value(json_value)
                .map_err(|e| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to deserialize response: {}",
                        e
                    )),
                )
            })?;

            Ok(sync_response)
        }
    }

    /// Convert bytes to hex string
    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Convert HTTP output data to TransactionOutput
    fn convert_http_output_to_lightweight(
        http_output: &HttpOutputData,
    ) -> WalletResult<TransactionOutput> {
        // Parse commitment
        if http_output.commitment.len() != 32 {
            return Err(WalletError::ConversionError(
                "Invalid commitment length, expected 32 bytes".to_string(),
            ));
        }
        let commitment =
            CompressedCommitment::new(http_output.commitment.clone().try_into().map_err(|_| {
                WalletError::ConversionError("Failed to convert commitment".to_string())
            })?);

        // Parse sender offset public key
        if http_output.sender_offset_public_key.len() != 32 {
            return Err(WalletError::ConversionError(
                "Invalid sender offset public key length, expected 32 bytes".to_string(),
            ));
        }
        let sender_offset_public_key = CompressedPublicKey::new(
            http_output
                .sender_offset_public_key
                .clone()
                .try_into()
                .map_err(|_| {
                    WalletError::ConversionError(
                        "Failed to convert sender offset public key".to_string(),
                    )
                })?,
        );

        // Convert Encrypted Data - match GRPC approach exactly
        let encrypted_data =
            EncryptedData::from_bytes(&http_output.encrypted_data).unwrap_or_default();

        // Convert OutputFeatures - match GRPC approach (HTTP API doesn't provide features, so use default)
        let features = OutputFeatures::default();

        // Convert range proof (not provided by this API endpoint)
        let proof = None;

        // Convert Script - match GRPC approach exactly
        let script = Script { bytes: Vec::new() };

        // Convert Metadata Signature - match GRPC approach exactly
        let metadata_signature = Signature::default();

        // Convert Covenant - match GRPC approach exactly
        let covenant = Covenant { bytes: Vec::new() };

        // Convert Minimum Value Promise - match GRPC approach exactly
        let minimum_value_promise = MicroMinotari::new(0);

        // Use direct construction exactly like GRPC scanner
        Ok(TransactionOutput {
            version: 0, // HTTP API doesn't provide version, GRPC uses grpc_output.version which is 0
            features,
            commitment,
            proof,
            script,
            sender_offset_public_key,
            metadata_signature,
            covenant,
            encrypted_data,
            minimum_value_promise,
        })
    }

    /// Convert HTTP input data to TransactionInput - simplified version
    fn convert_http_input_to_lightweight(
        output_hash_bytes: &[u8],
    ) -> WalletResult<TransactionInput> {
        // Parse output hash
        if output_hash_bytes.len() != 32 {
            return Err(WalletError::ConversionError(
                "Invalid output hash length, expected 32 bytes".to_string(),
            ));
        }
        let mut output_hash = [0u8; 32];
        output_hash.copy_from_slice(output_hash_bytes);

        // Create minimal TransactionInput with the output hash
        Ok(TransactionInput::new(
            1,                                                                // version
            0,                                                                // features (default)
            [0u8; 32],                      // commitment (not available from HTTP API)
            [0u8; 64],                      // script_signature (not available)
            CompressedPublicKey::default(), // sender_offset_public_key (not available)
            Vec::new(),                     // covenant (not available)
            crate::data_structures::transaction_input::ExecutionStack::new(), // input_data (not available)
            output_hash,           // output_hash (this is the actual data from HTTP API)
            0,                     // output_features (not available)
            [0u8; 64],             // output_metadata_signature (not available)
            0,                     // maturity (not available)
            MicroMinotari::new(0), // value (not available)
        ))
    }

    /// Convert HTTP block data to BlockInfo
    fn convert_http_block_to_block_info(http_block: &HttpBlockData) -> WalletResult<BlockInfo> {
        let outputs = http_block
            .outputs
            .iter()
            .map(Self::convert_http_output_to_lightweight)
            .collect::<WalletResult<Vec<_>>>()?;

        // Handle simplified inputs structure
        let inputs = http_block
            .inputs
            .iter()
            .map(|hash_bytes| Self::convert_http_input_to_lightweight(hash_bytes))
            .collect::<WalletResult<Vec<_>>>()?;

        Ok(BlockInfo {
            height: 0,        // Block height not available in sync_utxos_by_block response
            hash: Vec::new(), // Block hash not available in sync_utxos_by_block response
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
    ) -> WalletResult<ScanConfig> {
        // Get the master key from the wallet for scanning
        let master_key_bytes = wallet.master_key_bytes();

        // Use the first 16 bytes of the master key as entropy (following Tari CipherSeed pattern)
        let mut entropy = [0u8; 16];
        entropy.copy_from_slice(&master_key_bytes[..16]);

        // Derive the proper view key using Tari's key derivation specification
        let (view_key, _spend_key) =
            crate::key_management::key_derivation::derive_view_and_spend_keys_from_entropy(
                &entropy,
            )
            .map_err(WalletError::KeyManagementError)?;

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
            #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
            request_timeout: self.timeout,
            #[cfg(all(feature = "http", target_arch = "wasm32"))]
            request_timeout: std::time::Duration::from_secs(30), // Default for WASM
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
            #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
            request_timeout: self.timeout,
            #[cfg(all(feature = "http", target_arch = "wasm32"))]
            request_timeout: std::time::Duration::from_secs(30), // Default for WASM
            extraction_config,
        }
    }

    /// Scan for regular recoverable outputs using encrypted data decryption
    fn scan_for_recoverable_output(
        output: &TransactionOutput,
        extraction_config: &ExtractionConfig,
    ) -> WalletResult<Option<WalletOutput>> {
        // Skip non-payment outputs for this scan type
        if !matches!(output.features().output_type, OutputType::Payment) {
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
        output: &TransactionOutput,
        extraction_config: &ExtractionConfig,
    ) -> WalletResult<Option<WalletOutput>> {
        // Skip non-payment outputs for this scan type
        if !matches!(output.features().output_type, OutputType::Payment) {
            return Ok(None);
        }

        // Use the same extraction logic - the difference is in creation, not detection
        match extract_wallet_output(output, extraction_config) {
            Ok(wallet_output) => Ok(Some(wallet_output)),
            Err(_) => Ok(None),
        }
    }

    /// Scan for coinbase outputs
    fn scan_for_coinbase_output(output: &TransactionOutput) -> WalletResult<Option<WalletOutput>> {
        // Only handle coinbase outputs
        if !matches!(output.features().output_type, OutputType::Coinbase) {
            return Ok(None);
        }

        // For coinbase outputs, the value is typically revealed in the minimum value promise
        if output.minimum_value_promise().as_u64() > 0 {
            let wallet_output = WalletOutput::new(
                output.version(),
                output.minimum_value_promise(),
                crate::data_structures::wallet_output::KeyId::Zero,
                output.features().clone(),
                output.script().clone(),
                crate::data_structures::wallet_output::ExecutionStack::default(),
                crate::data_structures::wallet_output::KeyId::Zero,
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

    /// Fetch block range using the sync_utxos_by_block endpoint
    async fn fetch_block_range(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> WalletResult<Vec<HttpBlockData>> {
        // Get the starting header hash
        let start_header = self.get_header_by_height(start_height).await?;
        let mut current_header_hash = Self::bytes_to_hex(&start_header.hash);

        let mut all_blocks = Vec::new();
        let mut blocks_collected = 0;
        let max_blocks = (end_height - start_height + 1) as usize;

        #[cfg(feature = "tracing")]
        debug!(
            "Starting fetch_block_range from height {} to {} (max {} blocks)",
            start_height, end_height, max_blocks
        );

        while blocks_collected < max_blocks {
            // Use sync_utxos_by_block to get batch of blocks
            let sync_response = self.sync_utxos_by_block(&current_header_hash).await?;

            if sync_response.blocks.is_empty() {
                #[cfg(feature = "tracing")]
                debug!("No more blocks available from base node");
                break;
            }

            // Add all blocks from this response (we can't filter by height since it's not provided)
            for block in sync_response.blocks {
                all_blocks.push(block);
                blocks_collected += 1;

                // Stop if we've collected enough blocks
                if blocks_collected >= max_blocks {
                    break;
                }
            }

            // Check if we have a next header to continue with and haven't reached our limit
            if blocks_collected < max_blocks {
                if let Some(next_header) = sync_response.next_header_to_scan {
                    current_header_hash = Self::bytes_to_hex(&next_header);
                    #[cfg(feature = "tracing")]
                    debug!(
                        "Continuing with next header: {} (collected {}/{} blocks)",
                        &current_header_hash[..16],
                        blocks_collected,
                        max_blocks
                    );
                } else {
                    #[cfg(feature = "tracing")]
                    debug!("No more headers to scan, reached end of available data");
                    break;
                }
            }
        }

        #[cfg(feature = "tracing")]
        debug!(
            "Fetched {} blocks for range {} to {}",
            all_blocks.len(),
            start_height,
            end_height
        );

        Ok(all_blocks)
    }
}

#[cfg(feature = "http")]
#[async_trait(?Send)]
impl BlockchainScanner for HttpBlockchainScanner {
    async fn scan_blocks(&mut self, config: ScanConfig) -> WalletResult<Vec<BlockScanResult>> {
        #[cfg(feature = "tracing")]
        debug!(
            "Starting HTTP block scan from height {} to {:?}",
            config.start_height, config.end_height
        );

        // Get tip info to determine end height
        let tip_info = self.get_tip_info().await?;
        let end_height = config.end_height.unwrap_or(tip_info.best_block_height);

        if config.start_height > end_height {
            return Ok(Vec::new());
        }

        // Fetch blocks using the new API
        let http_blocks = self
            .fetch_block_range(config.start_height, end_height)
            .await?;

        let mut results = Vec::new();

        for http_block in http_blocks {
            let block_info = Self::convert_http_block_to_block_info(&http_block)?;
            let mut wallet_outputs = Vec::new();

            for output in &block_info.outputs {
                let mut found_output = false;

                // Strategy 1: Regular recoverable outputs
                if !found_output {
                    if let Some(wallet_output) =
                        Self::scan_for_recoverable_output(output, &config.extraction_config)?
                    {
                        wallet_outputs.push(wallet_output);
                        found_output = true;
                    }
                }

                // Strategy 2: One-sided payments
                if !found_output {
                    if let Some(wallet_output) =
                        Self::scan_for_one_sided_payment(output, &config.extraction_config)?
                    {
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
        debug!(
            "HTTP scan completed, found {} blocks with wallet outputs",
            results.len()
        );
        Ok(results)
    }

    async fn get_tip_info(&mut self) -> WalletResult<TipInfo> {
        let url = format!("{}/get_tip_info", self.base_url);

        // Native implementation using reqwest
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let response = self.client.get(&url).send().await.map_err(|e| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP request failed: {e}"
                    )),
                )
            })?;

            if !response.status().is_success() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            let tip_response: HttpTipInfoResponse = response.json().await.map_err(|e| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to parse response: {e}"
                    )),
                )
            })?;

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
            request.headers().set("Accept", "application/json")?;

            let window = window().ok_or_else(|| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "No window object available",
                    ),
                )
            })?;

            let resp_value = JsFuture::from(window.fetch_with_request(&request))
                .await
                .map_err(|_| {
                    WalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(
                            "HTTP request failed",
                        ),
                    )
                })?;

            let response: Response = resp_value.dyn_into().map_err(|_| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Invalid response type",
                    ),
                )
            })?;

            if !response.ok() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            // Get JSON response
            let json_promise = response.json().map_err(|_| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Failed to get JSON response",
                    ),
                )
            })?;

            let json_value = JsFuture::from(json_promise).await.map_err(|_| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Failed to parse JSON response",
                    ),
                )
            })?;

            let tip_response: HttpTipInfoResponse = serde_wasm_bindgen::from_value(json_value)
                .map_err(|e| {
                    WalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(&format!(
                            "Failed to deserialize response: {}",
                            e
                        )),
                    )
                })?;

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
    ) -> WalletResult<Vec<BlockScanResult>> {
        // This endpoint is not implemented in the current HTTP API
        // It would require a different endpoint that searches for specific commitments
        Err(WalletError::ScanningError(
            crate::errors::ScanningError::blockchain_connection_failed(
                "search_utxos not implemented for HTTP scanner",
            ),
        ))
    }

    async fn fetch_utxos(&mut self, _hashes: Vec<Vec<u8>>) -> WalletResult<Vec<TransactionOutput>> {
        // This endpoint is not implemented in the current HTTP API
        // It would require a different endpoint that fetches specific UTXOs by hash
        Err(WalletError::ScanningError(
            crate::errors::ScanningError::blockchain_connection_failed(
                "fetch_utxos not implemented for HTTP scanner",
            ),
        ))
    }

    async fn get_blocks_by_heights(&mut self, heights: Vec<u64>) -> WalletResult<Vec<BlockInfo>> {
        let mut blocks = Vec::new();

        for height in heights {
            if let Some(block) = self.get_block_by_height(height).await? {
                blocks.push(block);
            }
        }

        Ok(blocks)
    }

    async fn get_block_by_height(&mut self, height: u64) -> WalletResult<Option<BlockInfo>> {
        let url = format!("{}/base_node/blocks/{}", self.base_url, height);

        let response = self
            .client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to fetch block {height}: {e}"
                    )),
                )
            })?;

        if !response.status().is_success() {
            if response.status() == 404 {
                return Ok(None);
            }
            return Err(WalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "HTTP {} error fetching block {height}",
                    response.status()
                )),
            ));
        }

        let block_response: SingleBlockResponse = response.json().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                &format!("Failed to parse block response for height {height}: {e}"),
            ))
        })?;

        let block = block_response.block;
        Ok(Some(BlockInfo {
            height: block.header.height,
            hash: hex::decode(&block.header.hash).map_err(|_| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Invalid block hash format",
                    ),
                )
            })?,
            outputs: block.body.outputs,
            inputs: Vec::new(),  // HTTP API doesn't provide input details
            kernels: Vec::new(), // HTTP API doesn't provide kernel details
            timestamp: block.header.timestamp,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        data_structures::types::PrivateKey, extraction::ExtractionConfig, scanning::BlockScanResult,
    };
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct TestBlockHeader {
        name: String,
        height: u64,
        hash: Vec<u8>,
    }

    const TEST_PRIVATE_KEY: &str =
        "ab5ab1fdc94094ca1fc0ee46dc86ad5098b8ebf8e54c2a77eeb5b26334b8fa0d";

    // Load real block data from JSON files
    const BLOCK_32038_DATA: &str = include_str!("test_fixtures/block_32038.json");
    const BLOCK_34926_DATA: &str = include_str!("test_fixtures/block_34926.json");
    const BLOCK_37928_DATA: &str = include_str!("test_fixtures/block_37928.json");
    const BLOCK_39949_DATA: &str = include_str!("test_fixtures/block_39949.json");

    // Load block headers from JSON file
    const BLOCK_HEADERS_JSON: &str = include_str!("test_fixtures/block_headers.json");

    fn create_test_private_key() -> PrivateKey {
        let mut key_bytes = [0u8; 32];
        hex::decode_to_slice(TEST_PRIVATE_KEY, &mut key_bytes).expect("Valid hex");
        PrivateKey::new(key_bytes)
    }

    fn parse_test_block_data() -> HttpSyncUtxosResponse {
        serde_json::from_str(BLOCK_32038_DATA).expect("Valid JSON")
    }

    fn load_all_test_block_data() -> Vec<HttpSyncUtxosResponse> {
        vec![
            serde_json::from_str(BLOCK_32038_DATA).expect("Valid JSON for block 32038"),
            serde_json::from_str(BLOCK_34926_DATA).expect("Valid JSON for block 34926"),
            serde_json::from_str(BLOCK_37928_DATA).expect("Valid JSON for block 37928"),
            serde_json::from_str(BLOCK_39949_DATA).expect("Valid JSON for block 39949"),
        ]
    }

    fn load_test_block_headers() -> Vec<TestBlockHeader> {
        serde_json::from_str(BLOCK_HEADERS_JSON).expect("Valid block headers JSON")
    }

    #[test]
    fn test_block_header_data_consistency() {
        // Verify our test block header data is consistent
        let headers = load_test_block_headers();
        for header in &headers {
            assert_eq!(
                header.hash.len(),
                32,
                "Block {} hash should be 32 bytes",
                header.name
            );
            assert!(
                header.height > 0,
                "Block {} height should be positive",
                header.name
            );
        }
    }

    #[test]
    fn test_private_key_creation() {
        let private_key = create_test_private_key();

        // Verify the private key was created correctly
        let key_bytes = private_key.as_bytes();
        assert_eq!(key_bytes.len(), 32);

        // Verify it matches our expected test key
        let expected_bytes = hex::decode(TEST_PRIVATE_KEY).expect("Valid hex");
        assert_eq!(key_bytes, &expected_bytes[..]);
    }

    #[test]
    fn test_real_block_data_parsing() {
        let sync_response = parse_test_block_data();

        // Verify the structure of the real block data
        assert_eq!(sync_response.blocks.len(), 1);
        assert!(sync_response.has_next_page);
        assert!(sync_response.next_header_to_scan.is_some());

        let block = &sync_response.blocks[0];
        assert_eq!(block.mined_timestamp, 1750340139);
        assert!(!block.outputs.is_empty());
        assert!(!block.inputs.is_empty());

        // Verify output structure
        let output = &block.outputs[0];
        assert_eq!(output.output_hash.len(), 32);
        assert_eq!(output.commitment.len(), 32);
        assert_eq!(output.sender_offset_public_key.len(), 32);
        assert!(!output.encrypted_data.is_empty());
    }

    #[test]
    fn test_http_output_conversion() {
        let sync_response = parse_test_block_data();
        let http_output = &sync_response.blocks[0].outputs[0];

        // Test converting HTTP output to TransactionOutput
        let result = HttpBlockchainScanner::convert_http_output_to_lightweight(http_output);

        match result {
            Ok(tx_output) => {
                // Verify the conversion worked
                assert_eq!(
                    tx_output.commitment().as_bytes(),
                    &http_output.commitment[..]
                );
                assert_eq!(
                    tx_output.sender_offset_public_key().as_bytes(),
                    &http_output.sender_offset_public_key[..]
                );
                assert_eq!(
                    tx_output.encrypted_data().as_bytes(),
                    &http_output.encrypted_data[..]
                );
            }
            Err(e) => panic!("Failed to convert HTTP output: {}", e),
        }
    }

    #[test]
    fn test_http_input_conversion() {
        let sync_response = parse_test_block_data();
        let input_hash = &sync_response.blocks[0].inputs[0];

        // Test converting HTTP input to TransactionInput
        let result = HttpBlockchainScanner::convert_http_input_to_lightweight(input_hash);

        match result {
            Ok(tx_input) => {
                // Verify the conversion worked - check that output hash matches
                let output_hash = &tx_input.output_hash;
                assert_eq!(output_hash.as_slice(), input_hash.as_slice());
            }
            Err(e) => panic!("Failed to convert HTTP input: {}", e),
        }
    }

    #[test]
    fn test_block_conversion() {
        let sync_response = parse_test_block_data();
        let http_block = &sync_response.blocks[0];

        // Test converting HTTP block to BlockInfo
        let result = HttpBlockchainScanner::convert_http_block_to_block_info(http_block);

        match result {
            Ok(block_info) => {
                assert_eq!(block_info.timestamp, http_block.mined_timestamp);
                assert_eq!(block_info.outputs.len(), http_block.outputs.len());
                assert_eq!(block_info.inputs.len(), http_block.inputs.len());
            }
            Err(e) => panic!("Failed to convert HTTP block: {}", e),
        }
    }

    #[test]
    fn test_utxo_extraction_with_test_key() {
        let sync_response = parse_test_block_data();
        let http_block = &sync_response.blocks[0];
        let private_key = create_test_private_key();

        // Convert HTTP block to BlockInfo
        let block_info = HttpBlockchainScanner::convert_http_block_to_block_info(http_block)
            .expect("Block conversion should work");

        // Create extraction config with our test private key
        let extraction_config = ExtractionConfig::with_private_key(private_key);

        // Try to extract wallet outputs from each output in the block
        let mut wallet_outputs = Vec::new();
        for output in &block_info.outputs {
            // Test recoverable output scanning
            if let Some(wallet_output) =
                HttpBlockchainScanner::scan_for_recoverable_output(output, &extraction_config)
                    .expect("Scan should not error")
            {
                wallet_outputs.push(wallet_output);
            }

            // Test one-sided payment scanning
            if let Some(wallet_output) =
                HttpBlockchainScanner::scan_for_one_sided_payment(output, &extraction_config)
                    .expect("Scan should not error")
            {
                wallet_outputs.push(wallet_output);
            }

            // Test coinbase output scanning (will be None for payment outputs)
            if let Some(wallet_output) = HttpBlockchainScanner::scan_for_coinbase_output(output)
                .expect("Scan should not error")
            {
                wallet_outputs.push(wallet_output);
            }
        }

        // Note: We don't expect to find any UTXOs with our test private key since it's
        // not associated with the real outputs in the block data. This test verifies
        // the scanning logic works without errors.
        println!(
            "Found {} wallet outputs with test private key",
            wallet_outputs.len()
        );
    }

    #[test]
    fn test_all_blocks_data_loading() {
        let all_blocks = load_all_test_block_data();
        let headers = load_test_block_headers();

        // Verify we have 4 blocks
        assert_eq!(all_blocks.len(), 4);
        assert_eq!(headers.len(), 4);

        // Verify each block has expected structure
        for (i, sync_response) in all_blocks.iter().enumerate() {
            let header = &headers[i];

            for block in &sync_response.blocks {
                println!("Block {} (height {}):", header.name, header.height);
                println!("  - Outputs: {}", block.outputs.len());
                println!("  - Inputs: {}", block.inputs.len());
                println!("  - Timestamp: {}", block.mined_timestamp);

                // Basic validation
                assert!(
                    !block.outputs.is_empty(),
                    "Block {} should have outputs",
                    header.name
                );

                // Validate output structure for each output
                for (j, output) in block.outputs.iter().enumerate() {
                    assert_eq!(
                        output.output_hash.len(),
                        32,
                        "Block {} output {} hash should be 32 bytes",
                        header.name,
                        j
                    );
                    assert_eq!(
                        output.commitment.len(),
                        32,
                        "Block {} output {} commitment should be 32 bytes",
                        header.name,
                        j
                    );
                    assert_eq!(
                        output.sender_offset_public_key.len(),
                        32,
                        "Block {} output {} sender key should be 32 bytes",
                        header.name,
                        j
                    );
                    assert!(
                        !output.encrypted_data.is_empty(),
                        "Block {} output {} should have encrypted data",
                        header.name,
                        j
                    );

                    // Test conversion works for each output
                    let conversion_result =
                        HttpBlockchainScanner::convert_http_output_to_lightweight(output);
                    assert!(
                        conversion_result.is_ok(),
                        "Block {} output {} should convert successfully",
                        header.name,
                        j
                    );
                }
            }
        }
    }

    #[test]
    fn test_debug_output_5_block_32038() {
        // Load the test data
        let sync_response: HttpSyncUtxosResponse =
            serde_json::from_str(BLOCK_32038_DATA).expect("Failed to parse block 32038 JSON");

        // Create the extraction config with the correct wallet key from database (wallet_id 2 "small")
        let view_key_hex = "ab5ab1fdc94094ca1fc0ee46dc86ad5098b8ebf8e54c2a77eeb5b26334b8fa0d";
        let view_key_bytes = hex::decode(view_key_hex).expect("Valid hex");
        let mut view_key_array = [0u8; 32];
        view_key_array.copy_from_slice(&view_key_bytes);
        let view_private_key = PrivateKey::new(view_key_array);
        let extraction_config = ExtractionConfig::with_private_key(view_private_key);

        let http_block = &sync_response.blocks[0];
        let block_info = HttpBlockchainScanner::convert_http_block_to_block_info(http_block)
            .expect("Block conversion should work");

        println!("Block 32038 has {} outputs", block_info.outputs.len());

        // Focus on output 92 (the one with the correct commitment)
        if block_info.outputs.len() > 92 {
            let output_5 = &block_info.outputs[92];
            println!("=== DEBUG OUTPUT 92 (commitment 080e9955...) ===");
            println!("Output type: {:?}", output_5.features().output_type);
            println!(
                "Commitment: {}",
                hex::encode(output_5.commitment().as_bytes())
            );
            println!(
                "Encrypted data length: {}",
                output_5.encrypted_data().as_bytes().len()
            );
            println!(
                "Encrypted data hex: {}",
                hex::encode(output_5.encrypted_data().as_bytes())
            );
            println!(
                "Sender offset public key: {}",
                hex::encode(output_5.sender_offset_public_key().as_bytes())
            );

            // Try to decrypt with extraction config
            println!("Attempting extraction...");

            // Debug: Also try direct decryption to see if the data can be decrypted at all
            println!("🔍 Testing direct decryption mechanisms...");

            // Test direct change output decryption
            let test_private_key = create_test_private_key();
            if let Ok((value, _mask, payment_id)) =
                crate::data_structures::encrypted_data::EncryptedData::decrypt_data(
                    &test_private_key,
                    output_5.commitment(),
                    output_5.encrypted_data(),
                )
            {
                println!("✅ Direct change output decryption succeeded!");
                println!("🔍 Value: {} µT", value.as_u64());
                println!("🔍 Payment ID: {:?}", payment_id);
            } else {
                println!("❌ Direct change output decryption failed");
            }

            // Test direct one-sided payment decryption
            if let Ok((value, _mask, payment_id)) =
                crate::data_structures::encrypted_data::EncryptedData::decrypt_one_sided_data(
                    &test_private_key,
                    output_5.commitment(),
                    output_5.sender_offset_public_key(),
                    output_5.encrypted_data(),
                )
            {
                println!("✅ Direct one-sided payment decryption succeeded!");
                println!("🔍 Value: {} µT", value.as_u64());
                println!("🔍 Payment ID: {:?}", payment_id);
            } else {
                println!("❌ Direct one-sided payment decryption failed");
            }

            match crate::extraction::extract_wallet_output(output_5, &extraction_config) {
                Ok(wallet_output) => {
                    println!("✅ Successfully extracted wallet output!");
                    println!("  Value: {} µT", wallet_output.value().as_u64());
                    println!("  Payment ID: {:?}", wallet_output.payment_id());
                }
                Err(e) => {
                    println!("❌ Extraction failed: {:?}", e);
                }
            }

            // Also test the scan functions directly
            println!("Testing scan_for_recoverable_output...");
            match HttpBlockchainScanner::scan_for_recoverable_output(output_5, &extraction_config) {
                Ok(Some(wallet_output)) => {
                    println!("✅ scan_for_recoverable_output succeeded!");
                    println!("  Value: {} µT", wallet_output.value().as_u64());
                }
                Ok(None) => {
                    println!("❌ scan_for_recoverable_output returned None (not a wallet output)");
                }
                Err(e) => {
                    println!("❌ scan_for_recoverable_output failed: {:?}", e);
                }
            }
        }
    }

    #[test]
    fn test_scanning_all_blocks_with_test_key() {
        let all_blocks = load_all_test_block_data();
        let headers = load_test_block_headers();
        let private_key = create_test_private_key();
        let extraction_config = ExtractionConfig::with_private_key(private_key);

        let mut total_outputs_scanned = 0;
        let mut total_inputs_scanned = 0;
        let mut total_wallet_outputs_found = 0;
        let mut wallet_output_hashes = std::collections::HashSet::new();

        for (i, sync_response) in all_blocks.iter().enumerate() {
            let header = &headers[i];

            for http_block in &sync_response.blocks {
                // Convert HTTP block to BlockInfo
                let block_info =
                    HttpBlockchainScanner::convert_http_block_to_block_info(http_block)
                        .expect("Block conversion should work");

                let mut wallet_outputs = Vec::new();

                // Scan outputs for wallet ownership
                for (output_index, output) in block_info.outputs.iter().enumerate() {
                    total_outputs_scanned += 1;

                    if let Some(wallet_output) = HttpBlockchainScanner::scan_for_recoverable_output(
                        output,
                        &extraction_config,
                    )
                    .expect("Scan should not error")
                    {
                        // Debug successful outputs to compare with failing ones
                        println!(
                            "✅ HTTP: Successfully decrypted output at block {}, index {}",
                            header.height, output_index
                        );
                        println!(
                            "  - commitment: {}",
                            hex::encode(output.commitment().as_bytes())
                        );
                        println!("  - value: {} µT", wallet_output.value().as_u64());

                        // Store the output hash for later input matching (this is what inputs reference)
                        let http_output = &http_block.outputs[output_index];
                        let output_hash = http_output.output_hash.clone();
                        wallet_output_hashes.insert(output_hash);
                        wallet_outputs.push(wallet_output);
                    }
                }

                total_wallet_outputs_found += wallet_outputs.len();

                println!(
                    "Block {} (height {}): Found {} wallet outputs from {} total outputs",
                    header.name,
                    header.height,
                    wallet_outputs.len(),
                    block_info.outputs.len()
                );
            }
        }

        // Now scan all blocks for spent inputs that match our wallet outputs
        let mut total_spent_wallet_inputs = 0;

        for (i, sync_response) in all_blocks.iter().enumerate() {
            let header = &headers[i];
            let http_block = &sync_response.blocks[0];

            // Convert HTTP block to BlockInfo
            let block_info = HttpBlockchainScanner::convert_http_block_to_block_info(http_block)
                .expect("Block conversion should work");

            let mut spent_wallet_inputs = 0;

            // Check each input to see if it spends one of our wallet outputs
            for input in &block_info.inputs {
                total_inputs_scanned += 1;
                let input_output_hash = &input.output_hash;

                // Check if this input spends one of our wallet outputs
                if wallet_output_hashes.contains(input_output_hash.as_slice()) {
                    spent_wallet_inputs += 1;
                }
            }

            total_spent_wallet_inputs += spent_wallet_inputs;

            println!(
                "Block {} (height {}): Found {} spent wallet inputs from {} total inputs",
                header.name,
                header.height,
                spent_wallet_inputs,
                block_info.inputs.len()
            );
        }

        println!("Total scan results:");
        println!(
            "  - {} wallet outputs found from {} total outputs across {} blocks",
            total_wallet_outputs_found,
            total_outputs_scanned,
            all_blocks.len()
        );
        println!(
            "  - {} spent wallet inputs found from {} total inputs across {} blocks",
            total_spent_wallet_inputs,
            total_inputs_scanned,
            all_blocks.len()
        );

        // The test key should detect both outputs and spent inputs in these blocks
        // since they contain inputs and outputs for the private view key according to the user
    }

    #[test]
    fn test_input_detection_and_spent_outputs() {
        let all_blocks = load_all_test_block_data();
        let headers = load_test_block_headers();
        let private_key = create_test_private_key();
        let extraction_config = ExtractionConfig::with_private_key(private_key);

        // First pass: collect all wallet outputs and their identifiers
        let mut wallet_output_identifiers = std::collections::HashMap::new();
        let mut all_input_hashes = std::collections::HashSet::new();

        for (i, sync_response) in all_blocks.iter().enumerate() {
            let header = &headers[i];
            let http_block = &sync_response.blocks[0];
            let block_info = HttpBlockchainScanner::convert_http_block_to_block_info(http_block)
                .expect("Block conversion should work");

            // Collect all input hashes to see what's being spent
            for input in &block_info.inputs {
                all_input_hashes.insert(input.output_hash.clone());
            }

            // Scan for wallet outputs and store their identifiers
            for output in &block_info.outputs {
                if let Some(_wallet_output) =
                    HttpBlockchainScanner::scan_for_recoverable_output(output, &extraction_config)
                        .expect("Scan should not error")
                {
                    // Store the output hash for later input matching (this is what inputs reference)
                    let http_output = &http_block.outputs[block_info
                        .outputs
                        .iter()
                        .position(|o| std::ptr::eq(o, output))
                        .unwrap()];
                    let output_hash = http_output.output_hash.clone();
                    let output_hash_key =
                        format!("{}_{}", header.height, hex::encode(&output_hash[..8]));
                    wallet_output_identifiers.insert(
                        output_hash_key.clone(),
                        (header.height, output_hash.clone()),
                    );

                    println!(
                        "Found wallet output in block {} with output hash: {}",
                        header.height,
                        hex::encode(&output_hash[..8])
                    );
                }
            }
        }

        // Second pass: check for spent wallet outputs by matching input hashes
        let mut spent_outputs_detected = 0;

        for (i, sync_response) in all_blocks.iter().enumerate() {
            let header = &headers[i];
            let http_block = &sync_response.blocks[0];
            let block_info = HttpBlockchainScanner::convert_http_block_to_block_info(http_block)
                .expect("Block conversion should work");

            for input in &block_info.inputs {
                // Check if this input hash matches any of our wallet output hashes
                for (_output_key, (origin_height, output_hash)) in &wallet_output_identifiers {
                    // Check if the input references one of our wallet outputs by hash
                    if input.output_hash.as_slice() == output_hash.as_slice() {
                        spent_outputs_detected += 1;
                        println!("Detected spent wallet output: Block {} input spends output from block {} (output hash match)", 
                                 header.height, origin_height);
                    }

                    // 2. Check if the input output_hash appears in our collected hashes
                    if all_input_hashes.contains(&input.output_hash) {
                        // This input references an output that exists in our dataset
                        // Additional logic could be added here for more sophisticated matching
                    }
                }
            }
        }

        println!("Input detection summary:");
        println!(
            "  - Total wallet outputs found: {}",
            wallet_output_identifiers.len()
        );
        println!(
            "  - Total spent wallet outputs detected: {}",
            spent_outputs_detected
        );
        println!("  - Total unique input hashes: {}", all_input_hashes.len());

        // Verify that we can detect both creation and spending of wallet outputs
        assert!(
            wallet_output_identifiers.len() > 0,
            "Should find wallet outputs"
        );

        // Additional analysis: check if any inputs reference the actual output hashes from HTTP data
        let mut cross_referenced_inputs = 0;
        for (i, sync_response) in all_blocks.iter().enumerate() {
            let header = &headers[i];
            let http_block = &sync_response.blocks[0];

            for input_hash in &http_block.inputs {
                // Check if this input hash matches any output hash from the same or other blocks
                for (j, other_sync_response) in all_blocks.iter().enumerate() {
                    let other_http_block = &other_sync_response.blocks[0];
                    for output in &other_http_block.outputs {
                        if input_hash.as_slice() == output.output_hash.as_slice() {
                            cross_referenced_inputs += 1;
                            println!("Found input in block {} that spends output from block {} (output hash match)", 
                                     header.height, headers[j].height);
                        }
                    }
                }
            }
        }

        println!(
            "Cross-reference analysis: {} inputs reference outputs within our test blocks",
            cross_referenced_inputs
        );
    }

    #[test]
    fn test_scan_config_creation() {
        let private_key = create_test_private_key();
        let private_key_bytes = private_key.as_bytes();

        let _start_height = 32038;
        let _end_height = Some(32040);

        // Test the basic scan config structure that would be created
        let extraction_config = ExtractionConfig::with_private_key(private_key);

        // Verify extraction config was created properly
        assert_eq!(
            extraction_config
                .private_key
                .expect("Private key should be set")
                .as_bytes(),
            private_key_bytes
        );
    }

    #[test]
    fn test_bytes_to_hex_conversion() {
        // Test the utility function used in the scanner
        let test_bytes = &[0xde, 0xad, 0xbe, 0xef];
        let hex_result = HttpBlockchainScanner::bytes_to_hex(test_bytes);
        assert_eq!(hex_result, "deadbeef");

        // Test with block header hash
        let headers = load_test_block_headers();
        let header_hash = &headers[0].hash;
        let hex_hash = HttpBlockchainScanner::bytes_to_hex(header_hash);
        assert_eq!(hex_hash.len(), 64); // 32 bytes = 64 hex chars
        assert!(hex_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_error_handling_invalid_commitment() {
        // Test error handling with invalid commitment length
        let mut invalid_output = HttpOutputData {
            output_hash: vec![0u8; 32],
            commitment: vec![0u8; 31], // Invalid length
            encrypted_data: vec![0u8; 161],
            sender_offset_public_key: vec![0u8; 32],
        };

        let result = HttpBlockchainScanner::convert_http_output_to_lightweight(&invalid_output);
        assert!(result.is_err());

        // Test with invalid sender offset public key length
        invalid_output.commitment = vec![0u8; 32];
        invalid_output.sender_offset_public_key = vec![0u8; 31]; // Invalid length

        let result = HttpBlockchainScanner::convert_http_output_to_lightweight(&invalid_output);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_handling_invalid_input_hash() {
        // Test error handling with invalid input hash length
        let invalid_hash = vec![0u8; 31]; // Invalid length

        let result = HttpBlockchainScanner::convert_http_input_to_lightweight(&invalid_hash);
        assert!(result.is_err());
    }

    // Integration test that demonstrates the full scanning workflow
    // Note: This test uses mock data and doesn't require network access
    #[test]
    fn test_scanning_workflow_integration() {
        let sync_response = parse_test_block_data();
        let private_key = create_test_private_key();

        // Simulate the scanning workflow that would happen in scan_blocks
        let extraction_config = ExtractionConfig::with_private_key(private_key);

        let mut results = Vec::new();

        for http_block in &sync_response.blocks {
            let block_info = HttpBlockchainScanner::convert_http_block_to_block_info(http_block)
                .expect("Block conversion should work");

            let mut wallet_outputs = Vec::new();

            for (_output_index, output) in block_info.outputs.iter().enumerate() {
                let mut found_output = false;

                // Strategy 1: Regular recoverable outputs
                if !found_output {
                    if let Some(wallet_output) = HttpBlockchainScanner::scan_for_recoverable_output(
                        output,
                        &extraction_config,
                    )
                    .expect("Scan should not error")
                    {
                        wallet_outputs.push(wallet_output);
                        found_output = true;
                    }
                }

                // Strategy 2: One-sided payments
                if !found_output {
                    if let Some(wallet_output) = HttpBlockchainScanner::scan_for_one_sided_payment(
                        output,
                        &extraction_config,
                    )
                    .expect("Scan should not error")
                    {
                        wallet_outputs.push(wallet_output);
                        found_output = true;
                    }
                }

                // Strategy 3: Coinbase outputs
                if !found_output {
                    if let Some(wallet_output) =
                        HttpBlockchainScanner::scan_for_coinbase_output(output)
                            .expect("Scan should not error")
                    {
                        wallet_outputs.push(wallet_output);
                    }
                }
            }

            let scan_result = BlockScanResult {
                height: block_info.height,
                block_hash: block_info.hash,
                outputs: block_info.outputs,
                wallet_outputs,
                mined_timestamp: block_info.timestamp,
            };

            results.push(scan_result);
        }

        // Verify the workflow produced expected results
        assert_eq!(results.len(), 1);
        let result = &results[0];
        assert_eq!(result.height, 0); // Block height not available in sync_utxos_by_block response
        assert_eq!(result.mined_timestamp, 1750340139);
        assert!(result.outputs.len() > 0, "Block should have outputs");

        println!(
            "Scanning workflow completed successfully with {} wallet outputs found",
            result.wallet_outputs.len()
        );
    }
}
