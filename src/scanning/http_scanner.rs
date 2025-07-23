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

#![cfg(any(feature = "http", target_arch = "wasm32"))]

// Native targets use reqwest
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
use reqwest::Client;
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
use std::time::Duration;

// WASM targets use web-sys
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use std::time::Duration;

// WASM imports - needed for both web and node
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use web_sys::{Request, RequestInit, RequestMode, Response};

// Web-specific imports (window function) - import even if not wasm-web for other methods
#[cfg(all(feature = "http", target_arch = "wasm32"))]
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
        transaction_output::LightweightTransactionOutput,
        types::{CompressedCommitment, CompressedPublicKey, MicroMinotari, PrivateKey},
        wallet_output::{
            LightweightCovenant, LightweightOutputFeatures, LightweightRangeProof,
            LightweightScript, LightweightSignature, LightweightWalletOutput,
        },
        LightweightOutputType, LightweightRangeProofType,
    },
    errors::{LightweightWalletError, LightweightWalletResult},
    extraction::{extract_wallet_output, ExtractionConfig},
    scanning::{
        BlockInfo, BlockScanResult, BlockchainScanner, DefaultScanningLogic, ProgressCallback,
        ScanConfig, TipInfo, WalletScanConfig, WalletScanResult, WalletScanner,
    },
    wallet::Wallet,
};

/// HTTP API block response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlockResponse {
    pub blocks: Vec<HttpBlockData>,
    pub has_next_page: bool,
}

/// HTTP API input data structure - SIMPLIFIED for actual API response
/// The API returns inputs as simple arrays of 32-byte output hashes that have been spent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInputData {
    /// This is just the 32-byte commitment/output hash that was spent
    /// The API returns inputs as Vec<Vec<u8>> where each inner Vec is 32 bytes
    pub commitment: Vec<u8>,
}

/// HTTP API block data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlockData {
    pub header_hash: Vec<u8>,
    pub height: u64,
    pub outputs: Vec<HttpOutputData>,
    /// Inputs are now just arrays of 32-byte hashes (commitments) that have been spent
    /// This is optional for backward compatibility with older API versions
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

/// HTTP API tip info response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTipInfoMetadata {
    pub best_block_height: u64,
    pub best_block_hash: Vec<u8>,
    pub pruning_horizon: u64,
    pub pruned_height: u64,
    pub accumulated_difficulty: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTipInfoResponse {
    pub metadata: HttpTipInfoMetadata,
    pub is_synced: bool,
}

/// HTTP API search UTXO request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpSearchUtxosRequest {
    pub commitments: Vec<Vec<u8>>,
}

/// HTTP API fetch UTXO request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFetchUtxosRequest {
    pub hashes: Vec<Vec<u8>>,
}

/// HTTP API get blocks request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpGetBlocksRequest {
    pub heights: Vec<u64>,
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
            let client = Client::builder().timeout(timeout).build().map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to create HTTP client: {e}"
                    )),
                )
            })?;

            // Test the connection
            let test_url = format!("{base_url}/get_tip_info");
            let response = client.get(&test_url).send().await;
            if response.is_err() {
                return Err(LightweightWalletError::ScanningError(
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
            // WASM environment - test connection and create scanner
            let test_url = format!("{}/get_tip_info", base_url);

            let opts = RequestInit::new();
            opts.set_method("GET");
            opts.set_mode(RequestMode::Cors);

            let request = Request::new_with_str_and_init(&test_url, &opts)?;

            // Try to make a test request to verify connectivity
            // We'll use runtime detection in fetch_request
            let scanner = Self { base_url };
            let _resp = scanner.fetch_request(&request).await?;

            Ok(scanner)
        }
    }

    /// Perform a fetch request using the appropriate method for the target environment
    #[cfg(all(feature = "http", target_arch = "wasm32"))]
    async fn fetch_request(&self, request: &Request) -> Result<Response, LightweightWalletError> {
        #[cfg(feature = "wasm-node")]
        {
            // Node.js environment - use global fetch
            let global = js_sys::global();

            if let Ok(fetch_fn) = js_sys::Reflect::get(&global, &JsValue::from_str("fetch")) {
                if let Ok(fetch_fn) = fetch_fn.dyn_into::<js_sys::Function>() {
                    let resp_value = JsFuture::from(js_sys::Promise::from(
                        fetch_fn.call1(&global, request).map_err(|_| {
                            LightweightWalletError::ScanningError(
                                crate::errors::ScanningError::blockchain_connection_failed(
                                    "Failed to call fetch function",
                                ),
                            )
                        })?,
                    ))
                    .await
                    .map_err(|_| {
                        LightweightWalletError::ScanningError(
                            crate::errors::ScanningError::blockchain_connection_failed(
                                "Fetch request failed",
                            ),
                        )
                    })?;

                    return resp_value.dyn_into::<Response>().map_err(|_| {
                        LightweightWalletError::ScanningError(
                            crate::errors::ScanningError::blockchain_connection_failed(
                                "Invalid response type",
                            ),
                        )
                    });
                }
            }

            return Err(LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(
                    "No fetch function available in Node.js environment",
                ),
            ));
        }

        #[cfg(feature = "wasm-web")]
        {
            // Browser environment - use web-sys window.fetch
            let window = web_sys::window().ok_or_else(|| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "No window object available",
                    ),
                )
            })?;

            let resp_value = JsFuture::from(window.fetch_with_request(request))
                .await
                .map_err(|_| {
                    LightweightWalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(
                            "Fetch request failed",
                        ),
                    )
                })?;

            return resp_value.dyn_into::<Response>().map_err(|_| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Invalid response type",
                    ),
                )
            });
        }

        #[cfg(not(any(feature = "wasm-node", feature = "wasm-web")))]
        {
            // Fallback error - should not reach here in normal builds
            Err(LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(
                    "No WASM fetch implementation available",
                ),
            ))
        }
    }

    /// Create a new HTTP scanner with custom timeout (native only)
    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    pub async fn with_timeout(
        base_url: String,
        timeout: Duration,
    ) -> LightweightWalletResult<Self> {
        let client = Client::builder().timeout(timeout).build().map_err(|e| {
            LightweightWalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Failed to create HTTP client: {e}"
                )),
            )
        })?;

        // Test the connection
        let test_url = format!("{base_url}/get_tip_info");
        let response = client.get(&test_url).send().await;
        if response.is_err() {
            return Err(LightweightWalletError::ScanningError(
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
    pub async fn with_timeout(
        base_url: String,
        _timeout: Duration,
    ) -> LightweightWalletResult<Self> {
        // WASM doesn't support timeouts in the same way, so we ignore the timeout parameter
        Self::new(base_url).await
    }

    /// Convert HTTP output data to LightweightTransactionOutput
    fn convert_http_output_to_lightweight(
        http_output: &HttpOutputData,
    ) -> LightweightWalletResult<LightweightTransactionOutput> {
        // Parse commitment
        if http_output.commitment.len() != 32 {
            return Err(LightweightWalletError::ConversionError(
                "Invalid commitment length, expected 32 bytes".to_string(),
            ));
        }
        let commitment =
            CompressedCommitment::new(http_output.commitment.clone().try_into().map_err(|_| {
                LightweightWalletError::ConversionError("Failed to convert commitment".to_string())
            })?);

        // Parse sender offset public key
        if http_output.sender_offset_public_key.len() != 32 {
            return Err(LightweightWalletError::ConversionError(
                "Invalid sender offset public key length, expected 32 bytes".to_string(),
            ));
        }
        let sender_offset_public_key = CompressedPublicKey::new(
            http_output
                .sender_offset_public_key
                .clone()
                .try_into()
                .map_err(|_| {
                    LightweightWalletError::ConversionError(
                        "Failed to convert sender offset public key".to_string(),
                    )
                })?,
        );

        // Parse encrypted data
        let encrypted_data =
            EncryptedData::from_bytes(&http_output.encrypted_data).map_err(|e| {
                LightweightWalletError::ConversionError(format!("Invalid encrypted data: {e}"))
            })?;

        // Convert features
        let features = http_output
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

        // Convert range proof
        let proof = http_output
            .range_proof
            .as_ref()
            .map(|rp| LightweightRangeProof { bytes: rp.clone() });

        // Convert script
        let script = LightweightScript {
            bytes: http_output.script.clone().unwrap_or_default(),
        };

        // Convert metadata signature
        let metadata_signature = http_output
            .metadata_signature
            .as_ref()
            .map(|sig| LightweightSignature { bytes: sig.clone() })
            .unwrap_or_default();

        // Convert covenant
        let covenant = LightweightCovenant {
            bytes: http_output.covenant.clone().unwrap_or_default(),
        };

        // Convert minimum value promise
        let minimum_value_promise =
            MicroMinotari::new(http_output.minimum_value_promise.unwrap_or(0));

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

    /// Convert HTTP input data to TransactionInput - SIMPLIFIED VERSION
    /// Since the API only provides output hashes, we create minimal TransactionInput objects
    /// Note: The HTTP inputs array contains OUTPUT HASHES of spent outputs, not commitments
    fn convert_http_input_to_lightweight(
        output_hash_bytes: &[u8],
    ) -> LightweightWalletResult<TransactionInput> {
        // Parse output hash
        if output_hash_bytes.len() != 32 {
            return Err(LightweightWalletError::ConversionError(
                "Invalid output hash length, expected 32 bytes".to_string(),
            ));
        }
        let mut output_hash = [0u8; 32];
        output_hash.copy_from_slice(output_hash_bytes);

        // Create minimal TransactionInput with the output hash
        // We don't have the commitment from the HTTP API, so we use zeros as placeholder
        // The important field is output_hash which we use for matching spent outputs
        Ok(TransactionInput::new(
            1,                                                                           // version
            0,                              // features (default)
            [0u8; 32], // commitment (not available from HTTP API, use placeholder)
            [0u8; 64], // script_signature (not available)
            CompressedPublicKey::default(), // sender_offset_public_key (not available)
            Vec::new(), // covenant (not available)
            crate::data_structures::transaction_input::LightweightExecutionStack::new(), // input_data (not available)
            output_hash,           // output_hash (this is the actual data from HTTP API)
            0,                     // output_features (not available)
            [0u8; 64],             // output_metadata_signature (not available)
            0,                     // maturity (not available)
            MicroMinotari::new(0), // value (not available)
        ))
    }

    /// Convert HTTP block data to BlockInfo - UPDATED for simplified inputs
    fn convert_http_block_to_block_info(
        http_block: &HttpBlockData,
    ) -> LightweightWalletResult<BlockInfo> {
        let outputs = http_block
            .outputs
            .iter()
            .map(Self::convert_http_output_to_lightweight)
            .collect::<LightweightWalletResult<Vec<_>>>()?;

        // Handle simplified inputs structure
        let inputs = http_block
            .inputs
            .as_ref()
            .map(|input_hashes| {
                input_hashes
                    .iter()
                    .map(|hash_bytes| Self::convert_http_input_to_lightweight(hash_bytes))
                    .collect::<LightweightWalletResult<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();

        // Preserve original HTTP output hashes for accurate spending detection
        let http_output_hashes = Some(
            http_block
                .outputs
                .iter()
                .map(|output| output.output_hash.clone())
                .collect::<Vec<Vec<u8>>>(),
        );

        Ok(BlockInfo {
            height: http_block.height,
            hash: http_block.header_hash.clone(),
            timestamp: http_block.mined_timestamp,
            outputs,
            inputs,
            kernels: Vec::new(), // HTTP API doesn't provide kernels in this format
            http_output_hashes,
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
        output: &LightweightTransactionOutput,
        extraction_config: &ExtractionConfig,
    ) -> LightweightWalletResult<Option<LightweightWalletOutput>> {
        // Skip non-payment outputs for this scan type
        if !matches!(
            output.features().output_type,
            LightweightOutputType::Payment
        ) {
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
        if !matches!(
            output.features().output_type,
            LightweightOutputType::Payment
        ) {
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
        if !matches!(
            output.features().output_type,
            LightweightOutputType::Coinbase
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

    /// Fetch blocks by heights using HTTP API - converts to header-based requests
    async fn fetch_blocks_by_heights(
        &self,
        heights: Vec<u64>,
    ) -> LightweightWalletResult<HttpBlockResponse> {
        // Sort heights for sequential processing
        let mut sorted_heights = heights;
        sorted_heights.sort();

        if sorted_heights.is_empty() {
            return Ok(HttpBlockResponse {
                blocks: vec![],
                has_next_page: false,
            });
        }

        // For the Tari base node API, we need to fetch blocks sequentially using header hashes
        // We will fetch each height individually

        // Fetch blocks for all heights individually using the base node API
        let mut all_blocks = Vec::new();

        for &height in &sorted_heights {
            match self.get_header_by_height(height).await {
                Ok(block_response) => {
                    // Add all blocks from this response to our collection
                    all_blocks.extend(block_response.blocks);
                }
                Err(e) => {
                    eprintln!("Failed to fetch block at height {}: {}", height, e);
                    // Continue with other blocks rather than failing completely
                }
            }
        }

        Ok(HttpBlockResponse {
            blocks: all_blocks,
            has_next_page: false, // We've fetched the specific heights requested
        })
    }

    /// Get header by height using Tari base node API
    async fn get_header_by_height(
        &self,
        height: u64,
    ) -> LightweightWalletResult<HttpBlockResponse> {
        let url = format!("{}/get_header_by_height", self.base_url);

        // Create request body with height
        let request_body = serde_json::json!({
            "height": height
        });

        // Native implementation using reqwest
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let response = self
                .client
                .post(&url)
                .json(&request_body)
                .send()
                .await
                .map_err(|e| {
                    LightweightWalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(&format!(
                            "HTTP request failed: {e}"
                        )),
                    )
                })?;

            if !response.status().is_success() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            let http_response: HttpBlockResponse = response.json().await.map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to parse response: {e}"
                    )),
                )
            })?;

            Ok(http_response)
        }

        // WASM implementation using web-sys
        #[cfg(all(feature = "http", target_arch = "wasm32"))]
        {
            let json_body = serde_json::to_string(&request_body).map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to serialize request: {}",
                        e
                    )),
                )
            })?;

            let opts = RequestInit::new();
            opts.set_method("POST");
            opts.set_mode(RequestMode::Cors);
            opts.set_body(&JsValue::from_str(&json_body));

            let request = Request::new_with_str_and_init(&url, &opts)?;

            // Set Content-Type header
            request.headers().set("Content-Type", "application/json")?;

            let response: Response = self.fetch_request(&request).await.map_err(|_| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Invalid response type",
                    ),
                )
            })?;

            if !response.ok() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            // Get JSON response
            let json_promise = response.json().map_err(|_| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Failed to get JSON response",
                    ),
                )
            })?;

            let json_value = JsFuture::from(json_promise).await.map_err(|_| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Failed to parse JSON response",
                    ),
                )
            })?;

            // Convert JsValue to our struct using serde-wasm-bindgen
            let http_response: HttpBlockResponse = serde_wasm_bindgen::from_value(json_value)
                .map_err(|e| {
                    LightweightWalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(&format!(
                            "Failed to deserialize response: {}",
                            e
                        )),
                    )
                })?;

            Ok(http_response)
        }
    }

    /// Helper method to process HTTP response into block scan results
    async fn process_http_response_to_block_scan_results(
        &self,
        http_response: HttpBlockResponse,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
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
                        debug!(
                            "Failed to extract wallet output during commitment search: {}",
                            _e
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
}

#[cfg(feature = "http")]
#[async_trait(?Send)]
impl BlockchainScanner for HttpBlockchainScanner {
    async fn scan_blocks(
        &mut self,
        config: ScanConfig,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
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

        let mut results = Vec::new();
        let mut current_height = config.start_height;

        while current_height <= end_height {
            let batch_end = std::cmp::min(current_height + config.batch_size - 1, end_height);
            let heights: Vec<u64> = (current_height..=batch_end).collect();

            // Fetch blocks for this batch
            let http_response = self.fetch_blocks_by_heights(heights).await?;

            for http_block in http_response.blocks {
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

            current_height = batch_end + 1;
        }

        #[cfg(feature = "tracing")]
        debug!(
            "HTTP scan completed, found {} blocks with wallet outputs",
            results.len()
        );
        Ok(results)
    }

    async fn get_tip_info(&mut self) -> LightweightWalletResult<TipInfo> {
        let url = format!("{}/get_tip_info", self.base_url);

        // Native implementation using reqwest
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let response = self.client.get(&url).send().await.map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP request failed: {e}"
                    )),
                )
            })?;

            if !response.status().is_success() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            let tip_response: HttpTipInfoResponse = response.json().await.map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to parse response: {e}"
                    )),
                )
            })?;

            Ok(TipInfo {
                best_block_height: tip_response.metadata.best_block_height,
                best_block_hash: tip_response.metadata.best_block_hash,
                accumulated_difficulty: hex::decode(&tip_response.metadata.accumulated_difficulty)
                    .unwrap_or_default(),
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

            let response = self.fetch_request(&request).await?;

            if !response.ok() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            // Get JSON response
            let json_promise = response.json().map_err(|_| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Failed to get JSON response",
                    ),
                )
            })?;

            let json_value = JsFuture::from(json_promise).await.map_err(|_| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Failed to parse JSON response",
                    ),
                )
            })?;

            let tip_response: HttpTipInfoResponse = serde_wasm_bindgen::from_value(json_value)
                .map_err(|e| {
                    LightweightWalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(&format!(
                            "Failed to deserialize response: {}",
                            e
                        )),
                    )
                })?;

            Ok(TipInfo {
                best_block_height: tip_response.metadata.best_block_height,
                best_block_hash: tip_response.metadata.best_block_hash,
                accumulated_difficulty: hex::decode(&tip_response.metadata.accumulated_difficulty)
                    .unwrap_or_default(),
                pruned_height: tip_response.metadata.pruned_height,
                timestamp: tip_response.metadata.timestamp,
            })
        }
    }

    async fn search_utxos(
        &mut self,
        commitments: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
        let url = format!("{}/api/search_utxos", self.base_url);
        let request = HttpSearchUtxosRequest { commitments };

        // Native implementation using reqwest
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let response = self
                .client
                .post(&url)
                .json(&request)
                .send()
                .await
                .map_err(|e| {
                    LightweightWalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(&format!(
                            "HTTP request failed: {e}"
                        )),
                    )
                })?;

            if !response.status().is_success() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            let http_response: HttpBlockResponse = response.json().await.map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to parse response: {e}"
                    )),
                )
            })?;

            self.process_http_response_to_block_scan_results(http_response)
                .await
        }

        // WASM implementation using web-sys
        #[cfg(all(feature = "http", target_arch = "wasm32"))]
        {
            let json_body = serde_json::to_string(&request).map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to serialize request: {}",
                        e
                    )),
                )
            })?;

            let opts = RequestInit::new();
            opts.set_method("POST");
            opts.set_mode(RequestMode::Cors);
            opts.set_body(&JsValue::from_str(&json_body));

            let request = Request::new_with_str_and_init(&url, &opts)?;

            // Set Content-Type header
            request.headers().set("Content-Type", "application/json")?;

            let response = self.fetch_request(&request).await?;

            if !response.ok() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            // Get JSON response
            let json_promise = response.json().map_err(|_| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Failed to get JSON response",
                    ),
                )
            })?;

            let json_value = JsFuture::from(json_promise).await.map_err(|_| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Failed to parse JSON response",
                    ),
                )
            })?;

            let http_response: HttpBlockResponse = serde_wasm_bindgen::from_value(json_value)
                .map_err(|e| {
                    LightweightWalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(&format!(
                            "Failed to deserialize response: {}",
                            e
                        )),
                    )
                })?;

            self.process_http_response_to_block_scan_results(http_response)
                .await
        }
    }

    async fn fetch_utxos(
        &mut self,
        hashes: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<Vec<LightweightTransactionOutput>> {
        let url = format!("{}/api/fetch_utxos", self.base_url);
        let request = HttpFetchUtxosRequest { hashes };

        // Native implementation using reqwest
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let response = self
                .client
                .post(&url)
                .json(&request)
                .send()
                .await
                .map_err(|e| {
                    LightweightWalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(&format!(
                            "HTTP request failed: {e}"
                        )),
                    )
                })?;

            if !response.status().is_success() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            let outputs: Vec<HttpOutputData> = response.json().await.map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to parse response: {e}"
                    )),
                )
            })?;

            Ok(self.convert_http_outputs_to_lightweight(&outputs)?)
        }

        // WASM implementation using web-sys
        #[cfg(all(feature = "http", target_arch = "wasm32"))]
        {
            let json_body = serde_json::to_string(&request).map_err(|e| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to serialize request: {}",
                        e
                    )),
                )
            })?;

            let opts = RequestInit::new();
            opts.set_method("POST");
            opts.set_mode(RequestMode::Cors);
            opts.set_body(&JsValue::from_str(&json_body));

            let request = Request::new_with_str_and_init(&url, &opts)?;

            // Set Content-Type header
            request.headers().set("Content-Type", "application/json")?;

            let response = self.fetch_request(&request).await?;

            if !response.ok() {
                return Err(LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            // Get JSON response
            let json_promise = response.json().map_err(|_| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Failed to get JSON response",
                    ),
                )
            })?;

            let json_value = JsFuture::from(json_promise).await.map_err(|_| {
                LightweightWalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Failed to parse JSON response",
                    ),
                )
            })?;

            let outputs: Vec<HttpOutputData> =
                serde_wasm_bindgen::from_value(json_value).map_err(|e| {
                    LightweightWalletError::ScanningError(
                        crate::errors::ScanningError::blockchain_connection_failed(&format!(
                            "Failed to deserialize response: {}",
                            e
                        )),
                    )
                })?;

            Ok(self.convert_http_outputs_to_lightweight(&outputs)?)
        }
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

#[cfg(feature = "http")]
impl HttpBlockchainScanner {
    /// Convert HTTP output data to LightweightTransactionOutput (minimal viable format)
    fn convert_http_outputs_to_lightweight(
        &self,
        http_outputs: &[HttpOutputData],
    ) -> LightweightWalletResult<Vec<LightweightTransactionOutput>> {
        let mut outputs = Vec::new();

        for http_output in http_outputs {
            // Parse commitment
            if http_output.commitment.len() != 32 {
                return Err(LightweightWalletError::DataStructureError(
                    crate::errors::DataStructureError::invalid_output_value(
                        "Invalid commitment length, expected 32 bytes",
                    ),
                ));
            }
            let commitment = CompressedCommitment::new(
                http_output.commitment.clone().try_into().map_err(|_| {
                    LightweightWalletError::DataStructureError(
                        crate::errors::DataStructureError::invalid_output_value(
                            "Failed to convert commitment",
                        ),
                    )
                })?,
            );

            // Parse sender offset public key
            if http_output.sender_offset_public_key.len() != 32 {
                return Err(LightweightWalletError::DataStructureError(
                    crate::errors::DataStructureError::invalid_output_value(
                        "Invalid sender offset public key length, expected 32 bytes",
                    ),
                ));
            }
            let sender_offset_public_key = CompressedPublicKey::new(
                http_output
                    .sender_offset_public_key
                    .clone()
                    .try_into()
                    .map_err(|_| {
                        LightweightWalletError::DataStructureError(
                            crate::errors::DataStructureError::invalid_output_value(
                                "Failed to convert sender offset public key",
                            ),
                        )
                    })?,
            );

            // Parse encrypted data
            let encrypted_data =
                EncryptedData::from_bytes(&http_output.encrypted_data).map_err(|e| {
                    LightweightWalletError::DataStructureError(
                        crate::errors::DataStructureError::invalid_output_value(&format!(
                            "Invalid encrypted data: {e}"
                        )),
                    )
                })?;

            // Create LightweightTransactionOutput with minimal viable data
            // HTTP API provides limited data, so we use defaults for missing fields
            let output = LightweightTransactionOutput::new_current_version(
                LightweightOutputFeatures::default(), // Default features (will be 0/Standard)
                commitment,
                None,                         // Range proof not provided in HTTP API
                LightweightScript::default(), // Script not provided, use empty/default
                sender_offset_public_key,
                LightweightSignature::default(), // Metadata signature not provided, use default
                LightweightCovenant::default(),  // Covenant not provided, use default
                encrypted_data,
                MicroMinotari::from(0u64), // Minimum value promise not provided, use 0
            );

            outputs.push(output);
        }

        Ok(outputs)
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
        let base_url = self.base_url.ok_or_else(|| {
            LightweightWalletError::ConfigurationError("Base URL not specified".to_string())
        })?;

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

// Placeholder module for when HTTP feature is not enabled
#[cfg(not(feature = "http"))]
pub struct HttpBlockchainScanner;

#[cfg(not(feature = "http"))]
impl HttpBlockchainScanner {
    pub async fn new(_base_url: String) -> crate::errors::LightweightWalletResult<Self> {
        Err(
            crate::errors::LightweightWalletError::OperationNotSupported(
                "HTTP feature not enabled".to_string(),
            ),
        )
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
        Err(
            crate::errors::LightweightWalletError::OperationNotSupported(
                "HTTP feature not enabled".to_string(),
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_http_scanner_builder() {
        let builder = HttpScannerBuilder::new()
            .with_base_url("http://127.0.0.1:18142".to_string())
            .with_timeout(Duration::from_secs(10));

        // Note: This will fail if no server is running, but tests the builder pattern
        let result = builder.build().await;
        assert!(result.is_err()); // Expected to fail in test environment
    }

    #[test]
    fn test_http_output_conversion() {
        let http_output = HttpOutputData {
            output_hash: vec![0u8; 32],
            commitment: vec![1u8; 32],
            encrypted_data: vec![1u8; 80], // Provide minimum required bytes for encrypted data
            sender_offset_public_key: vec![2u8; 32],
            features: Some(HttpOutputFeatures {
                output_type: 0,
                maturity: 0,
                range_proof_type: 0,
            }),
            script: None,
            metadata_signature: None,
            covenant: None,
            minimum_value_promise: Some(0),
            range_proof: None,
        };

        let result = HttpBlockchainScanner::convert_http_output_to_lightweight(&http_output);
        assert!(result.is_ok());
    }

    #[test]
    fn test_http_block_data_json_parsing_without_inputs() {
        // Test JSON without inputs field (current API)
        let json_without_inputs = r#"{
            "header_hash": [1, 2, 3, 4],
            "height": 12345,
            "outputs": [],
            "mined_timestamp": 1748298680
        }"#;

        let result: Result<HttpBlockData, serde_json::Error> =
            serde_json::from_str(json_without_inputs);
        assert!(result.is_ok());
        let block_data = result.unwrap();
        assert_eq!(block_data.height, 12345);
        assert!(block_data.inputs.is_none());
    }

    #[test]
    fn test_http_block_data_json_parsing_with_inputs() {
        // Test JSON with inputs field (future API)
        let json_with_inputs = r#"{
            "header_hash": [1, 2, 3, 4],
            "height": 12345,
            "outputs": [],
            "inputs": [],
            "mined_timestamp": 1748298680
        }"#;

        let result: Result<HttpBlockData, serde_json::Error> =
            serde_json::from_str(json_with_inputs);
        assert!(result.is_ok());
        let block_data = result.unwrap();
        assert_eq!(block_data.height, 12345);
        assert!(block_data.inputs.is_some());
        assert_eq!(block_data.inputs.unwrap().len(), 0);
    }

    #[test]
    fn test_http_block_data_json_parsing_realistic() {
        // Test with a structure more similar to the actual API response
        let realistic_json = r#"{
            "header_hash": [231, 255, 164, 211, 0, 70, 4, 43, 228, 117, 57, 30, 28, 158, 164, 27, 159, 146, 97, 112, 63, 88, 121, 180, 192, 8, 246, 238, 220, 113, 249, 98],
            "height": 1234567,
            "outputs": [
                {
                    "output_hash": [236, 175, 136, 57, 202, 44, 147, 168, 33, 102, 64, 24, 131, 245, 50, 123, 1, 193, 158, 192, 79, 168, 104, 180, 28, 101, 239, 255, 235, 137, 169, 231],
                    "commitment": [236, 247, 186, 249, 183, 8, 249, 103, 238, 32, 98, 6, 234, 222, 124, 29, 39, 154, 86, 159, 235, 104, 243, 172, 19, 166, 60, 254, 63, 26, 191, 77],
                    "encrypted_data": [172, 214, 115, 5, 92, 254, 168, 41, 177, 156, 217, 118, 48, 97, 148],
                    "sender_offset_public_key": [178, 35, 220, 210, 106, 214, 63, 27, 83, 76, 53, 154, 208, 114, 162, 165, 134, 176, 107, 102, 49, 74, 191, 157, 91, 175, 68, 162, 107, 48, 99, 10]
                }
            ],
            "mined_timestamp": 1748298680
        }"#;

        let result: Result<HttpBlockData, serde_json::Error> = serde_json::from_str(realistic_json);
        assert!(result.is_ok());
        let block_data = result.unwrap();
        assert_eq!(block_data.height, 1234567);
        assert!(block_data.inputs.is_none()); // No inputs field in the JSON
        assert_eq!(block_data.outputs.len(), 1);
        assert_eq!(block_data.mined_timestamp, 1748298680);
    }
}
