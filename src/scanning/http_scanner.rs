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
        wallet_output::{
            Covenant, OutputFeatures,
            Script, Signature, WalletOutput,
        },
        OutputType, LightweightRangeProofType,
    },
    errors::{WalletError, WalletResult},
    extraction::{extract_wallet_output, ExtractionConfig},
    scanning::{
        BlockInfo, BlockScanResult, BlockchainScanner, ScanConfig, TipInfo,
    },
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

    /// Convert HTTP output data to LightweightTransactionOutput
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

        // Parse encrypted data
        let encrypted_data =
            EncryptedData::from_bytes(&http_output.encrypted_data).map_err(|e| {
                WalletError::ConversionError(format!("Invalid encrypted data: {e}"))
            })?;

        // Convert features
        let features = http_output
            .features
            .as_ref()
            .map(|f| OutputFeatures {
                output_type: match f.output_type {
                    0 => OutputType::Payment,
                    1 => OutputType::Coinbase,
                    2 => OutputType::Burn,
                    3 => OutputType::ValidatorNodeRegistration,
                    4 => OutputType::CodeTemplateRegistration,
                    _ => OutputType::Payment,
                },
                maturity: f.maturity,
                range_proof_type: LightweightRangeProofType::BulletProofPlus, // Default
            })
            .unwrap_or_default();

        // Convert range proof (not provided by this API endpoint)
        let proof = None;

        // Convert script
        let script = Script {
            bytes: http_output.script.clone().unwrap_or_default(),
        };

        // Convert metadata signature
        let metadata_signature = http_output
            .metadata_signature
            .as_ref()
            .map(|sig| Signature { bytes: sig.clone() })
            .unwrap_or_default();

        // Convert covenant
        let covenant = Covenant {
            bytes: http_output.covenant.clone().unwrap_or_default(),
        };

        // Convert minimum value promise
        let minimum_value_promise =
            MicroMinotari::new(http_output.minimum_value_promise.unwrap_or(0));

        Ok(TransactionOutput::new_current_version(
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
            1,                                                                           // version
            0,                              // features (default)
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
            .as_ref()
            .map(|input_hashes| {
                input_hashes
                    .iter()
                    .map(|hash_bytes| Self::convert_http_input_to_lightweight(hash_bytes))
                    .collect::<WalletResult<Vec<_>>>()
            })
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
        if !matches!(
            output.features().output_type,
            OutputType::Payment
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
        output: &TransactionOutput,
        extraction_config: &ExtractionConfig,
    ) -> WalletResult<Option<WalletOutput>> {
        // Skip non-payment outputs for this scan type
        if !matches!(
            output.features().output_type,
            OutputType::Payment
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
        output: &TransactionOutput,
    ) -> WalletResult<Option<WalletOutput>> {
        // Only handle coinbase outputs
        if !matches!(
            output.features().output_type,
            OutputType::Coinbase
        ) {
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
    ) -> WalletResult<Vec<HttpBlockUtxoInfo>> {
        // Get the starting header hash
        let start_header = self.get_header_by_height(start_height).await?;
        let mut current_header_hash = Self::bytes_to_hex(&start_header.hash);

        let mut all_blocks = Vec::new();
        let mut current_height = start_height;

        while current_height <= end_height {
            // Use sync_utxos_by_block to get batch of blocks
            let sync_response = self.sync_utxos_by_block(&current_header_hash).await?;

            if sync_response.blocks.is_empty() {
                #[cfg(feature = "tracing")]
                debug!("No more blocks available from base node");
                break;
            }

            // Filter blocks within our target range
            for block in sync_response.blocks {
                if block.height >= start_height && block.height <= end_height {
                    all_blocks.push(block.clone());
                    current_height = std::cmp::max(current_height, block.height + 1);
                }
            }

            // Check if we have a next header to continue with
            if let Some(next_header) = sync_response.next_header_to_scan {
                current_header_hash = Self::bytes_to_hex(&next_header);
                #[cfg(feature = "tracing")]
                debug!(
                    "Continuing with next header: {}",
                    &current_header_hash[..16]
                );
            } else {
                #[cfg(feature = "tracing")]
                debug!("No more headers to scan, reached end of available data");
                break;
            }

            // Safety check to prevent infinite loops
            if current_height > end_height {
                break;
            }
        }

        // Sort blocks by height
        all_blocks.sort_by_key(|block| block.height);

        #[cfg(feature = "tracing")]
        debug!(
            "Fetched {} blocks in range {} to {}",
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

    async fn fetch_utxos(
        &mut self,
        _hashes: Vec<Vec<u8>>,
    ) -> WalletResult<Vec<TransactionOutput>> {
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
            WalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Failed to parse block response for height {height}: {e}"
                )),
            )
        })?;

        let block = block_response.block;
        Ok(Some(BlockInfo {
            height: block.header.height,
            hash: hex::decode(&block.header.hash).map_err(|_| {
                WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(
                        "Invalid block hash format"
                    ),
                )
            })?,
            outputs: block.body.outputs,
            inputs: Vec::new(), // HTTP API doesn't provide input details
            kernels: Vec::new(), // HTTP API doesn't provide kernel details
            timestamp: block.header.timestamp,
        }))
    }
}
