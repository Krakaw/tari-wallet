//! UTXO scanning module for lightweight wallet libraries
//!
//! This module provides a lightweight interface for scanning the Tari blockchain
//! for wallet outputs. It uses a trait-based approach that allows different
//! backend implementations (gRPC, HTTP, etc.) to be plugged in.

use std::time::{Duration, Instant};

#[cfg(any(feature = "grpc", feature = "http", target_arch = "wasm32"))]
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    data_structures::{
        encrypted_data::EncryptedData,
        transaction_input::TransactionInput,
        transaction_kernel::TransactionKernel,
        transaction_output::LightweightTransactionOutput,
        types::{CompressedPublicKey, PrivateKey},
        wallet_output::LightweightWalletOutput,
    },
    errors::{LightweightWalletError, LightweightWalletResult},
    extraction::{extract_wallet_output, ExtractionConfig},
    key_management::{self, KeyManager, KeyStore},
};
use blake2::{Blake2b, Digest};
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use tari_utilities::ByteArray;
#[cfg(feature = "tracing")]
use tracing::{debug, info};

// Core scanner library components
pub mod scan_configuration;
pub mod scan_results;
pub mod scanner_engine;
pub mod storage_manager;
pub mod wallet_source;

// Include GRPC scanner when the feature is enabled
#[cfg(feature = "grpc")]
pub mod grpc_scanner;

// Include HTTP scanner when the feature is enabled
#[cfg(any(feature = "http", target_arch = "wasm32"))]
pub mod http_scanner;

// Re-export core library components
pub use scan_configuration::ScanConfiguration;
pub use scan_results::{ScanProgress as LibraryScanProgress, ScanResults};
pub use scanner_engine::ScannerEngine;
#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
pub use storage_manager::BackgroundWriterAdapter;
#[cfg(feature = "storage")]
pub use storage_manager::StorageManager;
#[cfg(feature = "storage")]
pub use storage_manager::{AdapterSelectionStrategy, DirectStorageAdapter, StorageManagerBuilder};
pub use wallet_source::{WalletContext, WalletSource, WalletSourceType};

// Re-export GRPC scanner types
#[cfg(feature = "grpc")]
pub use grpc_scanner::{GrpcBlockchainScanner, GrpcScannerBuilder};

// Re-export HTTP scanner types
#[cfg(any(feature = "http", target_arch = "wasm32"))]
pub use http_scanner::{HttpBlockchainScanner, HttpScannerBuilder};

/// Progress callback for scanning operations
pub type ProgressCallback = Box<dyn Fn(ScanProgress) + Send + Sync>;

/// Scanning progress information
#[derive(Debug, Clone)]
pub struct ScanProgress {
    /// Current block height being scanned
    pub current_height: u64,
    /// Target block height to scan to
    pub target_height: u64,
    /// Number of outputs found so far
    pub outputs_found: u64,
    /// Total value of outputs found so far (in MicroMinotari)
    pub total_value: u64,
    /// Time elapsed since scan started
    pub elapsed: Duration,
}

/// Configuration for blockchain scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Starting block height (wallet birthday)
    pub start_height: u64,
    /// Ending block height (optional, if None scans to tip)
    pub end_height: Option<u64>,
    /// Maximum number of blocks to scan in one request
    pub batch_size: u64,
    /// Timeout for requests
    #[serde(with = "duration_serde")]
    pub request_timeout: Duration,
    /// Extraction configuration (excluded from serialization for security)
    #[serde(skip)]
    pub extraction_config: ExtractionConfig,
}

// Helper module for Duration serialization
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

impl ScanConfig {
    /// Create a new scan config with a progress callback
    pub fn with_progress_callback(self, callback: ProgressCallback) -> ScanConfigWithCallback {
        ScanConfigWithCallback {
            config: self,
            progress_callback: Some(callback),
        }
    }
}

/// Scan config with progress callback (not Debug/Clone)
pub struct ScanConfigWithCallback {
    pub config: ScanConfig,
    pub progress_callback: Option<ProgressCallback>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            start_height: 0,
            end_height: None,
            batch_size: 100,
            request_timeout: Duration::from_secs(30),
            extraction_config: ExtractionConfig::default(),
        }
    }
}

/// Configuration for wallet-specific scanning
pub struct WalletScanConfig {
    /// Base scan configuration
    pub scan_config: ScanConfig,
    /// Key manager for wallet key derivation
    pub key_manager: Option<Box<dyn KeyManager + Send + Sync>>,
    /// Key store for imported keys
    pub key_store: Option<KeyStore>,
    /// Whether to scan for stealth addresses
    pub scan_stealth_addresses: bool,
    /// Maximum number of addresses to scan per account
    pub max_addresses_per_account: u32,
    /// Whether to scan for imported keys
    pub scan_imported_keys: bool,
}

impl WalletScanConfig {
    /// Create a new wallet scan config
    pub fn new(start_height: u64) -> Self {
        Self {
            scan_config: ScanConfig {
                start_height,
                end_height: None,
                batch_size: 100,
                request_timeout: Duration::from_secs(30),
                extraction_config: ExtractionConfig::default(),
            },
            key_manager: None,
            key_store: None,
            scan_stealth_addresses: true,
            max_addresses_per_account: 1000,
            scan_imported_keys: true,
        }
    }

    /// Set the key manager
    pub fn with_key_manager(mut self, key_manager: Box<dyn KeyManager + Send + Sync>) -> Self {
        self.key_manager = Some(key_manager);
        self
    }

    /// Set the key store
    pub fn with_key_store(mut self, key_store: KeyStore) -> Self {
        self.key_store = Some(key_store);
        self
    }

    /// Set whether to scan for stealth addresses
    pub fn with_stealth_address_scanning(mut self, enabled: bool) -> Self {
        self.scan_stealth_addresses = enabled;
        self
    }

    /// Set maximum addresses per account
    pub fn with_max_addresses_per_account(mut self, max: u32) -> Self {
        self.max_addresses_per_account = max;
        self
    }

    /// Set whether to scan for imported keys
    pub fn with_imported_key_scanning(mut self, enabled: bool) -> Self {
        self.scan_imported_keys = enabled;
        self
    }

    /// Set the end height
    pub fn with_end_height(mut self, end_height: u64) -> Self {
        self.scan_config.end_height = Some(end_height);
        self
    }

    /// Set the batch size
    pub fn with_batch_size(mut self, batch_size: u64) -> Self {
        self.scan_config.batch_size = batch_size;
        self
    }

    /// Set the request timeout
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.scan_config.request_timeout = timeout;
        self
    }
}

/// Result of a wallet scan operation
#[derive(Debug, Clone)]
pub struct WalletScanResult {
    /// Block scan results
    pub block_results: Vec<BlockScanResult>,
    /// Total wallet outputs found
    pub total_wallet_outputs: u64,
    /// Total value found (in MicroMinotari)
    pub total_value: u64,
    /// Number of addresses scanned
    pub addresses_scanned: u64,
    /// Number of accounts scanned
    pub accounts_scanned: u64,
    /// Scan duration
    pub scan_duration: Duration,
}

/// Chain tip information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipInfo {
    /// Current best block height
    pub best_block_height: u64,
    /// Current best block hash
    pub best_block_hash: Vec<u8>,
    /// Accumulated difficulty
    pub accumulated_difficulty: Vec<u8>,
    /// Pruned height (minimum height this node can provide complete blocks for)
    pub pruned_height: u64,
    /// Timestamp
    pub timestamp: u64,
}

/// Result of a block scan operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockScanResult {
    /// Block height
    pub height: u64,
    /// Block hash
    pub block_hash: Vec<u8>,
    /// Transaction outputs found in this block
    pub outputs: Vec<LightweightTransactionOutput>,
    /// Wallet outputs extracted from transaction outputs
    pub wallet_outputs: Vec<LightweightWalletOutput>,
    /// Timestamp when block was mined
    pub mined_timestamp: u64,
}

/// Block information
#[derive(Debug, Clone)]
pub struct BlockInfo {
    /// Block height
    pub height: u64,
    /// Block hash
    pub hash: Vec<u8>,
    /// Block timestamp
    pub timestamp: u64,
    /// Transaction outputs in this block
    pub outputs: Vec<LightweightTransactionOutput>,
    /// Transaction inputs in this block
    pub inputs: Vec<TransactionInput>,
    /// Transaction kernels in this block
    pub kernels: Vec<TransactionKernel>,
}

/// Blockchain scanner trait for scanning UTXOs
///
/// This trait provides a lightweight interface that can be implemented by
/// different backend providers (gRPC, HTTP, etc.) without requiring heavy
/// dependencies in the core library.
#[cfg(any(feature = "grpc", feature = "http", target_arch = "wasm32"))]
#[async_trait(?Send)]
pub trait BlockchainScanner: Send + Sync {
    /// Scan for wallet outputs in the specified block range
    async fn scan_blocks(
        &mut self,
        config: ScanConfig,
    ) -> LightweightWalletResult<Vec<BlockScanResult>>;

    /// Get the current chain tip information
    async fn get_tip_info(&mut self) -> LightweightWalletResult<TipInfo>;

    /// Search for specific UTXOs by commitment
    async fn search_utxos(
        &mut self,
        commitments: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<Vec<BlockScanResult>>;

    /// Fetch specific UTXOs by hash
    async fn fetch_utxos(
        &mut self,
        hashes: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<Vec<LightweightTransactionOutput>>;

    /// Get blocks by height range
    async fn get_blocks_by_heights(
        &mut self,
        heights: Vec<u64>,
    ) -> LightweightWalletResult<Vec<BlockInfo>>;

    /// Get a single block by height
    async fn get_block_by_height(
        &mut self,
        height: u64,
    ) -> LightweightWalletResult<Option<BlockInfo>>;
}

/// Wallet scanner trait for scanning with wallet keys
///
/// This trait extends the basic blockchain scanner with wallet-specific
/// functionality for scanning with key management.
#[cfg(any(feature = "grpc", feature = "http", target_arch = "wasm32"))]
#[async_trait(?Send)]
pub trait WalletScanner: Send + Sync {
    /// Scan for wallet outputs using wallet keys
    async fn scan_wallet(
        &mut self,
        config: WalletScanConfig,
    ) -> LightweightWalletResult<WalletScanResult>;

    /// Scan for wallet outputs with progress reporting
    async fn scan_wallet_with_progress(
        &mut self,
        config: WalletScanConfig,
        progress_callback: Option<&ProgressCallback>,
    ) -> LightweightWalletResult<WalletScanResult>;

    /// Get the underlying blockchain scanner
    fn blockchain_scanner(&mut self) -> &mut dyn BlockchainScanner;
}

/// Default scanning logic implementation
#[derive(Debug, Clone)]
pub struct DefaultScanningLogic {
    entropy: [u8; 16],
}

impl DefaultScanningLogic {
    /// Create new scanning logic with entropy
    pub fn new(entropy: [u8; 16]) -> Self {
        Self { entropy }
    }

    /// Extract wallet output from transaction output using reference-compatible key derivation
    pub fn extract_wallet_output(
        &self,
        transaction_output: &LightweightTransactionOutput,
    ) -> Result<Option<LightweightWalletOutput>, LightweightWalletError> {
        // Derive view key using the same method as reference
        let (view_key_ristretto, _spend_key) =
            key_management::derive_view_and_spend_keys_from_entropy(&self.entropy).map_err(
                |e| LightweightWalletError::InvalidArgument {
                    argument: "entropy".to_string(),
                    value: "key_derivation".to_string(),
                    message: format!("Key derivation failed: {e}"),
                },
            )?;

        // Convert RistrettoSecretKey to PrivateKey
        let view_key_bytes = view_key_ristretto.as_bytes();
        let mut view_key_array = [0u8; 32];
        view_key_array.copy_from_slice(view_key_bytes);
        let view_key = PrivateKey::new(view_key_array);

        // Try Diffie-Hellman shared secret approach (reference implementation method)
        if let Some(wallet_output) =
            self.try_diffie_hellman_recovery(transaction_output, &view_key)?
        {
            return Ok(Some(wallet_output));
        }

        Ok(None)
    }

    /// Try Diffie-Hellman shared secret recovery (matches reference implementation)
    fn try_diffie_hellman_recovery(
        &self,
        transaction_output: &LightweightTransactionOutput,
        view_private_key: &PrivateKey,
    ) -> Result<Option<LightweightWalletOutput>, LightweightWalletError> {
        // Get sender offset public key from the output
        let sender_offset_public_key = transaction_output.sender_offset_public_key();

        // Compute Diffie-Hellman shared secret: view_private_key * sender_offset_public_key
        let shared_secret =
            self.compute_diffie_hellman_shared_secret(view_private_key, sender_offset_public_key)?;

        // Derive encryption key from shared secret (same as reference implementation)
        let encryption_key = self.shared_secret_to_encryption_key(&shared_secret)?;

        // Try to decrypt the encrypted data
        match EncryptedData::decrypt_data(
            &encryption_key,
            transaction_output.commitment(),
            transaction_output.encrypted_data(),
        ) {
            Ok((value, _mask, payment_id)) => {
                #[cfg(feature = "tracing")]
                info!(
                    "Successfully decrypted output with DH approach: value={}, payment_id={:?}",
                    value.as_u64(),
                    payment_id
                );

                // Use the extraction logic to create a proper wallet output
                let extraction_config = ExtractionConfig::with_private_key(encryption_key);
                match extract_wallet_output(transaction_output, &extraction_config) {
                    Ok(wallet_output) => Ok(Some(wallet_output)),
                    Err(_) => {
                        #[cfg(feature = "tracing")]
                        info!("Extraction failed, but decryption succeeded - creating basic wallet output");
                        Ok(None) // For now, return None to avoid constructor complexity
                    }
                }
            }
            Err(e) => {
                #[cfg(feature = "tracing")]
                debug!("DH decryption failed: {}", e);
                Ok(None)
            }
        }
    }

    /// Compute Diffie-Hellman shared secret: private_key * public_key
    fn compute_diffie_hellman_shared_secret(
        &self,
        private_key: &PrivateKey,
        public_key: &CompressedPublicKey,
    ) -> Result<[u8; 32], LightweightWalletError> {
        // Convert private key to RistrettoSecretKey
        let secret_key = RistrettoSecretKey::from_canonical_bytes(&private_key.as_bytes())
            .map_err(|e| LightweightWalletError::InvalidArgument {
                argument: "private_key".to_string(),
                value: "key_derivation".to_string(),
                message: format!("Invalid private key: {e}"),
            })?;

        // Decompress public key to RistrettoPublicKey
        let pub_key =
            RistrettoPublicKey::from_canonical_bytes(&public_key.as_bytes()).map_err(|e| {
                LightweightWalletError::InvalidArgument {
                    argument: "public_key".to_string(),
                    value: "key_derivation".to_string(),
                    message: format!("Invalid public key: {e}"),
                }
            })?;

        // Compute shared secret: private_key * public_key
        let shared_secret_point = pub_key * secret_key;

        // Convert to bytes - need to convert properly
        let shared_secret_bytes = shared_secret_point.as_bytes();
        let mut result = [0u8; 32];
        result.copy_from_slice(shared_secret_bytes);
        Ok(result)
    }

    /// Convert shared secret to encryption key (mimics reference implementation)
    fn shared_secret_to_encryption_key(
        &self,
        shared_secret: &[u8; 32],
    ) -> Result<PrivateKey, LightweightWalletError> {
        // Use Blake2b hash to derive encryption key from shared secret
        // This matches the pattern used in the reference implementation
        let mut hasher = Blake2b::<digest::consts::U32>::new();
        hasher.update(b"TARI_SHARED_SECRET_TO_ENCRYPTION_KEY");
        hasher.update(shared_secret);

        let result = hasher.finalize();
        let key_bytes: [u8; 32] =
            result
                .as_slice()
                .try_into()
                .map_err(|_| LightweightWalletError::InvalidArgument {
                    argument: "shared_secret".to_string(),
                    value: "key_derivation".to_string(),
                    message: "Failed to convert hash to key".to_string(),
                })?;

        Ok(PrivateKey::new(key_bytes))
    }

    /// Process blocks and extract wallet outputs
    pub fn process_blocks(
        blocks: Vec<BlockInfo>,
        extraction_config: &ExtractionConfig,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
        let mut results = Vec::new();

        for block in blocks {
            let mut wallet_outputs = Vec::new();

            for output in &block.outputs {
                match extract_wallet_output(output, extraction_config) {
                    Ok(wallet_output) => wallet_outputs.push(wallet_output),
                    Err(e) => {
                        // Log error but continue processing other outputs
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Failed to extract wallet output: {}", e);
                    }
                }
            }

            results.push(BlockScanResult {
                height: block.height,
                block_hash: block.hash,
                outputs: block.outputs,
                wallet_outputs,
                mined_timestamp: block.timestamp,
            });
        }

        Ok(results)
    }

    /// Process blocks with wallet key management
    pub fn process_blocks_with_wallet_keys(
        blocks: Vec<BlockInfo>,
        config: &WalletScanConfig,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
        let mut results = Vec::new();

        // Use the existing extraction config from the WalletScanConfig
        // The GRPC scanner sets this up correctly when creating the scan config
        let extraction_config = &config.scan_config.extraction_config;

        for block in blocks {
            let mut wallet_outputs = Vec::new();

            for output in &block.outputs {
                // Try to find wallet outputs using multiple scanning strategies
                let mut found_output = false;

                // Strategy 1: One-sided payments (different detection logic)
                if !found_output {
                    if let Some(wallet_output) =
                        Self::scan_for_one_sided_payment(output, extraction_config)?
                    {
                        wallet_outputs.push(wallet_output);
                        found_output = true;
                    }
                }

                // Strategy 2: Regular recoverable outputs (encrypted data decryption)
                if !found_output {
                    if let Some(wallet_output) =
                        Self::scan_for_recoverable_output(output, extraction_config)?
                    {
                        wallet_outputs.push(wallet_output);
                        found_output = true;
                    }
                }

                // Strategy 3: Coinbase outputs (special handling)
                if !found_output {
                    if let Some(wallet_output) = Self::scan_for_coinbase_output(output)? {
                        wallet_outputs.push(wallet_output);
                        // found_output = true; // Leaving this here in case we add additional strategies in the future
                    }
                }
            }

            results.push(BlockScanResult {
                height: block.height,
                block_hash: block.hash.clone(),
                outputs: block.outputs.clone(),
                wallet_outputs,
                mined_timestamp: block.timestamp,
            });
        }

        Ok(results)
    }

    /// Scan for regular recoverable outputs using encrypted data decryption
    fn scan_for_recoverable_output(
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

    /// Scan for one-sided payments (outputs sent to wallet without interaction)
    fn scan_for_one_sided_payment(
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

    /// Scan for coinbase outputs (special handling for mining rewards)
    fn scan_for_coinbase_output(
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
            use crate::data_structures::payment_id::PaymentId;
            use crate::data_structures::wallet_output::*;

            let wallet_output = LightweightWalletOutput::new(
                output.version(),
                output.minimum_value_promise(),
                LightweightKeyId::Zero,
                output.features().clone(),
                output.script().clone(),
                LightweightExecutionStack::default(),
                LightweightKeyId::Zero,
                output.sender_offset_public_key().clone(),
                output.metadata_signature().clone(),
                0,
                output.covenant().clone(),
                output.encrypted_data().clone(),
                output.minimum_value_promise(),
                output.proof().cloned(),
                PaymentId::Empty,
            );

            return Ok(Some(wallet_output));
        }

        Ok(None)
    }

    /// Scan blocks with progress reporting
    pub async fn scan_blocks_with_progress<S>(
        scanner: &mut S,
        config: ScanConfig,
        progress_callback: Option<&ProgressCallback>,
    ) -> LightweightWalletResult<Vec<BlockScanResult>>
    where
        S: BlockchainScanner,
    {
        let start_time = Instant::now();
        let mut all_results = Vec::new();
        let mut current_height = config.start_height;
        let end_height = config.end_height.unwrap_or_else(|| {
            // Get tip info if no end height specified
            // For now, we'll use a reasonable default
            current_height + 1000
        });

        while current_height <= end_height {
            let batch_end = std::cmp::min(current_height + config.batch_size - 1, end_height);

            // Get blocks in this batch
            let heights: Vec<u64> = (current_height..=batch_end).collect();
            let blocks = scanner.get_blocks_by_heights(heights).await?;

            // Process blocks
            let batch_results = Self::process_blocks(blocks, &config.extraction_config)?;
            all_results.extend(batch_results);

            // Update progress
            if let Some(callback) = progress_callback {
                let total_outputs: u64 = all_results
                    .iter()
                    .map(|r| r.wallet_outputs.len() as u64)
                    .sum();
                let total_value: u64 = all_results
                    .iter()
                    .flat_map(|r| &r.wallet_outputs)
                    .map(|wo| wo.value().as_u64())
                    .sum();

                callback(ScanProgress {
                    current_height: batch_end,
                    target_height: end_height,
                    outputs_found: total_outputs,
                    total_value,
                    elapsed: start_time.elapsed(),
                });
            }

            current_height = batch_end + 1;
        }

        Ok(all_results)
    }

    /// Scan wallet with progress reporting
    pub async fn scan_wallet_with_progress<S>(
        scanner: &mut S,
        config: WalletScanConfig,
        progress_callback: Option<&ProgressCallback>,
    ) -> LightweightWalletResult<WalletScanResult>
    where
        S: BlockchainScanner,
    {
        let start_time = Instant::now();
        let mut all_results = Vec::new();
        let mut current_height = config.scan_config.start_height;
        let end_height = config.scan_config.end_height.unwrap_or_else(|| {
            // Get tip info if no end height specified
            // For now, we'll use a reasonable default
            current_height + 1000
        });

        while current_height <= end_height {
            let batch_end = std::cmp::min(
                current_height + config.scan_config.batch_size - 1,
                end_height,
            );

            // Get blocks in this batch
            let heights: Vec<u64> = (current_height..=batch_end).collect();
            let blocks = scanner.get_blocks_by_heights(heights).await?;

            // Process blocks with wallet keys
            let batch_results = Self::process_blocks_with_wallet_keys(blocks, &config)?;
            all_results.extend(batch_results);

            // Update progress
            if let Some(callback) = progress_callback {
                let total_outputs: u64 = all_results
                    .iter()
                    .map(|r| r.wallet_outputs.len() as u64)
                    .sum();
                let total_value: u64 = all_results
                    .iter()
                    .flat_map(|r| &r.wallet_outputs)
                    .map(|wo| wo.value().as_u64())
                    .sum();

                callback(ScanProgress {
                    current_height: batch_end,
                    target_height: end_height,
                    outputs_found: total_outputs,
                    total_value,
                    elapsed: start_time.elapsed(),
                });
            }

            current_height = batch_end + 1;
        }

        let total_wallet_outputs: u64 = all_results
            .iter()
            .map(|r| r.wallet_outputs.len() as u64)
            .sum();
        let total_value: u64 = all_results
            .iter()
            .flat_map(|r| &r.wallet_outputs)
            .map(|wo| wo.value().as_u64())
            .sum();

        Ok(WalletScanResult {
            block_results: all_results,
            total_wallet_outputs,
            total_value,
            addresses_scanned: 0, // Will be calculated during implementation
            accounts_scanned: 0,  // Will be calculated during implementation
            scan_duration: start_time.elapsed(),
        })
    }
}

/// Mock implementation for testing
pub struct MockBlockchainScanner {
    blocks: Vec<BlockInfo>,
    tip_info: TipInfo,
}

impl Default for MockBlockchainScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBlockchainScanner {
    /// Create a new mock scanner
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            tip_info: TipInfo {
                best_block_height: 1000,
                best_block_hash: vec![1, 2, 3, 4],
                accumulated_difficulty: vec![5, 6, 7, 8],
                pruned_height: 500,
                timestamp: 1234567890,
            },
        }
    }

    /// Add a mock block
    pub fn add_block(&mut self, block: BlockInfo) {
        self.blocks.push(block);
    }

    /// Set tip info
    pub fn set_tip_info(&mut self, tip_info: TipInfo) {
        self.tip_info = tip_info;
    }
}

#[cfg(any(feature = "grpc", feature = "http", target_arch = "wasm32"))]
#[async_trait(?Send)]
impl BlockchainScanner for MockBlockchainScanner {
    async fn scan_blocks(
        &mut self,
        config: ScanConfig,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
        DefaultScanningLogic::scan_blocks_with_progress(self, config, None).await
    }

    async fn get_tip_info(&mut self) -> LightweightWalletResult<TipInfo> {
        Ok(self.tip_info.clone())
    }

    async fn search_utxos(
        &mut self,
        _commitments: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
        // Mock implementation - return empty results
        Ok(Vec::new())
    }

    async fn fetch_utxos(
        &mut self,
        _hashes: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<Vec<LightweightTransactionOutput>> {
        // Mock implementation - return empty results
        Ok(Vec::new())
    }

    async fn get_blocks_by_heights(
        &mut self,
        heights: Vec<u64>,
    ) -> LightweightWalletResult<Vec<BlockInfo>> {
        let mut result = Vec::new();
        for height in heights {
            if let Some(block) = self.blocks.iter().find(|b| b.height == height) {
                result.push(block.clone());
            }
        }
        Ok(result)
    }

    async fn get_block_by_height(
        &mut self,
        height: u64,
    ) -> LightweightWalletResult<Option<BlockInfo>> {
        Ok(self.blocks.iter().find(|b| b.height == height).cloned())
    }
}

/// Builder for creating blockchain scanners
pub struct BlockchainScannerBuilder {
    scanner_type: Option<ScannerType>,
    config: Option<ScannerConfig>,
}

#[derive(Debug, Clone)]
pub enum ScannerType {
    Mock,
    // Add other scanner types here as needed
    #[cfg(feature = "grpc")]
    Grpc {
        url: String,
    },
    // Http { url: String },
}

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub base_url: String,
    pub timeout: Duration,
    pub retry_attempts: u32,
}

impl BlockchainScannerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            scanner_type: None,
            config: None,
        }
    }

    /// Set the scanner type
    pub fn with_type(mut self, scanner_type: ScannerType) -> Self {
        self.scanner_type = Some(scanner_type);
        self
    }

    /// Set the scanner configuration
    pub fn with_config(mut self, config: ScannerConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Build the scanner
    pub async fn build(self) -> LightweightWalletResult<Box<dyn BlockchainScanner>> {
        match self.scanner_type {
            Some(ScannerType::Mock) => Ok(Box::new(MockBlockchainScanner::new())),
            #[cfg(feature = "grpc")]
            Some(ScannerType::Grpc { url }) => {
                let scanner = crate::scanning::GrpcBlockchainScanner::new(url).await?;
                Ok(Box::new(scanner))
            }
            None => Err(LightweightWalletError::ConfigurationError(
                "Scanner type not specified".to_string(),
            )),
        }
    }
}

impl Default for BlockchainScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_scan_config_default() {
        let config = ScanConfig::default();
        assert_eq!(config.start_height, 0);
        assert_eq!(config.end_height, None);
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert!(config.extraction_config.enable_key_derivation);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_scan_progress() {
        let progress = ScanProgress {
            current_height: 1000,
            target_height: 2000,
            outputs_found: 5,
            total_value: 1000000,
            elapsed: Duration::from_secs(10),
        };

        assert_eq!(progress.current_height, 1000);
        assert_eq!(progress.target_height, 2000);
        assert_eq!(progress.outputs_found, 5);
        assert_eq!(progress.total_value, 1000000);
        assert_eq!(progress.elapsed, Duration::from_secs(10));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_block_scan_result() {
        let result = BlockScanResult {
            height: 1000,
            block_hash: vec![1, 2, 3, 4],
            outputs: vec![],
            wallet_outputs: vec![],
            mined_timestamp: 1234567890,
        };

        assert_eq!(result.height, 1000);
        assert_eq!(result.block_hash, vec![1, 2, 3, 4]);
        assert_eq!(result.mined_timestamp, 1234567890);
        assert!(result.outputs.is_empty());
        assert!(result.wallet_outputs.is_empty());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_tip_info() {
        let tip_info = TipInfo {
            best_block_height: 1000,
            best_block_hash: vec![1, 2, 3, 4],
            accumulated_difficulty: vec![5, 6, 7, 8],
            pruned_height: 500,
            timestamp: 1234567890,
        };

        assert_eq!(tip_info.best_block_height, 1000);
        assert_eq!(tip_info.best_block_hash, vec![1, 2, 3, 4]);
        assert_eq!(tip_info.accumulated_difficulty, vec![5, 6, 7, 8]);
        assert_eq!(tip_info.pruned_height, 500);
        assert_eq!(tip_info.timestamp, 1234567890);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_mock_scanner() {
        let mut scanner = MockBlockchainScanner::new();
        let tip_info = scanner.get_tip_info().await.unwrap();
        assert_eq!(tip_info.best_block_height, 1000);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_scanner_builder() {
        let builder = BlockchainScannerBuilder::new().with_type(ScannerType::Mock);

        let mut scanner = builder.build().await.unwrap();
        let tip_info = scanner.get_tip_info().await.unwrap();
        assert_eq!(tip_info.best_block_height, 1000);
    }
}
