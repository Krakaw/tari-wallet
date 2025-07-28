//! Main wallet scanning implementation and public API.
//!
//! This module contains the core blockchain scanning logic, wallet creation
//! and setup functions, and the primary public API for wallet scanning
//! operations.
//!
//! This module is part of the scanner.rs binary refactoring effort.

use blake2::{Blake2b, Digest};
use digest::consts::U32;
use tari_utilities::ByteArray;
use tokio::time::Instant;

use crate::{
    common::format_number,
    data_structures::{
        transaction::TransactionDirection, transaction_output::LightweightTransactionOutput,
        types::PrivateKey, wallet_transaction::WalletState,
    },
    errors::{KeyManagementError, LightweightWalletError, LightweightWalletResult},
    key_management::key_derivation,
    scanning::GrpcBlockchainScanner,
    storage::storage_trait::{OutputStatus, StoredOutput},
    wallet::Wallet,
};

use super::{BinaryScanConfig, ProgressTracker, ScanContext, ScannerStorage};

/// Extract UTXO data from blockchain outputs and create StoredOutput objects
#[cfg(all(feature = "grpc", feature = "storage"))]
pub fn extract_utxo_outputs_from_wallet_state(
    wallet_state: &WalletState,
    scan_context: &ScanContext,
    wallet_id: u32,
    block_outputs: &[LightweightTransactionOutput],
    block_height: u64,
) -> LightweightWalletResult<Vec<StoredOutput>> {
    let mut utxo_outputs = Vec::new();

    // Get inbound transactions from this specific block
    let block_transactions: Vec<_> = wallet_state
        .transactions
        .iter()
        .filter(|tx| {
            tx.block_height == block_height
                && tx.transaction_direction == TransactionDirection::Inbound
        })
        .collect();

    for transaction in block_transactions {
        // Find the corresponding blockchain output
        if let Some(output_index) = transaction.output_index {
            if let Some(blockchain_output) = block_outputs.get(output_index) {
                // Derive spending keys for this output
                let (spending_key, script_private_key) =
                    derive_utxo_spending_keys(&scan_context.entropy, output_index as u64)?;

                // Extract script input data and lock height
                let (input_data, script_lock_height) =
                    extract_script_data(&blockchain_output.script.bytes)?;

                // Create StoredOutput from blockchain data
                let stored_output = StoredOutput {
                    id: None, // Will be set by database
                    wallet_id,

                    // Core UTXO identification
                    commitment: blockchain_output.commitment.as_bytes().to_vec(),
                    hash: compute_output_hash(blockchain_output)?,
                    value: transaction.value,

                    // Spending keys (derived from entropy)
                    spending_key: hex::encode(spending_key.as_bytes()),
                    script_private_key: hex::encode(script_private_key.as_bytes()),

                    // Script and covenant data
                    script: blockchain_output.script.bytes.clone(),
                    input_data,
                    covenant: blockchain_output.covenant.bytes.clone(),

                    // Output features and type
                    output_type: blockchain_output.features.output_type.clone() as u32,
                    features_json: serde_json::to_string(&blockchain_output.features).map_err(
                        |e| {
                            LightweightWalletError::StorageError(format!(
                                "Failed to serialize features: {e}"
                            ))
                        },
                    )?,

                    // Maturity and lock constraints
                    maturity: blockchain_output.features.maturity,
                    script_lock_height,

                    // Metadata signature components
                    sender_offset_public_key: blockchain_output
                        .sender_offset_public_key
                        .as_bytes()
                        .to_vec(),
                    // Note: LightweightSignature only has bytes field, so we use placeholders
                    // In a full implementation, these would be extracted from the signature structure
                    metadata_signature_ephemeral_commitment: vec![0u8; 32], // Placeholder
                    metadata_signature_ephemeral_pubkey: vec![0u8; 32],     // Placeholder
                    metadata_signature_u_a: if blockchain_output.metadata_signature.bytes.len()
                        >= 32
                    {
                        blockchain_output.metadata_signature.bytes[0..32].to_vec()
                    } else {
                        vec![0u8; 32]
                    },
                    metadata_signature_u_x: if blockchain_output.metadata_signature.bytes.len()
                        >= 64
                    {
                        blockchain_output.metadata_signature.bytes[32..64].to_vec()
                    } else {
                        vec![0u8; 32]
                    },
                    metadata_signature_u_y: vec![0u8; 32], // Placeholder

                    // Payment information
                    encrypted_data: blockchain_output.encrypted_data.as_bytes().to_vec(),
                    minimum_value_promise: blockchain_output.minimum_value_promise.as_u64(),

                    // Range proof
                    rangeproof: blockchain_output.proof.as_ref().map(|p| p.bytes.clone()),

                    // Status and spending tracking
                    status: if transaction.is_spent {
                        OutputStatus::Spent as u32
                    } else {
                        OutputStatus::Unspent as u32
                    },
                    mined_height: Some(transaction.block_height),
                    spent_in_tx_id: if transaction.is_spent {
                        // Calculate transaction ID from spent block and input index
                        transaction.spent_in_block.and_then(|spent_block| {
                            transaction.spent_in_input.map(|spent_input| {
                                generate_transaction_id(spent_block, spent_input)
                            })
                        })
                    } else {
                        None
                    },

                    // Timestamps (will be set by database)
                    created_at: None,
                    updated_at: None,
                };

                utxo_outputs.push(stored_output);
            }
        }
    }

    Ok(utxo_outputs)
}

/// Extract script input data and script lock height from script bytes
#[cfg(all(feature = "grpc", feature = "storage"))]
fn extract_script_data(script_bytes: &[u8]) -> LightweightWalletResult<(Vec<u8>, u64)> {
    // If script is empty, return empty data
    if script_bytes.is_empty() {
        return Ok((Vec::new(), 0));
    }

    let mut input_data = Vec::new();
    let mut script_lock_height = 0u64;
    let mut potential_heights = Vec::new();

    // Parse script bytecode to extract data
    // This is a simplified parser - in a full implementation, you'd use a proper script interpreter
    let mut i = 0;
    while i < script_bytes.len() {
        match script_bytes[i] {
            // Check for potential lock height patterns
            0x6a => {
                // OP_PUSHDATA - extract the data being pushed
                if i + 1 < script_bytes.len() {
                    let data_len = script_bytes[i + 1] as usize;
                    if i + 2 + data_len <= script_bytes.len() {
                        let data = &script_bytes[i + 2..i + 2 + data_len];
                        input_data.extend_from_slice(data);

                        // Check if this could be a block height (8 bytes, little endian)
                        if data_len == 8 {
                            let bytes: [u8; 8] = data.try_into().unwrap_or([0u8; 8]);
                            let potential_height = u64::from_le_bytes(bytes);

                            // Reasonable block height range (current mainnet is around 3M blocks)
                            if potential_height > 0 && potential_height < 10_000_000 {
                                potential_heights.push(potential_height);
                            }
                        }
                        i += 2 + data_len;
                    } else {
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            // Look for other relevant opcodes that might contain lock heights
            0x51..=0x60 => {
                // OP_1 through OP_16 - small numbers
                let value = (script_bytes[i] - 0x50) as u64;
                potential_heights.push(value);
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    // Use the largest reasonable value as script lock height
    if let Some(&max_height) = potential_heights.iter().max() {
        script_lock_height = max_height;
    }

    Ok((input_data, script_lock_height))
}

/// Generate a deterministic transaction ID from block height and input index
#[cfg(all(feature = "grpc", feature = "storage"))]
fn generate_transaction_id(block_height: u64, input_index: usize) -> u64 {
    // Create a deterministic transaction ID by combining block height and input index
    // This is a simplified approach - in a real implementation, you'd use the actual transaction hash
    //
    // Format: [32-bit block_height][32-bit input_index]
    // This ensures unique IDs while being deterministic and easily debuggable

    // Use the block height as the upper 32 bits and input index as lower 32 bits
    let tx_id = ((block_height & 0xFFFFFFFF) << 32) | (input_index as u64 & 0xFFFFFFFF);

    // Ensure we don't return 0 (which is often treated as "no transaction")
    if tx_id == 0 {
        1
    } else {
        tx_id
    }
}

/// Derive spending keys for a UTXO output using wallet entropy
/// For view-key mode (entropy all zeros), returns placeholder keys
#[cfg(all(feature = "grpc", feature = "storage"))]
fn derive_utxo_spending_keys(
    entropy: &[u8; 16],
    output_index: u64,
) -> LightweightWalletResult<(PrivateKey, PrivateKey)> {
    // Check if we have real entropy or if this is view-key mode
    let has_real_entropy = entropy != &[0u8; 16];

    if has_real_entropy {
        // Derive real spending keys using wallet entropy
        let spending_key_raw = key_derivation::derive_private_key_from_entropy(
            entropy,
            "wallet_spending", // Branch for spending keys
            output_index,
        )?;

        let script_private_key_raw = key_derivation::derive_private_key_from_entropy(
            entropy,
            "script_keys", // Branch for script keys
            output_index,
        )?;

        // Convert to PrivateKey type
        let spending_key =
            PrivateKey::new(spending_key_raw.as_bytes().try_into().map_err(|_| {
                KeyManagementError::key_derivation_failed("Failed to convert spending key")
            })?);

        let script_private_key =
            PrivateKey::new(script_private_key_raw.as_bytes().try_into().map_err(|_| {
                KeyManagementError::key_derivation_failed("Failed to convert script private key")
            })?);

        Ok((spending_key, script_private_key))
    } else {
        // View-key mode: use placeholder keys (cannot spend, but can store UTXO structure)
        let placeholder_key_bytes = [0u8; 32];
        let spending_key = PrivateKey::new(placeholder_key_bytes);
        let script_private_key = PrivateKey::new(placeholder_key_bytes);

        Ok((spending_key, script_private_key))
    }
}

/// Compute output hash for UTXO identification
#[cfg(all(feature = "grpc", feature = "storage"))]
fn compute_output_hash(output: &LightweightTransactionOutput) -> LightweightWalletResult<Vec<u8>> {
    // Compute hash of output fields for identification
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(output.commitment.as_bytes());
    hasher.update(output.script.bytes.as_slice());
    hasher.update(output.sender_offset_public_key.as_bytes());
    hasher.update(output.minimum_value_promise.as_u64().to_le_bytes());

    Ok(hasher.finalize().to_vec())
}

/// Create a wallet from a seed phrase and return the scan context with default block
///
/// This function combines wallet creation from a seed phrase with scan context creation,
/// providing a convenient wrapper for the scanner binary.
///
/// # Arguments
/// * `seed_phrase` - The mnemonic seed phrase to create the wallet from
///
/// # Returns
/// A tuple containing:
/// - `ScanContext` with view key and entropy from the wallet
/// - `u64` representing the wallet's birthday (default from block)
///
/// # Errors
/// Returns an error if the wallet creation or scan context creation fails
pub fn create_wallet_from_seed_phrase(
    seed_phrase: &str,
) -> LightweightWalletResult<(ScanContext, u64)> {
    let wallet = Wallet::new_from_seed_phrase(seed_phrase, None)?;
    let scan_context = ScanContext::from_wallet(&wallet)?;
    let default_from_block = wallet.birthday();
    Ok((scan_context, default_from_block))
}

/// Create a scan context from a view key with default block set to genesis
///
/// This function creates a view-only scan context from a hex view key,
/// providing a convenient wrapper for the scanner binary.
///
/// # Arguments
/// * `view_key_hex` - 64-character hexadecimal string representing the view key
///
/// # Returns
/// A tuple containing:
/// - `ScanContext` with view key populated and entropy set to zeros
/// - `u64` set to 0 (genesis block) since no wallet birthday is available
///
/// # Errors
/// Returns an error if the view key is invalid or cannot be parsed
pub fn create_wallet_from_view_key(
    view_key_hex: &str,
) -> LightweightWalletResult<(ScanContext, u64)> {
    let scan_context = ScanContext::from_view_key(view_key_hex)?;
    let default_from_block = 0; // Start from genesis when using view key only
    Ok((scan_context, default_from_block))
}

/// Represents the result of a wallet scanning operation
#[derive(Debug, Clone)]
pub enum ScanResult {
    /// Scan completed successfully with final wallet state
    Completed(WalletState),
    /// Scan was interrupted (e.g., by user) with current wallet state
    Interrupted(WalletState),
}

/// Wallet scanner for performing blockchain scanning operations
///
/// This struct encapsulates the main scanning functionality that was previously
/// implemented directly in the scanner binary. It provides a clean API for
/// scanning wallets across blockchain height ranges.
pub struct WalletScanner {
    /// Progress tracker for monitoring scan progress
    progress_tracker: Option<ProgressTracker>,
}

impl WalletScanner {
    /// Create a new wallet scanner
    pub fn new() -> Self {
        Self {
            progress_tracker: None,
        }
    }

    /// Create a new wallet scanner with progress tracking
    pub fn with_progress_tracker(progress_tracker: ProgressTracker) -> Self {
        Self {
            progress_tracker: Some(progress_tracker),
        }
    }

    /// Perform wallet scanning across blocks with cancellation support
    ///
    /// This is the main scanning method that processes blockchain blocks to find
    /// wallet outputs and transactions. It supports both specific block scanning
    /// and range scanning with automatic resume functionality.
    ///
    /// # Arguments
    /// * `scanner` - GRPC blockchain scanner for fetching blocks
    /// * `scan_context` - Wallet scanning context with keys and entropy
    /// * `config` - Binary scan configuration
    /// * `storage_backend` - Storage backend for persistence
    /// * `cancel_rx` - Channel receiver for cancellation signals
    ///
    /// # Returns
    /// `ScanResult` indicating completion or interruption with wallet state
    pub async fn scan(
        &mut self,
        scanner: &mut GrpcBlockchainScanner,
        scan_context: &ScanContext,
        config: &BinaryScanConfig,
        storage_backend: &mut ScannerStorage,
        cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> LightweightWalletResult<ScanResult> {
        scan_wallet_across_blocks_with_cancellation(
            scanner,
            scan_context,
            config,
            storage_backend,
            cancel_rx,
            self.progress_tracker.as_mut(),
        )
        .await
    }
}

impl Default for WalletScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Core scanning logic - simplified and focused with batch processing
#[cfg(feature = "grpc")]
async fn scan_wallet_across_blocks_with_cancellation(
    _scanner: &mut GrpcBlockchainScanner,
    _scan_context: &ScanContext,
    config: &BinaryScanConfig,
    storage_backend: &mut ScannerStorage,
    _cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    _progress_tracker: Option<&mut ProgressTracker>,
) -> LightweightWalletResult<ScanResult> {
    let has_specific_blocks = config.block_heights.is_some();

    // Handle automatic resume functionality for database storage
    let (from_block, to_block) = if config.use_database
        && config.explicit_from_block.is_none()
        && config.block_heights.is_none()
    {
        #[cfg(feature = "storage")]
        if let Some(_wallet_id) = storage_backend.wallet_id {
            // Get the wallet to check its resume block
            if let Some(wallet_birthday) = storage_backend.get_wallet_birthday().await? {
                if !config.quiet {
                    println!(
                        "📄 Resuming wallet from last scanned block {}",
                        format_number(wallet_birthday)
                    );
                }
                (wallet_birthday, config.to_block)
            } else {
                if !config.quiet {
                    println!("📄 Wallet not found, starting from configuration");
                }
                (config.from_block, config.to_block)
            }
        } else {
            if !config.quiet {
                println!("⚠️  Resume requires a selected wallet");
            }
            (config.from_block, config.to_block)
        }

        #[cfg(not(feature = "storage"))]
        {
            (config.from_block, config.to_block)
        }
    } else {
        (config.from_block, config.to_block)
    };

    let wallet_state = WalletState::new();
    let _total_outputs = 0;
    let _start_time = Instant::now();

    // TODO: Setup progress tracking if available
    // Progress tracking will be implemented in a future task

    let block_heights = if has_specific_blocks {
        let heights = config.block_heights.as_ref().unwrap().clone();
        if !config.quiet {
            display_scan_info(config, &heights, has_specific_blocks);
        }
        heights
    } else {
        let heights: Vec<u64> = (from_block..=to_block).collect();
        if !config.quiet {
            display_scan_info(config, &heights, has_specific_blocks);
        }
        heights
    };

    // TODO: Implement the actual scanning logic
    // For now, this is a placeholder that will be fully implemented in future tasks

    if !config.quiet {
        println!("🔄 Wallet scanning functionality moved to library (placeholder implementation)");
        println!(
            "   • Scan range: {} to {}",
            format_number(from_block),
            format_number(to_block)
        );
        println!(
            "   • Blocks to scan: {}",
            format_number(block_heights.len())
        );
        println!("   • Note: Full scanning implementation will be completed in subsequent tasks");
    }

    Ok(ScanResult::Completed(wallet_state))
}

/// Display scan configuration information
#[cfg(feature = "grpc")]
fn display_scan_info(config: &BinaryScanConfig, block_heights: &[u64], has_specific_blocks: bool) {
    if has_specific_blocks {
        println!(
            "🔍 Scanning {} specific blocks: {:?}",
            format_number(block_heights.len()),
            if block_heights.len() <= 10 {
                block_heights
                    .iter()
                    .map(|h| format_number(*h))
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                format!(
                    "{}..{} and {} others",
                    format_number(block_heights[0]),
                    format_number(block_heights.last().copied().unwrap_or(0)),
                    format_number(block_heights.len() - 2)
                )
            }
        );
    } else {
        let block_range = config.to_block - config.from_block + 1;
        println!(
            "🔍 Scanning blocks {} to {} ({} blocks total)...",
            format_number(config.from_block),
            format_number(config.to_block),
            format_number(block_range)
        );
    }

    println!();
}

/// Display wallet activity summary
#[cfg(feature = "grpc")]
#[allow(dead_code)]
fn display_wallet_activity(wallet_state: &WalletState, from_block: u64, to_block: u64) {
    let (total_received, total_spent, balance, _unspent_count, _spent_count) =
        wallet_state.get_summary();
    let total_count = wallet_state.transactions.len();

    if total_count == 0 {
        println!(
            "💡 No wallet activity found in blocks {} to {}",
            format_number(from_block),
            format_number(to_block)
        );
        if from_block > 1 {
            println!("   ⚠️  Note: Scanning from block {} - wallet history before this block was not checked", format_number(from_block));
            println!("   💡 For complete history, try: cargo run --bin scanner --features grpc-storage -- --seed-phrase \"your seed phrase\" --from-block 1");
        }
        return;
    }

    println!("🏦 WALLET ACTIVITY SUMMARY");
    println!("========================");
    println!(
        "Scan range: Block {} to {} ({} blocks)",
        format_number(from_block),
        format_number(to_block),
        format_number(to_block - from_block + 1)
    );

    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();
    println!(
        "📥 Inbound:  {} transactions, {} μT ({:.6} T)",
        format_number(inbound_count),
        format_number(total_received),
        total_received as f64 / 1_000_000.0
    );
    println!(
        "📤 Outbound: {} transactions, {} μT ({:.6} T)",
        format_number(outbound_count),
        format_number(total_spent),
        total_spent as f64 / 1_000_000.0
    );
    println!(
        "💰 Current balance: {} μT ({:.6} T)",
        format_number(balance),
        balance as f64 / 1_000_000.0
    );
    println!(
        "📊 Total activity: {} transactions",
        format_number(total_count)
    );
    println!();
}

// Placeholder type definitions until actual implementation
// TODO: Rename to WalletScanner once refactoring is complete and trait is moved
pub struct BinaryWalletScanner;
pub struct BinaryScanResult;
