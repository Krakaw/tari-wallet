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

use crate::{
    data_structures::{
        transaction::TransactionDirection, transaction_output::LightweightTransactionOutput,
        types::PrivateKey, wallet_transaction::WalletState,
    },
    errors::{KeyManagementError, LightweightWalletError, LightweightWalletResult},
    key_management::key_derivation,
    storage::storage_trait::{OutputStatus, StoredOutput},
};

use super::ScanContext;
use crate::wallet::Wallet;

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

// Placeholder type definitions until actual implementation
// TODO: Rename to WalletScanner once refactoring is complete and trait is moved
pub struct BinaryWalletScanner;
pub struct BinaryScanResult;
