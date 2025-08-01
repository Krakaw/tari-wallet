//! Storage trait definition for wallet transaction persistence
//!
//! This module defines the `WalletStorage` trait that provides a common interface
//! for different storage backends to persist and retrieve wallet transaction data.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    data_structures::{
        transaction::{TransactionDirection, TransactionStatus},
        types::{CompressedCommitment, PrivateKey},
        wallet_transaction::{WalletState, WalletTransaction},
    },
    errors::LightweightWalletResult,
};

/// A stored UTXO output with all data needed for spending
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredOutput {
    /// Unique output ID (database primary key)
    pub id: Option<u32>,
    /// Wallet ID this output belongs to
    pub wallet_id: u32,

    // Core UTXO identification
    pub commitment: Vec<u8>, // 32 bytes commitment
    pub hash: Vec<u8>,       // Output hash for identification
    pub value: u64,          // Value in microMinotari

    // Spending keys
    pub spending_key: String,       // Private key to spend this output
    pub script_private_key: String, // Private key for script execution

    // Script and covenant data
    pub script: Vec<u8>,     // Script that governs spending
    pub input_data: Vec<u8>, // Execution stack data for script
    pub covenant: Vec<u8>,   // Covenant restrictions

    // Output features and type
    pub output_type: u32,      // Type: 0=Payment, 1=Coinbase, etc.
    pub features_json: String, // Serialized output features

    // Maturity and lock constraints
    pub maturity: u64,           // Block height when spendable
    pub script_lock_height: u64, // Script lock height

    // Metadata signature components
    pub sender_offset_public_key: Vec<u8>, // Sender offset public key
    pub metadata_signature_ephemeral_commitment: Vec<u8>, // Ephemeral commitment
    pub metadata_signature_ephemeral_pubkey: Vec<u8>, // Ephemeral public key
    pub metadata_signature_u_a: Vec<u8>,   // Signature component u_a
    pub metadata_signature_u_x: Vec<u8>,   // Signature component u_x
    pub metadata_signature_u_y: Vec<u8>,   // Signature component u_y

    // Payment information
    pub encrypted_data: Vec<u8>,    // Contains payment information
    pub minimum_value_promise: u64, // Minimum value promise

    // Range proof
    pub rangeproof: Option<Vec<u8>>, // Range proof bytes (nullable)

    // Status and spending tracking
    pub status: u32,                 // 0=Unspent, 1=Spent, 2=Locked, etc.
    pub mined_height: Option<u64>,   // Block height when mined
    pub spent_in_tx_id: Option<u64>, // Transaction ID where spent

    // Timestamps
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Output status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputStatus {
    Unspent = 0,
    Spent = 1,
    Locked = 2,
    Frozen = 3,
}

impl From<u32> for OutputStatus {
    fn from(value: u32) -> Self {
        match value {
            0 => OutputStatus::Unspent,
            1 => OutputStatus::Spent,
            2 => OutputStatus::Locked,
            3 => OutputStatus::Frozen,
            _ => OutputStatus::Unspent,
        }
    }
}

impl From<OutputStatus> for u32 {
    fn from(status: OutputStatus) -> Self {
        status as u32
    }
}

/// Query filters for retrieving outputs
#[derive(Debug, Clone, Default)]
pub struct OutputFilter {
    /// Filter by wallet ID
    pub wallet_id: Option<u32>,
    /// Filter by output status
    pub status: Option<OutputStatus>,
    /// Filter by minimum value
    pub min_value: Option<u64>,
    /// Filter by maximum value  
    pub max_value: Option<u64>,
    /// Filter by maturity block height range
    pub maturity_range: Option<(u64, u64)>,
    /// Filter by mined height range
    pub mined_height_range: Option<(u64, u64)>,
    /// Only outputs spendable at given block height
    pub spendable_at_height: Option<u64>,
    /// Limit number of results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

impl OutputFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by wallet ID
    pub fn with_wallet_id(mut self, wallet_id: u32) -> Self {
        self.wallet_id = Some(wallet_id);
        self
    }

    /// Filter by output status
    pub fn with_status(mut self, status: OutputStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Filter by value range
    pub fn with_value_range(mut self, min: u64, max: u64) -> Self {
        self.min_value = Some(min);
        self.max_value = Some(max);
        self
    }

    /// Filter outputs spendable at given block height
    pub fn spendable_at(mut self, block_height: u64) -> Self {
        self.spendable_at_height = Some(block_height);
        self
    }

    /// Set pagination limit
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set pagination offset
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }
}

impl StoredOutput {
    /// Check if this output can be spent at the given block height
    pub fn can_spend_at_height(&self, block_height: u64) -> bool {
        self.status == OutputStatus::Unspent as u32
            && self.spent_in_tx_id.is_none()
            && self.mined_height.is_some()
            && block_height >= self.maturity
            && block_height >= self.script_lock_height
    }

    /// Check if this output is currently spendable (assuming current tip)
    pub fn is_spendable(&self) -> bool {
        self.status == OutputStatus::Unspent as u32
            && self.spent_in_tx_id.is_none()
            && self.mined_height.is_some()
    }

    /// Get commitment as hex string
    pub fn commitment_hex(&self) -> String {
        hex::encode(&self.commitment)
    }

    /// Get output hash as hex string
    pub fn hash_hex(&self) -> String {
        hex::encode(&self.hash)
    }
}

/// A wallet stored in the database with keys and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredWallet {
    /// Unique wallet ID (database primary key)
    pub id: Option<u32>,
    /// User-friendly wallet name (must be unique)
    pub name: String,
    /// Encrypted seed phrase (optional, if provided then view/spend keys are also stored)
    pub seed_phrase: Option<String>,
    /// Private view key in hex format (always present for functional wallets)
    pub view_key_hex: String,
    /// Private spend key in hex format (optional, only for spending wallets)
    pub spend_key_hex: Option<String>,
    /// Wallet birthday block height
    pub birthday_block: u64,
    /// Latest block height scanned for this wallet
    pub latest_scanned_block: Option<u64>,
    /// Creation timestamp
    pub created_at: Option<String>,
    /// Last update timestamp
    pub updated_at: Option<String>,
}

impl StoredWallet {
    /// Create a new wallet from seed phrase (derives and stores all keys)
    pub fn from_seed_phrase(
        name: String,
        seed_phrase: String,
        view_key: PrivateKey,
        spend_key: PrivateKey,
        birthday_block: u64,
    ) -> Self {
        Self {
            id: None,
            name,
            seed_phrase: Some(seed_phrase),
            view_key_hex: hex::encode(view_key.as_bytes()),
            spend_key_hex: Some(hex::encode(spend_key.as_bytes())),
            birthday_block,
            latest_scanned_block: None,
            created_at: None,
            updated_at: None,
        }
    }

    /// Create a new wallet from view and spend keys
    pub fn from_keys(
        name: String,
        view_key: PrivateKey,
        spend_key: PrivateKey,
        birthday_block: u64,
    ) -> Self {
        Self {
            id: None,
            name,
            seed_phrase: None,
            view_key_hex: hex::encode(view_key.as_bytes()),
            spend_key_hex: Some(hex::encode(spend_key.as_bytes())),
            birthday_block,
            latest_scanned_block: None,
            created_at: None,
            updated_at: None,
        }
    }

    /// Create a view-only wallet (no spend key)
    pub fn view_only(name: String, view_key: PrivateKey, birthday_block: u64) -> Self {
        Self {
            id: None,
            name,
            seed_phrase: None,
            view_key_hex: hex::encode(view_key.as_bytes()),
            spend_key_hex: None,
            birthday_block,
            latest_scanned_block: None,
            created_at: None,
            updated_at: None,
        }
    }

    /// Validate that the wallet has the required keys
    pub fn validate(&self) -> Result<(), String> {
        // View key is always required
        if self.view_key_hex.is_empty() {
            return Err("View key is required".to_string());
        }

        // Either seed phrase or keys (or both) must be present
        if self.seed_phrase.is_none() && self.spend_key_hex.is_none() {
            // This is a view-only wallet, which is valid
        }

        Ok(())
    }

    /// Check if this wallet has a seed phrase
    pub fn has_seed_phrase(&self) -> bool {
        self.seed_phrase.is_some()
    }

    /// Check if this wallet has individual keys (always true now since view key is required)
    pub fn has_individual_keys(&self) -> bool {
        true
    }

    /// Check if this wallet can spend (has spend key or seed phrase)
    pub fn can_spend(&self) -> bool {
        self.seed_phrase.is_some() || self.spend_key_hex.is_some()
    }

    /// Get the view key as PrivateKey (decode from hex)
    pub fn get_view_key(&self) -> Result<PrivateKey, String> {
        let bytes =
            hex::decode(&self.view_key_hex).map_err(|e| format!("Invalid view key hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("View key must be 32 bytes, got {}", bytes.len()));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(PrivateKey::new(key_bytes))
    }

    /// Get the spend key as PrivateKey (decode from hex)
    pub fn get_spend_key(&self) -> Result<PrivateKey, String> {
        if let Some(hex_key) = &self.spend_key_hex {
            let bytes = hex::decode(hex_key).map_err(|e| format!("Invalid spend key hex: {e}"))?;
            if bytes.len() != 32 {
                return Err(format!("Spend key must be 32 bytes, got {}", bytes.len()));
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            Ok(PrivateKey::new(key_bytes))
        } else {
            Err("No spend key available".to_string())
        }
    }

    /// Get the resume block height (latest scanned block + 1, or birthday block if never scanned)
    pub fn get_resume_block(&self) -> u64 {
        self.latest_scanned_block
            .map(|block| block + 1)
            .unwrap_or(self.birthday_block)
    }
}

/// Storage query filters for retrieving transactions
#[derive(Debug, Clone, Default)]
pub struct TransactionFilter {
    /// Filter by wallet ID
    pub wallet_id: Option<u32>,
    /// Filter by block height range
    pub block_height_range: Option<(u64, u64)>,
    /// Filter by transaction direction
    pub direction: Option<TransactionDirection>,
    /// Filter by transaction status
    pub status: Option<TransactionStatus>,
    /// Filter by spent status
    pub is_spent: Option<bool>,
    /// Filter by maturity status
    pub is_mature: Option<bool>,
    /// Limit number of results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Transaction storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    /// Total number of transactions stored
    pub total_transactions: usize,
    /// Number of inbound transactions
    pub inbound_count: usize,
    /// Number of outbound transactions
    pub outbound_count: usize,
    /// Number of unspent transactions
    pub unspent_count: usize,
    /// Number of spent transactions
    pub spent_count: usize,
    /// Total value received
    pub total_received: u64,
    /// Total value spent
    pub total_spent: u64,
    /// Current balance
    pub current_balance: i64,
    /// Highest block height processed
    pub highest_block: Option<u64>,
    /// Lowest block height processed
    pub lowest_block: Option<u64>,
    /// Latest scanned block
    pub latest_scanned_block: Option<u64>,
}

/// Trait for wallet transaction storage backends
#[async_trait]
pub trait WalletStorage: Send + Sync {
    /// Initialize the storage backend (create tables, indexes, etc.)
    async fn initialize(&self) -> LightweightWalletResult<()>;

    // === Wallet Management Methods ===

    /// Save a wallet to storage (create or update)
    async fn save_wallet(&self, wallet: &StoredWallet) -> LightweightWalletResult<u32>;

    /// Get a wallet by ID
    async fn get_wallet_by_id(
        &self,
        wallet_id: u32,
    ) -> LightweightWalletResult<Option<StoredWallet>>;

    /// Get a wallet by name
    async fn get_wallet_by_name(&self, name: &str)
        -> LightweightWalletResult<Option<StoredWallet>>;

    /// List all wallets
    async fn list_wallets(&self) -> LightweightWalletResult<Vec<StoredWallet>>;

    /// Delete a wallet and all its transactions
    async fn delete_wallet(&self, wallet_id: u32) -> LightweightWalletResult<bool>;

    /// Check if a wallet name exists
    async fn wallet_name_exists(&self, name: &str) -> LightweightWalletResult<bool>;

    /// Update the latest scanned block for a wallet
    async fn update_wallet_scanned_block(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> LightweightWalletResult<()>;

    // === Transaction Management Methods (updated with wallet support) ===

    /// Save a single transaction to storage
    async fn save_transaction(
        &self,
        wallet_id: u32,
        transaction: &WalletTransaction,
    ) -> LightweightWalletResult<()>;

    /// Save multiple transactions in a batch for efficiency
    async fn save_transactions(
        &self,
        wallet_id: u32,
        transactions: &[WalletTransaction],
    ) -> LightweightWalletResult<()>;

    /// Update an existing transaction (e.g., mark as spent)
    async fn update_transaction(
        &self,
        transaction: &WalletTransaction,
    ) -> LightweightWalletResult<()>;

    /// Mark a transaction as spent by commitment
    async fn mark_transaction_spent(
        &self,
        commitment: &CompressedCommitment,
        spent_in_block: u64,
        spent_in_input: usize,
    ) -> LightweightWalletResult<bool>;

    /// Mark multiple transactions as spent in a batch for efficiency
    async fn mark_transactions_spent_batch(
        &self,
        spent_commitments: &[(CompressedCommitment, u64, usize)], // (commitment, block_height, input_index)
    ) -> LightweightWalletResult<usize>; // Returns number of transactions marked as spent

    /// Get a transaction by commitment
    async fn get_transaction_by_commitment(
        &self,
        commitment: &CompressedCommitment,
    ) -> LightweightWalletResult<Option<WalletTransaction>>;

    /// Get transactions with optional filtering
    async fn get_transactions(
        &self,
        filter: Option<TransactionFilter>,
    ) -> LightweightWalletResult<Vec<WalletTransaction>>;

    /// Get all transactions for a wallet and build a WalletState
    async fn load_wallet_state(&self, wallet_id: u32) -> LightweightWalletResult<WalletState>;

    /// Get storage statistics
    async fn get_statistics(&self) -> LightweightWalletResult<StorageStats>;

    /// Get storage statistics for a specific wallet
    async fn get_wallet_statistics(
        &self,
        wallet_id: Option<u32>,
    ) -> LightweightWalletResult<StorageStats>;

    /// Get transactions by block height range
    async fn get_transactions_by_block_range(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> LightweightWalletResult<Vec<WalletTransaction>>;

    /// Process all inputs in the specified block range and mark corresponding outputs as spent
    ///
    /// This method should be called after scanning to identify which outputs have been spent
    /// by inputs in the scanned blocks. It returns the number of outputs marked as spent.
    async fn mark_spent_outputs_from_inputs(
        &self,
        wallet_id: u32,
        from_block: u64,
        to_block: u64,
    ) -> LightweightWalletResult<usize>;

    /// Get unspent transactions only
    async fn get_unspent_transactions(&self) -> LightweightWalletResult<Vec<WalletTransaction>>;

    /// Get spent transactions only
    async fn get_spent_transactions(&self) -> LightweightWalletResult<Vec<WalletTransaction>>;

    /// Check if a commitment exists in storage
    async fn has_commitment(
        &self,
        commitment: &CompressedCommitment,
    ) -> LightweightWalletResult<bool>;

    /// Get the highest block height processed
    async fn get_highest_block(&self) -> LightweightWalletResult<Option<u64>>;

    /// Get the lowest block height processed
    async fn get_lowest_block(&self) -> LightweightWalletResult<Option<u64>>;

    /// Clear all transactions (useful for re-scanning)
    async fn clear_all_transactions(&self) -> LightweightWalletResult<()>;

    /// Get transaction count
    async fn get_transaction_count(&self) -> LightweightWalletResult<usize>;

    /// Close the storage connection gracefully
    async fn close(&self) -> LightweightWalletResult<()>;

    // === UTXO Output Management Methods (NEW) ===

    /// Save a UTXO output to storage
    async fn save_output(&self, output: &StoredOutput) -> LightweightWalletResult<u32>;

    /// Save multiple UTXO outputs in a batch
    async fn save_outputs(&self, outputs: &[StoredOutput]) -> LightweightWalletResult<Vec<u32>>;

    /// Update an existing output (e.g., mark as spent)
    async fn update_output(&self, output: &StoredOutput) -> LightweightWalletResult<()>;

    /// Mark an output as spent
    async fn mark_output_spent(
        &self,
        output_id: u32,
        spent_in_tx_id: u64,
    ) -> LightweightWalletResult<()>;

    /// Get an output by ID
    async fn get_output_by_id(
        &self,
        output_id: u32,
    ) -> LightweightWalletResult<Option<StoredOutput>>;

    /// Get an output by commitment
    async fn get_output_by_commitment(
        &self,
        commitment: &[u8],
    ) -> LightweightWalletResult<Option<StoredOutput>>;

    /// Get outputs with optional filtering
    async fn get_outputs(
        &self,
        filter: Option<OutputFilter>,
    ) -> LightweightWalletResult<Vec<StoredOutput>>;

    /// Get all unspent outputs for a wallet
    async fn get_unspent_outputs(
        &self,
        wallet_id: u32,
    ) -> LightweightWalletResult<Vec<StoredOutput>>;

    /// Get outputs spendable at a specific block height
    async fn get_spendable_outputs(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> LightweightWalletResult<Vec<StoredOutput>>;

    /// Get total value of unspent outputs for a wallet
    async fn get_spendable_balance(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> LightweightWalletResult<u64>;

    /// Delete an output
    async fn delete_output(&self, output_id: u32) -> LightweightWalletResult<bool>;

    /// Clear all outputs for a wallet
    async fn clear_outputs(&self, wallet_id: u32) -> LightweightWalletResult<()>;

    /// Get output count for a wallet
    async fn get_output_count(&self, wallet_id: u32) -> LightweightWalletResult<usize>;
}

impl TransactionFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by wallet ID
    pub fn with_wallet_id(mut self, wallet_id: u32) -> Self {
        self.wallet_id = Some(wallet_id);
        self
    }

    /// Filter by block height range
    pub fn with_block_range(mut self, from: u64, to: u64) -> Self {
        self.block_height_range = Some((from, to));
        self
    }

    /// Filter by transaction direction
    pub fn with_direction(mut self, direction: TransactionDirection) -> Self {
        self.direction = Some(direction);
        self
    }

    /// Filter by transaction status
    pub fn with_status(mut self, status: TransactionStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Filter by spent status
    pub fn with_spent_status(mut self, is_spent: bool) -> Self {
        self.is_spent = Some(is_spent);
        self
    }

    /// Filter by maturity status
    pub fn with_maturity(mut self, is_mature: bool) -> Self {
        self.is_mature = Some(is_mature);
        self
    }

    /// Limit results
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set offset for pagination
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }
}
