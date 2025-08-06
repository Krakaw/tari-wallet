use serde::{Deserialize, Serialize};

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
    pub block_hash: Option<Vec<u8>>, // Block hash when mined
    pub spent_in_tx_id: Option<u64>, // Transaction ID where spent

    // Timestamps
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}
