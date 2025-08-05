//! Event type definitions and data structures for wallet scanning operations
//!
//! This module defines the core event types and shared traits used throughout
//! the wallet scanner event system. Events are designed to be efficiently
//! shared between listeners using Arc<Event> pattern.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Shared event metadata present in all events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    /// Unique identifier for this event
    pub event_id: String,
    /// Timestamp when the event was created
    pub timestamp: SystemTime,
    /// Optional correlation ID for tracking related events
    pub correlation_id: Option<String>,
    /// Source component that emitted this event
    pub source: String,
}

impl EventMetadata {
    /// Create new event metadata with generated ID
    pub fn new(source: &str) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: SystemTime::now(),
            correlation_id: None,
            source: source.to_string(),
        }
    }

    /// Create new event metadata with correlation ID
    pub fn with_correlation(source: &str, correlation_id: String) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: SystemTime::now(),
            correlation_id: Some(correlation_id),
            source: source.to_string(),
        }
    }
}

/// Trait for events that can provide their type name
pub trait EventType {
    /// Get the string name of this event type
    fn event_type(&self) -> &'static str;

    /// Get metadata associated with this event
    fn metadata(&self) -> &EventMetadata;

    /// Get optional serialized data for debugging
    fn debug_data(&self) -> Option<String> {
        None
    }
}

/// Trait for events that can be serialized for debugging/logging
pub trait SerializableEvent {
    /// Serialize event to JSON string for debugging (pretty-printed)
    fn to_debug_json(&self) -> Result<String, String>;

    /// Serialize event to compact JSON string for performance
    fn to_compact_json(&self) -> Result<String, String>;

    /// Get human-readable summary of the event
    fn summary(&self) -> String;
}

/// Configuration data for scanning operations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanConfig {
    pub batch_size: Option<usize>,
    pub timeout_seconds: Option<u64>,
    pub retry_attempts: Option<u32>,
    pub scan_mode: Option<String>,
    pub filters: HashMap<String, String>,
}

/// Complete output data information for OutputFound events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputData {
    /// The commitment value of the output
    pub commitment: String,
    /// The range proof associated with the output
    pub range_proof: String,
    /// The encrypted value of the output (if available)
    pub encrypted_value: Option<Vec<u8>>,
    /// The script associated with the output (if any)
    pub script: Option<String>,
    /// Features flags for this output
    pub features: u32,
    /// Maturity height (if applicable)
    pub maturity_height: Option<u64>,
    /// The amount value (if decrypted successfully)
    pub amount: Option<u64>,
    /// Whether this output belongs to our wallet
    pub is_mine: bool,
    /// Spending key index used (if this is our output)
    pub key_index: Option<u64>,
}

/// Information about a spent output for SpentOutputFound events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpentOutputData {
    /// The commitment of the spent output
    pub spent_commitment: String,
    /// The output hash of the spent output (if available)
    pub spent_output_hash: Option<String>,
    /// The input index in the spending transaction
    pub input_index: usize,
    /// The amount that was spent (if known)
    pub spent_amount: Option<u64>,
    /// The block height where the output was originally found
    pub original_block_height: u64,
    /// The block height where the output was spent
    pub spending_block_height: u64,
    /// Whether this was matched by output hash or commitment
    pub match_method: String, // "output_hash" or "commitment"
}

impl SpentOutputData {
    /// Create a new SpentOutputData with required fields
    pub fn new(
        spent_commitment: String,
        input_index: usize,
        original_block_height: u64,
        spending_block_height: u64,
        match_method: String,
    ) -> Self {
        Self {
            spent_commitment,
            spent_output_hash: None,
            input_index,
            spent_amount: None,
            original_block_height,
            spending_block_height,
            match_method,
        }
    }

    /// Set the output hash for this spent output
    pub fn with_output_hash(mut self, output_hash: String) -> Self {
        self.spent_output_hash = Some(output_hash);
        self
    }

    /// Set the spent amount for this output
    pub fn with_spent_amount(mut self, amount: u64) -> Self {
        self.spent_amount = Some(amount);
        self
    }
}

impl OutputData {
    /// Create a new OutputData with required fields
    pub fn new(commitment: String, range_proof: String, features: u32, is_mine: bool) -> Self {
        Self {
            commitment,
            range_proof,
            encrypted_value: None,
            script: None,
            features,
            maturity_height: None,
            amount: None,
            is_mine,
            key_index: None,
        }
    }

    /// Set the decrypted amount
    pub fn with_amount(mut self, amount: u64) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Set the key index for owned outputs
    pub fn with_key_index(mut self, key_index: u64) -> Self {
        self.key_index = Some(key_index);
        self
    }

    /// Set the maturity height
    pub fn with_maturity_height(mut self, height: u64) -> Self {
        self.maturity_height = Some(height);
        self
    }

    /// Set the script
    pub fn with_script(mut self, script: String) -> Self {
        self.script = Some(script);
        self
    }

    /// Set encrypted value
    pub fn with_encrypted_value(mut self, encrypted_value: Vec<u8>) -> Self {
        self.encrypted_value = Some(encrypted_value);
        self
    }
}

/// Block information associated with an output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    /// Block height where the output was found
    pub height: u64,
    /// Block hash
    pub hash: String,
    /// Block timestamp
    pub timestamp: u64,
    /// Transaction index within the block
    pub transaction_index: Option<usize>,
    /// Output index within the transaction
    pub output_index: usize,
    /// Block difficulty (if available)
    pub difficulty: Option<u64>,
}

impl BlockInfo {
    /// Create new block info with required fields
    pub fn new(height: u64, hash: String, timestamp: u64, output_index: usize) -> Self {
        Self {
            height,
            hash,
            timestamp,
            transaction_index: None,
            output_index,
            difficulty: None,
        }
    }

    /// Set the transaction index
    pub fn with_transaction_index(mut self, tx_index: usize) -> Self {
        self.transaction_index = Some(tx_index);
        self
    }

    /// Set the block difficulty
    pub fn with_difficulty(mut self, difficulty: u64) -> Self {
        self.difficulty = Some(difficulty);
        self
    }
}

/// Transaction data information for wallet transaction storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionData {
    /// Transaction value in microTari
    pub value: u64,
    /// Transaction status (e.g., "Unspent", "Spent", "Pending")
    pub status: String,
    /// Transaction direction ("Inbound" or "Outbound")
    pub direction: String,
    /// Optional output index in the transaction
    pub output_index: Option<usize>,
    /// Optional payment ID for tracking
    pub payment_id: Option<String>,
    /// Fee paid for the transaction (if outbound)
    pub fee: Option<u64>,
    /// Kernel excess for the transaction
    pub kernel_excess: Option<String>,
    /// Transaction timestamp
    pub timestamp: u64,
}

impl TransactionData {
    /// Create new transaction data with required fields
    pub fn new(value: u64, status: String, direction: String, timestamp: u64) -> Self {
        Self {
            value,
            status,
            direction,
            output_index: None,
            payment_id: None,
            fee: None,
            kernel_excess: None,
            timestamp,
        }
    }

    /// Set the output index
    pub fn with_output_index(mut self, output_index: usize) -> Self {
        self.output_index = Some(output_index);
        self
    }

    /// Set the payment ID
    pub fn with_payment_id(mut self, payment_id: String) -> Self {
        self.payment_id = Some(payment_id);
        self
    }

    /// Set the transaction fee
    pub fn with_fee(mut self, fee: u64) -> Self {
        self.fee = Some(fee);
        self
    }

    /// Set the kernel excess
    pub fn with_kernel_excess(mut self, kernel_excess: String) -> Self {
        self.kernel_excess = Some(kernel_excess);
        self
    }
}

/// Address information for the output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    /// The address that can spend this output
    pub address: String,
    /// Address type (e.g., "stealth", "standard", "script")
    pub address_type: String,
    /// Network type (e.g., "mainnet", "testnet", "localnet")
    pub network: String,
    /// Derivation path for deterministic wallets
    pub derivation_path: Option<String>,
    /// Public spend key (if applicable)
    pub public_spend_key: Option<String>,
    /// View key used for scanning (if applicable)
    pub view_key: Option<String>,
}

impl AddressInfo {
    /// Create new address info with required fields
    pub fn new(address: String, address_type: String, network: String) -> Self {
        Self {
            address,
            address_type,
            network,
            derivation_path: None,
            public_spend_key: None,
            view_key: None,
        }
    }

    /// Set the derivation path
    pub fn with_derivation_path(mut self, path: String) -> Self {
        self.derivation_path = Some(path);
        self
    }

    /// Set the public spend key
    pub fn with_public_spend_key(mut self, key: String) -> Self {
        self.public_spend_key = Some(key);
        self
    }

    /// Set the view key
    pub fn with_view_key(mut self, key: String) -> Self {
        self.view_key = Some(key);
        self
    }
}

/// Error types for wallet event processing failures
#[derive(Debug, Error, Clone)]
pub enum WalletEventError {
    /// Event validation failed
    #[error("Event validation failed: {message}")]
    ValidationError { message: String, event_type: String },

    /// Event serialization failed
    #[error("Event serialization failed for {event_type}: {message}")]
    SerializationError { message: String, event_type: String },

    /// Event deserialization failed
    #[error("Event deserialization failed: {message}")]
    DeserializationError {
        message: String,
        data_snippet: String,
    },

    /// Event metadata is invalid or missing required fields
    #[error("Invalid event metadata: {field} - {message}")]
    InvalidMetadata { field: String, message: String },

    /// Event payload is invalid or contains inconsistent data
    #[error("Invalid event payload for {event_type}: {field} - {message}")]
    InvalidPayload {
        event_type: String,
        field: String,
        message: String,
    },

    /// Event processing failed due to business logic constraints
    #[error("Event processing failed for {event_type}: {reason}")]
    ProcessingError { event_type: String, reason: String },

    /// Event listener encountered an error
    #[error("Event listener '{listener_name}' failed: {error}")]
    ListenerError {
        listener_name: String,
        error: String,
    },

    /// Event replay failed
    #[error("Event replay failed at sequence {sequence}: {reason}")]
    ReplayError { sequence: u64, reason: String },

    /// Event storage operation failed
    #[error("Event storage operation failed: {operation} - {reason}")]
    StorageError { operation: String, reason: String },

    /// Event sequence is invalid (out of order, duplicate, etc.)
    #[error("Invalid event sequence: expected {expected}, got {actual}")]
    SequenceError { expected: u64, actual: u64 },

    /// Event already exists (duplicate event ID)
    #[error("Event with ID '{event_id}' already exists")]
    DuplicateEvent { event_id: String },

    /// Event not found
    #[error("Event with ID '{event_id}' not found")]
    EventNotFound { event_id: String },

    /// Wallet ID mismatch in event
    #[error("Wallet ID mismatch: expected '{expected}', found '{actual}'")]
    WalletIdMismatch { expected: String, actual: String },

    /// Event type mismatch during processing
    #[error("Event type mismatch: expected '{expected}', found '{actual}'")]
    EventTypeMismatch { expected: String, actual: String },

    /// Invalid block height in event
    #[error("Invalid block height {height}: {reason}")]
    InvalidBlockHeight { height: u64, reason: String },

    /// Invalid amount in event
    #[error("Invalid amount {amount}: {reason}")]
    InvalidAmount { amount: String, reason: String },

    /// Invalid UTXO state transition
    #[error("Invalid UTXO state transition for {utxo_id}: {from_state} -> {to_state}")]
    InvalidStateTransition {
        utxo_id: String,
        from_state: String,
        to_state: String,
    },

    /// Concurrent modification detected
    #[error("Concurrent modification detected for {resource}: {details}")]
    ConcurrentModification { resource: String, details: String },

    /// Event timeout during processing
    #[error("Event processing timeout after {seconds}s for {event_type}")]
    ProcessingTimeout { event_type: String, seconds: u64 },

    /// Configuration error
    #[error("Event system configuration error: {parameter} - {message}")]
    ConfigurationError { parameter: String, message: String },

    /// Network-related error during event processing
    #[error("Network error during event processing: {operation} - {error}")]
    NetworkError { operation: String, error: String },

    /// Insufficient permissions for event operation
    #[error("Insufficient permissions for {operation}: {reason}")]
    PermissionDenied { operation: String, reason: String },

    /// Generic internal error
    #[error("Internal error during event processing: {details}")]
    InternalError { details: String },
}

/// Validation-specific errors for wallet events
#[derive(Debug, Error, Clone)]
pub enum WalletEventValidationError {
    /// Required field is missing
    #[error("Required field '{field}' is missing")]
    MissingField { field: String },

    /// Field value is out of valid range
    #[error("Field '{field}' value {value} is out of range: {constraint}")]
    OutOfRange {
        field: String,
        value: String,
        constraint: String,
    },

    /// Field format is invalid
    #[error("Field '{field}' has invalid format: {value} (expected: {expected_format})")]
    InvalidFormat {
        field: String,
        value: String,
        expected_format: String,
    },

    /// Field contains invalid characters
    #[error("Field '{field}' contains invalid characters: {value}")]
    InvalidCharacters { field: String, value: String },

    /// Field length exceeds maximum allowed
    #[error("Field '{field}' length {actual} exceeds maximum {max}")]
    FieldTooLong {
        field: String,
        actual: usize,
        max: usize,
    },

    /// Field is too short
    #[error("Field '{field}' length {actual} is below minimum {min}")]
    FieldTooShort {
        field: String,
        actual: usize,
        min: usize,
    },

    /// Cross-field validation failed
    #[error("Cross-field validation failed: {field1} and {field2} - {reason}")]
    CrossFieldValidation {
        field1: String,
        field2: String,
        reason: String,
    },

    /// Business rule validation failed
    #[error("Business rule validation failed: {rule} - {reason}")]
    BusinessRuleViolation { rule: String, reason: String },

    /// Duplicate value where uniqueness is required
    #[error("Duplicate value for unique field '{field}': {value}")]
    DuplicateValue { field: String, value: String },

    /// Referenced entity does not exist
    #[error("Referenced {entity_type} '{entity_id}' does not exist")]
    ReferenceNotFound {
        entity_type: String,
        entity_id: String,
    },
}

/// Event listener-specific errors
#[derive(Debug, Error, Clone)]
pub enum EventListenerError {
    /// Listener initialization failed
    #[error("Listener '{name}' initialization failed: {reason}")]
    InitializationFailed { name: String, reason: String },

    /// Listener is not in a valid state for operation
    #[error("Listener '{name}' is in invalid state '{state}' for operation '{operation}'")]
    InvalidState {
        name: String,
        state: String,
        operation: String,
    },

    /// Listener configuration is invalid
    #[error("Listener '{name}' has invalid configuration: {parameter} - {message}")]
    InvalidConfiguration {
        name: String,
        parameter: String,
        message: String,
    },

    /// Listener dependency is missing or unavailable
    #[error("Listener '{name}' dependency '{dependency}' is unavailable: {reason}")]
    DependencyUnavailable {
        name: String,
        dependency: String,
        reason: String,
    },

    /// Resource limit exceeded
    #[error("Listener '{name}' exceeded {resource} limit: {current}/{max}")]
    ResourceLimitExceeded {
        name: String,
        resource: String,
        current: u64,
        max: u64,
    },
}

impl WalletEventError {
    /// Create a validation error
    pub fn validation(message: impl Into<String>, event_type: impl Into<String>) -> Self {
        Self::ValidationError {
            message: message.into(),
            event_type: event_type.into(),
        }
    }

    /// Create a serialization error
    pub fn serialization(message: impl Into<String>, event_type: impl Into<String>) -> Self {
        Self::SerializationError {
            message: message.into(),
            event_type: event_type.into(),
        }
    }

    /// Create a deserialization error
    pub fn deserialization(message: impl Into<String>, data_snippet: impl Into<String>) -> Self {
        Self::DeserializationError {
            message: message.into(),
            data_snippet: data_snippet.into(),
        }
    }

    /// Create a processing error
    pub fn processing(event_type: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::ProcessingError {
            event_type: event_type.into(),
            reason: reason.into(),
        }
    }

    /// Create a storage error
    pub fn storage(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::StorageError {
            operation: operation.into(),
            reason: reason.into(),
        }
    }

    /// Create an invalid payload error
    pub fn invalid_payload(
        event_type: impl Into<String>,
        field: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::InvalidPayload {
            event_type: event_type.into(),
            field: field.into(),
            message: message.into(),
        }
    }

    /// Check if this error is recoverable (can be retried)
    pub fn is_recoverable(&self) -> bool {
        match self {
            // Transient errors that might succeed on retry
            Self::NetworkError { .. }
            | Self::ProcessingTimeout { .. }
            | Self::StorageError { .. }
            | Self::ConcurrentModification { .. } => true,

            // Permanent errors that won't succeed on retry
            Self::ValidationError { .. }
            | Self::SerializationError { .. }
            | Self::DeserializationError { .. }
            | Self::InvalidMetadata { .. }
            | Self::InvalidPayload { .. }
            | Self::DuplicateEvent { .. }
            | Self::EventNotFound { .. }
            | Self::WalletIdMismatch { .. }
            | Self::EventTypeMismatch { .. }
            | Self::InvalidBlockHeight { .. }
            | Self::InvalidAmount { .. }
            | Self::InvalidStateTransition { .. }
            | Self::ConfigurationError { .. }
            | Self::PermissionDenied { .. } => false,

            // Context-dependent errors
            Self::ProcessingError { .. }
            | Self::ListenerError { .. }
            | Self::ReplayError { .. }
            | Self::SequenceError { .. }
            | Self::InternalError { .. } => false,
        }
    }

    /// Get the error category for metrics/logging
    pub fn category(&self) -> &'static str {
        match self {
            Self::ValidationError { .. }
            | Self::InvalidMetadata { .. }
            | Self::InvalidPayload { .. } => "validation",
            Self::SerializationError { .. } | Self::DeserializationError { .. } => "serialization",
            Self::ProcessingError { .. } | Self::ListenerError { .. } => "processing",
            Self::ReplayError { .. } | Self::SequenceError { .. } => "replay",
            Self::StorageError { .. }
            | Self::DuplicateEvent { .. }
            | Self::EventNotFound { .. } => "storage",
            Self::WalletIdMismatch { .. } | Self::EventTypeMismatch { .. } => "consistency",
            Self::InvalidBlockHeight { .. }
            | Self::InvalidAmount { .. }
            | Self::InvalidStateTransition { .. } => "business_logic",
            Self::ConcurrentModification { .. } | Self::ProcessingTimeout { .. } => "concurrency",
            Self::ConfigurationError { .. } => "configuration",
            Self::NetworkError { .. } => "network",
            Self::PermissionDenied { .. } => "security",
            Self::InternalError { .. } => "internal",
        }
    }
}

/// Convert from validation errors
impl From<WalletEventValidationError> for WalletEventError {
    fn from(err: WalletEventValidationError) -> Self {
        Self::ValidationError {
            message: err.to_string(),
            event_type: "unknown".to_string(),
        }
    }
}

/// Convert from listener errors
impl From<EventListenerError> for WalletEventError {
    fn from(err: EventListenerError) -> Self {
        Self::ListenerError {
            listener_name: "unknown".to_string(),
            error: err.to_string(),
        }
    }
}

/// Convert from serde JSON errors
impl From<serde_json::Error> for WalletEventError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError {
            message: err.to_string(),
            event_type: "unknown".to_string(),
        }
    }
}

/// Result type for wallet event operations
pub type WalletEventResult<T> = Result<T, WalletEventError>;

/// Specific payload structures for wallet events

/// Payload for UTXO received events - captures the essential data about a newly received UTXO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoReceivedPayload {
    /// Unique identifier for the UTXO (commitment or output hash)
    pub utxo_id: String,
    /// The amount received in microTari
    pub amount: u64,
    /// Block height where the UTXO was confirmed
    pub block_height: u64,
    /// Block hash where the UTXO was confirmed
    pub block_hash: String,
    /// Block timestamp
    pub block_timestamp: u64,
    /// Transaction hash containing this output
    pub transaction_hash: String,
    /// Output index within the transaction
    pub output_index: usize,
    /// The wallet address that received this UTXO
    pub receiving_address: String,
    /// Key index used for this output (for deterministic wallets)
    pub key_index: u64,
    /// Commitment value
    pub commitment: String,
    /// Features flags for this output
    pub features: u32,
    /// Maturity height (if applicable for coinbase outputs)
    pub maturity_height: Option<u64>,
    /// Script associated with the output (if any)
    pub script_hash: Option<String>,
    /// Whether this output requires additional unlocking conditions
    pub has_unlock_conditions: bool,
    /// Network where this UTXO exists (mainnet, testnet, etc.)
    pub network: String,
}

impl UtxoReceivedPayload {
    /// Create a new UTXO received payload with required fields
    pub fn new(
        utxo_id: String,
        amount: u64,
        block_height: u64,
        block_hash: String,
        block_timestamp: u64,
        transaction_hash: String,
        output_index: usize,
        receiving_address: String,
        key_index: u64,
        commitment: String,
        features: u32,
        network: String,
    ) -> Self {
        Self {
            utxo_id,
            amount,
            block_height,
            block_hash,
            block_timestamp,
            transaction_hash,
            output_index,
            receiving_address,
            key_index,
            commitment,
            features,
            maturity_height: None,
            script_hash: None,
            has_unlock_conditions: false,
            network,
        }
    }

    /// Set maturity height for coinbase outputs
    pub fn with_maturity_height(mut self, height: u64) -> Self {
        self.maturity_height = Some(height);
        self
    }

    /// Set script hash if output has a script
    pub fn with_script_hash(mut self, script_hash: String) -> Self {
        self.script_hash = Some(script_hash);
        self
    }

    /// Mark as having unlock conditions
    pub fn with_unlock_conditions(mut self) -> Self {
        self.has_unlock_conditions = true;
        self
    }
}

/// Payload for UTXO spent events - captures the essential data about a spent UTXO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoSpentPayload {
    /// Unique identifier for the spent UTXO
    pub utxo_id: String,
    /// The amount that was spent in microTari
    pub amount: u64,
    /// Block height where the UTXO was originally received
    pub original_block_height: u64,
    /// Block height where the UTXO was spent
    pub spending_block_height: u64,
    /// Block hash where the spending occurred
    pub spending_block_hash: String,
    /// Block timestamp when spent
    pub spending_block_timestamp: u64,
    /// Transaction hash that spent this UTXO
    pub spending_transaction_hash: String,
    /// Input index within the spending transaction
    pub input_index: usize,
    /// The wallet address that owned this UTXO
    pub spending_address: String,
    /// Key index used for this output
    pub key_index: u64,
    /// Commitment value of the spent output
    pub commitment: String,
    /// How the spent output was matched (commitment, output_hash, etc.)
    pub match_method: String,
    /// Fee paid for the spending transaction (if this wallet initiated it)
    pub transaction_fee: Option<u64>,
    /// Whether this was an intentional spend by our wallet or external
    pub is_self_spend: bool,
    /// Network where this spend occurred
    pub network: String,
}

impl UtxoSpentPayload {
    /// Create a new UTXO spent payload with required fields
    pub fn new(
        utxo_id: String,
        amount: u64,
        original_block_height: u64,
        spending_block_height: u64,
        spending_block_hash: String,
        spending_block_timestamp: u64,
        spending_transaction_hash: String,
        input_index: usize,
        spending_address: String,
        key_index: u64,
        commitment: String,
        match_method: String,
        is_self_spend: bool,
        network: String,
    ) -> Self {
        Self {
            utxo_id,
            amount,
            original_block_height,
            spending_block_height,
            spending_block_hash,
            spending_block_timestamp,
            spending_transaction_hash,
            input_index,
            spending_address,
            key_index,
            commitment,
            match_method,
            transaction_fee: None,
            is_self_spend,
            network,
        }
    }

    /// Set transaction fee if this was a self-spend
    pub fn with_transaction_fee(mut self, fee: u64) -> Self {
        self.transaction_fee = Some(fee);
        self
    }
}

/// Payload for blockchain reorganization events - captures reorg impact on wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReorgPayload {
    /// The block height where the reorg diverged from our chain
    pub fork_height: u64,
    /// The old block hash at the fork point
    pub old_block_hash: String,
    /// The new block hash at the fork point
    pub new_block_hash: String,
    /// How many blocks were rolled back
    pub rollback_depth: u64,
    /// How many new blocks were added in the reorg
    pub new_blocks_count: u64,
    /// List of transaction hashes that were affected (removed/added)
    pub affected_transaction_hashes: Vec<String>,
    /// List of UTXO IDs that were affected by the reorg
    pub affected_utxo_ids: Vec<String>,
    /// UTXOs that were invalidated (no longer exist after reorg)
    pub invalidated_utxos: Vec<String>,
    /// UTXOs that were restored (exist again after reorg)  
    pub restored_utxos: Vec<String>,
    /// Balance change due to the reorg (positive = gained, negative = lost)
    pub balance_change: i64,
    /// Network where this reorg occurred
    pub network: String,
    /// Timestamp when the reorg was detected
    pub detection_timestamp: u64,
    /// Additional recovery information for debugging
    pub recovery_info: HashMap<String, String>,
}

impl ReorgPayload {
    /// Create a new reorg payload with required fields
    pub fn new(
        fork_height: u64,
        old_block_hash: String,
        new_block_hash: String,
        rollback_depth: u64,
        new_blocks_count: u64,
        affected_transaction_hashes: Vec<String>,
        affected_utxo_ids: Vec<String>,
        balance_change: i64,
        network: String,
        detection_timestamp: u64,
    ) -> Self {
        Self {
            fork_height,
            old_block_hash,
            new_block_hash,
            rollback_depth,
            new_blocks_count,
            affected_transaction_hashes,
            affected_utxo_ids,
            invalidated_utxos: Vec::new(),
            restored_utxos: Vec::new(),
            balance_change,
            network,
            detection_timestamp,
            recovery_info: HashMap::new(),
        }
    }

    /// Add invalidated UTXOs
    pub fn with_invalidated_utxos(mut self, utxo_ids: Vec<String>) -> Self {
        self.invalidated_utxos = utxo_ids;
        self
    }

    /// Add restored UTXOs
    pub fn with_restored_utxos(mut self, utxo_ids: Vec<String>) -> Self {
        self.restored_utxos = utxo_ids;
        self
    }

    /// Add recovery information
    pub fn with_recovery_info(mut self, key: String, value: String) -> Self {
        self.recovery_info.insert(key, value);
        self
    }
}

impl ScanConfig {
    /// Create a new scan configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set batch size for processing
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = Some(batch_size);
        self
    }

    /// Set timeout for operations
    pub fn with_timeout_seconds(mut self, timeout: u64) -> Self {
        self.timeout_seconds = Some(timeout);
        self
    }

    /// Set retry attempts for failed operations
    pub fn with_retry_attempts(mut self, attempts: u32) -> Self {
        self.retry_attempts = Some(attempts);
        self
    }

    /// Add a filter parameter
    pub fn with_filter(mut self, key: String, value: String) -> Self {
        self.filters.insert(key, value);
        self
    }
}

/// Core event types emitted during wallet scanning operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletScanEvent {
    /// Emitted when a scan operation begins
    ScanStarted {
        metadata: EventMetadata,
        config: ScanConfig,
        block_range: (u64, u64),
        wallet_context: String,
    },
    /// Emitted when a block is processed
    BlockProcessed {
        metadata: EventMetadata,
        height: u64,
        hash: String,
        timestamp: u64,
        processing_duration: Duration,
        outputs_count: usize,
        spent_outputs_count: usize,
    },
    /// Emitted when an output is found for the wallet
    OutputFound {
        metadata: EventMetadata,
        output_data: OutputData,
        block_info: BlockInfo,
        address_info: AddressInfo,
        transaction_data: TransactionData,
    },
    /// Emitted when a previously found output is spent (input detected)
    SpentOutputFound {
        metadata: EventMetadata,
        spent_output_data: SpentOutputData,
        spending_block_info: BlockInfo,
        original_output_info: OutputData,
        spending_transaction_data: TransactionData,
    },
    /// Emitted periodically to report scan progress
    ScanProgress {
        metadata: EventMetadata,
        current_block: u64,
        total_blocks: u64,
        current_block_height: u64,
        percentage: f64,
        speed_blocks_per_second: f64,
        estimated_time_remaining: Option<Duration>,
    },
    /// Emitted when scan completes successfully
    ScanCompleted {
        metadata: EventMetadata,
        final_statistics: HashMap<String, u64>,
        success: bool,
        total_duration: Duration,
    },
    /// Emitted when an error occurs during scanning
    ScanError {
        metadata: EventMetadata,
        error_message: String,
        error_code: Option<String>,
        block_height: Option<u64>,
        retry_info: Option<String>,
        is_recoverable: bool,
    },
    /// Emitted when scanning is cancelled
    ScanCancelled {
        metadata: EventMetadata,
        reason: String,
        final_statistics: HashMap<String, u64>,
        partial_completion: Option<f64>,
    },
}

impl EventType for WalletScanEvent {
    fn event_type(&self) -> &'static str {
        match self {
            WalletScanEvent::ScanStarted { .. } => "ScanStarted",
            WalletScanEvent::BlockProcessed { .. } => "BlockProcessed",
            WalletScanEvent::OutputFound { .. } => "OutputFound",
            WalletScanEvent::SpentOutputFound { .. } => "SpentOutputFound",
            WalletScanEvent::ScanProgress { .. } => "ScanProgress",
            WalletScanEvent::ScanCompleted { .. } => "ScanCompleted",
            WalletScanEvent::ScanError { .. } => "ScanError",
            WalletScanEvent::ScanCancelled { .. } => "ScanCancelled",
        }
    }

    fn metadata(&self) -> &EventMetadata {
        match self {
            WalletScanEvent::ScanStarted { metadata, .. } => metadata,
            WalletScanEvent::BlockProcessed { metadata, .. } => metadata,
            WalletScanEvent::OutputFound { metadata, .. } => metadata,
            WalletScanEvent::SpentOutputFound { metadata, .. } => metadata,
            WalletScanEvent::ScanProgress { metadata, .. } => metadata,
            WalletScanEvent::ScanCompleted { metadata, .. } => metadata,
            WalletScanEvent::ScanError { metadata, .. } => metadata,
            WalletScanEvent::ScanCancelled { metadata, .. } => metadata,
        }
    }

    fn debug_data(&self) -> Option<String> {
        // Provide basic debug information for each event type
        match self {
            WalletScanEvent::ScanStarted {
                block_range,
                wallet_context,
                ..
            } => Some(format!(
                "blocks: {}-{}, wallet: {wallet_context}",
                block_range.0, block_range.1
            )),
            WalletScanEvent::BlockProcessed {
                height,
                outputs_count,
                ..
            } => Some(format!("height: {height}, outputs: {outputs_count}")),
            WalletScanEvent::OutputFound {
                block_info,
                output_data,
                ..
            } => {
                let amount_str = output_data
                    .amount
                    .map_or("unknown".to_string(), |a| a.to_string());
                Some(format!(
                    "block: {}, amount: {amount_str}, mine: {}",
                    block_info.height, output_data.is_mine
                ))
            }
            WalletScanEvent::SpentOutputFound {
                spending_block_info,
                spent_output_data,
                ..
            } => {
                let amount_str = spent_output_data
                    .spent_amount
                    .map_or("unknown".to_string(), |a| a.to_string());
                Some(format!(
                    "block: {}, amount: {amount_str}, method: {}, input: {}",
                    spending_block_info.height,
                    spent_output_data.match_method,
                    spent_output_data.input_index
                ))
            }
            WalletScanEvent::ScanProgress {
                current_block,
                total_blocks,
                percentage,
                speed_blocks_per_second,
                estimated_time_remaining,
                ..
            } => {
                let eta_str = estimated_time_remaining.map_or("unknown".to_string(), |dur| {
                    let secs = dur.as_secs();
                    format!("{secs}s")
                });
                Some(format!(
                    "{current_block}/{total_blocks} ({percentage:.1}%), speed: {speed_blocks_per_second:.1} bps, ETA: {eta_str}"
                ))
            }
            WalletScanEvent::ScanCompleted {
                success,
                final_statistics,
                total_duration,
                ..
            } => {
                let stats_count = final_statistics.len();
                Some(format!(
                    "success: {success}, duration: {total_duration:?}, stats: {stats_count} items"
                ))
            }
            WalletScanEvent::ScanError {
                error_message,
                block_height,
                ..
            } => Some(format!("error: {error_message}, block: {block_height:?}")),
            WalletScanEvent::ScanCancelled { reason, .. } => Some(format!("reason: {reason}")),
        }
    }
}

impl SerializableEvent for WalletScanEvent {
    fn to_debug_json(&self) -> Result<String, String> {
        // Use serde_json for proper JSON serialization (pretty-printed for debugging)
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    fn to_compact_json(&self) -> Result<String, String> {
        // Use serde_json for compact JSON serialization (performance-focused)
        serde_json::to_string(self).map_err(|e| e.to_string())
    }

    fn summary(&self) -> String {
        match self {
            WalletScanEvent::ScanStarted {
                block_range,
                wallet_context,
                ..
            } => {
                format!(
                    "Scan started for wallet '{wallet_context}' on blocks {}-{}",
                    block_range.0, block_range.1
                )
            }
            WalletScanEvent::BlockProcessed {
                height,
                outputs_count,
                ..
            } => {
                format!("Processed block {height} with {outputs_count} outputs")
            }
            WalletScanEvent::OutputFound {
                block_info,
                output_data,
                address_info,
                ..
            } => {
                let amount_str = output_data
                    .amount
                    .map_or("unknown amount".to_string(), |a| format!("{a} units"));
                let mine_str = if output_data.is_mine {
                    "mine"
                } else {
                    "not mine"
                };
                format!(
                    "Found output at block {} ({amount_str}, {mine_str}, addr: {})",
                    block_info.height, address_info.address
                )
            }
            WalletScanEvent::SpentOutputFound {
                spending_block_info,
                spent_output_data,
                original_output_info,
                ..
            } => {
                let amount_str = spent_output_data
                    .spent_amount
                    .or(original_output_info.amount)
                    .map_or("unknown amount".to_string(), |a| format!("{a} units"));
                format!(
                    "Output spent at block {} ({amount_str}, method: {}, input index: {})",
                    spending_block_info.height,
                    spent_output_data.match_method,
                    spent_output_data.input_index
                )
            }
            WalletScanEvent::ScanProgress {
                current_block,
                total_blocks,
                percentage,
                speed_blocks_per_second,
                estimated_time_remaining,
                ..
            } => {
                let eta_str = estimated_time_remaining.map_or("unknown ETA".to_string(), |dur| {
                    let secs = dur.as_secs();
                    if secs < 60 {
                        format!("{secs}s")
                    } else if secs < 3600 {
                        let mins = secs / 60;
                        let rem_secs = secs % 60;
                        format!("{mins}m {rem_secs}s")
                    } else {
                        let hours = secs / 3600;
                        let rem_mins = (secs % 3600) / 60;
                        format!("{hours}h {rem_mins}m")
                    }
                });
                format!(
                    "Scan progress: {current_block}/{total_blocks} blocks ({percentage:.1}%) at {speed_blocks_per_second:.1} blocks/sec, {eta_str}"
                )
            }
            WalletScanEvent::ScanCompleted {
                success,
                final_statistics,
                total_duration,
                ..
            } => {
                let duration_str = {
                    let secs = total_duration.as_secs();
                    if secs < 60 {
                        format!("{secs}s")
                    } else if secs < 3600 {
                        let mins = secs / 60;
                        let rem_secs = secs % 60;
                        format!("{mins}m {rem_secs}s")
                    } else {
                        let hours = secs / 3600;
                        let rem_mins = (secs % 3600) / 60;
                        format!("{hours}h {rem_mins}m")
                    }
                };

                let key_stats = [
                    ("blocks_processed", "blocks"),
                    ("outputs_found", "outputs"),
                    ("transactions_found", "transactions"),
                    ("errors_encountered", "errors"),
                ]
                .iter()
                .filter_map(|(key, unit)| {
                    final_statistics
                        .get(*key)
                        .map(|value| format!("{value} {unit}"))
                })
                .collect::<Vec<_>>()
                .join(", ");

                if key_stats.is_empty() {
                    format!("Scan completed (success: {success}) in {duration_str}")
                } else {
                    format!("Scan completed (success: {success}) in {duration_str} - {key_stats}")
                }
            }
            WalletScanEvent::ScanError {
                error_message,
                block_height,
                ..
            } => match block_height {
                Some(height) => format!("Scan error at block {height}: {error_message}"),
                None => format!("Scan error: {error_message}"),
            },
            WalletScanEvent::ScanCancelled { reason, .. } => {
                format!("Scan cancelled: {reason}")
            }
        }
    }
}

/// Core wallet events for state changes and transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletEvent {
    /// Emitted when a UTXO is received by the wallet
    UtxoReceived {
        metadata: EventMetadata,
        payload: UtxoReceivedPayload,
    },
    /// Emitted when a UTXO is spent from the wallet
    UtxoSpent {
        metadata: EventMetadata,
        payload: UtxoSpentPayload,
    },
    /// Emitted when a blockchain reorganization affects wallet state
    Reorg {
        metadata: EventMetadata,
        payload: ReorgPayload,
    },
}

impl EventType for WalletEvent {
    fn event_type(&self) -> &'static str {
        match self {
            WalletEvent::UtxoReceived { .. } => "UtxoReceived",
            WalletEvent::UtxoSpent { .. } => "UtxoSpent",
            WalletEvent::Reorg { .. } => "Reorg",
        }
    }

    fn metadata(&self) -> &EventMetadata {
        match self {
            WalletEvent::UtxoReceived { metadata, .. } => metadata,
            WalletEvent::UtxoSpent { metadata, .. } => metadata,
            WalletEvent::Reorg { metadata, .. } => metadata,
        }
    }

    fn debug_data(&self) -> Option<String> {
        match self {
            WalletEvent::UtxoReceived { payload, .. } => Some(format!(
                "block: {}, amount: {}, addr: {}",
                payload.block_height, payload.amount, payload.receiving_address
            )),
            WalletEvent::UtxoSpent { payload, .. } => Some(format!(
                "block: {}, amount: {}, method: {}",
                payload.spending_block_height, payload.amount, payload.match_method
            )),
            WalletEvent::Reorg { payload, .. } => Some(format!(
                "rollback: {} -> {}, depth: {}, affected_txs: {}",
                payload.fork_height,
                payload.fork_height + payload.new_blocks_count,
                payload.rollback_depth,
                payload.affected_transaction_hashes.len()
            )),
        }
    }
}

impl SerializableEvent for WalletEvent {
    fn to_debug_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    fn to_compact_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| e.to_string())
    }

    fn summary(&self) -> String {
        match self {
            WalletEvent::UtxoReceived { payload, .. } => format!(
                "UTXO received at block {} ({} units, addr: {})",
                payload.block_height, payload.amount, payload.receiving_address
            ),
            WalletEvent::UtxoSpent { payload, .. } => format!(
                "UTXO spent at block {} ({} units, method: {})",
                payload.spending_block_height, payload.amount, payload.match_method
            ),
            WalletEvent::Reorg { payload, .. } => format!(
                "Blockchain reorg: fork at {} (depth: {}, {} transactions affected)",
                payload.fork_height,
                payload.rollback_depth,
                payload.affected_transaction_hashes.len()
            ),
        }
    }
}

/// Helper functions for creating wallet events
impl WalletEvent {
    /// Create a new UtxoReceived event
    pub fn utxo_received(payload: UtxoReceivedPayload) -> Self {
        Self::UtxoReceived {
            metadata: EventMetadata::new("wallet"),
            payload,
        }
    }

    /// Create a new UtxoSpent event
    pub fn utxo_spent(payload: UtxoSpentPayload) -> Self {
        Self::UtxoSpent {
            metadata: EventMetadata::new("wallet"),
            payload,
        }
    }

    /// Create a new Reorg event
    pub fn reorg(payload: ReorgPayload) -> Self {
        Self::Reorg {
            metadata: EventMetadata::new("wallet"),
            payload,
        }
    }

    /// Deserialize a wallet event from JSON string
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| e.to_string())
    }
}

/// Type alias for efficiently shared events
pub type SharedEvent = Arc<WalletScanEvent>;

/// Type alias for efficiently shared wallet events  
pub type SharedWalletEvent = Arc<WalletEvent>;

/// Helper functions for event serialization and deserialization
impl WalletScanEvent {
    /// Deserialize an event from JSON string
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| e.to_string())
    }

    /// Create a shared event from JSON string
    pub fn shared_from_json(json: &str) -> Result<SharedEvent, String> {
        Self::from_json(json).map(Arc::new)
    }
}

/// Helper functions for creating events with proper metadata
impl WalletScanEvent {
    /// Create a new ScanStarted event
    pub fn scan_started(
        config: ScanConfig,
        block_range: (u64, u64),
        wallet_context: String,
    ) -> Self {
        Self::ScanStarted {
            metadata: EventMetadata::new("wallet_scanner"),
            config,
            block_range,
            wallet_context,
        }
    }

    /// Create a new BlockProcessed event
    pub fn block_processed(
        height: u64,
        hash: String,
        timestamp: u64,
        processing_duration: Duration,
        outputs_count: usize,
    ) -> Self {
        Self::BlockProcessed {
            metadata: EventMetadata::new("wallet_scanner"),
            height,
            hash,
            timestamp,
            processing_duration,
            outputs_count,
            spent_outputs_count: 0,
        }
    }

    /// Create a new OutputFound event
    pub fn output_found(
        output_data: OutputData,
        block_info: BlockInfo,
        address_info: AddressInfo,
        transaction_data: TransactionData,
    ) -> Self {
        Self::OutputFound {
            metadata: EventMetadata::new("wallet_scanner"),
            output_data,
            block_info,
            address_info,
            transaction_data,
        }
    }

    /// Create a new SpentOutputFound event
    pub fn spent_output_found(
        spent_output_data: SpentOutputData,
        spending_block_info: BlockInfo,
        original_output_info: OutputData,
        spending_transaction_data: TransactionData,
    ) -> Self {
        Self::SpentOutputFound {
            metadata: EventMetadata::new("wallet_scanner"),
            spent_output_data,
            spending_block_info,
            original_output_info,
            spending_transaction_data,
        }
    }

    /// Create a new ScanProgress event
    pub fn scan_progress(
        current_block: u64,
        total_blocks: u64,
        current_block_height: u64,
        percentage: f64,
        speed_blocks_per_second: f64,
        estimated_time_remaining: Option<Duration>,
    ) -> Self {
        Self::ScanProgress {
            metadata: EventMetadata::new("wallet_scanner"),
            current_block,
            total_blocks,
            current_block_height,
            percentage,
            speed_blocks_per_second,
            estimated_time_remaining,
        }
    }

    /// Create a new ScanCompleted event
    pub fn scan_completed(
        final_statistics: HashMap<String, u64>,
        success: bool,
        total_duration: Duration,
    ) -> Self {
        Self::ScanCompleted {
            metadata: EventMetadata::new("wallet_scanner"),
            final_statistics,
            success,
            total_duration,
        }
    }

    /// Create a new ScanError event
    pub fn scan_error(
        error_message: String,
        error_code: Option<String>,
        block_height: Option<u64>,
        retry_info: Option<String>,
        is_recoverable: bool,
    ) -> Self {
        Self::ScanError {
            metadata: EventMetadata::new("wallet_scanner"),
            error_message,
            error_code,
            block_height,
            retry_info,
            is_recoverable,
        }
    }

    /// Create a new ScanCancelled event
    pub fn scan_cancelled(
        reason: String,
        final_statistics: HashMap<String, u64>,
        partial_completion: Option<f64>,
    ) -> Self {
        Self::ScanCancelled {
            metadata: EventMetadata::new("wallet_scanner"),
            reason,
            final_statistics,
            partial_completion,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn test_scan_started_event_creation() {
        let config = ScanConfig::new()
            .with_batch_size(10)
            .with_timeout_seconds(30)
            .with_retry_attempts(3);

        let event = WalletScanEvent::scan_started(
            config.clone(),
            (1000, 2000),
            "test_wallet_context".to_string(),
        );

        match &event {
            WalletScanEvent::ScanStarted {
                metadata,
                config: event_config,
                block_range,
                wallet_context,
            } => {
                assert!(!metadata.event_id.is_empty());
                assert_eq!(metadata.source, "wallet_scanner");
                assert!(metadata.timestamp <= SystemTime::now());
                assert_eq!(event_config.batch_size, Some(10));
                assert_eq!(event_config.timeout_seconds, Some(30));
                assert_eq!(event_config.retry_attempts, Some(3));
                assert_eq!(*block_range, (1000, 2000));
                assert_eq!(wallet_context, "test_wallet_context");
            }
            _ => panic!("Expected ScanStarted event"),
        }
    }

    #[test]
    fn test_scan_started_event_traits() {
        let config = ScanConfig::default();
        let event = WalletScanEvent::scan_started(config, (0, 100), "wallet_123".to_string());

        // Test EventType trait
        assert_eq!(event.event_type(), "ScanStarted");
        assert!(event.debug_data().is_some());
        assert!(event.debug_data().unwrap().contains("blocks: 0-100"));
        assert!(event.debug_data().unwrap().contains("wallet: wallet_123"));

        // Test SerializableEvent trait
        let summary = event.summary();
        assert!(summary.contains("Scan started"));
        assert!(summary.contains("wallet_123"));
        assert!(summary.contains("blocks 0-100"));

        let json = event.to_debug_json().unwrap();
        assert!(json.contains("ScanStarted"));
        assert!(json.contains("\"block_range\""));
        assert!(json.contains("wallet_123"));
    }

    #[test]
    fn test_scan_started_with_correlation_id() {
        let metadata =
            EventMetadata::with_correlation("wallet_scanner", "scan_session_123".to_string());
        let config = ScanConfig::default();

        let event = WalletScanEvent::ScanStarted {
            metadata,
            config,
            block_range: (500, 1500),
            wallet_context: "test_wallet".to_string(),
        };

        match &event {
            WalletScanEvent::ScanStarted { metadata, .. } => {
                assert_eq!(
                    metadata.correlation_id,
                    Some("scan_session_123".to_string())
                );
                assert_eq!(metadata.source, "wallet_scanner");
            }
            _ => panic!("Expected ScanStarted event"),
        }
    }

    #[test]
    fn test_event_serialization_roundtrip() {
        let config = ScanConfig::new()
            .with_batch_size(25)
            .with_timeout_seconds(60);

        let event = WalletScanEvent::scan_started(config, (1000, 2000), "test_wallet".to_string());

        // Test pretty JSON serialization
        let pretty_json = event.to_debug_json().unwrap();
        assert!(pretty_json.contains("ScanStarted"));
        assert!(pretty_json.contains("test_wallet"));
        assert!(pretty_json.contains("1000"));
        assert!(pretty_json.contains("2000"));

        // Test compact JSON serialization
        let compact_json = event.to_compact_json().unwrap();
        assert!(compact_json.contains("ScanStarted"));
        assert!(compact_json.len() < pretty_json.len()); // Compact should be smaller

        // Test deserialization roundtrip
        let deserialized = WalletScanEvent::from_json(&compact_json).unwrap();
        match (&event, &deserialized) {
            (
                WalletScanEvent::ScanStarted {
                    block_range: br1,
                    wallet_context: wc1,
                    ..
                },
                WalletScanEvent::ScanStarted {
                    block_range: br2,
                    wallet_context: wc2,
                    ..
                },
            ) => {
                assert_eq!(br1, br2);
                assert_eq!(wc1, wc2);
            }
            _ => panic!("Deserialized event type mismatch"),
        }
    }

    #[test]
    fn test_shared_event_serialization() {
        let event = WalletScanEvent::scan_started(
            ScanConfig::default(),
            (500, 1500),
            "shared_test".to_string(),
        );

        let compact_json = event.to_compact_json().unwrap();
        let shared_event = WalletScanEvent::shared_from_json(&compact_json).unwrap();

        match shared_event.as_ref() {
            WalletScanEvent::ScanStarted {
                block_range,
                wallet_context,
                ..
            } => {
                assert_eq!(*block_range, (500, 1500));
                assert_eq!(wallet_context, "shared_test");
            }
            _ => panic!("Expected ScanStarted event"),
        }
    }

    #[test]
    fn test_serialization_with_complex_data() {
        let output_data = OutputData::new(
            "commitment_123".to_string(),
            "proof_data_456".to_string(),
            1,
            true,
        )
        .with_amount(1000)
        .with_key_index(5);

        let block_info = BlockInfo::new(12345, "block_hash_abc".to_string(), 1697123456, 2);

        let address_info = AddressInfo::new(
            "tari1xyz123...".to_string(),
            "stealth".to_string(),
            "mainnet".to_string(),
        );

        let transaction_data = TransactionData::new(
            1000,
            "MinedConfirmed".to_string(),
            "Inbound".to_string(),
            1697123456,
        );
        let event =
            WalletScanEvent::output_found(output_data, block_info, address_info, transaction_data);

        // Test serialization
        let json = event.to_debug_json().unwrap();
        assert!(json.contains("OutputFound"));
        assert!(json.contains("commitment_123"));
        assert!(json.contains("tari1xyz123..."));
        assert!(json.contains("12345"));

        // Test roundtrip
        let deserialized = WalletScanEvent::from_json(&json).unwrap();
        match &deserialized {
            WalletScanEvent::OutputFound {
                output_data,
                block_info,
                address_info,
                ..
            } => {
                assert_eq!(output_data.commitment, "commitment_123");
                assert_eq!(output_data.amount, Some(1000));
                assert_eq!(block_info.height, 12345);
                assert_eq!(address_info.address, "tari1xyz123...");
            }
            _ => panic!("Expected OutputFound event"),
        }
    }

    #[test]
    fn test_scan_config_builder_pattern() {
        let config = ScanConfig::new()
            .with_batch_size(25)
            .with_timeout_seconds(60)
            .with_retry_attempts(5)
            .with_filter("output_type".to_string(), "utxo".to_string())
            .with_filter("min_value".to_string(), "1000".to_string());

        assert_eq!(config.batch_size, Some(25));
        assert_eq!(config.timeout_seconds, Some(60));
        assert_eq!(config.retry_attempts, Some(5));
        assert_eq!(config.filters.get("output_type"), Some(&"utxo".to_string()));
        assert_eq!(config.filters.get("min_value"), Some(&"1000".to_string()));
        assert_eq!(config.filters.len(), 2);
    }

    #[test]
    fn test_block_processed_event_creation() {
        let processing_duration = Duration::from_millis(250);
        let event = WalletScanEvent::block_processed(
            12345,
            "0x1234567890abcdef".to_string(),
            1697123456,
            processing_duration,
            5,
        );

        match &event {
            WalletScanEvent::BlockProcessed {
                metadata,
                height,
                hash,
                timestamp,
                processing_duration: duration,
                outputs_count,
                spent_outputs_count,
            } => {
                assert!(!metadata.event_id.is_empty());
                assert_eq!(metadata.source, "wallet_scanner");
                assert!(metadata.timestamp <= SystemTime::now());
                assert_eq!(*height, 12345);
                assert_eq!(hash, "0x1234567890abcdef");
                assert_eq!(*timestamp, 1697123456);
                assert_eq!(*duration, processing_duration);
                assert_eq!(*outputs_count, 5);
                assert_eq!(*spent_outputs_count, 0);
            }
            _ => panic!("Expected BlockProcessed event"),
        }
    }

    #[test]
    fn test_block_processed_event_traits() {
        let event = WalletScanEvent::block_processed(
            98765,
            "0xabcdef1234567890".to_string(),
            1697123999,
            Duration::from_millis(180),
            3,
        );

        // Test EventType trait
        assert_eq!(event.event_type(), "BlockProcessed");
        assert!(event.debug_data().is_some());
        let debug_data = event.debug_data().unwrap();
        assert!(debug_data.contains("height: 98765"));
        assert!(debug_data.contains("outputs: 3"));

        // Test SerializableEvent trait
        let summary = event.summary();
        assert!(summary.contains("Processed block 98765"));
        assert!(summary.contains("with 3 outputs"));

        let json = event.to_debug_json().unwrap();
        assert!(json.contains("BlockProcessed"));
        assert!(json.contains("98765"));
        assert!(json.contains("0xabcdef1234567890"));
        assert!(json.contains("3"));
    }

    #[test]
    fn test_block_processed_zero_outputs() {
        let event = WalletScanEvent::block_processed(
            100,
            "0x0000000000000000".to_string(),
            1697000000,
            Duration::from_millis(50),
            0,
        );

        match &event {
            WalletScanEvent::BlockProcessed { outputs_count, .. } => {
                assert_eq!(*outputs_count, 0);
            }
            _ => panic!("Expected BlockProcessed event"),
        }

        let summary = event.summary();
        assert!(summary.contains("with 0 outputs"));
    }

    #[test]
    fn test_block_processed_with_correlation_id() {
        let metadata =
            EventMetadata::with_correlation("wallet_scanner", "block_batch_123".to_string());
        let event = WalletScanEvent::BlockProcessed {
            metadata,
            height: 54321,
            hash: "0xdeadbeef".to_string(),
            timestamp: 1697987654,
            processing_duration: Duration::from_millis(300),
            outputs_count: 10,
            spent_outputs_count: 0,
        };

        match &event {
            WalletScanEvent::BlockProcessed { metadata, .. } => {
                assert_eq!(metadata.correlation_id, Some("block_batch_123".to_string()));
                assert_eq!(metadata.source, "wallet_scanner");
            }
            _ => panic!("Expected BlockProcessed event"),
        }
    }

    #[test]
    fn test_block_processed_duration_handling() {
        // Test various processing durations
        let durations = [
            Duration::from_nanos(1),
            Duration::from_micros(1),
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_secs(60),
        ];

        for (i, duration) in durations.iter().enumerate() {
            let event = WalletScanEvent::block_processed(
                i as u64,
                format!("0x{i:016x}"),
                1697000000 + i as u64,
                *duration,
                i,
            );

            match &event {
                WalletScanEvent::BlockProcessed {
                    processing_duration,
                    ..
                } => {
                    assert_eq!(processing_duration, duration);
                }
                _ => panic!("Expected BlockProcessed event"),
            }
        }
    }

    #[test]
    fn test_output_found_event_creation() {
        let output_data = OutputData::new(
            "0x1234567890abcdef".to_string(),
            "range_proof_data".to_string(),
            1,    // features
            true, // is_mine
        )
        .with_amount(1000)
        .with_key_index(5);

        let block_info = BlockInfo::new(
            12345,
            "0xabcdef1234567890".to_string(),
            1697123456,
            2, // output_index
        )
        .with_transaction_index(1);

        let address_info = AddressInfo::new(
            "tari1xyz123...".to_string(),
            "stealth".to_string(),
            "mainnet".to_string(),
        )
        .with_derivation_path("m/44'/0'/0'/0/5".to_string());

        let transaction_data = TransactionData::new(
            1000,
            "MinedConfirmed".to_string(),
            "Inbound".to_string(),
            1697123456,
        );
        let event =
            WalletScanEvent::output_found(output_data, block_info, address_info, transaction_data);

        match &event {
            WalletScanEvent::OutputFound {
                metadata,
                output_data,
                block_info,
                address_info,
                transaction_data: _,
            } => {
                assert!(!metadata.event_id.is_empty());
                assert_eq!(metadata.source, "wallet_scanner");

                // Test output data
                assert_eq!(output_data.commitment, "0x1234567890abcdef");
                assert_eq!(output_data.range_proof, "range_proof_data");
                assert_eq!(output_data.features, 1);
                assert!(output_data.is_mine);
                assert_eq!(output_data.amount, Some(1000));
                assert_eq!(output_data.key_index, Some(5));

                // Test block info
                assert_eq!(block_info.height, 12345);
                assert_eq!(block_info.hash, "0xabcdef1234567890");
                assert_eq!(block_info.timestamp, 1697123456);
                assert_eq!(block_info.output_index, 2);
                assert_eq!(block_info.transaction_index, Some(1));

                // Test address info
                assert_eq!(address_info.address, "tari1xyz123...");
                assert_eq!(address_info.address_type, "stealth");
                assert_eq!(address_info.network, "mainnet");
                assert_eq!(
                    address_info.derivation_path,
                    Some("m/44'/0'/0'/0/5".to_string())
                );
            }
            _ => panic!("Expected OutputFound event"),
        }
    }

    #[test]
    fn test_output_found_event_traits() {
        let output_data = OutputData::new(
            "0xcommitment123".to_string(),
            "proof_data".to_string(),
            0,
            false, // not mine
        );

        let block_info = BlockInfo::new(98765, "0xblockhash456".to_string(), 1697999999, 0);

        let address_info = AddressInfo::new(
            "tari1abc456...".to_string(),
            "standard".to_string(),
            "testnet".to_string(),
        );

        let transaction_data = TransactionData::new(
            5000,
            "MinedConfirmed".to_string(),
            "Inbound".to_string(),
            1697999999,
        );
        let event =
            WalletScanEvent::output_found(output_data, block_info, address_info, transaction_data);

        // Test EventType trait
        assert_eq!(event.event_type(), "OutputFound");
        assert!(event.debug_data().is_some());
        let debug_data = event.debug_data().unwrap();
        assert!(debug_data.contains("block: 98765"));
        assert!(debug_data.contains("mine: false"));
        assert!(debug_data.contains("amount: unknown"));

        // Test SerializableEvent trait
        let summary = event.summary();
        assert!(summary.contains("Found output at block 98765"));
        assert!(summary.contains("not mine"));
        assert!(summary.contains("tari1abc456..."));

        let json = event.to_debug_json().unwrap();
        assert!(json.contains("OutputFound"));
        assert!(json.contains("98765"));
        assert!(json.contains("false"));
        assert!(json.contains("tari1abc456..."));
        assert!(json.contains("0xcommitment123"));
    }

    #[test]
    fn test_output_data_builder_pattern() {
        let output_data = OutputData::new("commitment".to_string(), "proof".to_string(), 1, true)
            .with_amount(500)
            .with_key_index(10)
            .with_maturity_height(1000)
            .with_script("script".to_string())
            .with_encrypted_value(vec![1, 2, 3]);

        assert_eq!(output_data.commitment, "commitment");
        assert_eq!(output_data.range_proof, "proof");
        assert_eq!(output_data.features, 1);
        assert!(output_data.is_mine);
        assert_eq!(output_data.amount, Some(500));
        assert_eq!(output_data.key_index, Some(10));
        assert_eq!(output_data.maturity_height, Some(1000));
        assert_eq!(output_data.script, Some("script".to_string()));
        assert_eq!(output_data.encrypted_value, Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_scan_progress_event_creation() {
        let event = WalletScanEvent::scan_progress(
            750,
            1000,
            1750,
            75.0,
            5.5,
            Some(Duration::from_secs(45)),
        );

        match &event {
            WalletScanEvent::ScanProgress {
                metadata,
                current_block,
                total_blocks,
                current_block_height: _,
                percentage,
                speed_blocks_per_second,
                estimated_time_remaining,
            } => {
                assert!(!metadata.event_id.is_empty());
                assert_eq!(metadata.source, "wallet_scanner");
                assert_eq!(*current_block, 750);
                assert_eq!(*total_blocks, 1000);
                assert_eq!(*percentage, 75.0);
                assert_eq!(*speed_blocks_per_second, 5.5);
                assert_eq!(*estimated_time_remaining, Some(Duration::from_secs(45)));
            }
            _ => panic!("Expected ScanProgress event"),
        }
    }

    #[test]
    fn test_scan_progress_event_traits() {
        let event = WalletScanEvent::scan_progress(
            500,
            2000,
            1500,
            25.0,
            10.0,
            Some(Duration::from_secs(150)),
        );

        // Test EventType trait
        assert_eq!(event.event_type(), "ScanProgress");
        assert!(event.debug_data().is_some());
        let debug_data = event.debug_data().unwrap();
        assert!(debug_data.contains("500/2000"));
        assert!(debug_data.contains("25.0%"));
        assert!(debug_data.contains("speed: 10.0 bps"));
        assert!(debug_data.contains("ETA: 150s"));

        // Test SerializableEvent trait
        let summary = event.summary();
        assert!(summary.contains("Scan progress: 500/2000 blocks"));
        assert!(summary.contains("25.0%"));
        assert!(summary.contains("10.0 blocks/sec"));
        assert!(summary.contains("2m 30s"));

        let json = event.to_debug_json().unwrap();
        assert!(json.contains("ScanProgress"));
        assert!(json.contains("500"));
        assert!(json.contains("2000"));
        assert!(json.contains("25.0"));
        assert!(json.contains("10.0"));
        assert!(json.contains("150"));
    }

    #[test]
    fn test_scan_progress_no_eta() {
        let event = WalletScanEvent::scan_progress(100, 500, 1100, 20.0, 2.0, None);

        match &event {
            WalletScanEvent::ScanProgress {
                estimated_time_remaining,
                ..
            } => {
                assert_eq!(*estimated_time_remaining, None);
            }
            _ => panic!("Expected ScanProgress event"),
        }

        // Test serialization handles None ETA
        let debug_data = event.debug_data().unwrap();
        assert!(debug_data.contains("ETA: unknown"));

        let summary = event.summary();
        assert!(summary.contains("unknown ETA"));

        let json = event.to_debug_json().unwrap();
        assert!(json.contains("null"));
    }

    #[test]
    fn test_scan_progress_eta_formatting() {
        // Test different ETA durations
        let test_cases = vec![
            (Duration::from_secs(30), "30s"),
            (Duration::from_secs(90), "1m 30s"),
            (Duration::from_secs(3661), "1h 1m"),
            (Duration::from_secs(7200), "2h 0m"),
        ];

        for (duration, expected_format) in test_cases {
            let event = WalletScanEvent::scan_progress(100, 200, 1100, 50.0, 1.0, Some(duration));
            let summary = event.summary();
            assert!(
                summary.contains(expected_format),
                "Expected '{expected_format}' in summary: {summary}"
            );
        }
    }

    #[test]
    fn test_scan_progress_edge_cases() {
        // Test 0% progress
        let event = WalletScanEvent::scan_progress(0, 1000, 1000, 0.0, 0.0, None);
        match &event {
            WalletScanEvent::ScanProgress {
                current_block,
                percentage,
                speed_blocks_per_second,
                ..
            } => {
                assert_eq!(*current_block, 0);
                assert_eq!(*percentage, 0.0);
                assert_eq!(*speed_blocks_per_second, 0.0);
            }
            _ => panic!("Expected ScanProgress event"),
        }

        // Test 100% progress
        let event =
            WalletScanEvent::scan_progress(1000, 1000, 2000, 100.0, 5.0, Some(Duration::ZERO));
        match &event {
            WalletScanEvent::ScanProgress {
                current_block,
                total_blocks,
                percentage,
                estimated_time_remaining,
                ..
            } => {
                assert_eq!(*current_block, 1000);
                assert_eq!(*total_blocks, 1000);
                assert_eq!(*percentage, 100.0);
                assert_eq!(*estimated_time_remaining, Some(Duration::ZERO));
            }
            _ => panic!("Expected ScanProgress event"),
        }
    }

    #[test]
    fn test_scan_progress_with_correlation_id() {
        let metadata =
            EventMetadata::with_correlation("wallet_scanner", "scan_batch_456".to_string());
        let event = WalletScanEvent::ScanProgress {
            metadata,
            current_block: 300,
            total_blocks: 600,
            current_block_height: 1300,
            percentage: 50.0,
            speed_blocks_per_second: 8.0,
            estimated_time_remaining: Some(Duration::from_secs(37)),
        };

        match &event {
            WalletScanEvent::ScanProgress { metadata, .. } => {
                assert_eq!(metadata.correlation_id, Some("scan_batch_456".to_string()));
                assert_eq!(metadata.source, "wallet_scanner");
            }
            _ => panic!("Expected ScanProgress event"),
        }
    }

    #[test]
    fn test_scan_completed_event_creation() {
        let mut final_stats = HashMap::new();
        final_stats.insert("blocks_processed".to_string(), 1000);
        final_stats.insert("outputs_found".to_string(), 25);
        final_stats.insert("transactions_found".to_string(), 15);
        final_stats.insert("errors_encountered".to_string(), 0);

        let event =
            WalletScanEvent::scan_completed(final_stats.clone(), true, Duration::from_secs(300));

        match &event {
            WalletScanEvent::ScanCompleted {
                metadata,
                final_statistics,
                success,
                total_duration,
            } => {
                assert!(!metadata.event_id.is_empty());
                assert_eq!(metadata.source, "wallet_scanner");
                assert!(success);
                assert_eq!(*total_duration, Duration::from_secs(300));
                assert_eq!(final_statistics.len(), 4);
                assert_eq!(final_statistics.get("blocks_processed"), Some(&1000));
                assert_eq!(final_statistics.get("outputs_found"), Some(&25));
                assert_eq!(final_statistics.get("transactions_found"), Some(&15));
                assert_eq!(final_statistics.get("errors_encountered"), Some(&0));
            }
            _ => panic!("Expected ScanCompleted event"),
        }
    }

    #[test]
    fn test_scan_completed_event_traits() {
        let mut final_stats = HashMap::new();
        final_stats.insert("blocks_processed".to_string(), 500);
        final_stats.insert("outputs_found".to_string(), 10);

        let event = WalletScanEvent::scan_completed(final_stats, true, Duration::from_secs(150));

        // Test EventType trait
        assert_eq!(event.event_type(), "ScanCompleted");
        assert!(event.debug_data().is_some());
        let debug_data = event.debug_data().unwrap();
        assert!(debug_data.contains("success: true"));
        assert!(debug_data.contains("duration: 150s"));
        assert!(debug_data.contains("stats: 2 items"));

        // Test SerializableEvent trait
        let summary = event.summary();
        assert!(summary.contains("Scan completed (success: true)"));
        assert!(summary.contains("2m 30s"));
        assert!(summary.contains("500 blocks"));
        assert!(summary.contains("10 outputs"));

        let json = event.to_debug_json().unwrap();
        assert!(json.contains("ScanCompleted"));
        assert!(json.contains("true"));
        assert!(json.contains("150"));
        assert!(json.contains("2"));
    }

    #[test]
    fn test_scan_completed_failure() {
        let mut final_stats = HashMap::new();
        final_stats.insert("blocks_processed".to_string(), 750);
        final_stats.insert("errors_encountered".to_string(), 5);

        let event = WalletScanEvent::scan_completed(final_stats, false, Duration::from_secs(45));

        match &event {
            WalletScanEvent::ScanCompleted { success, .. } => {
                assert!(!success);
            }
            _ => panic!("Expected ScanCompleted event"),
        }

        let summary = event.summary();
        assert!(summary.contains("success: false"));
        assert!(summary.contains("45s"));
        assert!(summary.contains("750 blocks"));
        assert!(summary.contains("5 errors"));
    }

    #[test]
    fn test_scan_completed_empty_stats() {
        let empty_stats = HashMap::new();
        let event = WalletScanEvent::scan_completed(empty_stats, true, Duration::from_secs(30));

        // Test with empty statistics
        let debug_data = event.debug_data().unwrap();
        assert!(debug_data.contains("stats: 0 items"));

        let summary = event.summary();
        assert!(summary.contains("Scan completed (success: true) in 30s"));
        // Should not contain additional stats when empty
        assert!(!summary.contains(" - "));
    }

    #[test]
    fn test_scan_completed_duration_formatting() {
        // Test different duration formats
        let test_cases = vec![
            (Duration::from_secs(30), "30s"),
            (Duration::from_secs(90), "1m 30s"),
            (Duration::from_secs(3661), "1h 1m"),
            (Duration::from_secs(7200), "2h 0m"),
        ];

        for (duration, expected_format) in test_cases {
            let event = WalletScanEvent::scan_completed(HashMap::new(), true, duration);
            let summary = event.summary();
            assert!(
                summary.contains(expected_format),
                "Expected '{expected_format}' in summary: {summary}"
            );
        }
    }

    #[test]
    fn test_scan_completed_with_correlation_id() {
        let metadata =
            EventMetadata::with_correlation("wallet_scanner", "final_scan_789".to_string());
        let mut stats = HashMap::new();
        stats.insert("blocks_processed".to_string(), 100);

        let event = WalletScanEvent::ScanCompleted {
            metadata,
            final_statistics: stats,
            success: true,
            total_duration: Duration::from_secs(60),
        };

        match &event {
            WalletScanEvent::ScanCompleted { metadata, .. } => {
                assert_eq!(metadata.correlation_id, Some("final_scan_789".to_string()));
                assert_eq!(metadata.source, "wallet_scanner");
            }
            _ => panic!("Expected ScanCompleted event"),
        }
    }

    #[test]
    fn test_scan_completed_comprehensive_stats() {
        let mut comprehensive_stats = HashMap::new();
        comprehensive_stats.insert("blocks_processed".to_string(), 2000);
        comprehensive_stats.insert("outputs_found".to_string(), 150);
        comprehensive_stats.insert("transactions_found".to_string(), 75);
        comprehensive_stats.insert("errors_encountered".to_string(), 3);
        comprehensive_stats.insert("average_block_time_ms".to_string(), 250);
        comprehensive_stats.insert("total_value_found".to_string(), 50000);

        let event = WalletScanEvent::scan_completed(
            comprehensive_stats,
            true,
            Duration::from_secs(1800), // 30 minutes
        );

        let summary = event.summary();
        assert!(summary.contains("2000 blocks"));
        assert!(summary.contains("150 outputs"));
        assert!(summary.contains("75 transactions"));
        assert!(summary.contains("3 errors"));
        assert!(summary.contains("30m 0s"));

        // Should only include the key stats, not all stats
        assert!(!summary.contains("average_block_time_ms"));
        assert!(!summary.contains("total_value_found"));
    }

    #[test]
    fn test_scan_error_event_creation() {
        let event = WalletScanEvent::scan_error(
            "Connection timeout".to_string(),
            Some("E001".to_string()),
            Some(12345),
            Some("Will retry in 5 seconds".to_string()),
            true,
        );

        match &event {
            WalletScanEvent::ScanError {
                metadata,
                error_message,
                error_code,
                block_height,
                retry_info,
                is_recoverable,
            } => {
                assert!(!metadata.event_id.is_empty());
                assert_eq!(metadata.source, "wallet_scanner");
                assert_eq!(error_message, "Connection timeout");
                assert_eq!(error_code, &Some("E001".to_string()));
                assert_eq!(block_height, &Some(12345));
                assert_eq!(retry_info, &Some("Will retry in 5 seconds".to_string()));
                assert!(is_recoverable);
            }
            _ => panic!("Expected ScanError event"),
        }
    }

    #[test]
    fn test_scan_error_event_traits() {
        let event = WalletScanEvent::scan_error(
            "Database connection failed".to_string(),
            None,
            None,
            None,
            false,
        );

        // Test EventType trait
        assert_eq!(event.event_type(), "ScanError");
        let debug_data = event.debug_data().unwrap();
        assert!(debug_data.contains("error: Database connection failed"));
        assert!(debug_data.contains("block: None"));

        // Test SerializableEvent trait
        let summary = event.summary();
        assert_eq!(summary, "Scan error: Database connection failed");

        let json = event.to_debug_json().unwrap();
        assert!(json.contains("ScanError"));
        assert!(json.contains("Database connection failed"));
    }

    #[test]
    fn test_scan_cancelled_event_creation() {
        let mut final_stats = HashMap::new();
        final_stats.insert("blocks_processed".to_string(), 500);
        final_stats.insert("outputs_found".to_string(), 25);

        let event = WalletScanEvent::scan_cancelled(
            "User cancelled operation".to_string(),
            final_stats,
            Some(0.5), // 50% completion
        );

        match &event {
            WalletScanEvent::ScanCancelled {
                metadata,
                reason,
                final_statistics,
                partial_completion,
            } => {
                assert!(!metadata.event_id.is_empty());
                assert_eq!(metadata.source, "wallet_scanner");
                assert_eq!(reason, "User cancelled operation");
                assert_eq!(final_statistics.get("blocks_processed"), Some(&500));
                assert_eq!(final_statistics.get("outputs_found"), Some(&25));
                assert_eq!(partial_completion, &Some(0.5));
            }
            _ => panic!("Expected ScanCancelled event"),
        }
    }

    #[test]
    fn test_scan_cancelled_event_traits() {
        let event =
            WalletScanEvent::scan_cancelled("Network timeout".to_string(), HashMap::new(), None);

        // Test EventType trait
        assert_eq!(event.event_type(), "ScanCancelled");
        let debug_data = event.debug_data().unwrap();
        assert!(debug_data.contains("reason: Network timeout"));

        // Test SerializableEvent trait
        let summary = event.summary();
        assert_eq!(summary, "Scan cancelled: Network timeout");

        let json = event.to_debug_json().unwrap();
        assert!(json.contains("ScanCancelled"));
        assert!(json.contains("Network timeout"));
    }

    #[test]
    fn test_event_metadata_creation() {
        let metadata = EventMetadata::new("test_source");

        assert!(!metadata.event_id.is_empty());
        assert_eq!(metadata.source, "test_source");
        assert!(metadata.correlation_id.is_none());
        assert!(metadata.timestamp <= SystemTime::now());
    }

    #[test]
    fn test_event_metadata_with_correlation() {
        let metadata =
            EventMetadata::with_correlation("test_source", "correlation_123".to_string());

        assert!(!metadata.event_id.is_empty());
        assert_eq!(metadata.source, "test_source");
        assert_eq!(metadata.correlation_id, Some("correlation_123".to_string()));
        assert!(metadata.timestamp <= SystemTime::now());
    }

    #[test]
    fn test_block_info_builder_pattern() {
        let block_info = BlockInfo::new(12345, "0xabc123".to_string(), 1697123456, 5)
            .with_transaction_index(2)
            .with_difficulty(98765);

        assert_eq!(block_info.height, 12345);
        assert_eq!(block_info.hash, "0xabc123");
        assert_eq!(block_info.timestamp, 1697123456);
        assert_eq!(block_info.output_index, 5);
        assert_eq!(block_info.transaction_index, Some(2));
        assert_eq!(block_info.difficulty, Some(98765));
    }

    #[test]
    fn test_address_info_builder_pattern() {
        let address_info = AddressInfo::new(
            "tari1abc123".to_string(),
            "stealth".to_string(),
            "mainnet".to_string(),
        )
        .with_derivation_path("m/44'/0'/0'/0/1".to_string())
        .with_public_spend_key("public_key_123".to_string())
        .with_view_key("view_key_456".to_string());

        assert_eq!(address_info.address, "tari1abc123");
        assert_eq!(address_info.address_type, "stealth");
        assert_eq!(address_info.network, "mainnet");
        assert_eq!(
            address_info.derivation_path,
            Some("m/44'/0'/0'/0/1".to_string())
        );
        assert_eq!(
            address_info.public_spend_key,
            Some("public_key_123".to_string())
        );
        assert_eq!(address_info.view_key, Some("view_key_456".to_string()));
    }

    #[test]
    fn test_json_serialization_error_handling() {
        // Test that the error handling for JSON serialization works correctly
        // by creating a valid event and checking error paths
        let event =
            WalletScanEvent::scan_started(ScanConfig::default(), (0, 100), "test".to_string());

        // These should succeed
        assert!(event.to_debug_json().is_ok());
        assert!(event.to_compact_json().is_ok());

        // Test deserialization with invalid JSON
        let invalid_json = "{invalid json}";
        assert!(WalletScanEvent::from_json(invalid_json).is_err());
        assert!(WalletScanEvent::shared_from_json(invalid_json).is_err());
    }

    // Tests for new WalletEvent serialization

    #[test]
    fn test_utxo_received_payload_serialization() {
        let payload = UtxoReceivedPayload::new(
            "utxo_123".to_string(),
            1000000, // 1 Tari
            12345,
            "block_hash_abc".to_string(),
            1697123456,
            "tx_hash_def".to_string(),
            0,
            "tari1xyz123...".to_string(),
            42,
            "commitment_ghi".to_string(),
            0,
            "mainnet".to_string(),
        )
        .with_maturity_height(12400)
        .with_script_hash("script_hash_jkl".to_string())
        .with_unlock_conditions();

        // Test JSON serialization
        let json = serde_json::to_string_pretty(&payload).unwrap();
        assert!(json.contains("utxo_123"));
        assert!(json.contains("1000000"));
        assert!(json.contains("tari1xyz123..."));
        assert!(json.contains("12345"));
        assert!(json.contains("true")); // has_unlock_conditions

        // Test roundtrip
        let deserialized: UtxoReceivedPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.utxo_id, "utxo_123");
        assert_eq!(deserialized.amount, 1000000);
        assert_eq!(deserialized.block_height, 12345);
        assert_eq!(deserialized.receiving_address, "tari1xyz123...");
        assert_eq!(deserialized.maturity_height, Some(12400));
        assert!(deserialized.has_unlock_conditions);
    }

    #[test]
    fn test_utxo_spent_payload_serialization() {
        let payload = UtxoSpentPayload::new(
            "utxo_456".to_string(),
            500000, // 0.5 Tari
            12345,  // original height
            12400,  // spending height
            "spending_block_hash".to_string(),
            1697123500,
            "spending_tx_hash".to_string(),
            1,
            "tari1abc456...".to_string(),
            25,
            "commitment_xyz".to_string(),
            "commitment".to_string(),
            true, // self spend
            "mainnet".to_string(),
        )
        .with_transaction_fee(1000);

        // Test JSON serialization
        let json = serde_json::to_string_pretty(&payload).unwrap();
        assert!(json.contains("utxo_456"));
        assert!(json.contains("500000"));
        assert!(json.contains("12400"));
        assert!(json.contains("true")); // is_self_spend
        assert!(json.contains("1000")); // transaction_fee

        // Test roundtrip
        let deserialized: UtxoSpentPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.utxo_id, "utxo_456");
        assert_eq!(deserialized.amount, 500000);
        assert_eq!(deserialized.spending_block_height, 12400);
        assert_eq!(deserialized.is_self_spend, true);
        assert_eq!(deserialized.transaction_fee, Some(1000));
    }

    #[test]
    fn test_reorg_payload_serialization() {
        let affected_txs = vec!["tx1".to_string(), "tx2".to_string()];
        let affected_utxos = vec!["utxo1".to_string(), "utxo2".to_string()];

        let payload = ReorgPayload::new(
            12300, // fork height
            "old_block_hash".to_string(),
            "new_block_hash".to_string(),
            5, // rollback depth
            3, // new blocks count
            affected_txs.clone(),
            affected_utxos.clone(),
            -250000, // balance change (loss)
            "mainnet".to_string(),
            1697123600,
        )
        .with_invalidated_utxos(vec!["utxo3".to_string()])
        .with_restored_utxos(vec!["utxo4".to_string()])
        .with_recovery_info("reason".to_string(), "chain_split".to_string());

        // Test JSON serialization
        let json = serde_json::to_string_pretty(&payload).unwrap();
        assert!(json.contains("12300"));
        assert!(json.contains("old_block_hash"));
        assert!(json.contains("new_block_hash"));
        assert!(json.contains("-250000"));
        assert!(json.contains("tx1"));
        assert!(json.contains("utxo3"));
        assert!(json.contains("chain_split"));

        // Test roundtrip
        let deserialized: ReorgPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.fork_height, 12300);
        assert_eq!(deserialized.rollback_depth, 5);
        assert_eq!(deserialized.new_blocks_count, 3);
        assert_eq!(deserialized.balance_change, -250000);
        assert_eq!(deserialized.affected_transaction_hashes, affected_txs);
        assert_eq!(deserialized.invalidated_utxos, vec!["utxo3".to_string()]);
        assert_eq!(
            deserialized.recovery_info.get("reason"),
            Some(&"chain_split".to_string())
        );
    }

    #[test]
    fn test_wallet_event_utxo_received_serialization() {
        let payload = UtxoReceivedPayload::new(
            "test_utxo".to_string(),
            2000000,
            15000,
            "test_block".to_string(),
            1697123700,
            "test_tx".to_string(),
            0,
            "test_address".to_string(),
            10,
            "test_commitment".to_string(),
            0,
            "testnet".to_string(),
        );

        let event = WalletEvent::utxo_received(payload);

        // Test JSON serialization
        let json = event.to_debug_json().unwrap();
        assert!(json.contains("UtxoReceived"));
        assert!(json.contains("test_utxo"));
        assert!(json.contains("2000000"));
        assert!(json.contains("15000"));
        assert!(json.contains("test_address"));

        // Test compact serialization
        let compact_json = event.to_compact_json().unwrap();
        assert!(compact_json.len() < json.len()); // Should be smaller
        assert!(compact_json.contains("UtxoReceived"));

        // Test roundtrip
        let deserialized = WalletEvent::from_json(&json).unwrap();
        match deserialized {
            WalletEvent::UtxoReceived { payload, .. } => {
                assert_eq!(payload.utxo_id, "test_utxo");
                assert_eq!(payload.amount, 2000000);
                assert_eq!(payload.block_height, 15000);
            }
            _ => panic!("Expected UtxoReceived event"),
        }

        // Test summary
        let summary = event.summary();
        assert!(summary.contains("UTXO received"));
        assert!(summary.contains("15000"));
        assert!(summary.contains("2000000 units"));
    }

    #[test]
    fn test_wallet_event_utxo_spent_serialization() {
        let payload = UtxoSpentPayload::new(
            "spent_utxo".to_string(),
            1500000,
            14000, // original height
            15500, // spending height
            "spending_block".to_string(),
            1697123800,
            "spending_tx".to_string(),
            2,
            "spending_address".to_string(),
            20,
            "spent_commitment".to_string(),
            "output_hash".to_string(),
            false, // not self spend
            "testnet".to_string(),
        );

        let event = WalletEvent::utxo_spent(payload);

        // Test JSON serialization
        let json = event.to_debug_json().unwrap();
        assert!(json.contains("UtxoSpent"));
        assert!(json.contains("spent_utxo"));
        assert!(json.contains("1500000"));
        assert!(json.contains("15500"));
        assert!(json.contains("false")); // is_self_spend

        // Test roundtrip
        let deserialized = WalletEvent::from_json(&json).unwrap();
        match deserialized {
            WalletEvent::UtxoSpent { payload, .. } => {
                assert_eq!(payload.utxo_id, "spent_utxo");
                assert_eq!(payload.amount, 1500000);
                assert_eq!(payload.spending_block_height, 15500);
                assert_eq!(payload.is_self_spend, false);
            }
            _ => panic!("Expected UtxoSpent event"),
        }

        // Test summary
        let summary = event.summary();
        assert!(summary.contains("UTXO spent"));
        assert!(summary.contains("15500"));
        assert!(summary.contains("1500000 units"));
    }

    #[test]
    fn test_wallet_event_reorg_serialization() {
        let payload = ReorgPayload::new(
            20000,
            "old_fork_block".to_string(),
            "new_fork_block".to_string(),
            3,
            5,
            vec!["reorg_tx1".to_string(), "reorg_tx2".to_string()],
            vec!["reorg_utxo1".to_string()],
            500000, // positive balance change
            "mainnet".to_string(),
            1697123900,
        );

        let event = WalletEvent::reorg(payload);

        // Test JSON serialization
        let json = event.to_debug_json().unwrap();
        assert!(json.contains("Reorg"));
        assert!(json.contains("20000"));
        assert!(json.contains("old_fork_block"));
        assert!(json.contains("new_fork_block"));
        assert!(json.contains("500000"));
        assert!(json.contains("reorg_tx1"));

        // Test roundtrip
        let deserialized = WalletEvent::from_json(&json).unwrap();
        match deserialized {
            WalletEvent::Reorg { payload, .. } => {
                assert_eq!(payload.fork_height, 20000);
                assert_eq!(payload.rollback_depth, 3);
                assert_eq!(payload.new_blocks_count, 5);
                assert_eq!(payload.balance_change, 500000);
                assert_eq!(payload.affected_transaction_hashes.len(), 2);
            }
            _ => panic!("Expected Reorg event"),
        }

        // Test summary
        let summary = event.summary();
        assert!(summary.contains("Blockchain reorg"));
        assert!(summary.contains("20000"));
        assert!(summary.contains("2 transactions affected"));
    }

    #[test]
    fn test_wallet_event_metadata_serialization() {
        let payload = UtxoReceivedPayload::new(
            "metadata_test".to_string(),
            100000,
            1000,
            "block".to_string(),
            1697124000,
            "tx".to_string(),
            0,
            "addr".to_string(),
            5,
            "commit".to_string(),
            0,
            "testnet".to_string(),
        );

        let event = WalletEvent::utxo_received(payload);

        // Test that metadata is properly included
        let json = event.to_debug_json().unwrap();
        assert!(json.contains("metadata"));
        assert!(json.contains("event_id"));
        assert!(json.contains("timestamp"));
        assert!(json.contains("source"));
        assert!(json.contains("wallet")); // source should be "wallet"

        // Verify metadata through EventType trait
        assert_eq!(event.event_type(), "UtxoReceived");
        let metadata = event.metadata();
        assert!(!metadata.event_id.is_empty());
        assert_eq!(metadata.source, "wallet");
        assert!(metadata.correlation_id.is_none());
    }

    // Tests for wallet event error handling

    #[test]
    fn test_wallet_event_error_creation() {
        // Test validation error
        let validation_err = WalletEventError::validation("Invalid amount", "UtxoReceived");
        assert_eq!(validation_err.category(), "validation");
        assert!(!validation_err.is_recoverable());
        assert!(validation_err
            .to_string()
            .contains("Event validation failed"));
        assert!(validation_err.to_string().contains("Invalid amount"));

        // Test serialization error
        let ser_err = WalletEventError::serialization("JSON parse error", "UtxoSpent");
        assert_eq!(ser_err.category(), "serialization");
        assert!(!ser_err.is_recoverable());

        // Test processing error
        let proc_err = WalletEventError::processing("Reorg", "Database constraint violation");
        assert_eq!(proc_err.category(), "processing");
        assert!(!proc_err.is_recoverable());

        // Test storage error (recoverable)
        let storage_err = WalletEventError::storage("insert", "Connection timeout");
        assert_eq!(storage_err.category(), "storage");
        assert!(storage_err.is_recoverable());
    }

    #[test]
    fn test_wallet_event_validation_errors() {
        // Test missing field error
        let missing_field = WalletEventValidationError::MissingField {
            field: "utxo_id".to_string(),
        };
        assert!(missing_field
            .to_string()
            .contains("Required field 'utxo_id' is missing"));

        // Test out of range error
        let out_of_range = WalletEventValidationError::OutOfRange {
            field: "amount".to_string(),
            value: "0".to_string(),
            constraint: "must be positive".to_string(),
        };
        assert!(out_of_range.to_string().contains("out of range"));

        // Test invalid format error
        let invalid_format = WalletEventValidationError::InvalidFormat {
            field: "block_hash".to_string(),
            value: "invalid_hash".to_string(),
            expected_format: "64-character hex string".to_string(),
        };
        assert!(invalid_format.to_string().contains("invalid format"));

        // Test field too long error
        let too_long = WalletEventValidationError::FieldTooLong {
            field: "description".to_string(),
            actual: 1000,
            max: 500,
        };
        assert!(too_long.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_event_listener_errors() {
        // Test initialization failed
        let init_failed = EventListenerError::InitializationFailed {
            name: "DatabaseListener".to_string(),
            reason: "Connection refused".to_string(),
        };
        assert!(init_failed.to_string().contains("initialization failed"));

        // Test invalid state
        let invalid_state = EventListenerError::InvalidState {
            name: "LoggingListener".to_string(),
            state: "closed".to_string(),
            operation: "handle_event".to_string(),
        };
        assert!(invalid_state.to_string().contains("invalid state"));

        // Test resource limit exceeded
        let limit_exceeded = EventListenerError::ResourceLimitExceeded {
            name: "MemoryListener".to_string(),
            resource: "memory".to_string(),
            current: 1024,
            max: 512,
        };
        assert!(limit_exceeded.to_string().contains("exceeded memory limit"));
    }

    #[test]
    fn test_error_conversions() {
        // Test conversion from validation error
        let validation_err = WalletEventValidationError::MissingField {
            field: "test_field".to_string(),
        };
        let wallet_err: WalletEventError = validation_err.into();
        match wallet_err {
            WalletEventError::ValidationError { message, .. } => {
                assert!(message.contains("test_field"));
            }
            _ => panic!("Expected ValidationError"),
        }

        // Test conversion from listener error
        let listener_err = EventListenerError::InitializationFailed {
            name: "TestListener".to_string(),
            reason: "Test reason".to_string(),
        };
        let wallet_err: WalletEventError = listener_err.into();
        match wallet_err {
            WalletEventError::ListenerError { error, .. } => {
                assert!(error.contains("TestListener"));
            }
            _ => panic!("Expected ListenerError"),
        }

        // Test conversion from serde_json error
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let wallet_err: WalletEventError = json_err.into();
        match wallet_err {
            WalletEventError::SerializationError { message, .. } => {
                assert!(message.contains("expected"));
            }
            _ => panic!("Expected SerializationError"),
        }
    }

    #[test]
    fn test_error_recoverability() {
        // Recoverable errors
        let recoverable_errors = vec![
            WalletEventError::NetworkError {
                operation: "send".to_string(),
                error: "timeout".to_string(),
            },
            WalletEventError::ProcessingTimeout {
                event_type: "UtxoReceived".to_string(),
                seconds: 30,
            },
            WalletEventError::StorageError {
                operation: "insert".to_string(),
                reason: "deadlock".to_string(),
            },
            WalletEventError::ConcurrentModification {
                resource: "utxo_state".to_string(),
                details: "version mismatch".to_string(),
            },
        ];

        for error in recoverable_errors {
            assert!(
                error.is_recoverable(),
                "Error should be recoverable: {:?}",
                error
            );
        }

        // Non-recoverable errors
        let non_recoverable_errors = vec![
            WalletEventError::ValidationError {
                message: "test".to_string(),
                event_type: "test".to_string(),
            },
            WalletEventError::InvalidPayload {
                event_type: "test".to_string(),
                field: "test".to_string(),
                message: "test".to_string(),
            },
            WalletEventError::DuplicateEvent {
                event_id: "test".to_string(),
            },
            WalletEventError::PermissionDenied {
                operation: "test".to_string(),
                reason: "test".to_string(),
            },
        ];

        for error in non_recoverable_errors {
            assert!(
                !error.is_recoverable(),
                "Error should not be recoverable: {:?}",
                error
            );
        }
    }

    #[test]
    fn test_error_categorization() {
        let test_cases = vec![
            (
                WalletEventError::ValidationError {
                    message: "test".to_string(),
                    event_type: "test".to_string(),
                },
                "validation",
            ),
            (
                WalletEventError::SerializationError {
                    message: "test".to_string(),
                    event_type: "test".to_string(),
                },
                "serialization",
            ),
            (
                WalletEventError::ProcessingError {
                    event_type: "test".to_string(),
                    reason: "test".to_string(),
                },
                "processing",
            ),
            (
                WalletEventError::ReplayError {
                    sequence: 1,
                    reason: "test".to_string(),
                },
                "replay",
            ),
            (
                WalletEventError::StorageError {
                    operation: "test".to_string(),
                    reason: "test".to_string(),
                },
                "storage",
            ),
            (
                WalletEventError::WalletIdMismatch {
                    expected: "test".to_string(),
                    actual: "test".to_string(),
                },
                "consistency",
            ),
            (
                WalletEventError::InvalidBlockHeight {
                    height: 0,
                    reason: "test".to_string(),
                },
                "business_logic",
            ),
            (
                WalletEventError::ConcurrentModification {
                    resource: "test".to_string(),
                    details: "test".to_string(),
                },
                "concurrency",
            ),
            (
                WalletEventError::ConfigurationError {
                    parameter: "test".to_string(),
                    message: "test".to_string(),
                },
                "configuration",
            ),
            (
                WalletEventError::NetworkError {
                    operation: "test".to_string(),
                    error: "test".to_string(),
                },
                "network",
            ),
            (
                WalletEventError::PermissionDenied {
                    operation: "test".to_string(),
                    reason: "test".to_string(),
                },
                "security",
            ),
            (
                WalletEventError::InternalError {
                    details: "test".to_string(),
                },
                "internal",
            ),
        ];

        for (error, expected_category) in test_cases {
            assert_eq!(
                error.category(),
                expected_category,
                "Error {:?} should have category {}",
                error,
                expected_category
            );
        }
    }

    #[test]
    fn test_wallet_event_result_usage() {
        // Test successful result
        let success: WalletEventResult<String> = Ok("success".to_string());
        assert!(success.is_ok());

        // Test error result
        let error: WalletEventResult<String> = Err(WalletEventError::validation("test", "test"));
        assert!(error.is_err());

        // Test error propagation
        fn test_function() -> WalletEventResult<String> {
            Err(WalletEventError::processing("TestEvent", "Test failure"))
        }

        let result = test_function();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.category(), "processing");
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_error_message_formatting() {
        // Test that error messages are properly formatted and contain expected information
        let validation_err = WalletEventError::ValidationError {
            message: "Amount cannot be zero".to_string(),
            event_type: "UtxoReceived".to_string(),
        };
        let message = validation_err.to_string();
        assert!(message.contains("Event validation failed"));
        assert!(message.contains("Amount cannot be zero"));

        let sequence_err = WalletEventError::SequenceError {
            expected: 5,
            actual: 3,
        };
        let message = sequence_err.to_string();
        assert!(message.contains("Invalid event sequence"));
        assert!(message.contains("expected 5"));
        assert!(message.contains("got 3"));

        let state_transition_err = WalletEventError::InvalidStateTransition {
            utxo_id: "utxo_123".to_string(),
            from_state: "Unspent".to_string(),
            to_state: "Invalid".to_string(),
        };
        let message = state_transition_err.to_string();
        assert!(message.contains("Invalid UTXO state transition"));
        assert!(message.contains("utxo_123"));
        assert!(message.contains("Unspent -> Invalid"));
    }

    #[test]
    fn test_wallet_event_serialization_completeness() {
        // Test that all WalletEvent variants can be serialized and deserialized
        let events = vec![
            WalletEvent::utxo_received(UtxoReceivedPayload::new(
                "test1".to_string(),
                100,
                1000,
                "block1".to_string(),
                1697124100,
                "tx1".to_string(),
                0,
                "addr1".to_string(),
                1,
                "commit1".to_string(),
                0,
                "net".to_string(),
            )),
            WalletEvent::utxo_spent(UtxoSpentPayload::new(
                "test2".to_string(),
                200,
                1000,
                1100,
                "block2".to_string(),
                1697124200,
                "tx2".to_string(),
                1,
                "addr2".to_string(),
                2,
                "commit2".to_string(),
                "method".to_string(),
                false,
                "net".to_string(),
            )),
            WalletEvent::reorg(ReorgPayload::new(
                1000,
                "old".to_string(),
                "new".to_string(),
                2,
                3,
                vec!["tx3".to_string()],
                vec!["utxo3".to_string()],
                0,
                "net".to_string(),
                1697124300,
            )),
        ];

        for event in events {
            // Test serialization doesn't fail
            let json = event.to_debug_json().unwrap();
            let _compact = event.to_compact_json().unwrap();

            // Test deserialization doesn't fail
            let deserialized = WalletEvent::from_json(&json).unwrap();

            // Test event types match
            assert_eq!(event.event_type(), deserialized.event_type());

            // Test summary doesn't fail
            let summary = event.summary();
            assert!(!summary.is_empty());

            // Test debug data doesn't fail
            let debug = event.debug_data();
            assert!(debug.is_some());
            assert!(!debug.unwrap().is_empty());
        }
    }
}
