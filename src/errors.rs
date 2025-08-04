use thiserror::Error;

/// Main error type for the lightweight wallet library
#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Data structure error: {0}")]
    DataStructureError(#[from] DataStructureError),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationError),

    #[error("Validation error: {0}")]
    ValidationError(#[from] ValidationError),

    #[error("Key management error: {0}")]
    KeyManagementError(#[from] KeyManagementError),

    #[error("Scanning error: {0}")]
    ScanningError(#[from] ScanningError),

    #[error("Encryption error: {0}")]
    EncryptionError(#[from] EncryptionError),

    #[error("Hex error: {0}")]
    HexError(#[from] crate::hex_utils::HexError),

    #[error("Conversion error: {0}")]
    ConversionError(String),

    #[error("Invalid argument: {argument} = {value}. {message}")]
    InvalidArgument {
        argument: String,
        value: String,
        message: String,
    },

    #[error("Operation not supported: {0}")]
    OperationNotSupported(String),

    #[error("Resource not found: {0}")]
    ResourceNotFound(String),

    #[error("Insufficient funds: {0}")]
    InsufficientFunds(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("gRPC error: {0}")]
    GrpcError(String),

    #[error("Data error: {0}")]
    DataError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

/// Errors related to data structure operations
#[derive(Debug, Error)]
pub enum DataStructureError {
    #[error("Invalid output version: {0}")]
    InvalidOutputVersion(String),

    #[error("Invalid output value: {0}")]
    InvalidOutputValue(String),

    #[error("Invalid key identifier: {0}")]
    InvalidKeyId(String),

    #[error("Invalid output features: {0}")]
    InvalidFeatures(String),

    #[error("Invalid script: {0}")]
    InvalidScript(String),

    #[error("Invalid covenant: {0}")]
    InvalidCovenant(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid range proof: {0}")]
    InvalidRangeProof(String),

    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),

    #[error("Invalid payment ID: {0}")]
    InvalidPaymentId(String),

    #[error("Invalid transaction output: {0}")]
    InvalidTransactionOutput(String),

    #[error("Invalid wallet output: {0}")]
    InvalidWalletOutput(String),

    #[error("Invalid encrypted data: {0}")]
    InvalidEncryptedData(String),

    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Data too large: expected max {max}, got {actual}")]
    DataTooLarge { max: usize, actual: usize },

    #[error("Data too small: expected min {min}, got {actual}")]
    DataTooSmall { min: usize, actual: usize },

    #[error("Incorrect data length: {0}")]
    IncorrectLength(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Duplicate data: {0}")]
    DuplicateData(String),

    #[error("Invalid data format: {0}")]
    InvalidDataFormat(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid checksum: {0}")]
    InvalidChecksum(String),

    #[error("Invalid network: {0}")]
    InvalidNetwork(String),
}

/// Errors related to serialization and deserialization
#[derive(Debug, Error)]
pub enum SerializationError {
    #[error("Serde serialization error: {0}")]
    SerdeSerializationError(String),

    #[error("Serde deserialization error: {0}")]
    SerdeDeserializationError(String),

    #[error("Borsh serialization error: {0}")]
    BorshSerializationError(String),

    #[error("Borsh deserialization error: {0}")]
    BorshDeserializationError(String),

    #[error("Hex encoding error: {0}")]
    HexEncodingError(String),

    #[error("Hex decoding error: {0}")]
    HexDecodingError(String),

    #[error("Base64 encoding error: {0}")]
    Base64EncodingError(String),

    #[error("Base64 decoding error: {0}")]
    Base64DecodingError(String),

    #[error("JSON serialization error: {0}")]
    JsonSerializationError(String),

    #[error("JSON deserialization error: {0}")]
    JsonDeserializationError(String),

    #[error("Protobuf serialization error: {0}")]
    ProtobufSerializationError(String),

    #[error("Protobuf deserialization error: {0}")]
    ProtobufDeserializationError(String),

    #[error("Buffer overflow: {0}")]
    BufferOverflow(String),

    #[error("Buffer underflow: {0}")]
    BufferUnderflow(String),

    #[error("Invalid encoding: {0}")]
    InvalidEncoding(String),
}

/// Errors related to validation operations
#[derive(Debug, Clone, Error)]
pub enum ValidationError {
    #[error("Range proof validation failed: {0}")]
    RangeProofValidationFailed(String),

    #[error("Signature validation failed: {0}")]
    SignatureValidationFailed(String),

    #[error("Metadata signature validation failed: {0}")]
    MetadataSignatureValidationFailed(String),

    #[error("Script signature validation failed: {0}")]
    ScriptSignatureValidationFailed(String),

    #[error("Commitment validation failed: {0}")]
    CommitmentValidationFailed(String),

    #[error("Script validation failed: {0}")]
    ScriptValidationFailed(String),

    #[error("Covenant validation failed: {0}")]
    CovenantValidationFailed(String),

    #[error("Output validation failed: {0}")]
    OutputValidationFailed(String),

    #[error("Input validation failed: {0}")]
    InputValidationFailed(String),

    #[error("Transaction validation failed: {0}")]
    TransactionValidationFailed(String),

    #[error("Block validation failed: {0}")]
    BlockValidationFailed(String),

    #[error("Value validation failed: {0}")]
    ValueValidationFailed(String),

    #[error("Key validation failed: {0}")]
    KeyValidationFailed(String),

    #[error("Address validation failed: {0}")]
    AddressValidationFailed(String),

    #[error("Network validation failed: {0}")]
    NetworkValidationFailed(String),

    #[error("Version validation failed: {0}")]
    VersionValidationFailed(String),

    #[error("Integrity check failed: {0}")]
    IntegrityCheckFailed(String),

    #[error("Consensus validation failed: {0}")]
    ConsensusValidationFailed(String),

    #[error("Minimum value promise validation failed: {0}")]
    MinimumValuePromiseValidationFailed(String),
}

/// Errors related to key management operations
#[derive(Debug, Error)]
pub enum KeyManagementError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid key derivation path: {0}")]
    InvalidKeyDerivationPath(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Key import failed: {0}")]
    KeyImportFailed(String),

    #[error("Key export failed: {0}")]
    KeyExportFailed(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Key recovery failed: {0}")]
    KeyRecoveryFailed(String),

    #[error("Stealth address recovery failed: {0}")]
    StealthAddressRecoveryFailed(String),

    #[error("Mnemonic error: {0}")]
    MnemonicError(String),

    #[error("Seed phrase error: {0}")]
    SeedPhraseError(String),

    #[error("Key storage error: {0}")]
    KeyStorageError(String),

    #[error("Key encryption error: {0}")]
    KeyEncryptionError(String),

    #[error("Key decryption error: {0}")]
    KeyDecryptionError(String),

    #[error("Key backup error: {0}")]
    KeyBackupError(String),

    #[error("Key restore error: {0}")]
    KeyRestoreError(String),

    #[error("Key migration error: {0}")]
    KeyMigrationError(String),

    #[error("Key version error: {0}")]
    KeyVersionError(String),

    #[error("CRC checksum error")]
    CrcError,

    #[error("Version mismatch")]
    VersionMismatch,

    #[error("Invalid data format")]
    InvalidData,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Cryptographic error: {0}")]
    CryptographicError(String),

    // === Enhanced Seed Phrase Error Types ===
    #[error("Invalid seed phrase format: {details}. Suggestion: {suggestion}")]
    InvalidSeedPhraseFormat { details: String, suggestion: String },

    #[error("Invalid word count: expected {expected} words, got {actual} words. Please check your seed phrase has exactly {expected} words.")]
    InvalidWordCount { expected: usize, actual: usize },

    #[error("Unknown word '{word}' at position {position}. This word is not in the BIP39 word list. Please check for typos.")]
    UnknownWord { word: String, position: usize },

    #[error("Invalid seed phrase checksum. The seed phrase appears to be corrupted or mistyped. Please verify all words are correct.")]
    InvalidSeedChecksum,

    #[error("Empty seed phrase provided. Please provide a valid seed phrase.")]
    EmptySeedPhrase,

    #[error("Seed phrase validation failed: {reason}. Suggestion: {suggestion}")]
    SeedValidationFailed { reason: String, suggestion: String },

    #[error("Seed phrase encoding error: {details}. The seed phrase could not be converted to the expected format.")]
    SeedEncodingError { details: String },

    #[error("Seed phrase decoding error: {details}. The provided data could not be converted to a valid seed phrase.")]
    SeedDecodingError { details: String },

    // === Enhanced Derivation Error Types ===
    #[error("Master key derivation failed: {reason}. Check that the seed phrase and passphrase are correct.")]
    MasterKeyDerivationFailed { reason: String },

    #[error("Branch key derivation failed for branch '{branch}' at index {index}: {reason}")]
    BranchKeyDerivationFailed {
        branch: String,
        index: u64,
        reason: String,
    },

    #[error("View key derivation failed: {reason}. This may indicate an issue with the master key or derivation parameters.")]
    ViewKeyDerivationFailed { reason: String },

    #[error("Spend key derivation failed: {reason}. This may indicate an issue with the master key or derivation parameters.")]
    SpendKeyDerivationFailed { reason: String },

    #[error(
        "Invalid derivation index {index} for branch '{branch}'. Index must be within valid range."
    )]
    InvalidDerivationIndex { branch: String, index: u64 },

    #[error("Derivation path too deep: {depth} levels. Maximum supported depth is {max_depth}.")]
    DerivationPathTooDeep { depth: usize, max_depth: usize },

    #[error("Hierarchical derivation failed at level {level}: {reason}")]
    HierarchicalDerivationFailed { level: usize, reason: String },

    // === Enhanced CipherSeed Error Types ===
    #[error(
        "CipherSeed version {version} is not supported. Supported versions: {supported_versions:?}"
    )]
    UnsupportedCipherSeedVersion {
        version: u8,
        supported_versions: Vec<u8>,
    },

    #[error("CipherSeed encryption failed: {reason}. Please check the passphrase and try again.")]
    CipherSeedEncryptionFailed { reason: String },

    #[error("CipherSeed decryption failed: {reason}. Please verify the passphrase is correct.")]
    CipherSeedDecryptionFailed { reason: String },

    #[error("Invalid CipherSeed format: {details}. The data does not match the expected CipherSeed structure.")]
    InvalidCipherSeedFormat { details: String },

    #[error("CipherSeed MAC verification failed. The seed data may be corrupted or the wrong passphrase was used.")]
    CipherSeedMacVerificationFailed,

    #[error("Invalid CipherSeed birthday {birthday}. Birthday must be within valid range.")]
    InvalidCipherSeedBirthday { birthday: u16 },

    #[error("CipherSeed entropy error: {details}. The entropy data is invalid or corrupted.")]
    CipherSeedEntropyError { details: String },

    // === Enhanced Passphrase Error Types ===
    #[error("Missing required passphrase. This seed phrase was created with a passphrase and requires one for decryption.")]
    MissingRequiredPassphrase,

    #[error("Invalid passphrase provided. Please check that the passphrase is correct.")]
    InvalidPassphrase,

    #[error("Passphrase validation failed: {reason}")]
    PassphraseValidationFailed { reason: String },

    // === Enhanced Key Validation Error Types ===
    #[error("Key validation failed: {key_type} key failed validation. Reason: {reason}")]
    KeyValidationFailed { key_type: String, reason: String },

    #[error("Key format error: {key_type} key has invalid format. Expected: {expected_format}, got: {actual_format}")]
    KeyFormatError {
        key_type: String,
        expected_format: String,
        actual_format: String,
    },

    #[error("Key length error: {key_type} key has invalid length. Expected: {expected_length} bytes, got: {actual_length} bytes")]
    KeyLengthError {
        key_type: String,
        expected_length: usize,
        actual_length: usize,
    },

    // === Enhanced Domain Separation Error Types ===
    #[error("Domain separation error: {operation} failed with domain '{domain}'. {details}")]
    DomainSeparationError {
        operation: String,
        domain: String,
        details: String,
    },

    #[error("Invalid domain label '{label}' for operation '{operation}'. Expected one of: {valid_labels:?}")]
    InvalidDomainLabel {
        operation: String,
        label: String,
        valid_labels: Vec<String>,
    },

    // === Enhanced Recovery Error Types ===
    #[error("Wallet recovery failed: {stage}. {details}. Suggestion: {suggestion}")]
    WalletRecoveryFailed {
        stage: String,
        details: String,
        suggestion: String,
    },

    #[error("Partial recovery completed: {recovered_items} items recovered, {failed_items} items failed. {details}")]
    PartialRecoveryCompleted {
        recovered_items: usize,
        failed_items: usize,
        details: String,
    },
}

/// Errors related to UTXO scanning operations
#[derive(Debug, Error)]
pub enum ScanningError {
    #[error("Blockchain connection failed: {0}")]
    BlockchainConnectionFailed(String),

    #[error("Block not found: {0}")]
    BlockNotFound(String),

    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    #[error("Output not found: {0}")]
    OutputNotFound(String),

    #[error("Scan interrupted: {0}")]
    ScanInterrupted(String),

    #[error("Scan timeout: {0}")]
    ScanTimeout(String),

    #[error("Invalid block height: {0}")]
    InvalidBlockHeight(String),

    #[error("Invalid block hash: {0}")]
    InvalidBlockHash(String),

    #[error("Invalid transaction hash: {0}")]
    InvalidTransactionHash(String),

    #[error("Invalid output hash: {0}")]
    InvalidOutputHash(String),

    #[error("Scan progress error: {0}")]
    ScanProgressError(String),

    #[error("Scan resume failed: {0}")]
    ScanResumeFailed(String),

    #[error("Scan state corrupted: {0}")]
    ScanStateCorrupted(String),

    #[error("Scan configuration error: {0}")]
    ScanConfigurationError(String),

    #[error("Scan memory error: {0}")]
    ScanMemoryError(String),

    #[error("Scan performance error: {0}")]
    ScanPerformanceError(String),

    #[error("Scan data corruption: {0}")]
    ScanDataCorruption(String),

    #[error("Scan network error: {0}")]
    ScanNetworkError(String),

    #[error("Scan rate limit exceeded: {0}")]
    ScanRateLimitExceeded(String),
}

/// Errors related to encryption and decryption operations
#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid encryption key: {0}")]
    InvalidEncryptionKey(String),

    #[error("Invalid decryption key: {0}")]
    InvalidDecryptionKey(String),

    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    #[error("Invalid plaintext: {0}")]
    InvalidPlaintext(String),

    #[error("Invalid tag: {0}")]
    InvalidTag(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Invalid encryption parameters: {0}")]
    InvalidEncryptionParameters(String),

    #[error("Encryption version error: {0}")]
    EncryptionVersionError(String),

    #[error("Encryption algorithm error: {0}")]
    EncryptionAlgorithmError(String),

    #[error("Encryption mode error: {0}")]
    EncryptionModeError(String),

    #[error("Encryption padding error: {0}")]
    EncryptionPaddingError(String),

    #[error("Encryption block size error: {0}")]
    EncryptionBlockSizeError(String),

    #[error("Encryption initialization error: {0}")]
    EncryptionInitializationError(String),

    #[error("Encryption finalization error: {0}")]
    EncryptionFinalizationError(String),
}

// Conversion implementations for external error types
impl From<hex::FromHexError> for SerializationError {
    fn from(err: hex::FromHexError) -> Self {
        SerializationError::HexDecodingError(err.to_string())
    }
}

impl From<std::io::Error> for SerializationError {
    fn from(err: std::io::Error) -> Self {
        SerializationError::BufferOverflow(err.to_string())
    }
}

impl From<String> for WalletError {
    fn from(err: String) -> Self {
        WalletError::InternalError(err)
    }
}

impl From<&str> for WalletError {
    fn from(err: &str) -> Self {
        WalletError::InternalError(err.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
impl From<wasm_bindgen::JsValue> for WalletError {
    fn from(err: wasm_bindgen::JsValue) -> Self {
        let message = if let Some(string) = err.as_string() {
            string
        } else {
            format!("{:?}", err)
        };
        WalletError::NetworkError(format!("WASM error: {}", message))
    }
}

// Note: Convenience constructors will be generated via macros (see macros.rs)

impl DataStructureError {
    /// Create an invalid output version error
    pub fn invalid_output_version(version: &str) -> Self {
        Self::InvalidOutputVersion(version.to_string())
    }

    /// Create an invalid output value error
    pub fn invalid_output_value(value: &str) -> Self {
        Self::InvalidOutputValue(value.to_string())
    }

    /// Create a data too large error
    pub fn data_too_large(max: usize, actual: usize) -> Self {
        Self::DataTooLarge { max, actual }
    }

    /// Create a data too small error
    pub fn data_too_small(min: usize, actual: usize) -> Self {
        Self::DataTooSmall { min, actual }
    }

    /// Create a missing field error
    pub fn missing_field(field: &str) -> Self {
        Self::MissingField(field.to_string())
    }

    /// Create an invalid address error
    pub fn invalid_address(address: &str) -> Self {
        Self::InvalidAddress(address.to_string())
    }
}

impl SerializationError {
    /// Create a hex encoding error
    pub fn hex_encoding_error(details: &str) -> Self {
        Self::HexEncodingError(details.to_string())
    }

    /// Create a hex decoding error
    pub fn hex_decoding_error(details: &str) -> Self {
        Self::HexDecodingError(details.to_string())
    }

    /// Create a serde serialization error
    pub fn serde_serialization_error(details: &str) -> Self {
        Self::SerdeSerializationError(details.to_string())
    }

    /// Create a serde deserialization error
    pub fn serde_deserialization_error(details: &str) -> Self {
        Self::SerdeDeserializationError(details.to_string())
    }
}

impl ValidationError {
    /// Create a range proof validation error
    pub fn range_proof_validation_failed(details: &str) -> Self {
        ValidationError::RangeProofValidationFailed(details.to_string())
    }

    /// Create a signature validation error
    pub fn signature_validation_failed(details: &str) -> Self {
        ValidationError::SignatureValidationFailed(details.to_string())
    }

    /// Create a metadata signature validation error
    pub fn metadata_signature_validation_failed(details: &str) -> Self {
        ValidationError::MetadataSignatureValidationFailed(details.to_string())
    }

    /// Create a script signature validation error
    pub fn script_signature_validation_failed(details: &str) -> Self {
        ValidationError::ScriptSignatureValidationFailed(details.to_string())
    }

    /// Create a commitment validation error
    pub fn commitment_validation_failed(details: &str) -> Self {
        ValidationError::CommitmentValidationFailed(details.to_string())
    }

    /// Create a minimum value promise validation error
    pub fn minimum_value_promise_validation_failed(details: &str) -> Self {
        ValidationError::MinimumValuePromiseValidationFailed(details.to_string())
    }
}

impl KeyManagementError {
    /// Create a key not found error
    pub fn key_not_found(key_id: &str) -> Self {
        Self::KeyNotFound(key_id.to_string())
    }

    /// Create a key derivation failed error
    pub fn key_derivation_failed(details: &str) -> Self {
        Self::KeyDerivationFailed(details.to_string())
    }

    /// Create a stealth address recovery failed error
    pub fn stealth_address_recovery_failed(details: &str) -> Self {
        Self::StealthAddressRecoveryFailed(details.to_string())
    }

    // === Seed Phrase Error Convenience Methods ===

    /// Create an invalid seed phrase format error with suggestion
    pub fn invalid_seed_phrase_format(details: &str, suggestion: &str) -> Self {
        Self::InvalidSeedPhraseFormat {
            details: details.to_string(),
            suggestion: suggestion.to_string(),
        }
    }

    /// Create an invalid word count error
    pub fn invalid_word_count(expected: usize, actual: usize) -> Self {
        Self::InvalidWordCount { expected, actual }
    }

    /// Create an unknown word error
    pub fn unknown_word(word: &str, position: usize) -> Self {
        Self::UnknownWord {
            word: word.to_string(),
            position,
        }
    }

    /// Create an invalid seed checksum error
    pub fn invalid_seed_checksum() -> Self {
        Self::InvalidSeedChecksum
    }

    /// Create an empty seed phrase error
    pub fn empty_seed_phrase() -> Self {
        Self::EmptySeedPhrase
    }

    /// Create a seed validation failed error with suggestion
    pub fn seed_validation_failed(reason: &str, suggestion: &str) -> Self {
        Self::SeedValidationFailed {
            reason: reason.to_string(),
            suggestion: suggestion.to_string(),
        }
    }

    /// Create a seed encoding error
    pub fn seed_encoding_error(details: &str) -> Self {
        Self::SeedEncodingError {
            details: details.to_string(),
        }
    }

    /// Create a seed decoding error
    pub fn seed_decoding_error(details: &str) -> Self {
        Self::SeedDecodingError {
            details: details.to_string(),
        }
    }

    // === Derivation Error Convenience Methods ===

    /// Create a master key derivation failed error
    pub fn master_key_derivation_failed(reason: &str) -> Self {
        Self::MasterKeyDerivationFailed {
            reason: reason.to_string(),
        }
    }

    /// Create a branch key derivation failed error
    pub fn branch_key_derivation_failed(branch: &str, index: u64, reason: &str) -> Self {
        Self::BranchKeyDerivationFailed {
            branch: branch.to_string(),
            index,
            reason: reason.to_string(),
        }
    }

    /// Create a view key derivation failed error
    pub fn view_key_derivation_failed(reason: &str) -> Self {
        Self::ViewKeyDerivationFailed {
            reason: reason.to_string(),
        }
    }

    /// Create a spend key derivation failed error
    pub fn spend_key_derivation_failed(reason: &str) -> Self {
        Self::SpendKeyDerivationFailed {
            reason: reason.to_string(),
        }
    }

    /// Create an invalid derivation index error
    pub fn invalid_derivation_index(branch: &str, index: u64) -> Self {
        Self::InvalidDerivationIndex {
            branch: branch.to_string(),
            index,
        }
    }

    /// Create a derivation path too deep error
    pub fn derivation_path_too_deep(depth: usize, max_depth: usize) -> Self {
        Self::DerivationPathTooDeep { depth, max_depth }
    }

    /// Create a hierarchical derivation failed error
    pub fn hierarchical_derivation_failed(level: usize, reason: &str) -> Self {
        Self::HierarchicalDerivationFailed {
            level,
            reason: reason.to_string(),
        }
    }

    // === CipherSeed Error Convenience Methods ===

    /// Create an unsupported CipherSeed version error
    pub fn unsupported_cipher_seed_version(version: u8, supported_versions: Vec<u8>) -> Self {
        Self::UnsupportedCipherSeedVersion {
            version,
            supported_versions,
        }
    }

    /// Create a CipherSeed encryption failed error
    pub fn cipher_seed_encryption_failed(reason: &str) -> Self {
        Self::CipherSeedEncryptionFailed {
            reason: reason.to_string(),
        }
    }

    /// Create a CipherSeed decryption failed error
    pub fn cipher_seed_decryption_failed(reason: &str) -> Self {
        Self::CipherSeedDecryptionFailed {
            reason: reason.to_string(),
        }
    }

    /// Create an invalid CipherSeed format error
    pub fn invalid_cipher_seed_format(details: &str) -> Self {
        Self::InvalidCipherSeedFormat {
            details: details.to_string(),
        }
    }

    /// Create a CipherSeed MAC verification failed error
    pub fn cipher_seed_mac_verification_failed() -> Self {
        Self::CipherSeedMacVerificationFailed
    }

    /// Create an invalid CipherSeed birthday error
    pub fn invalid_cipher_seed_birthday(birthday: u16) -> Self {
        Self::InvalidCipherSeedBirthday { birthday }
    }

    /// Create a CipherSeed entropy error
    pub fn cipher_seed_entropy_error(details: &str) -> Self {
        Self::CipherSeedEntropyError {
            details: details.to_string(),
        }
    }

    // === Passphrase Error Convenience Methods ===

    /// Create a missing required passphrase error
    pub fn missing_required_passphrase() -> Self {
        Self::MissingRequiredPassphrase
    }

    /// Create an invalid passphrase error
    pub fn invalid_passphrase() -> Self {
        Self::InvalidPassphrase
    }

    /// Create a passphrase validation failed error
    pub fn passphrase_validation_failed(reason: &str) -> Self {
        Self::PassphraseValidationFailed {
            reason: reason.to_string(),
        }
    }

    // === Key Validation Error Convenience Methods ===

    /// Create a key validation failed error
    pub fn key_validation_failed(key_type: &str, reason: &str) -> Self {
        Self::KeyValidationFailed {
            key_type: key_type.to_string(),
            reason: reason.to_string(),
        }
    }

    /// Create a key format error
    pub fn key_format_error(key_type: &str, expected_format: &str, actual_format: &str) -> Self {
        Self::KeyFormatError {
            key_type: key_type.to_string(),
            expected_format: expected_format.to_string(),
            actual_format: actual_format.to_string(),
        }
    }

    /// Create a key length error
    pub fn key_length_error(key_type: &str, expected_length: usize, actual_length: usize) -> Self {
        Self::KeyLengthError {
            key_type: key_type.to_string(),
            expected_length,
            actual_length,
        }
    }

    // === Domain Separation Error Convenience Methods ===

    /// Create a domain separation error
    pub fn domain_separation_error(operation: &str, domain: &str, details: &str) -> Self {
        Self::DomainSeparationError {
            operation: operation.to_string(),
            domain: domain.to_string(),
            details: details.to_string(),
        }
    }

    /// Create an invalid domain label error
    pub fn invalid_domain_label(operation: &str, label: &str, valid_labels: Vec<String>) -> Self {
        Self::InvalidDomainLabel {
            operation: operation.to_string(),
            label: label.to_string(),
            valid_labels,
        }
    }

    // === Recovery Error Convenience Methods ===

    /// Create a wallet recovery failed error
    pub fn wallet_recovery_failed(stage: &str, details: &str, suggestion: &str) -> Self {
        Self::WalletRecoveryFailed {
            stage: stage.to_string(),
            details: details.to_string(),
            suggestion: suggestion.to_string(),
        }
    }

    /// Create a partial recovery completed error
    pub fn partial_recovery_completed(
        recovered_items: usize,
        failed_items: usize,
        details: &str,
    ) -> Self {
        Self::PartialRecoveryCompleted {
            recovered_items,
            failed_items,
            details: details.to_string(),
        }
    }

    // === Helper Methods for Error Analysis ===

    /// Check if this is a recoverable error (user can potentially fix)
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::UnknownWord { .. }
                | Self::InvalidWordCount { .. }
                | Self::InvalidSeedChecksum
                | Self::EmptySeedPhrase
                | Self::MissingRequiredPassphrase
                | Self::InvalidPassphrase
                | Self::InvalidSeedPhraseFormat { .. }
                | Self::SeedValidationFailed { .. }
        )
    }

    /// Check if this is a critical error (requires immediate attention)
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::MasterKeyDerivationFailed { .. }
                | Self::KeyValidationFailed { .. }
                | Self::CipherSeedMacVerificationFailed
                | Self::CipherSeedEntropyError { .. }
                | Self::DomainSeparationError { .. }
        )
    }

    /// Get suggested recovery action for this error
    pub fn recovery_suggestion(&self) -> Option<String> {
        match self {
            Self::UnknownWord { position, .. } => Some(format!(
                "Check word {} for typos. Verify it's in the BIP39 word list.",
                position + 1
            )),
            Self::InvalidWordCount { expected, .. } => Some(format!(
                "Ensure your seed phrase has exactly {expected} words separated by spaces."
            )),
            Self::InvalidSeedChecksum => {
                Some("Verify all words are spelled correctly and in the right order.".to_string())
            }
            Self::EmptySeedPhrase => {
                Some("Provide a valid seed phrase with 12 or 24 words.".to_string())
            }
            Self::MissingRequiredPassphrase => Some(
                "This wallet was created with a passphrase. Please provide the correct passphrase."
                    .to_string(),
            ),
            Self::InvalidPassphrase => {
                Some("Check that the passphrase is correct and try again.".to_string())
            }
            Self::InvalidSeedPhraseFormat { suggestion, .. } => Some(suggestion.clone()),
            Self::SeedValidationFailed { suggestion, .. } => Some(suggestion.clone()),
            _ => None,
        }
    }

    /// Get the error category for this error
    pub fn category(&self) -> &'static str {
        match self {
            Self::UnknownWord { .. }
            | Self::InvalidWordCount { .. }
            | Self::InvalidSeedChecksum
            | Self::EmptySeedPhrase
            | Self::InvalidSeedPhraseFormat { .. }
            | Self::SeedValidationFailed { .. }
            | Self::SeedEncodingError { .. }
            | Self::SeedDecodingError { .. } => "seed_phrase",

            Self::MasterKeyDerivationFailed { .. }
            | Self::BranchKeyDerivationFailed { .. }
            | Self::ViewKeyDerivationFailed { .. }
            | Self::SpendKeyDerivationFailed { .. }
            | Self::InvalidDerivationIndex { .. }
            | Self::DerivationPathTooDeep { .. }
            | Self::HierarchicalDerivationFailed { .. } => "key_derivation",

            Self::UnsupportedCipherSeedVersion { .. }
            | Self::CipherSeedEncryptionFailed { .. }
            | Self::CipherSeedDecryptionFailed { .. }
            | Self::InvalidCipherSeedFormat { .. }
            | Self::CipherSeedMacVerificationFailed
            | Self::InvalidCipherSeedBirthday { .. }
            | Self::CipherSeedEntropyError { .. } => "cipher_seed",

            Self::MissingRequiredPassphrase
            | Self::InvalidPassphrase
            | Self::PassphraseValidationFailed { .. } => "passphrase",

            Self::KeyValidationFailed { .. }
            | Self::KeyFormatError { .. }
            | Self::KeyLengthError { .. } => "key_validation",

            Self::DomainSeparationError { .. } | Self::InvalidDomainLabel { .. } => {
                "domain_separation"
            }

            Self::WalletRecoveryFailed { .. } | Self::PartialRecoveryCompleted { .. } => "recovery",

            _ => "general",
        }
    }
}

impl ScanningError {
    /// Create a blockchain connection failed error
    pub fn blockchain_connection_failed(details: &str) -> Self {
        Self::BlockchainConnectionFailed(details.to_string())
    }

    /// Create a block not found error
    pub fn block_not_found(block_id: &str) -> Self {
        Self::BlockNotFound(block_id.to_string())
    }

    /// Create a scan timeout error
    pub fn scan_timeout(operation: &str) -> Self {
        Self::ScanTimeout(operation.to_string())
    }
}

impl EncryptionError {
    /// Create an encryption failed error
    pub fn encryption_failed(details: &str) -> Self {
        Self::EncryptionFailed(details.to_string())
    }

    /// Create a decryption failed error
    pub fn decryption_failed(details: &str) -> Self {
        Self::DecryptionFailed(details.to_string())
    }

    /// Create an authentication failed error
    pub fn authentication_failed(details: &str) -> Self {
        Self::AuthenticationFailed(details.to_string())
    }
}

/// Result type for lightweight wallet operations
pub type WalletResult<T> = Result<T, WalletError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lightweight_wallet_error_display() {
        let error = WalletError::ConversionError("test error".to_string());
        assert_eq!(error.to_string(), "Conversion error: test error");
    }

    #[test]
    fn test_lightweight_wallet_error_from_string() {
        let error = WalletError::from("test error");
        assert_eq!(error.to_string(), "Internal error: test error");
    }

    #[test]
    fn test_lightweight_wallet_error_from_str() {
        let error = WalletError::from("test error");
        assert_eq!(error.to_string(), "Internal error: test error");
    }

    #[test]
    fn test_data_structure_error_convenience_constructors() {
        let error = DataStructureError::invalid_output_version("v2");
        assert_eq!(error.to_string(), "Invalid output version: v2");

        let error = DataStructureError::invalid_output_value("negative");
        assert_eq!(error.to_string(), "Invalid output value: negative");

        let error = DataStructureError::data_too_large(100, 200);
        assert_eq!(
            error.to_string(),
            "Data too large: expected max 100, got 200"
        );

        let error = DataStructureError::data_too_small(50, 10);
        assert_eq!(error.to_string(), "Data too small: expected min 50, got 10");

        let error = DataStructureError::missing_field("commitment");
        assert_eq!(error.to_string(), "Missing required field: commitment");

        let error = DataStructureError::invalid_address("invalid_addr");
        assert_eq!(error.to_string(), "Invalid address: invalid_addr");
    }

    #[test]
    fn test_serialization_error_convenience_constructors() {
        let error = SerializationError::hex_encoding_error("invalid hex");
        assert_eq!(error.to_string(), "Hex encoding error: invalid hex");

        let error = SerializationError::hex_decoding_error("not hex");
        assert_eq!(error.to_string(), "Hex decoding error: not hex");

        let error = SerializationError::serde_serialization_error("failed");
        assert_eq!(error.to_string(), "Serde serialization error: failed");

        let error = SerializationError::serde_deserialization_error("failed");
        assert_eq!(error.to_string(), "Serde deserialization error: failed");
    }

    #[test]
    fn test_validation_error_convenience_constructors() {
        let error = ValidationError::range_proof_validation_failed("invalid proof");
        assert_eq!(
            error.to_string(),
            "Range proof validation failed: invalid proof"
        );

        let error = ValidationError::signature_validation_failed("bad signature");
        assert_eq!(
            error.to_string(),
            "Signature validation failed: bad signature"
        );

        let error = ValidationError::metadata_signature_validation_failed("meta failed");
        assert_eq!(
            error.to_string(),
            "Metadata signature validation failed: meta failed"
        );

        let error = ValidationError::script_signature_validation_failed("script failed");
        assert_eq!(
            error.to_string(),
            "Script signature validation failed: script failed"
        );

        let error = ValidationError::commitment_validation_failed("commitment failed");
        assert_eq!(
            error.to_string(),
            "Commitment validation failed: commitment failed"
        );

        let error = ValidationError::minimum_value_promise_validation_failed("mvp failed");
        assert_eq!(
            error.to_string(),
            "Minimum value promise validation failed: mvp failed"
        );
    }

    #[test]
    fn test_key_management_error_basic_constructors() {
        let error = KeyManagementError::key_not_found("key123");
        assert_eq!(error.to_string(), "Key not found: key123");

        let error = KeyManagementError::key_derivation_failed("path invalid");
        assert_eq!(error.to_string(), "Key derivation failed: path invalid");

        let error = KeyManagementError::stealth_address_recovery_failed("recovery error");
        assert_eq!(
            error.to_string(),
            "Stealth address recovery failed: recovery error"
        );
    }

    #[test]
    fn test_seed_phrase_error_constructors() {
        let error = KeyManagementError::invalid_seed_phrase_format("bad format", "use 12 words");
        assert_eq!(
            error.to_string(),
            "Invalid seed phrase format: bad format. Suggestion: use 12 words"
        );

        let error = KeyManagementError::invalid_word_count(12, 10);
        assert_eq!(error.to_string(), "Invalid word count: expected 12 words, got 10 words. Please check your seed phrase has exactly 12 words.");

        let error = KeyManagementError::unknown_word("wrongword", 5);
        assert_eq!(error.to_string(), "Unknown word 'wrongword' at position 5. This word is not in the BIP39 word list. Please check for typos.");

        let error = KeyManagementError::invalid_seed_checksum();
        assert_eq!(error.to_string(), "Invalid seed phrase checksum. The seed phrase appears to be corrupted or mistyped. Please verify all words are correct.");

        let error = KeyManagementError::empty_seed_phrase();
        assert_eq!(
            error.to_string(),
            "Empty seed phrase provided. Please provide a valid seed phrase."
        );

        let error = KeyManagementError::seed_validation_failed("checksum", "verify words");
        assert_eq!(
            error.to_string(),
            "Seed phrase validation failed: checksum. Suggestion: verify words"
        );

        let error = KeyManagementError::seed_encoding_error("utf8 error");
        assert_eq!(error.to_string(), "Seed phrase encoding error: utf8 error. The seed phrase could not be converted to the expected format.");

        let error = KeyManagementError::seed_decoding_error("invalid bytes");
        assert_eq!(error.to_string(), "Seed phrase decoding error: invalid bytes. The provided data could not be converted to a valid seed phrase.");
    }

    #[test]
    fn test_derivation_error_constructors() {
        let error = KeyManagementError::master_key_derivation_failed("bad seed");
        assert_eq!(error.to_string(), "Master key derivation failed: bad seed. Check that the seed phrase and passphrase are correct.");

        let error = KeyManagementError::branch_key_derivation_failed("spend", 123, "overflow");
        assert_eq!(
            error.to_string(),
            "Branch key derivation failed for branch 'spend' at index 123: overflow"
        );

        let error = KeyManagementError::view_key_derivation_failed("crypto error");
        assert_eq!(error.to_string(), "View key derivation failed: crypto error. This may indicate an issue with the master key or derivation parameters.");

        let error = KeyManagementError::spend_key_derivation_failed("invalid params");
        assert_eq!(error.to_string(), "Spend key derivation failed: invalid params. This may indicate an issue with the master key or derivation parameters.");

        let error = KeyManagementError::invalid_derivation_index("view", 9999999);
        assert_eq!(
            error.to_string(),
            "Invalid derivation index 9999999 for branch 'view'. Index must be within valid range."
        );

        let error = KeyManagementError::derivation_path_too_deep(10, 5);
        assert_eq!(
            error.to_string(),
            "Derivation path too deep: 10 levels. Maximum supported depth is 5."
        );

        let error = KeyManagementError::hierarchical_derivation_failed(3, "invalid key");
        assert_eq!(
            error.to_string(),
            "Hierarchical derivation failed at level 3: invalid key"
        );
    }

    #[test]
    fn test_cipher_seed_error_constructors() {
        let error = KeyManagementError::unsupported_cipher_seed_version(2, vec![0, 1]);
        assert_eq!(
            error.to_string(),
            "CipherSeed version 2 is not supported. Supported versions: [0, 1]"
        );

        let error = KeyManagementError::cipher_seed_encryption_failed("aes error");
        assert_eq!(
            error.to_string(),
            "CipherSeed encryption failed: aes error. Please check the passphrase and try again."
        );

        let error = KeyManagementError::cipher_seed_decryption_failed("wrong key");
        assert_eq!(
            error.to_string(),
            "CipherSeed decryption failed: wrong key. Please verify the passphrase is correct."
        );

        let error = KeyManagementError::invalid_cipher_seed_format("bad header");
        assert_eq!(error.to_string(), "Invalid CipherSeed format: bad header. The data does not match the expected CipherSeed structure.");

        let error = KeyManagementError::cipher_seed_mac_verification_failed();
        assert_eq!(error.to_string(), "CipherSeed MAC verification failed. The seed data may be corrupted or the wrong passphrase was used.");

        let error = KeyManagementError::invalid_cipher_seed_birthday(65535);
        assert_eq!(
            error.to_string(),
            "Invalid CipherSeed birthday 65535. Birthday must be within valid range."
        );

        let error = KeyManagementError::cipher_seed_entropy_error("not random");
        assert_eq!(
            error.to_string(),
            "CipherSeed entropy error: not random. The entropy data is invalid or corrupted."
        );
    }

    #[test]
    fn test_passphrase_error_constructors() {
        let error = KeyManagementError::missing_required_passphrase();
        assert_eq!(error.to_string(), "Missing required passphrase. This seed phrase was created with a passphrase and requires one for decryption.");

        let error = KeyManagementError::invalid_passphrase();
        assert_eq!(
            error.to_string(),
            "Invalid passphrase provided. Please check that the passphrase is correct."
        );

        let error = KeyManagementError::passphrase_validation_failed("too short");
        assert_eq!(error.to_string(), "Passphrase validation failed: too short");
    }

    #[test]
    fn test_key_validation_error_constructors() {
        let error = KeyManagementError::key_validation_failed("private", "invalid curve point");
        assert_eq!(
            error.to_string(),
            "Key validation failed: private key failed validation. Reason: invalid curve point"
        );

        let error = KeyManagementError::key_format_error("public", "hex", "base64");
        assert_eq!(
            error.to_string(),
            "Key format error: public key has invalid format. Expected: hex, got: base64"
        );

        let error = KeyManagementError::key_length_error("shared", 32, 16);
        assert_eq!(
            error.to_string(),
            "Key length error: shared key has invalid length. Expected: 32 bytes, got: 16 bytes"
        );
    }

    #[test]
    fn test_domain_separation_error_constructors() {
        let error = KeyManagementError::domain_separation_error("hash", "wallet", "invalid label");
        assert_eq!(
            error.to_string(),
            "Domain separation error: hash failed with domain 'wallet'. invalid label"
        );

        let error = KeyManagementError::invalid_domain_label(
            "sign",
            "wrong",
            vec!["key".to_string(), "msg".to_string()],
        );
        assert_eq!(error.to_string(), "Invalid domain label 'wrong' for operation 'sign'. Expected one of: [\"key\", \"msg\"]");
    }

    #[test]
    fn test_recovery_error_constructors() {
        let error =
            KeyManagementError::wallet_recovery_failed("scanning", "no utxos", "check blocks");
        assert_eq!(
            error.to_string(),
            "Wallet recovery failed: scanning. no utxos. Suggestion: check blocks"
        );

        let error = KeyManagementError::partial_recovery_completed(5, 2, "some errors");
        assert_eq!(
            error.to_string(),
            "Partial recovery completed: 5 items recovered, 2 items failed. some errors"
        );
    }

    #[test]
    fn test_key_management_error_helper_methods() {
        // Test recoverable errors
        assert!(KeyManagementError::unknown_word("bad", 1).is_recoverable());
        assert!(KeyManagementError::invalid_word_count(12, 10).is_recoverable());
        assert!(KeyManagementError::invalid_seed_checksum().is_recoverable());
        assert!(KeyManagementError::empty_seed_phrase().is_recoverable());
        assert!(KeyManagementError::missing_required_passphrase().is_recoverable());
        assert!(KeyManagementError::invalid_passphrase().is_recoverable());

        // Test non-recoverable errors
        assert!(!KeyManagementError::CrcError.is_recoverable());
        assert!(!KeyManagementError::VersionMismatch.is_recoverable());

        // Test critical errors
        assert!(KeyManagementError::master_key_derivation_failed("test").is_critical());
        assert!(KeyManagementError::key_validation_failed("test", "test").is_critical());
        assert!(KeyManagementError::cipher_seed_mac_verification_failed().is_critical());
        assert!(KeyManagementError::cipher_seed_entropy_error("test").is_critical());
        assert!(KeyManagementError::domain_separation_error("test", "test", "test").is_critical());

        // Test non-critical errors
        assert!(!KeyManagementError::unknown_word("bad", 1).is_critical());
        assert!(!KeyManagementError::missing_required_passphrase().is_critical());
    }

    #[test]
    fn test_error_conversions() {
        // Test hex error conversion
        let hex_error = hex::FromHexError::InvalidHexCharacter { c: 'z', index: 0 };
        let serialization_error = SerializationError::from(hex_error);
        assert!(serialization_error
            .to_string()
            .contains("Hex decoding error"));

        // Test io error conversion
        let io_error = std::io::Error::new(std::io::ErrorKind::WriteZero, "test");
        let serialization_error = SerializationError::from(io_error);
        assert!(serialization_error.to_string().contains("Buffer overflow"));
    }

    #[test]
    fn test_wasm_error_conversion() {
        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen::JsValue;

            let js_error = JsValue::from_str("JavaScript error");
            let wallet_error = WalletError::from(js_error);
            assert!(wallet_error.to_string().contains("WASM error"));
        }
    }

    #[test]
    fn test_error_hierarchy() {
        // Test that sub-errors convert to main error
        let data_error = DataStructureError::InvalidAddress("test".to_string());
        let wallet_error = WalletError::from(data_error);
        assert!(wallet_error.to_string().contains("Data structure error"));

        let validation_error = ValidationError::RangeProofValidationFailed("test".to_string());
        let wallet_error = WalletError::from(validation_error);
        assert!(wallet_error.to_string().contains("Validation error"));

        let key_error = KeyManagementError::KeyNotFound("test".to_string());
        let wallet_error = WalletError::from(key_error);
        assert!(wallet_error.to_string().contains("Key management error"));
    }
}
