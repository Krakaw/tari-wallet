use semver::Version;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tari_common_types::{tari_address::TariAddress, transaction::TxId, types::FixedHash};
use tari_transaction_components::{
    tari_amount::MicroMinotari,
    transaction_components::{memo_field::MemoField, OutputFeatures, Transaction, WalletOutput},
};

use crate::{
    models::{marshal_output_pair::MarshalOutputPair, transaction_metadata::TransactionMetadata},
    SerializationError, WalletError,
};

const SUPPORTED_VERSION: &str = "1.0.0";

pub fn get_supported_version() -> Version {
    Version::parse(SUPPORTED_VERSION).unwrap()
}

pub trait HasVersion {
    fn get_version(&self) -> &Version;
}

pub trait TransactionResult: HasVersion + Serialize + DeserializeOwned + Sized {
    fn from_json(s: &str) -> Result<Self, WalletError> {
        let value: serde_json::Value = serde_json::from_str(s)
            .map_err(|e| SerializationError::JsonDeserializationError(e.to_string()))?;
        let version = value.get("version").ok_or_else(|| {
            SerializationError::JsonDeserializationError("Missing version".into())
        })?;
        let version: Version = serde_json::from_value(version.clone())
            .map_err(|e| SerializationError::JsonDeserializationError(e.to_string()))?;
        if version != get_supported_version() {
            return Err(SerializationError::JsonDeserializationError(format!(
                "Unsupported version. Expected '{}', got '{}'",
                get_supported_version(),
                version
            ))
            .into());
        }

        let deserialized_obj: Self = serde_json::from_str(s)
            .map_err(|e| SerializationError::JsonDeserializationError(e.to_string()))?;

        Ok(deserialized_obj)
    }

    fn to_json(&self) -> Result<String, WalletError> {
        serde_json::to_string(&self)
            .map_err(|e| SerializationError::JsonSerializationError(e.to_string()).into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PaymentRecipient {
    pub amount: MicroMinotari,
    pub output_features: OutputFeatures,
    pub address: TariAddress,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OneSidedTransactionInfo {
    /// Payment ID
    pub payment_id: MemoField,
    /// Recipient
    pub recipient: PaymentRecipient,
    /// The change output details. This may be None if no change is required.
    pub change_output: Option<MarshalOutputPair>,
    /// All transaction inputs inputs.
    pub inputs: Vec<MarshalOutputPair>,
    /// The recipient's outputs.
    pub outputs: Vec<MarshalOutputPair>,
    /// Details used to construct the transaction kernel.
    pub metadata: TransactionMetadata,
    /// Sender address
    pub sender_address: TariAddress,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PrepareOneSidedTransactionForSigningResult {
    pub version: Version,
    pub tx_id: TxId,
    pub info: OneSidedTransactionInfo,
}

impl TransactionResult for PrepareOneSidedTransactionForSigningResult {}

impl HasVersion for PrepareOneSidedTransactionForSigningResult {
    fn get_version(&self) -> &Version {
        &self.version
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub sent_hashes: Vec<FixedHash>,
    pub change_hashes: Vec<FixedHash>,
    pub change_output: Option<WalletOutput>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SignedOneSidedTransactionResult {
    pub version: Version,
    pub request: PrepareOneSidedTransactionForSigningResult,
    pub signed_transaction: SignedTransaction,
}

impl TransactionResult for SignedOneSidedTransactionResult {}

impl HasVersion for SignedOneSidedTransactionResult {
    fn get_version(&self) -> &Version {
        &self.version
    }
}
