//! Transaction metadata types for wallets
//!
//! This module contains transaction status, direction, and import status types
//! used for tracking transaction states and metadata in wallets.

use std::{
    convert::TryFrom,
    fmt,
    fmt::{Display, Error, Formatter},
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Unique identifier for a transaction as a u64 integer
pub type TxId = u64;

#[derive(
    Default,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[borsh(use_discriminant = true)]
pub enum TransactionStatus {
    /// This transaction has been completed between the parties but has not been broadcast to the base layer network.
    Completed = 0,
    /// This transaction has been broadcast to the base layer network and is currently in one or more base node
    /// mempools.
    Broadcast = 1,
    /// This transaction has been mined and included in a block.
    MinedUnconfirmed = 2,
    /// This transaction was generated as part of importing a spendable unblinded UTXO
    Imported = 3,
    /// This transaction is still being negotiated by the parties
    #[default]
    Pending = 4,
    /// This is a created Coinbase Transaction
    Coinbase = 5,
    /// This transaction is mined and confirmed at the current base node's height
    MinedConfirmed = 6,
    /// This transaction was Rejected by the mempool
    Rejected = 7,
    /// This transaction import status is used when a one-sided transaction has been scanned but is unconfirmed
    OneSidedUnconfirmed = 8,
    /// This transaction import status is used when a one-sided transaction has been scanned and confirmed
    OneSidedConfirmed = 9,
    /// This transaction is still being queued for initial sending
    Queued = 10,
    /// This transaction import status is used when a coinbase transaction has been scanned but is unconfirmed
    CoinbaseUnconfirmed = 11,
    /// This transaction import status is used when a coinbase transaction has been scanned and confirmed
    CoinbaseConfirmed = 12,
    /// This transaction import status is used when a coinbase transaction has been scanned but the outputs are not
    /// currently confirmed on the blockchain via the output manager
    CoinbaseNotInBlockChain = 13,
}

impl TransactionStatus {
    pub fn is_imported_from_chain(&self) -> bool {
        matches!(
            self,
            TransactionStatus::Imported
                | TransactionStatus::OneSidedUnconfirmed
                | TransactionStatus::OneSidedConfirmed
        )
    }

    pub fn is_coinbase(&self) -> bool {
        matches!(
            self,
            TransactionStatus::CoinbaseUnconfirmed
                | TransactionStatus::CoinbaseConfirmed
                | TransactionStatus::CoinbaseNotInBlockChain
        )
    }

    pub fn is_confirmed(&self) -> bool {
        matches!(
            self,
            TransactionStatus::OneSidedConfirmed
                | TransactionStatus::CoinbaseConfirmed
                | TransactionStatus::MinedConfirmed
        )
    }

    pub fn mined_confirm(&self) -> Self {
        match self {
            TransactionStatus::Completed
            | TransactionStatus::Broadcast
            | TransactionStatus::Pending
            | TransactionStatus::Coinbase
            | TransactionStatus::Rejected
            | TransactionStatus::Queued
            | TransactionStatus::MinedUnconfirmed
            | TransactionStatus::MinedConfirmed => TransactionStatus::MinedConfirmed,
            TransactionStatus::Imported
            | TransactionStatus::OneSidedUnconfirmed
            | TransactionStatus::OneSidedConfirmed => TransactionStatus::OneSidedConfirmed,
            TransactionStatus::CoinbaseNotInBlockChain
            | TransactionStatus::CoinbaseConfirmed
            | TransactionStatus::CoinbaseUnconfirmed => TransactionStatus::CoinbaseConfirmed,
        }
    }

    pub fn mined_unconfirm(&self) -> Self {
        match self {
            TransactionStatus::Completed
            | TransactionStatus::Broadcast
            | TransactionStatus::Pending
            | TransactionStatus::Coinbase
            | TransactionStatus::Rejected
            | TransactionStatus::Queued
            | TransactionStatus::MinedUnconfirmed
            | TransactionStatus::MinedConfirmed => TransactionStatus::MinedUnconfirmed,
            TransactionStatus::Imported
            | TransactionStatus::OneSidedUnconfirmed
            | TransactionStatus::OneSidedConfirmed => TransactionStatus::OneSidedUnconfirmed,
            TransactionStatus::CoinbaseConfirmed
            | TransactionStatus::CoinbaseUnconfirmed
            | TransactionStatus::CoinbaseNotInBlockChain => TransactionStatus::CoinbaseUnconfirmed,
        }
    }
}

#[derive(Debug, Error)]
#[error("Invalid TransactionStatus: {code}")]
pub struct TransactionConversionError {
    pub code: i32,
}

impl TryFrom<i32> for TransactionStatus {
    type Error = TransactionConversionError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TransactionStatus::Completed),
            1 => Ok(TransactionStatus::Broadcast),
            2 => Ok(TransactionStatus::MinedUnconfirmed),
            3 => Ok(TransactionStatus::Imported),
            4 => Ok(TransactionStatus::Pending),
            5 => Ok(TransactionStatus::Coinbase),
            6 => Ok(TransactionStatus::MinedConfirmed),
            7 => Ok(TransactionStatus::Rejected),
            8 => Ok(TransactionStatus::OneSidedUnconfirmed),
            9 => Ok(TransactionStatus::OneSidedConfirmed),
            10 => Ok(TransactionStatus::Queued),
            11 => Ok(TransactionStatus::CoinbaseUnconfirmed),
            12 => Ok(TransactionStatus::CoinbaseConfirmed),
            13 => Ok(TransactionStatus::CoinbaseNotInBlockChain),
            code => Err(TransactionConversionError { code }),
        }
    }
}

impl Display for TransactionStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        // No struct or tuple variants
        match self {
            TransactionStatus::Completed => write!(f, "Completed"),
            TransactionStatus::Broadcast => write!(f, "Broadcast"),
            TransactionStatus::MinedUnconfirmed => write!(f, "Mined Unconfirmed"),
            TransactionStatus::MinedConfirmed => write!(f, "Mined Confirmed"),
            TransactionStatus::Imported => write!(f, "Imported"),
            TransactionStatus::Pending => write!(f, "Pending"),
            TransactionStatus::Coinbase => write!(f, "Coinbase"),
            TransactionStatus::Rejected => write!(f, "Rejected"),
            TransactionStatus::OneSidedUnconfirmed => write!(f, "One-Sided Unconfirmed"),
            TransactionStatus::OneSidedConfirmed => write!(f, "One-Sided Confirmed"),
            TransactionStatus::CoinbaseUnconfirmed => write!(f, "Coinbase Unconfirmed"),
            TransactionStatus::CoinbaseConfirmed => write!(f, "Coinbase Confirmed"),
            TransactionStatus::CoinbaseNotInBlockChain => write!(f, "Coinbase not mined"),
            TransactionStatus::Queued => write!(f, "Queued"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum ImportStatus {
    /// Special case where we import a tx received from broadcast
    Broadcast,
    /// This transaction import status is used when importing a spendable UTXO
    Imported,
    /// This transaction import status is used when a one-sided transaction has been scanned but is unconfirmed
    OneSidedUnconfirmed,
    /// This transaction import status is used when a one-sided transaction has been scanned and confirmed
    OneSidedConfirmed,
    /// This transaction import status is used when a coinbase transaction has been scanned but is unconfirmed
    CoinbaseUnconfirmed,
    /// This transaction import status is used when a coinbase transaction has been scanned and confirmed
    CoinbaseConfirmed,
}

impl TryFrom<ImportStatus> for TransactionStatus {
    type Error = TransactionConversionError;

    fn try_from(value: ImportStatus) -> Result<Self, Self::Error> {
        match value {
            ImportStatus::Broadcast => Ok(TransactionStatus::Broadcast),
            ImportStatus::Imported => Ok(TransactionStatus::Imported),
            ImportStatus::OneSidedUnconfirmed => Ok(TransactionStatus::OneSidedUnconfirmed),
            ImportStatus::OneSidedConfirmed => Ok(TransactionStatus::OneSidedConfirmed),
            ImportStatus::CoinbaseUnconfirmed => Ok(TransactionStatus::CoinbaseUnconfirmed),
            ImportStatus::CoinbaseConfirmed => Ok(TransactionStatus::CoinbaseConfirmed),
        }
    }
}

impl TryFrom<TransactionStatus> for ImportStatus {
    type Error = TransactionConversionError;

    fn try_from(value: TransactionStatus) -> Result<Self, Self::Error> {
        match value {
            TransactionStatus::Broadcast => Ok(ImportStatus::Broadcast),
            TransactionStatus::Imported => Ok(ImportStatus::Imported),
            TransactionStatus::OneSidedUnconfirmed => Ok(ImportStatus::OneSidedUnconfirmed),
            TransactionStatus::OneSidedConfirmed => Ok(ImportStatus::OneSidedConfirmed),
            TransactionStatus::CoinbaseUnconfirmed => Ok(ImportStatus::CoinbaseUnconfirmed),
            TransactionStatus::CoinbaseConfirmed => Ok(ImportStatus::CoinbaseConfirmed),
            _ => Err(TransactionConversionError { code: i32::MAX }),
        }
    }
}

impl fmt::Display for ImportStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            ImportStatus::Broadcast => write!(f, "Broadcast"),
            ImportStatus::Imported => write!(f, "Imported"),
            ImportStatus::OneSidedUnconfirmed => write!(f, "OneSidedUnconfirmed"),
            ImportStatus::OneSidedConfirmed => write!(f, "OneSidedConfirmed"),
            ImportStatus::CoinbaseUnconfirmed => write!(f, "CoinbaseUnconfirmed"),
            ImportStatus::CoinbaseConfirmed => write!(f, "CoinbaseConfirmed"),
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Default,
)]
pub enum TransactionDirection {
    Inbound,
    Outbound,
    #[default]
    Unknown,
}

#[derive(Debug, Error)]
#[error("Invalid TransactionDirection: {code}")]
pub struct TransactionDirectionError {
    pub code: i32,
}

impl TryFrom<i32> for TransactionDirection {
    type Error = TransactionDirectionError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TransactionDirection::Inbound),
            1 => Ok(TransactionDirection::Outbound),
            2 => Ok(TransactionDirection::Unknown),
            code => Err(TransactionDirectionError { code }),
        }
    }
}

impl Display for TransactionDirection {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        // No struct or tuple variants
        match self {
            TransactionDirection::Inbound => write!(f, "Inbound"),
            TransactionDirection::Outbound => write!(f, "Outbound"),
            TransactionDirection::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn test_transaction_status_conversion() {
        // Test valid conversions
        assert_eq!(
            TransactionStatus::try_from(0).unwrap(),
            TransactionStatus::Completed
        );
        assert_eq!(
            TransactionStatus::try_from(1).unwrap(),
            TransactionStatus::Broadcast
        );
        assert_eq!(
            TransactionStatus::try_from(2).unwrap(),
            TransactionStatus::MinedUnconfirmed
        );
        assert_eq!(
            TransactionStatus::try_from(3).unwrap(),
            TransactionStatus::Imported
        );
        assert_eq!(
            TransactionStatus::try_from(4).unwrap(),
            TransactionStatus::Pending
        );
        assert_eq!(
            TransactionStatus::try_from(5).unwrap(),
            TransactionStatus::Coinbase
        );
        assert_eq!(
            TransactionStatus::try_from(6).unwrap(),
            TransactionStatus::MinedConfirmed
        );
        assert_eq!(
            TransactionStatus::try_from(7).unwrap(),
            TransactionStatus::Rejected
        );
        assert_eq!(
            TransactionStatus::try_from(8).unwrap(),
            TransactionStatus::OneSidedUnconfirmed
        );
        assert_eq!(
            TransactionStatus::try_from(9).unwrap(),
            TransactionStatus::OneSidedConfirmed
        );
        assert_eq!(
            TransactionStatus::try_from(10).unwrap(),
            TransactionStatus::Queued
        );
        assert_eq!(
            TransactionStatus::try_from(11).unwrap(),
            TransactionStatus::CoinbaseUnconfirmed
        );
        assert_eq!(
            TransactionStatus::try_from(12).unwrap(),
            TransactionStatus::CoinbaseConfirmed
        );
        assert_eq!(
            TransactionStatus::try_from(13).unwrap(),
            TransactionStatus::CoinbaseNotInBlockChain
        );

        // Test invalid conversion
        assert!(TransactionStatus::try_from(99).is_err());
    }

    #[test]
    fn test_transaction_direction_conversion() {
        // Test valid conversions
        assert_eq!(
            TransactionDirection::try_from(0).unwrap(),
            TransactionDirection::Inbound
        );
        assert_eq!(
            TransactionDirection::try_from(1).unwrap(),
            TransactionDirection::Outbound
        );
        assert_eq!(
            TransactionDirection::try_from(2).unwrap(),
            TransactionDirection::Unknown
        );

        // Test invalid conversion
        assert!(TransactionDirection::try_from(99).is_err());
    }

    #[test]
    fn test_transaction_status_display() {
        assert_eq!(TransactionStatus::Completed.to_string(), "Completed");
        assert_eq!(TransactionStatus::Broadcast.to_string(), "Broadcast");
        assert_eq!(
            TransactionStatus::MinedUnconfirmed.to_string(),
            "Mined Unconfirmed"
        );
        assert_eq!(
            TransactionStatus::MinedConfirmed.to_string(),
            "Mined Confirmed"
        );
        assert_eq!(TransactionStatus::Imported.to_string(), "Imported");
        assert_eq!(TransactionStatus::Pending.to_string(), "Pending");
        assert_eq!(TransactionStatus::Coinbase.to_string(), "Coinbase");
        assert_eq!(TransactionStatus::Rejected.to_string(), "Rejected");
        assert_eq!(
            TransactionStatus::OneSidedUnconfirmed.to_string(),
            "One-Sided Unconfirmed"
        );
        assert_eq!(
            TransactionStatus::OneSidedConfirmed.to_string(),
            "One-Sided Confirmed"
        );
        assert_eq!(
            TransactionStatus::CoinbaseUnconfirmed.to_string(),
            "Coinbase Unconfirmed"
        );
        assert_eq!(
            TransactionStatus::CoinbaseConfirmed.to_string(),
            "Coinbase Confirmed"
        );
        assert_eq!(
            TransactionStatus::CoinbaseNotInBlockChain.to_string(),
            "Coinbase not mined"
        );
        assert_eq!(TransactionStatus::Queued.to_string(), "Queued");
    }

    #[test]
    fn test_transaction_direction_display() {
        assert_eq!(TransactionDirection::Inbound.to_string(), "Inbound");
        assert_eq!(TransactionDirection::Outbound.to_string(), "Outbound");
        assert_eq!(TransactionDirection::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_import_status_display() {
        assert_eq!(ImportStatus::Broadcast.to_string(), "Broadcast");
        assert_eq!(ImportStatus::Imported.to_string(), "Imported");
        assert_eq!(
            ImportStatus::OneSidedUnconfirmed.to_string(),
            "OneSidedUnconfirmed"
        );
        assert_eq!(
            ImportStatus::OneSidedConfirmed.to_string(),
            "OneSidedConfirmed"
        );
        assert_eq!(
            ImportStatus::CoinbaseUnconfirmed.to_string(),
            "CoinbaseUnconfirmed"
        );
        assert_eq!(
            ImportStatus::CoinbaseConfirmed.to_string(),
            "CoinbaseConfirmed"
        );
    }

    #[test]
    fn test_transaction_status_methods() {
        // Test is_imported_from_chain
        assert!(TransactionStatus::Imported.is_imported_from_chain());
        assert!(TransactionStatus::OneSidedUnconfirmed.is_imported_from_chain());
        assert!(TransactionStatus::OneSidedConfirmed.is_imported_from_chain());
        assert!(!TransactionStatus::Pending.is_imported_from_chain());

        // Test is_coinbase
        assert!(TransactionStatus::CoinbaseUnconfirmed.is_coinbase());
        assert!(TransactionStatus::CoinbaseConfirmed.is_coinbase());
        assert!(TransactionStatus::CoinbaseNotInBlockChain.is_coinbase());
        assert!(!TransactionStatus::Pending.is_coinbase());

        // Test is_confirmed
        assert!(TransactionStatus::OneSidedConfirmed.is_confirmed());
        assert!(TransactionStatus::CoinbaseConfirmed.is_confirmed());
        assert!(TransactionStatus::MinedConfirmed.is_confirmed());
        assert!(!TransactionStatus::MinedUnconfirmed.is_confirmed());
    }

    #[test]
    fn test_transaction_status_state_transitions() {
        // Test mined_confirm
        assert_eq!(
            TransactionStatus::MinedUnconfirmed.mined_confirm(),
            TransactionStatus::MinedConfirmed
        );
        assert_eq!(
            TransactionStatus::OneSidedUnconfirmed.mined_confirm(),
            TransactionStatus::OneSidedConfirmed
        );
        assert_eq!(
            TransactionStatus::CoinbaseUnconfirmed.mined_confirm(),
            TransactionStatus::CoinbaseConfirmed
        );

        // Test mined_unconfirm
        assert_eq!(
            TransactionStatus::MinedConfirmed.mined_unconfirm(),
            TransactionStatus::MinedUnconfirmed
        );
        assert_eq!(
            TransactionStatus::OneSidedConfirmed.mined_unconfirm(),
            TransactionStatus::OneSidedUnconfirmed
        );
        assert_eq!(
            TransactionStatus::CoinbaseConfirmed.mined_unconfirm(),
            TransactionStatus::CoinbaseUnconfirmed
        );
    }

    #[test]
    fn test_import_status_conversions() {
        // Test ImportStatus to TransactionStatus
        let import_status = ImportStatus::OneSidedConfirmed;
        let transaction_status: TransactionStatus = import_status.try_into().unwrap();
        assert_eq!(transaction_status, TransactionStatus::OneSidedConfirmed);

        // Test TransactionStatus to ImportStatus
        let back_to_import: ImportStatus = transaction_status.try_into().unwrap();
        assert_eq!(back_to_import, ImportStatus::OneSidedConfirmed);

        // Test conversion that should fail
        let result: Result<ImportStatus, _> = TransactionStatus::Pending.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_serialization() {
        use serde_json;

        // Test TransactionStatus serialization
        let status = TransactionStatus::MinedConfirmed;
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: TransactionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, deserialized);

        // Test TransactionDirection serialization
        let direction = TransactionDirection::Inbound;
        let json = serde_json::to_string(&direction).unwrap();
        let deserialized: TransactionDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(direction, deserialized);

        // Test ImportStatus serialization
        let import_status = ImportStatus::CoinbaseConfirmed;
        let json = serde_json::to_string(&import_status).unwrap();
        let deserialized: ImportStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(import_status, deserialized);
    }

    #[test]
    fn test_defaults() {
        assert_eq!(TransactionStatus::default(), TransactionStatus::Pending);
        assert_eq!(
            TransactionDirection::default(),
            TransactionDirection::Unknown
        );
    }
}
