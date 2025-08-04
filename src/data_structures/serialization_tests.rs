use crate::data_structures::EncryptedData;
use borsh::{from_slice, to_vec, BorshDeserialize, BorshSerialize};
use serde_json;

fn serde_roundtrip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_string(value).unwrap();
    let de: T = serde_json::from_str(&json).unwrap();
    assert_eq!(value, &de);
    de
}

fn borsh_roundtrip<T>(value: &T) -> T
where
    T: BorshSerialize + BorshDeserialize + PartialEq + std::fmt::Debug,
{
    let bytes = to_vec(value).unwrap();
    let de = from_slice::<T>(&bytes).unwrap();
    assert_eq!(value, &de);
    de
}

#[test]
fn test_encrypted_data_serialization() {
    let ed = EncryptedData::default();
    serde_roundtrip(&ed);
    borsh_roundtrip(&ed);
}

#[test]
fn test_wallet_output_serialization() {
    let wo = crate::data_structures::wallet_output::WalletOutput::default();
    serde_roundtrip(&wo);
    borsh_roundtrip(&wo);
}

#[test]
fn test_transaction_output_serialization() {
    let to = crate::data_structures::transaction_output::TransactionOutput::default();
    serde_roundtrip(&to);
    borsh_roundtrip(&to);
}

#[test]
fn test_payment_id_serialization() {
    use crate::data_structures::payment_id::{PaymentId, TxType};
    use primitive_types::U256;
    let ids = vec![
        PaymentId::Empty,
        PaymentId::U256(U256::from(12345)),
        PaymentId::Open {
            user_data: vec![1, 2, 3],
            tx_type: TxType::PaymentToOther,
        },
        PaymentId::Raw(vec![10, 11, 12]),
    ];
    for id in ids {
        serde_roundtrip(&id);
        borsh_roundtrip(&id);
    }
}

#[test]
fn test_transaction_status_serialization() {
    use crate::data_structures::transaction::{
        ImportStatus, TransactionDirection, TransactionStatus,
    };

    let statuses = vec![
        TransactionStatus::Completed,
        TransactionStatus::Broadcast,
        TransactionStatus::MinedUnconfirmed,
        TransactionStatus::Imported,
        TransactionStatus::Pending,
        TransactionStatus::Coinbase,
        TransactionStatus::MinedConfirmed,
        TransactionStatus::Rejected,
        TransactionStatus::OneSidedUnconfirmed,
        TransactionStatus::OneSidedConfirmed,
        TransactionStatus::Queued,
        TransactionStatus::CoinbaseUnconfirmed,
        TransactionStatus::CoinbaseConfirmed,
        TransactionStatus::CoinbaseNotInBlockChain,
    ];

    for status in statuses {
        serde_roundtrip(&status);
        borsh_roundtrip(&status);
    }

    let directions = vec![
        TransactionDirection::Inbound,
        TransactionDirection::Outbound,
        TransactionDirection::Unknown,
    ];

    for direction in directions {
        serde_roundtrip(&direction);
        borsh_roundtrip(&direction);
    }

    let import_statuses = vec![
        ImportStatus::Broadcast,
        ImportStatus::Imported,
        ImportStatus::OneSidedUnconfirmed,
        ImportStatus::OneSidedConfirmed,
        ImportStatus::CoinbaseUnconfirmed,
        ImportStatus::CoinbaseConfirmed,
    ];

    for import_status in import_statuses {
        serde_roundtrip(&import_status);
        borsh_roundtrip(&import_status);
    }
}

#[test]
fn test_wallet_transaction_serialization() {
    use crate::data_structures::{
        payment_id::PaymentId,
        transaction::{TransactionDirection, TransactionStatus},
        types::CompressedCommitment,
        wallet_transaction::{WalletState, WalletTransaction},
    };

    // Test WalletTransaction serialization
    let commitment = CompressedCommitment::new([1u8; 32]);
    let wallet_tx = WalletTransaction::new(
        12345,
        Some(0),
        None,
        commitment,
        Some(vec![1, 2, 3, 4]), // Add the missing output_hash parameter
        1000000,
        PaymentId::Empty,
        TransactionStatus::MinedConfirmed,
        TransactionDirection::Inbound,
        true,
    );

    serde_roundtrip(&wallet_tx);
    borsh_roundtrip(&wallet_tx);

    // Test WalletState serialization
    let wallet_state = WalletState::new();
    serde_roundtrip(&wallet_state);
    borsh_roundtrip(&wallet_state);
}
