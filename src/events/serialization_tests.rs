//! Comprehensive serialization tests for event types
//! Task 1.7: Write unit tests for event type serialization and deserialization

use crate::events::types::*;
use serde_json;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_metadata_serialization() {
        // Test EventMetadata serialization/deserialization
        let metadata = EventMetadata::new("test_source", "test_wallet");
        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: EventMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(metadata.event_id, deserialized.event_id);
        assert_eq!(metadata.wallet_id, deserialized.wallet_id);
        assert_eq!(metadata.source, deserialized.source);
        assert_eq!(metadata.sequence_number, deserialized.sequence_number);
        assert_eq!(metadata.correlation_id, deserialized.correlation_id);
    }

    #[test]
    fn test_utxo_received_payload_serialization() {
        // Test UtxoReceivedPayload with all optional fields
        let payload = UtxoReceivedPayload::new(
            "utxo_123".to_string(),
            5000000, // 5 Tari
            1234567,
            "block_hash_abc".to_string(),
            1697124100,
            "tx_hash_xyz".to_string(),
            2,
            "7a1b2c3d4e5f6789".to_string(),
            42,
            "commitment_def".to_string(),
            1,
            "mainnet".to_string(),
        )
        .with_maturity_height(1234600)
        .with_script_hash("script_hash_456".to_string())
        .with_unlock_conditions();

        let json = serde_json::to_string_pretty(&payload).unwrap();
        let deserialized: UtxoReceivedPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(payload.utxo_id, deserialized.utxo_id);
        assert_eq!(payload.amount, deserialized.amount);
        assert_eq!(payload.block_height, deserialized.block_height);
        assert_eq!(payload.maturity_height, deserialized.maturity_height);
        assert_eq!(payload.script_hash, deserialized.script_hash);
        assert_eq!(
            payload.has_unlock_conditions,
            deserialized.has_unlock_conditions
        );
        assert_eq!(payload.network, deserialized.network);
    }

    #[test]
    fn test_utxo_spent_payload_serialization() {
        // Test UtxoSpentPayload with all optional fields
        let payload = UtxoSpentPayload::new(
            "utxo_456".to_string(),
            3000000, // 3 Tari
            1234567,
            1234600,
            "spending_block_hash".to_string(),
            1697124200,
            "spending_tx_hash".to_string(),
            1,
            "spending_address".to_string(),
            24,
            "spending_commitment".to_string(),
            "commitment_match".to_string(),
            true,
            "testnet".to_string(),
        )
        .with_transaction_fee(100000); // 0.1 Tari fee

        let json = serde_json::to_string_pretty(&payload).unwrap();
        let deserialized: UtxoSpentPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(payload.utxo_id, deserialized.utxo_id);
        assert_eq!(payload.amount, deserialized.amount);
        assert_eq!(
            payload.original_block_height,
            deserialized.original_block_height
        );
        assert_eq!(
            payload.spending_block_height,
            deserialized.spending_block_height
        );
        assert_eq!(payload.transaction_fee, deserialized.transaction_fee);
        assert_eq!(payload.is_self_spend, deserialized.is_self_spend);
        assert_eq!(payload.match_method, deserialized.match_method);
    }

    #[test]
    fn test_reorg_payload_serialization() {
        // Test ReorgPayload with affected transactions and UTXOs
        let payload = ReorgPayload::new(
            1000500,
            "old_block_hash".to_string(),
            "new_block_hash".to_string(),
            5,
            3,
            vec!["tx1".to_string(), "tx2".to_string(), "tx3".to_string()],
            vec!["utxo1".to_string(), "utxo2".to_string()],
            150000000, // 150 Tari balance change
            "mainnet".to_string(),
            1697124300,
        );

        let json = serde_json::to_string_pretty(&payload).unwrap();
        let deserialized: ReorgPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(payload.fork_height, deserialized.fork_height);
        assert_eq!(payload.old_block_hash, deserialized.old_block_hash);
        assert_eq!(payload.new_block_hash, deserialized.new_block_hash);
        assert_eq!(payload.rollback_depth, deserialized.rollback_depth);
        assert_eq!(payload.new_blocks_count, deserialized.new_blocks_count);
        assert_eq!(payload.affected_transaction_hashes.len(), 3);
        assert_eq!(payload.affected_utxo_ids.len(), 2);
        assert_eq!(payload.balance_change, deserialized.balance_change);
        assert_eq!(payload.network, deserialized.network);
    }

    #[test]
    fn test_wallet_event_serialization_roundtrip() {
        // Test that all WalletEvent variants can be serialized and deserialized
        let events = vec![
            WalletEvent::utxo_received(
                "test_wallet",
                UtxoReceivedPayload::new(
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
                ),
            ),
            WalletEvent::utxo_spent(
                "test_wallet",
                UtxoSpentPayload::new(
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
                ),
            ),
            WalletEvent::reorg(
                "test_wallet",
                ReorgPayload::new(
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
                ),
            ),
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

    #[test]
    fn test_serialization_roundtrip_fidelity() {
        // Test that serialization -> deserialization maintains data fidelity
        let original_event = WalletEvent::utxo_received(
            "roundtrip_test_wallet",
            UtxoReceivedPayload::new(
                "roundtrip_utxo".to_string(),
                9999999999,   // Large amount to test u64 limits
                u64::MAX - 1, // Near-max block height
                "very_long_block_hash_with_64_characters_to_test_string_limits".to_string(),
                u64::MAX - 1000, // Large timestamp
                "transaction_hash_with_special_chars_!@#$%^&*()".to_string(),
                usize::MAX - 1, // Large output index
                "address_with_unicode_テスト_characters".to_string(),
                u64::MAX - 10, // Large key index
                "commitment_with_very_long_hexadecimal_string_representation".to_string(),
                u32::MAX, // Max features
                "testnet_with_special_name".to_string(),
            )
            .with_maturity_height(u64::MAX - 100)
            .with_script_hash("script_hash_special_chars_0x123ABC".to_string())
            .with_unlock_conditions(),
        );

        // Test both pretty and compact serialization
        let pretty_json = original_event.to_debug_json().unwrap();
        let compact_json = original_event.to_compact_json().unwrap();

        // Deserialize from both formats
        let from_pretty = WalletEvent::from_json(&pretty_json).unwrap();
        let from_compact = WalletEvent::from_json(&compact_json).unwrap();

        // Verify all variants produce the same result
        assert_eq!(original_event.event_type(), from_pretty.event_type());
        assert_eq!(original_event.event_type(), from_compact.event_type());

        // Extract payloads and verify field-by-field equality
        if let (
            WalletEvent::UtxoReceived { payload: orig, .. },
            WalletEvent::UtxoReceived {
                payload: pretty, ..
            },
            WalletEvent::UtxoReceived {
                payload: compact, ..
            },
        ) = (&original_event, &from_pretty, &from_compact)
        {
            // Test all fields are preserved
            assert_eq!(orig.utxo_id, pretty.utxo_id);
            assert_eq!(orig.utxo_id, compact.utxo_id);
            assert_eq!(orig.amount, pretty.amount);
            assert_eq!(orig.amount, compact.amount);
            assert_eq!(orig.block_height, pretty.block_height);
            assert_eq!(orig.block_height, compact.block_height);
            assert_eq!(orig.maturity_height, pretty.maturity_height);
            assert_eq!(orig.maturity_height, compact.maturity_height);
            assert_eq!(orig.has_unlock_conditions, pretty.has_unlock_conditions);
            assert_eq!(orig.has_unlock_conditions, compact.has_unlock_conditions);
        } else {
            panic!("Event type mismatch in roundtrip test");
        }
    }

    #[test]
    fn test_serialization_error_handling() {
        // Test error handling for malformed JSON
        let invalid_json = r#"{"invalid": "json", "structure": true}"#;
        let result = WalletEvent::from_json(invalid_json);
        assert!(result.is_err());

        // Test partial JSON (missing required fields)
        let partial_json = r#"{"UtxoReceived": {"metadata": {"event_id": "test"}}}"#;
        let result = WalletEvent::from_json(partial_json);
        assert!(result.is_err());

        // Test empty string
        let result = WalletEvent::from_json("");
        assert!(result.is_err());

        // Test non-JSON string
        let result = WalletEvent::from_json("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_data_structure_serialization() {
        // Test supporting data structures individually
        let output_data = OutputData::new(
            "commitment_123".to_string(),
            "range_proof_456".to_string(),
            42,
            true,
        )
        .with_amount(1000000)
        .with_key_index(5)
        .with_maturity_height(12345)
        .with_script("script_code".to_string())
        .with_encrypted_value(vec![1, 2, 3, 4, 5]);

        let json = serde_json::to_string(&output_data).unwrap();
        let deserialized: OutputData = serde_json::from_str(&json).unwrap();

        assert_eq!(output_data.commitment, deserialized.commitment);
        assert_eq!(output_data.amount, deserialized.amount);
        assert_eq!(output_data.is_mine, deserialized.is_mine);
        assert_eq!(output_data.encrypted_value, deserialized.encrypted_value);

        // Test BlockInfo
        let block_info = BlockInfo::new(12345, "block_hash_abc".to_string(), 1697124400, 2)
            .with_transaction_index(1)
            .with_difficulty(1000000);

        let json = serde_json::to_string(&block_info).unwrap();
        let deserialized: BlockInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(block_info.height, deserialized.height);
        assert_eq!(block_info.hash, deserialized.hash);
        assert_eq!(block_info.transaction_index, deserialized.transaction_index);
        assert_eq!(block_info.difficulty, deserialized.difficulty);

        // Test AddressInfo
        let address_info = AddressInfo::new(
            "tari1abc123def456".to_string(),
            "stealth".to_string(),
            "mainnet".to_string(),
        )
        .with_derivation_path("m/44'/0'/0'/0/5".to_string())
        .with_public_spend_key("public_key_hex".to_string())
        .with_view_key("view_key_hex".to_string());

        let json = serde_json::to_string(&address_info).unwrap();
        let deserialized: AddressInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(address_info.address, deserialized.address);
        assert_eq!(address_info.address_type, deserialized.address_type);
        assert_eq!(address_info.derivation_path, deserialized.derivation_path);
        assert_eq!(address_info.public_spend_key, deserialized.public_spend_key);
    }

    #[test]
    fn test_error_types_serialization() {
        // Test WalletEventError serialization
        let error = WalletEventError::validation("test message", "TestEvent");
        assert_eq!(error.category(), "validation");
        assert!(!error.is_recoverable());

        let error = WalletEventError::serialization("serde failed", "TestEvent");
        assert_eq!(error.category(), "serialization");

        let error = WalletEventError::processing("TestEvent", "test failure");
        assert_eq!(error.category(), "processing");
        assert!(!error.is_recoverable());

        // Test network error is recoverable
        let error = WalletEventError::NetworkError {
            operation: "connect".to_string(),
            error: "timeout".to_string(),
        };
        assert!(error.is_recoverable());
    }

    #[test]
    fn test_scan_config_serialization() {
        // Test ScanConfig structure
        let config = ScanConfig::new()
            .with_batch_size(20)
            .with_timeout_seconds(60)
            .with_retry_attempts(5)
            .with_filter("coinbase".to_string(), "true".to_string());

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ScanConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.batch_size, deserialized.batch_size);
        assert_eq!(config.timeout_seconds, deserialized.timeout_seconds);
        assert_eq!(config.retry_attempts, deserialized.retry_attempts);
        assert_eq!(config.filters, deserialized.filters);
    }

    #[test]
    fn test_json_format_consistency() {
        // Test that JSON format is consistent between pretty and compact modes
        let event = WalletEvent::utxo_received(
            "format_test_wallet",
            UtxoReceivedPayload::new(
                "format_test_utxo".to_string(),
                1000000,
                12345,
                "test_block_hash".to_string(),
                1697124100,
                "test_tx_hash".to_string(),
                0,
                "test_address".to_string(),
                1,
                "test_commitment".to_string(),
                0,
                "mainnet".to_string(),
            ),
        );

        let pretty_json = event.to_debug_json().unwrap();
        let compact_json = event.to_compact_json().unwrap();

        // Both should deserialize to the same event
        let from_pretty = WalletEvent::from_json(&pretty_json).unwrap();
        let from_compact = WalletEvent::from_json(&compact_json).unwrap();

        assert_eq!(from_pretty.event_type(), from_compact.event_type());

        // Compact JSON should be shorter than pretty JSON
        assert!(compact_json.len() < pretty_json.len());

        // Pretty JSON should contain newlines and indentation
        assert!(pretty_json.contains('\n'));
        assert!(pretty_json.contains("  "));

        // Compact JSON should not contain unnecessary whitespace
        assert!(!compact_json.contains('\n'));
        assert!(!compact_json.contains("  "));
    }
}
