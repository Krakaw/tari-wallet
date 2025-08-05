//! Tests for automatic timestamping and sequence number assignment (Task 4.3)
//!
//! This module tests the enhanced automatic assignment features for event creation.

#[cfg(feature = "storage")]
mod automatic_assignment_tests {
    use lightweight_wallet_libs::storage::{EventStorage, SqliteEventStorage};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio_rusqlite::Connection;

    async fn create_test_storage() -> SqliteEventStorage {
        let conn = Connection::open(":memory:").await.unwrap();
        SqliteEventStorage::new(conn).await.unwrap()
    }

    #[tokio::test]
    async fn test_create_event_automatic_assignment() {
        let storage = create_test_storage().await;
        let before_create = SystemTime::now();

        // Create an event using the enhanced automatic method
        let event = storage
            .create_event(
                "wallet-1",
                "UTXO_RECEIVED",
                r#"{"amount": 1000, "commitment": "abc123"}"#.to_string(),
                "scanner",
            )
            .await
            .unwrap();

        let after_create = SystemTime::now();

        // Verify automatic assignments
        assert_eq!(event.wallet_id, "wallet-1");
        assert_eq!(event.event_type, "UTXO_RECEIVED");
        assert_eq!(event.sequence_number, 1); // First event should be sequence 1
        assert_eq!(event.source, "scanner");
        assert!(event.correlation_id.is_none()); // Basic create doesn't set correlation

        // Verify automatic event ID is a valid UUID
        assert_eq!(event.event_id.len(), 36); // UUID format
        assert!(event.event_id.contains('-'));

        // Verify timestamp is recent and reasonable
        assert!(event.timestamp >= before_create);
        assert!(event.timestamp <= after_create);

        // Verify automatic metadata contains expected fields
        let metadata: serde_json::Value = serde_json::from_str(&event.metadata_json).unwrap();
        assert_eq!(metadata["auto_generated"], true);
        assert_eq!(metadata["wallet_id"], "wallet-1");
        assert_eq!(metadata["sequence"], 1);
        assert!(metadata["created_at"].is_number());

        // Verify database ID was assigned
        assert!(event.id.is_some());
        assert!(event.id.unwrap() > 0);
    }

    #[tokio::test]
    async fn test_create_event_with_correlation_automatic_assignment() {
        let storage = create_test_storage().await;

        // Create an event with correlation
        let event = storage
            .create_event_with_correlation(
                "wallet-1",
                "UTXO_SPENT",
                r#"{"amount": 500, "input_index": 0}"#.to_string(),
                "transaction",
                "tx-correlation-123".to_string(),
            )
            .await
            .unwrap();

        // Verify basic automatic assignments
        assert_eq!(event.wallet_id, "wallet-1");
        assert_eq!(event.event_type, "UTXO_SPENT");
        assert_eq!(event.sequence_number, 1);
        assert_eq!(event.source, "transaction");

        // Verify correlation is properly set
        assert_eq!(event.correlation_id, Some("tx-correlation-123".to_string()));

        // Verify enhanced metadata includes correlation info
        let metadata: serde_json::Value = serde_json::from_str(&event.metadata_json).unwrap();
        assert_eq!(metadata["auto_generated"], true);
        assert_eq!(metadata["correlation_id"], "tx-correlation-123");
        assert_eq!(metadata["wallet_id"], "wallet-1");
        assert_eq!(metadata["sequence"], 1);
    }

    #[tokio::test]
    async fn test_create_events_batch_automatic_assignment() {
        let storage = create_test_storage().await;
        let before_create = SystemTime::now();

        // Create batch of events
        let events = vec![
            (
                "UTXO_RECEIVED".to_string(),
                r#"{"amount": 1000}"#.to_string(),
                "scanner".to_string(),
            ),
            (
                "UTXO_RECEIVED".to_string(),
                r#"{"amount": 2000}"#.to_string(),
                "scanner".to_string(),
            ),
            (
                "UTXO_SPENT".to_string(),
                r#"{"amount": 500}"#.to_string(),
                "transaction".to_string(),
            ),
        ];

        let created_events = storage
            .create_events_batch("wallet-1", &events)
            .await
            .unwrap();

        let after_create = SystemTime::now();

        // Verify batch created correct number of events
        assert_eq!(created_events.len(), 3);

        // Verify sequence numbers are assigned sequentially
        for (i, event) in created_events.iter().enumerate() {
            assert_eq!(event.sequence_number, (i + 1) as u64);
            assert_eq!(event.wallet_id, "wallet-1");

            // Verify timestamp is within expected range
            assert!(event.timestamp >= before_create);
            assert!(event.timestamp <= after_create);

            // Verify unique event IDs
            assert_eq!(event.event_id.len(), 36);
            assert!(event.id.is_some());

            // Verify batch metadata
            let metadata: serde_json::Value = serde_json::from_str(&event.metadata_json).unwrap();
            assert_eq!(metadata["auto_generated"], true);
            assert_eq!(metadata["batch_operation"], true);
            assert_eq!(metadata["wallet_id"], "wallet-1");
            assert_eq!(metadata["sequence"], (i + 1) as u64);
        }

        // Verify event types match input
        assert_eq!(created_events[0].event_type, "UTXO_RECEIVED");
        assert_eq!(created_events[1].event_type, "UTXO_RECEIVED");
        assert_eq!(created_events[2].event_type, "UTXO_SPENT");

        // Verify sources match input
        assert_eq!(created_events[0].source, "scanner");
        assert_eq!(created_events[1].source, "scanner");
        assert_eq!(created_events[2].source, "transaction");

        // Verify all events have the same timestamp (batch operation)
        let base_timestamp = created_events[0].timestamp;
        for event in &created_events {
            assert_eq!(event.timestamp, base_timestamp);
        }
    }

    #[tokio::test]
    async fn test_sequence_number_continuity() {
        let storage = create_test_storage().await;

        // Create individual events and verify sequence continuity
        let event1 = storage
            .create_event("wallet-1", "UTXO_RECEIVED", "{}".to_string(), "scanner")
            .await
            .unwrap();
        assert_eq!(event1.sequence_number, 1);

        let event2 = storage
            .create_event("wallet-1", "UTXO_SPENT", "{}".to_string(), "transaction")
            .await
            .unwrap();
        assert_eq!(event2.sequence_number, 2);

        // Create batch and verify sequences continue correctly
        let batch_events = vec![
            ("REORG".to_string(), "{}".to_string(), "scanner".to_string()),
            (
                "UTXO_RECEIVED".to_string(),
                "{}".to_string(),
                "scanner".to_string(),
            ),
        ];

        let batch_results = storage
            .create_events_batch("wallet-1", &batch_events)
            .await
            .unwrap();
        assert_eq!(batch_results[0].sequence_number, 3);
        assert_eq!(batch_results[1].sequence_number, 4);

        // Create another individual event
        let event5 = storage
            .create_event("wallet-1", "UTXO_RECEIVED", "{}".to_string(), "scanner")
            .await
            .unwrap();
        assert_eq!(event5.sequence_number, 5);

        // Verify total count
        let total_count = storage.get_event_count("wallet-1").await.unwrap();
        assert_eq!(total_count, 5);
    }

    #[tokio::test]
    async fn test_sequence_assignment_per_wallet() {
        let storage = create_test_storage().await;

        // Create events for different wallets
        let wallet1_event1 = storage
            .create_event("wallet-1", "UTXO_RECEIVED", "{}".to_string(), "scanner")
            .await
            .unwrap();
        let wallet2_event1 = storage
            .create_event("wallet-2", "UTXO_RECEIVED", "{}".to_string(), "scanner")
            .await
            .unwrap();
        let wallet1_event2 = storage
            .create_event("wallet-1", "UTXO_SPENT", "{}".to_string(), "transaction")
            .await
            .unwrap();

        // Verify each wallet has independent sequence numbering
        assert_eq!(wallet1_event1.sequence_number, 1);
        assert_eq!(wallet2_event1.sequence_number, 1); // Independent sequence for wallet-2
        assert_eq!(wallet1_event2.sequence_number, 2); // Continues wallet-1 sequence

        // Verify wallet isolation
        assert_eq!(wallet1_event1.wallet_id, "wallet-1");
        assert_eq!(wallet2_event1.wallet_id, "wallet-2");
        assert_eq!(wallet1_event2.wallet_id, "wallet-1");
    }

    #[tokio::test]
    async fn test_get_next_sequence_number() {
        let storage = create_test_storage().await;

        // Check next sequence for empty wallet
        let next_seq = storage.get_next_sequence_number("wallet-1").await.unwrap();
        assert_eq!(next_seq, 1);

        // Create an event
        storage
            .create_event("wallet-1", "UTXO_RECEIVED", "{}".to_string(), "scanner")
            .await
            .unwrap();

        // Check next sequence after creating event
        let next_seq = storage.get_next_sequence_number("wallet-1").await.unwrap();
        assert_eq!(next_seq, 2);

        // Create batch of events
        let batch_events = vec![
            (
                "UTXO_RECEIVED".to_string(),
                "{}".to_string(),
                "scanner".to_string(),
            ),
            (
                "UTXO_SPENT".to_string(),
                "{}".to_string(),
                "transaction".to_string(),
            ),
        ];
        storage
            .create_events_batch("wallet-1", &batch_events)
            .await
            .unwrap();

        // Check next sequence after batch
        let next_seq = storage.get_next_sequence_number("wallet-1").await.unwrap();
        assert_eq!(next_seq, 4);

        // Check next sequence for different wallet
        let next_seq_w2 = storage.get_next_sequence_number("wallet-2").await.unwrap();
        assert_eq!(next_seq_w2, 1); // wallet-2 has no events
    }

    #[tokio::test]
    async fn test_is_sequence_available() {
        let storage = create_test_storage().await;

        // All sequences should be available for empty wallet
        assert!(storage.is_sequence_available("wallet-1", 1).await.unwrap());
        assert!(storage.is_sequence_available("wallet-1", 2).await.unwrap());
        assert!(storage
            .is_sequence_available("wallet-1", 100)
            .await
            .unwrap());

        // Create an event at sequence 1
        storage
            .create_event("wallet-1", "UTXO_RECEIVED", "{}".to_string(), "scanner")
            .await
            .unwrap();

        // Sequence 1 should no longer be available
        assert!(!storage.is_sequence_available("wallet-1", 1).await.unwrap());

        // But sequence 2 should still be available
        assert!(storage.is_sequence_available("wallet-1", 2).await.unwrap());

        // Create batch to fill sequences 2-3
        let batch_events = vec![
            (
                "UTXO_RECEIVED".to_string(),
                "{}".to_string(),
                "scanner".to_string(),
            ),
            (
                "UTXO_SPENT".to_string(),
                "{}".to_string(),
                "transaction".to_string(),
            ),
        ];
        storage
            .create_events_batch("wallet-1", &batch_events)
            .await
            .unwrap();

        // Sequences 1-3 should be unavailable
        assert!(!storage.is_sequence_available("wallet-1", 1).await.unwrap());
        assert!(!storage.is_sequence_available("wallet-1", 2).await.unwrap());
        assert!(!storage.is_sequence_available("wallet-1", 3).await.unwrap());

        // But sequence 4+ should be available
        assert!(storage.is_sequence_available("wallet-1", 4).await.unwrap());
        assert!(storage.is_sequence_available("wallet-1", 5).await.unwrap());
    }

    #[tokio::test]
    async fn test_timestamp_accuracy() {
        let storage = create_test_storage().await;

        // Record time before and after event creation
        let before = SystemTime::now();
        let event = storage
            .create_event("wallet-1", "UTXO_RECEIVED", "{}".to_string(), "scanner")
            .await
            .unwrap();
        let after = SystemTime::now();

        // Verify timestamp is within expected range
        assert!(event.timestamp >= before);
        assert!(event.timestamp <= after);

        // Verify timestamp precision (should be within 1 second)
        let duration = after.duration_since(before).unwrap();
        assert!(duration < Duration::from_secs(1));

        // Verify metadata timestamp matches event timestamp
        let metadata: serde_json::Value = serde_json::from_str(&event.metadata_json).unwrap();
        let metadata_timestamp = metadata["created_at"].as_i64().unwrap();
        let event_timestamp_secs = event
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert_eq!(metadata_timestamp, event_timestamp_secs);
    }

    #[tokio::test]
    async fn test_event_id_uniqueness() {
        let storage = create_test_storage().await;

        // Create multiple events and collect event IDs
        let mut event_ids = std::collections::HashSet::new();

        // Create individual events
        for i in 1..=5 {
            let event = storage
                .create_event(
                    "wallet-1",
                    "UTXO_RECEIVED",
                    format!(r#"{{"event": {i}}}"#),
                    "scanner",
                )
                .await
                .unwrap();

            // Verify UUID format
            assert_eq!(event.event_id.len(), 36);
            assert!(event.event_id.contains('-'));

            // Verify uniqueness
            assert!(
                event_ids.insert(event.event_id.clone()),
                "Duplicate event ID: {}",
                event.event_id
            );
        }

        // Create batch events
        let batch_events = vec![
            (
                "UTXO_RECEIVED".to_string(),
                "{}".to_string(),
                "scanner".to_string(),
            ),
            (
                "UTXO_SPENT".to_string(),
                "{}".to_string(),
                "transaction".to_string(),
            ),
            ("REORG".to_string(), "{}".to_string(), "scanner".to_string()),
        ];

        let batch_results = storage
            .create_events_batch("wallet-1", &batch_events)
            .await
            .unwrap();
        for event in batch_results {
            // Verify UUID format
            assert_eq!(event.event_id.len(), 36);
            assert!(event.event_id.contains('-'));

            // Verify uniqueness
            assert!(
                event_ids.insert(event.event_id.clone()),
                "Duplicate event ID: {}",
                event.event_id
            );
        }

        // Should have 8 unique event IDs
        assert_eq!(event_ids.len(), 8);
    }

    #[tokio::test]
    async fn test_empty_batch_handling() {
        let storage = create_test_storage().await;

        // Create empty batch should return empty result
        let empty_batch: Vec<(String, String, String)> = vec![];
        let results = storage
            .create_events_batch("wallet-1", &empty_batch)
            .await
            .unwrap();
        assert_eq!(results.len(), 0);

        // Verify no events were created
        let count = storage.get_event_count("wallet-1").await.unwrap();
        assert_eq!(count, 0);

        // Next sequence number should still be 1
        let next_seq = storage.get_next_sequence_number("wallet-1").await.unwrap();
        assert_eq!(next_seq, 1);
    }

    #[tokio::test]
    async fn test_sequential_event_creation_consistency() {
        let storage = create_test_storage().await;

        // Create multiple events sequentially and verify consistency
        let mut results = Vec::new();

        for i in 0..5 {
            let event = storage
                .create_event(
                    "wallet-sequential",
                    "UTXO_RECEIVED",
                    format!(r#"{{"task": {i}}}"#),
                    "scanner",
                )
                .await
                .unwrap();
            results.push(event);
        }

        // Verify all events were created successfully
        assert_eq!(results.len(), 5);

        // Verify sequence numbers are assigned sequentially
        for (i, event) in results.iter().enumerate() {
            assert_eq!(event.sequence_number, (i + 1) as u64);
            assert_eq!(event.wallet_id, "wallet-sequential");
            assert_eq!(event.event_type, "UTXO_RECEIVED");
            assert_eq!(event.source, "scanner");
        }

        // Verify all have unique event IDs
        let event_ids: std::collections::HashSet<_> = results.iter().map(|e| &e.event_id).collect();
        assert_eq!(event_ids.len(), 5);
    }
}
