//! Tests for event retrieval methods specifically designed for replay functionality
//!
//! This module tests the enhanced event retrieval methods that were added as part
//! of task 4.7 to support event replay and verification systems.

#[cfg(feature = "storage")]
mod replay_tests {
    use lightweight_wallet_libs::storage::event_storage::{
        EventStorage, SqliteEventStorage, StoredEvent,
    };
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio_rusqlite::Connection;

    async fn create_test_storage() -> SqliteEventStorage {
        let conn = Connection::open(":memory:").await.unwrap();
        SqliteEventStorage::new(conn).await.unwrap()
    }

    async fn create_test_events(storage: &SqliteEventStorage, wallet_id: &str, count: usize) {
        for i in 1..=count {
            let event = StoredEvent::new(
                format!("event-{i}-{wallet_id}"),
                wallet_id.to_string(),
                "UTXO_RECEIVED".to_string(),
                i as u64,
                format!("{{\"amount\": {}}}", i * 100),
                "{}".to_string(),
                "test-source".to_string(),
                if i % 3 == 0 {
                    Some(format!("correlation-{}", i / 3))
                } else {
                    None
                },
                UNIX_EPOCH + Duration::from_secs(1000 + i as u64),
            );
            storage.store_event(&event).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_get_events_for_replay() {
        let storage = create_test_storage().await;
        let wallet_id = "test-wallet-123";

        // Create test events
        create_test_events(&storage, wallet_id, 5).await;

        // Test get_events_for_replay
        let events = storage.get_events_for_replay(wallet_id).await.unwrap();
        assert_eq!(events.len(), 5);

        // Verify events are in chronological order (sequence 1, 2, 3, 4, 5)
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.sequence_number, (i + 1) as u64);
            assert_eq!(event.wallet_id, wallet_id);
        }
    }

    #[tokio::test]
    async fn test_get_events_for_incremental_replay() {
        let storage = create_test_storage().await;
        let wallet_id = "test-wallet-456";

        // Create test events
        create_test_events(&storage, wallet_id, 10).await;

        // First, verify all events were created
        let all_events = storage.get_events_for_replay(wallet_id).await.unwrap();
        assert_eq!(all_events.len(), 10);

        // Test incremental replay from sequence 5 (should get events 6-10)
        let events = storage
            .get_events_for_incremental_replay(wallet_id, 5)
            .await
            .unwrap();

        println!("Events since sequence 5: {:?}", events.len());
        for event in &events {
            println!("Event sequence: {}", event.sequence_number);
        }

        assert_eq!(events.len(), 5); // Events 6, 7, 8, 9, 10
        if !events.is_empty() {
            assert_eq!(events[0].sequence_number, 6);
            assert_eq!(events[4].sequence_number, 10);
        }
    }

    #[tokio::test]
    async fn test_get_events_batch_for_replay() {
        let storage = create_test_storage().await;
        let wallet_id = "test-wallet-789";

        // Create test events
        create_test_events(&storage, wallet_id, 20).await;

        // Test batched replay
        let batch1 = storage
            .get_events_batch_for_replay(wallet_id, 1, 5)
            .await
            .unwrap();
        assert_eq!(batch1.len(), 5);
        assert_eq!(batch1[0].sequence_number, 1);
        assert_eq!(batch1[4].sequence_number, 5);

        let batch2 = storage
            .get_events_batch_for_replay(wallet_id, 6, 5)
            .await
            .unwrap();
        assert_eq!(batch2.len(), 5);
        assert_eq!(batch2[0].sequence_number, 6);
        assert_eq!(batch2[4].sequence_number, 10);

        // Test partial batch at end
        let batch3 = storage
            .get_events_batch_for_replay(wallet_id, 18, 5)
            .await
            .unwrap();
        assert_eq!(batch3.len(), 3); // Events 18, 19, 20
        assert_eq!(batch3[0].sequence_number, 18);
        assert_eq!(batch3[2].sequence_number, 20);
    }

    #[tokio::test]
    async fn test_get_first_and_last_event() {
        let storage = create_test_storage().await;
        let wallet_id = "test-wallet-first-last";

        // Test with no events
        let first = storage.get_first_event(wallet_id).await.unwrap();
        let last = storage.get_last_event(wallet_id).await.unwrap();
        assert!(first.is_none());
        assert!(last.is_none());

        // Create test events
        create_test_events(&storage, wallet_id, 3).await;

        // Test with events
        let first = storage.get_first_event(wallet_id).await.unwrap();
        let last = storage.get_last_event(wallet_id).await.unwrap();

        assert!(first.is_some());
        assert!(last.is_some());
        assert_eq!(first.unwrap().sequence_number, 1);
        assert_eq!(last.unwrap().sequence_number, 3);
    }

    #[tokio::test]
    async fn test_verify_replay_integrity() {
        let storage = create_test_storage().await;
        let wallet_id = "test-wallet-integrity";

        // Test with no events
        let integrity = storage.verify_replay_integrity(wallet_id).await.unwrap();
        assert!(integrity); // Empty is considered valid

        // Create continuous sequence
        create_test_events(&storage, wallet_id, 5).await;
        let integrity = storage.verify_replay_integrity(wallet_id).await.unwrap();
        assert!(integrity);

        // Test with gap (create event with sequence 7, skipping 6)
        let gap_event = StoredEvent::new(
            format!("gap-event-{wallet_id}"),
            wallet_id.to_string(),
            "UTXO_RECEIVED".to_string(),
            7, // This creates a gap at sequence 6
            "{}".to_string(),
            "{}".to_string(),
            "test-source".to_string(),
            None,
            SystemTime::now(),
        );
        storage.store_event(&gap_event).await.unwrap();

        let integrity = storage.verify_replay_integrity(wallet_id).await.unwrap();
        assert!(!integrity); // Should detect the gap
    }

    #[tokio::test]
    async fn test_get_events_by_type_for_replay() {
        let storage = create_test_storage().await;
        let wallet_id = "test-wallet-by-type";

        // Create mixed event types
        for i in 1..=6 {
            let event_type = if i % 2 == 0 {
                "UTXO_SPENT"
            } else {
                "UTXO_RECEIVED"
            };
            let event = StoredEvent::new(
                format!("event-{i}-{wallet_id}"),
                wallet_id.to_string(),
                event_type.to_string(),
                i as u64,
                "{}".to_string(),
                "{}".to_string(),
                "test-source".to_string(),
                None,
                SystemTime::now(),
            );
            storage.store_event(&event).await.unwrap();
        }

        // Test selective replay by type
        let received_events = storage
            .get_events_by_type_for_replay(wallet_id, "UTXO_RECEIVED")
            .await
            .unwrap();
        assert_eq!(received_events.len(), 3); // Events 1, 3, 5

        let spent_events = storage
            .get_events_by_type_for_replay(wallet_id, "UTXO_SPENT")
            .await
            .unwrap();
        assert_eq!(spent_events.len(), 3); // Events 2, 4, 6

        // Verify sequence order within type
        for (i, event) in received_events.iter().enumerate() {
            assert_eq!(event.sequence_number, (i * 2 + 1) as u64); // 1, 3, 5
        }
    }

    #[tokio::test]
    async fn test_get_events_in_time_range_for_replay() {
        let storage = create_test_storage().await;
        let wallet_id = "test-wallet-time-range";

        // Create events with specific timestamps
        let base_time = UNIX_EPOCH + Duration::from_secs(1000);
        for i in 1..=10 {
            let event = StoredEvent::new(
                format!("event-{i}-{wallet_id}"),
                wallet_id.to_string(),
                "UTXO_RECEIVED".to_string(),
                i as u64,
                "{}".to_string(),
                "{}".to_string(),
                "test-source".to_string(),
                None,
                base_time + Duration::from_secs(i as u64 * 100), // Events at 1100, 1200, 1300, etc.
            );
            storage.store_event(&event).await.unwrap();
        }

        // Test time range replay (events 3-7: timestamps 1300-1700)
        let from_time = base_time + Duration::from_secs(300);
        let to_time = base_time + Duration::from_secs(700);

        let events = storage
            .get_events_in_time_range_for_replay(wallet_id, from_time, to_time)
            .await
            .unwrap();

        assert_eq!(events.len(), 5); // Events 3, 4, 5, 6, 7
        assert_eq!(events[0].sequence_number, 3);
        assert_eq!(events[4].sequence_number, 7);
    }

    #[tokio::test]
    async fn test_get_correlated_events_for_replay() {
        let storage = create_test_storage().await;
        let wallet_id = "test-wallet-correlation";

        // Create events with various correlation IDs
        for i in 1..=9 {
            let correlation_id = match i % 3 {
                1 => Some("batch-a".to_string()),
                2 => Some("batch-b".to_string()),
                _ => None,
            };

            let event = StoredEvent::new(
                format!("event-{i}-{wallet_id}"),
                wallet_id.to_string(),
                "UTXO_RECEIVED".to_string(),
                i as u64,
                "{}".to_string(),
                "{}".to_string(),
                "test-source".to_string(),
                correlation_id,
                SystemTime::now(),
            );
            storage.store_event(&event).await.unwrap();
        }

        // Test correlated replay
        let batch_a_events = storage
            .get_correlated_events_for_replay(wallet_id, "batch-a")
            .await
            .unwrap();
        assert_eq!(batch_a_events.len(), 3); // Events 1, 4, 7

        let batch_b_events = storage
            .get_correlated_events_for_replay(wallet_id, "batch-b")
            .await
            .unwrap();
        assert_eq!(batch_b_events.len(), 3); // Events 2, 5, 8

        // Verify correct correlation IDs
        for event in &batch_a_events {
            assert_eq!(event.correlation_id.as_ref().unwrap(), "batch-a");
        }
        for event in &batch_b_events {
            assert_eq!(event.correlation_id.as_ref().unwrap(), "batch-b");
        }
    }

    #[tokio::test]
    async fn test_replay_methods_with_multiple_wallets() {
        let storage = create_test_storage().await;
        let wallet1 = "wallet-1";
        let wallet2 = "wallet-2";

        // Create events for two different wallets
        create_test_events(&storage, wallet1, 3).await;
        create_test_events(&storage, wallet2, 5).await;

        // Test that replay methods only return events for the specified wallet
        let wallet1_events = storage.get_events_for_replay(wallet1).await.unwrap();
        let wallet2_events = storage.get_events_for_replay(wallet2).await.unwrap();

        assert_eq!(wallet1_events.len(), 3);
        assert_eq!(wallet2_events.len(), 5);

        // Verify wallet isolation
        for event in &wallet1_events {
            assert_eq!(event.wallet_id, wallet1);
        }
        for event in &wallet2_events {
            assert_eq!(event.wallet_id, wallet2);
        }

        // Test first/last events are wallet-specific
        let first1 = storage.get_first_event(wallet1).await.unwrap().unwrap();
        let last1 = storage.get_last_event(wallet1).await.unwrap().unwrap();
        let first2 = storage.get_first_event(wallet2).await.unwrap().unwrap();
        let last2 = storage.get_last_event(wallet2).await.unwrap().unwrap();

        assert_eq!(first1.sequence_number, 1);
        assert_eq!(last1.sequence_number, 3);
        assert_eq!(first2.sequence_number, 1);
        assert_eq!(last2.sequence_number, 5);
    }
}
