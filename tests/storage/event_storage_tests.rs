//! Tests for event storage functionality
//!
//! This module contains tests for the event storage implementation,
//! verifying database schema creation, event persistence, and querying capabilities.

#[cfg(feature = "storage")]
mod event_storage_tests {
    use crate::storage::{EventFilter, EventStorage, SqliteEventStorage, StoredEvent};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio_rusqlite::Connection;

    async fn create_test_storage() -> SqliteEventStorage {
        let conn = Connection::open(":memory:").await.unwrap();
        SqliteEventStorage::new(conn).await.unwrap()
    }

    fn create_test_event(
        event_id: &str,
        wallet_id: &str,
        event_type: &str,
        sequence: u64,
    ) -> StoredEvent {
        StoredEvent::new(
            event_id.to_string(),
            wallet_id.to_string(),
            event_type.to_string(),
            sequence,
            "{}".to_string(),  // Empty JSON payload for tests
            "{}".to_string(),  // Empty JSON metadata for tests
            "test-source".to_string(),
            None,
            SystemTime::now(),
        )
    }

    #[tokio::test]
    async fn test_event_storage_initialization() {
        let storage = create_test_storage().await;
        
        // Verify initial state
        let stats = storage.get_storage_stats().await.unwrap();
        assert_eq!(stats.total_events, 0);
        assert_eq!(stats.unique_wallets, 0);
        assert!(stats.events_by_type.is_empty());
    }

    #[tokio::test]
    async fn test_store_single_event() {
        let storage = create_test_storage().await;
        let event = create_test_event("event-1", "wallet-1", "UTXO_RECEIVED", 1);

        // Store the event
        let event_id = storage.store_event(&event).await.unwrap();
        assert!(event_id > 0);

        // Verify the event was stored
        let retrieved = storage.get_event_by_id("event-1").await.unwrap();
        assert!(retrieved.is_some());
        
        let retrieved_event = retrieved.unwrap();
        assert_eq!(retrieved_event.event_id, "event-1");
        assert_eq!(retrieved_event.wallet_id, "wallet-1");
        assert_eq!(retrieved_event.event_type, "UTXO_RECEIVED");
        assert_eq!(retrieved_event.sequence_number, 1);
    }

    #[tokio::test]
    async fn test_store_events_batch() {
        let storage = create_test_storage().await;
        
        let events = vec![
            create_test_event("event-1", "wallet-1", "UTXO_RECEIVED", 1),
            create_test_event("event-2", "wallet-1", "UTXO_RECEIVED", 2),
            create_test_event("event-3", "wallet-2", "UTXO_RECEIVED", 1),
        ];

        // Store events in batch
        let event_ids = storage.store_events_batch(&events).await.unwrap();
        assert_eq!(event_ids.len(), 3);

        // Verify all events were stored
        for event in &events {
            let retrieved = storage.get_event_by_id(&event.event_id).await.unwrap();
            assert!(retrieved.is_some());
        }

        // Check statistics
        let stats = storage.get_storage_stats().await.unwrap();
        assert_eq!(stats.total_events, 3);
        assert_eq!(stats.unique_wallets, 2);
        assert_eq!(stats.events_by_type.get("UTXO_RECEIVED"), Some(&3));
    }

    #[tokio::test]
    async fn test_get_events_with_filter() {
        let storage = create_test_storage().await;
        
        let events = vec![
            create_test_event("event-1", "wallet-1", "UTXO_RECEIVED", 1),
            create_test_event("event-2", "wallet-1", "UTXO_SPENT", 2),
            create_test_event("event-3", "wallet-2", "UTXO_RECEIVED", 1),
            create_test_event("event-4", "wallet-1", "UTXO_RECEIVED", 3),
        ];

        storage.store_events_batch(&events).await.unwrap();

        // Filter by wallet ID
        let filter = EventFilter::new().with_wallet_id("wallet-1".to_string());
        let filtered_events = storage.get_events(&filter).await.unwrap();
        assert_eq!(filtered_events.len(), 3);

        // Filter by event type
        let filter = EventFilter::new().with_event_type("UTXO_RECEIVED".to_string());
        let filtered_events = storage.get_events(&filter).await.unwrap();
        assert_eq!(filtered_events.len(), 3);

        // Filter by wallet and event type
        let filter = EventFilter::new()
            .with_wallet_id("wallet-1".to_string())
            .with_event_type("UTXO_RECEIVED".to_string());
        let filtered_events = storage.get_events(&filter).await.unwrap();
        assert_eq!(filtered_events.len(), 2);

        // Filter with limit
        let filter = EventFilter::new().with_limit(2);
        let filtered_events = storage.get_events(&filter).await.unwrap();
        assert_eq!(filtered_events.len(), 2);
    }

    #[tokio::test]
    async fn test_sequence_ordering() {
        let storage = create_test_storage().await;
        
        let events = vec![
            create_test_event("event-3", "wallet-1", "UTXO_RECEIVED", 3),
            create_test_event("event-1", "wallet-1", "UTXO_RECEIVED", 1),
            create_test_event("event-2", "wallet-1", "UTXO_RECEIVED", 2),
        ];

        storage.store_events_batch(&events).await.unwrap();

        // Get events in ascending order (default)
        let filter = EventFilter::new().with_wallet_id("wallet-1".to_string());
        let ordered_events = storage.get_events(&filter).await.unwrap();
        
        assert_eq!(ordered_events.len(), 3);
        assert_eq!(ordered_events[0].sequence_number, 1);
        assert_eq!(ordered_events[1].sequence_number, 2);
        assert_eq!(ordered_events[2].sequence_number, 3);

        // Get events in descending order
        let filter = EventFilter::new()
            .with_wallet_id("wallet-1".to_string())
            .order_desc();
        let ordered_events = storage.get_events(&filter).await.unwrap();
        
        assert_eq!(ordered_events.len(), 3);
        assert_eq!(ordered_events[0].sequence_number, 3);
        assert_eq!(ordered_events[1].sequence_number, 2);
        assert_eq!(ordered_events[2].sequence_number, 1);
    }

    #[tokio::test]
    async fn test_get_latest_sequence() {
        let storage = create_test_storage().await;
        
        // No events yet
        let latest = storage.get_latest_sequence("wallet-1").await.unwrap();
        assert!(latest.is_none());

        // Store some events
        let events = vec![
            create_test_event("event-1", "wallet-1", "UTXO_RECEIVED", 1),
            create_test_event("event-2", "wallet-1", "UTXO_RECEIVED", 3),
            create_test_event("event-3", "wallet-2", "UTXO_RECEIVED", 2),
        ];

        storage.store_events_batch(&events).await.unwrap();

        // Check latest sequence for each wallet
        let latest_w1 = storage.get_latest_sequence("wallet-1").await.unwrap();
        assert_eq!(latest_w1, Some(3));

        let latest_w2 = storage.get_latest_sequence("wallet-2").await.unwrap();
        assert_eq!(latest_w2, Some(2));

        let latest_w3 = storage.get_latest_sequence("wallet-3").await.unwrap();
        assert!(latest_w3.is_none());
    }

    #[tokio::test]
    async fn test_get_events_since_sequence() {
        let storage = create_test_storage().await;
        
        let events = vec![
            create_test_event("event-1", "wallet-1", "UTXO_RECEIVED", 1),
            create_test_event("event-2", "wallet-1", "UTXO_RECEIVED", 2),
            create_test_event("event-3", "wallet-1", "UTXO_RECEIVED", 3),
            create_test_event("event-4", "wallet-1", "UTXO_RECEIVED", 4),
        ];

        storage.store_events_batch(&events).await.unwrap();

        // Get events since sequence 2
        let since_events = storage.get_events_since_sequence("wallet-1", 2).await.unwrap();
        assert_eq!(since_events.len(), 2);
        assert_eq!(since_events[0].sequence_number, 3);
        assert_eq!(since_events[1].sequence_number, 4);

        // Get events since sequence 4 (should be empty)
        let since_events = storage.get_events_since_sequence("wallet-1", 4).await.unwrap();
        assert_eq!(since_events.len(), 0);
    }

    #[tokio::test]
    async fn test_event_count() {
        let storage = create_test_storage().await;
        
        // Initial count should be 0
        let count = storage.get_event_count("wallet-1").await.unwrap();
        assert_eq!(count, 0);

        // Store some events
        let events = vec![
            create_test_event("event-1", "wallet-1", "UTXO_RECEIVED", 1),
            create_test_event("event-2", "wallet-1", "UTXO_RECEIVED", 2),
            create_test_event("event-3", "wallet-2", "UTXO_RECEIVED", 1),
        ];

        storage.store_events_batch(&events).await.unwrap();

        // Check counts
        let count_w1 = storage.get_event_count("wallet-1").await.unwrap();
        assert_eq!(count_w1, 2);

        let count_w2 = storage.get_event_count("wallet-2").await.unwrap();
        assert_eq!(count_w2, 1);
    }

    #[tokio::test]
    async fn test_event_exists() {
        let storage = create_test_storage().await;
        
        // Event should not exist initially
        let exists = storage.event_exists("event-1").await.unwrap();
        assert!(!exists);

        // Store an event
        let event = create_test_event("event-1", "wallet-1", "UTXO_RECEIVED", 1);
        storage.store_event(&event).await.unwrap();

        // Event should now exist
        let exists = storage.event_exists("event-1").await.unwrap();
        assert!(exists);

        // Non-existent event should still not exist
        let exists = storage.event_exists("event-999").await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn test_unique_constraints() {
        let storage = create_test_storage().await;
        
        let event1 = create_test_event("event-1", "wallet-1", "UTXO_RECEIVED", 1);
        
        // Store first event
        storage.store_event(&event1).await.unwrap();

        // Try to store event with same ID (should fail)
        let duplicate_id_event = create_test_event("event-1", "wallet-2", "UTXO_SPENT", 2);
        let result = storage.store_event(&duplicate_id_event).await;
        assert!(result.is_err());

        // Try to store event with same wallet_id + sequence_number (should fail)
        let duplicate_seq_event = create_test_event("event-2", "wallet-1", "UTXO_SPENT", 1);
        let result = storage.store_event(&duplicate_seq_event).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sequence_range_filter() {
        let storage = create_test_storage().await;
        
        let events = vec![
            create_test_event("event-1", "wallet-1", "UTXO_RECEIVED", 1),
            create_test_event("event-2", "wallet-1", "UTXO_RECEIVED", 2),
            create_test_event("event-3", "wallet-1", "UTXO_RECEIVED", 3),
            create_test_event("event-4", "wallet-1", "UTXO_RECEIVED", 4),
            create_test_event("event-5", "wallet-1", "UTXO_RECEIVED", 5),
        ];

        storage.store_events_batch(&events).await.unwrap();

        // Filter by sequence range
        let filter = EventFilter::new()
            .with_wallet_id("wallet-1".to_string())
            .with_sequence_range(2, 4);
        let filtered_events = storage.get_events(&filter).await.unwrap();
        
        assert_eq!(filtered_events.len(), 3);
        assert_eq!(filtered_events[0].sequence_number, 2);
        assert_eq!(filtered_events[1].sequence_number, 3);
        assert_eq!(filtered_events[2].sequence_number, 4);
    }

    #[tokio::test]
    async fn test_timestamp_filter() {
        let storage = create_test_storage().await;
        
        let base_time = UNIX_EPOCH + std::time::Duration::from_secs(1000000);
        let time_1 = base_time;
        let time_2 = base_time + std::time::Duration::from_secs(3600); // 1 hour later
        let time_3 = base_time + std::time::Duration::from_secs(7200); // 2 hours later

        let mut event1 = create_test_event("event-1", "wallet-1", "UTXO_RECEIVED", 1);
        event1.timestamp = time_1;
        
        let mut event2 = create_test_event("event-2", "wallet-1", "UTXO_RECEIVED", 2);
        event2.timestamp = time_2;
        
        let mut event3 = create_test_event("event-3", "wallet-1", "UTXO_RECEIVED", 3);
        event3.timestamp = time_3;

        storage.store_events_batch(&[event1, event2, event3]).await.unwrap();

        // Filter by timestamp range
        let filter = EventFilter::new()
            .with_wallet_id("wallet-1".to_string())
            .with_timestamp_range(time_1, time_2);
        let filtered_events = storage.get_events(&filter).await.unwrap();
        
        assert_eq!(filtered_events.len(), 2);
        assert_eq!(filtered_events[0].sequence_number, 1);
        assert_eq!(filtered_events[1].sequence_number, 2);
    }

    #[tokio::test]
    async fn test_correlation_id_filter() {
        let storage = create_test_storage().await;
        
        let mut event1 = create_test_event("event-1", "wallet-1", "UTXO_RECEIVED", 1);
        event1.correlation_id = Some("correlation-123".to_string());
        
        let mut event2 = create_test_event("event-2", "wallet-1", "UTXO_RECEIVED", 2);
        event2.correlation_id = Some("correlation-123".to_string());
        
        let event3 = create_test_event("event-3", "wallet-1", "UTXO_RECEIVED", 3);
        // event3 has no correlation_id

        storage.store_events_batch(&[event1, event2, event3]).await.unwrap();

        // Filter by correlation ID
        let filter = EventFilter::new()
            .with_wallet_id("wallet-1".to_string())
            .with_correlation_id("correlation-123".to_string());
        let filtered_events = storage.get_events(&filter).await.unwrap();
        
        assert_eq!(filtered_events.len(), 2);
        assert_eq!(filtered_events[0].sequence_number, 1);
        assert_eq!(filtered_events[1].sequence_number, 2);
    }

    #[tokio::test]
    async fn test_pagination() {
        let storage = create_test_storage().await;
        
        let events: Vec<_> = (1..=10)
            .map(|i| create_test_event(&format!("event-{i}"), "wallet-1", "UTXO_RECEIVED", i))
            .collect();

        storage.store_events_batch(&events).await.unwrap();

        // First page (limit 3)
        let filter = EventFilter::new()
            .with_wallet_id("wallet-1".to_string())
            .with_limit(3);
        let page1 = storage.get_events(&filter).await.unwrap();
        assert_eq!(page1.len(), 3);
        assert_eq!(page1[0].sequence_number, 1);
        assert_eq!(page1[2].sequence_number, 3);

        // Second page (offset 3, limit 3)
        let filter = EventFilter::new()
            .with_wallet_id("wallet-1".to_string())
            .with_limit(3)
            .with_offset(3);
        let page2 = storage.get_events(&filter).await.unwrap();
        assert_eq!(page2.len(), 3);
        assert_eq!(page2[0].sequence_number, 4);
        assert_eq!(page2[2].sequence_number, 6);
    }
}
