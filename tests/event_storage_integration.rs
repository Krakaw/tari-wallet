//! Integration tests for event storage functionality
//!
//! This module contains tests for the event storage implementation,
//! verifying database schema creation, event persistence, and querying capabilities.

#[cfg(feature = "storage")]
mod event_storage_tests {
    use lightweight_wallet_libs::storage::{
        EventFilter, EventStorage, SqliteEventStorage, StoredEvent,
    };
    use std::time::SystemTime;
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
            "{}".to_string(), // Empty JSON payload for tests
            "{}".to_string(), // Empty JSON metadata for tests
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
}
