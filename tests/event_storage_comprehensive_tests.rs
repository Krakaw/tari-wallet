//! Comprehensive unit tests for event storage operations
//!
//! This module provides comprehensive unit tests for all event storage operations,
//! focusing on automatic assignment, batch operations, sequence validation,
//! and edge cases that weren't covered in the basic tests.

#[cfg(feature = "storage")]
use lightweight_wallet_libs::storage::event_storage::{
    EventStorage, SqliteEventStorage, StoredEvent,
};
#[cfg(feature = "storage")]
use std::time::SystemTime;
#[cfg(feature = "storage")]
use tokio_rusqlite::Connection;

#[cfg(feature = "storage")]
async fn create_test_storage() -> SqliteEventStorage {
    let conn = Connection::open(":memory:").await.unwrap();
    SqliteEventStorage::new(conn).await.unwrap()
}

#[cfg(feature = "storage")]
fn create_test_event_with_timestamp(
    event_id: &str,
    wallet_id: &str,
    event_type: &str,
    sequence: u64,
    timestamp: SystemTime,
    correlation_id: Option<String>,
) -> StoredEvent {
    StoredEvent::new(
        event_id.to_string(),
        wallet_id.to_string(),
        event_type.to_string(),
        sequence,
        format!("{{\"test_data\": \"{}\"}}", event_id),
        format!("{{\"meta\": \"{}\"}}", event_id),
        "comprehensive-test-source".to_string(),
        correlation_id,
        timestamp,
    )
}

// MARK: - Automatic Assignment Tests

#[cfg(feature = "storage")]
#[tokio::test]
async fn test_create_event_automatic_assignment() {
    let storage = create_test_storage().await;
    let wallet_id = "auto-wallet-1";

    // Create first event
    let event1 = storage
        .create_event(
            wallet_id,
            "UTXO_RECEIVED",
            "{\"amount\": 100}".to_string(),
            "scanner",
        )
        .await
        .unwrap();

    assert_eq!(event1.wallet_id, wallet_id);
    assert_eq!(event1.event_type, "UTXO_RECEIVED");
    assert_eq!(event1.sequence_number, 1);
    assert_eq!(event1.source, "scanner");
    assert!(!event1.event_id.is_empty());
    assert!(event1.correlation_id.is_none());

    // Create second event
    let event2 = storage
        .create_event(
            wallet_id,
            "UTXO_SPENT",
            "{\"amount\": 50}".to_string(),
            "spender",
        )
        .await
        .unwrap();

    assert_eq!(event2.sequence_number, 2);
    assert_ne!(event1.event_id, event2.event_id); // Should have unique IDs
    assert!(event2.timestamp >= event1.timestamp); // Should be later or equal
}

#[cfg(feature = "storage")]
#[tokio::test]
async fn test_create_events_batch_automatic_assignment() {
    let storage = create_test_storage().await;
    let wallet_id = "batch-wallet";

    let events_data = vec![
        (
            "UTXO_RECEIVED".to_string(),
            "{\"amount\": 100}".to_string(),
            "scanner".to_string(),
        ),
        (
            "UTXO_RECEIVED".to_string(),
            "{\"amount\": 200}".to_string(),
            "scanner".to_string(),
        ),
        (
            "UTXO_SPENT".to_string(),
            "{\"amount\": 150}".to_string(),
            "spender".to_string(),
        ),
    ];

    let created_events = storage
        .create_events_batch(wallet_id, &events_data)
        .await
        .unwrap();

    assert_eq!(created_events.len(), 3);

    // Verify sequential assignment
    for (i, event) in created_events.iter().enumerate() {
        assert_eq!(event.wallet_id, wallet_id);
        assert_eq!(event.sequence_number, (i + 1) as u64);
        assert!(!event.event_id.is_empty());

        // Each event should have unique ID
        for (j, other_event) in created_events.iter().enumerate() {
            if i != j {
                assert_ne!(event.event_id, other_event.event_id);
            }
        }
    }

    // Verify event types and sources are correct
    assert_eq!(created_events[0].event_type, "UTXO_RECEIVED");
    assert_eq!(created_events[1].event_type, "UTXO_RECEIVED");
    assert_eq!(created_events[2].event_type, "UTXO_SPENT");
    assert_eq!(created_events[0].source, "scanner");
    assert_eq!(created_events[2].source, "spender");
}

#[cfg(feature = "storage")]
#[tokio::test]
async fn test_get_next_sequence_number() {
    let storage = create_test_storage().await;
    let wallet_id = "sequence-wallet";

    // No events yet, should start at 1
    let next_seq = storage.get_next_sequence_number(wallet_id).await.unwrap();
    assert_eq!(next_seq, 1);

    // Create some events
    storage
        .create_event(wallet_id, "UTXO_RECEIVED", "{}".to_string(), "test")
        .await
        .unwrap();

    let next_seq = storage.get_next_sequence_number(wallet_id).await.unwrap();
    assert_eq!(next_seq, 2);

    storage
        .create_events_batch(
            wallet_id,
            &[
                (
                    "UTXO_SPENT".to_string(),
                    "{}".to_string(),
                    "test".to_string(),
                ),
                (
                    "UTXO_RECEIVED".to_string(),
                    "{}".to_string(),
                    "test".to_string(),
                ),
            ],
        )
        .await
        .unwrap();

    let next_seq = storage.get_next_sequence_number(wallet_id).await.unwrap();
    assert_eq!(next_seq, 4);
}

#[cfg(feature = "storage")]
#[tokio::test]
async fn test_validate_sequence_continuity_perfect() {
    let storage = create_test_storage().await;
    let wallet_id = "continuity-wallet";

    // Create continuous sequence
    storage
        .create_events_batch(
            wallet_id,
            &[
                (
                    "UTXO_RECEIVED".to_string(),
                    "{}".to_string(),
                    "test".to_string(),
                ),
                (
                    "UTXO_RECEIVED".to_string(),
                    "{}".to_string(),
                    "test".to_string(),
                ),
                (
                    "UTXO_RECEIVED".to_string(),
                    "{}".to_string(),
                    "test".to_string(),
                ),
                (
                    "UTXO_RECEIVED".to_string(),
                    "{}".to_string(),
                    "test".to_string(),
                ),
            ],
        )
        .await
        .unwrap();

    let missing = storage
        .validate_sequence_continuity(wallet_id)
        .await
        .unwrap();
    assert!(missing.is_empty());
}

#[cfg(feature = "storage")]
#[tokio::test]
async fn test_validate_sequence_continuity_with_gaps() {
    let storage = create_test_storage().await;
    let wallet_id = "gap-wallet";

    // Create events with gaps in sequence
    let events = vec![
        create_test_event_with_timestamp(
            "event-1",
            wallet_id,
            "UTXO_RECEIVED",
            1,
            SystemTime::now(),
            None,
        ),
        create_test_event_with_timestamp(
            "event-3",
            wallet_id,
            "UTXO_RECEIVED",
            3,
            SystemTime::now(),
            None,
        ),
        create_test_event_with_timestamp(
            "event-5",
            wallet_id,
            "UTXO_RECEIVED",
            5,
            SystemTime::now(),
            None,
        ),
        create_test_event_with_timestamp(
            "event-7",
            wallet_id,
            "UTXO_RECEIVED",
            7,
            SystemTime::now(),
            None,
        ),
    ];

    storage.store_events_batch(&events).await.unwrap();

    let missing = storage
        .validate_sequence_continuity(wallet_id)
        .await
        .unwrap();
    assert_eq!(missing, vec![2, 4, 6]);
}

#[cfg(feature = "storage")]
#[tokio::test]
async fn test_get_wallet_events_head_and_tail() {
    let storage = create_test_storage().await;
    let wallet_id = "head-tail-wallet";

    // Create 10 events
    let events_data: Vec<_> = (1..=10)
        .map(|i| {
            (
                "UTXO_RECEIVED".to_string(),
                format!("{{\"seq\": {}}}", i),
                "test".to_string(),
            )
        })
        .collect();

    storage
        .create_events_batch(wallet_id, &events_data)
        .await
        .unwrap();

    // Test head (first 3 events)
    let head_events = storage.get_wallet_events_head(wallet_id, 3).await.unwrap();
    assert_eq!(head_events.len(), 3);
    assert_eq!(head_events[0].sequence_number, 1);
    assert_eq!(head_events[1].sequence_number, 2);
    assert_eq!(head_events[2].sequence_number, 3);

    // Test tail (last 3 events, newest first)
    let tail_events = storage.get_wallet_events_tail(wallet_id, 3).await.unwrap();
    assert_eq!(tail_events.len(), 3);
    assert_eq!(tail_events[0].sequence_number, 10); // Newest first
    assert_eq!(tail_events[1].sequence_number, 9);
    assert_eq!(tail_events[2].sequence_number, 8);
}

#[cfg(feature = "storage")]
#[tokio::test]
async fn test_store_events_batch_transactional() {
    let storage = create_test_storage().await;
    let wallet_id = "transactional-wallet";

    // Create valid events
    let valid_events = vec![
        create_test_event_with_timestamp(
            "event-1",
            wallet_id,
            "UTXO_RECEIVED",
            1,
            SystemTime::now(),
            None,
        ),
        create_test_event_with_timestamp(
            "event-2",
            wallet_id,
            "UTXO_RECEIVED",
            2,
            SystemTime::now(),
            None,
        ),
    ];

    // Store valid batch
    let result = storage.store_events_batch(&valid_events).await;
    assert!(result.is_ok());

    let count = storage.get_event_count(wallet_id).await.unwrap();
    assert_eq!(count, 2);

    // Try to store batch with duplicate sequence (should fail completely)
    let invalid_events = vec![
        create_test_event_with_timestamp(
            "event-3",
            wallet_id,
            "UTXO_RECEIVED",
            3,
            SystemTime::now(),
            None,
        ),
        create_test_event_with_timestamp(
            "event-4",
            wallet_id,
            "UTXO_RECEIVED",
            2,
            SystemTime::now(),
            None,
        ), // Duplicate sequence
    ];

    let result = storage.store_events_batch(&invalid_events).await;
    assert!(result.is_err());

    // Count should still be 2 (transaction rolled back)
    let count = storage.get_event_count(wallet_id).await.unwrap();
    assert_eq!(count, 2);
}

#[cfg(feature = "storage")]
#[tokio::test]
async fn test_large_batch_operation() {
    let storage = create_test_storage().await;
    let wallet_id = "large-batch-wallet";

    // Create a large batch (100 events for faster testing)
    let large_batch: Vec<_> = (1..=100)
        .map(|i| {
            (
                if i % 2 == 0 {
                    "UTXO_RECEIVED"
                } else {
                    "UTXO_SPENT"
                }
                .to_string(),
                format!("{{\"seq\": {}}}", i),
                "test".to_string(),
            )
        })
        .collect();

    let start_time = std::time::Instant::now();
    let created_events = storage
        .create_events_batch(wallet_id, &large_batch)
        .await
        .unwrap();
    let duration = start_time.elapsed();

    // Verify all events were created
    assert_eq!(created_events.len(), 100);

    // Verify sequential numbering
    for (i, event) in created_events.iter().enumerate() {
        assert_eq!(event.sequence_number, (i + 1) as u64);
    }

    // Performance check (should complete within reasonable time)
    assert!(
        duration.as_secs() < 2,
        "Large batch took too long: {:?}",
        duration
    );

    // Verify counts by type
    let counts = storage.get_event_count_by_type(wallet_id).await.unwrap();
    assert_eq!(counts.get("UTXO_RECEIVED"), Some(&50));
    assert_eq!(counts.get("UTXO_SPENT"), Some(&50));
}

#[cfg(feature = "storage")]
#[tokio::test]
async fn test_multi_wallet_sequence_isolation() {
    let storage = create_test_storage().await;
    let wallet1 = "isolation-wallet-1";
    let wallet2 = "isolation-wallet-2";

    // Create events for wallet 1
    storage
        .create_events_batch(
            wallet1,
            &[
                (
                    "UTXO_RECEIVED".to_string(),
                    "{}".to_string(),
                    "test".to_string(),
                ),
                (
                    "UTXO_SPENT".to_string(),
                    "{}".to_string(),
                    "test".to_string(),
                ),
                (
                    "UTXO_RECEIVED".to_string(),
                    "{}".to_string(),
                    "test".to_string(),
                ),
            ],
        )
        .await
        .unwrap();

    // Create events for wallet 2
    storage
        .create_events_batch(
            wallet2,
            &[
                (
                    "UTXO_RECEIVED".to_string(),
                    "{}".to_string(),
                    "test".to_string(),
                ),
                (
                    "UTXO_RECEIVED".to_string(),
                    "{}".to_string(),
                    "test".to_string(),
                ),
            ],
        )
        .await
        .unwrap();

    // Verify sequence numbering is independent
    let wallet1_events = storage.get_wallet_events(wallet1).await.unwrap();
    let wallet2_events = storage.get_wallet_events(wallet2).await.unwrap();

    assert_eq!(wallet1_events.len(), 3);
    assert_eq!(wallet2_events.len(), 2);

    // Wallet 1 should have sequences 1, 2, 3
    for (i, event) in wallet1_events.iter().enumerate() {
        assert_eq!(event.sequence_number, (i + 1) as u64);
        assert_eq!(event.wallet_id, wallet1);
    }

    // Wallet 2 should have sequences 1, 2 (independent of wallet 1)
    for (i, event) in wallet2_events.iter().enumerate() {
        assert_eq!(event.sequence_number, (i + 1) as u64);
        assert_eq!(event.wallet_id, wallet2);
    }

    // Next sequence numbers should be independent
    let next_seq1 = storage.get_next_sequence_number(wallet1).await.unwrap();
    let next_seq2 = storage.get_next_sequence_number(wallet2).await.unwrap();
    assert_eq!(next_seq1, 4);
    assert_eq!(next_seq2, 3);
}
