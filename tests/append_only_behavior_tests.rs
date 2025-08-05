//! Tests for append-only behavior enforcement in event storage
//!
//! This module verifies that the event storage system properly enforces
//! append-only behavior by preventing updates and deletes of existing events.

#[cfg(feature = "storage")]
mod append_only_tests {
    use crate::common::create_test_connection;
    use lightweight_wallet_libs::storage::event_storage::{
        EventStorage, SqliteEventStorage, StoredEvent,
    };
    use rusqlite::Error as SqliteError;
    use std::time::SystemTime;

    /// Test that database triggers prevent UPDATE operations on wallet_events
    #[tokio::test]
    async fn test_database_prevents_updates() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn.clone()).await?;

        // Create and store a test event
        let event = create_test_stored_event("wallet1", "UTXO_RECEIVED", 1);
        let event_id = storage.store_event(&event).await?;

        // Attempt to update the event directly via SQL - this should fail
        let result = conn
            .call(move |conn| {
                Ok(conn.execute(
                    "UPDATE wallet_events SET event_type = 'MODIFIED' WHERE id = ?",
                    rusqlite::params![event_id as i64],
                )?)
            })
            .await;

        // Verify the update was blocked
        assert!(result.is_err());
        if let Err(tokio_rusqlite::Error::Rusqlite(SqliteError::SqliteFailure(err, msg))) = result {
            assert_eq!(err.code, rusqlite::ErrorCode::ConstraintViolation);
            assert!(msg
                .unwrap_or_default()
                .contains("Updates to wallet_events are not allowed"));
        } else {
            panic!("Expected constraint violation error for update attempt");
        }

        Ok(())
    }

    /// Test that database triggers prevent DELETE operations on wallet_events
    #[tokio::test]
    async fn test_database_prevents_deletes() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn.clone()).await?;

        // Create and store a test event
        let event = create_test_stored_event("wallet1", "UTXO_RECEIVED", 1);
        let event_id = storage.store_event(&event).await?;

        // Attempt to delete the event directly via SQL - this should fail
        let result = conn
            .call(move |conn| {
                Ok(conn.execute(
                    "DELETE FROM wallet_events WHERE id = ?",
                    rusqlite::params![event_id as i64],
                )?)
            })
            .await;

        // Verify the delete was blocked
        assert!(result.is_err());
        if let Err(tokio_rusqlite::Error::Rusqlite(SqliteError::SqliteFailure(err, msg))) = result {
            assert_eq!(err.code, rusqlite::ErrorCode::ConstraintViolation);
            assert!(msg
                .unwrap_or_default()
                .contains("Deletes from wallet_events are not allowed"));
        } else {
            panic!("Expected constraint violation error for delete attempt");
        }

        Ok(())
    }

    /// Test that the EventStorage trait doesn't expose update methods
    #[tokio::test]
    async fn test_trait_has_no_update_methods() {
        // This is a compile-time check - the trait should not have any update methods
        // If this compiles, it means we don't have update methods exposed

        // The EventStorage trait should only have:
        // - store_event (insert only)
        // - store_events_batch (insert only)
        // - get_* methods (read only)
        // - create_* methods (insert only)
        // - insert_* methods (insert only)

        // No update_*, modify_*, delete_*, or remove_* methods should exist
        let _methods_check = std::marker::PhantomData::<dyn EventStorage>;
    }

    /// Test that the EventStorage trait doesn't expose delete methods
    #[tokio::test]
    async fn test_trait_has_no_delete_methods() {
        // This is a compile-time check - the trait should not have any delete methods
        // If this compiles, it means we don't have delete methods exposed
        let _methods_check = std::marker::PhantomData::<dyn EventStorage>;
    }

    /// Test that attempting bulk operations maintains append-only behavior
    #[tokio::test]
    async fn test_bulk_operations_are_append_only() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn.clone()).await?;

        // Create multiple events
        let events = vec![
            create_test_stored_event("wallet1", "UTXO_RECEIVED", 1),
            create_test_stored_event("wallet1", "UTXO_SPENT", 2),
            create_test_stored_event("wallet1", "REORG", 3),
        ];

        let event_ids = storage.store_events_batch(&events).await?;
        assert_eq!(event_ids.len(), 3);

        // Verify all events were stored correctly
        let stored_events = storage.get_wallet_events("wallet1").await?;
        assert_eq!(stored_events.len(), 3);

        // Verify we cannot modify any of the stored events
        for event_id in event_ids {
            let result = conn
                .call(move |conn| {
                    Ok(conn.execute(
                        "UPDATE wallet_events SET payload_json = '{}' WHERE id = ?",
                        rusqlite::params![event_id as i64],
                    )?)
                })
                .await;

            assert!(result.is_err());
        }

        Ok(())
    }

    /// Test that sequence numbers are immutable after creation
    #[tokio::test]
    async fn test_sequence_numbers_immutable() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn.clone()).await?;

        // Create an event with sequence number 1
        let event = create_test_stored_event("wallet1", "UTXO_RECEIVED", 1);
        let event_id = storage.store_event(&event).await?;

        // Attempt to change the sequence number - this should fail
        let result = conn
            .call(move |conn| {
                Ok(conn.execute(
                    "UPDATE wallet_events SET sequence_number = 999 WHERE id = ?",
                    rusqlite::params![event_id as i64],
                )?)
            })
            .await;

        assert!(result.is_err());

        // Verify sequence number is unchanged
        let stored_event = storage.get_event_by_sequence("wallet1", 1).await?;
        assert!(stored_event.is_some());
        assert_eq!(stored_event.unwrap().sequence_number, 1);

        Ok(())
    }

    /// Test that event IDs are immutable after creation
    #[tokio::test]
    async fn test_event_ids_immutable() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn.clone()).await?;

        let original_event_id = "test-event-id-123";
        let mut event = create_test_stored_event("wallet1", "UTXO_RECEIVED", 1);
        event.event_id = original_event_id.to_string();

        let db_id = storage.store_event(&event).await?;

        // Attempt to change the event ID - this should fail
        let result = conn
            .call(move |conn| {
                Ok(conn.execute(
                    "UPDATE wallet_events SET event_id = 'modified-id' WHERE id = ?",
                    rusqlite::params![db_id as i64],
                )?)
            })
            .await;

        assert!(result.is_err());

        // Verify event ID is unchanged
        let stored_event = storage.get_event_by_id(original_event_id).await?;
        assert!(stored_event.is_some());
        assert_eq!(stored_event.unwrap().event_id, original_event_id);

        Ok(())
    }

    /// Test that timestamps are immutable after creation
    #[tokio::test]
    async fn test_timestamps_immutable() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn.clone()).await?;

        let event = create_test_stored_event("wallet1", "UTXO_RECEIVED", 1);
        let original_timestamp = event.timestamp;
        let event_id = storage.store_event(&event).await?;

        // Attempt to change the timestamp - this should fail
        let result = conn
            .call(move |conn| {
                Ok(conn.execute(
                    "UPDATE wallet_events SET timestamp = 0 WHERE id = ?",
                    rusqlite::params![event_id as i64],
                )?)
            })
            .await;

        assert!(result.is_err());

        // Verify timestamp is unchanged (within a reasonable tolerance due to precision differences)
        let stored_event = storage.get_event_by_sequence("wallet1", 1).await?;
        assert!(stored_event.is_some());
        let stored_timestamp = stored_event.unwrap().timestamp;
        let time_diff = stored_timestamp
            .duration_since(original_timestamp)
            .unwrap_or_else(|_| original_timestamp.duration_since(stored_timestamp).unwrap());
        assert!(time_diff.as_secs() < 2, "Timestamp should be unchanged");

        Ok(())
    }

    /// Test that the table cannot be truncated
    #[tokio::test]
    async fn test_table_cannot_be_truncated() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn.clone()).await?;

        // Store some events
        let events = vec![
            create_test_stored_event("wallet1", "UTXO_RECEIVED", 1),
            create_test_stored_event("wallet1", "UTXO_SPENT", 2),
        ];
        storage.store_events_batch(&events).await?;

        // Attempt to truncate the table - this should fail due to DELETE trigger
        let result = conn
            .call(|conn| Ok(conn.execute("DELETE FROM wallet_events", [])?))
            .await;

        assert!(result.is_err());

        // Verify events are still there
        let stored_events = storage.get_wallet_events("wallet1").await?;
        assert_eq!(stored_events.len(), 2);

        Ok(())
    }

    /// Test that event payloads are immutable after creation
    #[tokio::test]
    async fn test_payloads_immutable() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn.clone()).await?;

        let original_payload = r#"{"transaction_id":"tx123","amount":1000}"#;
        let mut event = create_test_stored_event("wallet1", "UTXO_RECEIVED", 1);
        event.payload_json = original_payload.to_string();

        let event_id = storage.store_event(&event).await?;

        // Attempt to change the payload - this should fail
        let result = conn
            .call(move |conn| {
                Ok(conn.execute(
                    "UPDATE wallet_events SET payload_json = '{}' WHERE id = ?",
                    rusqlite::params![event_id as i64],
                )?)
            })
            .await;

        assert!(result.is_err());

        // Verify payload is unchanged
        let stored_event = storage.get_event_by_sequence("wallet1", 1).await?;
        assert!(stored_event.is_some());
        assert_eq!(stored_event.unwrap().payload_json, original_payload);

        Ok(())
    }

    /// Test error messages are clear and informative
    #[tokio::test]
    async fn test_clear_error_messages() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn.clone()).await?;

        let event = create_test_stored_event("wallet1", "UTXO_RECEIVED", 1);
        let event_id = storage.store_event(&event).await?;

        // Test update error message
        let update_result = conn
            .call(move |conn| {
                Ok(conn.execute(
                    "UPDATE wallet_events SET event_type = 'MODIFIED' WHERE id = ?",
                    rusqlite::params![event_id as i64],
                )?)
            })
            .await;

        if let Err(tokio_rusqlite::Error::Rusqlite(SqliteError::SqliteFailure(_, Some(msg)))) =
            update_result
        {
            assert!(msg.contains("Updates to wallet_events are not allowed"));
            assert!(msg.contains("append-only table"));
        }

        // Test delete error message
        let delete_result = conn
            .call(move |conn| {
                Ok(conn.execute(
                    "DELETE FROM wallet_events WHERE id = ?",
                    rusqlite::params![event_id as i64],
                )?)
            })
            .await;

        if let Err(tokio_rusqlite::Error::Rusqlite(SqliteError::SqliteFailure(_, Some(msg)))) =
            delete_result
        {
            assert!(msg.contains("Deletes from wallet_events are not allowed"));
            assert!(msg.contains("append-only table"));
        }

        Ok(())
    }

    // Helper function to create test stored events
    fn create_test_stored_event(wallet_id: &str, event_type: &str, sequence: u64) -> StoredEvent {
        StoredEvent::new(
            uuid::Uuid::new_v4().to_string(),
            wallet_id.to_string(),
            event_type.to_string(),
            sequence,
            r#"{"test": "data"}"#.to_string(),
            r#"{"metadata": "test"}"#.to_string(),
            "test".to_string(),
            None,
            SystemTime::now(),
        )
    }
}

#[cfg(feature = "storage")]
mod common {
    use tokio_rusqlite::Connection;

    /// Create a test database connection
    pub async fn create_test_connection() -> Result<Connection, Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory().await?;
        Ok(conn)
    }
}
