//! Database integrity tests for event storage
//!
//! This module provides comprehensive tests to verify database integrity,
//! including schema validation, constraint enforcement, corruption detection,
//! and transaction atomicity for the event storage system.

#[cfg(feature = "storage")]
mod database_integrity_tests {
    use crate::common::create_test_connection;
    use lightweight_wallet_libs::storage::event_storage::{
        EventStorage, SqliteEventStorage, StoredEvent,
    };
    use std::time::SystemTime;

    /// Test that the database schema is correctly created with all required constraints
    #[tokio::test]
    async fn test_schema_integrity() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let _storage = SqliteEventStorage::new(conn.clone()).await?;

        // Verify the wallet_events table exists with correct schema
        let table_info = conn
            .call(|conn| {
                let mut stmt = conn.prepare("PRAGMA table_info(wallet_events)")?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>("name")?,
                        row.get::<_, String>("type")?,
                        row.get::<_, bool>("notnull")?,
                        row.get::<_, bool>("pk")?,
                    ))
                })?;

                let mut columns = Vec::new();
                for row in rows {
                    columns.push(row?);
                }
                Ok(columns)
            })
            .await?;

        // Expected columns with their properties
        let expected_columns = vec![
            ("id", "INTEGER", false, true),
            ("event_id", "TEXT", true, false),
            ("wallet_id", "TEXT", true, false),
            ("event_type", "TEXT", true, false),
            ("sequence_number", "INTEGER", true, false),
            ("payload_json", "TEXT", true, false),
            ("metadata_json", "TEXT", true, false),
            ("source", "TEXT", true, false),
            ("correlation_id", "TEXT", false, false),
            ("timestamp", "INTEGER", true, false),
            ("stored_at", "INTEGER", true, false),
        ];

        assert_eq!(table_info.len(), expected_columns.len());

        for (name, type_str, notnull, pk) in expected_columns {
            let found = table_info
                .iter()
                .find(|(col_name, _, _, _)| col_name == name);
            assert!(found.is_some(), "Column '{}' not found", name);

            let (_, col_type, col_notnull, col_pk) = found.unwrap();
            assert_eq!(col_type, type_str, "Column '{}' has wrong type", name);
            assert_eq!(
                col_notnull, &notnull,
                "Column '{}' has wrong NOT NULL constraint",
                name
            );
            assert_eq!(
                col_pk, &pk,
                "Column '{}' has wrong PRIMARY KEY constraint",
                name
            );
        }

        Ok(())
    }

    /// Test that all required indexes are created
    #[tokio::test]
    async fn test_index_integrity() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let _storage = SqliteEventStorage::new(conn.clone()).await?;

        // Get all indexes on the wallet_events table
        let indexes = conn
            .call(|conn| {
                let mut stmt = conn.prepare("PRAGMA index_list(wallet_events)")?;
                let rows = stmt.query_map([], |row| Ok(row.get::<_, String>("name")?))?;

                let mut index_names = Vec::new();
                for row in rows {
                    index_names.push(row?);
                }
                Ok(index_names)
            })
            .await?;

        // Expected indexes (excluding sqlite_autoindex which is automatic)
        let expected_indexes = vec![
            "idx_events_wallet_id",
            "idx_events_event_type",
            "idx_events_sequence",
            "idx_events_timestamp",
            "idx_events_correlation",
            "idx_events_source",
            "idx_events_stored_at",
            "idx_events_wallet_type",
            "idx_events_wallet_time",
            "idx_events_type_time",
        ];

        for expected_index in expected_indexes {
            assert!(
                indexes.iter().any(|name| name == expected_index),
                "Index '{}' not found",
                expected_index
            );
        }

        Ok(())
    }

    /// Test that unique constraints are properly enforced
    #[tokio::test]
    async fn test_unique_constraint_integrity() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn).await?;

        // Test unique event_id constraint
        let event1 = create_test_stored_event("wallet1", "UTXO_RECEIVED", 1);
        let mut event2 = create_test_stored_event("wallet1", "UTXO_SPENT", 2);
        event2.event_id = event1.event_id.clone(); // Same event ID

        // First insert should succeed
        storage.store_event(&event1).await?;

        // Second insert with same event_id should fail
        let result = storage.store_event(&event2).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("UNIQUE constraint failed"));

        Ok(())
    }

    /// Test that wallet_id + sequence_number unique constraint is enforced
    #[tokio::test]
    async fn test_sequence_uniqueness_constraint() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn).await?;

        // Create two events with same wallet_id and sequence_number
        let event1 = create_test_stored_event("wallet1", "UTXO_RECEIVED", 1);
        let event2 = create_test_stored_event("wallet1", "UTXO_SPENT", 1); // Same sequence

        // First insert should succeed
        storage.store_event(&event1).await?;

        // Second insert with same wallet_id + sequence should fail
        let result = storage.store_event(&event2).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("UNIQUE constraint failed"));

        // But different wallet_id with same sequence should work
        let event3 = create_test_stored_event("wallet2", "UTXO_RECEIVED", 1);
        storage.store_event(&event3).await?;

        Ok(())
    }

    /// Test that database triggers are properly installed and functional
    #[tokio::test]
    async fn test_trigger_integrity() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let _storage = SqliteEventStorage::new(conn.clone()).await?;

        // Get list of triggers
        let triggers = conn
            .call(|conn| {
                let mut stmt =
                    conn.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'trigger'")?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>("name")?,
                        row.get::<_, Option<String>>("sql")?,
                    ))
                })?;

                let mut trigger_info = Vec::new();
                for row in rows {
                    trigger_info.push(row?);
                }
                Ok(trigger_info)
            })
            .await?;

        // Verify the required triggers exist
        let expected_triggers = vec!["prevent_event_updates", "prevent_event_deletes"];

        for expected_trigger in expected_triggers {
            assert!(
                triggers.iter().any(|(name, _)| name == expected_trigger),
                "Trigger '{}' not found",
                expected_trigger
            );
        }

        // Verify trigger SQL contains expected ABORT behavior
        for (name, sql) in triggers {
            if name.starts_with("prevent_event_") {
                let sql = sql.unwrap_or_default();
                assert!(
                    sql.contains("RAISE(ABORT"),
                    "Trigger '{}' should contain RAISE(ABORT)",
                    name
                );
                assert!(
                    sql.contains("append-only table"),
                    "Trigger '{}' should contain 'append-only table' message",
                    name
                );
            }
        }

        Ok(())
    }

    /// Test transaction atomicity for batch operations
    #[tokio::test]
    async fn test_transaction_atomicity() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn).await?;

        // Create a batch with one valid and one invalid event (duplicate sequence)
        let valid_event = create_test_stored_event("wallet1", "UTXO_RECEIVED", 1);
        let invalid_event = create_test_stored_event("wallet1", "UTXO_SPENT", 1); // Duplicate sequence

        let events = vec![valid_event, invalid_event];

        // The batch insert should fail completely
        let result = storage.store_events_batch(&events).await;
        assert!(result.is_err());

        // Verify no events were inserted (atomic rollback)
        let stored_events = storage.get_wallet_events("wallet1").await?;
        assert_eq!(stored_events.len(), 0);

        Ok(())
    }

    /// Test database consistency after simulated corruption scenarios
    #[tokio::test]
    async fn test_corruption_detection() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn.clone()).await?;

        // Insert some valid events
        let events = vec![
            create_test_stored_event("wallet1", "UTXO_RECEIVED", 1),
            create_test_stored_event("wallet1", "UTXO_SPENT", 2),
            create_test_stored_event("wallet1", "REORG", 3),
        ];
        storage.store_events_batch(&events).await?;

        // Verify sequence continuity (should be valid)
        let missing_sequences = storage.validate_sequence_continuity("wallet1").await?;
        assert!(missing_sequences.is_empty());

        // Simulate corruption by manually inserting an event with a gap (bypassing triggers)
        // Note: In a real database, this would require disabling triggers temporarily
        // For this test, we'll verify that our validation can detect gaps

        // Insert event with sequence 5 (creating a gap at 4)
        let gap_event = create_test_stored_event("wallet1", "UTXO_RECEIVED", 5);
        storage.store_event(&gap_event).await?;

        // Now validate_sequence_continuity should detect the gap
        let missing_sequences = storage.validate_sequence_continuity("wallet1").await?;
        assert_eq!(missing_sequences, vec![4]);

        Ok(())
    }

    /// Test database integrity after concurrent operations
    #[tokio::test]
    async fn test_concurrent_integrity() -> Result<(), Box<dyn std::error::Error>> {
        // Note: SQLiteEventStorage doesn't implement Clone, so we'll test sequential operations
        // that simulate concurrent scenarios by rapid sequential insertions
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn).await?;

        // Simulate concurrent operations by rapid sequential insertions
        let mut all_events = Vec::new();

        for i in 0..10 {
            let wallet_id = format!("wallet{i}");
            // Each wallet gets 10 events
            for seq in 1..=10 {
                let event = create_test_stored_event(&wallet_id, "UTXO_RECEIVED", seq);
                all_events.push((wallet_id.clone(), event));
            }
        }

        // Insert all events rapidly
        for (_wallet_id, event) in all_events {
            storage.store_event(&event).await?;
        }

        // Verify integrity for all wallets
        for i in 0..10 {
            let wallet_id = format!("wallet{i}");
            let events = storage.get_wallet_events(&wallet_id).await?;
            assert_eq!(events.len(), 10);

            // Verify sequence numbers are continuous
            let missing_sequences = storage.validate_sequence_continuity(&wallet_id).await?;
            assert!(
                missing_sequences.is_empty(),
                "Wallet {} has missing sequences: {:?}",
                wallet_id,
                missing_sequences
            );
        }

        Ok(())
    }

    /// Test storage statistics integrity
    #[tokio::test]
    async fn test_storage_stats_integrity() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn).await?;

        // Initially, stats should be empty
        let stats = storage.get_storage_stats().await?;
        assert_eq!(stats.total_events, 0);
        assert_eq!(stats.unique_wallets, 0);
        assert!(stats.events_by_type.is_empty());

        // Insert events for multiple wallets
        let events = vec![
            create_test_stored_event("wallet1", "UTXO_RECEIVED", 1),
            create_test_stored_event("wallet1", "UTXO_SPENT", 2),
            create_test_stored_event("wallet2", "UTXO_RECEIVED", 1),
            create_test_stored_event("wallet2", "REORG", 2),
        ];
        storage.store_events_batch(&events).await?;

        // Verify stats are accurate
        let stats = storage.get_storage_stats().await?;
        assert_eq!(stats.total_events, 4);
        assert_eq!(stats.unique_wallets, 2);

        // Check event type counts
        assert_eq!(stats.events_by_type.get("UTXO_RECEIVED"), Some(&2));
        assert_eq!(stats.events_by_type.get("UTXO_SPENT"), Some(&1));
        assert_eq!(stats.events_by_type.get("REORG"), Some(&1));

        // Verify timestamps are reasonable
        assert!(stats.oldest_event.is_some());
        assert!(stats.newest_event.is_some());
        assert!(stats.oldest_event.unwrap() <= stats.newest_event.unwrap());

        Ok(())
    }

    /// Test database vacuum and maintenance operations don't break integrity
    #[tokio::test]
    async fn test_maintenance_integrity() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn.clone()).await?;

        // Insert test data
        let events = vec![
            create_test_stored_event("wallet1", "UTXO_RECEIVED", 1),
            create_test_stored_event("wallet1", "UTXO_SPENT", 2),
        ];
        storage.store_events_batch(&events).await?;

        // Perform VACUUM operation
        conn.call(|conn| Ok(conn.execute("VACUUM", [])?)).await?;

        // Verify data integrity after vacuum
        let stored_events = storage.get_wallet_events("wallet1").await?;
        assert_eq!(stored_events.len(), 2);

        // Verify triggers still work after vacuum
        let result = conn
            .call(|conn| {
                Ok(conn.execute(
                    "UPDATE wallet_events SET event_type = 'MODIFIED' WHERE sequence_number = 1",
                    [],
                )?)
            })
            .await;
        assert!(result.is_err());

        // Perform ANALYZE operation
        conn.call(|conn| Ok(conn.execute("ANALYZE", [])?)).await?;

        // Verify data integrity after analyze
        let stored_events = storage.get_wallet_events("wallet1").await?;
        assert_eq!(stored_events.len(), 2);

        Ok(())
    }

    /// Test foreign key constraints (if any are added in the future)
    #[tokio::test]
    async fn test_foreign_key_integrity() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let _storage = SqliteEventStorage::new(conn.clone()).await?;

        // Check if foreign keys are enabled
        let fk_enabled = conn
            .call(|conn| {
                let mut stmt = conn.prepare("PRAGMA foreign_keys")?;
                let enabled: i32 = stmt.query_row([], |row| row.get(0))?;
                Ok(enabled != 0)
            })
            .await?;

        // Currently, the schema doesn't use foreign keys, but this test ensures
        // that if they are added in the future, they work correctly
        if fk_enabled {
            // Test would go here if foreign keys are used
            println!("Foreign keys are enabled - ready for FK constraint testing");
        } else {
            println!("Foreign keys not enabled - skipping FK constraint tests");
        }

        Ok(())
    }

    /// Test database file integrity and checkpoint operations
    #[tokio::test]
    async fn test_checkpoint_integrity() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let storage = SqliteEventStorage::new(conn.clone()).await?;

        // Insert test data
        let events = vec![
            create_test_stored_event("wallet1", "UTXO_RECEIVED", 1),
            create_test_stored_event("wallet1", "UTXO_SPENT", 2),
        ];
        storage.store_events_batch(&events).await?;

        // Force checkpoint (if using WAL mode)
        let _checkpoint_result = conn
            .call(|conn| {
                // This may fail if not in WAL mode, which is fine
                let _ = conn.execute("PRAGMA wal_checkpoint", []);
                Ok(())
            })
            .await;

        // Verify data integrity after checkpoint
        let stored_events = storage.get_wallet_events("wallet1").await?;
        assert_eq!(stored_events.len(), 2);

        // Verify sequences are still valid
        let missing_sequences = storage.validate_sequence_continuity("wallet1").await?;
        assert!(missing_sequences.is_empty());

        Ok(())
    }

    /// Test that database schema version can be verified
    #[tokio::test]
    async fn test_schema_version_integrity() -> Result<(), Box<dyn std::error::Error>> {
        let conn = create_test_connection().await?;
        let _storage = SqliteEventStorage::new(conn.clone()).await?;

        // Check that we can verify the database was created correctly
        let tables = conn
            .call(|conn| {
                let mut stmt =
                    conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?;
                let rows = stmt.query_map([], |row| Ok(row.get::<_, String>(0)?))?;

                let mut table_names = Vec::new();
                for row in rows {
                    table_names.push(row?);
                }
                Ok(table_names)
            })
            .await?;

        // wallet_events table must exist
        assert!(tables.contains(&"wallet_events".to_string()));

        // Check for the existence of the recent_wallet_events view
        let views = conn
            .call(|conn| {
                let mut stmt =
                    conn.prepare("SELECT name FROM sqlite_master WHERE type = 'view'")?;
                let rows = stmt.query_map([], |row| Ok(row.get::<_, String>(0)?))?;

                let mut view_names = Vec::new();
                for row in rows {
                    view_names.push(row?);
                }
                Ok(view_names)
            })
            .await?;

        assert!(views.contains(&"recent_wallet_events".to_string()));

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
