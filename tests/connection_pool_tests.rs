//! Tests for connection pooling functionality
//!
//! This module verifies that the connection pool works correctly
//! for concurrent event storage operations.

#[cfg(feature = "storage")]
mod connection_pool_tests {
    use lightweight_wallet_libs::storage::{
        ConnectionPool, ConnectionPoolConfig, EventStorage, PooledSqliteEventStorage,
        SqliteConnectionOptions, StoredEvent,
    };
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};
    use tempfile::NamedTempFile;
    use tokio::sync::Barrier;

    async fn create_test_pool() -> ConnectionPool {
        let temp_file = NamedTempFile::new().unwrap();
        let database_path = temp_file.path().to_string_lossy().to_string();
        ConnectionPool::with_database_path(database_path)
            .await
            .unwrap()
    }

    async fn create_test_storage() -> PooledSqliteEventStorage {
        let temp_file = NamedTempFile::new().unwrap();
        let database_path = temp_file.path().to_string_lossy().to_string();
        PooledSqliteEventStorage::with_database_path(database_path)
            .await
            .unwrap()
    }

    fn create_test_event(wallet_id: &str, event_type: &str, sequence: u64) -> StoredEvent {
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

    #[tokio::test]
    async fn test_basic_pool_functionality() {
        let pool = create_test_pool().await;

        // Test basic connection acquisition
        let conn = pool.acquire().await.unwrap();
        assert!(conn
            .connection()
            .call(|conn| Ok(conn.execute("SELECT 1", [])))
            .await
            .is_ok());

        // Check pool stats
        let stats = pool.get_stats().await;
        assert_eq!(stats.connections_in_use, 1);
        assert_eq!(stats.total_acquisitions, 1);

        drop(conn); // Return connection to pool
        tokio::time::sleep(Duration::from_millis(10)).await; // Wait for async return

        let stats = pool.get_stats().await;
        assert_eq!(stats.connections_in_use, 0);
    }

    #[tokio::test]
    async fn test_concurrent_connection_acquisition() {
        let pool = Arc::new(create_test_pool().await);
        let barrier = Arc::new(Barrier::new(5));
        let mut handles = Vec::new();

        // Spawn 5 concurrent tasks that acquire connections
        for i in 0..5 {
            let pool_clone = pool.clone();
            let barrier_clone = barrier.clone();

            let handle = tokio::spawn(async move {
                barrier_clone.wait().await; // Synchronize start

                let conn = pool_clone.acquire().await.unwrap();

                // Simulate some database work
                let result = conn
                    .connection()
                    .call(move |conn| Ok(conn.execute("SELECT ?", [i]).map(|_| i)?))
                    .await
                    .unwrap();

                assert_eq!(result, i);

                // Hold connection for a bit
                tokio::time::sleep(Duration::from_millis(50)).await;

                result
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        let results: Vec<i32> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // Verify all tasks completed successfully
        assert_eq!(results.len(), 5);
        assert!(results.contains(&0));
        assert!(results.contains(&4));

        // Check final pool stats
        tokio::time::sleep(Duration::from_millis(100)).await; // Wait for connections to return
        let stats = pool.get_stats().await;
        assert_eq!(stats.connections_in_use, 0);
        assert_eq!(stats.total_acquisitions, 5);
    }

    #[tokio::test]
    async fn test_pool_configuration_options() {
        let temp_file = NamedTempFile::new().unwrap();
        let database_path = temp_file.path().to_string_lossy().to_string();

        let config = ConnectionPoolConfig {
            max_connections: 3,
            min_connections: 1,
            connection_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(10),
            database_path,
            sqlite_options: SqliteConnectionOptions::high_performance(),
        };

        let pool = ConnectionPool::new(config.clone()).await.unwrap();

        // Verify configuration
        assert_eq!(pool.get_config().max_connections, 3);
        assert_eq!(pool.get_config().min_connections, 1);

        // Verify initial connections
        let stats = pool.get_stats().await;
        assert_eq!(stats.active_connections, 1); // min_connections
    }

    #[tokio::test]
    async fn test_high_performance_pool() {
        let temp_file = NamedTempFile::new().unwrap();
        let database_path = temp_file.path().to_string_lossy().to_string();

        let pool = ConnectionPool::high_performance(database_path)
            .await
            .unwrap();

        let config = pool.get_config();
        assert_eq!(config.max_connections, 20);
        assert_eq!(config.min_connections, 5);
        assert_eq!(config.sqlite_options.cache_size_kb, 8192);
        assert!(config.sqlite_options.enable_wal_mode);
    }

    #[tokio::test]
    async fn test_pooled_event_storage_basic_operations() {
        let storage = create_test_storage().await;

        // Test storing an event
        let event = create_test_event("wallet1", "UTXO_RECEIVED", 1);
        let event_id = storage.store_event(&event).await.unwrap();
        assert!(event_id > 0);

        // Test retrieving the event
        let retrieved = storage.get_event_by_sequence("wallet1", 1).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().event_type, "UTXO_RECEIVED");

        // Test event count
        let count = storage.get_event_count("wallet1").await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_pooled_event_storage_concurrent_writes() {
        let storage = Arc::new(create_test_storage().await);
        let mut handles = Vec::new();

        // Spawn multiple concurrent tasks that write events
        for wallet_num in 0..5 {
            let storage_clone = storage.clone();

            let handle = tokio::spawn(async move {
                let wallet_id = format!("wallet{wallet_num}");
                let mut event_ids = Vec::new();

                // Each wallet writes 10 events
                for seq in 1..=10 {
                    let event = create_test_event(&wallet_id, "UTXO_RECEIVED", seq);
                    let event_id = storage_clone.store_event(&event).await.unwrap();
                    event_ids.push(event_id);
                }

                (wallet_id, event_ids)
            });

            handles.push(handle);
        }

        // Wait for all writes to complete
        let results = futures::future::join_all(handles).await;

        // Verify all writes succeeded
        assert_eq!(results.len(), 5);
        for result in results {
            let (wallet_id, event_ids) = result.unwrap();
            assert_eq!(event_ids.len(), 10);

            // Verify events were stored correctly
            let count = storage.get_event_count(&wallet_id).await.unwrap();
            assert_eq!(count, 10);
        }

        // Check pool statistics
        let pool_stats = storage.get_pool_stats().await;
        assert!(pool_stats.total_acquisitions >= 50); // At least 5 wallets * 10 events
    }

    #[tokio::test]
    async fn test_pooled_event_storage_batch_operations() {
        let storage = create_test_storage().await;

        // Create a batch of events
        let events = (1..=100)
            .map(|seq| create_test_event("wallet1", "UTXO_RECEIVED", seq))
            .collect::<Vec<_>>();

        // Store the batch
        let event_ids = storage.store_events_batch(&events).await.unwrap();
        assert_eq!(event_ids.len(), 100);

        // Verify all events were stored
        let count = storage.get_event_count("wallet1").await.unwrap();
        assert_eq!(count, 100);

        // Verify sequence continuity
        let missing = storage
            .validate_sequence_continuity("wallet1")
            .await
            .unwrap();
        assert!(missing.is_empty());
    }

    #[tokio::test]
    async fn test_connection_pool_timeout_handling() {
        let temp_file = NamedTempFile::new().unwrap();
        let database_path = temp_file.path().to_string_lossy().to_string();

        // Create a pool with very limited connections and short timeout
        let config = ConnectionPoolConfig {
            max_connections: 1,
            min_connections: 1,
            connection_timeout: Duration::from_millis(100),
            operation_timeout: Duration::from_secs(1),
            database_path,
            sqlite_options: SqliteConnectionOptions::default(),
        };

        let pool = ConnectionPool::new(config).await.unwrap();

        // Acquire the only connection and hold it
        let _held_conn = pool.acquire().await.unwrap();

        // Try to acquire another connection - should timeout quickly
        let timeout_result = pool.acquire().await;

        assert!(timeout_result.is_err());
        let stats = pool.get_stats().await;
        assert_eq!(stats.timeout_count, 1);
    }

    #[tokio::test]
    async fn test_pooled_storage_complex_queries() {
        let storage = create_test_storage().await;

        // Create events for multiple wallets and types
        let mut all_events = Vec::new();
        for wallet_num in 1..=3 {
            for seq in 1..=20 {
                let event_type = if seq % 3 == 0 {
                    "REORG"
                } else if seq % 2 == 0 {
                    "UTXO_SPENT"
                } else {
                    "UTXO_RECEIVED"
                };

                let event = create_test_event(&format!("wallet{wallet_num}"), event_type, seq);
                all_events.push(event);
            }
        }

        // Store all events
        let _event_ids = storage.store_events_batch(&all_events).await.unwrap();

        // Test complex queries
        let wallet1_events = storage.get_wallet_events("wallet1").await.unwrap();
        assert_eq!(wallet1_events.len(), 20);

        let wallet1_head = storage.get_wallet_events_head("wallet1", 5).await.unwrap();
        assert_eq!(wallet1_head.len(), 5);
        assert_eq!(wallet1_head[0].sequence_number, 1);

        let wallet1_tail = storage.get_wallet_events_tail("wallet1", 5).await.unwrap();
        assert_eq!(wallet1_tail.len(), 5);
        assert_eq!(wallet1_tail[0].sequence_number, 20); // Newest first

        let range_events = storage
            .get_wallet_events_in_range("wallet1", 5, 10)
            .await
            .unwrap();
        assert_eq!(range_events.len(), 6); // 5,6,7,8,9,10

        // Test storage statistics
        let stats = storage.get_storage_stats().await.unwrap();
        assert_eq!(stats.total_events, 60); // 3 wallets * 20 events
        assert_eq!(stats.unique_wallets, 3);
        assert_eq!(stats.events_by_type.len(), 3); // 3 event types
    }

    #[tokio::test]
    async fn test_connection_pool_resource_cleanup() {
        let pool = create_test_pool().await;

        // Acquire multiple connections
        let mut connections = Vec::new();
        for _ in 0..5 {
            connections.push(pool.acquire().await.unwrap());
        }

        let stats = pool.get_stats().await;
        assert_eq!(stats.connections_in_use, 5);

        // Drop all connections
        drop(connections);
        tokio::time::sleep(Duration::from_millis(50)).await; // Wait for async cleanup

        let stats = pool.get_stats().await;
        assert_eq!(stats.connections_in_use, 0);

        // Close the pool
        pool.close().await;

        let stats = pool.get_stats().await;
        assert_eq!(stats.active_connections, 0);
    }

    #[tokio::test]
    async fn test_operation_timeout_in_pooled_storage() {
        let storage = create_test_storage().await;

        // Test that operations complete within timeout
        let start = std::time::Instant::now();
        let event = create_test_event("wallet1", "UTXO_RECEIVED", 1);
        let _event_id = storage.store_event(&event).await.unwrap();
        let elapsed = start.elapsed();

        // Operation should complete well within the default timeout
        assert!(elapsed < Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_pooled_storage_automatic_methods() {
        let storage = create_test_storage().await;

        // Test automatic event creation methods
        let event = storage
            .create_event(
                "wallet1",
                "UTXO_RECEIVED",
                r#"{"amount": 100}"#.to_string(),
                "scanner",
            )
            .await
            .unwrap();

        assert_eq!(event.sequence_number, 1);
        assert_eq!(event.event_type, "UTXO_RECEIVED");
        assert_eq!(event.wallet_id, "wallet1");
        assert!(!event.event_id.is_empty());

        // Test event with correlation
        let correlated_event = storage
            .create_event_with_correlation(
                "wallet1",
                "UTXO_SPENT",
                r#"{"amount": 50}"#.to_string(),
                "scanner",
                "correlation-123".to_string(),
            )
            .await
            .unwrap();

        assert_eq!(correlated_event.sequence_number, 2);
        assert_eq!(
            correlated_event.correlation_id,
            Some("correlation-123".to_string())
        );

        // Test batch creation
        let batch_events = vec![
            (
                "REORG".to_string(),
                r#"{"height": 1000}"#.to_string(),
                "scanner".to_string(),
            ),
            (
                "REORG".to_string(),
                r#"{"height": 1001}"#.to_string(),
                "scanner".to_string(),
            ),
        ];

        let created_events = storage
            .create_events_batch("wallet1", &batch_events)
            .await
            .unwrap();

        assert_eq!(created_events.len(), 2);
        assert_eq!(created_events[0].sequence_number, 3);
        assert_eq!(created_events[1].sequence_number, 4);

        // Verify total count
        let count = storage.get_event_count("wallet1").await.unwrap();
        assert_eq!(count, 4);
    }
}
