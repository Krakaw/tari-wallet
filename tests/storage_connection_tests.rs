//! Database connection and infrastructure tests for SQLite storage
//!
//! These tests focus on database connection handling, error scenarios,
//! and infrastructure resilience to improve coverage of critical storage paths.

#[cfg(feature = "storage")]
use std::sync::Arc;
#[cfg(feature = "storage")]
use std::time::Duration;
#[cfg(feature = "storage")]
use tempfile::TempDir;
#[cfg(feature = "storage")]
use tokio::task::JoinSet;
#[cfg(feature = "storage")]
use tokio::time::timeout;

#[cfg(feature = "storage")]
use lightweight_wallet_libs::{
    data_structures::types::PrivateKey,
    errors::WalletError,
    storage::{sqlite::SqliteStorage, SqlitePerformanceConfig, StoredWallet, WalletStorage},
};

#[cfg(feature = "storage")]
mod connection_tests {
    use super::*;

    #[tokio::test]
    async fn test_database_file_creation() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_wallet.db");

        // Ensure database file doesn't exist initially
        assert!(!db_path.exists());

        // Create storage - should create the file
        let storage = SqliteStorage::new(&db_path).await.unwrap();
        storage.initialize().await.unwrap();

        // Verify file was created
        assert!(db_path.exists());

        // Verify we can open it again
        let storage2 = SqliteStorage::new(&db_path).await.unwrap();
        storage2.initialize().await.unwrap();
    }

    #[tokio::test]
    async fn test_invalid_database_path() {
        // Try to create database in non-existent directory
        let invalid_path = "/non/existent/directory/wallet.db";

        let result = SqliteStorage::new(invalid_path).await;
        assert!(result.is_err());

        if let Err(WalletError::StorageError(msg)) = result {
            assert!(msg.contains("Failed to open SQLite database"));
        } else {
            panic!("Expected StorageError");
        }
    }

    #[tokio::test]
    async fn test_readonly_directory_database_creation() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let readonly_dir = temp_dir.path().join("readonly");
        std::fs::create_dir(&readonly_dir).unwrap();

        // Make directory readonly (Unix-like systems)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&readonly_dir).unwrap().permissions();
            perms.set_mode(0o444); // Read-only
            std::fs::set_permissions(&readonly_dir, perms).unwrap();
        }

        let db_path = readonly_dir.join("wallet.db");
        let result = SqliteStorage::new(&db_path).await;

        // Should fail on readonly directory
        #[cfg(unix)]
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_in_memory_database_isolation() {
        // Create two in-memory databases
        let storage1 = SqliteStorage::new_in_memory().await.unwrap();
        let storage2 = SqliteStorage::new_in_memory().await.unwrap();

        storage1.initialize().await.unwrap();
        storage2.initialize().await.unwrap();

        // Create a wallet in storage1
        let view_key = PrivateKey::new([1u8; 32]);
        let spend_key = PrivateKey::new([2u8; 32]);
        let wallet = StoredWallet::from_keys("test1".to_string(), view_key, spend_key, 100);
        storage1.save_wallet(&wallet).await.unwrap();

        // Verify it doesn't exist in storage2
        let wallets1 = storage1.list_wallets().await.unwrap();
        let wallets2 = storage2.list_wallets().await.unwrap();

        assert_eq!(wallets1.len(), 1);
        assert_eq!(wallets2.len(), 0);
    }

    #[tokio::test]
    async fn test_concurrent_database_access() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("concurrent_test.db");

        // Create and initialize the database
        let storage = SqliteStorage::new(&db_path).await.unwrap();
        storage.initialize().await.unwrap();
        drop(storage); // Close initial connection

        let db_path = Arc::new(db_path);
        let mut join_set = JoinSet::new();

        // Spawn multiple concurrent tasks
        for i in 0..5 {
            let path = Arc::clone(&db_path);
            join_set.spawn(async move {
                let storage = SqliteStorage::new(path.as_ref()).await.unwrap();
                storage.initialize().await.unwrap();

                // Create a unique wallet
                let wallet_name = format!("wallet_{i}");
                let view_key = PrivateKey::new([(i as u8 + 1); 32]);
                let spend_key = PrivateKey::new([(i as u8 + 2); 32]);
                let wallet =
                    StoredWallet::from_keys(wallet_name.clone(), view_key, spend_key, i * 100);
                storage.save_wallet(&wallet).await.unwrap();

                // Verify we can read it back
                let wallets = storage.list_wallets().await.unwrap();
                assert!(wallets.iter().any(|w| w.name == wallet_name));

                i
            });
        }

        // Wait for all tasks to complete
        let mut results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            results.push(result.unwrap());
        }

        // Verify all operations succeeded
        assert_eq!(results.len(), 5);

        // Verify final state
        let final_storage = SqliteStorage::new(db_path.as_ref()).await.unwrap();
        final_storage.initialize().await.unwrap();
        let wallets = final_storage.list_wallets().await.unwrap();
        assert_eq!(wallets.len(), 5);
    }

    #[tokio::test]
    async fn test_database_connection_timeout() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        // Test operation with timeout
        let result = timeout(Duration::from_millis(100), async {
            storage.get_statistics().await
        })
        .await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_database_reopen_after_close() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("reopen_test.db");

        // Create database and add some data
        {
            let storage = SqliteStorage::new(&db_path).await.unwrap();
            storage.initialize().await.unwrap();
            let view_key = PrivateKey::new([1u8; 32]);
            let spend_key = PrivateKey::new([2u8; 32]);
            let wallet =
                StoredWallet::from_keys("test_wallet".to_string(), view_key, spend_key, 100);
            storage.save_wallet(&wallet).await.unwrap();
        } // Storage drops here, closing connection

        // Reopen database and verify data persists
        {
            let storage = SqliteStorage::new(&db_path).await.unwrap();
            storage.initialize().await.unwrap();
            let wallets = storage.list_wallets().await.unwrap();
            assert_eq!(wallets.len(), 1);
            assert_eq!(wallets[0].name, "test_wallet");
        }
    }

    #[tokio::test]
    async fn test_database_schema_initialization_idempotent() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();

        // Initialize multiple times - should not error
        storage.initialize().await.unwrap();
        storage.initialize().await.unwrap();
        storage.initialize().await.unwrap();

        // Should still work normally
        let stats = storage.get_statistics().await.unwrap();
        assert_eq!(stats.total_transactions, 0);
    }

    #[tokio::test]
    async fn test_database_corruption_detection() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("corruption_test.db");

        // Create and initialize database
        {
            let storage = SqliteStorage::new(&db_path).await.unwrap();
            storage.initialize().await.unwrap();
            let view_key = PrivateKey::new([1u8; 32]);
            let spend_key = PrivateKey::new([2u8; 32]);
            let wallet = StoredWallet::from_keys("test".to_string(), view_key, spend_key, 100);
            storage.save_wallet(&wallet).await.unwrap();
        }

        // Corrupt the database file by writing garbage
        std::fs::write(&db_path, b"This is not a valid SQLite database").unwrap();

        // Also corrupt WAL and SHM files if they exist (WAL mode creates these)
        let wal_path = db_path.with_extension("db-wal");
        let shm_path = db_path.with_extension("db-shm");

        if wal_path.exists() {
            std::fs::write(&wal_path, b"corrupted wal").unwrap();
        }
        if shm_path.exists() {
            std::fs::write(&shm_path, b"corrupted shm").unwrap();
        }

        // SQLite's open() doesn't validate format - corruption is detected on actual use
        // Use minimal config to ensure corruption detection works
        let storage_result =
            SqliteStorage::new_with_config(&db_path, SqlitePerformanceConfig::minimal()).await;

        // Check if storage creation itself detected corruption
        if storage_result.is_err() {
            // Expected - corruption detected during storage creation
            if let Err(WalletError::StorageError(msg)) = storage_result {
                assert!(
                    msg.contains("database")
                        || msg.contains("SQL")
                        || msg.contains("corrupt")
                        || msg.contains("not a database"),
                    "Expected database error message, got: {}",
                    msg
                );
            } else {
                panic!("Expected StorageError for corrupted database");
            }
        } else {
            // Storage creation succeeded, try initialization
            let storage = storage_result.unwrap();
            let result = storage.initialize().await;

            // If initialization doesn't detect corruption, try a read operation
            if result.is_ok() {
                // Try to read wallets - this should definitely fail on corrupted database
                let read_result = storage.list_wallets().await;
                assert!(
                    read_result.is_err(),
                    "Expected read operation to fail on corrupted database"
                );

                if let Err(WalletError::StorageError(msg)) = read_result {
                    // Should contain database/SQL error message
                    assert!(
                        msg.contains("database")
                            || msg.contains("SQL")
                            || msg.contains("corrupt")
                            || msg.contains("malformed")
                    );
                } else {
                    panic!("Expected StorageError for corrupted database");
                }
            } else {
                // Original path - initialization failed as expected
                if let Err(WalletError::StorageError(msg)) = result {
                    // Should contain database/SQL error message
                    assert!(
                        msg.contains("database") || msg.contains("SQL") || msg.contains("corrupt")
                    );
                } else {
                    panic!("Expected StorageError for corrupted database");
                }
            }
        }
    }

    #[tokio::test]
    async fn test_database_large_path_handling() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        // Create a very long path
        let mut long_path = temp_dir.path().to_path_buf();
        for i in 0..10 {
            long_path = long_path.join(format!("very_long_directory_name_{i}"));
        }

        // Create the directory structure
        std::fs::create_dir_all(&long_path).unwrap();
        let db_path = long_path.join("wallet.db");

        // Should handle long paths gracefully
        let storage = SqliteStorage::new(&db_path).await.unwrap();
        storage.initialize().await.unwrap();

        // Verify it works
        let stats = storage.get_statistics().await.unwrap();
        assert_eq!(stats.total_transactions, 0);
    }

    #[tokio::test]
    async fn test_database_special_characters_in_path() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let special_path = temp_dir
            .path()
            .join("test wallet with spaces & symbols!.db");

        let storage = SqliteStorage::new(&special_path).await.unwrap();
        storage.initialize().await.unwrap();

        // Verify database works with special characters in path
        let view_key = PrivateKey::new([1u8; 32]);
        let spend_key = PrivateKey::new([2u8; 32]);
        let wallet = StoredWallet::from_keys("test".to_string(), view_key, spend_key, 100);
        storage.save_wallet(&wallet).await.unwrap();
        let wallets = storage.list_wallets().await.unwrap();
        assert_eq!(wallets.len(), 1);
    }
}

#[cfg(feature = "storage")]
mod connection_pool_tests {
    use super::*;

    #[tokio::test]
    async fn test_multiple_connections_same_database() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("multi_conn_test.db");

        // Create initial database
        let storage1 = SqliteStorage::new(&db_path).await.unwrap();
        storage1.initialize().await.unwrap();

        // Open second connection to same database
        let storage2 = SqliteStorage::new(&db_path).await.unwrap();
        storage2.initialize().await.unwrap();

        // Both should be able to read/write
        let view_key1 = PrivateKey::new([1u8; 32]);
        let spend_key1 = PrivateKey::new([2u8; 32]);
        let view_key2 = PrivateKey::new([3u8; 32]);
        let spend_key2 = PrivateKey::new([4u8; 32]);
        let wallet1 = StoredWallet::from_keys("wallet1".to_string(), view_key1, spend_key1, 100);
        let wallet2 = StoredWallet::from_keys("wallet2".to_string(), view_key2, spend_key2, 200);
        storage1.save_wallet(&wallet1).await.unwrap();
        storage2.save_wallet(&wallet2).await.unwrap();

        // Verify both can see all wallets
        let wallets1 = storage1.list_wallets().await.unwrap();
        let wallets2 = storage2.list_wallets().await.unwrap();

        assert_eq!(wallets1.len(), 2);
        assert_eq!(wallets2.len(), 2);
    }

    #[tokio::test]
    async fn test_connection_under_load() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        let mut join_set = JoinSet::new();
        let storage = Arc::new(storage);

        // Spawn many concurrent operations
        for i in 0..20 {
            let storage_clone = Arc::clone(&storage);
            join_set.spawn(async move {
                // Rapid-fire operations
                for j in 0..10 {
                    let wallet_name = format!("wallet_{i}_{j}");
                    let view_key = PrivateKey::new([(i + j) as u8 + 1; 32]);
                    let spend_key = PrivateKey::new([(i + j) as u8 + 2; 32]);
                    let wallet =
                        StoredWallet::from_keys(wallet_name, view_key, spend_key, i * 100 + j);
                    storage_clone.save_wallet(&wallet).await.unwrap();
                }
                i
            });
        }

        // Wait for all operations
        let mut completed = 0;
        while let Some(result) = join_set.join_next().await {
            result.unwrap();
            completed += 1;
        }

        assert_eq!(completed, 20);

        // Verify final state
        let wallets = storage.list_wallets().await.unwrap();
        assert_eq!(wallets.len(), 200); // 20 * 10
    }
}

#[cfg(feature = "storage")]
mod error_handling_tests {
    use super::*;

    #[tokio::test]
    async fn test_operation_on_uninitialized_storage() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        // Don't call initialize()

        // Operations should fail gracefully
        let result = storage.list_wallets().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_sql_injection_protection() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        // Try SQL injection in wallet name
        let malicious_name = "test'; DROP TABLE wallets; --";

        // Should not succeed in SQL injection
        let view_key = PrivateKey::new([1u8; 32]);
        let spend_key = PrivateKey::new([2u8; 32]);
        let wallet = StoredWallet::from_keys(malicious_name.to_string(), view_key, spend_key, 100);
        let result = storage.save_wallet(&wallet).await;
        assert!(result.is_ok()); // SQLite properly handles this

        // Verify tables still exist
        let wallets = storage.list_wallets().await.unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].name, malicious_name); // Name stored as-is
    }

    #[tokio::test]
    async fn test_very_long_input_handling() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        // Test with very long strings
        let long_name = "a".repeat(10000);
        let view_key = PrivateKey::new([1u8; 32]);
        let spend_key = PrivateKey::new([2u8; 32]);
        let wallet = StoredWallet::from_keys(long_name, view_key, spend_key, 100);

        let result = storage.save_wallet(&wallet).await;
        // Should either succeed or fail gracefully
        match result {
            Ok(_) => {
                let wallets = storage.list_wallets().await.unwrap();
                assert_eq!(wallets.len(), 1);
            }
            Err(_) => {
                // Acceptable to reject very long inputs
            }
        }
    }

    #[tokio::test]
    async fn test_null_byte_handling() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        // Test with null bytes in strings
        let name_with_null = "test\0wallet";
        let view_key = PrivateKey::new([1u8; 32]);
        let spend_key = PrivateKey::new([2u8; 32]);
        let wallet = StoredWallet::from_keys(name_with_null.to_string(), view_key, spend_key, 100);

        let result = storage.save_wallet(&wallet).await;
        // Should handle null bytes gracefully (either accept or reject)
        match result {
            Ok(_) => {
                let wallets = storage.list_wallets().await.unwrap();
                assert_eq!(wallets.len(), 1);
            }
            Err(_) => {
                // Acceptable to reject null bytes
            }
        }
    }
}
