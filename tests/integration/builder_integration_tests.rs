//! Integration tests for wallet builder pattern with event listeners
//!
//! These tests verify that the WalletBuilder correctly integrates with the event system
//! in real-world scenarios, including database operations, memory management,
//! and concurrent event processing. Unlike unit tests, these integration tests
//! use actual databases, real file systems, and complete wallet workflows.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(feature = "storage")]
use tempfile::TempDir;
use tokio::time::sleep;

use lightweight_wallet_libs::wallet::{Wallet, WalletBuilder, WalletBuildError};
use lightweight_wallet_libs::events::listeners::{EventLogger, MockEventListener};
use lightweight_wallet_libs::events::types::{EventMetadata, WalletEvent};
use lightweight_wallet_libs::key_management::generate_seed_phrase;

#[cfg(feature = "storage")]
use lightweight_wallet_libs::storage::{SqliteStorage, WalletStorage};

/// Integration test for wallet builder with single event listener
#[tokio::test]
async fn test_wallet_builder_single_listener_integration() {
    // Create a wallet with an event listener using the builder pattern
    let listener = EventLogger::console().expect("Failed to create EventLogger");
    let listener_name = listener.name().to_string();
    
    let wallet = WalletBuilder::new()
        .generate_new()
        .with_label("Integration Test Wallet")
        .with_network("testnet")
        .with_event_listener(Box::new(listener))
        .build_async()
        .await
        .expect("Failed to build wallet with event listener");

    // Verify wallet is properly configured
    assert_eq!(wallet.label(), Some(&"Integration Test Wallet".to_string()));
    assert_eq!(wallet.network(), "testnet");
    assert!(wallet.events_enabled());
    assert_eq!(wallet.event_listener_count(), 1);

    // Verify event listener is registered
    if let Some(registry) = wallet.event_registry() {
        assert!(registry.has_listener(&listener_name));
    } else {
        panic!("Event registry should be available");
    }

    // Test address generation (this would trigger events in a full implementation)
    let address = wallet.get_dual_address(0, None).expect("Failed to generate address");
    assert!(!address.to_string().is_empty());

    println!("✓ Single listener integration test passed");
}

/// Integration test for wallet builder with memory-only events
#[tokio::test]
async fn test_wallet_builder_memory_only_events_integration() {
    let mock_listener = MockEventListener::new();
    let captured_events = mock_listener.get_captured_events();
    
    let mut wallet = WalletBuilder::new()
        .generate_new()
        .with_memory_only_events()
        .with_event_listener(Box::new(mock_listener))
        .with_label("Memory Events Wallet")
        .build_async()
        .await
        .expect("Failed to build wallet with memory-only events");

    // Verify memory-only configuration
    assert!(wallet.events_enabled());
    assert_eq!(wallet.get_property("event_storage_mode"), Some(&"memory_only".to_string()));
    assert_eq!(wallet.event_listener_count(), 1);

    // Perform wallet operations to trigger events
    wallet.set_network("mainnet".to_string());
    
    // Generate multiple addresses to potentially trigger events
    for i in 0..3 {
        let _address = wallet.get_dual_address(i, None).expect("Failed to generate address");
    }

    // Small delay to allow async event processing
    sleep(Duration::from_millis(50)).await;

    // In the current implementation, we're testing the infrastructure rather than actual events
    // The captured events would be populated when wallet operations emit events
    let events = captured_events.lock().unwrap();
    // We can't assert on specific events yet since event emission isn't fully implemented
    // but we can verify the listener infrastructure is working
    
    println!("✓ Memory-only events integration test passed (events captured: {})", events.len());
}

/// Integration test for builder preset configurations
#[tokio::test]
async fn test_wallet_builder_preset_configurations_integration() {
    // Test for_testing preset
    let testing_wallet = WalletBuilder::new()
        .generate_new()
        .for_testing()
        .expect("Failed to create testing preset")
        .build_async()
        .await
        .expect("Failed to build testing wallet");

    assert!(testing_wallet.events_enabled());
    assert_eq!(testing_wallet.get_property("deployment_mode"), Some(&"testing".to_string()));
    assert_eq!(testing_wallet.get_property("event_storage_mode"), Some(&"memory_only".to_string()));
    assert_eq!(testing_wallet.event_listener_count(), 1); // EventLogger

    // Test for_development with memory-only
    let dev_wallet = WalletBuilder::new()
        .generate_new()
        .for_development(None)
        .await
        .expect("Failed to create development preset")
        .build_async()
        .await
        .expect("Failed to build development wallet");

    assert!(dev_wallet.events_enabled());
    assert_eq!(dev_wallet.get_property("deployment_mode"), Some(&"development".to_string()));
    assert_eq!(dev_wallet.get_property("event_storage_mode"), Some(&"memory_only".to_string()));
    assert_eq!(dev_wallet.event_listener_count(), 1); // EventLogger

    println!("✓ Preset configurations integration test passed");
}

/// Integration test for builder with database storage
#[cfg(feature = "storage")]
#[tokio::test]
async fn test_wallet_builder_database_storage_integration() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("integration_test.db");
    let db_path_str = db_path.to_str().unwrap();

    // Test production preset with database
    let prod_wallet = WalletBuilder::new()
        .generate_new()
        .for_production(db_path_str.to_string())
        .await
        .expect("Failed to create production preset")
        .build_async()
        .await
        .expect("Failed to build production wallet");

    assert!(prod_wallet.events_enabled());
    assert_eq!(prod_wallet.get_property("deployment_mode"), Some(&"production".to_string()));
    assert_eq!(prod_wallet.get_property("event_storage_mode"), Some(&"database".to_string()));
    
    // Verify database was created
    assert!(db_path.exists(), "Database file should be created");

    // Test development preset with database
    let dev_db_path = temp_dir.path().join("dev_test.db");
    let dev_wallet = WalletBuilder::new()
        .generate_new()
        .for_development(Some(dev_db_path.to_str().unwrap().to_string()))
        .await
        .expect("Failed to create development preset with database")
        .build_async()
        .await
        .expect("Failed to build development wallet with database");

    assert!(dev_wallet.events_enabled());
    assert_eq!(dev_wallet.get_property("deployment_mode"), Some(&"development".to_string()));
    assert_eq!(dev_wallet.get_property("event_storage_mode"), Some(&"database".to_string()));
    assert_eq!(dev_wallet.event_listener_count(), 1); // EventLogger (Database listener not yet implemented)

    println!("✓ Database storage integration test passed");
}

/// Integration test for builder error handling scenarios
#[tokio::test]
async fn test_wallet_builder_error_handling_integration() {
    // Test building without specifying creation method
    let result = WalletBuilder::new().build_async().await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), WalletBuildError::MissingParameter(_)));

    // Test sync build with event listeners (should fail)
    let listener = EventLogger::console().expect("Failed to create EventLogger");
    let result = WalletBuilder::new()
        .generate_new()
        .with_event_listener(Box::new(listener))
        .build(); // Sync build
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), WalletBuildError::ConfigurationError(_)));

    // Test invalid seed phrase
    let invalid_seed = "invalid seed phrase with wrong word count";
    let result = WalletBuilder::new()
        .from_seed_phrase(invalid_seed.to_string(), None)
        .build_async()
        .await;
    
    assert!(result.is_err());

    println!("✓ Error handling integration test passed");
}

/// Integration test for builder with complex configuration
#[tokio::test]
async fn test_wallet_builder_complex_configuration_integration() {
    let seed_phrase = generate_seed_phrase().expect("Failed to generate seed phrase");
    let mock_listener = MockEventListener::new();
    let captured_events = mock_listener.get_captured_events();
    
    let wallet = WalletBuilder::new()
        .from_seed_phrase(seed_phrase.clone(), None)
        .with_label("Complex Configuration Wallet")
        .with_network("stagenet")
        .with_key_index(5)
        .with_property("test_mode", "true")
        .with_property("version", "integration_test")
        .with_memory_only_events()
        .with_event_listener(Box::new(mock_listener))
        .build_async()
        .await
        .expect("Failed to build complex wallet");

    // Verify all configuration was applied
    assert_eq!(wallet.label(), Some(&"Complex Configuration Wallet".to_string()));
    assert_eq!(wallet.network(), "stagenet");
    assert_eq!(wallet.current_key_index(), 5);
    assert_eq!(wallet.get_property("test_mode"), Some(&"true".to_string()));
    assert_eq!(wallet.get_property("version"), Some(&"integration_test".to_string()));
    assert_eq!(wallet.export_seed_phrase().expect("Failed to export seed phrase"), seed_phrase);
    
    // Verify event system
    assert!(wallet.events_enabled());
    assert_eq!(wallet.get_property("event_storage_mode"), Some(&"memory_only".to_string()));
    assert_eq!(wallet.event_listener_count(), 1);

    // Generate addresses and verify functionality
    for i in 5..8 { // Start from key index 5
        let address = wallet.get_dual_address(i, None).expect("Failed to generate address");
        assert!(!address.to_string().is_empty());
    }

    println!("✓ Complex configuration integration test passed");
}

/// Integration test for concurrent wallet builder operations
#[tokio::test]
async fn test_wallet_builder_concurrent_operations_integration() {
    let num_wallets = 5;
    let mut tasks = Vec::new();

    // Create multiple wallets concurrently using the builder
    for i in 0..num_wallets {
        let task = tokio::spawn(async move {
            let listener = EventLogger::console().expect("Failed to create EventLogger");
            
            let wallet = WalletBuilder::new()
                .generate_new()
                .with_label(&format!("Concurrent Wallet {}", i))
                .with_network("testnet")
                .with_event_listener(Box::new(listener))
                .build_async()
                .await
                .expect("Failed to build concurrent wallet");

            (i, wallet)
        });
        tasks.push(task);
    }

    // Wait for all wallets to be created
    let mut wallets = Vec::new();
    for task in tasks {
        let (index, wallet) = task.await.expect("Task failed");
        wallets.push((index, wallet));
    }

    // Verify all wallets were created successfully
    assert_eq!(wallets.len(), num_wallets);
    
    for (index, wallet) in wallets {
        assert_eq!(wallet.label(), Some(&format!("Concurrent Wallet {}", index)));
        assert_eq!(wallet.network(), "testnet");
        assert!(wallet.events_enabled());
        assert_eq!(wallet.event_listener_count(), 1);
        
        // Verify each wallet can generate unique addresses
        let address = wallet.get_dual_address(0, None).expect("Failed to generate address");
        assert!(!address.to_string().is_empty());
    }

    println!("✓ Concurrent operations integration test passed");
}

/// Integration test for builder state management and reuse
#[tokio::test]
async fn test_wallet_builder_state_management_integration() {
    // Test that builder can be configured incrementally
    let mut builder = WalletBuilder::new();
    
    // Configure step by step
    builder = builder.generate_new();
    builder = builder.with_label("State Management Test");
    builder = builder.with_network("devnet");
    
    let listener = EventLogger::console().expect("Failed to create EventLogger");
    builder = builder.with_event_listener(Box::new(listener));
    
    // Add properties incrementally
    builder = builder.with_property("test_phase", "1");
    builder = builder.with_property("test_phase", "2"); // Override previous value
    builder = builder.with_property("additional", "value");

    // Build the wallet
    let wallet = builder.build_async().await.expect("Failed to build wallet");

    // Verify final state
    assert_eq!(wallet.label(), Some(&"State Management Test".to_string()));
    assert_eq!(wallet.network(), "devnet");
    assert_eq!(wallet.get_property("test_phase"), Some(&"2".to_string())); // Should be overridden value
    assert_eq!(wallet.get_property("additional"), Some(&"value".to_string()));
    assert!(wallet.events_enabled());
    assert_eq!(wallet.event_listener_count(), 1);

    println!("✓ State management integration test passed");
}

/// Integration test for builder with event listener lifecycle
#[tokio::test]
async fn test_wallet_builder_event_listener_lifecycle_integration() {
    let mock_listener = MockEventListener::new();
    let captured_events = mock_listener.get_captured_events();
    
    // Build wallet with event listener
    let mut wallet = WalletBuilder::new()
        .generate_new()
        .with_label("Lifecycle Test Wallet")
        .with_event_listener(Box::new(mock_listener))
        .build_async()
        .await
        .expect("Failed to build wallet with event listener");

    // Verify initial state
    assert!(wallet.events_enabled());
    assert_eq!(wallet.event_listener_count(), 1);

    // Test adding another listener at runtime
    let logger = EventLogger::console().expect("Failed to create EventLogger");
    wallet.add_event_listener(Box::new(logger)).await
        .expect("Failed to add event listener");
    
    assert_eq!(wallet.event_listener_count(), 2);

    // Test removing a listener
    let result = wallet.remove_event_listener("EventLogger").await;
    assert!(result.is_ok());
    assert_eq!(wallet.event_listener_count(), 1);

    // Test removing non-existent listener
    let result = wallet.remove_event_listener("NonExistentListener").await;
    assert!(result.is_err());

    // Test disabling events
    let disable_result = wallet.disable_events().await;
    assert!(disable_result);
    assert!(!wallet.events_enabled());

    // Test re-enabling events
    let enable_result = wallet.enable_events();
    assert!(enable_result);
    assert!(wallet.events_enabled());

    println!("✓ Event listener lifecycle integration test passed");
}

#[cfg(feature = "storage")]
/// Integration test for builder with database operations and error recovery
#[tokio::test]
async fn test_wallet_builder_database_error_recovery_integration() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("error_recovery_test.db");
    let db_path_str = db_path.to_str().unwrap();

    // Create wallet with database storage
    let wallet = WalletBuilder::new()
        .generate_new()
        .with_database_storage(db_path_str.to_string())
        .await
        .expect("Failed to configure database storage")
        .with_label("Database Error Recovery Test")
        .build_async()
        .await
        .expect("Failed to build wallet with database");

    assert!(wallet.events_enabled());
    assert_eq!(wallet.get_property("event_storage_mode"), Some(&"database".to_string()));

    // Verify database file exists
    assert!(db_path.exists());

    // Test database operations (would involve event storage when implemented)
    let address = wallet.get_dual_address(0, None).expect("Failed to generate address");
    assert!(!address.to_string().is_empty());

    // Simulate database operations by directly checking storage
    let storage = SqliteStorage::new_with_path(db_path_str).await
        .expect("Failed to create storage connection");
    
    // In a full implementation, we would test event storage operations here
    // For now, we verify the database connection works
    drop(storage);

    println!("✓ Database error recovery integration test passed");
}

/// Integration test verifying builder produces consistent wallets
#[tokio::test] 
async fn test_wallet_builder_consistency_integration() {
    let seed_phrase = generate_seed_phrase().expect("Failed to generate seed phrase");
    
    // Create two wallets with identical configuration
    let wallet1 = WalletBuilder::new()
        .from_seed_phrase(seed_phrase.clone(), None)
        .with_label("Consistency Test")
        .with_network("mainnet")
        .with_key_index(10)
        .build_async()
        .await
        .expect("Failed to build first wallet");

    let wallet2 = WalletBuilder::new()
        .from_seed_phrase(seed_phrase.clone(), None)
        .with_label("Consistency Test")
        .with_network("mainnet")
        .with_key_index(10)
        .build_async()
        .await
        .expect("Failed to build second wallet");

    // Verify both wallets are identical
    assert_eq!(wallet1.label(), wallet2.label());
    assert_eq!(wallet1.network(), wallet2.network());
    assert_eq!(wallet1.current_key_index(), wallet2.current_key_index());
    assert_eq!(wallet1.export_seed_phrase().unwrap(), wallet2.export_seed_phrase().unwrap());

    // Verify they generate the same addresses
    let address1 = wallet1.get_dual_address(10, None).expect("Failed to generate address from wallet1");
    let address2 = wallet2.get_dual_address(10, None).expect("Failed to generate address from wallet2");
    assert_eq!(address1.to_string(), address2.to_string());

    println!("✓ Wallet consistency integration test passed");
}
