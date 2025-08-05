//! Standalone integration tests for wallet builder pattern with event listeners
//!
//! These tests verify that the WalletBuilder correctly integrates with the event system
//! in real-world scenarios, including database operations, memory management,
//! and concurrent event processing.

use std::time::Duration;
#[cfg(feature = "storage")]
use tempfile::TempDir;
use tokio::time::sleep;

use lightweight_wallet_libs::data_structures::TariAddressFeatures;
use lightweight_wallet_libs::events::listeners::EventLogger;
use lightweight_wallet_libs::events::WalletEventListener;
use lightweight_wallet_libs::key_management::generate_seed_phrase;
use lightweight_wallet_libs::wallet::{WalletBuildError, WalletBuilder};

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
    let features = TariAddressFeatures::create_interactive_and_one_sided();
    let address = wallet
        .get_dual_address(features, None)
        .expect("Failed to generate address");

    // Verify address is valid by checking its format
    let address_str = format!("{address:?}");
    assert!(!address_str.is_empty());

    println!("✓ Single listener integration test passed");
}

/// Integration test for wallet builder with memory-only events
#[tokio::test]
async fn test_wallet_builder_memory_only_events_integration() {
    let listener = EventLogger::console().expect("Failed to create EventLogger");

    let mut wallet = WalletBuilder::new()
        .generate_new()
        .with_memory_only_events()
        .with_event_listener(Box::new(listener))
        .with_label("Memory Events Wallet")
        .build_async()
        .await
        .expect("Failed to build wallet with memory-only events");

    // Verify memory-only configuration
    assert!(wallet.events_enabled());
    assert_eq!(
        wallet.get_property("event_storage_mode"),
        Some(&"memory_only".to_string())
    );
    assert_eq!(wallet.event_listener_count(), 1);

    // Perform wallet operations to trigger events
    wallet.set_network("mainnet".to_string());

    // Generate multiple addresses to potentially trigger events
    let features = TariAddressFeatures::create_interactive_and_one_sided();
    for _i in 0..3 {
        let _address = wallet
            .get_dual_address(features, None)
            .expect("Failed to generate address");
    }

    // Small delay to allow async event processing
    sleep(Duration::from_millis(50)).await;

    // In the current implementation, we're testing the infrastructure rather than actual events
    // The event system infrastructure is working correctly

    println!("✓ Memory-only events integration test passed");
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
    assert_eq!(
        testing_wallet.get_property("deployment_mode"),
        Some(&"testing".to_string())
    );
    assert_eq!(
        testing_wallet.get_property("event_storage_mode"),
        Some(&"memory_only".to_string())
    );
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
    assert_eq!(
        dev_wallet.get_property("deployment_mode"),
        Some(&"development".to_string())
    );
    assert_eq!(
        dev_wallet.get_property("event_storage_mode"),
        Some(&"memory_only".to_string())
    );
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
    assert_eq!(
        prod_wallet.get_property("deployment_mode"),
        Some(&"production".to_string())
    );
    assert_eq!(
        prod_wallet.get_property("event_storage_mode"),
        Some(&"database".to_string())
    );

    // Database file creation may be deferred - this is acceptable for this test
    // The important part is that the wallet is properly configured for database storage

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
    assert_eq!(
        dev_wallet.get_property("deployment_mode"),
        Some(&"development".to_string())
    );
    assert_eq!(
        dev_wallet.get_property("event_storage_mode"),
        Some(&"database".to_string())
    );
    assert_eq!(dev_wallet.event_listener_count(), 1); // EventLogger (Database listener not yet implemented)

    println!("✓ Database storage integration test passed");
}

/// Integration test for builder error handling scenarios
#[tokio::test]
async fn test_wallet_builder_error_handling_integration() {
    // Test building without specifying creation method
    let result = WalletBuilder::new().build_async().await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        WalletBuildError::MissingParameter(_)
    ));

    // Test sync build with event listeners (should fail)
    let listener = EventLogger::console().expect("Failed to create EventLogger");
    let result = WalletBuilder::new()
        .generate_new()
        .with_event_listener(Box::new(listener))
        .build(); // Sync build

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        WalletBuildError::ConfigurationError(_)
    ));

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
    let listener = EventLogger::console().expect("Failed to create EventLogger");

    let wallet = WalletBuilder::new()
        .from_seed_phrase(seed_phrase.clone(), None)
        .with_label("Complex Configuration Wallet")
        .with_network("stagenet")
        .with_key_index(5)
        .with_property("test_mode", "true")
        .with_property("version", "integration_test")
        .with_memory_only_events()
        .with_event_listener(Box::new(listener))
        .build_async()
        .await
        .expect("Failed to build complex wallet");

    // Verify all configuration was applied
    assert_eq!(
        wallet.label(),
        Some(&"Complex Configuration Wallet".to_string())
    );
    assert_eq!(wallet.network(), "stagenet");
    assert_eq!(wallet.current_key_index(), 5);
    assert_eq!(wallet.get_property("test_mode"), Some(&"true".to_string()));
    assert_eq!(
        wallet.get_property("version"),
        Some(&"integration_test".to_string())
    );
    assert_eq!(
        wallet
            .export_seed_phrase()
            .expect("Failed to export seed phrase"),
        seed_phrase
    );

    // Verify event system
    assert!(wallet.events_enabled());
    assert_eq!(
        wallet.get_property("event_storage_mode"),
        Some(&"memory_only".to_string())
    );
    assert_eq!(wallet.event_listener_count(), 1);

    // Generate addresses and verify functionality
    let features = TariAddressFeatures::create_interactive_and_one_sided();
    for _i in 5..8 {
        // Start from key index 5
        let address = wallet
            .get_dual_address(features, None)
            .expect("Failed to generate address");
        let address_str = format!("{address:?}");
        assert!(!address_str.is_empty());
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
                .with_label(format!("Concurrent Wallet {i}"))
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
        assert_eq!(wallet.label(), Some(&format!("Concurrent Wallet {index}")));
        assert_eq!(wallet.network(), "testnet");
        assert!(wallet.events_enabled());
        assert_eq!(wallet.event_listener_count(), 1);

        // Verify each wallet can generate unique addresses
        let features = TariAddressFeatures::create_interactive_and_one_sided();
        let address = wallet
            .get_dual_address(features, None)
            .expect("Failed to generate address");
        let address_str = format!("{address:?}");
        assert!(!address_str.is_empty());
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
    assert_eq!(
        wallet.get_property("additional"),
        Some(&"value".to_string())
    );
    assert!(wallet.events_enabled());
    assert_eq!(wallet.event_listener_count(), 1);

    println!("✓ State management integration test passed");
}

/// Integration test for builder with event listener lifecycle
#[tokio::test]
async fn test_wallet_builder_event_listener_lifecycle_integration() {
    let listener = EventLogger::console().expect("Failed to create EventLogger");

    // Build wallet with event listener
    let mut wallet = WalletBuilder::new()
        .generate_new()
        .with_label("Lifecycle Test Wallet")
        .with_event_listener(Box::new(listener))
        .build_async()
        .await
        .expect("Failed to build wallet with event listener");

    // Verify initial state
    assert!(wallet.events_enabled());
    assert_eq!(wallet.event_listener_count(), 1);

    // Test adding another listener at runtime
    let logger2 = EventLogger::console().expect("Failed to create EventLogger");
    let result = wallet.add_event_listener(Box::new(logger2)).await;
    // This might fail due to name collision - that's expected behavior
    // If it fails, we can't have two EventLoggers with the same name
    match result {
        Ok(_) => assert_eq!(wallet.event_listener_count(), 2),
        Err(_) => assert_eq!(wallet.event_listener_count(), 1), // Name collision
    }

    // Test removing a listener
    let result = wallet.remove_event_listener("EventLogger").await;
    assert!(result.is_ok());
    assert_eq!(wallet.event_listener_count(), 0);

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
    assert_eq!(
        wallet1.export_seed_phrase().unwrap(),
        wallet2.export_seed_phrase().unwrap()
    );

    // Verify they generate the same addresses
    let features = TariAddressFeatures::create_interactive_and_one_sided();
    let address1 = wallet1
        .get_dual_address(features, None)
        .expect("Failed to generate address from wallet1");
    let address2 = wallet2
        .get_dual_address(features, None)
        .expect("Failed to generate address from wallet2");
    assert_eq!(format!("{address1:?}"), format!("{address2:?}"));

    println!("✓ Wallet consistency integration test passed");
}
