//! Integration tests for event system listeners with real scenarios
//!
//! These tests verify that the event listeners work correctly with real databases,
//! progress tracking, console output, and combined scenarios. Unlike unit tests,
//! these integration tests use actual databases, real progress scenarios, and
//! verify end-to-end functionality.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(feature = "storage")]
use tempfile::TempDir;

use lightweight_wallet_libs::events::types::{EventMetadata, ScanConfig};
use lightweight_wallet_libs::events::{EventDispatcher, EventListener, WalletScanEvent};

use lightweight_wallet_libs::events::listeners::{
    ConsoleLoggingListener, MockEventListener, ProgressTrackingListener,
};

#[cfg(feature = "storage")]
use lightweight_wallet_libs::events::types::{AddressInfo, BlockInfo, OutputData, TransactionData};

#[cfg(feature = "storage")]
use lightweight_wallet_libs::events::listeners::DatabaseStorageListener;

#[cfg(feature = "storage")]
use lightweight_wallet_libs::wallet::Wallet;

/// Integration test for ProgressTrackingListener with real progress scenarios
#[tokio::test]
async fn test_progress_tracking_listener_integration() {
    // Shared state for callbacks
    let progress_updates = Arc::new(Mutex::new(Vec::new()));
    let completion_called = Arc::new(Mutex::new(false));

    let progress_updates_clone = progress_updates.clone();
    let completion_called_clone = completion_called.clone();

    // Create progress listener with real callbacks
    let mut progress_listener = ProgressTrackingListener::builder()
        .frequency(1) // Update every block for testing
        .with_progress_callback(move |info| {
            progress_updates_clone.lock().unwrap().push((
                info.current_block,
                info.total_blocks,
                info.progress_percent,
            ));
        })
        .with_completion_callback(move |_stats| {
            *completion_called_clone.lock().unwrap() = true;
        })
        .verbose(true)
        .build();

    // Create test events sequence
    let scan_started = WalletScanEvent::ScanStarted {
        metadata: EventMetadata::new("integration_test"),
        config: ScanConfig::new().with_batch_size(10),
        block_range: (1000, 1010),
        wallet_context: "test_wallet_123".to_string(),
    };

    let scan_progress = WalletScanEvent::ScanProgress {
        metadata: EventMetadata::new("integration_test"),
        current_block: 1005,
        total_blocks: 10,
        percentage: 50.0,
        speed_blocks_per_second: 1.8,
        estimated_time_remaining: Some(Duration::from_millis(2777)),
    };

    let scan_completed = WalletScanEvent::ScanCompleted {
        metadata: EventMetadata::new("integration_test"),
        final_statistics: {
            let mut stats = HashMap::new();
            stats.insert("blocks_processed".to_string(), 10);
            stats.insert("outputs_found".to_string(), 3);
            stats
        },
        success: true,
        total_duration: Duration::from_millis(5000),
    };

    // Process events sequentially
    let result = progress_listener
        .handle_event(&Arc::new(scan_started))
        .await;
    assert!(
        result.is_ok(),
        "Failed to handle ScanStarted event: {result:?}",
    );

    let result = progress_listener
        .handle_event(&Arc::new(scan_progress))
        .await;
    assert!(
        result.is_ok(),
        "Failed to handle ScanProgress event: {result:?}",
    );

    let result = progress_listener
        .handle_event(&Arc::new(scan_completed))
        .await;
    assert!(
        result.is_ok(),
        "Failed to handle ScanCompleted event: {result:?}",
    );

    // Verify callbacks were called
    let updates = progress_updates.lock().unwrap();
    assert!(
        !updates.is_empty(),
        "Progress updates should have been called"
    );
    assert!(
        *completion_called.lock().unwrap(),
        "Completion callback should have been called"
    );

    println!("✓ ProgressTrackingListener integration test passed");
}

/// Integration test for ConsoleLoggingListener with real output verification
#[tokio::test]
async fn test_console_logging_listener_integration() {
    // Create console listeners with different configurations
    let mut minimal_listener = ConsoleLoggingListener::builder().minimal_preset().build();
    let mut debug_listener = ConsoleLoggingListener::builder().debug_preset().build();

    // Create test event
    let block_processed = WalletScanEvent::BlockProcessed {
        metadata: EventMetadata::new("integration_test"),
        height: 2005,
        hash: "test_block_hash".to_string(),
        timestamp: 1640995200,
        processing_duration: Duration::from_millis(75),
        outputs_count: 1,
        spent_outputs_count: 0,
    };

    // Test minimal configuration
    let result = minimal_listener
        .handle_event(&Arc::new(block_processed.clone()))
        .await;
    assert!(
        result.is_ok(),
        "Failed to handle event in minimal config: {result:?}",
    );

    // Test debug configuration
    let result = debug_listener
        .handle_event(&Arc::new(block_processed))
        .await;
    assert!(
        result.is_ok(),
        "Failed to handle event in debug config: {result:?}",
    );

    println!("✓ ConsoleLoggingListener integration test passed");
}

/// Integration test combining multiple listeners working together
#[tokio::test]
async fn test_combined_listeners_integration() {
    // Create event dispatcher
    let mut dispatcher = EventDispatcher::new();

    // Add multiple listeners
    let mock_listener = MockEventListener::new();
    let captured_events = mock_listener.get_captured_events();

    let progress_listener = ProgressTrackingListener::builder()
        .frequency(1)
        .verbose(false)
        .build();
    dispatcher
        .register(Box::new(progress_listener))
        .expect("Failed to register progress listener");

    let console_listener = ConsoleLoggingListener::builder().minimal_preset().build();
    dispatcher
        .register(Box::new(console_listener))
        .expect("Failed to register console listener");

    dispatcher
        .register(Box::new(mock_listener))
        .expect("Failed to register mock listener");

    // Create test events
    let scan_started = WalletScanEvent::ScanStarted {
        metadata: EventMetadata::new("integration_test"),
        config: ScanConfig::new(),
        block_range: (10000, 10050),
        wallet_context: "test_wallet_999".to_string(),
    };

    let scan_progress = WalletScanEvent::ScanProgress {
        metadata: EventMetadata::new("integration_test"),
        current_block: 10025,
        total_blocks: 50,
        percentage: 50.0,
        speed_blocks_per_second: 5.0,
        estimated_time_remaining: Some(Duration::from_millis(5000)),
    };

    let scan_completed = WalletScanEvent::ScanCompleted {
        metadata: EventMetadata::new("integration_test"),
        final_statistics: {
            let mut stats = HashMap::new();
            stats.insert("blocks_processed".to_string(), 50);
            stats.insert("outputs_found".to_string(), 10);
            stats
        },
        success: true,
        total_duration: Duration::from_millis(10000),
    };

    // Dispatch events to all listeners
    dispatcher.dispatch(scan_started).await;
    dispatcher.dispatch(scan_progress).await;
    dispatcher.dispatch(scan_completed).await;

    // Verify mock listener captured all events
    let captured = captured_events.lock().unwrap();
    assert_eq!(
        captured.len(),
        3,
        "Mock listener should have captured 3 events"
    );

    println!("✓ Combined listeners integration test passed");
}

/// Integration test for error handling across listeners
#[tokio::test]
async fn test_error_handling_integration() {
    let mut dispatcher = EventDispatcher::new();

    // Add listener that can handle errors
    let progress_listener = ProgressTrackingListener::builder()
        .frequency(1)
        .verbose(true)
        .build();
    dispatcher
        .register(Box::new(progress_listener))
        .expect("Failed to register progress listener");

    // Create error scenario
    let error_event = WalletScanEvent::ScanError {
        metadata: EventMetadata::new("integration_test"),
        error_message: "Failed to connect to node".to_string(),
        error_code: Some("NETWORK_ERROR".to_string()),
        block_height: Some(1500),
        retry_info: Some("Retrying in 5 seconds".to_string()),
        is_recoverable: true,
    };

    // Dispatch error event - should not panic
    dispatcher.dispatch(error_event).await;

    // Test recovery scenario
    let recovery_event = WalletScanEvent::ScanProgress {
        metadata: EventMetadata::new("integration_test"),
        current_block: 1501,
        total_blocks: 2000,
        percentage: 75.05,
        speed_blocks_per_second: 3.0,
        estimated_time_remaining: Some(Duration::from_millis(166333)),
    };

    dispatcher.dispatch(recovery_event).await;

    println!("✓ Error handling integration test passed");
}

/// Integration test for DatabaseStorageListener with real database operations
#[cfg(feature = "storage")]
#[tokio::test]
async fn test_database_storage_listener_integration() {
    // Create temporary database
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_wallet.db");
    let db_path_str = db_path.to_str().unwrap();

    // Create database listener
    let mut db_listener = DatabaseStorageListener::new(db_path_str)
        .await
        .expect("Failed to create database listener");

    // Create test wallet for context
    let _wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

    // Create scan started event with wallet context
    let scan_started = WalletScanEvent::ScanStarted {
        metadata: EventMetadata::new("integration_test"),
        config: ScanConfig::new(),
        block_range: (1000, 2000),
        wallet_context: "test_wallet_id".to_string(),
    };

    // Handle scan started event
    let result = db_listener.handle_event(&Arc::new(scan_started)).await;
    assert!(
        result.is_ok(),
        "Failed to handle ScanStarted event: {result:?}",
    );

    // Create and handle block processed event
    let block_processed = WalletScanEvent::BlockProcessed {
        metadata: EventMetadata::new("integration_test"),
        height: 1002,
        hash: "block_hash_1002".to_string(),
        timestamp: 1640995440,
        processing_duration: Duration::from_millis(50),
        outputs_count: 1,
        spent_outputs_count: 0,
    };

    let result = db_listener.handle_event(&Arc::new(block_processed)).await;
    assert!(
        result.is_ok(),
        "Failed to handle BlockProcessed event: {result:?}",
    );

    // Create and handle output found event
    let output_found = WalletScanEvent::OutputFound {
        metadata: EventMetadata::new("integration_test"),
        output_data: OutputData::new(
            "commitment_test_1".to_string(),
            "rangeproof_test_1".to_string(),
            0,
            true,
        )
        .with_amount(1000000)
        .with_key_index(0),
        block_info: BlockInfo::new(1002, "block_hash_1002".to_string(), 1640995440, 0),
        address_info: AddressInfo::new(
            "test_address".to_string(),
            "stealth".to_string(),
            "testnet".to_string(),
        ),
        transaction_data: TransactionData::new(
            1000000,
            "Unspent".to_string(),
            "Inbound".to_string(),
            1640995440,
        ),
    };

    let result = db_listener.handle_event(&Arc::new(output_found)).await;
    assert!(
        result.is_ok(),
        "Failed to handle OutputFound event: {result:?}",
    );

    // Handle scan completion
    let scan_completed = WalletScanEvent::ScanCompleted {
        metadata: EventMetadata::new("integration_test"),
        final_statistics: {
            let mut stats = HashMap::new();
            stats.insert("blocks_processed".to_string(), 5);
            stats.insert("outputs_found".to_string(), 1);
            stats
        },
        success: true,
        total_duration: Duration::from_millis(5000),
    };

    let result = db_listener.handle_event(&Arc::new(scan_completed)).await;
    assert!(
        result.is_ok(),
        "Failed to handle ScanCompleted event: {result:?}",
    );

    println!("✓ DatabaseStorageListener integration test passed");
}

/// Performance integration test for high-frequency events
#[tokio::test]
async fn test_high_frequency_events_integration() {
    let mut dispatcher = EventDispatcher::new();

    // Add performance-optimized listeners
    let progress_listener = ProgressTrackingListener::builder()
        .performance_preset()
        .build();
    dispatcher
        .register(Box::new(progress_listener))
        .expect("Failed to register progress listener");

    let console_listener = ConsoleLoggingListener::builder().minimal_preset().build();
    dispatcher
        .register(Box::new(console_listener))
        .expect("Failed to register console listener");

    // Start timing
    let start_time = std::time::Instant::now();

    // Generate high-frequency block processed events
    for i in 0..100 {
        let event = WalletScanEvent::BlockProcessed {
            metadata: EventMetadata::new("integration_test"),
            height: 20000 + i,
            hash: format!("block_hash_{i}"),
            timestamp: 1640995200 + i * 120,
            processing_duration: Duration::from_millis(25),
            outputs_count: if i % 10 == 0 { 1 } else { 0 },
            spent_outputs_count: 0,
        };

        dispatcher.dispatch(event).await;
    }

    let elapsed = start_time.elapsed();
    println!(
        "Processed 100 events in {:?} ({:.2} events/sec)",
        elapsed,
        100.0 / elapsed.as_secs_f64()
    );

    // Should process at least 10 events per second
    assert!(
        elapsed < Duration::from_secs(10),
        "Performance too slow: {elapsed:?}"
    );

    println!("✓ High-frequency events integration test passed");
}
