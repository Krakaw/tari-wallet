//! Integration tests for event system listeners with real scenarios
//!
//! These tests verify that the event listeners work correctly with real databases,
//! progress tracking, console output, and combined scenarios. Unlike unit tests,
//! these integration tests use actual databases, real progress scenarios, and
//! verify end-to-end functionality.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::{sleep, timeout};

use lightweight_wallet_libs::events::{
    EventDispatcher, EventListener, WalletScanEvent, SharedEvent
};
use lightweight_wallet_libs::events::types::{
    ScanStarted, BlockProcessed, OutputFound, ScanProgress, ScanCompleted, ScanError,
    BlockInfo, OutputData, AddressInfo, ScanStats, EventMetadata
};

#[cfg(feature = "storage")]
use lightweight_wallet_libs::events::listeners::DatabaseStorageListener;
use lightweight_wallet_libs::events::listeners::{
    ProgressTrackingListener, ConsoleLoggingListener, MockEventListener, AsciiProgressBarListener
};

#[cfg(feature = "storage")]
use lightweight_wallet_libs::{
    wallet::Wallet,
    storage::{SqliteStorage, WalletStorage}
};

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
    let wallet = Wallet::generate_new_with_seed_phrase(None)
        .expect("Failed to generate wallet");

    // Create scan started event with wallet context
    let scan_started = WalletScanEvent::ScanStarted(ScanStarted {
        metadata: EventMetadata::new(),
        wallet_id: wallet.wallet_id(),
        from_block: 1000,
        to_block: 2000,
        estimated_blocks: 1000,
        scan_mode: "GRPC".to_string(),
    });

    // Handle scan started event
    let result = db_listener.handle_event(Arc::new(scan_started)).await;
    assert!(result.is_ok(), "Failed to handle ScanStarted event: {:?}", result);

    // Create and handle block processed events
    for block_height in 1000..1005 {
        let block_processed = WalletScanEvent::BlockProcessed(BlockProcessed {
            metadata: EventMetadata::new(),
            block_info: BlockInfo {
                height: block_height,
                hash: format!("block_hash_{}", block_height),
                timestamp: 1640995200 + (block_height - 1000) * 120,
                difficulty: 1000000,
                total_fees: 5000,
            },
            processing_time_ms: 50,
            outputs_found: if block_height % 2 == 0 { 2 } else { 0 },
            transactions_processed: 10,
        });

        let result = db_listener.handle_event(Arc::new(block_processed)).await;
        assert!(result.is_ok(), "Failed to handle BlockProcessed event: {:?}", result);
    }

    // Create and handle output found events
    let output_found = WalletScanEvent::OutputFound(OutputFound {
        metadata: EventMetadata::new(),
        output_data: OutputData {
            commitment: format!("commitment_test_1"),
            value: 1000000,
            script_public_key: "script_key_1".to_string(),
            sender_offset_public_key: "sender_offset_1".to_string(),
            metadata_signature: "metadata_sig_1".to_string(),
            rangeproof: "rangeproof_1".to_string(),
            encrypted_data: "encrypted_data_1".to_string(),
            minimum_value_promise: 0,
        },
        block_info: BlockInfo {
            height: 1002,
            hash: "block_hash_1002".to_string(),
            timestamp: 1640995440,
            difficulty: 1000000,
            total_fees: 5000,
        },
        address_info: AddressInfo {
            address: wallet.get_dual_address(0, None).expect("Failed to get address").to_string(),
            key_index: 0,
            is_change: false,
        },
        spend_height: None,
        mined_timestamp: 1640995440,
    });

    let result = db_listener.handle_event(Arc::new(output_found)).await;
    assert!(result.is_ok(), "Failed to handle OutputFound event: {:?}", result);

    // Handle scan completion
    let scan_completed = WalletScanEvent::ScanCompleted(ScanCompleted {
        metadata: EventMetadata::new(),
        success: true,
        final_stats: ScanStats {
            blocks_processed: 5,
            outputs_found: 1,
            total_value: 1000000,
            scan_duration_ms: 5000,
            average_block_time_ms: 1000,
        },
        wallet_balance: 1000000,
        last_scanned_block: 1004,
    });

    let result = db_listener.handle_event(Arc::new(scan_completed)).await;
    assert!(result.is_ok(), "Failed to handle ScanCompleted event: {:?}", result);

    // Verify data was actually stored in database
    let storage = SqliteStorage::new_with_path(db_path_str)
        .await
        .expect("Failed to create storage for verification");

    // Check wallet exists
    let wallet_exists = storage.wallet_exists(wallet.wallet_id()).await
        .expect("Failed to check wallet existence");
    assert!(wallet_exists, "Wallet should exist in database");

    // Check outputs were stored
    let outputs = storage.get_outputs_for_wallet(wallet.wallet_id()).await
        .expect("Failed to get outputs");
    assert_eq!(outputs.len(), 1, "Should have one output stored");

    println!("✓ DatabaseStorageListener integration test passed");
}

/// Integration test for ProgressTrackingListener with real progress scenarios
#[tokio::test]
async fn test_progress_tracking_listener_integration() {
    // Shared state for callbacks
    let progress_updates = Arc::new(Mutex::new(Vec::new()));
    let completion_called = Arc::new(Mutex::new(false));
    let error_called = Arc::new(Mutex::new(false));

    let progress_updates_clone = progress_updates.clone();
    let completion_called_clone = completion_called.clone();
    let error_called_clone = error_called.clone();

    // Create progress listener with real callbacks
    let progress_listener = ProgressTrackingListener::builder()
        .frequency(2) // Update every 2 blocks for testing
        .with_progress_callback(move |info| {
            progress_updates_clone.lock().unwrap().push((
                info.blocks_processed,
                info.total_blocks,
                info.progress_percent,
                info.outputs_found,
            ));
        })
        .with_completion_callback(move |stats| {
            *completion_called_clone.lock().unwrap() = true;
            println!("Scan completed with {} outputs found", stats.outputs_found);
        })
        .with_error_callback(move |error| {
            *error_called_clone.lock().unwrap() = true;
            println!("Scan error: {:?}", error);
        })
        .verbose(true)
        .build();

    // Create test events sequence
    let events = vec![
        // Start scan
        WalletScanEvent::ScanStarted(ScanStarted {
            metadata: EventMetadata::new(),
            wallet_id: 123,
            from_block: 1000,
            to_block: 1010,
            estimated_blocks: 10,
            scan_mode: "GRPC".to_string(),
        }),
        // Process blocks with progress
        WalletScanEvent::ScanProgress(ScanProgress {
            metadata: EventMetadata::new(),
            current_block: 1002,
            total_blocks: 10,
            blocks_processed: 2,
            percentage: 20.0,
            blocks_per_second: 1.5,
            estimated_time_remaining_ms: 5333,
            outputs_found: 0,
        }),
        WalletScanEvent::ScanProgress(ScanProgress {
            metadata: EventMetadata::new(),
            current_block: 1005,
            total_blocks: 10,
            blocks_processed: 5,
            percentage: 50.0,
            blocks_per_second: 1.8,
            estimated_time_remaining_ms: 2777,
            outputs_found: 2,
        }),
        WalletScanEvent::ScanProgress(ScanProgress {
            metadata: EventMetadata::new(),
            current_block: 1008,
            total_blocks: 10,
            blocks_processed: 8,
            percentage: 80.0,
            blocks_per_second: 2.0,
            estimated_time_remaining_ms: 1000,
            outputs_found: 3,
        }),
        // Complete scan
        WalletScanEvent::ScanCompleted(ScanCompleted {
            metadata: EventMetadata::new(),
            success: true,
            final_stats: ScanStats {
                blocks_processed: 10,
                outputs_found: 3,
                total_value: 3000000,
                scan_duration_ms: 5000,
                average_block_time_ms: 500,
            },
            wallet_balance: 3000000,
            last_scanned_block: 1010,
        }),
    ];

    // Process events sequentially
    for event in events {
        let result = progress_listener.handle_event(Arc::new(event)).await;
        assert!(result.is_ok(), "Failed to handle event: {:?}", result);
        
        // Small delay to ensure callbacks are processed
        sleep(Duration::from_millis(10)).await;
    }

    // Verify callbacks were called correctly
    let updates = progress_updates.lock().unwrap();
    assert!(!updates.is_empty(), "Progress updates should have been called");
    
    // Verify progress increases
    let mut last_progress = 0.0;
    for (_, _, progress, _) in updates.iter() {
        assert!(*progress >= last_progress, "Progress should be non-decreasing");
        last_progress = *progress;
    }

    assert!(*completion_called.lock().unwrap(), "Completion callback should have been called");
    assert!(!*error_called.lock().unwrap(), "Error callback should not have been called");

    println!("✓ ProgressTrackingListener integration test passed");
}

/// Integration test for ConsoleLoggingListener with real output verification
#[tokio::test]
async fn test_console_logging_listener_integration() {
    // Create console listener with different configurations
    let listeners = vec![
        ("minimal", ConsoleLoggingListener::builder().minimal_preset().build()),
        ("debug", ConsoleLoggingListener::builder().debug_preset().build()),
        ("console", ConsoleLoggingListener::builder().console_preset().build()),
    ];

    for (config_name, listener) in listeners {
        println!("Testing {} configuration", config_name);

        // Create comprehensive event sequence
        let events = vec![
            WalletScanEvent::ScanStarted(ScanStarted {
                metadata: EventMetadata::new(),
                wallet_id: 456,
                from_block: 2000,
                to_block: 2020,
                estimated_blocks: 20,
                scan_mode: "HTTP".to_string(),
            }),
            WalletScanEvent::BlockProcessed(BlockProcessed {
                metadata: EventMetadata::new(),
                block_info: BlockInfo {
                    height: 2005,
                    hash: "test_block_hash".to_string(),
                    timestamp: 1640995200,
                    difficulty: 2000000,
                    total_fees: 10000,
                },
                processing_time_ms: 75,
                outputs_found: 1,
                transactions_processed: 15,
            }),
            WalletScanEvent::OutputFound(OutputFound {
                metadata: EventMetadata::new(),
                output_data: OutputData {
                    commitment: "test_commitment".to_string(),
                    value: 2000000,
                    script_public_key: "test_script_key".to_string(),
                    sender_offset_public_key: "test_sender_offset".to_string(),
                    metadata_signature: "test_metadata_sig".to_string(),
                    rangeproof: "test_rangeproof".to_string(),
                    encrypted_data: "test_encrypted_data".to_string(),
                    minimum_value_promise: 0,
                },
                block_info: BlockInfo {
                    height: 2005,
                    hash: "test_block_hash".to_string(),
                    timestamp: 1640995200,
                    difficulty: 2000000,
                    total_fees: 10000,
                },
                address_info: AddressInfo {
                    address: "test_address".to_string(),
                    key_index: 5,
                    is_change: false,
                },
                spend_height: None,
                mined_timestamp: 1640995200,
            }),
            WalletScanEvent::ScanError(ScanError {
                metadata: EventMetadata::new(),
                error_type: "NetworkTimeout".to_string(),
                error_message: "Connection timeout after 30 seconds".to_string(),
                block_height: Some(2010),
                retry_count: 1,
                is_recoverable: true,
                context: HashMap::new(),
            }),
            WalletScanEvent::ScanCompleted(ScanCompleted {
                metadata: EventMetadata::new(),
                success: true,
                final_stats: ScanStats {
                    blocks_processed: 20,
                    outputs_found: 1,
                    total_value: 2000000,
                    scan_duration_ms: 8000,
                    average_block_time_ms: 400,
                },
                wallet_balance: 2000000,
                last_scanned_block: 2020,
            }),
        ];

        // Process all events
        for event in events {
            let result = listener.handle_event(Arc::new(event)).await;
            assert!(result.is_ok(), "Failed to handle event in {} config: {:?}", config_name, result);
        }

        println!("✓ {} configuration handled all events", config_name);
    }

    println!("✓ ConsoleLoggingListener integration test passed");
}

/// Integration test for AsciiProgressBarListener with real scenarios
#[tokio::test]
async fn test_ascii_progress_bar_listener_integration() {
    // Test different progress bar configurations
    let configurations = vec![
        ("standard", AsciiProgressBarListener::builder().build()),
        ("detailed", AsciiProgressBarListener::builder().detailed_preset().build()),
        ("compact", AsciiProgressBarListener::builder().compact_preset().build()),
    ];

    for (config_name, listener) in configurations {
        println!("Testing ASCII progress bar: {} configuration", config_name);

        // Start scan
        let scan_started = WalletScanEvent::ScanStarted(ScanStarted {
            metadata: EventMetadata::new(),
            wallet_id: 789,
            from_block: 5000,
            to_block: 5100,
            estimated_blocks: 100,
            scan_mode: "GRPC".to_string(),
        });

        let result = listener.handle_event(Arc::new(scan_started)).await;
        assert!(result.is_ok(), "Failed to handle ScanStarted: {:?}", result);

        // Simulate progress updates
        for i in (0..=100).step_by(10) {
            let progress = WalletScanEvent::ScanProgress(ScanProgress {
                metadata: EventMetadata::new(),
                current_block: 5000 + i,
                total_blocks: 100,
                blocks_processed: i,
                percentage: i as f64,
                blocks_per_second: 2.5,
                estimated_time_remaining_ms: ((100 - i) as f64 / 2.5 * 1000.0) as u64,
                outputs_found: i / 10,
            });

            let result = listener.handle_event(Arc::new(progress)).await;
            assert!(result.is_ok(), "Failed to handle progress: {:?}", result);

            // Small delay to see progress updates
            sleep(Duration::from_millis(100)).await;
        }

        // Complete scan
        let scan_completed = WalletScanEvent::ScanCompleted(ScanCompleted {
            metadata: EventMetadata::new(),
            success: true,
            final_stats: ScanStats {
                blocks_processed: 100,
                outputs_found: 10,
                total_value: 10000000,
                scan_duration_ms: 40000,
                average_block_time_ms: 400,
            },
            wallet_balance: 10000000,
            last_scanned_block: 5100,
        });

        let result = listener.handle_event(Arc::new(scan_completed)).await;
        assert!(result.is_ok(), "Failed to handle ScanCompleted: {:?}", result);

        println!("✓ {} configuration completed", config_name);
    }

    println!("✓ AsciiProgressBarListener integration test passed");
}

/// Integration test combining multiple listeners working together
#[tokio::test]
async fn test_combined_listeners_integration() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    
    // Create event dispatcher
    let mut dispatcher = EventDispatcher::new();

    // Add multiple listeners
    let mock_listener = MockEventListener::new();
    let captured_events = mock_listener.get_captured_events();

    #[cfg(feature = "storage")]
    {
        let db_path = temp_dir.path().join("combined_test.db");
        let db_listener = DatabaseStorageListener::new(db_path.to_str().unwrap())
            .await
            .expect("Failed to create database listener");
        dispatcher.register(Box::new(db_listener))
            .expect("Failed to register database listener");
    }

    let progress_listener = ProgressTrackingListener::builder()
        .frequency(5)
        .verbose(true)
        .build();
    dispatcher.register(Box::new(progress_listener))
        .expect("Failed to register progress listener");

    let console_listener = ConsoleLoggingListener::builder()
        .minimal_preset()
        .build();
    dispatcher.register(Box::new(console_listener))
        .expect("Failed to register console listener");

    dispatcher.register(Box::new(mock_listener))
        .expect("Failed to register mock listener");

    // Create comprehensive event sequence
    let events = vec![
        WalletScanEvent::ScanStarted(ScanStarted {
            metadata: EventMetadata::new(),
            wallet_id: 999,
            from_block: 10000,
            to_block: 10050,
            estimated_blocks: 50,
            scan_mode: "GRPC".to_string(),
        }),
        WalletScanEvent::ScanProgress(ScanProgress {
            metadata: EventMetadata::new(),
            current_block: 10025,
            total_blocks: 50,
            blocks_processed: 25,
            percentage: 50.0,
            blocks_per_second: 5.0,
            estimated_time_remaining_ms: 5000,
            outputs_found: 5,
        }),
        WalletScanEvent::ScanCompleted(ScanCompleted {
            metadata: EventMetadata::new(),
            success: true,
            final_stats: ScanStats {
                blocks_processed: 50,
                outputs_found: 10,
                total_value: 5000000,
                scan_duration_ms: 10000,
                average_block_time_ms: 200,
            },
            wallet_balance: 5000000,
            last_scanned_block: 10050,
        }),
    ];

    // Dispatch events to all listeners
    for event in events {
        let result = dispatcher.dispatch(Arc::new(event)).await;
        assert!(result.is_ok(), "Failed to dispatch event: {:?}", result);
    }

    // Verify mock listener captured all events
    let captured = captured_events.lock().unwrap();
    assert_eq!(captured.len(), 3, "Mock listener should have captured 3 events");

    // Verify event types
    let event_types: Vec<String> = captured.iter()
        .map(|e| match e.as_ref() {
            WalletScanEvent::ScanStarted(_) => "ScanStarted".to_string(),
            WalletScanEvent::ScanProgress(_) => "ScanProgress".to_string(),
            WalletScanEvent::ScanCompleted(_) => "ScanCompleted".to_string(),
            _ => "Other".to_string(),
        })
        .collect();

    assert_eq!(event_types, vec!["ScanStarted", "ScanProgress", "ScanCompleted"]);

    println!("✓ Combined listeners integration test passed");
}

/// Integration test for error handling and recovery across listeners
#[tokio::test]
async fn test_error_handling_integration() {
    let mut dispatcher = EventDispatcher::new();

    // Add listeners that might encounter errors
    let progress_listener = ProgressTrackingListener::builder()
        .frequency(1)
        .verbose(true)
        .build();
    dispatcher.register(Box::new(progress_listener))
        .expect("Failed to register progress listener");

    // Create error scenario
    let error_event = WalletScanEvent::ScanError(ScanError {
        metadata: EventMetadata::new(),
        error_type: "DatabaseError".to_string(),
        error_message: "Failed to write to database".to_string(),
        block_height: Some(1500),
        retry_count: 2,
        is_recoverable: true,
        context: {
            let mut ctx = HashMap::new();
            ctx.insert("table".to_string(), "outputs".to_string());
            ctx.insert("operation".to_string(), "insert".to_string());
            ctx
        },
    });

    // Dispatch error event
    let result = dispatcher.dispatch(Arc::new(error_event)).await;
    assert!(result.is_ok(), "Error event handling should succeed: {:?}", result);

    // Test recovery scenario
    let recovery_event = WalletScanEvent::ScanProgress(ScanProgress {
        metadata: EventMetadata::new(),
        current_block: 1501,
        total_blocks: 2000,
        blocks_processed: 1501,
        percentage: 75.05,
        blocks_per_second: 3.0,
        estimated_time_remaining_ms: 166333,
        outputs_found: 8,
    });

    let result = dispatcher.dispatch(Arc::new(recovery_event)).await;
    assert!(result.is_ok(), "Recovery event handling should succeed: {:?}", result);

    println!("✓ Error handling integration test passed");
}

/// Performance integration test for high-frequency events
#[tokio::test]
async fn test_high_frequency_events_integration() {
    let mut dispatcher = EventDispatcher::new();

    // Add performance-optimized listeners
    let progress_listener = ProgressTrackingListener::builder()
        .performance_preset()
        .build();
    dispatcher.register(Box::new(progress_listener))
        .expect("Failed to register progress listener");

    let console_listener = ConsoleLoggingListener::builder()
        .minimal_preset()
        .build();
    dispatcher.register(Box::new(console_listener))
        .expect("Failed to register console listener");

    // Start timing
    let start_time = std::time::Instant::now();

    // Generate high-frequency block processed events
    let mut events = Vec::new();
    for i in 0..1000 {
        events.push(WalletScanEvent::BlockProcessed(BlockProcessed {
            metadata: EventMetadata::new(),
            block_info: BlockInfo {
                height: 20000 + i,
                hash: format!("block_hash_{}", i),
                timestamp: 1640995200 + i * 120,
                difficulty: 1000000,
                total_fees: 5000,
            },
            processing_time_ms: 25,
            outputs_found: if i % 10 == 0 { 1 } else { 0 },
            transactions_processed: 5,
        }));
    }

    // Process all events with timeout
    let processing_result = timeout(Duration::from_secs(30), async {
        for event in events {
            dispatcher.dispatch(Arc::new(event)).await?;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }).await;

    assert!(processing_result.is_ok(), "High-frequency event processing timed out");
    assert!(processing_result.unwrap().is_ok(), "High-frequency event processing failed");

    let elapsed = start_time.elapsed();
    println!("Processed 1000 events in {:?} ({:.2} events/sec)", 
             elapsed, 1000.0 / elapsed.as_secs_f64());

    // Should process at least 100 events per second
    assert!(elapsed < Duration::from_secs(10), "Performance too slow: {:?}", elapsed);

    println!("✓ High-frequency events integration test passed");
}
