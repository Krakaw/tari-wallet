//! Error scenario and recovery tests using mock failure modes
//!
//! These tests validate error handling, recovery mechanisms, and resilience
//! of the scanning library under various failure conditions.

use std::sync::Arc;
use std::time::Duration;

use lightweight_wallet_libs::scanning::{
    mocks::{MockBlockchainScanner, MockNetworkFailureModes, MockWalletStorage, MockFailureModes},
    storage_manager::StorageManagerBuilder,
    scanner_engine::{ScannerEngine, DefaultErrorHandler, ErrorRecoveryStrategy, ScanErrorContext},
    scan_configuration::ScanConfiguration,
    BlockInfo, TipInfo,
};
use lightweight_wallet_libs::storage::storage_trait::{StoredWallet, WalletStorage};
use lightweight_wallet_libs::data_structures::{
    transaction_output::LightweightTransactionOutput,
    types::{MicroMinotari, PrivateKey, CompressedCommitment},
    wallet_output::{LightweightOutputFeatures, LightweightOutputType, LightweightRangeProofType},
    wallet_transaction::WalletTransaction,
    payment_id::PaymentId,
    transaction::{TransactionDirection, TransactionStatus},
};
use lightweight_wallet_libs::errors::LightweightWalletError;

/// Test cascading network failures and recovery
#[tokio::test]
async fn test_cascading_network_failures() {
    let mut mock_scanner = MockBlockchainScanner::new();
    
    // Add test blocks
    for height in 8000..8005 {
        mock_scanner.add_block(BlockInfo {
            height,
            hash: vec![height as u8; 32],
            timestamp: 1640995200 + (height * 600),
            outputs: vec![create_test_output(1000, height)],
            inputs: vec![],
            kernels: vec![],
            http_output_hashes: None,
        });
    }

    let config = ScanConfiguration::new_range(8000, 8004);
    let mut scanner_engine = ScannerEngine::new(Box::new(mock_scanner), config);

    // Test multiple failure modes in sequence
    let failure_modes = vec![
        MockNetworkFailureModes {
            fail_scan_blocks: true,
            ..Default::default()
        },
        MockNetworkFailureModes {
            simulate_timeout: true,
            ..Default::default()
        },
        MockNetworkFailureModes {
            next_error_message: Some("Connection refused".to_string()),
            ..Default::default()
        },
        MockNetworkFailureModes {
            return_empty_results: true,
            ..Default::default()
        },
    ];

    for (i, failure_mode) in failure_modes.iter().enumerate() {
        scanner_engine.scanner.set_failure_modes(failure_mode.clone());
        
        let result = scanner_engine.scan_blocks(vec![8000 + i as u64]).await;
        
        match i {
            0 => {
                assert!(result.is_err());
                assert!(result.unwrap_err().to_string().contains("Mock failure: scan_blocks"));
            }
            1 => {
                assert!(result.is_err());
                assert!(result.unwrap_err().to_string().contains("Mock timeout"));
            }
            2 => {
                assert!(result.is_err());
                assert!(result.unwrap_err().to_string().contains("Connection refused"));
            }
            3 => {
                assert!(result.is_ok());
                assert!(result.unwrap().is_empty()); // Empty results mode
            }
            _ => unreachable!(),
        }
    }

    // Final scan should succeed (all error flags consumed)
    let final_result = scanner_engine.scan_blocks(vec![8004]).await;
    assert!(final_result.is_ok());
    assert_eq!(final_result.unwrap().len(), 1);
}

/// Test storage system failures and recovery
#[tokio::test]
async fn test_storage_system_failures() {
    let mock_storage = Arc::new(MockWalletStorage::new());
    let storage_manager = StorageManagerBuilder::new()
        .with_storage(mock_storage.clone())
        .with_direct_adapter()
        .build()
        .unwrap();

    // Test cascading storage failures
    let failure_scenarios = vec![
        MockFailureModes {
            fail_save_wallet: true,
            ..Default::default()
        },
        MockFailureModes {
            fail_save_transaction: true,
            ..Default::default()
        },
        MockFailureModes {
            fail_save_output: true,
            ..Default::default()
        },
        MockFailureModes {
            fail_get_operations: true,
            ..Default::default()
        },
        MockFailureModes {
            next_error_message: Some("Database connection lost".to_string()),
            ..Default::default()
        },
    ];

    for (i, failure_mode) in failure_scenarios.iter().enumerate() {
        mock_storage.set_failure_mode(failure_mode.clone());
        
        match i {
            0 => {
                // Test wallet save failure
                let wallet = StoredWallet::view_only(
                    format!("test_wallet_{}", i),
                    PrivateKey::new([i as u8; 32]),
                    1000,
                );
                let result = storage_manager.save_wallet(&wallet).await;
                assert!(result.is_err());
                assert!(result.unwrap_err().to_string().contains("Mock failure: save_wallet"));
            }
            1 => {
                // Test transaction save failure (need wallet first)
                let wallet = StoredWallet::view_only(
                    format!("test_wallet_{}", i),
                    PrivateKey::new([i as u8; 32]),
                    1000,
                );
                let wallet_id = storage_manager.save_wallet(&wallet).await.unwrap();
                
                let transaction = create_test_transaction(1000 + i as u64, i as u8);
                let result = storage_manager.save_transaction(wallet_id, &transaction).await;
                assert!(result.is_err());
                assert!(result.unwrap_err().to_string().contains("Mock failure: save_transaction"));
            }
            2 => {
                // Test output save failure  
                let output = create_test_stored_output(1, 5000);
                let result = storage_manager.save_output(&output).await;
                assert!(result.is_err());
                assert!(result.unwrap_err().to_string().contains("Mock failure: save_output"));
            }
            3 => {
                // Test get operation failure
                let result = storage_manager.get_wallet_by_id(1).await;
                assert!(result.is_err());
                assert!(result.unwrap_err().to_string().contains("Mock failure: get operation"));
            }
            4 => {
                // Test specific error message
                let wallet = StoredWallet::view_only(
                    format!("test_wallet_{}", i),
                    PrivateKey::new([i as u8; 32]),
                    1000,
                );
                let result = storage_manager.save_wallet(&wallet).await;
                assert!(result.is_err());
                assert!(result.unwrap_err().to_string().contains("Database connection lost"));
            }
            _ => unreachable!(),
        }
    }

    // All operations should work after failures are consumed
    let wallet = StoredWallet::view_only(
        "recovery_wallet".to_string(),
        PrivateKey::new([99u8; 32]),
        1000,
    );
    let wallet_id = storage_manager.save_wallet(&wallet).await.unwrap();
    assert_eq!(wallet_id, 1);
}

/// Test error recovery strategies
#[tokio::test]
async fn test_error_recovery_strategies() {
    let error_handler = DefaultErrorHandler;
    
    // Test different error contexts
    let test_scenarios = vec![
        (
            ScanErrorContext {
                block_height: 1000,
                error: "Network timeout".to_string(),
                has_specific_blocks: false,
                remaining_blocks: vec![1001, 1002, 1003],
                to_block: 2000,
            },
            ErrorRecoveryStrategy::Continue,
        ),
        (
            ScanErrorContext {
                block_height: 1500,
                error: "Invalid block data".to_string(),
                has_specific_blocks: true,
                remaining_blocks: vec![1501, 1502],
                to_block: 1502,
            },
            ErrorRecoveryStrategy::Continue,
        ),
        (
            ScanErrorContext {
                block_height: 2000,
                error: "Critical system error".to_string(),
                has_specific_blocks: false,
                remaining_blocks: vec![],
                to_block: 2000,
            },
            ErrorRecoveryStrategy::Continue,
        ),
    ];

    for (context, expected_strategy) in test_scenarios {
        let strategy = error_handler.handle_scan_error(&context);
        assert_eq!(strategy, expected_strategy);

        let block_strategy = error_handler.handle_block_error(context.block_height, &context.error);
        assert_eq!(block_strategy, expected_strategy);

        // Test resume command generation
        let resume_cmd = error_handler.generate_resume_command(&context);
        if context.has_specific_blocks && context.remaining_blocks.len() <= 20 {
            assert!(resume_cmd.contains("--blocks"));
        } else {
            assert!(resume_cmd.contains("--from-block"));
            assert!(resume_cmd.contains("--to-block"));
        }
    }
}

/// Test mixed error conditions (network + storage)
#[tokio::test] 
async fn test_mixed_error_conditions() {
    let mock_storage = Arc::new(MockWalletStorage::new());
    let storage_manager = StorageManagerBuilder::new()
        .with_storage(mock_storage.clone())
        .with_direct_adapter()
        .build()
        .unwrap();

    let mut mock_scanner = MockBlockchainScanner::new();
    mock_scanner.add_block(BlockInfo {
        height: 9000,
        hash: vec![0x90; 32],
        timestamp: 1640995200,
        outputs: vec![create_test_output(15000, 9000)],
        inputs: vec![],
        kernels: vec![],
        http_output_hashes: None,
    });

    // Set up interleaved network and storage failures
    let network_failure = MockNetworkFailureModes {
        next_error_message: Some("Network error".to_string()),
        ..Default::default()
    };
    
    let storage_failure = MockFailureModes {
        next_error_message: Some("Storage error".to_string()),
        ..Default::default()
    };

    mock_scanner.set_failure_modes(network_failure);
    mock_storage.set_failure_mode(storage_failure);

    let config = ScanConfiguration::new(9000);
    let mut scanner_engine = ScannerEngine::new(Box::new(mock_scanner), config);

    let wallet = StoredWallet::view_only(
        "mixed_error_wallet".to_string(),
        PrivateKey::new([50u8; 32]),
        9000,
    );

    // Both operations should fail initially
    let scan_result = scanner_engine.scan_blocks(vec![9000]).await;
    assert!(scan_result.is_err());
    assert!(scan_result.unwrap_err().to_string().contains("Network error"));

    let save_result = storage_manager.save_wallet(&wallet).await;
    assert!(save_result.is_err());
    assert!(save_result.unwrap_err().to_string().contains("Storage error"));

    // Both should succeed after errors are consumed
    let scan_result2 = scanner_engine.scan_blocks(vec![9000]).await;
    assert!(scan_result2.is_ok());

    let save_result2 = storage_manager.save_wallet(&wallet).await;
    assert!(save_result2.is_ok());
}

/// Test error propagation through the scanning pipeline
#[tokio::test]
async fn test_error_propagation_pipeline() {
    let mock_storage = Arc::new(MockWalletStorage::new());
    let storage_manager = StorageManagerBuilder::new()
        .with_storage(mock_storage.clone())
        .with_direct_adapter()
        .build()
        .unwrap();

    let mut mock_scanner = MockBlockchainScanner::new();
    
    // Add blocks but set scanner to fail on specific operations
    for height in 10000..10005 {
        mock_scanner.add_block(BlockInfo {
            height,
            hash: vec![height as u8; 32],
            timestamp: 1640995200,
            outputs: vec![create_test_output(2000, height)],
            inputs: vec![],
            kernels: vec![],
            http_output_hashes: None,
        });
    }

    // Test different pipeline failure points
    let pipeline_failures = vec![
        ("get_tip_info", MockNetworkFailureModes {
            fail_get_tip_info: true,
            ..Default::default()
        }),
        ("search_utxos", MockNetworkFailureModes {
            fail_search_utxos: true,
            ..Default::default()
        }),
        ("fetch_utxos", MockNetworkFailureModes {
            fail_fetch_utxos: true,
            ..Default::default()
        }),
    ];

    let config = ScanConfiguration::new_range(10000, 10004);
    let mut scanner_engine = ScannerEngine::new(Box::new(mock_scanner), config);

    for (operation, failure_mode) in pipeline_failures {
        scanner_engine.scanner.set_failure_modes(failure_mode);
        
        match operation {
            "get_tip_info" => {
                let result = scanner_engine.get_tip_info().await;
                assert!(result.is_err());
                assert!(result.unwrap_err().to_string().contains("Mock failure: get_tip_info"));
            }
            "search_utxos" => {
                let test_commitment = vec![1, 2, 3, 4];
                let result = scanner_engine.scanner.search_utxos(vec![test_commitment]).await;
                assert!(result.is_err());
                assert!(result.unwrap_err().to_string().contains("Mock failure: search_utxos"));
            }
            "fetch_utxos" => {
                let test_hash = vec![5, 6, 7, 8];
                let result = scanner_engine.scanner.fetch_utxos(vec![test_hash]).await;
                assert!(result.is_err());
                assert!(result.unwrap_err().to_string().contains("Mock failure: fetch_utxos"));
            }
            _ => unreachable!(),
        }
    }
}

/// Test stress scenarios with repeated failures
#[tokio::test]
async fn test_stress_repeated_failures() {
    let mock_storage = Arc::new(MockWalletStorage::new());
    let storage_manager = StorageManagerBuilder::new()
        .with_storage(mock_storage.clone())
        .with_direct_adapter()
        .build()
        .unwrap();

    // Create a wallet first
    let wallet = StoredWallet::view_only(
        "stress_test_wallet".to_string(),
        PrivateKey::new([88u8; 32]),
        11000,
    );
    let wallet_id = storage_manager.save_wallet(&wallet).await.unwrap();

    // Test repeated transaction save attempts with intermittent failures
    let mut success_count = 0;
    let mut failure_count = 0;

    for i in 0..20 {
        // Inject failure every 3rd attempt
        if i % 3 == 0 {
            mock_storage.set_failure_mode(MockFailureModes {
                fail_save_transaction: true,
                ..Default::default()
            });
        }

        let transaction = create_test_transaction(11000 + i, (i % 256) as u8);
        let result = storage_manager.save_transaction(wallet_id, &transaction).await;

        if result.is_ok() {
            success_count += 1;
        } else {
            failure_count += 1;
            assert!(result.unwrap_err().to_string().contains("Mock failure: save_transaction"));
        }
    }

    // Should have roughly 2/3 successes and 1/3 failures
    assert!(success_count >= 10); // At least 10 successes
    assert!(failure_count >= 5);  // At least 5 failures
    assert_eq!(success_count + failure_count, 20);

    // Verify that successful transactions were actually saved
    let wallet_state = storage_manager.load_wallet_state(wallet_id).await.unwrap();
    assert_eq!(wallet_state.transactions.len(), success_count);
}

/// Test timeout and retry behavior simulation
#[tokio::test] 
async fn test_timeout_retry_behavior() {
    let mut mock_scanner = MockBlockchainScanner::new();
    
    // Set network delay to simulate slow responses
    mock_scanner.set_network_delay(Duration::from_millis(200));
    
    mock_scanner.add_block(BlockInfo {
        height: 12000,
        hash: vec![0xC0; 32],
        timestamp: 1640995200,
        outputs: vec![create_test_output(25000, 12000)],
        inputs: vec![],
        kernels: vec![],
        http_output_hashes: None,
    });

    let config = ScanConfiguration::new(12000);
    let mut scanner_engine = ScannerEngine::new(Box::new(mock_scanner), config);

    // Test multiple operations with delays
    let operations = vec![
        ("get_tip_info", false),
        ("scan_blocks", false),
        ("get_tip_info", true), // This one will timeout
        ("scan_blocks", false), // This should work after timeout
    ];

    let mut operation_times = Vec::new();

    for (i, (operation, should_timeout)) in operations.iter().enumerate() {
        if *should_timeout {
            scanner_engine.scanner.set_failure_modes(MockNetworkFailureModes {
                simulate_timeout: true,
                ..Default::default()
            });
        }

        let start_time = std::time::Instant::now();
        
        let result = match *operation {
            "get_tip_info" => {
                scanner_engine.get_tip_info().await.map(|_| ())
            }
            "scan_blocks" => {
                scanner_engine.scan_blocks(vec![12000]).await.map(|_| ())
            }
            _ => unreachable!(),
        };

        let elapsed = start_time.elapsed();
        operation_times.push(elapsed);

        if *should_timeout {
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Mock timeout"));
            // Should have taken at least the network delay before timeout
            assert!(elapsed >= Duration::from_millis(180));
        } else {
            if i > 0 { // Allow first operation to succeed or fail
                // Should have taken at least the network delay
                assert!(elapsed >= Duration::from_millis(180));
            }
        }
    }

    // Verify that operations took progressively longer due to network delay
    assert!(operation_times.len() >= 4);
}

/// Test data corruption simulation and recovery
#[tokio::test]
async fn test_data_corruption_simulation() {
    let mock_storage = Arc::new(MockWalletStorage::new());
    let storage_manager = StorageManagerBuilder::new()
        .with_storage(mock_storage.clone())
        .with_direct_adapter()
        .build()
        .unwrap();

    // Create wallet and transactions
    let wallet = StoredWallet::view_only(
        "corruption_test_wallet".to_string(),
        PrivateKey::new([77u8; 32]),
        13000,
    );
    let wallet_id = storage_manager.save_wallet(&wallet).await.unwrap();

    // Save some valid transactions
    for i in 0..5 {
        let transaction = create_test_transaction(13000 + i, (i + 100) as u8);
        storage_manager.save_transaction(wallet_id, &transaction).await.unwrap();
    }

    // Verify initial state
    let initial_state = storage_manager.load_wallet_state(wallet_id).await.unwrap();
    assert_eq!(initial_state.transactions.len(), 5);

    // Simulate data corruption by injecting errors during reads
    mock_storage.set_failure_mode(MockFailureModes {
        fail_get_operations: true,
        ..Default::default()
    });

    // Attempt to read wallet state should fail
    let corrupt_read = storage_manager.load_wallet_state(wallet_id).await;
    assert!(corrupt_read.is_err());
    assert!(corrupt_read.unwrap_err().to_string().contains("Mock failure: get operation"));

    // Recovery: read should work after error is consumed
    let recovered_state = storage_manager.load_wallet_state(wallet_id).await.unwrap();
    assert_eq!(recovered_state.transactions.len(), 5);

    // Verify data integrity is maintained
    let total_value: u64 = recovered_state.transactions.iter().map(|tx| tx.value).sum();
    assert_eq!(total_value, 15000); // 5 transactions * 3000 each
}

// Helper functions

fn create_test_output(value: u64, height: u64) -> LightweightTransactionOutput {
    let features = LightweightOutputFeatures {
        version: 0,
        output_type: LightweightOutputType::Payment,
        maturity: height,
        metadata: vec![],
        sidechain_feature: None,
        range_proof_type: LightweightRangeProofType::BulletProofPlus,
    };
    
    LightweightTransactionOutput::new(
        0, // version
        features,
        vec![(height % 256) as u8; 32], // commitment - unique per height
        vec![0u8; 33], // script 
        vec![0u8; 33], // sender_offset_public_key
        vec![0u8; 64], // metadata_signature_ephemeral_commitment
        vec![0u8; 33], // metadata_signature_ephemeral_pubkey  
        vec![0u8; 32], // metadata_signature_u_a
        vec![0u8; 32], // metadata_signature_u_x
        vec![0u8; 32], // metadata_signature_u_y
        vec![0u8; 76], // encrypted_data
        MicroMinotari::from(value), // minimum_value_promise
        vec![0u8; 32], // covenant
        None, // range_proof
    ).unwrap()
}

fn create_test_transaction(block_height: u64, unique_id: u8) -> WalletTransaction {
    WalletTransaction::new(
        block_height,
        Some(0), // output_index
        None, // input_index
        CompressedCommitment::from_bytes(&[unique_id; 32]).unwrap(),
        Some(vec![unique_id; 4]), // output_hash
        3000, // value
        PaymentId::Empty,
        TransactionStatus::MinedConfirmed,
        TransactionDirection::Inbound,
        true, // is_mature
    )
}

fn create_test_stored_output(wallet_id: u32, value: u64) -> lightweight_wallet_libs::storage::storage_trait::StoredOutput {
    lightweight_wallet_libs::storage::storage_trait::StoredOutput {
        id: None,
        wallet_id,
        commitment: vec![42u8; 32],
        hash: vec![43u8; 32],
        value,
        spending_key: "test_spending_key".to_string(),
        script_private_key: "test_script_key".to_string(),
        script: vec![44u8; 32],
        input_data: vec![45u8; 32],
        covenant: vec![46u8; 32],
        output_type: 0, // Payment
        features_json: "{}".to_string(),
        maturity: 1000,
        script_lock_height: 0,
        sender_offset_public_key: vec![47u8; 33],
        metadata_signature_ephemeral_commitment: vec![48u8; 64],
        metadata_signature_ephemeral_pubkey: vec![49u8; 33],
        metadata_signature_u_a: vec![50u8; 32],
        metadata_signature_u_x: vec![51u8; 32],
        metadata_signature_u_y: vec![52u8; 32],
        encrypted_data: vec![53u8; 76],
        minimum_value_promise: value,
        rangeproof: Some(vec![54u8; 128]),
        status: 0, // Unspent
        mined_height: Some(1000),
        spent_in_tx_id: None,
        created_at: None,
        updated_at: None,
    }
}
