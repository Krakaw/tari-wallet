//! End-to-end workflow tests using both MockWalletStorage and MockBlockchainScanner
//!
//! These tests demonstrate complete scanning workflows using the mock implementations
//! to provide deterministic, repeatable test scenarios.

use std::sync::Arc;
use std::time::Duration;

use lightweight_wallet_libs::scanning::{
    mocks::{MockBlockchainScanner, MockNetworkFailureModes, MockWalletStorage, MockFailureModes},
    storage_manager::StorageManagerBuilder,
    scanner_engine::{ScannerEngine, ScannerEngineBuilder},
    scan_configuration::ScanConfiguration,
    BlockInfo, TipInfo,
};
use lightweight_wallet_libs::storage::storage_trait::{StoredWallet, WalletStorage};
use lightweight_wallet_libs::data_structures::{
    transaction_output::LightweightTransactionOutput,
    types::{MicroMinotari, PrivateKey},
    wallet_output::{LightweightOutputFeatures, LightweightOutputType, LightweightRangeProofType},
    wallet_transaction::WalletTransaction,
    payment_id::PaymentId,
    transaction::{TransactionDirection, TransactionStatus},
    types::CompressedCommitment,
};

/// Test complete wallet scanning workflow from start to finish
#[tokio::test]
async fn test_complete_scanning_workflow() {
    // Set up mock storage
    let mock_storage = Arc::new(MockWalletStorage::new());
    let storage_manager = StorageManagerBuilder::new()
        .with_storage(mock_storage.clone())
        .with_direct_adapter()
        .build()
        .unwrap();

    // Set up mock blockchain scanner
    let mut mock_scanner = MockBlockchainScanner::new();
    
    // Configure blockchain tip
    mock_scanner.set_tip_info(TipInfo {
        best_block_height: 2000,
        best_block_hash: vec![0xFF; 32],
        accumulated_difficulty: vec![0xAA; 32],
        pruned_height: 1000,
        timestamp: 1640995200,
    });

    // Add test blocks with outputs
    for height in 1500..1510 {
        mock_scanner.add_block(BlockInfo {
            height,
            hash: vec![height as u8; 32],
            timestamp: 1640995200 + (height * 600),
            outputs: vec![create_test_output((height - 1500 + 1) * 1000, height)],
            inputs: vec![],
            kernels: vec![],
            http_output_hashes: None,
        });
    }

    // Create wallet
    let wallet = StoredWallet::view_only(
        "workflow_test_wallet".to_string(),
        PrivateKey::new([42u8; 32]),
        1500, // birthday block
    );
    let wallet_id = storage_manager.save_wallet(&wallet).await.unwrap();

    // Create scanner engine
    let config = ScanConfiguration::new_range(1500, 1509)
        .with_batch_size(5);
    let mut scanner_engine = ScannerEngine::new(Box::new(mock_scanner), config);

    // Perform scanning
    let blocks_to_scan: Vec<u64> = (1500..1510).collect();
    let scan_results = scanner_engine.scan_blocks(blocks_to_scan).await.unwrap();

    // Verify scan results
    assert_eq!(scan_results.len(), 10);
    
    let total_outputs: usize = scan_results.iter().map(|r| r.outputs.len()).sum();
    assert_eq!(total_outputs, 10);

    // Simulate saving discovered transactions to storage
    for (i, result) in scan_results.iter().enumerate() {
        let transaction = WalletTransaction::new(
            result.height,
            Some(0), // output_index
            None, // input_index
            CompressedCommitment::from_bytes(&[(i + 20) as u8; 32]).unwrap(),
            Some(vec![i as u8; 4]),
            (i + 1) as u64 * 1000, // value
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true, // is_mature
        );
        storage_manager.save_transaction(wallet_id, &transaction).await.unwrap();
    }

    // Update wallet scanned block
    storage_manager.update_wallet_scanned_block(wallet_id, 1509).await.unwrap();

    // Verify final state
    let wallet_state = storage_manager.load_wallet_state(wallet_id).await.unwrap();
    assert_eq!(wallet_state.transactions.len(), 10);
    
    let total_value: u64 = wallet_state.transactions.iter().map(|tx| tx.value).sum();
    assert_eq!(total_value, 55000); // 1000 + 2000 + ... + 10000

    let updated_wallet = storage_manager.get_wallet_by_id(wallet_id).await.unwrap().unwrap();
    assert_eq!(updated_wallet.latest_scanned_block, Some(1509));
}

/// Test scanning workflow with network errors and recovery
#[tokio::test]
async fn test_scanning_workflow_with_error_recovery() {
    let mock_storage = Arc::new(MockWalletStorage::new());
    let storage_manager = StorageManagerBuilder::new()
        .with_storage(mock_storage.clone())
        .with_direct_adapter()
        .build()
        .unwrap();

    let mut mock_scanner = MockBlockchainScanner::new();
    
    // Add test blocks
    for height in 2000..2005 {
        mock_scanner.add_block(BlockInfo {
            height,
            hash: vec![height as u8; 32],
            timestamp: 1640995200 + (height * 600),
            outputs: vec![create_test_output(5000, height)],
            inputs: vec![],
            kernels: vec![],
            http_output_hashes: None,
        });
    }

    // Set up initial failure
    mock_scanner.set_failure_modes(MockNetworkFailureModes {
        next_error_message: Some("Temporary network failure".to_string()),
        ..Default::default()
    });

    let wallet = StoredWallet::view_only(
        "error_recovery_wallet".to_string(),
        PrivateKey::new([99u8; 32]),
        2000,
    );
    let wallet_id = storage_manager.save_wallet(&wallet).await.unwrap();

    let config = ScanConfiguration::new_range(2000, 2004);
    let mut scanner_engine = ScannerEngine::new(Box::new(mock_scanner), config);

    // First scan attempt should fail
    let result1 = scanner_engine.scan_blocks(vec![2000]).await;
    assert!(result1.is_err());
    assert!(result1.unwrap_err().to_string().contains("Temporary network failure"));

    // Second attempt should succeed (error was consumed)
    let result2 = scanner_engine.scan_blocks(vec![2000, 2001]).await;
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap().len(), 2);

    // Verify partial progress can be saved
    let transaction = WalletTransaction::new(
        2000,
        Some(0),
        None,
        CompressedCommitment::from_bytes(&[30u8; 32]).unwrap(),
        Some(vec![1, 2, 3, 4]),
        5000,
        PaymentId::Empty,
        TransactionStatus::MinedConfirmed,
        TransactionDirection::Inbound,
        true,
    );
    storage_manager.save_transaction(wallet_id, &transaction).await.unwrap();

    // Update partial progress
    storage_manager.update_wallet_scanned_block(wallet_id, 2000).await.unwrap();

    let updated_wallet = storage_manager.get_wallet_by_id(wallet_id).await.unwrap().unwrap();
    assert_eq!(updated_wallet.latest_scanned_block, Some(2000));
}

/// Test scanning workflow with storage errors
#[tokio::test]
async fn test_scanning_workflow_with_storage_errors() {
    let mock_storage = Arc::new(MockWalletStorage::new());
    let mut mock_scanner = MockBlockchainScanner::new();
    
    // Add test data
    mock_scanner.add_block(BlockInfo {
        height: 3000,
        hash: vec![0x30; 32],
        timestamp: 1640995200,
        outputs: vec![create_test_output(7500, 3000)],
        inputs: vec![],
        kernels: vec![],
        http_output_hashes: None,
    });

    // Create successful scanner
    let config = ScanConfiguration::new(3000);
    let mut scanner_engine = ScannerEngine::new(Box::new(mock_scanner), config);

    // Create wallet successfully first
    let wallet = StoredWallet::view_only(
        "storage_error_wallet".to_string(),
        PrivateKey::new([88u8; 32]),
        3000,
    );

    let storage_manager = StorageManagerBuilder::new()
        .with_storage(mock_storage.clone())
        .with_direct_adapter()
        .build()
        .unwrap();

    let wallet_id = storage_manager.save_wallet(&wallet).await.unwrap();

    // Perform scanning (should succeed)
    let scan_results = scanner_engine.scan_blocks(vec![3000]).await.unwrap();
    assert_eq!(scan_results.len(), 1);

    // Now inject storage failure for transaction saving
    mock_storage.set_failure_mode(MockFailureModes {
        fail_save_transaction: true,
        ..Default::default()
    });

    // Attempt to save transaction should fail
    let transaction = WalletTransaction::new(
        3000,
        Some(0),
        None,
        CompressedCommitment::from_bytes(&[40u8; 32]).unwrap(),
        Some(vec![5, 6, 7, 8]),
        7500,
        PaymentId::Empty,
        TransactionStatus::MinedConfirmed,
        TransactionDirection::Inbound,
        true,
    );

    let save_result = storage_manager.save_transaction(wallet_id, &transaction).await;
    assert!(save_result.is_err());
    assert!(save_result.unwrap_err().to_string().contains("Mock failure: save_transaction"));

    // But subsequent operations should work (error was consumed)
    let save_result2 = storage_manager.save_transaction(wallet_id, &transaction).await;
    assert!(save_result2.is_ok());
}

/// Test progressive scanning workflow with batch processing
#[tokio::test]
async fn test_progressive_batch_scanning_workflow() {
    let mock_storage = Arc::new(MockWalletStorage::new());
    let storage_manager = StorageManagerBuilder::new()
        .with_storage(mock_storage.clone())
        .with_direct_adapter()
        .build()
        .unwrap();

    let mut mock_scanner = MockBlockchainScanner::new();
    
    // Set up large range of blocks
    mock_scanner.set_tip_info(TipInfo {
        best_block_height: 5000,
        best_block_hash: vec![0x50; 32],
        accumulated_difficulty: vec![0xCC; 32],
        pruned_height: 4000,
        timestamp: 1640995200,
    });

    // Add blocks across multiple batches
    for height in 4500..4550 {
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

    let wallet = StoredWallet::view_only(
        "batch_scanning_wallet".to_string(),
        PrivateKey::new([77u8; 32]),
        4500,
    );
    let wallet_id = storage_manager.save_wallet(&wallet).await.unwrap();

    let config = ScanConfiguration::new_range(4500, 4549)
        .with_batch_size(10); // Small batches for testing
    let mut scanner_engine = ScannerEngine::new(Box::new(mock_scanner), config);

    // Scan in multiple batches
    let mut total_scanned = 0;
    let mut current_height = 4500u64;
    
    while current_height <= 4549 {
        let batch_end = std::cmp::min(current_height + 9, 4549);
        let batch: Vec<u64> = (current_height..=batch_end).collect();
        
        let batch_results = scanner_engine.scan_blocks(batch).await.unwrap();
        assert_eq!(batch_results.len(), (batch_end - current_height + 1) as usize);
        
        // Save transactions from this batch
        for (i, result) in batch_results.iter().enumerate() {
            let transaction = WalletTransaction::new(
                result.height,
                Some(0),
                None,
                CompressedCommitment::from_bytes(&[(current_height + i as u64 + 50) as u8; 32]).unwrap(),
                Some(vec![current_height as u8; 4]),
                1000,
                PaymentId::Empty,
                TransactionStatus::MinedConfirmed,
                TransactionDirection::Inbound,
                true,
            );
            storage_manager.save_transaction(wallet_id, &transaction).await.unwrap();
            total_scanned += 1;
        }

        // Update progress
        storage_manager.update_wallet_scanned_block(wallet_id, batch_end).await.unwrap();
        
        current_height = batch_end + 1;
    }

    // Verify complete scan
    assert_eq!(total_scanned, 50);
    
    let wallet_state = storage_manager.load_wallet_state(wallet_id).await.unwrap();
    assert_eq!(wallet_state.transactions.len(), 50);
    
    let final_wallet = storage_manager.get_wallet_by_id(wallet_id).await.unwrap().unwrap();
    assert_eq!(final_wallet.latest_scanned_block, Some(4549));
}

/// Test concurrent scanning workflow (simulated)
#[tokio::test]
async fn test_concurrent_scanning_workflow() {
    let mock_storage = Arc::new(MockWalletStorage::new());
    let storage_manager = StorageManagerBuilder::new()
        .with_storage(mock_storage.clone())
        .with_direct_adapter()
        .build()
        .unwrap();

    // Create multiple wallets
    let wallet1 = StoredWallet::view_only(
        "concurrent_wallet_1".to_string(),
        PrivateKey::new([11u8; 32]),
        6000,
    );
    let wallet2 = StoredWallet::view_only(
        "concurrent_wallet_2".to_string(),
        PrivateKey::new([22u8; 32]),
        6100,
    );

    let wallet_id1 = storage_manager.save_wallet(&wallet1).await.unwrap();
    let wallet_id2 = storage_manager.save_wallet(&wallet2).await.unwrap();

    // Create separate scanners for each wallet
    let mut scanner1 = MockBlockchainScanner::new();
    let mut scanner2 = MockBlockchainScanner::new();

    // Add different blocks to each scanner
    for height in 6000..6010 {
        scanner1.add_block(BlockInfo {
            height,
            hash: vec![(height % 256) as u8; 32],
            timestamp: 1640995200 + (height * 600),
            outputs: vec![create_test_output(2000, height)],
            inputs: vec![],
            kernels: vec![],
            http_output_hashes: None,
        });
    }

    for height in 6100..6110 {
        scanner2.add_block(BlockInfo {
            height,
            hash: vec![(height % 256) as u8; 32],
            timestamp: 1640995200 + (height * 600),
            outputs: vec![create_test_output(3000, height)],
            inputs: vec![],
            kernels: vec![],
            http_output_hashes: None,
        });
    }

    // Scan both wallets concurrently
    let config1 = ScanConfiguration::new_range(6000, 6009);
    let config2 = ScanConfiguration::new_range(6100, 6109);

    let mut engine1 = ScannerEngine::new(Box::new(scanner1), config1);
    let mut engine2 = ScannerEngine::new(Box::new(scanner2), config2);

    let blocks1: Vec<u64> = (6000..6010).collect();
    let blocks2: Vec<u64> = (6100..6110).collect();

    // Execute scans concurrently using join
    let (results1, results2) = tokio::join!(
        engine1.scan_blocks(blocks1),
        engine2.scan_blocks(blocks2)
    );

    let results1 = results1.unwrap();
    let results2 = results2.unwrap();

    assert_eq!(results1.len(), 10);
    assert_eq!(results2.len(), 10);

    // Save results for both wallets
    for (i, result) in results1.iter().enumerate() {
        let transaction = WalletTransaction::new(
            result.height,
            Some(0),
            None,
            CompressedCommitment::from_bytes(&[(i + 60) as u8; 32]).unwrap(),
            Some(vec![1u8; 4]),
            2000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );
        storage_manager.save_transaction(wallet_id1, &transaction).await.unwrap();
    }

    for (i, result) in results2.iter().enumerate() {
        let transaction = WalletTransaction::new(
            result.height,
            Some(0),
            None,
            CompressedCommitment::from_bytes(&[(i + 70) as u8; 32]).unwrap(),
            Some(vec![2u8; 4]),
            3000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );
        storage_manager.save_transaction(wallet_id2, &transaction).await.unwrap();
    }

    // Verify both wallets have correct data
    let state1 = storage_manager.load_wallet_state(wallet_id1).await.unwrap();
    let state2 = storage_manager.load_wallet_state(wallet_id2).await.unwrap();

    assert_eq!(state1.transactions.len(), 10);
    assert_eq!(state2.transactions.len(), 10);

    let total_value1: u64 = state1.transactions.iter().map(|tx| tx.value).sum();
    let total_value2: u64 = state2.transactions.iter().map(|tx| tx.value).sum();

    assert_eq!(total_value1, 20000); // 10 * 2000
    assert_eq!(total_value2, 30000); // 10 * 3000
}

/// Test network latency simulation in scanning workflow
#[tokio::test]
async fn test_scanning_workflow_with_network_latency() {
    let mock_storage = Arc::new(MockWalletStorage::new());
    let storage_manager = StorageManagerBuilder::new()
        .with_storage(mock_storage.clone())
        .with_direct_adapter()
        .build()
        .unwrap();

    let mut mock_scanner = MockBlockchainScanner::new();
    
    // Set network delay
    mock_scanner.set_network_delay(Duration::from_millis(100));
    
    // Add test block
    mock_scanner.add_block(BlockInfo {
        height: 7000,
        hash: vec![0x70; 32],
        timestamp: 1640995200,
        outputs: vec![create_test_output(12000, 7000)],
        inputs: vec![],
        kernels: vec![],
        http_output_hashes: None,
    });

    let wallet = StoredWallet::view_only(
        "latency_test_wallet".to_string(),
        PrivateKey::new([33u8; 32]),
        7000,
    );
    let wallet_id = storage_manager.save_wallet(&wallet).await.unwrap();

    let config = ScanConfiguration::new(7000);
    let mut scanner_engine = ScannerEngine::new(Box::new(mock_scanner), config);

    // Measure scan time
    let start_time = std::time::Instant::now();
    let results = scanner_engine.scan_blocks(vec![7000]).await.unwrap();
    let elapsed = start_time.elapsed();

    // Should have taken at least the network delay time
    assert!(elapsed >= Duration::from_millis(90)); // Allow some margin
    assert_eq!(results.len(), 1);

    // Save the transaction
    let transaction = WalletTransaction::new(
        7000,
        Some(0),
        None,
        CompressedCommitment::from_bytes(&[80u8; 32]).unwrap(),
        Some(vec![7, 8, 9, 10]),
        12000,
        PaymentId::Empty,
        TransactionStatus::MinedConfirmed,
        TransactionDirection::Inbound,
        true,
    );
    storage_manager.save_transaction(wallet_id, &transaction).await.unwrap();

    let wallet_state = storage_manager.load_wallet_state(wallet_id).await.unwrap();
    assert_eq!(wallet_state.transactions.len(), 1);
    assert_eq!(wallet_state.transactions[0].value, 12000);
}

// Helper function to create test outputs
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
