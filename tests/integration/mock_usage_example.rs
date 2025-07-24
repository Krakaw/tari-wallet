//! Example integration tests demonstrating the use of mock implementations for deterministic testing
//!
//! This file shows how to use the MockWalletStorage and MockBlockchainScanner
//! from the scanning::mocks module for predictable, deterministic testing.

use std::time::Duration;

use lightweight_wallet_libs::scanning::mocks::{MockBlockchainScanner, MockNetworkFailureModes, MockWalletStorage, MockFailureModes};
use lightweight_wallet_libs::scanning::{BlockInfo, TipInfo, ScanConfig};
use lightweight_wallet_libs::storage::storage_trait::{StoredWallet, WalletStorage, OutputFilter, OutputStatus};
use lightweight_wallet_libs::data_structures::{
    transaction_output::LightweightTransactionOutput,
    types::{MicroMinotari, PrivateKey},
    wallet_output::{LightweightOutputFeatures, LightweightOutputType, LightweightRangeProofType}
};
use lightweight_wallet_libs::errors::LightweightWalletError;
use lightweight_wallet_libs::extraction::ExtractionConfig;
use lightweight_wallet_libs::scanning::BlockchainScanner;

/// Test demonstrating basic usage of MockWalletStorage
#[tokio::test]
async fn test_mock_storage_deterministic_behavior() {
    let storage = MockWalletStorage::new();
    
    // Initialize storage
    storage.initialize().await.unwrap();
    
    // Create a test wallet
    let test_wallet = StoredWallet::view_only(
        "test_wallet".to_string(),
        PrivateKey::new([1u8; 32]),
        1000, // birthday block
    );
    
    // Save wallet and verify deterministic ID assignment
    let wallet_id = storage.save_wallet(&test_wallet).await.unwrap();
    assert_eq!(wallet_id, 1, "First wallet should get ID 1");
    
    // Save another wallet
    let second_wallet = StoredWallet::view_only(
        "second_wallet".to_string(),
        PrivateKey::new([2u8; 32]),
        2000,
    );
    let second_id = storage.save_wallet(&second_wallet).await.unwrap();
    assert_eq!(second_id, 2, "Second wallet should get ID 2");
    
    // Retrieve wallets and verify data
    let retrieved = storage.get_wallet_by_id(wallet_id).await.unwrap().unwrap();
    assert_eq!(retrieved.name, "test_wallet");
    assert_eq!(retrieved.birthday_block, 1000);
    
    // Test wallet list
    let all_wallets = storage.list_wallets().await.unwrap();
    assert_eq!(all_wallets.len(), 2);
    
    // Test deterministic reset behavior
    storage.reset();
    let wallets_after_reset = storage.list_wallets().await.unwrap();
    assert!(wallets_after_reset.is_empty());
}

/// Test demonstrating error injection capabilities of MockWalletStorage
#[tokio::test]
async fn test_mock_storage_error_injection() {
    let storage = MockWalletStorage::new();
    
    // Set up failure mode for save_wallet
    storage.set_failure_mode(MockFailureModes {
        fail_save_wallet: true,
        ..Default::default()
    });
    
    let test_wallet = StoredWallet::view_only(
        "failing_wallet".to_string(),
        PrivateKey::new([1u8; 32]),
        1000,
    );
    
    // This should fail due to mock failure mode
    let result = storage.save_wallet(&test_wallet).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Mock failure: save_wallet"));
    
    // After failure, the flag should be reset and next operation should succeed
    let success_result = storage.save_wallet(&test_wallet).await;
    assert!(success_result.is_ok());
}

/// Test demonstrating specific error injection
#[tokio::test]
async fn test_mock_storage_specific_errors() {
    let storage = MockWalletStorage::new();
    
    // Inject a specific error
    let specific_error = LightweightWalletError::ValidationError(
        "Specific test validation error".to_string(),
    );
    
    storage.set_failure_mode(MockFailureModes {
        next_error: Some(specific_error),
        ..Default::default()
    });
    
    let test_wallet = StoredWallet::view_only(
        "test_wallet".to_string(),
        PrivateKey::new([1u8; 32]),
        1000,
    );
    
    let result = storage.save_wallet(&test_wallet).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Specific test validation error"));
}

/// Test demonstrating basic usage of MockBlockchainScanner
#[tokio::test]
async fn test_mock_scanner_deterministic_behavior() {
    let mut scanner = MockBlockchainScanner::new();
    
    // Set up predictable tip info
    let test_tip = TipInfo {
        best_block_height: 1000,
        best_block_hash: vec![0x01, 0x02, 0x03, 0x04],
        accumulated_difficulty: vec![0x05, 0x06, 0x07, 0x08],
        pruned_height: 500,
        timestamp: 1640995200,
    };
    scanner.set_tip_info(test_tip.clone());
    
    // Test tip info retrieval
    let retrieved_tip = scanner.get_tip_info().await.unwrap();
    assert_eq!(retrieved_tip.best_block_height, test_tip.best_block_height);
    assert_eq!(retrieved_tip.best_block_hash, test_tip.best_block_hash);
    
    // Add test blocks with known data
    let test_block = BlockInfo {
        height: 100,
        hash: vec![0x10; 32],
        timestamp: 1640995200,
        outputs: vec![create_test_output(1000)],
        inputs: vec![],
        kernels: vec![],
        http_output_hashes: None,
    };
    scanner.add_block(test_block);
    
    // Test block retrieval
    let retrieved_block = scanner.get_block_by_height(100).await.unwrap().unwrap();
    assert_eq!(retrieved_block.height, 100);
    assert_eq!(retrieved_block.outputs.len(), 1);
}

/// Test demonstrating error injection for MockBlockchainScanner
#[tokio::test]
async fn test_mock_scanner_error_injection() {
    let mut scanner = MockBlockchainScanner::new();
    
    // Test scan_blocks failure
    scanner.set_failure_modes(MockNetworkFailureModes {
        fail_scan_blocks: true,
        ..Default::default()
    });
    
    let config = ScanConfig::default();
    let result = scanner.scan_blocks(config).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Mock failure: scan_blocks"));
    
    // Test timeout simulation
    scanner.set_failure_modes(MockNetworkFailureModes {
        simulate_timeout: true,
        ..Default::default() 
    });
    
    let config = ScanConfig::default();
    let result = scanner.scan_blocks(config).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Mock timeout"));
}

/// Test demonstrating network delay simulation
#[tokio::test]
async fn test_mock_scanner_network_delay() {
    let mut scanner = MockBlockchainScanner::new();
    
    // Set network delay simulation
    scanner.set_network_delay(Duration::from_millis(100));
    
    let start_time = std::time::Instant::now();
    let _result = scanner.get_tip_info().await.unwrap();
    let elapsed = start_time.elapsed();
    
    // Should have taken at least 100ms due to simulated delay
    assert!(elapsed >= Duration::from_millis(95)); // Allow small margin for timing variance
}

/// Test demonstrating empty results mode
#[tokio::test]
async fn test_mock_scanner_empty_results() {
    let mut scanner = MockBlockchainScanner::new();
    
    // Add blocks but set empty results mode
    scanner.add_block(BlockInfo {
        height: 100,
        hash: vec![0x10; 32],
        timestamp: 1640995200,
        outputs: vec![create_test_output(1000)],
        inputs: vec![],
        kernels: vec![],
        http_output_hashes: None,
    });
    
    scanner.set_failure_modes(MockNetworkFailureModes {
        return_empty_results: true,
        ..Default::default()
    });
    
    let config = ScanConfig {
        start_height: 100,
        end_height: Some(100),
        ..Default::default()
    };
    
    let results = scanner.scan_blocks(config).await.unwrap();
    assert!(results.is_empty(), "Should return empty results when flag is set");
}

/// Test demonstrating batch operations with multiple mocks
#[tokio::test] 
async fn test_integrated_mock_workflow() {
    let storage = MockWalletStorage::new();
    let mut scanner = MockBlockchainScanner::new();
    
    storage.initialize().await.unwrap();
    
    // Create a wallet
    let wallet = StoredWallet::view_only(
        "integration_test_wallet".to_string(),
        PrivateKey::new([42u8; 32]),
        500,
    );
    let wallet_id = storage.save_wallet(&wallet).await.unwrap();
    
    // Set up scanner with test data
    scanner.set_tip_info(TipInfo {
        best_block_height: 1000,
        best_block_hash: vec![0xFF; 32],
        accumulated_difficulty: vec![0xAA; 32],
        pruned_height: 500,
        timestamp: 1640995200,
    });
    
    // Add test blocks
    for height in 500..510 {
        scanner.add_block(BlockInfo {
            height,
            hash: vec![height as u8; 32],
            timestamp: 1640995200 + (height * 600),
            outputs: vec![create_test_output((height * 1000) as u64)],
            inputs: vec![],
            kernels: vec![],
            http_output_hashes: None,
        });
    }
    
    // Verify integrated behavior
    let tip = scanner.get_tip_info().await.unwrap();
    assert_eq!(tip.best_block_height, 1000);
    
    let blocks = scanner.get_blocks_by_heights(vec![500, 501, 502]).await.unwrap();
    assert_eq!(blocks.len(), 3);
    
    let wallet_stats = storage.get_wallet_statistics(Some(wallet_id)).await.unwrap();
    assert_eq!(wallet_stats.total_transactions, 0); // No transactions added yet
    
    // Test reset behavior
    storage.reset();
    scanner.reset();
    
    let wallets_after_reset = storage.list_wallets().await.unwrap();
    assert!(wallets_after_reset.is_empty());
    
    let blocks_after_reset = scanner.get_blocks_by_heights(vec![500]).await.unwrap();
    assert!(blocks_after_reset.is_empty());
}

/// Helper function to create test outputs
fn create_test_output(value: u64) -> LightweightTransactionOutput {
    let features = LightweightOutputFeatures {
        version: 0,
        output_type: LightweightOutputType::Payment,
        maturity: 0,
        metadata: vec![],
        sidechain_feature: None,
        range_proof_type: LightweightRangeProofType::BulletProofPlus,
    };
    
    LightweightTransactionOutput::new(
        0, // version
        features,
        vec![0u8; 32], // commitment
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

/// Test demonstrating deterministic state management across resets
#[tokio::test]
async fn test_deterministic_state_management() {
    let storage = MockWalletStorage::new();
    let mut scanner = MockBlockchainScanner::new();
    
    // Test initial state
    assert_eq!(storage.list_wallets().await.unwrap().len(), 0);
    assert_eq!(scanner.get_tip_info().await.unwrap().best_block_height, 1000);
    
    // Add data
    let wallet = StoredWallet::view_only(
        "test".to_string(),
        PrivateKey::new([1u8; 32]),
        100,
    );
    let wallet_id_1 = storage.save_wallet(&wallet).await.unwrap();
    assert_eq!(wallet_id_1, 1);
    
    scanner.add_block(BlockInfo {
        height: 100,
        hash: vec![0x10; 32],
        timestamp: 1640995200,
        outputs: vec![],
        inputs: vec![],
        kernels: vec![],
        http_output_hashes: None,
    });
    
    // Verify data exists
    assert_eq!(storage.list_wallets().await.unwrap().len(), 1);
    assert!(scanner.get_block_by_height(100).await.unwrap().is_some());
    
    // Reset and verify clean state
    storage.reset();
    scanner.reset();
    
    assert_eq!(storage.list_wallets().await.unwrap().len(), 0);
    assert!(scanner.get_block_by_height(100).await.unwrap().is_none());
    
    // Add data again and verify deterministic ID assignment
    let wallet_id_2 = storage.save_wallet(&wallet).await.unwrap();
    assert_eq!(wallet_id_2, 1, "After reset, first wallet should again get ID 1");
}
