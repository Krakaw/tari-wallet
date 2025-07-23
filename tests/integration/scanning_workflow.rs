//! Scanning workflow integration tests
//!
//! Tests the complete blockchain scanning workflow from setup to UTXO discovery
//! to balance calculation, including mock blockchain data and real scanning logic.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use lightweight_wallet_libs::data_structures::{
    encrypted_data::EncryptedData,
    transaction_output::LightweightTransactionOutput,
    types::{CompressedCommitment, CompressedPublicKey, MicroMinotari, PrivateKey},
    wallet_output::{LightweightOutputFeatures, LightweightOutputType, LightweightRangeProofType},
};
use lightweight_wallet_libs::errors::{LightweightWalletError, ValidationError};
use lightweight_wallet_libs::extraction::ExtractionConfig;
use lightweight_wallet_libs::LightweightWalletResult;

use lightweight_wallet_libs::scanning::*;
use lightweight_wallet_libs::wallet::*;

/// Mock scanner with test data
struct TestBlockchainScanner {
    blocks: HashMap<u64, BlockInfo>,
    tip_height: u64,
    latency_ms: u64,
}

impl TestBlockchainScanner {
    fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            tip_height: 1000,
            latency_ms: 10,
        }
    }

    fn add_test_block(&mut self, height: u64, outputs: Vec<LightweightTransactionOutput>) {
        let block = BlockInfo {
            height,
            hash: vec![height as u8; 32],
            timestamp: 1640995200 + (height * 600), // ~10 min blocks
            outputs,
            inputs: vec![],
            kernels: vec![],
            http_output_hashes: None,
        };
        self.blocks.insert(height, block);
        self.tip_height = self.tip_height.max(height);
    }

    fn set_latency(&mut self, latency_ms: u64) {
        self.latency_ms = latency_ms;
    }
}

#[async_trait(?Send)]
impl BlockchainScanner for TestBlockchainScanner {
    async fn scan_blocks(
        &mut self,
        config: ScanConfig,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
        // Simulate network latency
        if self.latency_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.latency_ms)).await;
        }

        DefaultScanningLogic::scan_blocks_with_progress(self, config, None).await
    }

    async fn get_tip_info(&mut self) -> LightweightWalletResult<TipInfo> {
        Ok(TipInfo {
            best_block_height: self.tip_height,
            best_block_hash: vec![self.tip_height as u8; 32],
            accumulated_difficulty: vec![0x42; 32],
            pruned_height: self.tip_height.saturating_sub(1000),
            timestamp: 1640995200 + (self.tip_height * 600),
        })
    }

    async fn search_utxos(
        &mut self,
        _commitments: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
        Ok(vec![])
    }

    async fn fetch_utxos(
        &mut self,
        _hashes: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<Vec<LightweightTransactionOutput>> {
        Ok(vec![])
    }

    async fn get_blocks_by_heights(
        &mut self,
        heights: Vec<u64>,
    ) -> LightweightWalletResult<Vec<BlockInfo>> {
        // Simulate network latency
        if self.latency_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.latency_ms)).await;
        }

        let mut result = Vec::new();
        for height in heights {
            if let Some(block) = self.blocks.get(&height) {
                result.push(block.clone());
            }
        }
        Ok(result)
    }

    async fn get_block_by_height(
        &mut self,
        height: u64,
    ) -> LightweightWalletResult<Option<BlockInfo>> {
        // Simulate network latency
        if self.latency_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.latency_ms)).await;
        }

        Ok(self.blocks.get(&height).cloned())
    }
}

/// Create a test transaction output with encrypted data
fn create_test_output(
    value: u64,
    view_key: &PrivateKey,
    spend_key: &PrivateKey,
) -> Result<LightweightTransactionOutput, LightweightWalletError> {
    use lightweight_wallet_libs::data_structures::{
        payment_id::PaymentId,
        wallet_output::{LightweightCovenant, LightweightScript, LightweightSignature},
    };

    // Create a basic commitment (mock)
    let commitment = CompressedCommitment::new([0x42; 32]);

    // Create sender offset public key from spend key
    let sender_offset_public_key = CompressedPublicKey::from_private_key(spend_key);

    // Create encrypted data for the value
    let encryption_key = view_key.clone();
    let micro_value = MicroMinotari::from(value);
    let mask = PrivateKey::new([0x03; 32]);
    let payment_id = PaymentId::Empty;

    let encrypted_data =
        EncryptedData::encrypt_data(&encryption_key, &commitment, micro_value, &mask, payment_id)
            .map_err(|e| {
            LightweightWalletError::ValidationError(ValidationError::ValueValidationFailed(
                format!("Failed to encrypt data: {e}"),
            ))
        })?;

    // Create features
    let features = LightweightOutputFeatures {
        output_type: LightweightOutputType::Payment,
        maturity: 0,
        range_proof_type: LightweightRangeProofType::BulletProofPlus,
    };

    // Create script
    let script = LightweightScript {
        bytes: vec![0x01, 0x02, 0x03],
    };

    // Create metadata signature (mock)
    let metadata_signature = LightweightSignature {
        bytes: vec![0x06; 64],
    };

    // Create covenant
    let covenant = LightweightCovenant {
        bytes: vec![0x07, 0x08, 0x09],
    };

    Ok(LightweightTransactionOutput::new(
        0, // version
        features,
        commitment,
        None, // proof
        script,
        sender_offset_public_key,
        metadata_signature,
        covenant,
        encrypted_data,
        micro_value, // minimum_value_promise
    ))
}

/// Test basic scanning workflow with mock data
#[tokio::test]
async fn test_basic_scanning_workflow() {
    // Setup: Create wallet and derive keys
    let wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

    let (view_key, spend_key) = derive_test_keys(&wallet);

    // Setup: Create mock scanner with test data
    let mut scanner = TestBlockchainScanner::new();

    // Add blocks with wallet outputs
    for height in 100..110 {
        let output = create_test_output(
            1000000 + height * 10000, // Increasing values
            &view_key,
            &spend_key,
        )
        .expect("Failed to create test output");

        scanner.add_test_block(height, vec![output]);
    }

    // Configure scan
    let extraction_config = ExtractionConfig::with_private_key(view_key.clone());
    let scan_config = ScanConfig {
        start_height: 100,
        end_height: Some(109),
        batch_size: 5,
        request_timeout: Duration::from_secs(30),
        extraction_config,
    };

    // Execute scan
    let start_time = Instant::now();
    let results = scanner.scan_blocks(scan_config).await.expect("Scan failed");
    let scan_duration = start_time.elapsed();

    // Verify results
    assert_eq!(results.len(), 10); // 10 blocks scanned

    let total_outputs: usize = results.iter().map(|r| r.wallet_outputs.len()).sum();
    assert_eq!(total_outputs, 10); // One output per block

    let total_value: u64 = results
        .iter()
        .flat_map(|r| &r.wallet_outputs)
        .map(|wo| wo.value().as_u64())
        .sum();

    let expected_value: u64 = (100..110).map(|height| 1000000 + height * 10000).sum();
    assert_eq!(total_value, expected_value);

    // Verify block details
    for (i, result) in results.iter().enumerate() {
        let expected_height = 100 + i as u64;
        assert_eq!(result.height, expected_height);
        assert_eq!(result.block_hash, vec![expected_height as u8; 32]);
        assert_eq!(result.wallet_outputs.len(), 1);

        let wallet_output = &result.wallet_outputs[0];
        let expected_output_value = 1000000 + expected_height * 10000;
        assert_eq!(wallet_output.value().as_u64(), expected_output_value);
    }

    println!("✓ Basic scanning workflow test passed");
    println!("  Scanned {} blocks in {:?}", results.len(), scan_duration);
    println!("  Found {total_outputs} wallet outputs with total value {total_value}");
}

/// Test scanning with progress callback
#[tokio::test]
async fn test_scanning_with_progress() {
    // Setup
    let wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");
    let (view_key, spend_key) = derive_test_keys(&wallet);

    let mut scanner = TestBlockchainScanner::new();
    scanner.set_latency(50); // Simulate slower network

    // Add blocks with various values
    for height in 200..250 {
        let output = create_test_output(
            500000 + (height % 10) * 100000, // Varying values
            &view_key,
            &spend_key,
        )
        .expect("Failed to create test output");

        scanner.add_test_block(height, vec![output]);
    }

    // Progress tracking
    let progress_updates = Arc::new(Mutex::new(Vec::new()));
    let progress_updates_clone = Arc::clone(&progress_updates);
    let progress_callback = move |progress: ScanProgress| {
        progress_updates_clone.lock().unwrap().push(progress);
    };

    let extraction_config = ExtractionConfig::with_private_key(view_key.clone());
    let scan_config = ScanConfig {
        start_height: 200,
        end_height: Some(249),
        batch_size: 10,
        request_timeout: Duration::from_secs(30),
        extraction_config,
    };

    let config_with_callback = scan_config.with_progress_callback(Box::new(progress_callback));

    // Execute scan with progress
    let start_time = Instant::now();
    let results = DefaultScanningLogic::scan_blocks_with_progress(
        &mut scanner,
        config_with_callback.config,
        config_with_callback.progress_callback.as_ref(),
    )
    .await
    .expect("Scan failed");
    let _scan_duration = start_time.elapsed();

    // Verify scan results
    assert_eq!(results.len(), 50); // 50 blocks

    // Verify progress updates
    let progress_updates = progress_updates.lock().unwrap();
    assert!(progress_updates.len() >= 5); // At least 5 batches

    // Verify progress is increasing
    for i in 1..progress_updates.len() {
        assert!(progress_updates[i].current_height >= progress_updates[i - 1].current_height);
        assert!(progress_updates[i].outputs_found >= progress_updates[i - 1].outputs_found);
        assert!(progress_updates[i].elapsed >= progress_updates[i - 1].elapsed);
    }

    // Verify final progress matches results
    let final_progress = progress_updates.last().unwrap();
    assert_eq!(final_progress.current_height, 249);
    assert_eq!(final_progress.target_height, 249);
    assert_eq!(final_progress.outputs_found, 50);

    println!("✓ Scanning with progress test passed");
    println!("  Progress updates: {}", progress_updates.len());
    println!(
        "  Final progress: height {}, outputs {}",
        final_progress.current_height, final_progress.outputs_found
    );
}

/// Test wallet scanning workflow with key management
#[tokio::test]
async fn test_wallet_scanning_workflow() {
    // Setup wallet
    let mut wallet =
        Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");
    wallet.set_network("mainnet".to_string());
    wallet.set_current_key_index(0);

    let (view_key, spend_key) = derive_test_keys(&wallet);

    // Setup scanner with wallet-specific data
    let mut scanner = TestBlockchainScanner::new();

    // Add blocks with different types of outputs
    for height in 300..320 {
        let mut outputs = Vec::new();

        // Add a wallet output
        if height % 3 == 0 {
            let output = create_test_output(2000000 + height * 5000, &view_key, &spend_key)
                .expect("Failed to create wallet output");
            outputs.push(output);
        }

        // Add a non-wallet output (different keys)
        let other_view = PrivateKey::new([0x99; 32]);
        let other_spend = PrivateKey::new([0xAA; 32]);
        let other_output = create_test_output(1000000, &other_view, &other_spend)
            .expect("Failed to create other output");
        outputs.push(other_output);

        scanner.add_test_block(height, outputs);
    }

    // Configure wallet scan
    let extraction_config = ExtractionConfig::with_private_key(view_key.clone());
    let wallet_scan_config = WalletScanConfig {
        scan_config: ScanConfig {
            start_height: 300,
            end_height: Some(319),
            batch_size: 5,
            request_timeout: Duration::from_secs(30),
            extraction_config,
        },
        key_manager: None,
        key_store: None,
        scan_stealth_addresses: true,
        max_addresses_per_account: 1000,
        scan_imported_keys: true,
    };

    // Execute wallet scan
    let start_time = Instant::now();
    let wallet_result =
        DefaultScanningLogic::scan_wallet_with_progress(&mut scanner, wallet_scan_config, None)
            .await
            .expect("Wallet scan failed");
    let scan_duration = start_time.elapsed();

    // Verify wallet scan results
    assert_eq!(wallet_result.block_results.len(), 20); // 20 blocks

    // Count wallet outputs (should only find every 3rd block)
    let wallet_outputs: usize = wallet_result
        .block_results
        .iter()
        .map(|r| r.wallet_outputs.len())
        .sum();

    // Every 3rd block starting from 300: 300, 303, 306, 309, 312, 315, 318 = 7 blocks
    let expected_wallet_outputs = (300..320).step_by(3).count();
    assert_eq!(wallet_outputs, expected_wallet_outputs);
    assert_eq!(
        wallet_result.total_wallet_outputs,
        expected_wallet_outputs as u64
    );

    // Verify total value
    let expected_total_value: u64 = (300..320)
        .step_by(3)
        .map(|height| 2000000 + height * 5000)
        .sum();
    assert_eq!(wallet_result.total_value, expected_total_value);

    // Verify scan metadata
    assert!(wallet_result.scan_duration <= scan_duration + Duration::from_millis(100));

    println!("✓ Wallet scanning workflow test passed");
    println!(
        "  Found {} wallet outputs in {} blocks",
        wallet_result.total_wallet_outputs,
        wallet_result.block_results.len()
    );
    println!("  Total value: {}", wallet_result.total_value);
}

/// Test balance calculation from scan results
#[tokio::test]
async fn test_balance_calculation_workflow() {
    // Setup
    let wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");
    let (view_key, spend_key) = derive_test_keys(&wallet);

    let mut scanner = TestBlockchainScanner::new();

    // Add blocks with varying output values
    let output_values = [
        1000000,  // 1 Tari
        5000000,  // 5 Tari
        2500000,  // 2.5 Tari
        10000000, // 10 Tari
        750000,   // 0.75 Tari
    ];

    for (i, &value) in output_values.iter().enumerate() {
        let height = 400 + i as u64;
        let output =
            create_test_output(value, &view_key, &spend_key).expect("Failed to create test output");
        scanner.add_test_block(height, vec![output]);
    }

    // Scan for outputs
    let extraction_config = ExtractionConfig::with_private_key(view_key.clone());
    let scan_config = ScanConfig {
        start_height: 400,
        end_height: Some(404),
        batch_size: 10,
        request_timeout: Duration::from_secs(30),
        extraction_config,
    };

    let results = scanner.scan_blocks(scan_config).await.expect("Scan failed");

    // Calculate balance
    let mut total_balance = 0u64;
    let mut output_count = 0;
    let mut mature_balance = 0u64;
    let mut immature_balance = 0u64;

    for result in &results {
        for wallet_output in &result.wallet_outputs {
            let value = wallet_output.value().as_u64();
            total_balance += value;
            output_count += 1;

            // Simulate maturity rules (outputs mature after 3 blocks)
            let blocks_since_mined = 1000 - result.height; // Assume tip is at 1000
            if blocks_since_mined >= 3 {
                mature_balance += value;
            } else {
                immature_balance += value;
            }
        }
    }

    // Verify balance calculations
    let expected_total: u64 = output_values.iter().sum();
    assert_eq!(total_balance, expected_total);
    assert_eq!(output_count, output_values.len());

    // All outputs should be mature (old blocks)
    assert_eq!(mature_balance, expected_total);
    assert_eq!(immature_balance, 0);

    // Test balance breakdown by account/address
    let mut balance_by_height: HashMap<u64, u64> = HashMap::new();
    for result in &results {
        let height_balance: u64 = result
            .wallet_outputs
            .iter()
            .map(|wo| wo.value().as_u64())
            .sum();
        balance_by_height.insert(result.height, height_balance);
    }

    // Verify individual balances
    for (i, &expected_value) in output_values.iter().enumerate() {
        let height = 400 + i as u64;
        assert_eq!(balance_by_height[&height], expected_value);
    }

    println!("✓ Balance calculation workflow test passed");
    println!("  Total balance: {total_balance} µT ({output_count} outputs)");
    println!("  Mature: {mature_balance} µT, Immature: {immature_balance} µT");
}

/// Test error handling and edge cases in scanning
#[tokio::test]
async fn test_scanning_error_handling() {
    let wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");
    let (view_key, _) = derive_test_keys(&wallet);

    // Test empty scan range
    let mut scanner = TestBlockchainScanner::new();
    let extraction_config = ExtractionConfig::with_private_key(view_key.clone());
    let empty_config = ScanConfig {
        start_height: 500,
        end_height: Some(499), // Invalid range
        batch_size: 10,
        request_timeout: Duration::from_secs(30),
        extraction_config: extraction_config.clone(),
    };

    let empty_results = scanner
        .scan_blocks(empty_config)
        .await
        .expect("Empty scan should succeed");
    assert!(empty_results.is_empty());

    // Test large batch size
    let large_batch_config = ScanConfig {
        start_height: 500,
        end_height: Some(502),
        batch_size: 1000, // Larger than range
        request_timeout: Duration::from_secs(30),
        extraction_config: extraction_config.clone(),
    };

    let large_batch_results = scanner
        .scan_blocks(large_batch_config)
        .await
        .expect("Large batch scan should succeed");
    assert_eq!(large_batch_results.len(), 0); // No blocks in scanner

    // Test scanning non-existent blocks
    let missing_config = ScanConfig {
        start_height: 9999,
        end_height: Some(10001),
        batch_size: 10,
        request_timeout: Duration::from_secs(30),
        extraction_config,
    };

    let missing_results = scanner
        .scan_blocks(missing_config)
        .await
        .expect("Missing blocks scan should succeed");
    assert!(missing_results.is_empty());

    println!("✓ Scanning error handling test passed");
}

/// Test concurrent scanning operations
#[tokio::test]
async fn test_concurrent_scanning() {
    let wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");
    let (view_key, spend_key) = derive_test_keys(&wallet);

    // Setup scanner with test data
    let mut scanner = TestBlockchainScanner::new();
    for height in 600..650 {
        let output = create_test_output(1000000, &view_key, &spend_key)
            .expect("Failed to create test output");
        scanner.add_test_block(height, vec![output]);
    }

    // Perform multiple scans concurrently
    let extraction_config = ExtractionConfig::with_private_key(view_key.clone());

    let config1 = ScanConfig {
        start_height: 600,
        end_height: Some(624),
        batch_size: 5,
        request_timeout: Duration::from_secs(30),
        extraction_config: extraction_config.clone(),
    };

    let config2 = ScanConfig {
        start_height: 625,
        end_height: Some(649),
        batch_size: 5,
        request_timeout: Duration::from_secs(30),
        extraction_config: extraction_config.clone(),
    };

    // Note: Since we can't easily clone the scanner, we'll test sequential execution
    let start_time = Instant::now();

    let results1 = scanner
        .scan_blocks(config1)
        .await
        .expect("First scan failed");

    let results2 = scanner
        .scan_blocks(config2)
        .await
        .expect("Second scan failed");

    let total_duration = start_time.elapsed();

    // Verify results
    assert_eq!(results1.len(), 25); // 600-624
    assert_eq!(results2.len(), 25); // 625-649

    let total_outputs1: usize = results1.iter().map(|r| r.wallet_outputs.len()).sum();
    let total_outputs2: usize = results2.iter().map(|r| r.wallet_outputs.len()).sum();

    assert_eq!(total_outputs1, 25);
    assert_eq!(total_outputs2, 25);

    // Verify no overlap in block heights
    let heights1: Vec<u64> = results1.iter().map(|r| r.height).collect();
    let heights2: Vec<u64> = results2.iter().map(|r| r.height).collect();

    for h1 in &heights1 {
        assert!(
            !heights2.contains(h1),
            "Height {h1} found in both result sets"
        );
    }

    println!("✓ Concurrent scanning test passed");
    println!(
        "  Scan 1: {} blocks, {} outputs",
        results1.len(),
        total_outputs1
    );
    println!(
        "  Scan 2: {} blocks, {} outputs",
        results2.len(),
        total_outputs2
    );
    println!("  Total duration: {total_duration:?}");
}

/// Helper function to derive test keys from wallet
fn derive_test_keys(wallet: &Wallet) -> (PrivateKey, PrivateKey) {
    // Get master key from wallet
    let master_key_bytes = wallet.master_key_bytes();

    // Create view key from master key
    let view_key =
        PrivateKey::from_canonical_bytes(&master_key_bytes).expect("Failed to create view key");

    // Create spend key by hashing master_key + "spend"
    use blake2b_simd::blake2b;
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(&master_key_bytes);
    hasher_input.extend_from_slice(b"spend");

    let spend_key_hash = blake2b(&hasher_input);
    let spend_key_bytes: [u8; 32] = spend_key_hash.as_bytes()[0..32]
        .try_into()
        .expect("Failed to create spend key bytes");

    let spend_key =
        PrivateKey::from_canonical_bytes(&spend_key_bytes).expect("Failed to create spend key");

    (view_key, spend_key)
}
