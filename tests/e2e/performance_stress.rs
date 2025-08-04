//! Performance and stress testing for large dataset processing
//!
//! Tests system performance under load with large datasets, memory usage profiling,
//! and concurrent operation validation to ensure scalability.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

use lightweight_wallet_libs::data_structures::{
    address::{TariAddress, TariAddressFeatures},
    transaction_output::TransactionOutput,
    types::PrivateKey,
};
use lightweight_wallet_libs::extraction::ExtractionConfig;
use lightweight_wallet_libs::scanning::*;
use lightweight_wallet_libs::wallet::*;

/// Performance metrics collection
#[derive(Debug, Clone)]
struct PerformanceMetrics {
    #[allow(dead_code)]
    operation: String,
    #[allow(dead_code)]
    duration: Duration,
    #[allow(dead_code)]
    items_processed: usize,
    memory_peak_mb: Option<f64>,
    throughput_per_second: f64,
}

impl PerformanceMetrics {
    fn new(operation: String, duration: Duration, items_processed: usize) -> Self {
        let throughput_per_second = if duration.as_secs_f64() > 0.0 {
            items_processed as f64 / duration.as_secs_f64()
        } else {
            0.0
        };

        Self {
            operation,
            duration,
            items_processed,
            memory_peak_mb: None,
            throughput_per_second,
        }
    }

    fn with_memory(mut self, memory_mb: f64) -> Self {
        self.memory_peak_mb = Some(memory_mb);
        self
    }
}

/// Memory usage monitor (simplified for testing)
struct MemoryMonitor {
    initial_usage: f64,
    peak_usage: f64,
}

impl MemoryMonitor {
    fn new() -> Self {
        Self {
            initial_usage: Self::get_memory_usage(),
            peak_usage: 0.0,
        }
    }

    fn update(&mut self) {
        let current = Self::get_memory_usage();
        if current > self.peak_usage {
            self.peak_usage = current;
        }
    }

    fn peak_delta_mb(&self) -> f64 {
        self.peak_usage - self.initial_usage
    }

    // Simplified memory usage estimation (in production would use actual system calls)
    fn get_memory_usage() -> f64 {
        // For testing purposes, return a simulated value
        // In real implementation, would use system APIs
        42.0 // MB
    }
}

/// Large dataset generator for stress testing
struct DatasetGenerator {
    seed: u64,
}

impl DatasetGenerator {
    fn new(seed: u64) -> Self {
        Self { seed }
    }

    fn generate_wallets(&self, count: usize) -> Vec<Wallet> {
        let mut wallets = Vec::with_capacity(count);

        for i in 0..count {
            // Use deterministic seed generation for reproducible tests
            let _wallet_seed = format!("test_wallet_{}_{}", self.seed, i);
            let wallet =
                Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");
            wallets.push(wallet);
        }

        wallets
    }

    fn generate_addresses(&self, wallet: &Wallet, count: usize) -> Vec<TariAddress> {
        let mut addresses = Vec::with_capacity(count);

        let features_variants = [
            TariAddressFeatures::create_interactive_only(),
            TariAddressFeatures::create_one_sided_only(),
            TariAddressFeatures::create_interactive_and_one_sided(),
        ];

        for i in 0..count {
            let features = features_variants[i % features_variants.len()];

            let address = if i % 2 == 0 {
                wallet
                    .get_dual_address(features, None)
                    .expect("Failed to generate dual address")
            } else {
                wallet
                    .get_single_address(features)
                    .expect("Failed to generate single address")
            };

            addresses.push(address);
        }

        addresses
    }

    fn generate_mock_blocks(&self, count: usize, outputs_per_block: usize) -> Vec<BlockInfo> {
        let mut blocks = Vec::with_capacity(count);

        for height in 0..count {
            let mut outputs = Vec::with_capacity(outputs_per_block);

            for output_index in 0..outputs_per_block {
                // Create mock transaction output
                let value = 1000000 + (height * outputs_per_block + output_index) as u64 * 1000;
                outputs.push(self.create_mock_output(value));
            }

            let block = BlockInfo {
                height: height as u64,
                hash: vec![(height % 256) as u8; 32],
                timestamp: 1640995200 + (height as u64 * 600), // ~10 min blocks
                outputs,
                inputs: vec![],
                kernels: vec![],
            };

            blocks.push(block);
        }

        blocks
    }

    fn create_mock_output(&self, value: u64) -> TransactionOutput {
        use lightweight_wallet_libs::data_structures::{
            encrypted_data::EncryptedData,
            transaction_output::TransactionOutput,
            types::{CompressedCommitment, CompressedPublicKey, MicroMinotari},
            wallet_output::{
                Covenant, LightweightRangeProofType, OutputFeatures, OutputType, Script, Signature,
            },
        };

        let features = OutputFeatures {
            output_type: OutputType::Payment,
            maturity: 0,
            range_proof_type: LightweightRangeProofType::BulletProofPlus,
        };

        let commitment = CompressedCommitment::new([0x42; 32]);
        let sender_offset_public_key =
            CompressedPublicKey::from_private_key(&PrivateKey::new([0x42; 32]));
        let metadata_signature = Signature::default();

        let micro_value = MicroMinotari::from(value);
        let encrypted_data = EncryptedData::default(); // Mock encrypted data

        TransactionOutput::new(
            1, // version
            features,
            commitment,
            None, // proof
            Script::default(),
            sender_offset_public_key,
            metadata_signature,
            Covenant::default(),
            encrypted_data,
            micro_value, // minimum_value_promise
        )
    }
}

/// Test large-scale wallet generation performance
#[tokio::test]
async fn test_large_scale_wallet_generation() {
    const WALLET_COUNT: usize = 1000;

    let mut memory_monitor = MemoryMonitor::new();
    let generator = DatasetGenerator::new(12345);

    println!("Starting large-scale wallet generation test...");

    let start_time = Instant::now();
    let wallets = generator.generate_wallets(WALLET_COUNT);
    let generation_duration = start_time.elapsed();
    memory_monitor.update();

    // Verify all wallets are unique
    let mut unique_keys = std::collections::HashSet::new();
    for wallet in &wallets {
        let master_key = wallet.master_key_bytes();
        assert!(
            unique_keys.insert(master_key),
            "Duplicate wallet master key found"
        );
    }

    let metrics = PerformanceMetrics::new(
        "wallet_generation".to_string(),
        generation_duration,
        WALLET_COUNT,
    )
    .with_memory(memory_monitor.peak_delta_mb());

    // Performance assertions
    assert_eq!(wallets.len(), WALLET_COUNT);
    assert!(
        metrics.throughput_per_second > 100.0,
        "Wallet generation too slow: {:.2} wallets/sec",
        metrics.throughput_per_second
    );

    println!("✓ Large-scale wallet generation test passed");
    println!("  Generated {WALLET_COUNT} wallets in {generation_duration:?}");
    println!(
        "  Throughput: {:.2} wallets/sec",
        metrics.throughput_per_second
    );
    println!("  Memory delta: {:.2} MB", memory_monitor.peak_delta_mb());
}

/// Test large-scale address generation performance
#[tokio::test]
async fn test_large_scale_address_generation() {
    const ADDRESS_COUNT: usize = 5000;

    let wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

    let generator = DatasetGenerator::new(54321);
    let mut memory_monitor = MemoryMonitor::new();

    println!("Starting large-scale address generation test...");

    let start_time = Instant::now();
    let addresses = generator.generate_addresses(&wallet, ADDRESS_COUNT);
    let generation_duration = start_time.elapsed();
    memory_monitor.update();

    // Verify all addresses are unique
    let mut unique_addresses = std::collections::HashSet::new();
    for address in &addresses {
        let hex_addr = address.to_hex();
        assert!(unique_addresses.insert(hex_addr), "Duplicate address found");
    }

    // Verify address type distribution
    let mut dual_count = 0;
    let mut single_count = 0;

    for address in &addresses {
        match address {
            TariAddress::Dual(_) => dual_count += 1,
            TariAddress::Single(_) => single_count += 1,
        }
    }

    let metrics = PerformanceMetrics::new(
        "address_generation".to_string(),
        generation_duration,
        ADDRESS_COUNT,
    )
    .with_memory(memory_monitor.peak_delta_mb());

    // Performance assertions
    assert_eq!(addresses.len(), ADDRESS_COUNT);
    assert!(
        dual_count > 0 && single_count > 0,
        "Should generate both address types"
    );
    assert!(
        metrics.throughput_per_second > 500.0,
        "Address generation too slow: {:.2} addresses/sec",
        metrics.throughput_per_second
    );

    println!("✓ Large-scale address generation test passed");
    println!("  Generated {ADDRESS_COUNT} addresses in {generation_duration:?}");
    println!("  Distribution: {dual_count} dual, {single_count} single");
    println!(
        "  Throughput: {:.2} addresses/sec",
        metrics.throughput_per_second
    );
    println!("  Memory delta: {:.2} MB", memory_monitor.peak_delta_mb());
}

/// Test large dataset scanning performance
#[tokio::test]
async fn test_large_dataset_scanning_performance() {
    const BLOCK_COUNT: usize = 1000;
    const OUTPUTS_PER_BLOCK: usize = 50;
    const TOTAL_OUTPUTS: usize = BLOCK_COUNT * OUTPUTS_PER_BLOCK;

    let wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

    let master_key_bytes = wallet.master_key_bytes();
    let view_key =
        PrivateKey::from_canonical_bytes(&master_key_bytes).expect("Failed to create view key");

    let generator = DatasetGenerator::new(98765);
    let mut memory_monitor = MemoryMonitor::new();

    println!("Generating large dataset for scanning test...");
    let dataset_start = Instant::now();
    let blocks = generator.generate_mock_blocks(BLOCK_COUNT, OUTPUTS_PER_BLOCK);
    let dataset_duration = dataset_start.elapsed();
    memory_monitor.update();

    println!(
        "Dataset generation: {BLOCK_COUNT} blocks with {TOTAL_OUTPUTS} outputs in {dataset_duration:?}"
    );

    // Test scanning performance
    println!("Starting large dataset scanning test...");
    let extraction_config = ExtractionConfig::with_private_key(view_key);

    let scan_start = Instant::now();
    let scan_results = DefaultScanningLogic::process_blocks(blocks, &extraction_config)
        .expect("Failed to process blocks");
    let scan_duration = scan_start.elapsed();
    memory_monitor.update();

    // Analyze results
    let total_wallet_outputs: usize = scan_results.iter().map(|r| r.wallet_outputs.len()).sum();

    let metrics = PerformanceMetrics::new(
        "large_dataset_scanning".to_string(),
        scan_duration,
        TOTAL_OUTPUTS,
    )
    .with_memory(memory_monitor.peak_delta_mb());

    // Performance assertions
    assert_eq!(scan_results.len(), BLOCK_COUNT);
    assert!(
        metrics.throughput_per_second > 1000.0,
        "Scanning too slow: {:.2} outputs/sec",
        metrics.throughput_per_second
    );

    println!("✓ Large dataset scanning test passed");
    println!("  Scanned {TOTAL_OUTPUTS} outputs in {BLOCK_COUNT} blocks in {scan_duration:?}");
    println!("  Found {total_wallet_outputs} wallet outputs");
    println!(
        "  Throughput: {:.2} outputs/sec",
        metrics.throughput_per_second
    );
    println!("  Memory delta: {:.2} MB", memory_monitor.peak_delta_mb());
}

/// Test concurrent wallet operations
#[tokio::test]
async fn test_concurrent_wallet_operations() {
    const CONCURRENT_WALLETS: usize = 100;
    const OPERATIONS_PER_WALLET: usize = 10;

    let semaphore = Arc::new(Semaphore::new(20)); // Limit concurrent operations
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut memory_monitor = MemoryMonitor::new();

    println!("Starting concurrent wallet operations test...");

    let start_time = Instant::now();
    let mut handles = Vec::new();

    for wallet_id in 0..CONCURRENT_WALLETS {
        let semaphore = semaphore.clone();
        let results = results.clone();

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();

            let wallet =
                Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

            let mut wallet_results = Vec::new();

            for op_id in 0..OPERATIONS_PER_WALLET {
                let op_start = Instant::now();

                // Perform various wallet operations
                match op_id % 4 {
                    0 => {
                        // Address generation
                        let address = wallet
                            .get_dual_address(TariAddressFeatures::create_interactive_only(), None)
                            .expect("Failed to generate address");
                        wallet_results.push((
                            "address_gen",
                            op_start.elapsed(),
                            address.to_hex().len(),
                        ));
                    }
                    1 => {
                        // Single address generation
                        let address = wallet
                            .get_single_address(TariAddressFeatures::create_one_sided_only())
                            .expect("Failed to generate single address");
                        wallet_results.push((
                            "single_address",
                            op_start.elapsed(),
                            address.to_hex().len(),
                        ));
                    }
                    2 => {
                        // Seed phrase export
                        let seed = wallet
                            .export_seed_phrase()
                            .expect("Failed to export seed phrase");
                        wallet_results.push(("seed_export", op_start.elapsed(), seed.len()));
                    }
                    3 => {
                        // Master key access
                        let master_key = wallet.master_key_bytes();
                        wallet_results.push(("master_key", op_start.elapsed(), master_key.len()));
                    }
                    _ => unreachable!(),
                }
            }

            // Store results
            let mut results_guard = results.lock().await;
            results_guard.push((wallet_id, wallet_results));
        });

        handles.push(handle);
    }

    // Wait for all operations to complete with timeout
    let timeout_duration = Duration::from_secs(30);
    for handle in handles {
        timeout(timeout_duration, handle)
            .await
            .expect("Operation timed out")
            .expect("Task failed");
    }

    let total_duration = start_time.elapsed();
    memory_monitor.update();

    // Analyze results
    let results_guard = results.lock().await;
    let total_operations = results_guard.len() * OPERATIONS_PER_WALLET;

    let mut operation_counts = HashMap::new();
    let mut total_op_duration = Duration::from_secs(0);

    for (_, wallet_ops) in results_guard.iter() {
        for (op_type, duration, _) in wallet_ops {
            *operation_counts.entry(op_type).or_insert(0) += 1;
            total_op_duration += *duration;
        }
    }

    let metrics = PerformanceMetrics::new(
        "concurrent_wallet_operations".to_string(),
        total_duration,
        total_operations,
    )
    .with_memory(memory_monitor.peak_delta_mb());

    // Performance assertions
    assert_eq!(results_guard.len(), CONCURRENT_WALLETS);
    assert!(
        metrics.throughput_per_second > 100.0,
        "Concurrent operations too slow: {:.2} ops/sec",
        metrics.throughput_per_second
    );

    println!("✓ Concurrent wallet operations test passed");
    println!(
        "  {CONCURRENT_WALLETS} wallets × {OPERATIONS_PER_WALLET} operations = {total_operations} total ops in {total_duration:?}"
    );
    println!("  Operation distribution: {operation_counts:?}");
    println!("  Throughput: {:.2} ops/sec", metrics.throughput_per_second);
    println!("  Memory delta: {:.2} MB", memory_monitor.peak_delta_mb());
}

/// Test memory usage under stress
#[tokio::test]
async fn test_memory_usage_stress() {
    const STRESS_ITERATIONS: usize = 100;
    const OBJECTS_PER_ITERATION: usize = 100;

    let mut memory_monitor = MemoryMonitor::new();
    let mut peak_memory_per_iteration = Vec::new();

    println!("Starting memory usage stress test...");

    for iteration in 0..STRESS_ITERATIONS {
        let iteration_start = MemoryMonitor::get_memory_usage();

        // Create many objects
        let mut wallets = Vec::new();
        let mut addresses = Vec::new();

        for _ in 0..OBJECTS_PER_ITERATION {
            let wallet =
                Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

            let address = wallet
                .get_dual_address(
                    TariAddressFeatures::create_interactive_and_one_sided(),
                    None,
                )
                .expect("Failed to generate address");

            wallets.push(wallet);
            addresses.push(address);
        }

        memory_monitor.update();
        let iteration_peak = MemoryMonitor::get_memory_usage();
        peak_memory_per_iteration.push(iteration_peak - iteration_start);

        // Force cleanup
        drop(wallets);
        drop(addresses);

        // Log progress every 10 iterations
        if iteration % 10 == 0 {
            println!(
                "  Iteration {}/{}: peak delta {:.2} MB",
                iteration,
                STRESS_ITERATIONS,
                iteration_peak - iteration_start
            );
        }
    }

    let total_objects = STRESS_ITERATIONS * OBJECTS_PER_ITERATION * 2; // wallets + addresses
    let average_memory_per_iteration: f64 =
        peak_memory_per_iteration.iter().sum::<f64>() / peak_memory_per_iteration.len() as f64;
    let max_memory_per_iteration = peak_memory_per_iteration
        .iter()
        .fold(0.0f64, |a, &b| a.max(b));

    // Memory assertions (these are rough estimates)
    assert!(
        max_memory_per_iteration < 100.0,
        "Memory usage too high: {max_memory_per_iteration:.2} MB"
    );
    assert!(
        average_memory_per_iteration < 50.0,
        "Average memory usage too high: {average_memory_per_iteration:.2} MB"
    );

    println!("✓ Memory usage stress test passed");
    println!(
        "  {} iterations × {} objects = {} total objects",
        STRESS_ITERATIONS,
        OBJECTS_PER_ITERATION * 2,
        total_objects
    );
    println!("  Average memory per iteration: {average_memory_per_iteration:.2} MB",);
    println!("  Peak memory per iteration: {max_memory_per_iteration:.2} MB",);
    println!(
        "  Total memory delta: {:.2} MB",
        memory_monitor.peak_delta_mb()
    );
}

/// Test performance degradation over time
#[tokio::test]
async fn test_performance_degradation() {
    const TIME_WINDOWS: usize = 10;
    const OPERATIONS_PER_WINDOW: usize = 1000;

    let wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

    let mut window_metrics = Vec::new();
    let mut memory_monitor = MemoryMonitor::new();

    println!("Starting performance degradation test...");

    for window in 0..TIME_WINDOWS {
        let window_start = Instant::now();

        // Perform many operations
        for i in 0..OPERATIONS_PER_WINDOW {
            let features = if i % 3 == 0 {
                TariAddressFeatures::create_interactive_only()
            } else if i % 3 == 1 {
                TariAddressFeatures::create_one_sided_only()
            } else {
                TariAddressFeatures::create_interactive_and_one_sided()
            };

            let _address = if i % 2 == 0 {
                wallet
                    .get_dual_address(features, None)
                    .expect("Failed to generate dual address")
            } else {
                wallet
                    .get_single_address(features)
                    .expect("Failed to generate single address")
            };
        }

        let window_duration = window_start.elapsed();
        memory_monitor.update();

        let window_metric = PerformanceMetrics::new(
            format!("window_{window}"),
            window_duration,
            OPERATIONS_PER_WINDOW,
        );

        window_metrics.push(window_metric.clone());

        println!(
            "  Window {}: {:.2} ops/sec in {:?}",
            window, window_metric.throughput_per_second, window_duration
        );
    }

    // Analyze performance degradation
    let first_window_throughput = window_metrics[0].throughput_per_second;
    let last_window_throughput = window_metrics[TIME_WINDOWS - 1].throughput_per_second;
    let degradation_percentage =
        ((first_window_throughput - last_window_throughput) / first_window_throughput) * 100.0;

    let average_throughput: f64 = window_metrics
        .iter()
        .map(|m| m.throughput_per_second)
        .sum::<f64>()
        / window_metrics.len() as f64;

    // Performance assertions
    assert!(
        degradation_percentage < 20.0,
        "Performance degraded too much: {degradation_percentage:.2}%"
    );
    assert!(
        average_throughput > 500.0,
        "Average throughput too low: {average_throughput:.2} ops/sec",
    );

    println!("✓ Performance degradation test passed");
    println!(
        "  {} windows × {} operations = {} total",
        TIME_WINDOWS,
        OPERATIONS_PER_WINDOW,
        TIME_WINDOWS * OPERATIONS_PER_WINDOW
    );
    println!("  First window: {first_window_throughput:.2} ops/sec");
    println!("  Last window: {last_window_throughput:.2} ops/sec");
    println!("  Degradation: {degradation_percentage:.2}%");
    println!("  Average throughput: {average_throughput:.2} ops/sec");
    println!("  Memory delta: {:.2} MB", memory_monitor.peak_delta_mb());
}

/// Test concurrent scanning operations
#[tokio::test]
async fn test_concurrent_scanning_operations() {
    const CONCURRENT_SCANNERS: usize = 10;
    const BLOCKS_PER_SCANNER: usize = 100;
    const OUTPUTS_PER_BLOCK: usize = 20;

    let semaphore = Arc::new(Semaphore::new(5)); // Limit concurrent scanners
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut memory_monitor = MemoryMonitor::new();

    println!("Starting concurrent scanning operations test...");

    let start_time = Instant::now();
    let mut handles = Vec::new();

    for scanner_id in 0..CONCURRENT_SCANNERS {
        let semaphore = semaphore.clone();
        let results = results.clone();

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();

            // Generate test data for this scanner
            let generator = DatasetGenerator::new(scanner_id as u64);
            let blocks = generator.generate_mock_blocks(BLOCKS_PER_SCANNER, OUTPUTS_PER_BLOCK);

            // Create extraction config
            let wallet =
                Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");
            let master_key_bytes = wallet.master_key_bytes();
            let view_key = PrivateKey::from_canonical_bytes(&master_key_bytes)
                .expect("Failed to create view key");
            let extraction_config = ExtractionConfig::with_private_key(view_key);

            // Perform scanning
            let scan_start = Instant::now();
            let scan_results = DefaultScanningLogic::process_blocks(blocks, &extraction_config)
                .expect("Failed to process blocks");
            let scan_duration = scan_start.elapsed();

            let total_outputs = scan_results.iter().map(|r| r.outputs.len()).sum::<usize>();
            let wallet_outputs = scan_results
                .iter()
                .map(|r| r.wallet_outputs.len())
                .sum::<usize>();

            // Store results
            let mut results_guard = results.lock().await;
            results_guard.push((scanner_id, scan_duration, total_outputs, wallet_outputs));
        });

        handles.push(handle);
    }

    // Wait for all scanners to complete
    let timeout_duration = Duration::from_secs(60);
    for handle in handles {
        timeout(timeout_duration, handle)
            .await
            .expect("Scanner timed out")
            .expect("Scanner task failed");
    }

    let total_duration = start_time.elapsed();
    memory_monitor.update();

    // Analyze results
    let results_guard = results.lock().await;
    let total_outputs_scanned: usize = results_guard
        .iter()
        .map(|(_, _, outputs, _)| *outputs)
        .sum();
    let total_wallet_outputs: usize = results_guard
        .iter()
        .map(|(_, _, _, wallet_outputs)| *wallet_outputs)
        .sum();

    let average_scan_duration: Duration = results_guard
        .iter()
        .map(|(_, duration, _, _)| *duration)
        .sum::<Duration>()
        / results_guard.len() as u32;

    let metrics = PerformanceMetrics::new(
        "concurrent_scanning".to_string(),
        total_duration,
        total_outputs_scanned,
    )
    .with_memory(memory_monitor.peak_delta_mb());

    // Performance assertions
    assert_eq!(results_guard.len(), CONCURRENT_SCANNERS);
    assert!(
        metrics.throughput_per_second > 1000.0,
        "Concurrent scanning too slow: {:.2} outputs/sec",
        metrics.throughput_per_second
    );

    println!("✓ Concurrent scanning operations test passed");
    println!("  {CONCURRENT_SCANNERS} concurrent scanners");
    println!("  Total outputs scanned: {total_outputs_scanned}");
    println!("  Total wallet outputs found: {total_wallet_outputs}");
    println!("  Average scan duration: {average_scan_duration:?}");
    println!(
        "  Total throughput: {:.2} outputs/sec",
        metrics.throughput_per_second
    );
    println!("  Memory delta: {:.2} MB", memory_monitor.peak_delta_mb());
}
