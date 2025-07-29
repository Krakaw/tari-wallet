# Tari Wallet Scanner Library Integration Guide

## Overview

The Tari Wallet Scanner provides a powerful, flexible library API for integrating blockchain scanning functionality into Rust applications. This guide demonstrates how to use the scanning library components to build custom wallet applications, web services, and blockchain monitoring tools.

## Library Architecture
```
src/scanning/              (9,249 lines of reusable library code)
├── mod.rs                 - Public API exports
├── scan_config.rs         - Configuration structures
├── storage_manager.rs     - Storage abstraction layer
├── background_writer.rs   - Async database operations
├── wallet_scanner.rs      - Core scanning implementation
├── progress.rs            - Progress tracking utilities
├── grpc_scanner.rs        - GRPC blockchain scanner
└── http_scanner.rs        - HTTP blockchain scanner

src/bin/scanner.rs         (796 lines of CLI-only code)
├── Clap argument parsing
├── User interface/prompts
├── Progress display
└── Library API orchestration
```

## Key Features

### ✅ Reusable Components
- **Modular design** - Import only the functionality you need
- **Multiple targets** - Native, WASM, web applications, mobile apps
- **Clean API** - Builder patterns and comprehensive error handling

### ✅ Comprehensive Testing
- **Unit tests** for individual library components
- **Mock support** for deterministic testing
- **Integration tests** for end-to-end workflows

### ✅ Performance Optimized
- **Background writer** for non-blocking database operations
- **Batch processing** with configurable sizes
- **Async/await** patterns throughout
- **Memory management** with proper zeroization

### ✅ Flexible Configuration
- **Feature flags** for platform-specific functionality
- **Multiple storage backends** (memory, SQLite database)
- **Custom progress tracking** and error handling
- **Retry mechanisms** and timeout configuration

## Integration Examples

### 1. Basic Wallet Scanning
```rust
use lightweight_wallet_libs::scanning::{
    create_wallet_from_seed_phrase,
    WalletScannerStruct, WalletScannerConfig,
    GrpcScannerBuilder, ScannerStorage,
    BinaryScanConfig
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create scan context from seed phrase
    let (scan_context, birthday) = create_wallet_from_seed_phrase("your seed phrase")?;
    
    // Create blockchain scanner
    let mut grpc_scanner = GrpcScannerBuilder::new()
        .with_base_url("http://localhost:18142".to_string())
        .build()
        .await?;
    
    // Create storage (memory or database)
    let mut storage = ScannerStorage::new_memory();
    
    // Configure scanning parameters
    let config = BinaryScanConfig::new(birthday, 100000)
        .with_batch_size(50)
        .with_quiet_mode(false);
    
    // Create wallet scanner with progress tracking
    let mut wallet_scanner = WalletScannerStruct::from_config(
        WalletScannerConfig::default().with_batch_size(50)
    ).with_progress_callback(|progress| {
        println!("Progress: {:.1}% - Block {}", 
                 progress.progress_percent, 
                 progress.current_block);
    });
    
    // Perform the scan
    let mut cancel_rx = tokio::sync::watch::channel(false).1;
    let result = wallet_scanner.scan(
        &mut grpc_scanner, 
        &scan_context, 
        &config, 
        &mut storage, 
        &mut cancel_rx
    ).await?;
    
    // Process results
    println!("Scan completed: {} transactions found", 
             result.wallet_state.transactions.len());
    
    Ok(())
}
```

### 2. Database-Backed Scanning with Resume
```rust
use lightweight_wallet_libs::scanning::{ScannerStorage, WalletScannerStruct};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create database storage with automatic resume capability
    let mut storage = ScannerStorage::new_with_database("./wallet.db").await?;
    
    // Handle wallet operations automatically
    let config = BinaryScanConfig::new(0, 100000)
        .with_database_path("./wallet.db".to_string());
    
    let scan_context = storage.handle_wallet_operations(&config, None).await?;
    
    // Get resume point automatically
    let wallet_birthday = storage.get_wallet_birthday().await?;
    let from_block = wallet_birthday.unwrap_or(0);
    
    // Continue with scanning...
    Ok(())
}
```

### 3. Custom Progress Tracking
```rust
use lightweight_wallet_libs::scanning::{ProgressInfo, WalletScannerStruct};

// Custom progress handler for web applications
fn web_progress_handler(progress: &ProgressInfo) {
    // Send progress updates to web client via WebSocket
    send_to_websocket(serde_json::json!({
        "type": "scan_progress",
        "percent": progress.progress_percent,
        "current_block": progress.current_block,
        "outputs_found": progress.outputs_found,
        "blocks_per_sec": progress.blocks_per_sec,
        "eta": progress.eta.map(|d| d.as_secs())
    })).expect("Failed to send progress update");
}

// Configure scanner with custom progress handler
let wallet_scanner = WalletScannerStruct::default()
    .with_progress_callback(web_progress_handler);
```

### 4. WASM Integration
```rust
// WASM-compatible scanning (web-sys feature)
use lightweight_wallet_libs::scanning::{
    WalletScannerStruct, HttpScannerBuilder, ScannerStorage
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub async fn scan_wallet_wasm(
    seed_phrase: &str,
    base_url: &str,
    from_block: u64,
    to_block: u64,
) -> Result<JsValue, JsValue> {
    let (scan_context, _) = create_wallet_from_seed_phrase(seed_phrase)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let mut http_scanner = HttpScannerBuilder::new()
        .with_base_url(base_url.to_string())
        .build()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let mut storage = ScannerStorage::new_memory();
    let config = BinaryScanConfig::new(from_block, to_block);
    
    let mut wallet_scanner = WalletScannerStruct::default();
    let mut cancel_rx = tokio::sync::watch::channel(false).1;
    
    let result = wallet_scanner.scan(
        &mut http_scanner, 
        &scan_context, 
        &config, 
        &mut storage, 
        &mut cancel_rx
    ).await
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    Ok(serde_wasm_bindgen::to_value(&result.wallet_state)?)
}
```

### 5. Batch Processing Integration
```rust
use lightweight_wallet_libs::scanning::{WalletScannerStruct, BatchProcessor};

// Custom batch processor for analytics
struct AnalyticsBatchProcessor {
    metrics_collector: MetricsCollector,
}

impl BatchProcessor for AnalyticsBatchProcessor {
    async fn process_batch(&mut self, blocks: &[Block]) -> Result<(), ScanError> {
        // Collect custom metrics from each batch
        for block in blocks {
            self.metrics_collector.record_block_metrics(block);
        }
        
        // Send metrics to analytics service
        self.metrics_collector.flush_to_analytics().await?;
        Ok(())
    }
}

// Use custom batch processor
let mut wallet_scanner = WalletScannerStruct::default()
    .with_batch_processor(AnalyticsBatchProcessor::new())
    .with_batch_size(100);
```

## Configuration Guide

### Scanner Configuration
```rust
use std::time::Duration;
use lightweight_wallet_libs::scanning::{
    BinaryScanConfig, WalletScannerConfig, OutputFormat, RetryConfig
};

// Scan configuration
let scan_config = BinaryScanConfig::new(1000, 2000)
    .with_batch_size(50)
    .with_progress_frequency(10)
    .with_output_format(OutputFormat::Json)
    .with_quiet_mode(true);

// Scanner configuration
let scanner_config = WalletScannerConfig {
    batch_size: 50,
    timeout: Some(Duration::from_secs(30)),
    verbose_logging: false,
    retry_config: RetryConfig::default()
        .with_max_retries(3)
        .with_retry_delay(Duration::from_millis(500)),
    progress_tracker: None, // Set separately with callback
};

// GRPC scanner configuration
let mut grpc_scanner = GrpcScannerBuilder::new()
    .with_base_url("http://localhost:18142".to_string())
    .with_timeout(Duration::from_secs(30))
    .with_retry_config(RetryConfig::default())
    .build()
    .await?;
```

## Error Handling Patterns  
```rust
use lightweight_wallet_libs::{LightweightWalletError, ScanError};

// Comprehensive error handling with specific error types
match wallet_scanner.scan(&mut scanner, &context, &config, &mut storage, &mut cancel_rx).await {
    Ok(result) => {
        match result {
            ScanResult::Completed(wallet_state, metadata) => {
                println!("Scan completed successfully with {} transactions", 
                         wallet_state.transactions.len());
            }
            ScanResult::Interrupted(wallet_state, metadata) => {
                println!("Scan interrupted but {} transactions processed", 
                         wallet_state.transactions.len());
                // Can resume from metadata.last_scanned_block
            }
        }
    }
    Err(LightweightWalletError::Validation(validation_error)) => {
        eprintln!("Validation error: {}", validation_error);
        // Handle validation failures
    }
    Err(LightweightWalletError::StorageError(storage_error)) => {
        eprintln!("Storage error: {}", storage_error);
        // Handle database issues
    }
    Err(LightweightWalletError::NetworkError(network_error)) => {
        eprintln!("Network error: {}", network_error);
        // Handle connection issues, retry logic
    }
    Err(e) => {
        eprintln!("Unexpected error: {}", e);
    }
}
```

## Testing Patterns
```rust
use lightweight_wallet_libs::scanning::{
    WalletScannerStruct, MockBlockchainScanner, ScannerStorage
};

#[tokio::test]
async fn test_wallet_scanning_with_mock_data() {
    // Create mock scanner with predictable test data
    let mut mock_scanner = MockBlockchainScanner::new();
    mock_scanner.add_test_blocks(1000..1100);
    
    let (scan_context, _) = create_test_scan_context();
    let config = BinaryScanConfig::new(1000, 1100);
    let mut storage = ScannerStorage::new_memory();
    
    let mut wallet_scanner = WalletScannerStruct::default();
    let mut cancel_rx = tokio::sync::watch::channel(false).1;
    
    let result = wallet_scanner.scan(
        &mut mock_scanner, 
        &scan_context, 
        &config, 
        &mut storage, 
        &mut cancel_rx
    ).await.unwrap();
    
    match result {
        ScanResult::Completed(wallet_state, _) => {
            assert!(!wallet_state.transactions.is_empty());
            assert_eq!(wallet_state.current_balance, expected_balance);
        }
        _ => panic!("Expected completed scan"),
    }
}

#[test]
fn test_scan_config_validation() {
    let config = BinaryScanConfig::new(100, 50); // Invalid range
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn test_storage_operations() {
    let mut storage = ScannerStorage::new_memory();
    
    let transaction = create_test_transaction();
    storage.save_transaction(&transaction).await.unwrap();
    
    let retrieved = storage.get_transaction(&transaction.id).await.unwrap();
    assert_eq!(retrieved.id, transaction.id);
}
```

## Performance Optimization Options
```rust
use lightweight_wallet_libs::scanning::{WalletScannerStruct, PerformanceConfig};

// Performance-optimized scanner
let wallet_scanner = WalletScannerStruct::performance_optimized()
    .with_batch_size(100)  // Larger batches for better throughput
    .with_parallel_validation(true)  // Enable rayon parallel processing
    .with_background_writer(true);   // Non-blocking database writes

// Memory-optimized scanner for resource-constrained environments
let wallet_scanner = WalletScannerStruct::memory_optimized()
    .with_batch_size(10)   // Smaller batches to reduce memory usage
    .with_streaming_mode(true);  // Process blocks as they arrive

// Custom performance configuration
let perf_config = PerformanceConfig {
    max_concurrent_requests: 50,
    request_timeout: Duration::from_secs(10),
    batch_processing_threads: num_cpus::get(),
    memory_limit_mb: 512,
    cache_size: 10000,
};

let wallet_scanner = WalletScannerStruct::from_performance_config(perf_config);
```

## Feature Flag Configuration
```toml
[features]
# Core scanning features
default = ["http"]
grpc = ["tonic", "prost", "rayon"]           # GRPC with parallel processing
http = ["reqwest", "serde_json"]             # HTTP scanning
storage = ["sqlx", "rusqlite", "tokio"]      # Database persistence
wasm = ["wasm-bindgen", "web-sys", "console_error_panic_hook"]

# Combined feature sets for common use cases
grpc-storage = ["grpc", "storage"]           # Full-featured server usage
http-storage = ["http", "storage"]           # HTTP with persistence
wasm-http = ["wasm", "http"]                 # Browser scanning

# Development and testing features
mock-scanner = ["async-trait"]               # Mock implementation for testing
performance-metrics = ["metrics", "histogram"] # Performance monitoring
```

## Integration Patterns

### 1. Web Server Integration
```rust
use axum::{routing::post, Json, Router};
use lightweight_wallet_libs::scanning::*;

#[derive(serde::Deserialize)]
struct ScanRequest {
    seed_phrase: String,
    from_block: u64,
    to_block: u64,
}

async fn scan_wallet(Json(request): Json<ScanRequest>) -> Result<Json<ScanResult>, StatusCode> {
    let (scan_context, _) = create_wallet_from_seed_phrase(&request.seed_phrase)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let mut scanner = HttpScannerBuilder::new()
        .with_base_url("http://localhost:18142".to_string())
        .build()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let config = BinaryScanConfig::new(request.from_block, request.to_block);
    let mut storage = ScannerStorage::new_memory();
    let mut wallet_scanner = WalletScannerStruct::default();
    let mut cancel_rx = tokio::sync::watch::channel(false).1;
    
    let result = wallet_scanner.scan(&mut scanner, &scan_context, &config, &mut storage, &mut cancel_rx)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(result))
}

let app = Router::new()
    .route("/scan", post(scan_wallet));
```

### 2. Mobile App Integration (via FFI)
```rust
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn scan_wallet_ffi(
    seed_phrase: *const c_char,
    from_block: u64,
    to_block: u64,
    progress_callback: extern "C" fn(f64), // Progress percentage
) -> *mut c_char {
    let seed_phrase = unsafe {
        CStr::from_ptr(seed_phrase).to_string_lossy().into_owned()
    };
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    
    let result = runtime.block_on(async {
        let (scan_context, _) = create_wallet_from_seed_phrase(&seed_phrase)?;
        
        let mut scanner = HttpScannerBuilder::new()
            .with_base_url("http://localhost:18142".to_string())
            .build()
            .await?;
        
        let config = BinaryScanConfig::new(from_block, to_block);
        let mut storage = ScannerStorage::new_memory();
        
        let mut wallet_scanner = WalletScannerStruct::default()
            .with_progress_callback(move |progress| {
                progress_callback(progress.progress_percent);
            });
        
        let mut cancel_rx = tokio::sync::watch::channel(false).1;
        wallet_scanner.scan(&mut scanner, &scan_context, &config, &mut storage, &mut cancel_rx).await
    });
    
    match result {
        Ok(scan_result) => {
            let json = serde_json::to_string(&scan_result).unwrap();
            CString::new(json).unwrap().into_raw()
        }
        Err(e) => {
            let error_json = serde_json::json!({"error": e.to_string()});
            CString::new(error_json.to_string()).unwrap().into_raw()
        }
    }
}
```

## CLI vs Library Decision Guide

### Use the CLI Binary When:
- ✅ **Interactive scanning** - need user prompts and progress display
- ✅ **One-off operations** - occasional wallet scanning tasks
- ✅ **Script automation** - bash scripts and CI/CD pipelines
- ✅ **Learning/debugging** - exploring wallet contents manually

### Use the Library API When:
- ✅ **Application integration** - web apps, mobile apps, desktop software
- ✅ **Custom workflows** - complex scanning logic with custom processing
- ✅ **Automated services** - background scanning services, monitoring tools
- ✅ **Testing** - unit tests, integration tests, mock data scenarios
- ✅ **Performance optimization** - custom batch sizes, parallel processing
- ✅ **WASM deployment** - browser-based wallet applications

## Best Practices

### 1. Async/Await Patterns
✅ **Use async/await throughout:**
```rust
let result = wallet_scanner.scan(...).await?; // All scanning operations are async
```

### 2. Error Handling
✅ **Handle errors appropriately:**
```rust
return Err(LightweightWalletError::ValidationError(...)); // Return errors for caller handling
```

### 3. Configuration Management
✅ **Use builder patterns:**
```rust
let config = BinaryScanConfig::new(from_block, to_block)
    .with_batch_size(50)
    .with_quiet_mode(true);
```

### 4. Progress Tracking
✅ **Implement custom progress callbacks:**
```rust
.with_progress_callback(|progress| {
    // Send progress to your UI/API
    send_progress_update(progress);
});
```

## Conclusion

The Tari Wallet Scanner library provides a comprehensive, flexible API for integrating blockchain scanning functionality into Rust applications. Key benefits include:

- **Broad platform support** - Native, WASM, web, and mobile applications
- **Comprehensive testing** - Unit tests, integration tests, and mock support
- **Performance optimization** - Configurable batch processing and async operations
- **Flexible architecture** - Modular components with clean separation of concerns

Whether you're building a web application, mobile app, or custom blockchain monitoring tool, the scanning library provides the building blocks you need for robust wallet functionality.

For detailed usage examples and additional documentation, please refer to the [AGENT.md](./AGENT.md) file or explore the comprehensive test suite in the repository.
