# Event System Adoption Guide

This guide helps developers integrate the new event-driven architecture into existing modules and new components within the Tari Wallet Libraries.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [Integration Patterns](#integration-patterns)
- [Built-in Listeners](#built-in-listeners)
- [Creating Custom Listeners](#creating-custom-listeners)
- [Testing with Events](#testing-with-events)
- [Migration from Legacy Systems](#migration-from-legacy-systems)
- [Performance Considerations](#performance-considerations)
- [Troubleshooting](#troubleshooting)

## Overview

The event system provides a flexible, decoupled architecture for handling wallet operations through publish-subscribe patterns. Instead of direct callback functions and storage backends, operations emit structured events that multiple listeners can handle independently.

### Key Benefits

- **Separation of Concerns**: Business logic is decoupled from storage and UI concerns
- **Flexibility**: Multiple listeners can handle the same events for different purposes
- **Testability**: Mock listeners enable comprehensive testing without real storage/network
- **Error Isolation**: Listener failures don't interrupt core operations
- **Cross-platform Compatibility**: Works on both native and WASM targets

## Quick Start

### Basic Setup

```rust
use lightweight_wallet_libs::events::{EventDispatcher, WalletScanEvent};
use lightweight_wallet_libs::events::listeners::{
    DatabaseStorageListener, ProgressTrackingListener, ConsoleLoggingListener
};

async fn setup_event_system() -> Result<EventDispatcher, Box<dyn std::error::Error>> {
    let mut dispatcher = EventDispatcher::new();
    
    // Add database storage with synchronous event handling
    let db_listener = DatabaseStorageListener::new("wallet.db").await?;
    dispatcher.register(Box::new(db_listener))?;
    
    // Add progress tracking
    let progress_listener = ProgressTrackingListener::new()
        .with_progress_callback(|info| {
            println!("Progress: {:.1}% ({}/{} blocks)", 
                info.progress_percent, info.blocks_processed, info.total_blocks);
        });
    dispatcher.register(Box::new(progress_listener))?;
    
    // Add console logging for development
    let console_listener = ConsoleLoggingListener::builder()
        .console_preset()
        .build();
    dispatcher.register(Box::new(console_listener))?;
    
    Ok(dispatcher)
}

// Use the dispatcher in your operations
async fn example_usage() -> Result<(), Box<dyn std::error::Error>> {
    let mut dispatcher = setup_event_system().await?;
    
    // Emit events during operations
    let event = WalletScanEvent::scan_started(
        ScanConfig::default(),
        (1000, 2000),
        "example_wallet".to_string()
    );
    dispatcher.dispatch(event).await;
    
    Ok(())
}
```

## Core Concepts

### Event Types

The system defines structured event types for different stages of wallet operations:

```rust
use lightweight_wallet_libs::events::types::{
    WalletScanEvent, ScanConfig, OutputData, BlockInfo, 
    AddressInfo, TransactionData, SpentOutputData
};
use std::collections::HashMap;
use std::time::Duration;

// Scan lifecycle events with constructor functions
let scan_started = WalletScanEvent::scan_started(config, (start_block, end_block), wallet_context);
let block_processed = WalletScanEvent::block_processed(height, hash, timestamp, duration, outputs_count);
let output_found = WalletScanEvent::output_found(output_data, block_info, address_info, transaction_data);
let spent_output_found = WalletScanEvent::spent_output_found(spent_output_data, spending_block_info, original_output_info, spending_transaction_data);
let scan_progress = WalletScanEvent::scan_progress(current_block, total_blocks, percentage, speed_blocks_per_second, estimated_time_remaining);
let scan_completed = WalletScanEvent::scan_completed(final_statistics, success, total_duration);
let scan_error = WalletScanEvent::scan_error(error_message, error_code, block_height, retry_info, is_recoverable);
let scan_cancelled = WalletScanEvent::scan_cancelled(reason, final_statistics, partial_completion);
```

#### Event Variants

Each event variant contains rich structured data:

**ScanStarted**
- `config: ScanConfig` - Scan configuration parameters
- `block_range: (u64, u64)` - Start and end block heights  
- `wallet_context: String` - Wallet identifier or context

**BlockProcessed**
- `height: u64` - Block height
- `hash: String` - Block hash
- `timestamp: u64` - Block timestamp
- `processing_duration: Duration` - Time to process this block
- `outputs_count: usize` - Number of outputs in the block

**OutputFound**
- `output_data: OutputData` - Complete output information (commitment, range proof, value, etc.)
- `block_info: BlockInfo` - Block details where output was found
- `address_info: AddressInfo` - Address and derivation information
- `transaction_data: TransactionData` - Transaction details for wallet storage

**SpentOutputFound**
- `spent_output_data: SpentOutputData` - Details about the spent output
- `spending_block_info: BlockInfo` - Block where spending occurred
- `original_output_info: OutputData` - Original output that was spent
- `spending_transaction_data: TransactionData` - Spending transaction details

**ScanProgress**
- `current_block: u64` - Current block being processed
- `total_blocks: u64` - Total blocks to process
- `percentage: f64` - Completion percentage (0.0 to 100.0)
- `speed_blocks_per_second: f64` - Processing speed
- `estimated_time_remaining: Option<Duration>` - ETA to completion

**ScanCompleted**
- `final_statistics: HashMap<String, u64>` - Summary statistics
- `success: bool` - Whether scan completed successfully
- `total_duration: Duration` - Total time taken

**ScanError**
- `error_message: String` - Human-readable error description
- `error_code: Option<String>` - Machine-readable error code
- `block_height: Option<u64>` - Block where error occurred (if applicable)
- `retry_info: Option<String>` - Retry information or suggestions
- `is_recoverable: bool` - Whether the error can be retried

**ScanCancelled**
- `reason: String` - Cancellation reason
- `final_statistics: HashMap<String, u64>` - Partial statistics
- `partial_completion: Option<f64>` - Percentage completed before cancellation

#### Supporting Data Structures

**OutputData**
```rust
pub struct OutputData {
    pub commitment: String,           // Output commitment value
    pub range_proof: String,          // Range proof data
    pub encrypted_value: Option<Vec<u8>>, // Encrypted value (if available)
    pub script: Option<String>,       // Output script (if any)
    pub features: u32,                // Output features flags
    pub maturity_height: Option<u64>, // Maturity height (if applicable)
    pub amount: Option<u64>,          // Decrypted amount value
    pub is_mine: bool,                // Whether this belongs to our wallet
}
```

**SpentOutputData**
```rust
pub struct SpentOutputData {
    pub spent_commitment: String,        // Commitment of spent output
    pub spent_output_hash: Option<String>, // Output hash (if available)
    pub input_index: usize,              // Index in spending transaction
    pub spent_amount: Option<u64>,       // Amount that was spent
    pub original_block_height: u64,      // Block where output was found
    pub spending_block_height: u64,      // Block where output was spent
    pub match_method: String,            // "output_hash" or "commitment"
}
```

**BlockInfo**
```rust
pub struct BlockInfo {
    pub height: u64,                     // Block height
    pub hash: String,                    // Block hash
    pub timestamp: u64,                  // Block timestamp
    pub transaction_index: Option<usize>, // Transaction index in block
    pub output_index: usize,             // Output index in transaction
    pub difficulty: Option<u64>,         // Block difficulty
}
```

**AddressInfo**
```rust
pub struct AddressInfo {
    pub address: String,                 // Wallet address
    pub address_type: String,            // Address type (stealth, standard, script)
    pub network: String,                 // Network (mainnet, testnet, localnet)
    pub derivation_path: Option<String>, // Derivation path
    pub public_spend_key: Option<String>, // Public spend key
    pub view_key: Option<String>,        // View key
}
```

**TransactionData**
```rust
pub struct TransactionData {
    pub value: u64,                      // Transaction value in microTari
    pub status: String,                  // Transaction status (Unspent, Spent, Pending)
    pub direction: String,               // Direction (Inbound, Outbound)
    pub output_index: Option<usize>,     // Output index in transaction
    pub payment_id: Option<String>,      // Payment ID for tracking
    pub fee: Option<u64>,                // Transaction fee (if outbound)
    pub kernel_excess: Option<String>,   // Kernel excess
    pub timestamp: u64,                  // Transaction timestamp
}
```

### Event Dispatcher

The `EventDispatcher` manages event delivery to registered listeners:

```rust
use lightweight_wallet_libs::events::EventDispatcher;

// Create dispatcher
let mut dispatcher = EventDispatcher::new();

// With debugging enabled
let mut dispatcher = EventDispatcher::new_with_debug();

// With listener limits
let mut dispatcher = EventDispatcher::new_with_limit(10);

// Register listeners
dispatcher.register(Box::new(your_listener))?;

// Dispatch events
dispatcher.dispatch(event).await;
```

### Event Listeners

Listeners implement the `EventListener` trait to handle events asynchronously:

```rust
use async_trait::async_trait;
use lightweight_wallet_libs::events::{EventListener, SharedEvent};

struct MyCustomListener;

#[async_trait]
impl EventListener for MyCustomListener {
    async fn handle_event(&mut self, event: &SharedEvent) 
        -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match &**event {
            WalletScanEvent::OutputFound { output_data, .. } => {
                // Handle output found event
                println!("Output found: {:?}", output_data);
            }
            WalletScanEvent::SpentOutputFound { spent_transaction, match_method, .. } => {
                // Handle spent output event
                println!("Output spent: {} (method: {})", 
                    hex::encode(spent_transaction.commitment.as_bytes()), match_method);
            }
            WalletScanEvent::ScanProgress { percentage, .. } => {
                // Handle progress updates
                println!("Progress: {:.1}%", percentage);
            }
            _ => {} // Handle other events as needed
        }
        Ok(())
    }
    
    fn name(&self) -> &'static str {
        "MyCustomListener"
    }
}
```

## Integration Patterns

### Pattern 1: Scanner Integration

For modules that perform long-running operations with progress tracking:

```rust
use lightweight_wallet_libs::scanning::event_emitter::ScanEventEmitter;

struct MyScanner {
    event_emitter: ScanEventEmitter,
}

impl MyScanner {
    pub fn new(dispatcher: EventDispatcher) -> Self {
        Self {
            event_emitter: ScanEventEmitter::new(dispatcher, "my_scanner".to_string())
                .with_fire_and_forget(true), // Optimal performance with reliable delivery
        }
    }
    
    pub async fn perform_scan(&mut self, config: ScanConfig) -> Result<(), MyError> {
        // Emit scan started event
        self.event_emitter.emit_scan_started(&config, (0, 1000), "wallet_id".to_string()).await?;
        
        for block_height in 0..1000 {
            // Process block
            let outputs = self.process_block(block_height).await?;
            
            // Emit block processed event
            self.event_emitter.emit_block_processed(
                block_height,
                block_hash,
                timestamp,
                processing_duration,
                outputs.len()
            ).await?;
            
            // Emit output found events
            for output in outputs {
                self.event_emitter.emit_output_found(output_data, block_info, address_info).await?;
            }
            
            // Emit spent output events
            for spent_info in spent_outputs {
                self.event_emitter.emit_spent_output_found(
                    &spent_info.spent_transaction,
                    &block,
                    spent_info.input_index,
                    &spent_info.match_method,
                    &original_block_info,
                ).await?;
            }
            
            // Emit progress updates
            let progress = (block_height as f64 / 1000.0) * 100.0;
            self.event_emitter.emit_scan_progress(
                block_height,
                1000,
                progress,
                speed,
                estimated_time_remaining
            ).await?;
        }
        
        // Emit completion event
        self.event_emitter.emit_scan_completed(true, final_stats, wallet_state).await?;
        Ok(())
    }
}
```

### Pattern 2: Direct Dispatcher Usage

For simpler integrations or one-off events:

```rust
use lightweight_wallet_libs::events::{EventDispatcher, WalletScanEvent};

async fn process_transaction(
    dispatcher: &mut EventDispatcher,
    transaction: Transaction
) -> Result<(), ProcessError> {
    // Process the transaction
    let result = validate_transaction(&transaction)?;
    
    // Emit relevant events
    if result.is_valid {
        let event = WalletScanEvent::output_found(
            result.output_data,
            result.block_info,
            result.address_info
        );
        dispatcher.dispatch(event).await;
    }
    
    Ok(())
}
```

### Pattern 3: Builder Pattern Integration

For components that need flexible event configuration:

```rust
use lightweight_wallet_libs::events::EventDispatcher;

pub struct WalletBuilder {
    dispatcher: Option<EventDispatcher>,
    // other fields...
}

impl WalletBuilder {
    pub fn with_event_dispatcher(mut self, dispatcher: EventDispatcher) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }
    
    pub fn with_default_events(mut self) -> Self {
        let mut dispatcher = EventDispatcher::new();
        
        // Add default listeners
        let progress_listener = ProgressTrackingListener::builder()
            .console_preset()
            .build();
        dispatcher.register(Box::new(progress_listener)).unwrap();
        
        self.dispatcher = Some(dispatcher);
        self
    }
    
    pub fn build(self) -> Result<Wallet, BuildError> {
        let dispatcher = self.dispatcher.unwrap_or_else(|| EventDispatcher::new());
        
        Ok(Wallet {
            dispatcher,
            // other fields...
        })
    }
}
```

## Built-in Listeners

### DatabaseStorageListener

Replaces direct database storage backends and handles both inbound and outbound transactions:

```rust
use lightweight_wallet_libs::events::listeners::DatabaseStorageListener;

// Basic usage - automatically handles output_found and spent_output_found events
let db_listener = DatabaseStorageListener::new("wallet.db").await?;

// Builder pattern with custom configuration
let db_listener = DatabaseStorageListener::builder()
    .database_path("wallet.db")
    .batch_size(100)
    .enable_wal_mode(true)
    .timeout_seconds(30)
    .build().await?;

// Preset configurations
let dev_db = DatabaseStorageListener::builder()
    .development_preset()
    .database_path("debug.db")
    .build().await?;

let prod_db = DatabaseStorageListener::builder()
    .production_preset()
    .database_path("production.db")
    .build().await?;
```

**Key Features:**
- **Inbound transactions**: Created when `OutputFound` events are received
- **Outbound transactions**: Created when `SpentOutputFound` events are received
- **Transaction directions**: Automatically sets `Inbound` for outputs, `Outbound` for spent outputs
- **Spent flags**: Marks original transactions as spent when spending is detected
- **Conflict resolution**: Uses `INSERT OR REPLACE` to handle duplicate outputs gracefully

### ProgressTrackingListener

Replaces callback-based progress tracking:

```rust
use lightweight_wallet_libs::events::listeners::ProgressTrackingListener;

// With custom callbacks
let progress_listener = ProgressTrackingListener::new()
    .with_progress_callback(|info| {
        println!("Scan progress: {:.1}% ({} outputs found)", 
            info.progress_percent, info.outputs_found);
    })
    .with_completion_callback(|stats| {
        println!("Scan completed! Total outputs: {}", stats.total_outputs);
    });

// Builder pattern
let progress_listener = ProgressTrackingListener::builder()
    .frequency(50) // Update every 50 blocks
    .verbose(true)
    .with_progress_callback(progress_handler)
    .build();

// Preset configurations
let console_progress = ProgressTrackingListener::builder()
    .console_preset()
    .build();

let silent_progress = ProgressTrackingListener::builder()
    .silent_preset()
    .with_progress_callback(log_progress)
    .build();
```

### ConsoleLoggingListener

Provides structured console output for development and debugging:

```rust
use lightweight_wallet_libs::events::listeners::{ConsoleLoggingListener, LogLevel};

// Basic usage
let console_listener = ConsoleLoggingListener::new();

// Custom configuration
let console_listener = ConsoleLoggingListener::builder()
    .log_level(LogLevel::Verbose)
    .with_colors(true)
    .with_timestamps(true)
    .with_prefix("[WALLET]".to_string())
    .build();

// Preset configurations
let dev_logger = ConsoleLoggingListener::builder()
    .debug_preset()
    .build();

let ci_logger = ConsoleLoggingListener::builder()
    .ci_preset()
    .build();
```

### AsciiProgressBarListener

Provides visual progress indication for command-line interfaces:

```rust
use lightweight_wallet_libs::events::listeners::AsciiProgressBarListener;

// Basic usage
let progress_bar = AsciiProgressBarListener::new();

// Custom configuration
let progress_bar = AsciiProgressBarListener::builder()
    .bar_width(50)
    .update_interval_ms(100)
    .show_eta(true)
    .show_speed(true)
    .build();

// Preset configurations
let detailed_bar = AsciiProgressBarListener::builder()
    .detailed_preset()
    .build();

let quiet_bar = AsciiProgressBarListener::builder()
    .quiet_preset()
    .build();
```

## Creating Custom Listeners

### Basic Custom Listener

```rust
use async_trait::async_trait;
use lightweight_wallet_libs::events::{EventListener, SharedEvent, WalletScanEvent};
use std::collections::HashMap;

pub struct MetricsListener {
    event_counts: HashMap<String, usize>,
    total_outputs: usize,
    total_blocks: usize,
}

impl MetricsListener {
    pub fn new() -> Self {
        Self {
            event_counts: HashMap::new(),
            total_outputs: 0,
            total_blocks: 0,
        }
    }
    
    pub fn get_metrics(&self) -> &HashMap<String, usize> {
        &self.event_counts
    }
}

#[async_trait]
impl EventListener for MetricsListener {
    async fn handle_event(&mut self, event: &SharedEvent) 
        -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        
        let event_type = match &**event {
            WalletScanEvent::ScanStarted { .. } => "scan_started",
            WalletScanEvent::BlockProcessed { .. } => {
                self.total_blocks += 1;
                "block_processed"
            },
            WalletScanEvent::OutputFound { .. } => {
                self.total_outputs += 1;
                "output_found"
            },
            WalletScanEvent::SpentOutputFound { .. } => "spent_output_found",
            WalletScanEvent::ScanProgress { .. } => "scan_progress",
            WalletScanEvent::ScanCompleted { .. } => "scan_completed",
            WalletScanEvent::ScanError { .. } => "scan_error",
            WalletScanEvent::ScanCancelled { .. } => "scan_cancelled",
        };
        
        *self.event_counts.entry(event_type.to_string()).or_insert(0) += 1;
        Ok(())
    }
    
    fn name(&self) -> &'static str {
        "MetricsListener"
    }
}
```

### Advanced Custom Listener with Builder

```rust
use async_trait::async_trait;
use lightweight_wallet_libs::events::{EventListener, SharedEvent, WalletScanEvent};
use std::sync::mpsc;

pub struct WebhookListener {
    webhook_url: String,
    client: reqwest::Client,
    event_filter: Vec<String>,
    sender: Option<mpsc::Sender<String>>,
}

pub struct WebhookListenerBuilder {
    webhook_url: Option<String>,
    event_filter: Vec<String>,
    timeout_seconds: u64,
    enable_async_channel: bool,
}

impl WebhookListenerBuilder {
    pub fn new() -> Self {
        Self {
            webhook_url: None,
            event_filter: vec![],
            timeout_seconds: 30,
            enable_async_channel: false,
        }
    }
    
    pub fn webhook_url(mut self, url: String) -> Self {
        self.webhook_url = Some(url);
        self
    }
    
    pub fn filter_events(mut self, event_types: Vec<String>) -> Self {
        self.event_filter = event_types;
        self
    }
    
    pub fn timeout_seconds(mut self, timeout: u64) -> Self {
        self.timeout_seconds = timeout;
        self
    }
    
    pub fn build(self) -> Result<WebhookListener, String> {
        let webhook_url = self.webhook_url.ok_or("webhook_url is required")?;
        
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(self.timeout_seconds))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
        
        Ok(WebhookListener {
            webhook_url,
            client,
            event_filter: self.event_filter,
            sender: None,
        })
    }
}

impl WebhookListener {
    pub fn builder() -> WebhookListenerBuilder {
        WebhookListenerBuilder::new()
    }
}

#[async_trait]
impl EventListener for WebhookListener {
    async fn handle_event(&mut self, event: &SharedEvent) 
        -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        
        let event_type = self.get_event_type_name(event);
        
        // Apply event filter if configured
        if !self.event_filter.is_empty() && !self.event_filter.contains(&event_type) {
            return Ok(());
        }
        
        // Serialize event for webhook
        let payload = serde_json::json!({
            "event_type": event_type,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "data": event
        });
        
        // Send webhook (non-blocking)
        let response = self.client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(format!("Webhook failed with status: {}", response.status()).into());
        }
        
        Ok(())
    }
    
    fn name(&self) -> &'static str {
        "WebhookListener"
    }
}

impl WebhookListener {
    fn get_event_type_name(&self, event: &SharedEvent) -> String {
        match &**event {
            WalletScanEvent::ScanStarted { .. } => "scan_started".to_string(),
            WalletScanEvent::BlockProcessed { .. } => "block_processed".to_string(),
            WalletScanEvent::OutputFound { .. } => "output_found".to_string(),
            WalletScanEvent::SpentOutputFound { .. } => "spent_output_found".to_string(),
            WalletScanEvent::ScanProgress { .. } => "scan_progress".to_string(),
            WalletScanEvent::ScanCompleted { .. } => "scan_completed".to_string(),
            WalletScanEvent::ScanError { .. } => "scan_error".to_string(),
            WalletScanEvent::ScanCancelled { .. } => "scan_cancelled".to_string(),
        }
    }
}
```

## Testing with Events

### Mock Listener for Testing

```rust
use lightweight_wallet_libs::events::listeners::MockEventListener;
use lightweight_wallet_libs::events::{EventDispatcher, WalletScanEvent};

#[tokio::test]
async fn test_scan_operation() {
    let mut dispatcher = EventDispatcher::new();
    let mock_listener = MockEventListener::new();
    let captured_events = mock_listener.get_captured_events();
    
    dispatcher.register(Box::new(mock_listener)).unwrap();
    
    // Perform your scan operation
    let event = WalletScanEvent::scan_started(
        ScanConfig::default(),
        (0, 100),
        "test_wallet".to_string()
    );
    dispatcher.dispatch(event).await;
    
    // Assert on captured events
    let events = captured_events.lock().unwrap();
    assert_eq!(events.len(), 1);
    
    match &events[0] {
        WalletScanEvent::ScanStarted { wallet_id, .. } => {
            assert_eq!(wallet_id, "test_wallet");
        }
        _ => panic!("Expected ScanStarted event"),
    }
}
```

### Testing Event Patterns

```rust
use lightweight_wallet_libs::events::test_utils::{EventPattern, TestScenario};

#[tokio::test]
async fn test_complete_scan_flow() {
    let mut scenario = TestScenario::new();
    
    // Define expected event pattern
    let expected_pattern = vec![
        EventPattern::ScanStarted,
        EventPattern::BlockProcessed { count: 5 },
        EventPattern::OutputFound { min_count: 1 },
        EventPattern::ScanProgress { min_updates: 3 },
        EventPattern::ScanCompleted,
    ];
    
    scenario.expect_pattern(expected_pattern);
    
    // Run your scan operation
    perform_test_scan(&mut scenario.get_dispatcher()).await;
    
    // Verify the pattern was matched
    scenario.assert_pattern_matched().unwrap();
}
```

## Migration from Legacy Systems

### Replacing Progress Callbacks

**Before:**
```rust
async fn scan_with_progress<F>(
    progress_callback: F
) -> Result<ScanResult, ScanError>
where
    F: Fn(f64) + Send + Sync,
{
    for i in 0..100 {
        // scanning logic...
        progress_callback(i as f64);
    }
    Ok(ScanResult::default())
}
```

**After:**
```rust
async fn scan_with_events(
    dispatcher: &mut EventDispatcher
) -> Result<ScanResult, ScanError> {
    for i in 0..100 {
        // scanning logic...
        let event = WalletScanEvent::scan_progress(i, 100, i as f64, 1.0, None);
        dispatcher.dispatch(event).await;
    }
    Ok(ScanResult::default())
}
```

### Replacing Storage Backends

**Before:**
```rust
trait StorageBackend {
    fn store_output(&mut self, output: TransactionOutput) -> Result<(), StorageError>;
    fn store_transaction(&mut self, tx: Transaction) -> Result<(), StorageError>;
}

async fn scan_with_storage<S: StorageBackend>(
    storage: &mut S
) -> Result<(), ScanError> {
    // scanning logic...
    storage.store_output(output)?;
    storage.store_transaction(transaction)?;
    Ok(())
}
```

**After:**
```rust
async fn scan_with_events(
    dispatcher: &mut EventDispatcher
) -> Result<(), ScanError> {
    // scanning logic...
    let output_event = WalletScanEvent::output_found(output_data, block_info, address_info);
    dispatcher.dispatch(output_event).await;
    
    // Storage is handled by DatabaseStorageListener
    Ok(())
}
```

### Gradual Migration Strategy

1. **Phase 1**: Add event system alongside existing interfaces
```rust
pub struct Scanner {
    dispatcher: Option<EventDispatcher>,
}

impl Scanner {
    // Legacy method (deprecated)
    #[deprecated(note = "Use scan_with_events instead")]
    pub async fn scan_with_callbacks<F>(&self, callback: F) -> Result<(), ScanError>
    where F: Fn(f64) + Send + Sync {
        // Implementation that works with both old and new systems
        if let Some(dispatcher) = &self.dispatcher {
            self.scan_with_events(dispatcher).await
        } else {
            self.legacy_scan_with_callbacks(callback).await
        }
    }
    
    // New method
    pub async fn scan_with_events(&self, dispatcher: &mut EventDispatcher) -> Result<(), ScanError> {
        // New implementation using events
    }
}
```

2. **Phase 2**: Migrate callers to use event system
3. **Phase 3**: Remove legacy interfaces

## Performance Considerations

### Event Emission Performance

- **Fire-and-forget mode**: Use `ScanEventEmitter::with_fire_and_forget(true)` for optimal performance
  - **How it works**: Spawns background async tasks for event dispatch, allowing the scanner to continue immediately
  - **Database safety**: Events are still reliably delivered to all listeners, including `DatabaseStorageListener`
  - **Best practice**: Use `fire_and_forget(true)` by default for all scanning operations
- **Event filtering**: Implement `wants_event()` in listeners to skip unnecessary events
- **Batch processing**: Group related events where possible

```rust
// Optimal event emission (recommended for all scanning operations)
let emitter = ScanEventEmitter::new(dispatcher, "scanner".to_string())
    .with_fire_and_forget(true);  // Non-blocking performance with reliable delivery

// Synchronous event emission (only needed for special cases)
let sync_emitter = ScanEventEmitter::new(dispatcher, "scanner".to_string())
    .with_fire_and_forget(false);  // Blocks scanner until all listeners complete

// Efficient listener
impl EventListener for EfficientListener {
    fn wants_event(&self, event: &SharedEvent) -> bool {
        matches!(**event, 
            WalletScanEvent::OutputFound { .. } | 
            WalletScanEvent::SpentOutputFound { .. }
        )
    }
    
    async fn handle_event(&mut self, event: &SharedEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Only receives OutputFound and SpentOutputFound events
        Ok(())
    }
}
```

### Memory Management

The event system includes automatic memory management:

```rust
// Configure memory limits
let memory_config = MemoryConfig {
    max_trace_entries: 5000,
    max_stats_map_entries: 200,
    auto_cleanup_threshold: 6000,
    cleanup_retention_ratio: 0.8,
};

let dispatcher = EventDispatcher::new_with_memory_config(memory_config);

// Monitor memory usage
let usage = dispatcher.get_memory_usage();
println!("Trace entries: {}/{}", usage.trace_entries, usage.max_trace_entries);
```

### Cross-Platform Considerations

```rust
// Platform-specific logging
#[cfg(target_arch = "wasm32")]
fn log_message(message: &str) {
    web_sys::console::log_1(&message.into());
}

#[cfg(not(target_arch = "wasm32"))]
fn log_message(message: &str) {
    println!("{}", message);
}

// In your listener implementation
impl EventListener for CrossPlatformListener {
    async fn handle_event(&mut self, event: &SharedEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log_message(&format!("Received event: {:?}", event));
        Ok(())
    }
}
```

## Troubleshooting

### Common Issues

1. **Events not being received**
   - Check listener registration: `dispatcher.register(listener)?`
   - Verify `wants_event()` implementation returns `true`
   - Enable debug mode: `EventDispatcher::new_with_debug()`

2. **Spent outputs not being detected**
   - Verify the scanner is loading existing wallet state from the database
   - Check that commitment-based matching is working as fallback to output hash matching
   - Verify that wallet transactions have proper commitment values
   - Ensure the scanner binary is using database storage (not memory-only mode)

3. **Database inconsistencies**
   - Ensure `DatabaseStorageListener` is registered before scanning
   - Check for UNIQUE constraint errors (should be handled automatically with `INSERT OR REPLACE`)
   - Verify that the database file has proper write permissions

4. **Performance issues**
   - Use fire-and-forget mode for non-critical events (progress updates)
   - Implement event filtering in listeners
   - Monitor memory usage with `get_memory_usage()`

5. **Cross-platform compilation errors**
   - Ensure `async_trait` is used for all EventListener implementations
   - Use platform-specific logging (web_sys vs println!)
   - Check feature flags for platform-specific dependencies

### Debugging Tools

```rust
// Enable debug mode
let mut dispatcher = EventDispatcher::new_with_debug();

// Get debug information
let stats = dispatcher.get_stats();
println!("Events dispatched: {}", stats.total_events_dispatched);
println!("Listener errors: {}", stats.total_listener_errors);

// Export traces for analysis
let traces_json = dispatcher.export_traces_json()?;
std::fs::write("event_traces.json", traces_json)?;

// Get formatted summary
println!("{}", dispatcher.get_debug_summary());
```

### Performance Monitoring

```rust
use lightweight_wallet_libs::events::test_utils::PerformanceAssertion;

#[tokio::test]
async fn test_event_performance() {
    let mut dispatcher = EventDispatcher::new();
    
    let perf_assertion = PerformanceAssertion::new()
        .max_avg_dispatch_time(Duration::from_millis(10))
        .max_total_time(Duration::from_secs(5))
        .min_throughput(1000); // events per second
    
    // Perform operations
    for i in 0..1000 {
        let event = WalletScanEvent::scan_progress(i, 1000, i as f64, 1.0, None);
        dispatcher.dispatch(event).await;
    }
    
    // Assert performance requirements
    perf_assertion.assert_performance(&dispatcher)?;
}
```

## Recent Fixes and Improvements

### Spent Output Detection (Fixed)

A critical issue was resolved where spent outputs were not being properly detected during blockchain scanning:

**Root Cause**: The `process_inputs_with_details` method was using an `else if` structure that prevented commitment-based matching when output hash values were present but didn't match wallet transactions.

**Symptoms**:
- Scanner summary showed spent outputs but database contained only inbound, unspent transactions
- `SpentOutputFound` events were never emitted
- All transactions appeared as unspent in the database

**Solution**: Changed the logic in [`src/data_structures/block.rs`](file:///src/data_structures/block.rs) to always attempt commitment matching as a fallback when output hash matching fails.

**Key Learning**: When using view-only scanning, wallet transactions have `output_hash=None` while GRPC inputs have actual output hash values, requiring commitment-based matching as a fallback.

### Fire-and-Forget Mode Performance

**Key Insight**: Fire-and-forget mode provides optimal performance while maintaining data integrity:

```rust
// Optimal: Use fire-and-forget for all scanning operations
let emitter = ScanEventEmitter::new(dispatcher, "scanner".to_string())
    .with_fire_and_forget(true);

// How it works:
// 1. Scanner emits event and continues immediately (non-blocking)
// 2. Background async task delivers event to all listeners
// 3. DatabaseStorageListener processes event synchronously
// 4. Database updates are reliably persisted
```

**Benefits**:
- **Performance**: Scanner doesn't wait for database I/O
- **Reliability**: Events are guaranteed to reach all listeners  
- **Consistency**: Database operations are still atomic within each listener
- **Scalability**: Multiple events can be processed concurrently

This guide provides comprehensive documentation for adopting the event system across the codebase. For specific implementation questions, refer to the module documentation in `src/events/` or examine the built-in listeners as examples.
