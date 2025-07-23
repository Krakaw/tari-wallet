# Scanner Binary Business Logic Analysis

## Overview

This document provides a comprehensive analysis of all business logic components found in `src/bin/scanner.rs` that need to be extracted into library components as part of Task 3.0 (Extract Business Logic from CLI Scanner).

## Business Logic Components Identified

### 1. Command-Line Interface and Configuration

**Current Location:** `CliArgs` struct and argument parsing
**Files:** Lines 148-226
**Business Logic:**
- Argument validation (seed phrase vs view key mutual exclusion)
- Storage mode determination (memory-only vs database based on key presence)
- Scan range configuration (from-block, to-block, specific blocks)
- Output format selection (JSON, Summary, Detailed)
- Progress reporting configuration

**Proposed Library Location:** `ScannerEngine::initialize_configuration()`

### 2. Wallet Creation and Key Management

**Current Location:** Main function lines 2588-2614, `ScanContext` implementation
**Files:** Lines 1173-1230, 2588-2614
**Business Logic:**
- Seed phrase to wallet conversion (`Wallet::new_from_seed_phrase`)
- View key parsing and validation 
- Entropy derivation from seed phrases
- Key derivation for encryption/decryption
- Wallet birthday determination
- Scan context creation from wallets or view keys

**Proposed Library Location:** `ScannerEngine::initialize_wallet()`

### 3. Database Storage and Wallet Management

**Current Location:** `ScannerStorage` implementation, wallet selection logic
**Files:** Lines 329-720, 501-650
**Business Logic:**
- Database vs memory-only storage selection
- Wallet creation, storage, and selection
- Interactive wallet selection prompts
- Background writer service management
- Transaction and output persistence
- Batch processing for performance optimization

**Proposed Library Location:** Storage abstraction layer (already partially completed in Task 2.0)

### 4. Blockchain Connection and Network Configuration

**Current Location:** Main function lines 2616-2646
**Files:** Lines 2616-2646
**Business Logic:**
- GRPC scanner initialization and configuration
- Base node connection establishment
- Network timeout configuration
- Blockchain tip information retrieval
- Connection error handling and user feedback

**Proposed Library Location:** `ScannerEngine::initialize_connection()`

### 5. Scan Range Calculation and Configuration

**Current Location:** `CliScanConfig`, scan range logic in main function
**Files:** Lines 231-284, 1820-1856, 2708-2715
**Business Logic:**
- From-block determination (wallet birthday, explicit, resume from database)
- To-block calculation (tip, explicit, range)
- Specific block list handling
- Automatic resume functionality for database wallets
- Batch size and progress frequency configuration

**Proposed Library Location:** `ScannerEngine::configure_scan_range()`

### 6. Core Blockchain Scanning Logic

**Current Location:** `scan_wallet_across_blocks_with_cancellation` function
**Files:** Lines 1811-2150
**Business Logic:**
- Block batch processing with configurable batch sizes
- Block fetching via GRPC with error handling
- Transaction output processing (finding received outputs)
- Transaction input processing (finding spent outputs)
- Wallet state maintenance and updates
- Cancellation handling during scanning
- Progress tracking and reporting

**Proposed Library Location:** `ScannerEngine::scan_blocks()` and `ScannerEngine::scan_range()`

### 7. Transaction Processing and Wallet State Management

**Current Location:** Block processing loops, wallet state updates
**Files:** Lines 1945-2100
**Business Logic:**
- Output decryption and validation
- Input processing for spent detection
- Wallet state transaction addition
- Balance calculations and running totals
- Transaction status tracking (spent/unspent, mature/immature)
- Commitment-based transaction matching

**Proposed Library Location:** `ScannerEngine::process_block()` and wallet state management

### 8. Storage Operations and Persistence

**Current Location:** Database saving operations within scanning loop
**Files:** Lines 1965-2100, storage backend methods
**Business Logic:**
- Incremental transaction saving during scanning
- Batch spent output marking
- UTXO output extraction and storage
- Wallet scanned block updates
- Performance-optimized batch operations
- Memory management for large scans

**Proposed Library Location:** Already implemented in Task 2.0's storage abstraction layer

### 9. Error Handling and Recovery

**Current Location:** `handle_scan_error` function, error handling throughout
**Files:** Lines 1325-1380, error handling throughout main scanning loop
**Business Logic:**
- Interactive error recovery (Continue/Skip/Abort)
- Resume command generation for failed scans
- GRPC error handling and retry logic
- Block-specific error handling
- User-friendly error messages and suggestions

**Proposed Library Location:** `ScannerEngine::handle_scan_error()`

### 10. Progress Reporting and User Interface

**Current Location:** Progress bar display, result formatting functions
**Files:** Lines 1890-1898, 2851-2900
**Business Logic:**
- Real-time progress bar updates
- Batch-based progress reporting
- Transaction count and balance display
- Multiple output formats (JSON, Summary, Detailed)
- Scan statistics and completion reporting
- User-friendly status messages

**Proposed Library Location:** Progress reporting abstraction in library

### 11. Interruption Handling and Graceful Shutdown

**Current Location:** Ctrl+C handling, cancellation tokens
**Files:** Lines 2734-2756, cancellation checks throughout scanning
**Business Logic:**
- Signal handling for graceful interruption
- Cancellation token propagation
- Partial result preservation
- Resume command generation
- Background service shutdown
- Cleanup operations

**Proposed Library Location:** `ScannerEngine` with cancellation token support

### 12. Output Display and Result Formatting

**Current Location:** Display functions for different output formats
**Files:** Lines 2851-2900, various display functions
**Business Logic:**
- JSON result serialization
- Summary format with key statistics
- Detailed transaction activity display
- Balance and transaction count formatting
- Storage completion information display
- Database statistics reporting

**Proposed Library Location:** Output formatting abstraction layer

## Data Structures That Need to Be Library Components

### 1. Core Configuration Types
- `ScanConfiguration` (library equivalent of `CliScanConfig`)
- `WalletSource` enum (seed phrase, view key, database)
- `ScanRange` (from-block, to-block, specific blocks)

### 2. Scanning Context and State
- `ScanContext` (view key, entropy) - move to library
- `ScanResult` enum (Completed, Interrupted) - move to library
- `ScanProgress` tracking - create library version

### 3. Error Types
- `ScannerError` enum for scanner-specific errors
- `NetworkError` for connection issues
- `StorageError` for database issues (already partially done)

## CLI-Specific Logic to Remain

### 1. Argument Parsing
- Command-line argument definitions
- Help text and usage examples
- Argument validation and CLI-specific error messages

### 2. User Interaction
- Interactive prompts for wallet selection
- Terminal output formatting and colors
- Progress bar display (while delegating calculations to library)

### 3. Process Management
- Signal handling setup
- Exit code management
- Terminal-specific cleanup

## Proposed Library API Design

Based on this analysis, the library should provide a clean API like:

```rust
// High-level scanner engine
let mut engine = ScannerEngine::new()
    .with_configuration(config)
    .with_wallet_source(WalletSource::SeedPhrase(phrase))
    .with_storage_mode(StorageMode::MemoryOnly)
    .build()
    .await?;

// Initialize connection and wallet
engine.initialize().await?;

// Configure scan range
let scan_range = engine.configure_scan_range(from_block, to_block).await?;

// Execute scan with progress callback
let results = engine.scan_with_progress(scan_range, |progress| {
    // Progress callback for UI updates
}).await?;
```

## Implementation Priority

1. **High Priority:** Core scanning logic (blocks 6, 7) - most complex business logic
2. **High Priority:** Wallet initialization (block 2) - foundational for all operations  
3. **Medium Priority:** Configuration management (blocks 1, 5) - needed for clean API
4. **Medium Priority:** Error handling (block 9) - critical for robustness
5. **Low Priority:** Display logic (block 12) - can remain CLI-specific initially

## Next Steps

The next tasks (3.2-3.8) should focus on extracting these components in the order of their dependencies:

1. Start with wallet initialization and configuration (Tasks 3.2)
2. Move core scanning logic (Task 3.3) 
3. Extract progress reporting (Task 3.4)
4. Implement error handling (Task 3.5)
5. Refactor CLI to thin wrapper (Task 3.6)
6. Ensure backward compatibility (Task 3.7)
7. Add interruption handling (Task 3.8)
