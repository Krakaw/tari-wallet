# Product Requirements Document: Scanner Business Logic Library Extraction

## Introduction/Overview

Extract all business logic from `src/bin/scanner.rs` into the library to create a thin CLI wrapper around a comprehensive scanning library. This refactoring will enable clean reuse of scanner functionality across WASM implementations, other binaries, and external applications while maintaining high performance across all target architectures.

**Problem**: Currently, the scanner binary contains substantial business logic including wallet operations, storage management, blockchain scanning coordination, and background processing. This creates code duplication with WASM implementations and prevents clean reuse in other contexts.

**Goal**: Create a unified, high-performance library interface that abstracts scanner functionality while maintaining compatibility with existing CLI interfaces and enabling seamless integration across WASM, native binaries, and external applications.

## Goals

1. **Complete Business Logic Extraction**: Move all scanner business logic from `bin/scanner.rs` to library modules
2. **Unified API Design**: Create a clean, consistent interface that works across all target architectures (WASM, native)
3. **Performance Optimization**: Abstract architectural differences (background writers vs direct storage) while maintaining optimal performance
4. **Feature Flag Compatibility**: Support all feature combinations (`http`, `grpc`, `storage`) in the library
5. **Backward Compatibility**: Maintain existing CLI interface with minimal breaking changes
6. **Comprehensive Testing**: Ensure robust unit and integration test coverage for the new library components
7. **Code Reuse**: Enable scanner functionality reuse in WASM wallets, integration tests, and external applications

## User Stories

### Library Consumer (Developer)
- **As a developer**, I want to initialize a scanner programmatically so that I can integrate wallet scanning into my application
- **As a developer**, I want to configure scanning parameters (block ranges, batch sizes, storage options) so that I can optimize for my use case
- **As a developer**, I want to handle scan progress and results programmatically so that I can provide custom user experiences
- **As a developer**, I want to use the same scanning logic in both WASM and native contexts so that I maintain consistency

### CLI User (End User)
- **As a CLI user**, I want the scanner to work exactly as before so that my existing workflows are preserved
- **As a CLI user**, I want consistent performance and error handling so that my scanning experience remains reliable

### WASM Wallet Developer
- **As a WASM wallet developer**, I want to use the same scanning engine as the CLI so that I get consistent results
- **As a WASM wallet developer**, I want optimal performance in browser environments so that my wallet is responsive

### Integration Test Developer
- **As a test developer**, I want to test scanner functionality directly so that I can write comprehensive integration tests
- **As a test developer**, I want to mock storage and network layers so that I can test edge cases reliably

## Functional Requirements

### 1. Scanner Library Core (`src/scanning/scanner_engine.rs`)
1.1. The system must provide a `ScannerEngine` struct that encapsulates all scanning business logic
1.2. The system must support initialization with view keys, seed phrases, or database wallets
1.3. The system must handle wallet operations (creation, selection, loading) through a unified interface
1.4. The system must coordinate between HTTP and GRPC scanners based on feature flags
1.5. The system must manage progress reporting and error handling consistently

### 2. Storage Abstraction (`src/scanning/storage_manager.rs`)
2.1. The system must abstract storage operations behind a unified interface
2.2. The system must automatically choose between background writers (native) and direct storage (WASM)
2.3. The system must handle incremental transaction saving with minimal memory overhead
2.4. The system must support both database and memory-only storage modes
2.5. The system must provide efficient batch operations for spent output tracking

### 3. Configuration Management (`src/scanning/scan_configuration.rs`)
3.1. The system must provide a comprehensive configuration structure for all scan parameters
3.2. The system must validate configuration parameters and provide clear error messages
3.3. The system must support default values that work across different use cases
3.4. The system must handle feature flag dependencies automatically

### 4. Progress and Results (`src/scanning/scan_results.rs`)
4.1. The system must provide structured progress reporting for long-running scans
4.2. The system must return detailed scan results including block-specific and cumulative data
4.3. The system must support both streaming and batch result reporting
4.4. The system must handle error conditions gracefully with recovery information

### 5. CLI Wrapper Refactoring (`src/bin/scanner.rs`)
5.1. The CLI must become a thin wrapper that primarily handles argument parsing and output formatting
5.2. The CLI must delegate all business logic to the library components
5.3. The CLI must maintain backward compatibility with existing command-line interfaces
5.4. The CLI must preserve existing error messages and exit codes where possible

### 6. WASM Integration Enhancement (`src/wasm.rs`)
6.1. The WASM module must use the same core scanning engine as the CLI
6.2. The WASM module must provide async interfaces where appropriate for browser compatibility
6.3. The WASM module must handle memory management efficiently for large scans
6.4. The WASM module must maintain existing public interfaces for backward compatibility

### 7. Error Handling Enhancement
7.1. The system must use existing error types where applicable
7.2. The system must add new error types for library-specific conditions
7.3. The system must provide clear error context for debugging
7.4. The system must handle interruption (Ctrl+C) gracefully with resume capabilities

### 8. Testing Infrastructure
8.1. The system must include unit tests for all new library components
8.2. The system must include integration tests that verify end-to-end functionality
8.3. The system must support mocking of storage and network layers for testing
8.4. The system must maintain existing test coverage while adding new test scenarios

## Non-Goals (Out of Scope)

1. **Breaking Changes to Public APIs**: Will not modify existing WASM or major CLI interfaces without compelling necessity
2. **New Scanning Algorithms**: Will not implement new consensus or cryptographic logic - only refactor existing code
3. **Performance Regressions**: Will not accept any performance degradation in favor of abstraction
4. **New Feature Flags**: Will not add new feature flags unless absolutely necessary for the refactoring
5. **Database Schema Changes**: Will not modify existing storage schemas or migration logic
6. **Network Protocol Changes**: Will not modify GRPC or HTTP communication protocols

## Design Considerations

### API Structure
```rust
// Core scanning engine
pub struct ScannerEngine {
    storage_manager: StorageManager,
    scan_config: ScanConfiguration,
    wallet_context: Option<WalletContext>,
}

impl ScannerEngine {
    pub fn new(config: ScanConfiguration) -> Result<Self, ScannerError>;
    pub async fn initialize_wallet(&mut self, wallet_source: WalletSource) -> Result<(), ScannerError>;
    pub async fn scan_range(&mut self, from_block: u64, to_block: u64) -> Result<ScanResults, ScannerError>;
    pub async fn scan_blocks(&mut self, block_heights: Vec<u64>) -> Result<ScanResults, ScannerError>;
    pub fn get_progress(&self) -> ScanProgress;
    pub fn get_current_state(&self) -> WalletState;
}

// Configuration structure
pub struct ScanConfiguration {
    pub base_url: String,
    pub batch_size: usize,
    pub progress_frequency: usize,
    pub storage_config: StorageConfiguration,
    pub output_format: OutputFormat,
    pub feature_flags: FeatureFlags,
}

// Wallet initialization options
pub enum WalletSource {
    SeedPhrase(String),
    ViewKey(String),
    Database { path: String, wallet_name: Option<String> },
    Memory { view_key: PrivateKey, entropy: [u8; 16] },
}
```

### Storage Architecture
- Maintain existing `BackgroundWriter` for native performance
- Use direct storage calls for WASM compatibility
- Abstract the choice behind `StorageManager` interface
- Preserve all existing storage functionality and error handling

### Feature Flag Handling
- Library supports `http`, `grpc`, and `storage` features
- Scanner binary compiles with `grpc` and `storage` only
- Runtime feature detection for optimal code paths
- Conditional compilation for target-specific optimizations

## Technical Considerations

### Performance Requirements
- **Memory Usage**: Must handle large scans (100K+ blocks) without memory leaks
- **CPU Efficiency**: Must maintain existing batch processing performance
- **Storage I/O**: Must not increase database operations overhead
- **Network Efficiency**: Must preserve existing GRPC/HTTP optimization patterns

### Architecture Dependencies
- Must work with existing `tari_crypto` integration
- Must maintain compatibility with current storage schema
- Must preserve existing validation and extraction logic
- Must support both `rayon` (native) and single-threaded (WASM) processing

### Cross-Platform Considerations
- WASM compatibility for all core scanning logic
- Native optimizations for background processing and parallel operations
- Feature flag conditional compilation for target-specific code
- Consistent error handling across platforms

## Success Metrics

### Code Quality Metrics
- **Code Duplication**: Reduce scanner-related duplication from current 3.7% to <1%
- **Binary Size**: Scanner binary should be <50 lines of business logic after refactoring
- **Test Coverage**: Maintain >90% test coverage across all new library components
- **API Consistency**: Single unified interface for all scanning operations

### Performance Metrics
- **Scan Speed**: No more than 5% performance regression for large scans
- **Memory Usage**: No increase in peak memory usage during scanning
- **Database I/O**: No increase in database operation count
- **Binary Size**: Minimal increase in compiled library size

### Compatibility Metrics
- **CLI Interface**: 100% backward compatibility for existing command-line usage
- **WASM Interface**: 100% backward compatibility for existing WASM public APIs
- **Feature Flags**: All existing feature flag combinations must continue working
- **Error Messages**: Preserve existing error messages where functionally equivalent

## Open Questions

### Implementation Priorities
1. **Phase 1**: Extract core scanning logic and configuration management
2. **Phase 2**: Implement storage abstraction and manager
3. **Phase 3**: Refactor CLI to use library and update WASM integration
4. **Phase 4**: Add comprehensive testing and documentation

### API Evolution
- Should the library provide both sync and async versions of key methods?
- How should we handle progress callbacks for different consumer types?
- What level of configuration granularity should be exposed in the public API?

### Testing Strategy
- Should we create a mock blockchain scanner for deterministic testing?
- How should we test the background writer abstraction across architectures?
- What integration test scenarios are most critical for validation?

### Performance Optimization
- Should we implement connection pooling for database operations in the library?
- How can we optimize memory usage during large scans while maintaining flexibility?
- What caching strategies should be implemented at the library level?
