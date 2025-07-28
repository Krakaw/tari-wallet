# Task List: Scanner Library Refactoring

Based on the PRD requirements, this task list guides the implementation of extracting scanner functionality from a 2,895-line binary into reusable library components.

## Relevant Files

- `src/scanning/mod.rs` - Main module file that exports all scanning functionality to the public API
- `src/scanning/scan_config.rs` - Configuration structures (ScanConfig, OutputFormat, ScanContext) 
- `src/scanning/storage_manager.rs` - Storage abstraction layer supporting memory and database modes
- `src/scanning/background_writer.rs` - Async database operations and command queue system
- `src/scanning/wallet_scanner.rs` - Core scanning implementation and main public API (WalletScanner)
- `src/scanning/progress.rs` - Progress tracking utilities and display functions
- `src/bin/scanner.rs` - Refactored binary containing only CLI parsing and user interaction (~200 lines)
- `src/lib.rs` - Updated to export the new scanning module
- `dependency_mapping_analysis.md` - Comprehensive analysis of dependency split between library and binary
- `src/scanning/tests/mod.rs` - Test module organization for scanning components
- `src/scanning/tests/test_scan_config.rs` - Unit tests for configuration structures
- `src/scanning/tests/test_storage_manager.rs` - Unit tests for storage manager functionality
- `src/scanning/tests/test_background_writer.rs` - Unit tests for background writer system
- `src/scanning/tests/test_wallet_scanner.rs` - Unit tests for main scanning API
- `src/scanning/tests/test_progress.rs` - Unit tests for progress tracking
- `tests/integration_scanner.rs` - Integration tests for end-to-end scanning workflows

### Notes

- All library components must maintain feature flag compatibility (`grpc`, `storage`, `wasm32`)
- Use `cargo test --features grpc-storage` for comprehensive testing of scanning functionality
- Background writer system requires async/await patterns throughout
- Sensitive data (private keys, seed phrases) must be properly zeroized
- Progress tracking should be optional and configurable
- Always run `cargo fmt --all` after each step.
- Always run `cargo check --features grpc-storage` after each step
- **NB** NEVER add TODO placeholders, either add the code, or update the task list to add the code.

## Tasks

- [x] 1.0 Set up library module structure and dependencies
  - [x] 1.1 Create `src/scanning/` directory structure with all required module files
  - [x] 1.2 Add empty module files: `mod.rs`, `scan_config.rs`, `storage_manager.rs`, `background_writer.rs`, `wallet_scanner.rs`, `progress.rs`
  - [x] 1.3 Add basic module declarations to `src/scanning/mod.rs`
  - [x] 1.4 Update `src/lib.rs` to include `pub mod scanning;`
  - [x] 1.5 Analyze current scanner dependencies and create dependency mapping for library vs binary components
  - [x] 1.6 Verify feature flag compilation works with new module structure

- [x] 2.0 Extract and migrate configuration components
  - [x] 2.1 Move `ScanConfig` struct from `src/bin/scanner.rs` to `src/scanning/scan_config.rs`
  - [x] 2.2 Move `OutputFormat` enum and its `from_str` implementation to `src/scanning/scan_config.rs`
  - [x] 2.3 Move `ScanContext` struct (containing view key and entropy) to `src/scanning/scan_config.rs`
  - [x] 2.4 Add necessary imports and make all structures public with proper documentation
  - [x] 2.5 Update `src/scanning/mod.rs` to re-export configuration types
  - [x] 2.6 Update imports in `src/bin/scanner.rs` to use library configuration types

- [x] 3.0 Extract storage management and background writer systems
  - [x] 3.1 Move `BackgroundWriterCommand` enum to `src/scanning/background_writer.rs` with proper feature flags
  - [x] 3.2 Move `BackgroundWriter` struct and implementation to `src/scanning/background_writer.rs`
  - [x] 3.3 Move background writer loop function and async operations to `src/scanning/background_writer.rs`
  - [x] 3.4 Move `ScannerStorage` struct to `src/scanning/storage_manager.rs`
  - [x] 3.5 Move core storage methods: `new_memory()`, `new_with_database()`, `start_background_writer()`, `stop_background_writer()`
  - [x] 3.6 Move wallet management methods: `list_wallets()`, `select_or_create_wallet()`, `load_scan_context_from_wallet()`, `get_wallet_birthday()`
  - [x] 3.7 Move transaction storage methods: `save_transactions_incremental()`, `save_outputs()`, `update_wallet_scanned_block()`, `mark_transaction_spent()`
  - [x] 3.8 Ensure all storage methods maintain architecture-specific implementations (WASM32 vs non-WASM32)
  - [x] 3.9 Remove direct user interaction from library methods, replace with error returns for binary to handle

- [ ] 4.0 Extract core scanning logic and create public API
  - [x] 4.1 Move progress display functions to `src/scanning/progress.rs` and create `ProgressTracker` struct
  - [x] 4.2 Move `extract_utxo_outputs_from_wallet_state` which uses the `StoredOutput` in `src/storage/storage_trait.rs` put it in the most logical place
  - [ ] 4.3 Move wallet creation functions (`create_wallet_from_seed_phrase`, `create_wallet_from_view_key`) to `src/scanning/wallet_scanner.rs`
  - [ ] 4.4 Move main scanning loop function to `src/scanning/wallet_scanner.rs` as `WalletScanner::scan()` method
  - [ ] 4.5 Extract helper functions for block processing, transaction extraction, and balance calculation
  - [ ] 4.6 Move result processing and output functions, creating `ScanResult` struct for scan outcomes
  - [ ] 4.7 Design and implement `WalletScanner` struct with methods: `new()`, `scan()`, `with_progress_callback()`
  - [ ] 4.8 Create clean public API with builder pattern support and comprehensive error handling
  - [ ] 4.9 Ensure all scanning logic maintains async/await compatibility and proper zeroization

- [ ] 5.0 Refactor binary to use library components
  - [ ] 5.1 Strip `src/bin/scanner.rs` down to CLI-only concerns: clap parsing, user interaction, output formatting
  - [ ] 5.2 Update imports to use library components: `use lightweight_wallet_libs::scanning::*`
  - [ ] 5.3 Convert CLI args to `ScanConfig` and integrate with `WalletScanner::new()`
  - [ ] 5.4 Replace removed functionality with library API calls, maintaining all CLI features
  - [ ] 5.5 Preserve user experience: identical progress display, error messages, and output formats
  - [ ] 5.6 Handle wallet selection prompts in binary while using library methods for data operations
  - [ ] 5.7 Ensure resume functionality and all CLI arguments work identically to original implementation
  - [ ] 5.8 Verify binary is reduced to <300 lines while maintaining full functionality

- [ ] 6.0 Implement comprehensive testing framework
  - [ ] 6.1 Create `src/scanning/tests/` directory and test module organization
  - [ ] 6.2 Write unit tests for `scan_config.rs`: configuration validation, enum parsing, structure creation
  - [ ] 6.3 Write unit tests for `storage_manager.rs`: memory vs database modes, wallet operations, transaction storage
  - [ ] 6.4 Write unit tests for `background_writer.rs`: async operations, command queue, error handling
  - [ ] 6.5 Write unit tests for `wallet_scanner.rs`: scanning logic, API methods, result processing
  - [ ] 6.6 Write unit tests for `progress.rs`: progress tracking, display formatting, callback handling
  - [ ] 6.7 Create integration tests for end-to-end scanning workflows with both memory and database storage
  - [ ] 6.8 Add tests for all feature flag combinations (`grpc`, `storage`, `wasm32`)
  - [ ] 6.9 Implement mocking for blockchain data to enable deterministic testing
  - [ ] 6.10 Achieve >80% test coverage for all scanning library components

- [ ] 7.0 Documentation and final validation
  - [ ] 7.1 Add comprehensive API documentation to all public structs and methods
  - [ ] 7.2 Update `AGENT.md` with new module structure and scanning library usage examples
  - [ ] 7.3 Update `README.md` examples to show both CLI and library usage
  - [ ] 7.4 Run performance validation comparing old vs new implementation (scan times, memory usage)
  - [ ] 7.5 Run `cargo clippy --all-features` and fix all warnings to achieve zero clippy warnings
  - [ ] 7.6 Run `cargo fmt` on all files and verify code formatting standards
  - [ ] 7.7 Test all feature flag combinations compile and work correctly
  - [ ] 7.8 Verify all existing integration tests pass with refactored implementation
  - [ ] 7.9 Conduct final code review to ensure no business logic remains in binary
  - [ ] 7.10 Create migration guide documenting the new library API for other developers
