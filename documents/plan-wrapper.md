````
# Implementation Plan

## Prerequisites
- Understanding of the current scanner.rs and wasm.rs implementations
- Knowledge of Rust trait-based architecture and binary patterns
- Familiarity with the existing scanning module traits and structures
- WASM-pack and wasm-bindgen knowledge for WebAssembly wrapper patterns

## Codebase Analysis
- **Architecture**: Trait-based modular system with clear separation between scanning, extraction, validation, and storage layers
- **Existing Patterns**: The scanning module (src/scanning/mod.rs) already provides trait abstractions (BlockchainScanner, WalletScanner) that should be leveraged
- **Current State**: scanner.rs (2315 lines) and wasm.rs (1000+ lines) contain significant direct implementation instead of delegating to library functions
- **Key Components**: 
  - Scanner binary implements full GRPC/storage logic directly
  - WASM wrapper contains duplicate processing logic
  - Core scanning traits exist but aren't fully utilized
- **Integration Points**: 
  - src/scanning/mod.rs provides BlockchainScanner trait
  - src/wallet/mod.rs provides Wallet abstraction  
  - Existing CLI argument parsing with clap
  - WASM bindings with wasm-bindgen

## Research Findings
- **Best Practices**: Lightweight main() functions that delegate to library code, trait-based abstractions for cross-platform compatibility
- **Binary Wrapper Patterns**: Use thin CLI layer that parses arguments and calls library functions, keep platform-specific code minimal
- **WASM Patterns**: Delegate complex logic to core library, keep WASM bindings focused on data conversion and async bridging
- **Security Considerations**: Sensitive data handling should remain in core library, not duplicated in wrappers
- **Performance Guidelines**: Avoid code duplication, centralize core logic for maintenance and optimization

## Task Breakdown

### 1. Extract Scanner Core Functionality
- **Files to modify:** 
  - src/scanning/mod<dot>rs (expand scanner orchestration)
  - src/bin/scanner<dot>rs (reduce to wrapper)
- **Files to create:** 
  - src/scanning/scanner_service<dot>rs (core scanner orchestration)
  - src/scanning/cli_config<dot>rs (configuration handling)
- **Dependencies:** None
- **Approach:** Extract 1800+ lines of scanner logic into a dedicated service module that implements the scanning orchestration, progress tracking, storage integration, and error handling. The binary becomes a thin wrapper that parses CLI args and delegates to ScannerService.
- **Integration points:** Uses existing BlockchainScanner trait, integrates with storage module
- **Key decisions:**
  - ScannerService trait: Provides high-level scanning operations (scan_with_config, resume_from_storage)
  - Configuration struct: Centralizes all scanning parameters and validation
  - Result types: Standardized return values for all operations
- **Data structures:**
  ```
  ScannerConfig: { grpc_url, storage_path, scan_range, wallet_keys, progress_config }
  ScannerService: trait with scan_wallet(), resume_scan(), get_progress()
  ScanResult: { wallet_state, statistics, resume_info }
  ```
- **Implementation notes:** Preserve all existing functionality including batch processing, progress tracking, and error handling with resume capability
- **Potential issues:** 
  - Complex CLI argument handling (mitigation: extract to separate config module)
  - Storage integration complexity (mitigation: use existing storage abstractions)

### 2. Extract WASM Core Functionality  
- **Files to modify:**
  - src/wasm<dot>rs (reduce to wrapper)
  - src/scanning/mod<dot>rs (add WASM-compatible methods)
- **Files to create:**
  - src/wasm/wasm_scanner_service<dot>rs (core WASM logic)
  - src/wasm/conversions<dot>rs (data type conversions)
- **Dependencies:** Scanner core functionality (Task 1)
- **Approach:** Extract the WasmScanner's complex processing logic into a service layer that can be shared. The WASM wrapper becomes focused only on JS<->Rust data conversion and async bridging.
- **Integration points:** Leverages ScannerService from Task 1, integrates with existing HTTP scanner
- **Key decisions:**
  - WasmScannerService: Core scanning logic without WASM-specific concerns
  - Conversion layer: Handles serialization/desererialization between JS and Rust types
  - Async bridging: Manages Promise/Future conversion cleanly
- **Implementation notes:** Maintain backward compatibility with existing WASM API, optimize for memory usage in long-running scans
- **Potential issues:**
  - WASM memory constraints (mitigation: implement cleanup patterns from existing code)
  - JS interop complexity (mitigation: isolate conversion logic)

### 3. Create Scanner Service Module
- **Files to modify:** 
  - src/scanning/mod<dot>rs (add re-exports)
  - src/lib<dot>rs (expose new services)
- **Files to create:** 
  - src/scanning/scanner_service<dot>rs
  - src/scanning/scanner_builder<dot>rs
  - src/scanning/progress_tracker<dot>rs
- **Dependencies:** None (foundational)
- **Approach:** Create a comprehensive service layer that implements all scanner orchestration logic. This becomes the primary interface for both binary and WASM wrappers.
- **Integration points:** Implements existing BlockchainScanner trait, uses storage abstractions
- **Key decisions:**
  - Builder pattern: Configure scanners with fluent API
  - Progress abstraction: Unified progress reporting across platforms  
  - Error handling: Consistent error types with recovery information
- **Data structures:**
  ```
  ScannerServiceBuilder: fluent configuration interface
  ProgressTracker: unified progress reporting
  ScannerError: enhanced error types with resume context
  ```
- **Implementation notes:** Focus on testability and modularity, support both GRPC and HTTP backends
- **Potential issues:**
  - Configuration complexity (mitigation: use builder pattern with sensible defaults)
  - Backend abstraction leaks (mitigation: careful trait design)

### 4. Create WASM Service Module
- **Files to modify:**
  - src/lib<dot>rs (conditional WASM exports)
- **Files to create:**
  - src/wasm/mod<dot>rs (WASM module organization)
  - src/wasm/scanner_service<dot>rs
  - src/wasm/types<dot>rs (WASM-specific type definitions)
- **Dependencies:** Scanner service module (Task 3)
- **Approach:** Create WASM-specific service layer that bridges between the core scanner service and JavaScript. Handles memory management, async operations, and data conversions.
- **Integration points:** Uses ScannerService from Task 3, integrates with wasm-bindgen patterns
- **Key decisions:**
  - Memory management: Explicit cleanup methods for long-running operations
  - Async bridge: Convert Rust async to JavaScript Promises properly
  - Type safety: Strong TypeScript definitions for all operations
- **Implementation notes:** Maintain existing API compatibility, add memory-efficient batch processing
- **Potential issues:**
  - WASM async complexity (mitigation: use established wasm-bindgen-futures patterns)
  - Memory leaks in long scans (mitigation: implement automatic cleanup triggers)

### 5. Refactor Scanner Binary
- **Files to modify:**
  - src/bin/scanner<dot>rs (major reduction)
- **Files to create:**
  - src/bin/scanner/main<dot>rs (new main function)
  - src/bin/scanner/cli<dot>rs (argument parsing)
  - src/bin/scanner/output<dot>rs (result formatting)
- **Dependencies:** Scanner service module (Task 3)
- **Approach:** Reduce scanner binary to ~200 lines focused on CLI argument parsing, service configuration, and output formatting. All business logic delegates to ScannerService.
- **Integration points:** Uses ScannerService and ScannerServiceBuilder
- **Key decisions:**
  - CLI separation: Parse args in separate module for testability
  - Output formatting: Delegate to specialized formatter functions
  - Error handling: Convert service errors to user-friendly messages
- **Implementation notes:** Preserve all existing CLI functionality and help text
- **Potential issues:**
  - CLI compatibility (mitigation: maintain exact argument compatibility)
  - Service configuration mapping (mitigation: comprehensive integration tests)

### 6. Refactor WASM Binary
- **Files to modify:**
  - src/wasm<dot>rs (major reduction)
- **Files to create:**
  - src/wasm/bindings<dot>rs (WASM bindings only)
  - src/wasm/async_bridge<dot>rs (Promise conversion)
- **Dependencies:** WASM service module (Task 4), Scanner service module (Task 3)
- **Approach:** Reduce WASM wrapper to ~300 lines focused only on wasm-bindgen exports, data conversion, and async bridging. All scanning logic delegates to WasmScannerService.
- **Integration points:** Uses WasmScannerService, maintains existing public API
- **Key decisions:**
  - API preservation: Keep exact same public interface for backward compatibility
  - Memory optimization: Implement cleanup patterns for large scans
  - Error bridging: Convert Rust errors to JavaScript-friendly formats
- **Implementation notes:** Maintain TypeScript compatibility, optimize for bundle size
- **Potential issues:**
  - API breaking changes (mitigation: maintain exact function signatures)
  - Performance regression (mitigation: benchmark key operations)

### 7. Update Configuration Management
- **Files to modify:**
  - src/scanning/mod<dot>rs (add config re-exports)
- **Files to create:**
  - src/config/mod<dot>rs (unified configuration)
  - src/config/scanner_config<dot>rs
  - src/config/validation<dot>rs
- **Dependencies:** Scanner service module (Task 3)
- **Approach:** Create unified configuration management that can be shared between CLI and WASM interfaces. Includes validation, defaults, and serialization support.
- **Integration points:** Used by both scanner binary and WASM wrapper
- **Key decisions:**
  - Validation layer: Comprehensive config validation with helpful error messages
  - Serialization: Support for JSON config files and environment variables
  - Defaults: Sensible defaults for all configuration options
- **Implementation notes:** Support feature-flag based configuration (grpc vs http)
- **Potential issues:**
  - Configuration complexity (mitigation: provide configuration templates and examples)
  - Cross-platform compatibility (mitigation: abstract platform-specific settings)

### 8. Add Integration Tests
- **Files to modify:**
  - tests/integration_tests<dot>rs (expand existing tests)
- **Files to create:**
  - tests/scanner_service_tests<dot>rs
  - tests/wasm_integration_tests<dot>rs
  - tests/common/test_fixtures<dot>rs
- **Dependencies:** All service modules (Tasks 3, 4)
- **Approach:** Create comprehensive integration tests that verify the refactored components work correctly together and maintain compatibility with existing behavior.
- **Integration points:** Tests both service layers and wrapper layers
- **Key decisions:**
  - Test coverage: Full coverage of existing functionality
  - Mock backends: Use mock blockchain scanner for deterministic tests
  - Performance tests: Verify no regression in scanning performance
- **Implementation notes:** Use existing test patterns, add WASM-specific tests using wasm-bindgen-test
- **Potential issues:**
  - Test complexity (mitigation: use shared test fixtures and helpers)
  - WASM test setup (mitigation: follow existing WASM test patterns)

## Potential Challenges & Mitigations
1. **Challenge:** Maintaining backward compatibility with existing CLI and WASM APIs
   **Mitigation:** Preserve exact function signatures and behavior, comprehensive integration testing

2. **Challenge:** Complex state management across service boundaries
   **Mitigation:** Use clear ownership patterns, minimize shared mutable state

3. **Challenge:** Performance regression due to additional abstraction layers
   **Mitigation:** Benchmark critical paths, optimize hot paths, use zero-cost abstractions

4. **Challenge:** WASM memory management complexity
   **Mitigation:** Implement explicit cleanup patterns, add memory usage monitoring

5. **Challenge:** Error handling consistency across platforms
   **Mitigation:** Standardized error types with platform-specific conversion layers

## File Description Updates
- src/bin/scanner<dot>rs: "Lightweight CLI wrapper around ScannerService for blockchain scanning operations"
- src/wasm<dot>rs: "Minimal WASM bindings wrapper around WasmScannerService for browser/Node.js compatibility"
- src/scanning/scanner_service<dot>rs: "Core scanner orchestration service implementing high-level scanning operations"
- src/wasm/scanner_service<dot>rs: "WASM-optimized scanning service with memory management and async bridging"
- src/config/scanner_config<dot>rs: "Unified configuration management for scanner operations across platforms"

## Codebase Overview Updates
- **Binary Architecture**: Update to reflect lightweight wrapper pattern with trait-based service delegation
- **WASM Integration**: Emphasize memory-efficient design and proper async bridging
- **Service Layer**: Document new service abstraction layer for scanner operations
- **Code Quality**: Note reduction in duplication from 3.7% with consolidated core logic

## Validation Steps
- Run existing CLI commands and verify identical output and behavior
- Execute WASM integration tests to ensure API compatibility  
- Run performance benchmarks to verify no regression
- Test memory usage in long-running WASM scans
- Validate error handling and recovery scenarios
- Check TypeScript definitions are generated correctly
- Verify storage integration works across all configurations
- Test feature flag combinations (grpc vs http vs storage)
- Run clippy and cargo check to ensure code quality standards
- Execute full test suite with --all-features flag
````