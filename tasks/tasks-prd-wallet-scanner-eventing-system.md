# Task List: Wallet Scanner Eventing System

## Relevant Files

- `src/events/mod.rs` - Core event system module with traits and dispatcher
- `src/events/types.rs` - Event type definitions and data structures
- `src/events/listeners/mod.rs` - Built-in event listeners module
- `src/events/listeners/database.rs` - Database storage event listener
- `src/events/listeners/progress.rs` - Progress tracking event listener  
- `src/events/listeners/console.rs` - Console logging event listener
- `src/scanning/wallet_scanner.rs` - Refactored wallet scanner implementation
- `src/scanning/event_emitter.rs` - Event emission integration for scanner
- `tests/events/` - Unit and integration tests for event system
- `tests/scanning/test_with_events.rs` - Integration tests for refactored scanner
- `examples/scanning_with_events.rs` - Usage examples for migration guide

### Notes

- Event system should be placed in a new `src/events/` module for organization
- Tests should cover both native and WASM compatibility scenarios
- Use `cargo test --all-features` to run comprehensive tests including event system
- Migration examples will help existing users adapt to the new API


## Tasks

- [ ] 1.0 Design and Implement Core Event System
  - [x] 1.1 Create `src/events/mod.rs` with public module exports and documentation
  - [ ] 1.2 Define `EventListener` trait with async `handle_event` method for cross-platform compatibility
  - [ ] 1.3 Implement `EventDispatcher` struct that maintains ordered list of listeners
  - [ ] 1.4 Add error isolation - wrap listener calls to prevent cascading failures
  - [ ] 1.5 Implement registration validation at construction time (Req #24)
  - [ ] 1.6 Add debugging capabilities for event flow tracing (Req #26)
  - [ ] 1.7 Ensure bounded memory usage with proper cleanup (Req #27)
  - [ ] 1.8 Test cross-platform compatibility (native vs WASM) (Req #2)

- [ ] 2.0 Create Event Types and Data Structures
  - [ ] 2.1 Create `src/events/types.rs` with base event enum and shared traits
  - [ ] 2.2 Implement `ScanStarted` event with scan config, block range, wallet context (Req #8)
  - [ ] 2.3 Implement `BlockProcessed` event with height, hash, timestamp, duration, outputs count (Req #9)
  - [ ] 2.4 Implement `OutputFound` event with complete output data, block info, address info (Req #10)
  - [ ] 2.5 Implement `ScanProgress` event with current/total blocks, percentage, speed, ETA (Req #11)
  - [ ] 2.6 Implement `ScanCompleted` event with final statistics and success status (Req #12)
  - [ ] 2.7 Implement `ScanError` event with error details, block height, retry info (Req #13)
  - [ ] 2.8 Implement `ScanCancelled` event with cancellation reason and final stats (Req #14)
  - [ ] 2.9 Use `Arc<Event>` for efficient sharing between listeners (Design consideration)
  - [ ] 2.10 Add serialization support for debugging (Open question #1)

- [ ] 3.0 Implement Built-in Event Listeners
  - [ ] 3.1 Create `src/events/listeners/mod.rs` with public exports
  - [ ] 3.2 Implement `DatabaseStorageListener` replicating current storage_backend (Req #15)
  - [ ] 3.3 Implement `ProgressTrackingListener` replicating current progress_tracker (Req #16)
  - [ ] 3.4 Implement `ConsoleLoggingListener` for development and debugging (Req #17)
  - [ ] 3.5 Add builder patterns for easy listener configuration (Req #18)
  - [ ] 3.6 Implement proper error recovery and logging in each listener (Req #19)
  - [ ] 3.7 Create `MockEventListener` for testing scenarios (Req #28)
  - [ ] 3.8 Add event capture functionality for test assertions (Req #29)
  - [ ] 3.9 Ensure deterministic async testing support (Req #30)

- [ ] 4.0 Refactor Wallet Scanner to Use Event System
  - [ ] 4.1 Create `src/scanning/event_emitter.rs` with scanner integration logic
  - [ ] 4.2 Update `scan_wallet_across_blocks_with_cancellation` signature - remove storage_backend and progress_tracker (Req #20)
  - [ ] 4.3 Add event dispatcher parameter to scanner construction (Req #21)
  - [ ] 4.4 Implement scanner builder pattern with default listeners (Req #22)
  - [ ] 4.5 Add event emission at each scanning stage (start, block processing, output found, progress, completion)
  - [ ] 4.6 Integrate cancellation mechanism with event system (Req #7)
  - [ ] 4.7 Ensure fire-and-forget async event emission doesn't block scanning (Req #3)
  - [ ] 4.8 Convert `src/bin/scanner.rs` to use the event system in place of existing functionality.

- [ ] 5.0 Update Tests and Add Migration Support
  - [ ] 5.1 Write unit tests for core event system components (>95% coverage target)
  - [ ] 5.2 Write integration tests for built-in listeners with real database/progress scenarios
  - [ ] 5.3 Write cross-platform tests ensuring identical behavior on native and WASM
  - [ ] 5.4 Create performance benchmarks comparing old vs new implementation
  - [ ] 5.5 Write migration examples in `examples/scanning_with_events.rs`
  - [ ] 5.6 Update existing tests to use new event-based scanner API
  - [ ] 5.7 Add comprehensive integration tests that verify all existing functionality works identically
  - [ ] 5.8 Create documentation for event system adoption by other modules
  - [ ] 5.9 Write CHANGELOG.md entry documenting breaking changes and migration path
