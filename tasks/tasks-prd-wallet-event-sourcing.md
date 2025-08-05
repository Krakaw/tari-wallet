## Relevant Files

- `src/events/mod.rs` - Main event system module containing event types and core functionality
- `src/events/types.rs` - Event type definitions and data structures (UTXO received, spent, reorg events)
- `src/events/listener.rs` - Event listener trait and registry implementation
- `src/events/storage.rs` - Event storage implementation for SQLite database
- `src/events/replay.rs` - Event replay engine that processes events in chronological order for state reconstruction (Task 5.1)
- `src/wallet/builder.rs` - Wallet builder implementation with event listener registration support
- `src/wallet/mod.rs` - Updated wallet module with builder exports
- `src/storage/event_storage.rs` - Database schema and operations for event persistence with SQLite implementation
- `src/storage/sqlite.rs` - Updated main SQLite storage with wallet_events table schema integration
- `src/storage/mod.rs` - Updated storage module to export event storage components
- `tests/events/mod.rs` - Integration tests for event system
- `tests/events/event_capture_tests.rs` - Tests for event capture functionality
- `tests/events/event_replay_tests.rs` - Tests for event replay and verification
- `tests/events/builder_integration_tests.rs` - Tests for wallet builder integration
- `tests/integration/builder_integration_tests.rs` - Integration tests for builder pattern with event listeners
- `tests/builder_integration_standalone.rs` - Standalone integration tests for wallet builder with event listeners
- `tests/event_storage_integration.rs` - Integration tests for event storage database operations
- `tests/event_storage_operations_tests.rs` - Integration tests for enhanced event storage operations (Task 4.2)
- `tests/automatic_assignment_tests.rs` - Integration tests for automatic timestamping and sequence assignment (Task 4.3)
- `tests/append_only_behavior_tests.rs` - Integration tests for append-only behavior enforcement (Task 4.4)
- `tests/feature_gating_tests.rs` - Tests for storage feature gating behavior (Task 4.5)
- `tests/connection_pool_tests.rs` - Tests for connection pooling functionality (Task 4.6)
- `tests/event_replay_methods_tests.rs` - Tests for specialized event retrieval methods for replay functionality (Task 4.7)
- `tests/event_storage_comprehensive_tests.rs` - Comprehensive unit tests for event storage operations covering automatic assignment, batch operations, sequence validation, and edge cases (Task 4.8)
- `tests/database_integrity_tests.rs` - Database integrity tests to verify append-only behavior, schema constraints, transaction atomicity, and corruption detection (Task 4.9)
- `tests/storage/event_storage_tests.rs` - Unit tests for event storage implementation
- `tests/storage/mod.rs` - Storage test module organization
- `tests/inconsistency_detection_tests.rs` - Tests for inconsistency detection and detailed reporting functionality (Task 5.3)
- `src/events/user_api.rs` - User-facing API methods for triggering event replay operations with convenience methods and progress monitoring (Task 5.4)
- `tests/user_api_tests.rs` - Tests for user-facing API methods and replay operations (Task 5.4)
- `tests/edge_case_replay_tests.rs` - Tests for edge case handling in event replay (partial states, missing events, corrupted data) (Task 5.5)
- `src/events/listeners/sqlite_event_listener.rs` - Direct SQLite event listener for storing wallet scanning events in the main database (Task 6.1)

### Notes

- Event system should be feature-gated with existing `storage` feature for database operations
- Use existing SQLite infrastructure and connection patterns from current storage implementation
- Event listeners should follow async patterns used in scanning components
- Use `cargo test --features storage` to run tests with database functionality

## Tasks

- [ ] 1.0 Define Event Types and Data Structures
  - [x] 1.1 Create `WalletEvent` enum with variants for UTXO_RECEIVED, UTXO_SPENT, and REORG
  - [x] 1.2 Define event payload structures for each event type (transaction data, block info, etc.)
  - [x] 1.3 Implement Serialize/Deserialize traits for JSON serialization
  - [x] 1.4 Add proper error types for event processing failures
  - [x] 1.5 Implement Zeroize trait for sensitive event data
  - [x] 1.6 Create event metadata structure (ID, timestamp, sequence number, wallet_id)
  - [x] 1.7 Write unit tests for event type serialization and deserialization

- [x] 2.0 Implement Event Listener Interface and Registry
  - [x] 2.1 Define `EventListener` trait with async event handling method
  - [x] 2.2 Create `EventRegistry` to manage multiple registered listeners
  - [x] 2.3 Implement async event dispatch to all registered listeners
  - [x] 2.4 Add error handling to prevent listener failures from breaking wallet operations
  - [x] 2.5 Create concrete listener implementations (EventLogger, AuditTrail)
  - [x] 2.6 Add listener registration/deregistration methods
  - [x] 2.7 Write unit tests for event listener interface and registry

- [x] 3.0 Integrate Event System with Wallet Builder
  - [x] 3.1 Modify wallet builder to accept event listeners via `with_event_listener()` method
  - [x] 3.2 Add internal event registry to wallet structure
  - [x] 3.3 Ensure event capture is opt-in (disabled by default)
  - [x] 3.4 Wire up event emission from existing wallet operations (receive/spend UTXOs)
  - [x] 3.5 Add feature flag integration for memory-only vs database-backed wallets
  - [x] 3.6 Update wallet builder tests to verify event listener registration
  - [x] 3.7 Write integration tests for builder pattern with event listeners

- [x] 4.0 Implement Event Storage in SQLite
  - [x] 4.1 Create database migration for `wallet_events` table with required schema
  - [x] 4.2 Implement event storage operations (insert, query by wallet_id, query by sequence)
  - [x] 4.3 Add automatic timestamping and sequence number assignment
  - [x] 4.4 Ensure append-only behavior (no updates or deletes allowed)
  - [x] 4.5 Feature-gate event storage with existing `storage` feature flag
  - [x] 4.6 Add connection pooling support for concurrent event writes
  - [x] 4.7 Implement event retrieval methods for replay functionality
  - [x] 4.8 Write unit tests for event storage operations
  - [x] 4.9 Add database integrity tests to verify append-only behavior

- [ ] 5.0 Implement Event Replay and Verification System
  - [x] 5.1 Create event replay engine that processes events in chronological order
  - [x] 5.2 Implement state verification logic to compare replayed state vs current state
  - [x] 5.3 Add inconsistency detection and detailed reporting functionality
  - [x] 5.4 Create user-facing API methods for triggering event replay
  - [x] 5.5 Handle edge cases (partial wallet states, missing events, corrupted data)
  - [ ] 5.6 Add progress reporting for long-running replay operations
  - [ ] 5.7 Implement replay cancellation support
  - [ ] 5.8 Write comprehensive integration tests for event replay scenarios
  - [ ] 5.9 Add performance tests to ensure replay doesn't impact wallet operations

- [ ] 6. SQLite fixes
   - [x] 6.1 This whole implementation is incomplete and invalid, it should be storing the events ONLY in the sqlite table that was created in 4.1
   - [ ] 6.2 Create the listeners that can be used in @/src/bin/scanner.rs to store the events in the wallet_events table by default.
   - [ ] 6.3 Remove the event_loggers and their tests only keep what is relevant to the sqlite wallet_events testing