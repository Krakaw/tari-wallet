# Product Requirements Document: Wallet Scanner Eventing System

## Introduction/Overview

Refactor the wallet scanner's `scan_wallet_across_blocks_with_cancellation` function to replace direct `storage_backend` and `progress_tracker` dependencies with a generic, asynchronous eventing system. This change will improve modularity, testability, and maintainability by decoupling scanning logic from specific storage and progress reporting implementations.

The new system will emit detailed events throughout the scanning process, allowing listeners to handle database operations, progress updates, and other cross-cutting concerns without the core scanning logic needing to know about these implementations.

## Goals

1. **Decouple scanning logic** from storage and progress tracking implementations
2. **Create a general-purpose event system** that works across native and WASM targets
3. **Maintain all existing functionality** through built-in event listeners
4. **Improve testability** by making dependencies injectable and observable
5. **Enable extensibility** for future scanning-related features
6. **Preserve performance** while adding eventing capabilities
7. **Support graceful cancellation** through the event system

## User Stories

**As a developer integrating the wallet scanner:**
- I want to register custom listeners for scanning events so that I can implement domain-specific logic without modifying core scanning code
- I want built-in listeners that replicate existing functionality so that migration is straightforward
- I want the ability to cancel scans so that long-running operations can be interrupted

**As a maintainer of the scanning code:**
- I want scanning logic separated from storage concerns so that I can modify one without affecting the other
- I want comprehensive test coverage so that I can refactor with confidence
- I want clear event interfaces so that new functionality can be added easily

**As a WASM application developer:**
- I want the event system to work identically in browser and Node.js environments so that I can build cross-platform applications

## Functional Requirements

### Core Event System

1. **The system must implement a general-purpose event system** that can be used beyond just wallet scanning
2. **The event system must work identically on native and WASM targets** without conditional compilation in user code
3. **The system must support asynchronous, fire-and-forget event emission** where scanning continues regardless of listener processing time
4. **Event listeners must be registered at scanner construction time** through a builder pattern or similar
5. **Event listeners must be processed in registration order** to provide predictable behavior
6. **Individual listener failures must not affect other listeners or halt scanning** - errors should be logged but isolated
7. **The system must support scan cancellation** through a cancellation mechanism that works with the event system

### Event Types and Data

8. **The system must emit `ScanStarted` events** containing: scan configuration, block range, wallet context
9. **The system must emit `BlockProcessed` events** containing: block height, block hash, timestamp, processing duration, outputs found count
10. **The system must emit `OutputFound` events** containing: complete output data, block height, transaction hash, output index, address information
11. **The system must emit `ScanProgress` events** containing: current block, total blocks, percentage complete, blocks per second, estimated time remaining, total outputs found
12. **The system must emit `ScanCompleted` events** containing: final statistics, total duration, blocks processed, outputs found, success status
13. **The system must emit `ScanError` events** containing: error details, block height where error occurred, retry information, severity level
14. **The system must emit `ScanCancelled` events** containing: cancellation reason, final statistics up to cancellation point

### Built-in Listeners

15. **The system must provide a `DatabaseStorageListener`** that replicates current storage_backend functionality
16. **The system must provide a `ProgressTrackingListener`** that replicates current progress_tracker functionality  
17. **The system must provide a `ConsoleLoggingListener`** for development and debugging purposes
18. **Built-in listeners must be easily configurable** through constructor parameters or builder patterns
19. **Built-in listeners must handle their own error recovery** and logging without affecting the scan

### API Changes

20. **The `scan_wallet_across_blocks_with_cancellation` function signature must be updated** to remove `storage_backend` and `progress_tracker` parameters
21. **The scanner must accept an event emitter/dispatcher** either at construction or as a parameter
22. **The scanner must provide a builder pattern** for easy configuration with default listeners
23. **All existing public APIs must have migration paths** or equivalent functionality through the new system

### Error Handling and Reliability

24. **Listener registration errors must be caught at construction time** not during scanning
25. **Event emission must not panic** regardless of listener behavior
26. **The system must provide debugging capabilities** to trace event flow and listener performance
27. **Memory usage must remain bounded** even with many events and listeners

### Testing Support

28. **The system must provide test-friendly mock listeners** for unit testing
29. **The system must support event capture** for assertion in tests
30. **The system must allow deterministic testing** of async event processing

## Non-Goals (Out of Scope)

- **Event persistence or replay** - events are processed once and discarded
- **Event filtering or transformation** - listeners receive all events they subscribe to
- **Dynamic listener registration/removal** during scanning
- **Event prioritization beyond registration order**
- **Cross-process or networked event delivery**
- **Event schema versioning** - this will be addressed in future iterations
- **Performance optimization for extremely high-frequency events** (>10k events/second)

## Design Considerations

### Event System Architecture
- Use a trait-based design for `EventListener` to enable easy testing and extension
- Consider using `tokio::mpsc` channels for native async and `wasm-bindgen-futures` for WASM compatibility
- Implement event dispatch through a simple `Vec<Box<dyn EventListener>>` to maintain order

### Error Isolation
- Wrap each listener call in error handling to prevent cascading failures
- Consider a configurable error reporting mechanism for listener failures

### Performance
- Use `Arc<Event>` for efficient event sharing between listeners
- Consider batching for high-frequency events if performance testing reveals issues

### Migration Strategy
- Provide deprecated wrapper functions that internally use the new event system
- Include migration examples in documentation

## Technical Considerations

### Dependencies
- Must work with existing `tokio` async runtime for native builds
- Must integrate with `wasm-bindgen-futures` for WASM compatibility
- Should minimize additional dependencies to maintain build performance

### Integration Points
- **Authentication Module**: Events may need to include authenticated context
- **Storage Module**: Database listener must integrate with existing schema
- **CLI Tools**: Progress listener must work with existing terminal output

### Memory Management
- Events should be designed to avoid unnecessary cloning of large data structures
- Consider using references where possible, owned data where necessary for async

## Success Metrics

1. **Code maintainability**: Reduction in coupling between scanning and storage/progress code
2. **Test coverage**: >95% test coverage for new event system components
3. **Performance**: <5% performance regression in scanning throughput
4. **Migration success**: All existing functionality works identically through new system
5. **Developer experience**: New features can be added through listeners without core changes

## Open Questions

1. **Event serialization**: Should events be serializable for future debugging/persistence features?
2. **Listener lifecycle**: Do we need listener cleanup/disposal methods for resource management?
3. **Event metadata**: Should events include timestamps, sequence numbers, or other metadata?
4. **Configuration**: How should built-in listeners be configured - environment variables, config files, or code?
5. **Documentation**: What level of documentation is needed for the event system to be adopted by other modules?

## Implementation Notes

- This is a **breaking change** that will require updates to all code using the scanning functionality
- Migration should be completed in phases: event system implementation, built-in listeners, API updates, deprecation of old APIs
- Comprehensive integration tests should be written before beginning refactoring to ensure behavioral compatibility
