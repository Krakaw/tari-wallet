# Product Requirements Document: Wallet Event Sourcing System

## Introduction/Overview

This feature implements an event sourcing system for the Tari wallet that captures all transaction-related events in SQLite storage. The system provides audit trails, debugging capabilities, and state recovery by maintaining an immutable history of wallet events that can be replayed to verify consistency.

The event system will be opt-in via the wallet builder pattern and work alongside existing wallet storage without replacing current state management.

## Goals

1. **Audit Trail**: Maintain a complete, immutable history of all wallet transaction events
2. **Debugging Support**: Enable developers and users to replay events to diagnose transaction issues
3. **State Verification**: Allow users to verify wallet state consistency by replaying the event history
4. **Recovery**: Provide ability to recover wallet state from event history if primary state becomes corrupted

## User Stories

1. **As a wallet developer**, I want to replay events to debug transaction issues so that I can identify where problems occurred in the transaction flow.

2. **As a wallet user**, I want to verify my transaction history hasn't been corrupted so that I can trust my wallet's state.

3. **As a wallet user**, I want to recover my wallet state from event history so that I can restore functionality if my wallet becomes corrupted.

4. **As a system administrator**, I want to audit all wallet operations so that I can track transaction flows for compliance purposes.

## Functional Requirements

1. **Event Capture**: The system must capture the following transaction events:
   - UTXO received events (incoming transactions)
   - UTXO spent events (outgoing transactions) 
   - Blockchain re-organization events

2. **Event Storage**: The system must store events in SQLite database with the following properties:
   - Sequential event ordering with timestamps
   - Event type identification
   - Complete event data payload
   - Immutable once written (append-only)

3. **Builder Integration**: The system must integrate with wallet creation via builder pattern:
   - Event listeners can be attached during wallet construction
   - Multiple event listeners can be registered
   - Event capture is opt-in (disabled by default)

4. **Event Replay**: The system must provide event replay functionality that:
   - Processes events in chronological order
   - Verifies current wallet state matches replayed state
   - Reports any inconsistencies found
   - Can be triggered by end users

5. **Cross-Platform Support**: The system must work with both:
   - Memory-only wallets (`grpc` feature)
   - Database-backed wallets (`grpc-storage` feature)

6. **Event Listener Interface**: The system must provide a clean event listener interface that:
   - Defines standard event types
   - Allows custom event handling logic
   - Supports async event processing
   - Handles event processing errors gracefully

## Non-Goals (Out of Scope)

1. **Event Encryption**: Events will not be encrypted or digitally signed
2. **Performance Optimization**: No specific performance requirements for event processing
3. **Event Pruning**: No automatic cleanup or archival of old events
4. **Real-time Streaming**: No real-time event streaming to external systems
5. **Event Privacy Filtering**: All transaction events will be captured without privacy exclusions
6. **State Replacement**: Event sourcing will not replace existing state storage, only supplement it

## Design Considerations

### Event Schema
Events should include:
- Unique event ID
- Event type (UTXO_RECEIVED, UTXO_SPENT, REORG)
- Timestamp
- Event payload (transaction details, block info, etc.)
- Sequence number for ordering

### Database Schema
```sql
CREATE TABLE wallet_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    sequence INTEGER NOT NULL,
    payload TEXT NOT NULL,
    wallet_id TEXT
);
```

### Builder Pattern Integration
```rust
let wallet = WalletBuilder::new()
    .with_event_listener(EventLogger::new())
    .with_event_listener(AuditTrail::new())
    .build()?;
```

## Technical Considerations

1. **Storage Integration**: Should integrate with existing `storage` feature flag and SQLite infrastructure
2. **Event Serialization**: Use JSON or similar for event payload serialization  
3. **Error Handling**: Event processing failures should not break wallet operations
4. **Threading**: Event processing should be async-compatible for non-WASM targets
5. **Memory Management**: Event listeners should use appropriate zeroization for sensitive data

## Success Metrics

1. **Functionality**: Event replay successfully detects 100% of introduced state inconsistencies in testing
2. **Reliability**: Event capture does not cause wallet operation failures
3. **Usability**: Developers can successfully debug transaction issues using event replay
4. **Performance**: Event processing adds <5% overhead to transaction operations

## Open Questions

1. Should event replay be automatically triggered periodically, or only on-demand?
2. What level of detail should be included in inconsistency reports?
3. Should there be a maximum event storage limit to prevent unbounded growth?
4. How should event replay handle partial wallet states (e.g., wallets created mid-blockchain)?
5. Should event listeners be configurable at runtime or only at build time?
