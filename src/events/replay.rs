//! Event replay engine for reconstructing wallet state from historical events
//!
//! This module provides functionality to replay wallet events in chronological order
//! to reconstruct wallet state. This is essential for state verification, debugging,
//! and recovering from data corruption.
//!
//! # Features
//!
//! - **Chronological replay**: Events are processed in the exact order they occurred
//! - **Incremental replay**: Resume replay from any sequence number
//! - **Batch processing**: Handle large event logs efficiently
//! - **Progress tracking**: Monitor replay progress with callbacks
//! - **Error handling**: Graceful handling of corrupted or missing events
//! - **Cancellation support**: Ability to cancel long-running replay operations
//!
//! # Usage
//!
//! ```rust,no_run
//! use lightweight_wallet_libs::events::replay::{EventReplayEngine, ReplayConfig};
//! use lightweight_wallet_libs::storage::event_storage::SqliteEventStorage;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(feature = "storage")]
//! # {
//! let storage = SqliteEventStorage::new(connection).await?;
//! let config = ReplayConfig::default();
//! let mut engine = EventReplayEngine::new(storage, config);
//!
//! // Replay all events for a wallet
//! let replayed_state = engine.replay_wallet("wallet-id").await?;
//!
//! // Incremental replay from a checkpoint
//! let state = engine.replay_from_sequence("wallet-id", 100).await?;
//! # }
//! # Ok(())
//! # }
//! ```

use crate::events::types::{WalletEvent, WalletEventError, WalletEventResult};
#[cfg(feature = "storage")]
use crate::storage::event_storage::{EventStorage, StoredEvent};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::watch;

/// Configuration for event replay operations
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Batch size for processing events in chunks
    pub batch_size: usize,
    /// Maximum time to spend on replay before yielding
    pub max_batch_duration: Duration,
    /// Whether to validate event sequence continuity
    pub validate_sequence_continuity: bool,
    /// Whether to stop on the first error or continue with best effort
    pub stop_on_error: bool,
    /// Progress reporting frequency (report every N events)
    pub progress_frequency: usize,
    /// Maximum number of events to replay (0 = no limit)
    pub max_events: usize,
    /// Whether to perform detailed validation of replayed state
    pub validate_replayed_state: bool,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            batch_size: 1000,
            max_batch_duration: Duration::from_millis(100),
            validate_sequence_continuity: true,
            stop_on_error: false,
            progress_frequency: 100,
            max_events: 0, // No limit
            validate_replayed_state: true,
        }
    }
}

impl ReplayConfig {
    /// Create a performance-optimized configuration for large replays
    pub fn performance_optimized() -> Self {
        Self {
            batch_size: 5000,
            max_batch_duration: Duration::from_millis(500),
            validate_sequence_continuity: false,
            stop_on_error: false,
            progress_frequency: 1000,
            max_events: 0,
            validate_replayed_state: false,
        }
    }

    /// Create a safety-first configuration with maximum validation
    pub fn strict_validation() -> Self {
        Self {
            batch_size: 100,
            max_batch_duration: Duration::from_millis(50),
            validate_sequence_continuity: true,
            stop_on_error: true,
            progress_frequency: 10,
            max_events: 0,
            validate_replayed_state: true,
        }
    }

    /// Create a configuration for incremental replay scenarios
    pub fn incremental() -> Self {
        Self {
            batch_size: 500,
            max_batch_duration: Duration::from_millis(100),
            validate_sequence_continuity: true,
            stop_on_error: false,
            progress_frequency: 50,
            max_events: 0,
            validate_replayed_state: false,
        }
    }

    /// Set the batch size for processing events
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// Set the maximum duration per batch
    pub fn with_max_batch_duration(mut self, duration: Duration) -> Self {
        self.max_batch_duration = duration;
        self
    }

    /// Enable or disable sequence continuity validation
    pub fn with_sequence_validation(mut self, validate: bool) -> Self {
        self.validate_sequence_continuity = validate;
        self
    }

    /// Set error handling behavior
    pub fn with_stop_on_error(mut self, stop_on_error: bool) -> Self {
        self.stop_on_error = stop_on_error;
        self
    }

    /// Set progress reporting frequency
    pub fn with_progress_frequency(mut self, frequency: usize) -> Self {
        self.progress_frequency = frequency;
        self
    }

    /// Set maximum number of events to replay
    pub fn with_max_events(mut self, max_events: usize) -> Self {
        self.max_events = max_events;
        self
    }
}

/// Progress information for replay operations
#[derive(Debug, Clone, Serialize)]
pub struct ReplayProgress {
    /// Wallet ID being replayed
    pub wallet_id: String,
    /// Current sequence number being processed
    pub current_sequence: u64,
    /// Total number of events to replay (if known)
    pub total_events: Option<usize>,
    /// Number of events processed so far
    pub events_processed: usize,
    /// Number of events successfully applied
    pub events_applied: usize,
    /// Number of events that failed to apply
    pub events_failed: usize,
    /// Time when replay started
    pub start_time: SystemTime,
    /// Estimated time remaining (if total is known)
    pub estimated_remaining: Option<Duration>,
    /// Current replay phase
    pub phase: ReplayPhase,
    /// Any errors encountered (if not stopping on errors)
    pub errors: Vec<String>,
}

/// Different phases of the replay process
#[derive(Debug, Clone, Serialize)]
pub enum ReplayPhase {
    /// Loading events from storage
    Loading,
    /// Validating event sequence continuity
    ValidatingSequence,
    /// Processing events to rebuild state
    ProcessingEvents,
    /// Validating the final reconstructed state
    ValidatingState,
    /// Replay completed successfully
    Completed,
    /// Replay was cancelled
    Cancelled,
    /// Replay failed with errors
    Failed,
}

/// Result of an event replay operation
#[derive(Debug, Clone)]
pub struct ReplayResult {
    /// The reconstructed wallet state
    pub wallet_state: ReplayedWalletState,
    /// Final progress information
    pub progress: ReplayProgress,
    /// Whether the replay completed successfully
    pub success: bool,
    /// Any validation issues discovered
    pub validation_issues: Vec<ValidationIssue>,
    /// Performance metrics
    pub metrics: ReplayMetrics,
}

/// Reconstructed wallet state from event replay
#[derive(Debug, Clone)]
pub struct ReplayedWalletState {
    /// Wallet ID
    pub wallet_id: String,
    /// All UTXOs currently owned by the wallet
    pub utxos: HashMap<String, UtxoState>,
    /// All spent UTXOs for historical reference
    pub spent_utxos: HashMap<String, SpentUtxoState>,
    /// Total balance (sum of unspent UTXOs)
    pub total_balance: u64,
    /// Number of transactions processed
    pub transaction_count: usize,
    /// Highest block height seen in events
    pub highest_block: u64,
    /// Last sequence number processed
    pub last_sequence: u64,
    /// Time when the state was last updated
    pub last_updated: SystemTime,
}

impl Default for ReplayedWalletState {
    fn default() -> Self {
        Self {
            wallet_id: String::new(),
            utxos: HashMap::new(),
            spent_utxos: HashMap::new(),
            total_balance: 0,
            transaction_count: 0,
            highest_block: 0,
            last_sequence: 0,
            last_updated: SystemTime::UNIX_EPOCH,
        }
    }
}

/// State of a UTXO in the replayed wallet
#[derive(Debug, Clone)]
pub struct UtxoState {
    /// UTXO identifier
    pub utxo_id: String,
    /// Amount in microTari
    pub amount: u64,
    /// Block height where confirmed
    pub block_height: u64,
    /// Transaction hash
    pub transaction_hash: String,
    /// Output index within transaction
    pub output_index: usize,
    /// Wallet address that received this
    pub receiving_address: String,
    /// Key index used
    pub key_index: u64,
    /// Commitment value
    pub commitment: String,
    /// When this UTXO was received
    pub received_at: SystemTime,
    /// Whether this UTXO is mature (can be spent)
    pub is_mature: bool,
    /// Maturity height if applicable
    pub maturity_height: Option<u64>,
}

/// State of a spent UTXO
#[derive(Debug, Clone)]
pub struct SpentUtxoState {
    /// Original UTXO state
    pub original_utxo: UtxoState,
    /// When it was spent
    pub spent_at: SystemTime,
    /// Block height where spent
    pub spent_block_height: u64,
    /// Transaction that spent it
    pub spending_transaction_hash: String,
}

/// Validation issues discovered during replay
#[derive(Debug, Clone, Serialize)]
pub struct ValidationIssue {
    /// Type of validation issue
    pub issue_type: ValidationIssueType,
    /// Description of the issue
    pub description: String,
    /// Sequence number where issue was found
    pub sequence_number: Option<u64>,
    /// Event ID associated with the issue
    pub event_id: Option<String>,
    /// Severity level
    pub severity: ValidationSeverity,
}

/// Types of validation issues
#[derive(Debug, Clone, Serialize)]
pub enum ValidationIssueType {
    /// Missing sequence number in the event chain
    MissingSequence,
    /// Duplicate sequence number found
    DuplicateSequence,
    /// Event references unknown UTXO
    UnknownUtxo,
    /// Trying to spend already spent UTXO
    DoubleSpend,
    /// Event has invalid or corrupted data
    InvalidEventData,
    /// Events are out of chronological order
    OutOfOrder,
    /// Balance calculation doesn't match
    BalanceMismatch,
}

/// Severity levels for validation issues
#[derive(Debug, Clone, Serialize)]
pub enum ValidationSeverity {
    /// Info-level issue (cosmetic)
    Info,
    /// Warning that might indicate a problem
    Warning,
    /// Error that affects data integrity
    Error,
    /// Critical error that makes replay unreliable
    Critical,
}

/// Performance metrics for replay operations
#[derive(Debug, Clone, Serialize)]
pub struct ReplayMetrics {
    /// Total time taken for replay
    pub total_duration: Duration,
    /// Time spent loading events from storage
    pub loading_duration: Duration,
    /// Time spent processing events
    pub processing_duration: Duration,
    /// Time spent on validation
    pub validation_duration: Duration,
    /// Average time per event processed
    pub average_event_time: Duration,
    /// Peak memory usage during replay (if available)
    pub peak_memory_usage: Option<usize>,
    /// Number of storage queries made
    pub storage_queries: usize,
}

/// Callback function type for progress reporting
pub type ProgressCallback = Arc<dyn Fn(&ReplayProgress) + Send + Sync>;

/// Event replay engine for reconstructing wallet state
#[cfg(feature = "storage")]
pub struct EventReplayEngine<S: EventStorage> {
    storage: S,
    config: ReplayConfig,
    progress_callback: Option<ProgressCallback>,
}

#[cfg(feature = "storage")]
impl<S: EventStorage + Sync> EventReplayEngine<S> {
    /// Create a new event replay engine
    pub fn new(storage: S, config: ReplayConfig) -> Self {
        Self {
            storage,
            config,
            progress_callback: None,
        }
    }

    /// Set a progress callback for monitoring replay operations
    pub fn with_progress_callback(mut self, callback: ProgressCallback) -> Self {
        self.progress_callback = Some(callback);
        self
    }

    /// Replay all events for a wallet from the beginning
    pub async fn replay_wallet(&self, wallet_id: &str) -> WalletEventResult<ReplayResult> {
        self.replay_from_sequence(wallet_id, 1).await
    }

    /// Replay events for a wallet starting from a specific sequence number
    pub async fn replay_from_sequence(
        &self,
        wallet_id: &str,
        from_sequence: u64,
    ) -> WalletEventResult<ReplayResult> {
        let mut cancel_rx = watch::channel(false).1;
        self.replay_from_sequence_with_cancel(wallet_id, from_sequence, &mut cancel_rx)
            .await
    }

    /// Replay events with cancellation support
    pub async fn replay_from_sequence_with_cancel(
        &self,
        wallet_id: &str,
        from_sequence: u64,
        cancel_rx: &mut watch::Receiver<bool>,
    ) -> WalletEventResult<ReplayResult> {
        let start_time = Instant::now();
        let mut metrics = ReplayMetrics {
            total_duration: Duration::ZERO,
            loading_duration: Duration::ZERO,
            processing_duration: Duration::ZERO,
            validation_duration: Duration::ZERO,
            average_event_time: Duration::ZERO,
            peak_memory_usage: None,
            storage_queries: 0,
        };

        let mut progress = ReplayProgress {
            wallet_id: wallet_id.to_string(),
            current_sequence: from_sequence,
            total_events: None,
            events_processed: 0,
            events_applied: 0,
            events_failed: 0,
            start_time: SystemTime::now(),
            estimated_remaining: None,
            phase: ReplayPhase::Loading,
            errors: Vec::new(),
        };

        // Check for cancellation
        if *cancel_rx.borrow() {
            progress.phase = ReplayPhase::Cancelled;
            return Ok(ReplayResult {
                wallet_state: ReplayedWalletState::default(),
                progress,
                success: false,
                validation_issues: Vec::new(),
                metrics,
            });
        }

        self.report_progress(&progress);

        // Phase 1: Load events from storage
        let loading_start = Instant::now();
        let events = if from_sequence == 1 {
            self.storage.get_events_for_replay(wallet_id).await?
        } else {
            self.storage
                .get_events_for_incremental_replay(wallet_id, from_sequence)
                .await?
        };
        metrics.loading_duration = loading_start.elapsed();
        metrics.storage_queries += 1;

        progress.total_events = Some(events.len());
        self.report_progress(&progress);

        // Phase 2: Validate sequence continuity if required
        let mut validation_issues = Vec::new();
        if self.config.validate_sequence_continuity {
            progress.phase = ReplayPhase::ValidatingSequence;
            self.report_progress(&progress);

            let validation_start = Instant::now();
            validation_issues.extend(self.validate_sequence_continuity(&events, from_sequence));
            metrics.validation_duration += validation_start.elapsed();
        }

        // Phase 3: Process events in chronological order
        progress.phase = ReplayPhase::ProcessingEvents;
        self.report_progress(&progress);

        let processing_start = Instant::now();
        let mut wallet_state = ReplayedWalletState {
            wallet_id: wallet_id.to_string(),
            ..Default::default()
        };

        // Process events in batches for performance
        for batch in events.chunks(self.config.batch_size) {
            let batch_start = Instant::now();

            for stored_event in batch {
                // Check for cancellation
                if *cancel_rx.borrow() {
                    progress.phase = ReplayPhase::Cancelled;
                    metrics.total_duration = start_time.elapsed();
                    return Ok(ReplayResult {
                        wallet_state,
                        progress,
                        success: false,
                        validation_issues,
                        metrics,
                    });
                }

                // Check max events limit
                if self.config.max_events > 0 && progress.events_processed >= self.config.max_events
                {
                    break;
                }

                progress.current_sequence = stored_event.sequence_number;
                progress.events_processed += 1;

                // Parse and apply the event
                match self
                    .parse_and_apply_event(stored_event, &mut wallet_state)
                    .await
                {
                    Ok(()) => {
                        progress.events_applied += 1;
                    }
                    Err(e) => {
                        progress.events_failed += 1;
                        progress.errors.push(format!(
                            "Failed to apply event {}: {}",
                            stored_event.event_id, e
                        ));

                        validation_issues.push(ValidationIssue {
                            issue_type: ValidationIssueType::InvalidEventData,
                            description: format!("Failed to apply event: {}", e),
                            sequence_number: Some(stored_event.sequence_number),
                            event_id: Some(stored_event.event_id.clone()),
                            severity: ValidationSeverity::Error,
                        });

                        if self.config.stop_on_error {
                            progress.phase = ReplayPhase::Failed;
                            metrics.total_duration = start_time.elapsed();
                            return Ok(ReplayResult {
                                wallet_state,
                                progress,
                                success: false,
                                validation_issues,
                                metrics,
                            });
                        }
                    }
                }

                // Report progress periodically
                if progress.events_processed % self.config.progress_frequency == 0 {
                    self.update_progress_estimates(&mut progress, start_time);
                    self.report_progress(&progress);
                }

                // Yield if we've been processing for too long
                if batch_start.elapsed() > self.config.max_batch_duration {
                    tokio::task::yield_now().await;
                    break;
                }
            }

            if self.config.max_events > 0 && progress.events_processed >= self.config.max_events {
                break;
            }
        }

        metrics.processing_duration = processing_start.elapsed();

        // Calculate wallet state
        wallet_state.last_sequence = progress.current_sequence;
        wallet_state.last_updated = SystemTime::now();
        wallet_state.total_balance = wallet_state.utxos.values().map(|u| u.amount).sum();
        wallet_state.transaction_count = wallet_state.utxos.len() + wallet_state.spent_utxos.len();

        // Phase 4: Final state validation if required
        if self.config.validate_replayed_state {
            progress.phase = ReplayPhase::ValidatingState;
            self.report_progress(&progress);

            let validation_start = Instant::now();
            validation_issues.extend(self.validate_final_state(&wallet_state));
            metrics.validation_duration += validation_start.elapsed();
        }

        // Finalize metrics
        metrics.total_duration = start_time.elapsed();
        if progress.events_processed > 0 {
            metrics.average_event_time =
                metrics.processing_duration / progress.events_processed as u32;
        }

        progress.phase = ReplayPhase::Completed;
        self.report_progress(&progress);

        let success = progress.events_failed == 0;

        Ok(ReplayResult {
            wallet_state,
            progress,
            success,
            validation_issues,
            metrics,
        })
    }

    /// Parse a stored event and apply it to the wallet state
    async fn parse_and_apply_event(
        &self,
        stored_event: &StoredEvent,
        wallet_state: &mut ReplayedWalletState,
    ) -> WalletEventResult<()> {
        // Parse the stored event back into a WalletEvent
        let wallet_event: WalletEvent =
            serde_json::from_str(&stored_event.payload_json).map_err(|e| {
                WalletEventError::serialization(
                    "parse_event",
                    format!("Failed to parse event payload: {}", e),
                )
            })?;

        // Apply the event to the wallet state
        match &wallet_event {
            WalletEvent::UtxoReceived { payload, .. } => {
                let utxo_state = UtxoState {
                    utxo_id: payload.utxo_id.clone(),
                    amount: payload.amount,
                    block_height: payload.block_height,
                    transaction_hash: payload.transaction_hash.clone(),
                    output_index: payload.output_index,
                    receiving_address: payload.receiving_address.clone(),
                    key_index: payload.key_index,
                    commitment: payload.commitment.clone(),
                    received_at: SystemTime::now(), // In real implementation, use event timestamp
                    is_mature: true,                // Simplified for now
                    maturity_height: payload.maturity_height,
                };

                wallet_state
                    .utxos
                    .insert(payload.utxo_id.clone(), utxo_state);
                wallet_state.highest_block = wallet_state.highest_block.max(payload.block_height);
            }
            WalletEvent::UtxoSpent { payload, .. } => {
                // Move UTXO from unspent to spent
                if let Some(utxo) = wallet_state.utxos.remove(&payload.utxo_id) {
                    let spent_utxo = SpentUtxoState {
                        original_utxo: utxo,
                        spent_at: SystemTime::now(), // In real implementation, use event timestamp
                        spent_block_height: payload.spending_block_height,
                        spending_transaction_hash: payload.spending_transaction_hash.clone(),
                    };
                    wallet_state
                        .spent_utxos
                        .insert(payload.utxo_id.clone(), spent_utxo);
                }
                wallet_state.highest_block = wallet_state
                    .highest_block
                    .max(payload.spending_block_height);
            }
            WalletEvent::Reorg { payload, .. } => {
                // Handle blockchain reorganization
                // This is complex and would involve rolling back state
                // For now, just update highest block
                wallet_state.highest_block = payload.fork_height;

                // In a full implementation, we would:
                // 1. Identify affected UTXOs (those confirmed after fork_height)
                // 2. Remove or mark them as unconfirmed
                // 3. Handle transaction rollbacks
            }
        }

        Ok(())
    }

    /// Validate sequence continuity in the event list
    fn validate_sequence_continuity(
        &self,
        events: &[StoredEvent],
        from_sequence: u64,
    ) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();
        let mut seen_sequences = BTreeSet::new();
        let mut expected_sequence = from_sequence;

        for event in events {
            let seq = event.sequence_number;

            // Check for duplicates
            if seen_sequences.contains(&seq) {
                issues.push(ValidationIssue {
                    issue_type: ValidationIssueType::DuplicateSequence,
                    description: format!("Duplicate sequence number: {}", seq),
                    sequence_number: Some(seq),
                    event_id: Some(event.event_id.clone()),
                    severity: ValidationSeverity::Error,
                });
            }

            // Check for gaps
            if seq != expected_sequence {
                for missing in expected_sequence..seq {
                    issues.push(ValidationIssue {
                        issue_type: ValidationIssueType::MissingSequence,
                        description: format!("Missing sequence number: {}", missing),
                        sequence_number: Some(missing),
                        event_id: None,
                        severity: ValidationSeverity::Warning,
                    });
                }
            }

            seen_sequences.insert(seq);
            expected_sequence = seq + 1;
        }

        issues
    }

    /// Validate the final reconstructed wallet state
    fn validate_final_state(&self, wallet_state: &ReplayedWalletState) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        // Validate balance calculation
        let calculated_balance: u64 = wallet_state.utxos.values().map(|u| u.amount).sum();
        if calculated_balance != wallet_state.total_balance {
            issues.push(ValidationIssue {
                issue_type: ValidationIssueType::BalanceMismatch,
                description: format!(
                    "Balance mismatch: calculated {} vs stored {}",
                    calculated_balance, wallet_state.total_balance
                ),
                sequence_number: None,
                event_id: None,
                severity: ValidationSeverity::Error,
            });
        }

        // Check for any obvious inconsistencies
        for (utxo_id, utxo) in &wallet_state.utxos {
            if utxo.utxo_id != *utxo_id {
                issues.push(ValidationIssue {
                    issue_type: ValidationIssueType::InvalidEventData,
                    description: format!(
                        "UTXO ID mismatch in state: {} vs {}",
                        utxo_id, utxo.utxo_id
                    ),
                    sequence_number: None,
                    event_id: None,
                    severity: ValidationSeverity::Error,
                });
            }
        }

        issues
    }

    /// Update progress estimates based on current processing rate
    fn update_progress_estimates(&self, progress: &mut ReplayProgress, start_time: Instant) {
        if let Some(total_events) = progress.total_events {
            if progress.events_processed > 0 {
                let elapsed = start_time.elapsed();
                let events_per_second = progress.events_processed as f64 / elapsed.as_secs_f64();
                let remaining_events = total_events - progress.events_processed;

                if events_per_second > 0.0 {
                    let estimated_seconds = remaining_events as f64 / events_per_second;
                    progress.estimated_remaining = Some(Duration::from_secs_f64(estimated_seconds));
                }
            }
        }
    }

    /// Report progress to the callback if one is registered
    fn report_progress(&self, progress: &ReplayProgress) {
        if let Some(ref callback) = self.progress_callback {
            callback(progress);
        }
    }
}

/// Helper function to create a default replay engine for testing
#[cfg(feature = "storage")]
pub async fn create_test_replay_engine<S: EventStorage + Sync>(storage: S) -> EventReplayEngine<S> {
    EventReplayEngine::new(storage, ReplayConfig::default())
}

#[cfg(all(test, feature = "storage"))]
mod tests {
    use super::*;
    use crate::storage::event_storage::SqliteEventStorage;
    use tokio_rusqlite::Connection;

    async fn create_test_storage() -> SqliteEventStorage {
        let conn = Connection::open_in_memory().await.unwrap();
        SqliteEventStorage::new(conn).await.unwrap()
    }

    #[tokio::test]
    async fn test_replay_engine_creation() {
        let storage = create_test_storage().await;
        let config = ReplayConfig::default();
        let engine = EventReplayEngine::new(storage, config);

        // Engine should be created successfully
        assert!(engine.progress_callback.is_none());
    }

    #[tokio::test]
    async fn test_replay_config_builder() {
        let config = ReplayConfig::default()
            .with_batch_size(500)
            .with_progress_frequency(50)
            .with_sequence_validation(false);

        assert_eq!(config.batch_size, 500);
        assert_eq!(config.progress_frequency, 50);
        assert!(!config.validate_sequence_continuity);
    }

    #[tokio::test]
    async fn test_replay_progress_callback() {
        let storage = create_test_storage().await;
        let config = ReplayConfig::default();

        let progress_calls = Arc::new(std::sync::Mutex::new(0));
        let progress_calls_clone = Arc::clone(&progress_calls);

        let callback: ProgressCallback = Arc::new(move |_progress| {
            *progress_calls_clone.lock().unwrap() += 1;
        });

        let engine = EventReplayEngine::new(storage, config).with_progress_callback(callback);

        assert!(engine.progress_callback.is_some());
    }

    #[tokio::test]
    async fn test_validation_issue_creation() {
        let issue = ValidationIssue {
            issue_type: ValidationIssueType::MissingSequence,
            description: "Test issue".to_string(),
            sequence_number: Some(42),
            event_id: Some("test-event".to_string()),
            severity: ValidationSeverity::Warning,
        };

        assert!(matches!(
            issue.issue_type,
            ValidationIssueType::MissingSequence
        ));
        assert_eq!(issue.sequence_number, Some(42));
        assert!(matches!(issue.severity, ValidationSeverity::Warning));
    }
}
