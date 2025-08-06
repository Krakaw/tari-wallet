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
//! - **State verification**: Compare replayed state against current wallet state
//! - **Discrepancy detection**: Identify and report differences between states
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

#[cfg(feature = "storage")]
use crate::data_structures::wallet_transaction::{WalletState, WalletTransaction};
#[cfg(feature = "storage")]
use crate::events::types::{WalletEvent, WalletEventError, WalletEventResult};
#[cfg(feature = "storage")]
use crate::storage::event_storage::{EventStorage, StoredEvent};
use serde::Serialize;
#[cfg(feature = "storage")]
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(feature = "storage")]
use std::time::Instant;
use std::time::{Duration, SystemTime};
#[cfg(feature = "storage")]
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

/// Result of state verification comparing replayed state vs current state
#[derive(Debug, Clone, Serialize)]
pub struct StateVerificationResult {
    /// Whether the states match perfectly
    pub states_match: bool,
    /// Detailed comparison results
    pub comparison: StateComparison,
    /// List of discrepancies found
    pub discrepancies: Vec<StateDiscrepancy>,
    /// Summary of the verification
    pub summary: VerificationSummary,
    /// Time taken for verification
    pub verification_duration: Duration,
}

/// Detailed comparison between replayed and current wallet states
#[derive(Debug, Clone, Serialize)]
pub struct StateComparison {
    /// Balance comparison
    pub balance_comparison: BalanceComparison,
    /// UTXO comparison results
    pub utxo_comparison: UtxoComparison,
    /// Transaction count comparison
    pub transaction_comparison: TransactionComparison,
    /// General statistics comparison
    pub statistics_comparison: StatisticsComparison,
}

/// Balance comparison between states
#[derive(Debug, Clone, Serialize)]
pub struct BalanceComparison {
    /// Replayed state balance
    pub replayed_balance: u64,
    /// Current state balance
    pub current_balance: u64,
    /// Difference (replayed - current)
    pub difference: i64,
    /// Whether balances match
    pub balances_match: bool,
}

/// UTXO comparison between states
#[derive(Debug, Clone, Serialize)]
pub struct UtxoComparison {
    /// Number of UTXOs in replayed state
    pub replayed_utxo_count: usize,
    /// Number of UTXOs in current state
    pub current_utxo_count: usize,
    /// UTXOs only in replayed state
    pub only_in_replayed: Vec<String>,
    /// UTXOs only in current state
    pub only_in_current: Vec<String>,
    /// UTXOs with different values
    pub value_mismatches: Vec<UtxoValueMismatch>,
    /// Whether all UTXOs match
    pub utxos_match: bool,
}

/// UTXO value mismatch details
#[derive(Debug, Clone, Serialize)]
pub struct UtxoValueMismatch {
    /// UTXO identifier
    pub utxo_id: String,
    /// Value in replayed state
    pub replayed_value: u64,
    /// Value in current state
    pub current_value: u64,
    /// Difference
    pub difference: i64,
}

/// Transaction count comparison
#[derive(Debug, Clone, Serialize)]
pub struct TransactionComparison {
    /// Transaction count in replayed state
    pub replayed_count: usize,
    /// Transaction count in current state
    pub current_count: usize,
    /// Difference
    pub difference: i64,
    /// Whether counts match
    pub counts_match: bool,
}

/// Statistics comparison between states
#[derive(Debug, Clone, Serialize)]
pub struct StatisticsComparison {
    /// Spent UTXO count comparison
    pub spent_count_comparison: CountComparison,
    /// Unspent UTXO count comparison  
    pub unspent_count_comparison: CountComparison,
    /// Highest block comparison
    pub highest_block_comparison: CountComparison,
}

/// Generic count comparison
#[derive(Debug, Clone, Serialize)]
pub struct CountComparison {
    /// Value in replayed state
    pub replayed_value: u64,
    /// Value in current state
    pub current_value: u64,
    /// Difference
    pub difference: i64,
    /// Whether values match
    pub values_match: bool,
}

/// Types of state discrepancies
#[derive(Debug, Clone, Serialize)]
pub enum StateDiscrepancy {
    /// Balance mismatch between states
    BalanceMismatch {
        replayed: u64,
        current: u64,
        difference: i64,
    },
    /// UTXO present in replayed state but missing in current state
    MissingUtxoInCurrent {
        utxo_id: String,
        amount: u64,
        block_height: u64,
    },
    /// UTXO present in current state but missing in replayed state
    ExtraUtxoInCurrent {
        utxo_id: String,
        amount: u64,
        block_height: u64,
    },
    /// UTXO has different values in the two states
    UtxoValueMismatch {
        utxo_id: String,
        replayed_value: u64,
        current_value: u64,
    },
    /// Transaction count mismatch
    TransactionCountMismatch {
        replayed_count: usize,
        current_count: usize,
    },
    /// Different spent/unspent counts
    SpentCountMismatch {
        replayed_spent: usize,
        current_spent: usize,
        replayed_unspent: usize,
        current_unspent: usize,
    },
    /// Different highest block values
    HighestBlockMismatch {
        replayed_block: u64,
        current_block: u64,
    },
}

/// Summary of verification results
#[derive(Debug, Clone, Serialize)]
pub struct VerificationSummary {
    /// Total number of discrepancies found
    pub total_discrepancies: usize,
    /// Number of critical discrepancies (affect balance)
    pub critical_discrepancies: usize,
    /// Number of warning discrepancies (affect metadata)
    pub warning_discrepancies: usize,
    /// Overall verification status
    pub verification_status: VerificationStatus,
    /// Confidence level in the verification
    pub confidence_level: ConfidenceLevel,
}

/// Overall verification status
#[derive(Debug, Clone, Serialize)]
pub enum VerificationStatus {
    /// States match perfectly
    Perfect,
    /// Minor discrepancies that don't affect balance
    MinorIssues,
    /// Significant discrepancies affecting balance or core functionality
    MajorIssues,
    /// Critical discrepancies indicating data corruption
    Critical,
}

/// Confidence level in verification results
#[derive(Debug, Clone, Serialize)]
pub enum ConfidenceLevel {
    /// High confidence - comprehensive verification completed
    High,
    /// Medium confidence - some limitations in verification
    Medium,
    /// Low confidence - verification was incomplete or limited
    Low,
}

/// Detailed inconsistency report for replayed state analysis
#[derive(Debug, Clone, Serialize)]
pub struct InconsistencyReport {
    /// Wallet ID that was analyzed
    pub wallet_id: String,
    /// List of detected inconsistencies
    pub inconsistencies: Vec<InconsistencyIssue>,
    /// Summary of issues by severity
    pub severity_summary: SeveritySummary,
    /// Total number of issues found
    pub total_issues: usize,
    /// Time taken for detection
    pub detection_duration: Duration,
    /// Summary of the replayed state analyzed
    pub replayed_state_summary: ReplayedStateSummary,
}

/// Individual inconsistency issue detected during analysis
#[derive(Debug, Clone, Serialize)]
pub struct InconsistencyIssue {
    /// Type of inconsistency detected
    pub issue_type: InconsistencyType,
    /// Severity level of the issue
    pub severity: InconsistencySeverity,
    /// Detailed description of the issue
    pub description: String,
    /// Affected entity (UTXO ID, transaction hash, etc.)
    pub affected_entity: Option<String>,
    /// Expected value or state
    pub expected: Option<String>,
    /// Actual value or state found
    pub actual: Option<String>,
    /// Block height where issue was detected (if applicable)
    pub block_height: Option<u64>,
    /// Sequence number where issue was detected (if applicable)
    pub sequence_number: Option<u64>,
    /// Additional context or metadata
    pub context: HashMap<String, String>,
    /// Potential impact of this issue
    pub impact: InconsistencyImpact,
    /// Suggested remediation actions
    pub remediation: Vec<String>,
}

/// Types of inconsistencies that can be detected
#[derive(Debug, Clone, Serialize)]
pub enum InconsistencyType {
    /// UTXO state is internally inconsistent
    InternalStateInconsistency,
    /// Business logic violation
    LogicalInconsistency,
    /// Time-related inconsistency (events out of order, etc.)
    TemporalInconsistency,
    /// Balance calculation doesn't match UTXO values
    BalanceInconsistency,
    /// UTXO has invalid state or transitions
    UtxoStateInconsistency,
    /// Duplicate entities found
    DuplicateEntity,
    /// Missing expected data
    MissingData,
    /// Data corruption detected
    DataCorruption,
    /// Cross-reference validation failed
    CrossReferenceInconsistency,
    /// Merkle or cryptographic proof validation failed
    CryptographicInconsistency,
}

/// Severity levels for inconsistency issues
#[derive(Debug, Clone, Serialize)]
pub enum InconsistencySeverity {
    /// Critical issue that affects wallet functionality
    Critical,
    /// Major issue that affects balance or transaction accuracy
    Major,
    /// Minor issue that affects metadata or auxiliary data
    Minor,
    /// Informational notice that may indicate potential issues
    Info,
}

/// Impact assessment for inconsistency issues
#[derive(Debug, Clone, Serialize)]
pub enum InconsistencyImpact {
    /// Affects wallet balance calculations
    BalanceImpact,
    /// Affects transaction history accuracy
    TransactionHistoryImpact,
    /// Affects UTXO availability for spending
    SpendabilityImpact,
    /// Affects wallet state reconstruction
    StateReconstructionImpact,
    /// Affects audit and compliance
    AuditImpact,
    /// Performance or efficiency impact
    PerformanceImpact,
    /// No functional impact, cosmetic only
    NoFunctionalImpact,
}

/// Summary of issues categorized by severity
#[derive(Debug, Clone, Serialize)]
pub struct SeveritySummary {
    /// Number of critical issues
    pub critical_count: usize,
    /// Number of major issues
    pub major_count: usize,
    /// Number of minor issues
    pub minor_count: usize,
    /// Number of informational issues
    pub info_count: usize,
    /// Overall risk level
    pub overall_risk: RiskLevel,
    /// Whether the state is considered reliable
    pub state_reliability: StateReliability,
}

/// Overall risk level assessment
#[derive(Debug, Clone, Serialize)]
pub enum RiskLevel {
    /// High risk - critical issues that require immediate attention
    High,
    /// Medium risk - significant issues that should be addressed
    Medium,
    /// Low risk - minor issues that can be addressed as time permits
    Low,
    /// No significant risk detected
    None,
}

/// Assessment of state reliability
#[derive(Debug, Clone, Serialize)]
pub enum StateReliability {
    /// State is reliable and can be trusted
    Reliable,
    /// State has some issues but is generally trustworthy
    MostlyReliable,
    /// State has significant issues and should be used with caution
    Questionable,
    /// State is unreliable and should not be trusted
    Unreliable,
}

/// Summary of the replayed state that was analyzed
#[derive(Debug, Clone, Serialize)]
pub struct ReplayedStateSummary {
    /// Total number of UTXOs
    pub total_utxos: usize,
    /// Total number of spent UTXOs
    pub total_spent_utxos: usize,
    /// Total balance
    pub total_balance: u64,
    /// Highest block height
    pub highest_block: u64,
    /// Last sequence number
    pub last_sequence: u64,
    /// Transaction count
    pub transaction_count: usize,
    /// Analysis timestamp
    pub analyzed_at: SystemTime,
}

impl ReplayedStateSummary {
    /// Create summary from replayed wallet state
    pub fn from_state(state: &ReplayedWalletState) -> Self {
        Self {
            total_utxos: state.utxos.len(),
            total_spent_utxos: state.spent_utxos.len(),
            total_balance: state.total_balance,
            highest_block: state.highest_block,
            last_sequence: state.last_sequence,
            transaction_count: state.transaction_count,
            analyzed_at: SystemTime::now(),
        }
    }
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
                            description: format!("Failed to apply event: {e}"),
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

    /// Parse a stored event and apply it to the wallet state with comprehensive edge case handling
    async fn parse_and_apply_event(
        &self,
        stored_event: &StoredEvent,
        wallet_state: &mut ReplayedWalletState,
    ) -> WalletEventResult<()> {
        // Validate stored event metadata first
        self.validate_stored_event_metadata(stored_event, wallet_state)?;

        // Parse the stored event back into a WalletEvent with corruption detection
        let wallet_event: WalletEvent = self.parse_stored_event_safely(stored_event)?;

        // Apply the event to the wallet state with consistency checks
        self.apply_event_with_validation(&wallet_event, stored_event, wallet_state)
            .await?;

        Ok(())
    }

    /// Validate stored event metadata for corruption and consistency
    fn validate_stored_event_metadata(
        &self,
        stored_event: &StoredEvent,
        wallet_state: &ReplayedWalletState,
    ) -> WalletEventResult<()> {
        // Check for missing or empty event ID
        if stored_event.event_id.is_empty() {
            return Err(WalletEventError::InvalidMetadata {
                field: "event_id".to_string(),
                message: "Event ID cannot be empty".to_string(),
            });
        }

        // Validate wallet ID consistency
        if stored_event.wallet_id != wallet_state.wallet_id {
            return Err(WalletEventError::WalletIdMismatch {
                expected: wallet_state.wallet_id.clone(),
                actual: stored_event.wallet_id.clone(),
            });
        }

        // Validate sequence number ordering (detect gaps or duplicates)
        if stored_event.sequence_number <= wallet_state.last_sequence
            && wallet_state.last_sequence > 0
        {
            return Err(WalletEventError::SequenceError {
                expected: wallet_state.last_sequence + 1,
                actual: stored_event.sequence_number,
            });
        }

        // Check for timestamp corruption (events in the future or too far in the past)
        let now = SystemTime::now();
        if stored_event.timestamp > now {
            return Err(WalletEventError::InvalidMetadata {
                field: "timestamp".to_string(),
                message: format!(
                    "Event timestamp is in the future: {:?}",
                    stored_event.timestamp
                ),
            });
        }

        // Check for extremely old timestamps (more than 10 years ago)
        if let Ok(duration_since_epoch) = stored_event
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
        {
            let ten_years_ago = Duration::from_secs(10 * 365 * 24 * 60 * 60);
            if duration_since_epoch < ten_years_ago {
                return Err(WalletEventError::InvalidMetadata {
                    field: "timestamp".to_string(),
                    message: format!(
                        "Event timestamp is suspiciously old: {:?}",
                        stored_event.timestamp
                    ),
                });
            }
        }

        Ok(())
    }

    /// Parse stored event with enhanced corruption detection
    fn parse_stored_event_safely(
        &self,
        stored_event: &StoredEvent,
    ) -> WalletEventResult<WalletEvent> {
        // Check for empty or malformed JSON
        if stored_event.payload_json.trim().is_empty() {
            return Err(WalletEventError::DeserializationError {
                message: "Event payload JSON is empty".to_string(),
                data_snippet: "<empty>".to_string(),
            });
        }

        // Validate JSON structure before parsing
        if !stored_event.payload_json.trim().starts_with('{')
            || !stored_event.payload_json.trim().ends_with('}')
        {
            return Err(WalletEventError::DeserializationError {
                message: "Event payload is not valid JSON object".to_string(),
                data_snippet: Self::get_data_snippet(&stored_event.payload_json),
            });
        }

        // Parse with detailed error reporting
        let wallet_event: WalletEvent =
            serde_json::from_str(&stored_event.payload_json).map_err(|e| {
                WalletEventError::DeserializationError {
                    message: format!("Failed to parse event payload: {e}"),
                    data_snippet: Self::get_data_snippet(&stored_event.payload_json),
                }
            })?;

        // Additional validation of parsed event structure
        self.validate_parsed_event(&wallet_event, stored_event)?;

        Ok(wallet_event)
    }

    /// Validate parsed event for logical consistency
    fn validate_parsed_event(
        &self,
        wallet_event: &WalletEvent,
        stored_event: &StoredEvent,
    ) -> WalletEventResult<()> {
        match wallet_event {
            WalletEvent::UtxoReceived { metadata, payload } => {
                // Validate metadata consistency
                if metadata.event_id != stored_event.event_id {
                    return Err(WalletEventError::InvalidMetadata {
                        field: "event_id".to_string(),
                        message: "Event ID mismatch between stored and parsed event".to_string(),
                    });
                }

                // Validate payload data
                if payload.amount == 0 {
                    return Err(WalletEventError::InvalidAmount {
                        amount: payload.amount.to_string(),
                        reason: "UTXO amount cannot be zero".to_string(),
                    });
                }

                if payload.utxo_id.is_empty() {
                    return Err(WalletEventError::InvalidPayload {
                        event_type: "UtxoReceived".to_string(),
                        field: "utxo_id".to_string(),
                        message: "UTXO ID cannot be empty".to_string(),
                    });
                }

                // Validate block height consistency
                if payload.block_height == 0 {
                    return Err(WalletEventError::InvalidBlockHeight {
                        height: payload.block_height,
                        reason: "Block height cannot be zero".to_string(),
                    });
                }
            }
            WalletEvent::UtxoSpent { metadata, payload } => {
                // Similar validation for spent events
                if metadata.event_id != stored_event.event_id {
                    return Err(WalletEventError::InvalidMetadata {
                        field: "event_id".to_string(),
                        message: "Event ID mismatch between stored and parsed event".to_string(),
                    });
                }

                if payload.utxo_id.is_empty() {
                    return Err(WalletEventError::InvalidPayload {
                        event_type: "UtxoSpent".to_string(),
                        field: "utxo_id".to_string(),
                        message: "UTXO ID cannot be empty".to_string(),
                    });
                }

                if payload.spending_transaction_hash.is_empty() {
                    return Err(WalletEventError::InvalidPayload {
                        event_type: "UtxoSpent".to_string(),
                        field: "spending_transaction_hash".to_string(),
                        message: "Spending transaction hash cannot be empty".to_string(),
                    });
                }
            }
            WalletEvent::Reorg { metadata, payload } => {
                if metadata.event_id != stored_event.event_id {
                    return Err(WalletEventError::InvalidMetadata {
                        field: "event_id".to_string(),
                        message: "Event ID mismatch between stored and parsed event".to_string(),
                    });
                }

                if payload.rollback_depth == 0 && payload.new_blocks_count == 0 {
                    return Err(WalletEventError::InvalidPayload {
                        event_type: "Reorg".to_string(),
                        field: "reorg_counts".to_string(),
                        message: "Invalid reorg: both rollback_depth and new_blocks_count are zero"
                            .to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Apply event with validation and consistency checks
    async fn apply_event_with_validation(
        &self,
        wallet_event: &WalletEvent,
        stored_event: &StoredEvent,
        wallet_state: &mut ReplayedWalletState,
    ) -> WalletEventResult<()> {
        match &wallet_event {
            WalletEvent::UtxoReceived { payload, .. } => {
                // Check for duplicate UTXO IDs
                if wallet_state.utxos.contains_key(&payload.utxo_id) {
                    return Err(WalletEventError::ProcessingError {
                        event_type: "UtxoReceived".to_string(),
                        reason: format!("UTXO {} already exists in wallet state", payload.utxo_id),
                    });
                }

                // Check if this UTXO was previously spent (resurrection scenario)
                if wallet_state.spent_utxos.contains_key(&payload.utxo_id) {
                    return Err(WalletEventError::ProcessingError {
                        event_type: "UtxoReceived".to_string(),
                        reason: format!(
                            "UTXO {} was previously spent and cannot be received again",
                            payload.utxo_id
                        ),
                    });
                }

                // Validate block height progression
                if payload.block_height < wallet_state.highest_block
                    && wallet_state.highest_block > 0
                {
                    // This might be valid due to reorgs, but we should warn
                    // For now, we'll allow it but could add to validation issues
                }

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
                // Check if UTXO exists and is available for spending
                if !wallet_state.utxos.contains_key(&payload.utxo_id) {
                    // Check if it was already spent
                    if wallet_state.spent_utxos.contains_key(&payload.utxo_id) {
                        return Err(WalletEventError::ProcessingError {
                            event_type: "UtxoSpent".to_string(),
                            reason: format!(
                                "UTXO {} is already spent (double spend attempt)",
                                payload.utxo_id
                            ),
                        });
                    } else {
                        return Err(WalletEventError::ProcessingError {
                            event_type: "UtxoSpent".to_string(),
                            reason: format!("UTXO {} not found in wallet state", payload.utxo_id),
                        });
                    }
                }

                // Validate spending block height
                if let Some(utxo) = wallet_state.utxos.get(&payload.utxo_id) {
                    if payload.spending_block_height < utxo.block_height {
                        return Err(WalletEventError::ProcessingError {
                            event_type: "UtxoSpent".to_string(),
                            reason: format!(
                                "Invalid spending block height {} for UTXO confirmed at height {}",
                                payload.spending_block_height, utxo.block_height
                            ),
                        });
                    }

                    // Check if UTXO is mature enough to be spent
                    if let Some(maturity_height) = utxo.maturity_height {
                        if payload.spending_block_height < maturity_height {
                            return Err(WalletEventError::ProcessingError {
                                event_type: "UtxoSpent".to_string(),
                                reason: format!(
                                    "UTXO {} cannot be spent at height {} (matures at height {})",
                                    payload.utxo_id, payload.spending_block_height, maturity_height
                                ),
                            });
                        }
                    }
                }

                // Move UTXO from unspent to spent
                if let Some(utxo) = wallet_state.utxos.remove(&payload.utxo_id) {
                    let spent_utxo = SpentUtxoState {
                        original_utxo: utxo,
                        spent_at: stored_event.timestamp,
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
                // Validate reorg parameters
                if payload.fork_height > wallet_state.highest_block {
                    return Err(WalletEventError::ProcessingError {
                        event_type: "Reorg".to_string(),
                        reason: format!(
                            "Reorg fork height {} is higher than current highest block {}",
                            payload.fork_height, wallet_state.highest_block
                        ),
                    });
                }

                // Handle blockchain reorganization with partial state recovery
                let affected_utxos: Vec<String> = wallet_state
                    .utxos
                    .iter()
                    .filter(|(_, utxo)| utxo.block_height > payload.fork_height)
                    .map(|(id, _)| id.clone())
                    .collect();

                let affected_spent_utxos: Vec<String> = wallet_state
                    .spent_utxos
                    .iter()
                    .filter(|(_, spent_utxo)| spent_utxo.spent_block_height > payload.fork_height)
                    .map(|(id, _)| id.clone())
                    .collect();

                // Remove or rollback affected UTXOs
                for utxo_id in affected_utxos {
                    if let Some(_utxo) = wallet_state.utxos.remove(&utxo_id) {
                        // In a real implementation, we might add these to a "pending" state
                        // For now, we'll remove them completely
                        // Could log this as a validation issue if we want to track it
                    }
                }

                // Restore UTXOs that were spent after the fork point
                for utxo_id in affected_spent_utxos {
                    if let Some(spent_utxo) = wallet_state.spent_utxos.remove(&utxo_id) {
                        // Only restore if the original UTXO was confirmed before the fork
                        if spent_utxo.original_utxo.block_height <= payload.fork_height {
                            wallet_state.utxos.insert(utxo_id, spent_utxo.original_utxo);
                        }
                        // If the original UTXO was also after the fork, it's completely invalid
                    }
                }

                // Update highest block to fork height
                wallet_state.highest_block = payload.fork_height;

                // Update affected transaction hashes list if provided
                for tx_hash in &payload.affected_transaction_hashes {
                    // In a full implementation, we would invalidate these transactions
                    // and potentially remove related UTXOs
                    if tx_hash.is_empty() {
                        return Err(WalletEventError::InvalidPayload {
                            event_type: "Reorg".to_string(),
                            field: "affected_transaction_hashes".to_string(),
                            message: "Empty transaction hash in affected list".to_string(),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Get a snippet of data for error reporting (truncate if too long)
    fn get_data_snippet(data: &str) -> String {
        const MAX_SNIPPET_LENGTH: usize = 100;
        if data.len() <= MAX_SNIPPET_LENGTH {
            data.to_string()
        } else {
            format!("{}...", &data[..MAX_SNIPPET_LENGTH])
        }
    }

    /// Handle missing events by attempting partial state reconstruction
    pub async fn handle_missing_events(
        &self,
        wallet_id: &str,
        missing_sequences: &[u64],
    ) -> WalletEventResult<MissingEventReport> {
        let mut report = MissingEventReport {
            wallet_id: wallet_id.to_string(),
            missing_sequences: missing_sequences.to_vec(),
            recovery_attempts: Vec::new(),
            recovered_events: 0,
            unrecoverable_events: 0,
            partial_state_possible: false,
            recommendations: Vec::new(),
        };

        // Attempt to identify the impact of missing events
        for &sequence in missing_sequences {
            let recovery_attempt = self.attempt_event_recovery(wallet_id, sequence).await?;

            if recovery_attempt.recoverable {
                report.recovered_events += 1;
                report.partial_state_possible = true;
            } else {
                report.unrecoverable_events += 1;
            }

            report.recovery_attempts.push(recovery_attempt);
        }

        // Generate recommendations based on analysis
        self.generate_recovery_recommendations(&mut report);

        Ok(report)
    }

    /// Attempt to recover a single missing event
    async fn attempt_event_recovery(
        &self,
        wallet_id: &str,
        sequence_number: u64,
    ) -> WalletEventResult<EventRecoveryAttempt> {
        // Try to infer the missing event from surrounding context
        let before_events = self
            .storage
            .get_wallet_events_in_range(
                wallet_id,
                sequence_number.saturating_sub(5),
                sequence_number - 1,
            )
            .await?;

        let after_events = self
            .storage
            .get_wallet_events_in_range(wallet_id, sequence_number + 1, sequence_number + 5)
            .await?;

        let recovery_attempt = EventRecoveryAttempt {
            sequence_number,
            recoverable: false,
            recovery_method: RecoveryMethod::None,
            confidence_level: RecoveryConfidence::None,
            inferred_event_type: None,
            impact_assessment: self.assess_missing_event_impact(&before_events, &after_events),
            recommendations: Vec::new(),
        };

        // For now, we'll mark most events as unrecoverable
        // In a full implementation, we might be able to infer some events
        // based on UTXO state changes in subsequent events

        Ok(recovery_attempt)
    }

    /// Assess the impact of a missing event based on surrounding events
    fn assess_missing_event_impact(
        &self,
        _before_events: &[StoredEvent],
        _after_events: &[StoredEvent],
    ) -> MissingEventImpact {
        // Simplified impact assessment
        // In a real implementation, we would analyze:
        // 1. UTXO state changes
        // 2. Balance implications
        // 3. Transaction continuity
        MissingEventImpact::Unknown
    }

    /// Generate recovery recommendations based on missing event analysis
    fn generate_recovery_recommendations(&self, report: &mut MissingEventReport) {
        if report.unrecoverable_events > 0 {
            report
                .recommendations
                .push("Manual intervention required for unrecoverable events".to_string());

            if report.unrecoverable_events > report.recovered_events {
                report
                    .recommendations
                    .push("Consider restoring from backup or re-scanning blockchain".to_string());
            }
        }

        if report.recovered_events > 0 {
            report
                .recommendations
                .push("Partial state reconstruction possible with recovered events".to_string());
        }

        if report.missing_sequences.len() > 10 {
            report.recommendations.push(
                "Large number of missing events detected - database corruption likely".to_string(),
            );
        }
    }

    /// Detect and handle corrupted data during replay
    pub async fn detect_corruption(
        &self,
        wallet_id: &str,
        events: &[StoredEvent],
    ) -> WalletEventResult<CorruptionReport> {
        let mut report = CorruptionReport {
            wallet_id: wallet_id.to_string(),
            total_events_checked: events.len(),
            corrupted_events: Vec::new(),
            corruption_patterns: Vec::new(),
            severity_level: CorruptionSeverity::None,
            data_integrity_score: 1.0,
            recovery_possible: true,
            recommendations: Vec::new(),
        };

        // Check each event for corruption indicators
        for event in events {
            if let Some(corruption) = self.check_event_corruption(event).await? {
                report.corrupted_events.push(corruption);
            }
        }

        // Analyze corruption patterns
        self.analyze_corruption_patterns(&mut report);

        // Calculate data integrity score
        report.data_integrity_score = self.calculate_integrity_score(&report);

        // Determine recovery feasibility
        report.recovery_possible = self.assess_recovery_feasibility(&report);

        // Generate recommendations
        self.generate_corruption_recommendations(&mut report);

        Ok(report)
    }

    /// Check a single event for corruption indicators
    async fn check_event_corruption(
        &self,
        event: &StoredEvent,
    ) -> WalletEventResult<Option<CorruptedEvent>> {
        let mut corruption_indicators = Vec::new();

        // Check for JSON corruption
        if serde_json::from_str::<serde_json::Value>(&event.payload_json).is_err() {
            corruption_indicators.push(CorruptionIndicator::MalformedJson);
        }

        // Check for timestamp corruption
        if event.timestamp > SystemTime::now() {
            corruption_indicators.push(CorruptionIndicator::InvalidTimestamp);
        }

        // Check for empty required fields
        if event.event_id.is_empty() || event.wallet_id.is_empty() {
            corruption_indicators.push(CorruptionIndicator::MissingRequiredFields);
        }

        // Check for suspicious sequence numbers
        if event.sequence_number == 0 {
            corruption_indicators.push(CorruptionIndicator::InvalidSequenceNumber);
        }

        if !corruption_indicators.is_empty() {
            let severity = self.determine_corruption_severity(&corruption_indicators);
            let recoverable = self.is_corruption_recoverable(&corruption_indicators);
            return Ok(Some(CorruptedEvent {
                event_id: event.event_id.clone(),
                sequence_number: event.sequence_number,
                corruption_indicators,
                severity,
                recoverable,
            }));
        }

        Ok(None)
    }

    /// Analyze patterns in detected corruption
    fn analyze_corruption_patterns(&self, report: &mut CorruptionReport) {
        if report.corrupted_events.is_empty() {
            return;
        }

        // Check for systematic corruption patterns
        let sequence_numbers: Vec<u64> = report
            .corrupted_events
            .iter()
            .map(|e| e.sequence_number)
            .collect();

        // Check for consecutive corruption
        let mut consecutive_count = 0;
        for window in sequence_numbers.windows(2) {
            if window[1] == window[0] + 1 {
                consecutive_count += 1;
            }
        }

        if consecutive_count > 2 {
            report
                .corruption_patterns
                .push(CorruptionPattern::ConsecutiveEvents);
        }

        // Check for corruption by type
        let json_corruption_count = report
            .corrupted_events
            .iter()
            .filter(|e| {
                e.corruption_indicators
                    .contains(&CorruptionIndicator::MalformedJson)
            })
            .count();

        if json_corruption_count > report.corrupted_events.len() / 2 {
            report
                .corruption_patterns
                .push(CorruptionPattern::SystematicJsonCorruption);
        }

        // Determine overall severity
        let critical_count = report
            .corrupted_events
            .iter()
            .filter(|e| matches!(e.severity, EventCorruptionSeverity::Critical))
            .count();

        report.severity_level = if critical_count > 0 {
            CorruptionSeverity::Critical
        } else if report.corrupted_events.len() > 5 {
            CorruptionSeverity::Major
        } else if report.corrupted_events.len() > 1 {
            CorruptionSeverity::Minor
        } else {
            CorruptionSeverity::None
        };
    }

    /// Calculate data integrity score (0.0 = completely corrupted, 1.0 = perfect)
    fn calculate_integrity_score(&self, report: &CorruptionReport) -> f64 {
        if report.total_events_checked == 0 {
            return 1.0;
        }

        let corruption_ratio =
            report.corrupted_events.len() as f64 / report.total_events_checked as f64;
        let base_score = 1.0 - corruption_ratio;

        // Adjust based on severity
        let severity_penalty = match report.severity_level {
            CorruptionSeverity::Critical => 0.5,
            CorruptionSeverity::Major => 0.3,
            CorruptionSeverity::Minor => 0.1,
            CorruptionSeverity::None => 0.0,
        };

        (base_score - severity_penalty).max(0.0)
    }

    /// Assess whether recovery is feasible given the corruption level
    fn assess_recovery_feasibility(&self, report: &CorruptionReport) -> bool {
        match report.severity_level {
            CorruptionSeverity::Critical => false,
            CorruptionSeverity::Major => report.data_integrity_score > 0.3,
            CorruptionSeverity::Minor => true,
            CorruptionSeverity::None => true,
        }
    }

    /// Generate recommendations for handling corruption
    fn generate_corruption_recommendations(&self, report: &mut CorruptionReport) {
        match report.severity_level {
            CorruptionSeverity::Critical => {
                report.recommendations.push(
                    "Critical corruption detected - database restore from backup required"
                        .to_string(),
                );
                report
                    .recommendations
                    .push("Do not attempt replay with current data".to_string());
            }
            CorruptionSeverity::Major => {
                report.recommendations.push(
                    "Major corruption detected - attempt partial recovery with caution".to_string(),
                );
                report
                    .recommendations
                    .push("Consider blockchain re-scan to recover missing data".to_string());
            }
            CorruptionSeverity::Minor => {
                report.recommendations.push(
                    "Minor corruption detected - replay may proceed with validation".to_string(),
                );
                report
                    .recommendations
                    .push("Monitor for additional issues during replay".to_string());
            }
            CorruptionSeverity::None => {
                report
                    .recommendations
                    .push("No corruption detected - replay can proceed normally".to_string());
            }
        }

        if report
            .corruption_patterns
            .contains(&CorruptionPattern::SystematicJsonCorruption)
        {
            report
                .recommendations
                .push("Systematic JSON corruption suggests storage subsystem issues".to_string());
        }
    }

    /// Determine corruption severity for a set of indicators
    fn determine_corruption_severity(
        &self,
        indicators: &[CorruptionIndicator],
    ) -> EventCorruptionSeverity {
        if indicators.contains(&CorruptionIndicator::MalformedJson) {
            EventCorruptionSeverity::Critical
        } else if indicators.contains(&CorruptionIndicator::MissingRequiredFields) {
            EventCorruptionSeverity::Major
        } else {
            EventCorruptionSeverity::Minor
        }
    }

    /// Check if corruption is recoverable
    fn is_corruption_recoverable(&self, indicators: &[CorruptionIndicator]) -> bool {
        !indicators.contains(&CorruptionIndicator::MalformedJson)
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
                    description: format!("Duplicate sequence number: {seq}"),
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
                        description: format!("Missing sequence number: {missing}"),
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

    /// Detect internal state inconsistencies within the replayed state
    fn detect_internal_inconsistencies(
        &self,
        state: &ReplayedWalletState,
        inconsistencies: &mut Vec<InconsistencyIssue>,
    ) {
        // Check if UTXO IDs match their HashMap keys
        for (key, utxo) in &state.utxos {
            if key != &utxo.utxo_id {
                inconsistencies.push(InconsistencyIssue {
                    issue_type: InconsistencyType::InternalStateInconsistency,
                    severity: InconsistencySeverity::Major,
                    description: format!(
                        "UTXO ID mismatch: HashMap key '{}' does not match UTXO ID '{}'",
                        key, utxo.utxo_id
                    ),
                    affected_entity: Some(key.clone()),
                    expected: Some(key.clone()),
                    actual: Some(utxo.utxo_id.clone()),
                    block_height: Some(utxo.block_height),
                    sequence_number: None,
                    context: HashMap::from([
                        ("utxo_amount".to_string(), utxo.amount.to_string()),
                        ("block_height".to_string(), utxo.block_height.to_string()),
                    ]),
                    impact: InconsistencyImpact::StateReconstructionImpact,
                    remediation: vec![
                        "Verify event replay logic".to_string(),
                        "Check UTXO creation process".to_string(),
                    ],
                });
            }
        }

        // Check spent UTXOs for similar inconsistencies
        for (key, spent_utxo) in &state.spent_utxos {
            if key != &spent_utxo.original_utxo.utxo_id {
                inconsistencies.push(InconsistencyIssue {
                    issue_type: InconsistencyType::InternalStateInconsistency,
                    severity: InconsistencySeverity::Major,
                    description: format!(
                        "Spent UTXO ID mismatch: HashMap key '{}' does not match original UTXO ID '{}'",
                        key, spent_utxo.original_utxo.utxo_id
                    ),
                    affected_entity: Some(key.clone()),
                    expected: Some(key.clone()),
                    actual: Some(spent_utxo.original_utxo.utxo_id.clone()),
                    block_height: Some(spent_utxo.spent_block_height),
                    sequence_number: None,
                    context: HashMap::from([
                        ("original_amount".to_string(), spent_utxo.original_utxo.amount.to_string()),
                        ("spent_block".to_string(), spent_utxo.spent_block_height.to_string()),
                    ]),
                    impact: InconsistencyImpact::StateReconstructionImpact,
                    remediation: vec![
                        "Verify spent UTXO tracking logic".to_string(),
                        "Check event application order".to_string(),
                    ],
                });
            }
        }
    }

    /// Detect logical inconsistencies in business rules
    fn detect_logical_inconsistencies(
        &self,
        state: &ReplayedWalletState,
        inconsistencies: &mut Vec<InconsistencyIssue>,
    ) {
        // Check for impossible maturity states
        for utxo in state.utxos.values() {
            if let Some(maturity_height) = utxo.maturity_height {
                if utxo.is_mature && utxo.block_height < maturity_height {
                    inconsistencies.push(InconsistencyIssue {
                        issue_type: InconsistencyType::LogicalInconsistency,
                        severity: InconsistencySeverity::Major,
                        description: format!(
                            "UTXO marked as mature but block height {} is less than maturity height {}",
                            utxo.block_height, maturity_height
                        ),
                        affected_entity: Some(utxo.utxo_id.clone()),
                        expected: Some("is_mature should be false".to_string()),
                        actual: Some("is_mature is true".to_string()),
                        block_height: Some(utxo.block_height),
                        sequence_number: None,
                        context: HashMap::from([
                            ("maturity_height".to_string(), maturity_height.to_string()),
                            ("amount".to_string(), utxo.amount.to_string()),
                        ]),
                        impact: InconsistencyImpact::SpendabilityImpact,
                        remediation: vec![
                            "Verify maturity calculation logic".to_string(),
                            "Check coinbase transaction handling".to_string(),
                        ],
                    });
                }
            }

            // Check for zero-value UTXOs
            if utxo.amount == 0 {
                inconsistencies.push(InconsistencyIssue {
                    issue_type: InconsistencyType::LogicalInconsistency,
                    severity: InconsistencySeverity::Minor,
                    description: "UTXO has zero value".to_string(),
                    affected_entity: Some(utxo.utxo_id.clone()),
                    expected: Some("amount > 0".to_string()),
                    actual: Some("amount = 0".to_string()),
                    block_height: Some(utxo.block_height),
                    sequence_number: None,
                    context: HashMap::from([
                        (
                            "transaction_hash".to_string(),
                            utxo.transaction_hash.clone(),
                        ),
                        ("output_index".to_string(), utxo.output_index.to_string()),
                    ]),
                    impact: InconsistencyImpact::BalanceImpact,
                    remediation: vec![
                        "Verify transaction parsing logic".to_string(),
                        "Check for dust transactions".to_string(),
                    ],
                });
            }
        }

        // Check for duplicate UTXOs across unspent and spent collections
        for utxo_id in state.utxos.keys() {
            if state.spent_utxos.contains_key(utxo_id) {
                inconsistencies.push(InconsistencyIssue {
                    issue_type: InconsistencyType::LogicalInconsistency,
                    severity: InconsistencySeverity::Critical,
                    description: format!(
                        "UTXO {utxo_id} exists in both unspent and spent collections"
                    ),
                    affected_entity: Some(utxo_id.clone()),
                    expected: Some("UTXO should be in only one collection".to_string()),
                    actual: Some("UTXO exists in both collections".to_string()),
                    block_height: None,
                    sequence_number: None,
                    context: HashMap::new(),
                    impact: InconsistencyImpact::BalanceImpact,
                    remediation: vec![
                        "Fix UTXO state transition logic".to_string(),
                        "Ensure proper move from unspent to spent".to_string(),
                    ],
                });
            }
        }
    }

    /// Detect temporal inconsistencies in event ordering and timestamps
    fn detect_temporal_inconsistencies(
        &self,
        state: &ReplayedWalletState,
        inconsistencies: &mut Vec<InconsistencyIssue>,
    ) {
        // Check that spent UTXOs were spent after they were received
        for spent_utxo in state.spent_utxos.values() {
            if spent_utxo.spent_at < spent_utxo.original_utxo.received_at {
                inconsistencies.push(InconsistencyIssue {
                    issue_type: InconsistencyType::TemporalInconsistency,
                    severity: InconsistencySeverity::Major,
                    description: format!(
                        "UTXO {} was spent before it was received",
                        spent_utxo.original_utxo.utxo_id
                    ),
                    affected_entity: Some(spent_utxo.original_utxo.utxo_id.clone()),
                    expected: Some("spent_at > received_at".to_string()),
                    actual: Some("spent_at < received_at".to_string()),
                    block_height: Some(spent_utxo.spent_block_height),
                    sequence_number: None,
                    context: HashMap::from([
                        (
                            "received_at".to_string(),
                            format!("{:?}", spent_utxo.original_utxo.received_at),
                        ),
                        ("spent_at".to_string(), format!("{:?}", spent_utxo.spent_at)),
                    ]),
                    impact: InconsistencyImpact::TransactionHistoryImpact,
                    remediation: vec![
                        "Check event timestamp assignments".to_string(),
                        "Verify chronological event processing".to_string(),
                    ],
                });
            }

            // Check that spending block height is not less than receiving block height
            if spent_utxo.spent_block_height < spent_utxo.original_utxo.block_height {
                inconsistencies.push(InconsistencyIssue {
                    issue_type: InconsistencyType::TemporalInconsistency,
                    severity: InconsistencySeverity::Critical,
                    description: format!(
                        "UTXO {} was spent at block {} before it was confirmed at block {}",
                        spent_utxo.original_utxo.utxo_id,
                        spent_utxo.spent_block_height,
                        spent_utxo.original_utxo.block_height
                    ),
                    affected_entity: Some(spent_utxo.original_utxo.utxo_id.clone()),
                    expected: Some("spent_block_height >= received_block_height".to_string()),
                    actual: Some("spent_block_height < received_block_height".to_string()),
                    block_height: Some(spent_utxo.spent_block_height),
                    sequence_number: None,
                    context: HashMap::from([
                        (
                            "received_block".to_string(),
                            spent_utxo.original_utxo.block_height.to_string(),
                        ),
                        (
                            "spent_block".to_string(),
                            spent_utxo.spent_block_height.to_string(),
                        ),
                    ]),
                    impact: InconsistencyImpact::TransactionHistoryImpact,
                    remediation: vec![
                        "Verify blockchain synchronization".to_string(),
                        "Check for reorganization handling errors".to_string(),
                    ],
                });
            }
        }
    }

    /// Detect balance calculation inconsistencies
    fn detect_balance_inconsistencies(
        &self,
        state: &ReplayedWalletState,
        inconsistencies: &mut Vec<InconsistencyIssue>,
    ) {
        // Calculate balance from UTXOs and compare with stored balance
        let calculated_balance: u64 = state.utxos.values().map(|u| u.amount).sum();

        if calculated_balance != state.total_balance {
            inconsistencies.push(InconsistencyIssue {
                issue_type: InconsistencyType::BalanceInconsistency,
                severity: InconsistencySeverity::Critical,
                description: format!(
                    "Total balance mismatch: calculated {} vs stored {}",
                    calculated_balance, state.total_balance
                ),
                affected_entity: Some(state.wallet_id.clone()),
                expected: Some(calculated_balance.to_string()),
                actual: Some(state.total_balance.to_string()),
                block_height: None,
                sequence_number: None,
                context: HashMap::from([
                    ("utxo_count".to_string(), state.utxos.len().to_string()),
                    (
                        "difference".to_string(),
                        (calculated_balance as i64 - state.total_balance as i64).to_string(),
                    ),
                ]),
                impact: InconsistencyImpact::BalanceImpact,
                remediation: vec![
                    "Recalculate balance from UTXOs".to_string(),
                    "Verify balance update logic in event processing".to_string(),
                ],
            });
        }

        // Check for any UTXOs with amounts that would cause overflow
        for utxo in state.utxos.values() {
            if utxo.amount > u64::MAX / 2 {
                // Conservative check for potential overflow
                inconsistencies.push(InconsistencyIssue {
                    issue_type: InconsistencyType::BalanceInconsistency,
                    severity: InconsistencySeverity::Major,
                    description: format!(
                        "UTXO {} has suspiciously large amount: {}",
                        utxo.utxo_id, utxo.amount
                    ),
                    affected_entity: Some(utxo.utxo_id.clone()),
                    expected: Some("reasonable amount < u64::MAX/2".to_string()),
                    actual: Some(utxo.amount.to_string()),
                    block_height: Some(utxo.block_height),
                    sequence_number: None,
                    context: HashMap::from([(
                        "transaction_hash".to_string(),
                        utxo.transaction_hash.clone(),
                    )]),
                    impact: InconsistencyImpact::BalanceImpact,
                    remediation: vec![
                        "Verify transaction amount parsing".to_string(),
                        "Check for data corruption".to_string(),
                    ],
                });
            }
        }
    }

    /// Detect UTXO state inconsistencies
    fn detect_utxo_state_inconsistencies(
        &self,
        state: &ReplayedWalletState,
        inconsistencies: &mut Vec<InconsistencyIssue>,
    ) {
        // Check for missing required fields
        for utxo in state.utxos.values() {
            if utxo.utxo_id.is_empty() {
                inconsistencies.push(InconsistencyIssue {
                    issue_type: InconsistencyType::UtxoStateInconsistency,
                    severity: InconsistencySeverity::Critical,
                    description: "UTXO has empty UTXO ID".to_string(),
                    affected_entity: None,
                    expected: Some("non-empty UTXO ID".to_string()),
                    actual: Some("empty string".to_string()),
                    block_height: Some(utxo.block_height),
                    sequence_number: None,
                    context: HashMap::from([
                        ("amount".to_string(), utxo.amount.to_string()),
                        (
                            "transaction_hash".to_string(),
                            utxo.transaction_hash.clone(),
                        ),
                    ]),
                    impact: InconsistencyImpact::StateReconstructionImpact,
                    remediation: vec![
                        "Fix UTXO ID generation logic".to_string(),
                        "Verify event payload construction".to_string(),
                    ],
                });
            }

            if utxo.transaction_hash.is_empty() {
                inconsistencies.push(InconsistencyIssue {
                    issue_type: InconsistencyType::UtxoStateInconsistency,
                    severity: InconsistencySeverity::Major,
                    description: format!("UTXO {} has empty transaction hash", utxo.utxo_id),
                    affected_entity: Some(utxo.utxo_id.clone()),
                    expected: Some("non-empty transaction hash".to_string()),
                    actual: Some("empty string".to_string()),
                    block_height: Some(utxo.block_height),
                    sequence_number: None,
                    context: HashMap::new(),
                    impact: InconsistencyImpact::TransactionHistoryImpact,
                    remediation: vec![
                        "Fix transaction hash tracking".to_string(),
                        "Verify blockchain data extraction".to_string(),
                    ],
                });
            }

            if utxo.commitment.is_empty() {
                inconsistencies.push(InconsistencyIssue {
                    issue_type: InconsistencyType::UtxoStateInconsistency,
                    severity: InconsistencySeverity::Major,
                    description: format!("UTXO {} has empty commitment", utxo.utxo_id),
                    affected_entity: Some(utxo.utxo_id.clone()),
                    expected: Some("non-empty commitment".to_string()),
                    actual: Some("empty string".to_string()),
                    block_height: Some(utxo.block_height),
                    sequence_number: None,
                    context: HashMap::new(),
                    impact: InconsistencyImpact::SpendabilityImpact,
                    remediation: vec![
                        "Fix commitment extraction logic".to_string(),
                        "Verify cryptographic data handling".to_string(),
                    ],
                });
            }
        }
    }

    /// Categorize inconsistencies by severity and assess overall risk
    fn categorize_inconsistency_severity(
        &self,
        inconsistencies: &[InconsistencyIssue],
    ) -> SeveritySummary {
        let mut critical_count = 0;
        let mut major_count = 0;
        let mut minor_count = 0;
        let mut info_count = 0;

        for issue in inconsistencies {
            match issue.severity {
                InconsistencySeverity::Critical => critical_count += 1,
                InconsistencySeverity::Major => major_count += 1,
                InconsistencySeverity::Minor => minor_count += 1,
                InconsistencySeverity::Info => info_count += 1,
            }
        }

        let overall_risk = if critical_count > 0 {
            RiskLevel::High
        } else if major_count > 0 {
            RiskLevel::Medium
        } else if minor_count > 0 {
            RiskLevel::Low
        } else {
            RiskLevel::None
        };

        let state_reliability = if critical_count > 0 {
            StateReliability::Unreliable
        } else if major_count > 2 {
            StateReliability::Questionable
        } else if major_count > 0 || minor_count > 5 {
            StateReliability::MostlyReliable
        } else {
            StateReliability::Reliable
        };

        SeveritySummary {
            critical_count,
            major_count,
            minor_count,
            info_count,
            overall_risk,
            state_reliability,
        }
    }

    /// Generate a detailed human-readable report from inconsistency results
    pub fn generate_detailed_report(&self, report: &InconsistencyReport) -> String {
        let mut output = String::new();

        output.push_str("# Wallet Event Replay Inconsistency Report\n\n");
        output.push_str(&format!("**Wallet ID:** {}\n", report.wallet_id));
        output.push_str(&format!(
            "**Analysis Duration:** {:?}\n",
            report.detection_duration
        ));
        output.push_str(&format!(
            "**Total Issues Found:** {}\n\n",
            report.total_issues
        ));

        // Risk assessment summary
        output.push_str("## Risk Assessment\n\n");
        output.push_str(&format!(
            "**Overall Risk Level:** {:?}\n",
            report.severity_summary.overall_risk
        ));
        output.push_str(&format!(
            "**State Reliability:** {:?}\n\n",
            report.severity_summary.state_reliability
        ));

        // Issue severity breakdown
        output.push_str("## Issue Severity Breakdown\n\n");
        output.push_str(&format!(
            "- **Critical:** {} issues\n",
            report.severity_summary.critical_count
        ));
        output.push_str(&format!(
            "- **Major:** {} issues\n",
            report.severity_summary.major_count
        ));
        output.push_str(&format!(
            "- **Minor:** {} issues\n",
            report.severity_summary.minor_count
        ));
        output.push_str(&format!(
            "- **Info:** {} issues\n\n",
            report.severity_summary.info_count
        ));

        // State summary
        output.push_str("## Replayed State Summary\n\n");
        output.push_str(&format!(
            "- **Total UTXOs:** {}\n",
            report.replayed_state_summary.total_utxos
        ));
        output.push_str(&format!(
            "- **Spent UTXOs:** {}\n",
            report.replayed_state_summary.total_spent_utxos
        ));
        output.push_str(&format!(
            "- **Total Balance:** {} microTari\n",
            report.replayed_state_summary.total_balance
        ));
        output.push_str(&format!(
            "- **Highest Block:** {}\n",
            report.replayed_state_summary.highest_block
        ));
        output.push_str(&format!(
            "- **Last Sequence:** {}\n",
            report.replayed_state_summary.last_sequence
        ));
        output.push_str(&format!(
            "- **Transaction Count:** {}\n\n",
            report.replayed_state_summary.transaction_count
        ));

        if !report.inconsistencies.is_empty() {
            output.push_str("## Detailed Issues\n\n");

            // Group issues by type
            let mut issues_by_type = HashMap::new();
            for issue in &report.inconsistencies {
                issues_by_type
                    .entry(format!("{:?}", issue.issue_type))
                    .or_insert_with(Vec::new)
                    .push(issue);
            }

            for (issue_type, issues) in issues_by_type {
                output.push_str(&format!("### {} ({} issues)\n\n", issue_type, issues.len()));

                for (i, issue) in issues.iter().enumerate() {
                    output.push_str(&format!("#### Issue {} - {:?}\n\n", i + 1, issue.severity));
                    output.push_str(&format!("**Description:** {}\n\n", issue.description));

                    if let Some(entity) = &issue.affected_entity {
                        output.push_str(&format!("**Affected Entity:** {entity}\n"));
                    }

                    if let Some(expected) = &issue.expected {
                        output.push_str(&format!("**Expected:** {expected}\n"));
                    }

                    if let Some(actual) = &issue.actual {
                        output.push_str(&format!("**Actual:** {actual}\n"));
                    }

                    if let Some(block_height) = issue.block_height {
                        output.push_str(&format!("**Block Height:** {block_height}\n"));
                    }

                    output.push_str(&format!("**Impact:** {:?}\n", issue.impact));

                    if !issue.remediation.is_empty() {
                        output.push_str("**Recommended Actions:**\n");
                        for action in &issue.remediation {
                            output.push_str(&format!("- {action}\n"));
                        }
                    }

                    if !issue.context.is_empty() {
                        output.push_str("**Additional Context:**\n");
                        for (key, value) in &issue.context {
                            output.push_str(&format!("- {key}: {value}\n"));
                        }
                    }

                    output.push_str("\n---\n\n");
                }
            }
        } else {
            output.push_str("## ✅ No Issues Found\n\n");
            output.push_str("The replayed wallet state appears to be consistent and reliable.\n\n");
        }

        output.push_str("## Recommendations\n\n");

        match report.severity_summary.overall_risk {
            RiskLevel::High => {
                output.push_str("⚠️ **IMMEDIATE ACTION REQUIRED**\n\n");
                output.push_str("Critical issues detected that affect wallet functionality. ");
                output.push_str("Do not rely on this wallet state for transactions until issues are resolved.\n\n");
            }
            RiskLevel::Medium => {
                output.push_str("⚠️ **ACTION RECOMMENDED**\n\n");
                output.push_str("Significant issues detected that should be addressed. ");
                output.push_str("Review the issues and consider re-scanning or investigating event sources.\n\n");
            }
            RiskLevel::Low => {
                output.push_str("ℹ️ **MINOR ISSUES**\n\n");
                output.push_str("Minor issues detected that can be addressed when convenient. ");
                output.push_str("Wallet functionality should not be significantly affected.\n\n");
            }
            RiskLevel::None => {
                output.push_str("✅ **ALL CLEAR**\n\n");
                output.push_str("No significant issues detected. Wallet state appears healthy and reliable.\n\n");
            }
        }

        output.push_str(&format!("Report generated at: {:?}\n", SystemTime::now()));

        output
    }

    /// Detect inconsistencies in replayed state with detailed analysis
    pub async fn detect_inconsistencies(
        &self,
        replayed_state: &ReplayedWalletState,
    ) -> WalletEventResult<InconsistencyReport> {
        let start_time = Instant::now();
        let mut inconsistencies = Vec::new();

        // Check for internal state inconsistencies
        self.detect_internal_inconsistencies(replayed_state, &mut inconsistencies);

        // Check for logical inconsistencies
        self.detect_logical_inconsistencies(replayed_state, &mut inconsistencies);

        // Check for temporal inconsistencies
        self.detect_temporal_inconsistencies(replayed_state, &mut inconsistencies);

        // Check for balance inconsistencies
        self.detect_balance_inconsistencies(replayed_state, &mut inconsistencies);

        // Check for UTXO state inconsistencies
        self.detect_utxo_state_inconsistencies(replayed_state, &mut inconsistencies);

        let severity_summary = self.categorize_inconsistency_severity(&inconsistencies);
        let detection_duration = start_time.elapsed();
        let total_issues = inconsistencies.len();

        Ok(InconsistencyReport {
            wallet_id: replayed_state.wallet_id.clone(),
            inconsistencies,
            severity_summary,
            total_issues,
            detection_duration,
            replayed_state_summary: ReplayedStateSummary::from_state(replayed_state),
        })
    }

    /// Verify replayed state against current wallet state
    pub async fn verify_state_against_current(
        &self,
        replayed_state: &ReplayedWalletState,
        current_state: &WalletState,
    ) -> WalletEventResult<StateVerificationResult> {
        let start_time = Instant::now();

        // Convert replayed state to the same format for comparison
        let mut discrepancies = Vec::new();

        // Compare balances
        let balance_comparison =
            self.compare_balances(replayed_state, current_state, &mut discrepancies);

        // Compare UTXOs
        let utxo_comparison = self.compare_utxos(replayed_state, current_state, &mut discrepancies);

        // Compare transaction counts
        let transaction_comparison =
            self.compare_transaction_counts(replayed_state, current_state, &mut discrepancies);

        // Compare general statistics
        let statistics_comparison =
            self.compare_statistics(replayed_state, current_state, &mut discrepancies);

        // Generate summary
        let summary = self.generate_verification_summary(&discrepancies);

        let states_match = discrepancies.is_empty();

        Ok(StateVerificationResult {
            states_match,
            comparison: StateComparison {
                balance_comparison,
                utxo_comparison,
                transaction_comparison,
                statistics_comparison,
            },
            discrepancies,
            summary,
            verification_duration: start_time.elapsed(),
        })
    }

    /// Compare balances between replayed and current states
    fn compare_balances(
        &self,
        replayed_state: &ReplayedWalletState,
        current_state: &WalletState,
        discrepancies: &mut Vec<StateDiscrepancy>,
    ) -> BalanceComparison {
        let replayed_balance = replayed_state.total_balance;
        let current_balance = current_state.get_unspent_value(); // Use unspent value for comparison
        let difference = replayed_balance as i64 - current_balance as i64;
        let balances_match = replayed_balance == current_balance;

        if !balances_match {
            discrepancies.push(StateDiscrepancy::BalanceMismatch {
                replayed: replayed_balance,
                current: current_balance,
                difference,
            });
        }

        BalanceComparison {
            replayed_balance,
            current_balance,
            difference,
            balances_match,
        }
    }

    /// Compare UTXOs between replayed and current states
    fn compare_utxos(
        &self,
        replayed_state: &ReplayedWalletState,
        current_state: &WalletState,
        discrepancies: &mut Vec<StateDiscrepancy>,
    ) -> UtxoComparison {
        // Get current state unspent transactions
        let current_utxos = current_state.get_unspent_transactions();
        let mut current_utxo_map: HashMap<String, &WalletTransaction> = HashMap::new();

        // Build a map of current UTXOs by commitment (hex format)
        for tx in &current_utxos {
            let commitment_hex = tx.commitment_hex();
            current_utxo_map.insert(commitment_hex, tx);
        }

        let mut only_in_replayed = Vec::new();
        let mut only_in_current = Vec::new();
        let mut value_mismatches = Vec::new();

        // Check replayed UTXOs against current
        for (utxo_id, replayed_utxo) in &replayed_state.utxos {
            if let Some(current_utxo) = current_utxo_map.get(utxo_id) {
                // UTXO exists in both - check values
                if replayed_utxo.amount != current_utxo.value {
                    let mismatch = UtxoValueMismatch {
                        utxo_id: utxo_id.clone(),
                        replayed_value: replayed_utxo.amount,
                        current_value: current_utxo.value,
                        difference: replayed_utxo.amount as i64 - current_utxo.value as i64,
                    };
                    value_mismatches.push(mismatch.clone());

                    discrepancies.push(StateDiscrepancy::UtxoValueMismatch {
                        utxo_id: utxo_id.clone(),
                        replayed_value: replayed_utxo.amount,
                        current_value: current_utxo.value,
                    });
                }
                // Remove from current map to track what's left
                current_utxo_map.remove(utxo_id);
            } else {
                // UTXO only in replayed state
                only_in_replayed.push(utxo_id.clone());
                discrepancies.push(StateDiscrepancy::MissingUtxoInCurrent {
                    utxo_id: utxo_id.clone(),
                    amount: replayed_utxo.amount,
                    block_height: replayed_utxo.block_height,
                });
            }
        }

        // Remaining UTXOs in current_utxo_map are only in current state
        for (utxo_id, current_utxo) in current_utxo_map {
            only_in_current.push(utxo_id.clone());
            discrepancies.push(StateDiscrepancy::ExtraUtxoInCurrent {
                utxo_id,
                amount: current_utxo.value,
                block_height: current_utxo.block_height,
            });
        }

        let utxos_match = only_in_replayed.is_empty()
            && only_in_current.is_empty()
            && value_mismatches.is_empty();

        UtxoComparison {
            replayed_utxo_count: replayed_state.utxos.len(),
            current_utxo_count: current_utxos.len(),
            only_in_replayed,
            only_in_current,
            value_mismatches,
            utxos_match,
        }
    }

    /// Compare transaction counts between states
    fn compare_transaction_counts(
        &self,
        replayed_state: &ReplayedWalletState,
        current_state: &WalletState,
        discrepancies: &mut Vec<StateDiscrepancy>,
    ) -> TransactionComparison {
        let replayed_count = replayed_state.transaction_count;
        let current_count = current_state.transaction_count();
        let difference = replayed_count as i64 - current_count as i64;
        let counts_match = replayed_count == current_count;

        if !counts_match {
            discrepancies.push(StateDiscrepancy::TransactionCountMismatch {
                replayed_count,
                current_count,
            });
        }

        TransactionComparison {
            replayed_count,
            current_count,
            difference,
            counts_match,
        }
    }

    /// Compare general statistics between states
    fn compare_statistics(
        &self,
        replayed_state: &ReplayedWalletState,
        current_state: &WalletState,
        discrepancies: &mut Vec<StateDiscrepancy>,
    ) -> StatisticsComparison {
        let (_, _, _, current_unspent, current_spent) = current_state.get_summary();

        let replayed_spent = replayed_state.spent_utxos.len() as u64;
        let replayed_unspent = replayed_state.utxos.len() as u64;

        let spent_match = replayed_spent == current_spent as u64;
        let unspent_match = replayed_unspent == current_unspent as u64;

        if !spent_match || !unspent_match {
            discrepancies.push(StateDiscrepancy::SpentCountMismatch {
                replayed_spent: replayed_spent as usize,
                current_spent,
                replayed_unspent: replayed_unspent as usize,
                current_unspent,
            });
        }

        // Compare highest block (we need to derive this from current state transactions)
        let current_highest_block = current_state
            .get_inbound_transactions()
            .iter()
            .map(|tx| tx.block_height)
            .max()
            .unwrap_or(0);

        let block_match = replayed_state.highest_block == current_highest_block;
        if !block_match {
            discrepancies.push(StateDiscrepancy::HighestBlockMismatch {
                replayed_block: replayed_state.highest_block,
                current_block: current_highest_block,
            });
        }

        StatisticsComparison {
            spent_count_comparison: CountComparison {
                replayed_value: replayed_spent,
                current_value: current_spent as u64,
                difference: replayed_spent as i64 - current_spent as i64,
                values_match: spent_match,
            },
            unspent_count_comparison: CountComparison {
                replayed_value: replayed_unspent,
                current_value: current_unspent as u64,
                difference: replayed_unspent as i64 - current_unspent as i64,
                values_match: unspent_match,
            },
            highest_block_comparison: CountComparison {
                replayed_value: replayed_state.highest_block,
                current_value: current_highest_block,
                difference: replayed_state.highest_block as i64 - current_highest_block as i64,
                values_match: block_match,
            },
        }
    }

    /// Generate verification summary based on discrepancies
    fn generate_verification_summary(
        &self,
        discrepancies: &[StateDiscrepancy],
    ) -> VerificationSummary {
        let total_discrepancies = discrepancies.len();
        let mut critical_discrepancies = 0;
        let mut warning_discrepancies = 0;

        for discrepancy in discrepancies {
            match discrepancy {
                StateDiscrepancy::BalanceMismatch { .. }
                | StateDiscrepancy::MissingUtxoInCurrent { .. }
                | StateDiscrepancy::ExtraUtxoInCurrent { .. }
                | StateDiscrepancy::UtxoValueMismatch { .. } => {
                    critical_discrepancies += 1;
                }
                StateDiscrepancy::TransactionCountMismatch { .. }
                | StateDiscrepancy::SpentCountMismatch { .. }
                | StateDiscrepancy::HighestBlockMismatch { .. } => {
                    warning_discrepancies += 1;
                }
            }
        }

        let verification_status = if total_discrepancies == 0 {
            VerificationStatus::Perfect
        } else if critical_discrepancies == 0 {
            VerificationStatus::MinorIssues
        } else if critical_discrepancies < 5 {
            VerificationStatus::MajorIssues
        } else {
            VerificationStatus::Critical
        };

        let confidence_level = if total_discrepancies == 0 {
            ConfidenceLevel::High
        } else if critical_discrepancies == 0 {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        };

        VerificationSummary {
            total_discrepancies,
            critical_discrepancies,
            warning_discrepancies,
            verification_status,
            confidence_level,
        }
    }

    /// Perform complete replay and verification against current state
    pub async fn replay_and_verify_wallet(
        &self,
        wallet_id: &str,
        current_state: &WalletState,
    ) -> WalletEventResult<(ReplayResult, StateVerificationResult)> {
        // First, replay the wallet state from events
        let replay_result = self.replay_wallet(wallet_id).await?;

        // Then verify the replayed state against current state
        let verification_result = self
            .verify_state_against_current(&replay_result.wallet_state, current_state)
            .await?;

        Ok((replay_result, verification_result))
    }
}

/// Report for missing event analysis and recovery attempts
#[derive(Debug, Clone, Serialize)]
pub struct MissingEventReport {
    /// Wallet ID being analyzed
    pub wallet_id: String,
    /// List of missing sequence numbers
    pub missing_sequences: Vec<u64>,
    /// Recovery attempts for each missing event
    pub recovery_attempts: Vec<EventRecoveryAttempt>,
    /// Number of events that could be recovered
    pub recovered_events: usize,
    /// Number of events that are unrecoverable
    pub unrecoverable_events: usize,
    /// Whether partial state reconstruction is possible
    pub partial_state_possible: bool,
    /// Recommendations for handling missing events
    pub recommendations: Vec<String>,
}

/// Attempt to recover a single missing event
#[derive(Debug, Clone, Serialize)]
pub struct EventRecoveryAttempt {
    /// Sequence number of the missing event
    pub sequence_number: u64,
    /// Whether recovery is possible for this event
    pub recoverable: bool,
    /// Method used for recovery
    pub recovery_method: RecoveryMethod,
    /// Confidence level in the recovery
    pub confidence_level: RecoveryConfidence,
    /// Inferred event type if recovery is possible
    pub inferred_event_type: Option<String>,
    /// Assessment of the impact of this missing event
    pub impact_assessment: MissingEventImpact,
    /// Specific recommendations for this event
    pub recommendations: Vec<String>,
}

/// Methods for recovering missing events
#[derive(Debug, Clone, Serialize)]
pub enum RecoveryMethod {
    /// No recovery possible
    None,
    /// Infer from surrounding events
    ContextInference,
    /// Reconstruct from blockchain data
    BlockchainReconstruction,
    /// Partial recovery from transaction data
    PartialReconstruction,
    /// Manual intervention required
    ManualIntervention,
}

/// Confidence level in event recovery
#[derive(Debug, Clone, Serialize)]
pub enum RecoveryConfidence {
    /// No confidence (no recovery possible)
    None,
    /// Low confidence in recovery accuracy
    Low,
    /// Medium confidence
    Medium,
    /// High confidence
    High,
}

/// Impact assessment for missing events
#[derive(Debug, Clone, Serialize)]
pub enum MissingEventImpact {
    /// Impact cannot be determined
    Unknown,
    /// No significant impact on wallet state
    None,
    /// Minor impact on metadata
    Minor,
    /// Major impact on balance or UTXO state
    Major,
    /// Critical impact making wallet state unreliable
    Critical,
}

/// Report for corruption detection and analysis
#[derive(Debug, Clone, Serialize)]
pub struct CorruptionReport {
    /// Wallet ID being analyzed
    pub wallet_id: String,
    /// Total number of events checked
    pub total_events_checked: usize,
    /// List of corrupted events found
    pub corrupted_events: Vec<CorruptedEvent>,
    /// Patterns detected in the corruption
    pub corruption_patterns: Vec<CorruptionPattern>,
    /// Overall severity level
    pub severity_level: CorruptionSeverity,
    /// Data integrity score (0.0 = completely corrupted, 1.0 = perfect)
    pub data_integrity_score: f64,
    /// Whether recovery is possible
    pub recovery_possible: bool,
    /// Recommendations for handling corruption
    pub recommendations: Vec<String>,
}

/// Details of a corrupted event
#[derive(Debug, Clone, Serialize)]
pub struct CorruptedEvent {
    /// Event ID of the corrupted event
    pub event_id: String,
    /// Sequence number of the corrupted event
    pub sequence_number: u64,
    /// List of corruption indicators found
    pub corruption_indicators: Vec<CorruptionIndicator>,
    /// Severity of the corruption
    pub severity: EventCorruptionSeverity,
    /// Whether this corruption is recoverable
    pub recoverable: bool,
}

/// Types of corruption indicators
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum CorruptionIndicator {
    /// JSON payload is malformed or unparseable
    MalformedJson,
    /// Event timestamp is invalid
    InvalidTimestamp,
    /// Required fields are missing or empty
    MissingRequiredFields,
    /// Sequence number is invalid
    InvalidSequenceNumber,
    /// Event metadata is inconsistent
    InconsistentMetadata,
    /// Event payload data is invalid
    InvalidPayloadData,
}

/// Patterns of corruption
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum CorruptionPattern {
    /// Corruption affects consecutive events
    ConsecutiveEvents,
    /// Systematic JSON corruption across many events
    SystematicJsonCorruption,
    /// Timestamp corruption pattern
    TimestampCorruption,
    /// Metadata corruption pattern
    MetadataCorruption,
    /// Random isolated corruption
    RandomCorruption,
}

/// Overall corruption severity levels
#[derive(Debug, Clone, Serialize)]
pub enum CorruptionSeverity {
    /// No corruption detected
    None,
    /// Minor corruption that doesn't affect core functionality
    Minor,
    /// Major corruption affecting data integrity
    Major,
    /// Critical corruption making data unreliable
    Critical,
}

/// Severity level for individual corrupted events
#[derive(Debug, Clone, Serialize)]
pub enum EventCorruptionSeverity {
    /// Minor corruption (e.g., invalid timestamp)
    Minor,
    /// Major corruption (e.g., missing required fields)
    Major,
    /// Critical corruption (e.g., malformed JSON)
    Critical,
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

    #[tokio::test]
    async fn test_state_verification_with_discrepancies() {
        let storage = create_test_storage().await;
        let engine = EventReplayEngine::new(storage, ReplayConfig::default());

        // Create mismatched states - replayed has content, current is empty
        let replayed_state = ReplayedWalletState {
            wallet_id: "test-wallet".to_string(),
            total_balance: 1000,
            transaction_count: 2,
            highest_block: 100,
            ..Default::default()
        };

        let current_state = WalletState::new();

        let result = engine
            .verify_state_against_current(&replayed_state, &current_state)
            .await
            .unwrap();

        // Should detect differences since current_state is empty
        assert!(!result.states_match);
        assert!(!result.discrepancies.is_empty());

        // Should have 1 critical discrepancy (balance mismatch) and 2 warning discrepancies
        assert_eq!(result.summary.critical_discrepancies, 1);
        assert_eq!(result.summary.warning_discrepancies, 2);
        assert_eq!(result.summary.total_discrepancies, 3);
        assert!(matches!(
            result.summary.verification_status,
            VerificationStatus::MajorIssues
        ));
    }

    #[tokio::test]
    async fn test_state_verification_balance_mismatch() {
        let storage = create_test_storage().await;
        let engine = EventReplayEngine::new(storage, ReplayConfig::default());

        let replayed_state = ReplayedWalletState {
            wallet_id: "test-wallet".to_string(),
            total_balance: 1000,
            ..Default::default()
        };

        let current_state = WalletState::new();

        let result = engine
            .verify_state_against_current(&replayed_state, &current_state)
            .await
            .unwrap();

        // Should detect balance mismatch
        assert!(!result.comparison.balance_comparison.balances_match);
        assert_eq!(result.comparison.balance_comparison.replayed_balance, 1000);
        assert_eq!(result.comparison.balance_comparison.current_balance, 0);

        // Should have at least one balance mismatch discrepancy
        let has_balance_mismatch = result
            .discrepancies
            .iter()
            .any(|d| matches!(d, StateDiscrepancy::BalanceMismatch { .. }));
        assert!(has_balance_mismatch);
    }

    #[tokio::test]
    async fn test_verification_summary_classification() {
        let storage = create_test_storage().await;
        let engine = EventReplayEngine::new(storage, ReplayConfig::default());

        // Test different types of discrepancies
        let balance_discrepancy = StateDiscrepancy::BalanceMismatch {
            replayed: 1000,
            current: 800,
            difference: 200,
        };

        let block_discrepancy = StateDiscrepancy::HighestBlockMismatch {
            replayed_block: 100,
            current_block: 95,
        };

        // Test critical classification
        let critical_discrepancies = vec![balance_discrepancy];
        let summary = engine.generate_verification_summary(&critical_discrepancies);
        assert_eq!(summary.critical_discrepancies, 1);
        assert_eq!(summary.warning_discrepancies, 0);
        assert!(matches!(
            summary.verification_status,
            VerificationStatus::MajorIssues
        ));

        // Test warning classification
        let warning_discrepancies = vec![block_discrepancy];
        let summary = engine.generate_verification_summary(&warning_discrepancies);
        assert_eq!(summary.critical_discrepancies, 0);
        assert_eq!(summary.warning_discrepancies, 1);
        assert!(matches!(
            summary.verification_status,
            VerificationStatus::MinorIssues
        ));
    }

    #[tokio::test]
    async fn test_state_discrepancy_types() {
        // Test creation of different discrepancy types
        let balance_mismatch = StateDiscrepancy::BalanceMismatch {
            replayed: 1000,
            current: 800,
            difference: 200,
        };

        let missing_utxo = StateDiscrepancy::MissingUtxoInCurrent {
            utxo_id: "utxo1".to_string(),
            amount: 500,
            block_height: 50,
        };

        let extra_utxo = StateDiscrepancy::ExtraUtxoInCurrent {
            utxo_id: "utxo2".to_string(),
            amount: 300,
            block_height: 60,
        };

        // Test that they can be created and matched
        assert!(matches!(
            balance_mismatch,
            StateDiscrepancy::BalanceMismatch { .. }
        ));
        assert!(matches!(
            missing_utxo,
            StateDiscrepancy::MissingUtxoInCurrent { .. }
        ));
        assert!(matches!(
            extra_utxo,
            StateDiscrepancy::ExtraUtxoInCurrent { .. }
        ));
    }
}
