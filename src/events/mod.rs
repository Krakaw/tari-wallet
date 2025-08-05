//! Event system for wallet scanner operations
//!
//! This module provides a flexible event-driven architecture for the wallet scanner,
//! allowing for decoupled monitoring, logging, and storage of scan operations.
//!
//! # Core Components
//!
//! - [`EventListener`] trait: Defines the interface for handling events asynchronously
//! - [`EventDispatcher`]: Manages and dispatches events to registered listeners
//! - Event types: Structured data for different stages of wallet scanning
//!
//! # Features
//!
//! - **Cross-platform compatibility**: Works on both native and WASM targets
//! - **Error isolation**: Listener failures don't cascade or interrupt scanning
//! - **Memory bounded**: Proper cleanup and resource management
//! - **Debugging support**: Event flow tracing capabilities
//! - **Async-first**: Built for asynchronous operations with cancellation support
//!
//! # Architecture
//!
//! The event system follows a publisher-subscriber pattern where the wallet scanner
//! emits events during scanning operations, and multiple listeners can handle these
//! events independently. This design enables:
//!
//! - Separation of concerns between scanning logic and data persistence
//! - Flexible monitoring and progress tracking
//! - Easy testing with mock listeners
//! - Extension points for custom behavior
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use lightweight_wallet_libs::events::{EventDispatcher, EventListener};
//! use lightweight_wallet_libs::events::listeners::{ProgressTrackingListener, ConsoleLoggingListener};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create an event dispatcher
//! let mut dispatcher = EventDispatcher::new();
//!
//! // Register built-in listeners
//! dispatcher.register(Box::new(ProgressTrackingListener::new()));
//! dispatcher.register(Box::new(ConsoleLoggingListener::new()));
//!
//! // The dispatcher can now be used with the wallet scanner
//! // to emit events during scanning operations
//! # Ok(())
//! # }
//! ```
//!
//! # Built-in Listeners
//!
//! The module provides several built-in listeners for common use cases:
//!
//! - [`listeners::DatabaseStorageListener`]: Persists scan results to database
//! - [`listeners::ProgressTrackingListener`]: Tracks and reports scan progress
//! - [`listeners::ConsoleLoggingListener`]: Logs events to console for debugging
//!
//! # Custom Listeners
//!
//! Custom event listeners can be created by implementing the [`EventListener`] trait:
//!
//! ```rust,no_run
//! use async_trait::async_trait;
//! use lightweight_wallet_libs::events::{EventListener, WalletScanEvent};
//! use lightweight_wallet_libs::events::SharedEvent;
//! struct CustomListener;
//!
//! #[async_trait]
//! impl EventListener for CustomListener {
//!     async fn handle_event(&mut self, event: &SharedEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!         // Handle the event
//!         println!("Received event: {:?}", event);
//!         Ok(())
//!     }
//! }
//! ```

use async_trait::async_trait;
use serde::Serialize;
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

// Public module exports
pub mod error_recovery;
pub mod integration_test_examples;
pub mod listener;
pub mod listeners;
pub mod replay;
pub mod test_utils;
pub mod types;

#[cfg(test)]
mod serialization_tests;

// Re-export core types for convenience
pub use error_recovery::{
    ErrorRecord, ErrorRecoveryConfig, ErrorRecoveryManager, ErrorStats, RetryableOperation,
};
pub use listener::{EventListener as WalletEventListener, EventRegistry, RegistryStats};
#[cfg(feature = "storage")]
pub use replay::{
    BalanceComparison, EventReplayEngine, ReplayConfig, ReplayProgress, ReplayResult,
    ReplayedWalletState, SpentUtxoState, StateComparison, StateDiscrepancy,
    StateVerificationResult, TransactionComparison, UtxoComparison, UtxoState, ValidationIssue,
    ValidationIssueType, ValidationSeverity, VerificationStatus, VerificationSummary,
};
pub use test_utils::{EventCapture, EventPattern, PerformanceAssertion, TestScenario};
pub use types::{
    EventListenerError, ReorgPayload, SharedWalletEvent, UtxoReceivedPayload, UtxoSpentPayload,
    WalletEvent, WalletEventError, WalletEventResult, WalletEventValidationError, *,
};

/// Errors that can occur during event dispatcher operations
#[derive(Debug, Clone)]
pub enum EventDispatcherError {
    /// Attempted to register a listener with a duplicate name
    DuplicateListener(String),
    /// Attempted to register more listeners than the configured maximum
    TooManyListeners { current: usize, max: usize },
    /// Listener name is invalid (empty or contains invalid characters)
    InvalidListenerName(String),
}

impl fmt::Display for EventDispatcherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventDispatcherError::DuplicateListener(name) => {
                write!(f, "Listener with name '{name}' is already registered")
            }
            EventDispatcherError::TooManyListeners { current, max } => {
                write!(
                    f,
                    "Cannot register listener: maximum of {max} listeners allowed, currently have {current}"
                )
            }
            EventDispatcherError::InvalidListenerName(name) => {
                write!(f, "Invalid listener name: '{name}'")
            }
        }
    }
}

impl Error for EventDispatcherError {}

/// Debug information about event processing
#[derive(Debug, Clone, Serialize)]
pub struct EventTrace {
    pub event_type: String,
    pub listener_name: String,
    pub processing_duration: Duration,
    pub success: bool,
    pub error_message: Option<String>,
    #[serde(skip)]
    pub timestamp: Instant,
}

/// Statistics about event processing
#[derive(Debug, Default, Clone, Serialize)]
pub struct EventStats {
    pub total_events_dispatched: usize,
    pub total_listener_calls: usize,
    pub total_listener_errors: usize,
    pub total_processing_time: Duration,
    pub events_by_type: std::collections::HashMap<String, usize>,
    pub errors_by_listener: std::collections::HashMap<String, usize>,
}

/// Memory management configuration for event dispatcher
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    pub max_trace_entries: usize,
    pub max_stats_map_entries: usize,
    pub auto_cleanup_threshold: usize,
    pub cleanup_retention_ratio: f32, // Ratio of entries to keep during cleanup (0.0-1.0)
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            max_trace_entries: 1000,
            max_stats_map_entries: 100, // Limit for events_by_type and errors_by_listener maps
            auto_cleanup_threshold: 1200, // Trigger cleanup when traces exceed this
            cleanup_retention_ratio: 0.8, // Keep 80% of entries during cleanup
        }
    }
}

/// Memory usage information for monitoring
#[derive(Debug, Clone)]
pub struct MemoryUsage {
    pub trace_entries: usize,
    pub max_trace_entries: usize,
    pub events_by_type_entries: usize,
    pub errors_by_listener_entries: usize,
    pub max_stats_map_entries: usize,
    pub registered_listeners: usize,
}

/// Trait for handling wallet scan events asynchronously
///
/// Event listeners receive events emitted during wallet scanning operations
/// and can perform arbitrary actions such as storage, logging, or progress tracking.
///
/// # Error Handling
///
/// Implementations should handle errors gracefully. The event dispatcher will
/// isolate failures to prevent one listener from affecting others or interrupting
/// the scanning process.
///
/// # Cross-platform Compatibility
///
/// This trait uses `async_trait` to ensure compatibility across native and WASM
/// targets where async traits behave differently.
#[async_trait]
pub trait EventListener: Send + Sync {
    /// Handle a wallet scan event
    ///
    /// # Arguments
    ///
    /// * `event` - The event to handle, wrapped in Arc for efficient sharing
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful handling, or an error if processing fails.
    /// Errors are logged but do not interrupt the scanning process or other listeners.
    async fn handle_event(
        &mut self,
        event: &SharedEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Optional: Get a name for this listener (used for debugging and logging)
    fn name(&self) -> &'static str {
        "UnnamedListener"
    }

    /// Optional: Check if this listener should receive events of a specific type
    ///
    /// This can be used for performance optimization when a listener only cares
    /// about specific event types.
    fn wants_event(&self, _event: &SharedEvent) -> bool {
        true
    }
}

/// Event dispatcher that manages and delivers events to registered listeners
///
/// The dispatcher maintains an ordered list of event listeners and ensures
/// that events are delivered to all listeners in registration order. Listener
/// failures are isolated and logged without affecting other listeners or the
/// scanning process.
///
/// # Memory Management
///
/// The dispatcher uses bounded memory and cleans up resources appropriately.
/// Events are shared using `Arc` to minimize memory usage when multiple
/// listeners handle the same event.
///
/// # Thread Safety
///
/// The dispatcher is designed to be used from async contexts and handles
/// concurrent access safely.
pub struct EventDispatcher {
    listeners: Vec<Box<dyn EventListener>>,
    debug_mode: bool,
    registered_names: HashSet<String>,
    max_listeners: Option<usize>,
    event_traces: Vec<EventTrace>,
    stats: EventStats,
    memory_config: MemoryConfig,
}

impl EventDispatcher {
    /// Create a new event dispatcher
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
            debug_mode: false,
            registered_names: HashSet::new(),
            max_listeners: None,
            event_traces: Vec::new(),
            stats: EventStats::default(),
            memory_config: MemoryConfig::default(),
        }
    }

    /// Create a new event dispatcher with debugging enabled
    ///
    /// When debug mode is enabled, the dispatcher will log detailed information
    /// about event flow and listener performance.
    pub fn new_with_debug() -> Self {
        Self {
            listeners: Vec::new(),
            debug_mode: true,
            registered_names: HashSet::new(),
            max_listeners: None,
            event_traces: Vec::new(),
            stats: EventStats::default(),
            memory_config: MemoryConfig::default(),
        }
    }

    /// Create a new event dispatcher with a maximum listener limit
    ///
    /// This prevents accidental registration of too many listeners which could
    /// impact performance or indicate a configuration error.
    ///
    /// # Arguments
    ///
    /// * `max_listeners` - Maximum number of listeners allowed
    pub fn new_with_limit(max_listeners: usize) -> Self {
        Self {
            listeners: Vec::new(),
            debug_mode: false,
            registered_names: HashSet::new(),
            max_listeners: Some(max_listeners),
            event_traces: Vec::new(),
            stats: EventStats::default(),
            memory_config: MemoryConfig::default(),
        }
    }

    /// Create a new event dispatcher with custom memory configuration
    ///
    /// # Arguments
    ///
    /// * `memory_config` - Memory management configuration
    pub fn new_with_memory_config(memory_config: MemoryConfig) -> Self {
        Self {
            listeners: Vec::new(),
            debug_mode: true, // Enable debug mode when custom memory config is provided
            registered_names: HashSet::new(),
            max_listeners: None,
            event_traces: Vec::new(),
            stats: EventStats::default(),
            memory_config,
        }
    }

    /// Create a new event dispatcher with custom trace limit (legacy method)
    ///
    /// # Arguments
    ///
    /// * `max_trace_entries` - Maximum number of trace entries to keep in memory
    pub fn new_with_trace_limit(max_trace_entries: usize) -> Self {
        let memory_config = MemoryConfig {
            max_trace_entries,
            ..MemoryConfig::default()
        };

        Self {
            listeners: Vec::new(),
            debug_mode: true, // Enable debug mode when tracing is requested
            registered_names: HashSet::new(),
            max_listeners: None,
            event_traces: Vec::new(),
            stats: EventStats::default(),
            memory_config,
        }
    }

    /// Register an event listener with validation
    ///
    /// Listeners are called in the order they are registered. The dispatcher
    /// takes ownership of the listener and validates the registration.
    ///
    /// # Arguments
    ///
    /// * `listener` - The event listener to register
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful registration, or an error if validation fails.
    ///
    /// # Errors
    ///
    /// * `DuplicateListener` - If a listener with the same name is already registered
    /// * `TooManyListeners` - If the maximum listener limit would be exceeded
    /// * `InvalidListenerName` - If the listener name is invalid
    pub fn register(
        &mut self,
        listener: Box<dyn EventListener>,
    ) -> Result<(), EventDispatcherError> {
        let listener_name = listener.name().to_string();

        // Validate listener name
        if listener_name.is_empty() || listener_name.trim().is_empty() {
            return Err(EventDispatcherError::InvalidListenerName(listener_name));
        }

        // Check for duplicate names
        if self.registered_names.contains(&listener_name) {
            return Err(EventDispatcherError::DuplicateListener(listener_name));
        }

        // Check listener limit
        if let Some(max) = self.max_listeners {
            if self.listeners.len() >= max {
                return Err(EventDispatcherError::TooManyListeners {
                    current: self.listeners.len(),
                    max,
                });
            }
        }

        // Registration is valid, proceed
        if self.debug_mode {
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(&format!("Registering event listener: {listener_name}").into());
            #[cfg(not(target_arch = "wasm32"))]
            println!("Registering event listener: {listener_name}");
        }

        self.registered_names.insert(listener_name);
        self.listeners.push(listener);
        Ok(())
    }

    /// Register an event listener without validation (for backwards compatibility)
    ///
    /// This method bypasses validation and should only be used when validation
    /// is not needed or when migrating existing code.
    ///
    /// # Arguments
    ///
    /// * `listener` - The event listener to register
    pub fn register_unchecked(&mut self, listener: Box<dyn EventListener>) {
        let listener_name = listener.name().to_string();

        if self.debug_mode {
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(
                &format!("Registering event listener (unchecked): {listener_name}").into(),
            );
            #[cfg(not(target_arch = "wasm32"))]
            println!("Registering event listener (unchecked): {listener_name}");
        }

        self.registered_names.insert(listener_name);
        self.listeners.push(listener);
    }

    /// Dispatch an event to all registered listeners
    ///
    /// Events are delivered to listeners in registration order. If a listener
    /// returns an error, it is logged but does not prevent delivery to other
    /// listeners or interrupt the scanning process.
    ///
    /// # Arguments
    ///
    /// * `event` - The event to dispatch
    pub async fn dispatch(&mut self, event: WalletScanEvent) {
        let dispatch_start = Instant::now();
        let shared_event = SharedEvent::new(event);
        let event_type = self.get_event_type_name(&shared_event);

        if self.debug_mode {
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(&format!("Dispatching event: {shared_event:?}").into());
            #[cfg(not(target_arch = "wasm32"))]
            println!("Dispatching event: {shared_event:?}");
        }

        // Update statistics
        self.stats.total_events_dispatched += 1;
        *self
            .stats
            .events_by_type
            .entry(event_type.clone())
            .or_insert(0) += 1;

        // Collect traces to add after processing (to avoid borrowing conflicts)
        let mut traces_to_add = Vec::new();

        for listener in &mut self.listeners {
            // Skip listeners that don't want this event type
            if !listener.wants_event(&shared_event) {
                continue;
            }

            let listener_name = listener.name().to_string();
            let listener_start = Instant::now();
            self.stats.total_listener_calls += 1;

            // Handle the event with error isolation and timing
            let result = listener.handle_event(&shared_event).await;
            let processing_duration = listener_start.elapsed();

            let (success, error_message) = match &result {
                Ok(_) => (true, None),
                Err(e) => {
                    self.stats.total_listener_errors += 1;
                    *self
                        .stats
                        .errors_by_listener
                        .entry(listener_name.clone())
                        .or_insert(0) += 1;

                    // Log the error but continue with other listeners
                    #[cfg(target_arch = "wasm32")]
                    web_sys::console::error_1(
                        &format!("Event listener '{listener_name}' failed: {e}").into(),
                    );
                    #[cfg(not(target_arch = "wasm32"))]
                    eprintln!("Event listener '{listener_name}' failed: {e}");

                    (false, Some(e.to_string()))
                }
            };

            // Create trace entry if debugging is enabled
            if self.debug_mode {
                let trace = EventTrace {
                    event_type: event_type.clone(),
                    listener_name: listener_name.clone(),
                    processing_duration,
                    success,
                    error_message,
                    timestamp: listener_start,
                };

                traces_to_add.push(trace);

                #[cfg(target_arch = "wasm32")]
                web_sys::console::log_1(
                    &format!(
                        "Listener '{listener_name}' processed {event_type} in {processing_duration:?} - Success: {success}"
                    )
                    .into(),
                );
                #[cfg(not(target_arch = "wasm32"))]
                println!(
                    "Listener '{listener_name}' processed {event_type} in {processing_duration:?} - Success: {success}"
                );
            }
        }

        // Add traces after loop to avoid borrowing conflicts
        for trace in traces_to_add {
            self.add_trace(trace);
        }

        // Check if auto cleanup should be triggered after all events in this dispatch
        // Only do auto cleanup if threshold is meaningfully higher than max
        if self.should_trigger_auto_cleanup()
            && self.memory_config.auto_cleanup_threshold > self.memory_config.max_trace_entries
        {
            self.perform_auto_cleanup();
        }

        let total_dispatch_duration = dispatch_start.elapsed();
        self.stats.total_processing_time += total_dispatch_duration;

        if self.debug_mode {
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(
                &format!("Event {event_type} dispatch completed in {total_dispatch_duration:?}")
                    .into(),
            );
            #[cfg(not(target_arch = "wasm32"))]
            println!("Event {event_type} dispatch completed in {total_dispatch_duration:?}");
        }
    }

    /// Get the number of registered listeners
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    /// Check if debugging is enabled
    pub fn is_debug_enabled(&self) -> bool {
        self.debug_mode
    }

    /// Enable or disable debug mode
    pub fn set_debug_mode(&mut self, enabled: bool) {
        self.debug_mode = enabled;
    }

    /// Get event processing statistics
    ///
    /// Returns a copy of the current statistics for analysis and monitoring.
    pub fn get_stats(&self) -> EventStats {
        self.stats.clone()
    }

    /// Get event traces (most recent first)
    ///
    /// Returns a copy of the event traces for debugging and analysis.
    /// Limited by the configured max_trace_entries.
    pub fn get_traces(&self) -> Vec<EventTrace> {
        self.event_traces.clone()
    }

    /// Get traces for a specific event type
    pub fn get_traces_for_event_type(&self, event_type: &str) -> Vec<EventTrace> {
        self.event_traces
            .iter()
            .filter(|trace| trace.event_type == event_type)
            .cloned()
            .collect()
    }

    /// Get traces for a specific listener
    pub fn get_traces_for_listener(&self, listener_name: &str) -> Vec<EventTrace> {
        self.event_traces
            .iter()
            .filter(|trace| trace.listener_name == listener_name)
            .cloned()
            .collect()
    }

    /// Clear all traces and reset statistics
    pub fn clear_debug_data(&mut self) {
        self.event_traces.clear();
        self.stats = EventStats::default();
    }

    /// Set the maximum number of trace entries to keep
    pub fn set_max_trace_entries(&mut self, max_entries: usize) {
        self.memory_config.max_trace_entries = max_entries;
        self.enforce_memory_limits();
    }

    /// Set complete memory configuration
    pub fn set_memory_config(&mut self, memory_config: MemoryConfig) {
        self.memory_config = memory_config;
        self.enforce_memory_limits();
    }

    /// Get current memory configuration
    pub fn get_memory_config(&self) -> &MemoryConfig {
        &self.memory_config
    }

    /// Get memory usage statistics
    pub fn get_memory_usage(&self) -> MemoryUsage {
        MemoryUsage {
            trace_entries: self.event_traces.len(),
            max_trace_entries: self.memory_config.max_trace_entries,
            events_by_type_entries: self.stats.events_by_type.len(),
            errors_by_listener_entries: self.stats.errors_by_listener.len(),
            max_stats_map_entries: self.memory_config.max_stats_map_entries,
            registered_listeners: self.listeners.len(),
        }
    }

    /// Force memory cleanup based on current configuration
    pub fn cleanup_memory(&mut self) {
        self.enforce_memory_limits();
        self.cleanup_statistics_maps();
    }

    /// Check if automatic cleanup should be triggered
    pub fn should_trigger_auto_cleanup(&self) -> bool {
        self.event_traces.len() >= self.memory_config.auto_cleanup_threshold
    }

    /// Export all traces to JSON for external analysis
    pub fn export_traces_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.event_traces).map_err(|e| e.to_string())
    }

    /// Export statistics to JSON for external analysis
    pub fn export_stats_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.stats).map_err(|e| e.to_string())
    }

    /// Get debugging summary as a formatted string
    pub fn get_debug_summary(&self) -> String {
        let stats = &self.stats;
        let total_events_dispatched = stats.total_events_dispatched;
        let total_listener_calls = stats.total_listener_calls;
        let total_listener_errors = stats.total_listener_errors;
        let total_processing_time = stats.total_processing_time;
        let avg_time_per_event = if stats.total_events_dispatched > 0 {
            stats.total_processing_time / stats.total_events_dispatched as u32
        } else {
            Duration::ZERO
        };
        let events_by_type = &stats.events_by_type;
        let errors_by_listener = &stats.errors_by_listener;
        let active_listeners = self.listeners.len();
        let trace_entries = self.event_traces.len();
        let max_trace_entries = self.memory_config.max_trace_entries;

        format!(
            "Event Dispatcher Debug Summary:\n\
             - Total events dispatched: {total_events_dispatched}\n\
             - Total listener calls: {total_listener_calls}\n\
             - Total listener errors: {total_listener_errors}\n\
             - Total processing time: {total_processing_time:?}\n\
             - Average time per event: {avg_time_per_event:?}\n\
             - Events by type: {events_by_type:?}\n\
             - Errors by listener: {errors_by_listener:?}\n\
             - Active listeners: {active_listeners}\n\
             - Trace entries: {trace_entries}/{max_trace_entries}"
        )
    }

    // Private helper methods

    /// Add a trace entry, maintaining the maximum number of entries
    fn add_trace(&mut self, trace: EventTrace) {
        self.event_traces.push(trace);

        // If auto cleanup threshold is higher than max_trace_entries, allow accumulation
        // until we reach the auto cleanup threshold. Otherwise, enforce max_trace_entries.
        let should_allow_accumulation =
            self.memory_config.auto_cleanup_threshold > self.memory_config.max_trace_entries;

        if should_allow_accumulation {
            // Only clean up when we exceed the auto cleanup threshold
            // (auto cleanup itself will be handled at dispatch level)
            if self.event_traces.len() > self.memory_config.auto_cleanup_threshold {
                let excess = self.event_traces.len() - self.memory_config.auto_cleanup_threshold;
                self.event_traces.drain(0..excess);
            }
        } else {
            // Enforce max_trace_entries limit when auto cleanup threshold is not higher
            if self.event_traces.len() > self.memory_config.max_trace_entries {
                let excess = self.event_traces.len() - self.memory_config.max_trace_entries;
                self.event_traces.drain(0..excess);
            }
        }

        // Always clean up statistics maps
        self.cleanup_statistics_maps();
    }

    /// Enforce memory limits on all data structures
    fn enforce_memory_limits(&mut self) {
        // Limit trace entries
        if self.event_traces.len() > self.memory_config.max_trace_entries {
            let excess = self.event_traces.len() - self.memory_config.max_trace_entries;
            self.event_traces.drain(0..excess);
        }

        // Limit statistics maps
        self.cleanup_statistics_maps();
    }

    /// Cleanup statistics maps if they exceed limits
    fn cleanup_statistics_maps(&mut self) {
        // Clean up events_by_type map if it gets too large
        if self.stats.events_by_type.len() > self.memory_config.max_stats_map_entries {
            let mut entries: Vec<_> = self
                .stats
                .events_by_type
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect();
            entries.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by count descending
            entries.truncate(self.memory_config.max_stats_map_entries);

            self.stats.events_by_type = entries.into_iter().collect();
        }

        // Clean up errors_by_listener map if it gets too large
        if self.stats.errors_by_listener.len() > self.memory_config.max_stats_map_entries {
            let mut entries: Vec<_> = self
                .stats
                .errors_by_listener
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect();
            entries.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by count descending
            entries.truncate(self.memory_config.max_stats_map_entries);

            self.stats.errors_by_listener = entries.into_iter().collect();
        }
    }

    /// Perform automatic cleanup when threshold is exceeded
    fn perform_auto_cleanup(&mut self) {
        let target_size = (self.memory_config.max_trace_entries as f32
            * self.memory_config.cleanup_retention_ratio) as usize;
        let current_size = self.event_traces.len();

        if current_size > target_size {
            let to_remove = current_size - target_size;
            self.event_traces.drain(0..to_remove);
        }

        if self.debug_mode {
            let removed_entries = current_size - self.event_traces.len();
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(
                &format!("Auto cleanup: removed {removed_entries} trace entries").into(),
            );
            #[cfg(not(target_arch = "wasm32"))]
            println!("Auto cleanup: removed {removed_entries} trace entries");
        }
    }

    /// Get the string name for an event type
    fn get_event_type_name(&self, event: &SharedEvent) -> String {
        match &**event {
            WalletScanEvent::ScanStarted { .. } => "ScanStarted".to_string(),
            WalletScanEvent::BlockProcessed { .. } => "BlockProcessed".to_string(),
            WalletScanEvent::OutputFound { .. } => "OutputFound".to_string(),
            WalletScanEvent::SpentOutputFound { .. } => "SpentOutputFound".to_string(),
            WalletScanEvent::ScanProgress { .. } => "ScanProgress".to_string(),
            WalletScanEvent::ScanCompleted { .. } => "ScanCompleted".to_string(),
            WalletScanEvent::ScanError { .. } => "ScanError".to_string(),
            WalletScanEvent::ScanCancelled { .. } => "ScanCancelled".to_string(),
        }
    }
}

impl Default for EventDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod native_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // Test listener that records events
    struct TestListener {
        events: Arc<Mutex<Vec<String>>>,
        name: &'static str,
        should_fail: bool,
    }

    impl TestListener {
        fn new(name: &'static str) -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                name,
                should_fail: false,
            }
        }

        fn new_failing(name: &'static str) -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                name,
                should_fail: true,
            }
        }

        #[allow(dead_code)]
        fn get_events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl EventListener for TestListener {
        async fn handle_event(
            &mut self,
            event: &SharedEvent,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if self.should_fail {
                return Err("Test listener failure".into());
            }

            let event_name = match &**event {
                WalletScanEvent::ScanStarted { .. } => "ScanStarted",
                WalletScanEvent::BlockProcessed { .. } => "BlockProcessed",
                WalletScanEvent::OutputFound { .. } => "OutputFound",
                WalletScanEvent::SpentOutputFound { .. } => "SpentOutputFound",
                WalletScanEvent::ScanProgress { .. } => "ScanProgress",
                WalletScanEvent::ScanCompleted { .. } => "ScanCompleted",
                WalletScanEvent::ScanError { .. } => "ScanError",
                WalletScanEvent::ScanCancelled { .. } => "ScanCancelled",
            };

            self.events.lock().unwrap().push(event_name.to_string());
            Ok(())
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }

    #[tokio::test]
    async fn test_event_dispatcher_basic() {
        let mut dispatcher = EventDispatcher::new();
        assert_eq!(dispatcher.listener_count(), 0);

        let listener = TestListener::new("test1");
        dispatcher.register(Box::new(listener)).unwrap();
        assert_eq!(dispatcher.listener_count(), 1);
    }

    #[tokio::test]
    async fn test_event_dispatcher_with_debug() {
        let mut dispatcher = EventDispatcher::new_with_debug();
        assert!(dispatcher.is_debug_enabled());

        dispatcher.set_debug_mode(false);
        assert!(!dispatcher.is_debug_enabled());
    }

    #[tokio::test]
    async fn test_event_dispatch_and_isolation() {
        let mut dispatcher = EventDispatcher::new();

        let listener1 = TestListener::new("listener1");
        let listener2 = TestListener::new_failing("listener2"); // This one will fail
        let listener3 = TestListener::new("listener3");

        let events1 = listener1.events.clone();
        let events3 = listener3.events.clone();

        dispatcher.register(Box::new(listener1)).unwrap();
        dispatcher.register(Box::new(listener2)).unwrap();
        dispatcher.register(Box::new(listener3)).unwrap();

        // Create a test event
        let event = WalletScanEvent::scan_started(
            "test_wallet",
            ScanConfig::default(),
            (0, 100),
            "test".to_string(),
        );

        // Dispatch the event
        dispatcher.dispatch(event).await;

        // Both working listeners should have received the event
        assert_eq!(events1.lock().unwrap().len(), 1);
        assert_eq!(events3.lock().unwrap().len(), 1);
        assert_eq!(events1.lock().unwrap()[0], "ScanStarted");
        assert_eq!(events3.lock().unwrap()[0], "ScanStarted");
    }

    #[tokio::test]
    async fn test_default_implementation() {
        let dispatcher = EventDispatcher::default();
        assert_eq!(dispatcher.listener_count(), 0);
        assert!(!dispatcher.is_debug_enabled());
    }

    #[tokio::test]
    async fn test_registration_validation_duplicate_names() {
        let mut dispatcher = EventDispatcher::new();

        let listener1 = TestListener::new("duplicate_name");
        let listener2 = TestListener::new("duplicate_name");

        // First registration should succeed
        assert!(dispatcher.register(Box::new(listener1)).is_ok());
        assert_eq!(dispatcher.listener_count(), 1);

        // Second registration with same name should fail
        let result = dispatcher.register(Box::new(listener2));
        assert!(result.is_err());
        if let Err(EventDispatcherError::DuplicateListener(name)) = result {
            assert_eq!(name, "duplicate_name");
        } else {
            panic!("Expected DuplicateListener error");
        }
        assert_eq!(dispatcher.listener_count(), 1);
    }

    #[tokio::test]
    async fn test_registration_validation_listener_limit() {
        let mut dispatcher = EventDispatcher::new_with_limit(2);

        let listener1 = TestListener::new("listener1");
        let listener2 = TestListener::new("listener2");
        let listener3 = TestListener::new("listener3");

        // First two registrations should succeed
        assert!(dispatcher.register(Box::new(listener1)).is_ok());
        assert!(dispatcher.register(Box::new(listener2)).is_ok());
        assert_eq!(dispatcher.listener_count(), 2);

        // Third registration should fail due to limit
        let result = dispatcher.register(Box::new(listener3));
        assert!(result.is_err());
        if let Err(EventDispatcherError::TooManyListeners { current, max }) = result {
            assert_eq!(current, 2);
            assert_eq!(max, 2);
        } else {
            panic!("Expected TooManyListeners error");
        }
        assert_eq!(dispatcher.listener_count(), 2);
    }

    #[tokio::test]
    async fn test_registration_validation_invalid_names() {
        let mut dispatcher = EventDispatcher::new();

        // Test empty name
        struct EmptyNameListener;
        #[async_trait]
        impl EventListener for EmptyNameListener {
            async fn handle_event(
                &mut self,
                _event: &SharedEvent,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
            fn name(&self) -> &'static str {
                ""
            }
        }

        let result = dispatcher.register(Box::new(EmptyNameListener));
        assert!(result.is_err());
        if let Err(EventDispatcherError::InvalidListenerName(name)) = result {
            assert_eq!(name, "");
        } else {
            panic!("Expected InvalidListenerName error");
        }

        // Test whitespace-only name
        struct WhitespaceNameListener;
        #[async_trait]
        impl EventListener for WhitespaceNameListener {
            async fn handle_event(
                &mut self,
                _event: &SharedEvent,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
            fn name(&self) -> &'static str {
                "   "
            }
        }

        let result = dispatcher.register(Box::new(WhitespaceNameListener));
        assert!(result.is_err());
        if let Err(EventDispatcherError::InvalidListenerName(name)) = result {
            assert_eq!(name, "   ");
        } else {
            panic!("Expected InvalidListenerName error");
        }
    }

    #[tokio::test]
    async fn test_register_unchecked() {
        let mut dispatcher = EventDispatcher::new_with_limit(1);

        let listener1 = TestListener::new("test1");
        let listener2 = TestListener::new("test1"); // Duplicate name

        // Use unchecked registration to bypass validation
        dispatcher.register_unchecked(Box::new(listener1));
        dispatcher.register_unchecked(Box::new(listener2)); // Should work despite duplicate name and limit

        assert_eq!(dispatcher.listener_count(), 2);
    }

    #[tokio::test]
    async fn test_event_tracing_and_statistics() {
        let mut dispatcher = EventDispatcher::new_with_debug();

        let listener1 = TestListener::new("tracing_listener1");
        let listener2 = TestListener::new_failing("tracing_listener2"); // This one will fail
        let listener3 = TestListener::new("tracing_listener3");

        dispatcher.register(Box::new(listener1)).unwrap();
        dispatcher.register(Box::new(listener2)).unwrap();
        dispatcher.register(Box::new(listener3)).unwrap();

        // Create test events
        let event1 = WalletScanEvent::scan_started(
            "test_wallet",
            ScanConfig::default(),
            (0, 100),
            "test".to_string(),
        );

        let event2 = WalletScanEvent::scan_progress(
            "test_wallet",
            50,
            100,
            1050,
            50.0,
            10.0,
            Some(std::time::Duration::from_secs(5)),
        );

        // Dispatch events
        dispatcher.dispatch(event1).await;
        dispatcher.dispatch(event2).await;

        // Check statistics
        let stats = dispatcher.get_stats();
        assert_eq!(stats.total_events_dispatched, 2);
        assert_eq!(stats.total_listener_calls, 6); // 3 listeners * 2 events
        assert_eq!(stats.total_listener_errors, 2); // 1 failing listener * 2 events
        assert!(stats.total_processing_time > Duration::ZERO);

        // Check events by type
        assert_eq!(stats.events_by_type.get("ScanStarted"), Some(&1));
        assert_eq!(stats.events_by_type.get("ScanProgress"), Some(&1));

        // Check errors by listener
        assert_eq!(stats.errors_by_listener.get("tracing_listener2"), Some(&2));

        // Check traces
        let traces = dispatcher.get_traces();
        assert_eq!(traces.len(), 6); // 3 listeners * 2 events

        // Check traces for specific event type
        let scan_started_traces = dispatcher.get_traces_for_event_type("ScanStarted");
        assert_eq!(scan_started_traces.len(), 3);

        // Check traces for specific listener
        let failing_listener_traces = dispatcher.get_traces_for_listener("tracing_listener2");
        assert_eq!(failing_listener_traces.len(), 2);
        assert!(failing_listener_traces.iter().all(|trace| !trace.success));
    }

    #[tokio::test]
    async fn test_trace_limit_enforcement() {
        // Use memory config with auto cleanup threshold lower than max to disable auto cleanup
        let memory_config = MemoryConfig {
            max_trace_entries: 3,
            max_stats_map_entries: 10,
            auto_cleanup_threshold: 1, // Lower than max to disable auto cleanup
            cleanup_retention_ratio: 0.8,
        };
        let mut dispatcher = EventDispatcher::new_with_memory_config(memory_config);

        let listener = TestListener::new("test_listener");
        dispatcher.register(Box::new(listener)).unwrap();

        // Dispatch 5 events (more than the limit of 3)
        for i in 0..5 {
            let event = WalletScanEvent::scan_started(
                "test_wallet",
                ScanConfig::default(),
                (i, i + 1),
                format!("test_{i}"),
            );
            dispatcher.dispatch(event).await;
        }

        // Should only keep the most recent 3 traces
        let traces = dispatcher.get_traces();
        assert_eq!(traces.len(), 3);

        // Check that these are the most recent traces
        assert_eq!(traces[0].event_type, "ScanStarted");
        assert_eq!(traces[1].event_type, "ScanStarted");
        assert_eq!(traces[2].event_type, "ScanStarted");
    }

    #[tokio::test]
    async fn test_json_export_functionality() {
        let mut dispatcher = EventDispatcher::new_with_debug();

        let listener = TestListener::new("json_test_listener");
        dispatcher.register(Box::new(listener)).unwrap();

        // Create and dispatch a test event
        let event = WalletScanEvent::scan_started(
            "test_wallet",
            ScanConfig::default(),
            (1000, 2000),
            "json_export_test".to_string(),
        );
        dispatcher.dispatch(event).await;

        // Test traces JSON export
        let traces_json = dispatcher.export_traces_json().unwrap();
        assert!(traces_json.contains("ScanStarted"));
        assert!(traces_json.contains("json_test_listener"));
        assert!(traces_json.contains("processing_duration"));

        // Test stats JSON export
        let stats_json = dispatcher.export_stats_json().unwrap();
        assert!(stats_json.contains("total_events_dispatched"));
        assert!(stats_json.contains("total_listener_calls"));
        assert!(stats_json.contains("events_by_type"));

        // Verify JSON is valid by parsing it back
        let _: serde_json::Value = serde_json::from_str(&traces_json).unwrap();
        let _: serde_json::Value = serde_json::from_str(&stats_json).unwrap();
    }

    #[tokio::test]
    async fn test_debug_summary() {
        let mut dispatcher = EventDispatcher::new_with_debug();

        let listener = TestListener::new("summary_listener");
        dispatcher.register(Box::new(listener)).unwrap();

        let event = WalletScanEvent::scan_started(
            "test_wallet",
            ScanConfig::default(),
            (0, 100),
            "test".to_string(),
        );

        dispatcher.dispatch(event).await;

        let summary = dispatcher.get_debug_summary();
        assert!(summary.contains("Total events dispatched: 1"));
        assert!(summary.contains("Total listener calls: 1"));
        assert!(summary.contains("Total listener errors: 0"));
        assert!(summary.contains("Active listeners: 1"));
        assert!(summary.contains("Trace entries: 1/1000"));
    }

    #[tokio::test]
    async fn test_clear_debug_data() {
        let mut dispatcher = EventDispatcher::new_with_debug();

        let listener = TestListener::new("clear_test_listener");
        dispatcher.register(Box::new(listener)).unwrap();

        let event = WalletScanEvent::scan_started(
            "test_wallet",
            ScanConfig::default(),
            (0, 100),
            "test".to_string(),
        );

        dispatcher.dispatch(event).await;

        // Verify data exists
        assert_eq!(dispatcher.get_stats().total_events_dispatched, 1);
        assert_eq!(dispatcher.get_traces().len(), 1);

        // Clear data
        dispatcher.clear_debug_data();

        // Verify data is cleared
        assert_eq!(dispatcher.get_stats().total_events_dispatched, 0);
        assert_eq!(dispatcher.get_traces().len(), 0);
    }

    #[tokio::test]
    async fn test_memory_management_configuration() {
        let memory_config = MemoryConfig {
            max_trace_entries: 5,
            max_stats_map_entries: 3,
            auto_cleanup_threshold: 7,
            cleanup_retention_ratio: 0.6,
        };

        let mut dispatcher = EventDispatcher::new_with_memory_config(memory_config);
        let listener = TestListener::new("memory_test_listener");
        dispatcher.register(Box::new(listener)).unwrap();

        // Test memory usage tracking
        let initial_usage = dispatcher.get_memory_usage();
        assert_eq!(initial_usage.trace_entries, 0);
        assert_eq!(initial_usage.max_trace_entries, 5);
        assert_eq!(initial_usage.registered_listeners, 1);

        // Dispatch some events to test memory limits
        for i in 0..10 {
            let event = WalletScanEvent::scan_started(
                "test_wallet",
                ScanConfig::default(),
                (i, i + 1),
                format!("test_{i}"),
            );
            dispatcher.dispatch(event).await;
        }

        let final_usage = dispatcher.get_memory_usage();

        // Should trigger auto cleanup when exceeding threshold (7)
        // Auto cleanup keeps 60% of max (3 out of 5), then more events can accumulate
        // So the final count should be <= the auto cleanup threshold
        assert!(final_usage.trace_entries <= 7);
    }

    #[tokio::test]
    async fn test_statistics_map_cleanup() {
        let memory_config = MemoryConfig {
            max_trace_entries: 100,
            max_stats_map_entries: 3, // Very small limit for testing
            auto_cleanup_threshold: 150,
            cleanup_retention_ratio: 0.8,
        };

        let mut dispatcher = EventDispatcher::new_with_memory_config(memory_config);
        let listener = TestListener::new("stats_test_listener");
        dispatcher.register(Box::new(listener)).unwrap();

        // Create events with many different types to test map cleanup
        for i in 0..10 {
            let event = match i % 5 {
                0 => WalletScanEvent::scan_started(
                    "test_wallet",
                    ScanConfig::default(),
                    (i, i + 1),
                    format!("test_{i}"),
                ),
                1 => WalletScanEvent::block_processed(
                    "test_wallet",
                    i,
                    format!("hash_{i}"),
                    i,
                    std::time::Duration::from_millis(100),
                    1,
                ),
                2 => WalletScanEvent::scan_progress(
                    "test_wallet",
                    i,
                    100,
                    1000 + i,
                    i as f64,
                    10.0,
                    Some(std::time::Duration::from_secs(5)),
                ),
                3 => WalletScanEvent::scan_completed(
                    "test_wallet",
                    std::collections::HashMap::new(),
                    true,
                    std::time::Duration::from_secs(60),
                ),
                _ => WalletScanEvent::scan_cancelled(
                    "test_wallet",
                    "test".to_string(),
                    std::collections::HashMap::new(),
                    None,
                ),
            };
            dispatcher.dispatch(event).await;
        }

        // Force cleanup
        dispatcher.cleanup_memory();

        let stats = dispatcher.get_stats();
        assert!(stats.events_by_type.len() <= 3); // Should be limited to max_stats_map_entries
    }

    #[tokio::test]
    async fn test_auto_cleanup_threshold() {
        let memory_config = MemoryConfig {
            max_trace_entries: 5,
            max_stats_map_entries: 10,
            auto_cleanup_threshold: 7,    // Trigger cleanup at 7 entries
            cleanup_retention_ratio: 0.6, // Keep 60% = 3 entries
        };

        let mut dispatcher = EventDispatcher::new_with_memory_config(memory_config);
        let listener = TestListener::new("auto_cleanup_listener");
        dispatcher.register(Box::new(listener)).unwrap();

        // Dispatch 7 events to reach the auto cleanup threshold (threshold is 7)
        for i in 0..7 {
            let event = WalletScanEvent::scan_started(
                "test_wallet",
                ScanConfig::default(),
                (i, i + 1),
                format!("test_{i}"),
            );
            dispatcher.dispatch(event).await;
        }

        // At this point auto cleanup should have been triggered
        // It should keep 60% of max_trace_entries = 3 entries
        let traces = dispatcher.get_traces();
        assert_eq!(traces.len(), 3);
    }

    #[tokio::test]
    async fn test_memory_configuration_updates() {
        let mut dispatcher = EventDispatcher::new_with_debug();

        // Initial configuration
        assert_eq!(dispatcher.get_memory_config().max_trace_entries, 1000);

        // Update trace limit
        dispatcher.set_max_trace_entries(10);
        assert_eq!(dispatcher.get_memory_config().max_trace_entries, 10);

        // Update full configuration
        let new_config = MemoryConfig {
            max_trace_entries: 20,
            max_stats_map_entries: 5,
            auto_cleanup_threshold: 25,
            cleanup_retention_ratio: 0.7,
        };

        dispatcher.set_memory_config(new_config.clone());
        let config = dispatcher.get_memory_config();
        assert_eq!(config.max_trace_entries, 20);
        assert_eq!(config.max_stats_map_entries, 5);
        assert_eq!(config.auto_cleanup_threshold, 25);
        assert_eq!(config.cleanup_retention_ratio, 0.7);
    }
}

// WASM-compatible tests - these run on both native and WASM
#[cfg(test)]
mod cross_platform_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    // Test listener that records events (WASM compatible)
    struct WasmTestListener {
        events: Arc<Mutex<Vec<String>>>,
        name: &'static str,
        should_fail: bool,
    }

    impl WasmTestListener {
        fn new(name: &'static str) -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                name,
                should_fail: false,
            }
        }

        fn new_failing(name: &'static str) -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                name,
                should_fail: true,
            }
        }
    }

    #[async_trait]
    impl EventListener for WasmTestListener {
        async fn handle_event(
            &mut self,
            event: &SharedEvent,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if self.should_fail {
                return Err("Test listener failure".into());
            }

            let event_name = match &**event {
                WalletScanEvent::ScanStarted { .. } => "ScanStarted",
                WalletScanEvent::BlockProcessed { .. } => "BlockProcessed",
                WalletScanEvent::OutputFound { .. } => "OutputFound",
                WalletScanEvent::SpentOutputFound { .. } => "SpentOutputFound",
                WalletScanEvent::ScanProgress { .. } => "ScanProgress",
                WalletScanEvent::ScanCompleted { .. } => "ScanCompleted",
                WalletScanEvent::ScanError { .. } => "ScanError",
                WalletScanEvent::ScanCancelled { .. } => "ScanCancelled",
            };

            self.events.lock().unwrap().push(event_name.to_string());
            Ok(())
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    async fn test_cross_platform_event_dispatch() {
        let mut dispatcher = EventDispatcher::new_with_debug();
        let listener = WasmTestListener::new("cross_platform_listener");
        dispatcher.register(Box::new(listener)).unwrap();

        let event = WalletScanEvent::scan_started(
            "test_wallet",
            ScanConfig::default(),
            (0, 100),
            "cross_platform_test".to_string(),
        );

        // This should work identically on native and WASM
        dispatcher.dispatch(event).await;

        let traces = dispatcher.get_traces();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].event_type, "ScanStarted");
        assert!(traces[0].success);
        assert!(traces[0].processing_duration > std::time::Duration::ZERO);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    async fn test_cross_platform_error_handling() {
        let mut dispatcher = EventDispatcher::new_with_debug();

        let working_listener = WasmTestListener::new("working_listener");
        let failing_listener = WasmTestListener::new_failing("failing_listener");
        let another_working_listener = WasmTestListener::new("another_working_listener");

        dispatcher.register(Box::new(working_listener)).unwrap();
        dispatcher.register(Box::new(failing_listener)).unwrap();
        dispatcher
            .register(Box::new(another_working_listener))
            .unwrap();

        let event = WalletScanEvent::scan_started(
            "test_wallet",
            ScanConfig::default(),
            (0, 100),
            "error_test".to_string(),
        );

        // Error isolation should work the same on both platforms
        dispatcher.dispatch(event).await;

        let traces = dispatcher.get_traces();
        assert_eq!(traces.len(), 3);

        // Verify error isolation worked
        assert!(traces[0].success); // working_listener
        assert!(!traces[1].success); // failing_listener
        assert!(traces[2].success); // another_working_listener

        assert!(traces[1].error_message.is_some());
        assert_eq!(
            traces[1].error_message.as_ref().unwrap(),
            "Test listener failure"
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    async fn test_cross_platform_basic_functionality() {
        let mut dispatcher = EventDispatcher::new();
        assert_eq!(dispatcher.listener_count(), 0);

        let listener = WasmTestListener::new("basic_test");
        dispatcher.register(Box::new(listener)).unwrap();
        assert_eq!(dispatcher.listener_count(), 1);

        let event = WalletScanEvent::scan_started(
            "test_wallet",
            ScanConfig::default(),
            (0, 100),
            "basic_test".to_string(),
        );

        dispatcher.dispatch(event).await;

        // Basic functionality should work the same on both platforms
        let stats = dispatcher.get_stats();
        assert_eq!(stats.total_events_dispatched, 1);
        assert_eq!(stats.total_listener_calls, 1);
        assert_eq!(stats.total_listener_errors, 0);
    }
}
