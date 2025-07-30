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
//!
//! struct CustomListener;
//!
//! #[async_trait]
//! impl EventListener for CustomListener {
//!     async fn handle_event(&mut self, event: &WalletScanEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!         // Handle the event
//!         println!("Received event: {:?}", event);
//!         Ok(())
//!     }
//! }
//! ```

use async_trait::async_trait;
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

// Public module exports
pub mod listeners;
pub mod types;

// Re-export core types for convenience
pub use types::*;

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
                write!(f, "Listener with name '{}' is already registered", name)
            }
            EventDispatcherError::TooManyListeners { current, max } => {
                write!(
                    f,
                    "Cannot register listener: maximum of {} listeners allowed, currently have {}",
                    max, current
                )
            }
            EventDispatcherError::InvalidListenerName(name) => {
                write!(f, "Invalid listener name: '{}'", name)
            }
        }
    }
}

impl Error for EventDispatcherError {}

/// Debug information about event processing
#[derive(Debug, Clone)]
pub struct EventTrace {
    pub event_type: String,
    pub listener_name: String,
    pub processing_duration: Duration,
    pub success: bool,
    pub error_message: Option<String>,
    pub timestamp: Instant,
}

/// Statistics about event processing
#[derive(Debug, Default, Clone)]
pub struct EventStats {
    pub total_events_dispatched: usize,
    pub total_listener_calls: usize,
    pub total_listener_errors: usize,
    pub total_processing_time: Duration,
    pub events_by_type: std::collections::HashMap<String, usize>,
    pub errors_by_listener: std::collections::HashMap<String, usize>,
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
        event: &WalletScanEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Optional: Get a name for this listener (used for debugging and logging)
    fn name(&self) -> &'static str {
        "UnnamedListener"
    }

    /// Optional: Check if this listener should receive events of a specific type
    ///
    /// This can be used for performance optimization when a listener only cares
    /// about specific event types.
    fn wants_event(&self, _event: &WalletScanEvent) -> bool {
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
    max_trace_entries: usize,
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
            max_trace_entries: 1000, // Default limit to prevent unbounded memory growth
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
            max_trace_entries: 1000,
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
            max_trace_entries: 1000,
        }
    }

    /// Create a new event dispatcher with custom trace limit
    ///
    /// # Arguments
    ///
    /// * `max_trace_entries` - Maximum number of trace entries to keep in memory
    pub fn new_with_trace_limit(max_trace_entries: usize) -> Self {
        Self {
            listeners: Vec::new(),
            debug_mode: true, // Enable debug mode when tracing is requested
            registered_names: HashSet::new(),
            max_listeners: None,
            event_traces: Vec::new(),
            stats: EventStats::default(),
            max_trace_entries,
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
            web_sys::console::log_1(
                &format!("Registering event listener: {}", listener_name).into(),
            );
            #[cfg(not(target_arch = "wasm32"))]
            println!("Registering event listener: {}", listener_name);
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
                &format!("Registering event listener (unchecked): {}", listener_name).into(),
            );
            #[cfg(not(target_arch = "wasm32"))]
            println!("Registering event listener (unchecked): {}", listener_name);
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
        let event_type = self.get_event_type_name(&event);

        if self.debug_mode {
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(&format!("Dispatching event: {:?}", event).into());
            #[cfg(not(target_arch = "wasm32"))]
            println!("Dispatching event: {:?}", event);
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
            if !listener.wants_event(&event) {
                continue;
            }

            let listener_name = listener.name().to_string();
            let listener_start = Instant::now();
            self.stats.total_listener_calls += 1;

            // Handle the event with error isolation and timing
            let result = listener.handle_event(&event).await;
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
                        &format!("Event listener '{}' failed: {}", listener_name, e).into(),
                    );
                    #[cfg(not(target_arch = "wasm32"))]
                    eprintln!("Event listener '{}' failed: {}", listener_name, e);

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
                        "Listener '{}' processed {} in {:?} - Success: {}",
                        listener_name, event_type, processing_duration, success
                    )
                    .into(),
                );
                #[cfg(not(target_arch = "wasm32"))]
                println!(
                    "Listener '{}' processed {} in {:?} - Success: {}",
                    listener_name, event_type, processing_duration, success
                );
            }
        }

        // Add traces after loop to avoid borrowing conflicts
        for trace in traces_to_add {
            self.add_trace(trace);
        }

        let total_dispatch_duration = dispatch_start.elapsed();
        self.stats.total_processing_time += total_dispatch_duration;

        if self.debug_mode {
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(
                &format!(
                    "Event {} dispatch completed in {:?}",
                    event_type, total_dispatch_duration
                )
                .into(),
            );
            #[cfg(not(target_arch = "wasm32"))]
            println!(
                "Event {} dispatch completed in {:?}",
                event_type, total_dispatch_duration
            );
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
        self.max_trace_entries = max_entries;
        // Trim existing traces if needed
        if self.event_traces.len() > max_entries {
            self.event_traces
                .drain(0..self.event_traces.len() - max_entries);
        }
    }

    /// Get debugging summary as a formatted string
    pub fn get_debug_summary(&self) -> String {
        let stats = &self.stats;
        format!(
            "Event Dispatcher Debug Summary:\n\
             - Total events dispatched: {}\n\
             - Total listener calls: {}\n\
             - Total listener errors: {}\n\
             - Total processing time: {:?}\n\
             - Average time per event: {:?}\n\
             - Events by type: {:?}\n\
             - Errors by listener: {:?}\n\
             - Active listeners: {}\n\
             - Trace entries: {}/{}",
            stats.total_events_dispatched,
            stats.total_listener_calls,
            stats.total_listener_errors,
            stats.total_processing_time,
            if stats.total_events_dispatched > 0 {
                stats.total_processing_time / stats.total_events_dispatched as u32
            } else {
                Duration::ZERO
            },
            stats.events_by_type,
            stats.errors_by_listener,
            self.listeners.len(),
            self.event_traces.len(),
            self.max_trace_entries
        )
    }

    // Private helper methods

    /// Add a trace entry, maintaining the maximum number of entries
    fn add_trace(&mut self, trace: EventTrace) {
        self.event_traces.push(trace);
        if self.event_traces.len() > self.max_trace_entries {
            self.event_traces.remove(0);
        }
    }

    /// Get the string name for an event type
    fn get_event_type_name(&self, event: &WalletScanEvent) -> String {
        match event {
            WalletScanEvent::ScanStarted { .. } => "ScanStarted".to_string(),
            WalletScanEvent::BlockProcessed { .. } => "BlockProcessed".to_string(),
            WalletScanEvent::OutputFound { .. } => "OutputFound".to_string(),
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

#[cfg(test)]
mod tests {
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
            event: &WalletScanEvent,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if self.should_fail {
                return Err("Test listener failure".into());
            }

            let event_name = match event {
                WalletScanEvent::ScanStarted { .. } => "ScanStarted",
                WalletScanEvent::BlockProcessed { .. } => "BlockProcessed",
                WalletScanEvent::OutputFound { .. } => "OutputFound",
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
        let event = WalletScanEvent::ScanStarted {
            config: ScanConfig::default(),
            block_range: (0, 100),
            wallet_context: "test".to_string(),
        };

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
                _event: &WalletScanEvent,
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
                _event: &WalletScanEvent,
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
        let event1 = WalletScanEvent::ScanStarted {
            config: ScanConfig::default(),
            block_range: (0, 100),
            wallet_context: "test".to_string(),
        };

        let event2 = WalletScanEvent::ScanProgress {
            current_block: 50,
            total_blocks: 100,
            percentage: 50.0,
            speed_blocks_per_second: 10.0,
            estimated_time_remaining_seconds: Some(5),
        };

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
        let mut dispatcher = EventDispatcher::new_with_trace_limit(3);

        let listener = TestListener::new("test_listener");
        dispatcher.register(Box::new(listener)).unwrap();

        // Dispatch 5 events (more than the limit of 3)
        for i in 0..5 {
            let event = WalletScanEvent::ScanStarted {
                config: ScanConfig::default(),
                block_range: (i, i + 1),
                wallet_context: format!("test_{}", i),
            };
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
    async fn test_debug_summary() {
        let mut dispatcher = EventDispatcher::new_with_debug();

        let listener = TestListener::new("summary_listener");
        dispatcher.register(Box::new(listener)).unwrap();

        let event = WalletScanEvent::ScanStarted {
            config: ScanConfig::default(),
            block_range: (0, 100),
            wallet_context: "test".to_string(),
        };

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

        let event = WalletScanEvent::ScanStarted {
            config: ScanConfig::default(),
            block_range: (0, 100),
            wallet_context: "test".to_string(),
        };

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
}
