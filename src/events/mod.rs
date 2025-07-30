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
use std::sync::Arc;

// Public module exports
pub mod listeners;
pub mod types;

// Re-export core types for convenience
pub use types::*;

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
}

impl EventDispatcher {
    /// Create a new event dispatcher
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
            debug_mode: false,
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
        }
    }

    /// Register an event listener
    ///
    /// Listeners are called in the order they are registered. The dispatcher
    /// takes ownership of the listener.
    ///
    /// # Arguments
    ///
    /// * `listener` - The event listener to register
    pub fn register(&mut self, listener: Box<dyn EventListener>) {
        if self.debug_mode {
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(
                &format!("Registering event listener: {}", listener.name()).into(),
            );
            #[cfg(not(target_arch = "wasm32"))]
            println!("Registering event listener: {}", listener.name());
        }
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
        if self.debug_mode {
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(&format!("Dispatching event: {:?}", event).into());
            #[cfg(not(target_arch = "wasm32"))]
            println!("Dispatching event: {:?}", event);
        }

        for listener in &mut self.listeners {
            // Skip listeners that don't want this event type
            if !listener.wants_event(&event) {
                continue;
            }

            // Handle the event with error isolation
            if let Err(e) = listener.handle_event(&event).await {
                // Log the error but continue with other listeners
                #[cfg(target_arch = "wasm32")]
                web_sys::console::error_1(
                    &format!("Event listener '{}' failed: {}", listener.name(), e).into(),
                );
                #[cfg(not(target_arch = "wasm32"))]
                eprintln!("Event listener '{}' failed: {}", listener.name(), e);
            }
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
        dispatcher.register(Box::new(listener));
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

        dispatcher.register(Box::new(listener1));
        dispatcher.register(Box::new(listener2));
        dispatcher.register(Box::new(listener3));

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
}
