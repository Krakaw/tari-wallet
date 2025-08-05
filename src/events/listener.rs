//! Event listener trait and registry implementation for the wallet event system
//!
//! This module provides the core infrastructure for event handling including:
//! - EventListener trait for async event processing
//! - EventRegistry for managing multiple listeners
//! - Error handling and isolation between listeners
//! - Concrete listener implementations for common use cases

use async_trait::async_trait;
use std::collections::HashMap;
use std::error::Error;

use crate::events::types::{SharedWalletEvent, WalletEventError, WalletEventResult};

/// Trait for handling wallet events asynchronously
///
/// Event listeners receive events emitted during wallet operations and can perform
/// arbitrary actions such as storage, logging, or progress tracking.
///
/// # Error Handling
///
/// Implementations should handle errors gracefully. The event registry will
/// isolate failures to prevent one listener from affecting others or interrupting
/// wallet operations.
///
/// # Cross-platform Compatibility
///
/// This trait uses `async_trait` to ensure compatibility across native and WASM
/// targets where async traits behave differently.
///
/// # Examples
///
/// ```rust,no_run
/// use async_trait::async_trait;
/// use lightweight_wallet_libs::events::{EventListener, SharedWalletEvent};
/// use std::error::Error;
///
/// struct ConsoleLogger;
///
/// #[async_trait]
/// impl EventListener for ConsoleLogger {
///     async fn handle_event(
///         &mut self,
///         event: &SharedWalletEvent
///     ) -> Result<(), Box<dyn Error + Send + Sync>> {
///         println!("Event received: {:?}", event);
///         Ok(())
///     }
///
///     fn name(&self) -> &'static str {
///         "ConsoleLogger"
///     }
/// }
/// ```
#[async_trait]
pub trait EventListener: Send + Sync {
    /// Handle a wallet event asynchronously
    ///
    /// # Arguments
    ///
    /// * `event` - The wallet event to handle, wrapped in Arc for efficient sharing
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful handling, or an error if processing fails.
    /// Errors are logged by the registry but do not interrupt other listeners or wallet operations.
    ///
    /// # Error Handling
    ///
    /// Event listeners should be resilient to errors and handle them gracefully.
    /// If an error is returned, it will be logged by the event registry but will not:
    /// - Stop other listeners from receiving the event
    /// - Interrupt wallet operations
    /// - Cause the event to be retried automatically
    ///
    /// For critical failures that should stop wallet operations, listeners should
    /// use other mechanisms to signal the error outside of the event system.
    async fn handle_event(
        &mut self,
        event: &SharedWalletEvent,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Get a unique name for this listener
    ///
    /// This name is used for:
    /// - Debugging and logging purposes
    /// - Preventing duplicate listener registration
    /// - Error reporting and metrics
    ///
    /// The name should be unique across all listeners in a registry and
    /// should not change during the lifetime of the listener.
    fn name(&self) -> &'static str;

    /// Check if this listener should receive events of a specific type
    ///
    /// This method can be used for performance optimization when a listener only
    /// cares about specific event types. By default, listeners receive all events.
    ///
    /// # Arguments
    ///
    /// * `event` - The event to check interest for
    ///
    /// # Returns
    ///
    /// Returns `true` if the listener wants to handle this event, `false` otherwise.
    fn wants_event(&self, _event: &SharedWalletEvent) -> bool {
        true
    }

    /// Initialize the listener before it starts receiving events
    ///
    /// This method is called once when the listener is registered with a registry.
    /// It can be used to set up resources, validate configuration, or prepare
    /// for event handling.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful initialization, or an error if setup fails.
    /// If initialization fails, the listener will not be registered.
    async fn initialize(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }

    /// Cleanup the listener when it's no longer needed
    ///
    /// This method is called when the listener is being removed from a registry
    /// or when the registry is being dropped. It can be used to release resources,
    /// close connections, or perform final cleanup.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful cleanup. Errors are logged but do not
    /// prevent the listener from being removed.
    async fn cleanup(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }

    /// Get configuration information about this listener
    ///
    /// This method can be used to expose listener-specific configuration
    /// for debugging or monitoring purposes.
    ///
    /// # Returns
    ///
    /// Returns a map of configuration key-value pairs. Empty by default.
    fn get_config(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    /// Check if the listener is currently in a healthy state
    ///
    /// This method can be used for health monitoring and to determine if
    /// the listener should continue receiving events.
    ///
    /// # Returns
    ///
    /// Returns `true` if the listener is healthy, `false` otherwise.
    /// Unhealthy listeners may be removed from the registry.
    fn is_healthy(&self) -> bool {
        true
    }
}

/// Registry for managing multiple event listeners
///
/// The EventRegistry provides centralized management of event listeners,
/// including registration, deregistration, and event dispatch to all
/// registered listeners.
///
/// # Features
///
/// - **Error Isolation**: Listener failures don't affect other listeners
/// - **Async Support**: Full async event handling with proper error propagation
/// - **Health Monitoring**: Track listener health and performance
/// - **Graceful Shutdown**: Proper cleanup of all listeners
///
/// # Examples
///
/// ```rust,no_run
/// use lightweight_wallet_libs::events::{EventRegistry, EventListener};
/// use lightweight_wallet_libs::events::listeners::ConsoleLogger;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut registry = EventRegistry::new();
///
/// // Register a console logging listener
/// registry.register(Box::new(ConsoleLogger::new())).await?;
///
/// // The registry can now dispatch events to all registered listeners
/// # Ok(())
/// # }
/// ```
pub struct EventRegistry {
    listeners: Vec<Box<dyn EventListener>>,
    listener_names: HashMap<String, usize>, // Maps names to indices
    max_listeners: Option<usize>,
    stats: RegistryStats,
}

/// Statistics about event registry operations
#[derive(Debug, Default, Clone)]
pub struct RegistryStats {
    pub total_events_dispatched: u64,
    pub total_listener_calls: u64,
    pub total_listener_errors: u64,
    pub listeners_registered: u64,
    pub listeners_removed: u64,
    pub events_by_type: HashMap<String, u64>,
    pub errors_by_listener: HashMap<String, u64>,
}

impl EventRegistry {
    /// Create a new event registry
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
            listener_names: HashMap::new(),
            max_listeners: None,
            stats: RegistryStats::default(),
        }
    }

    /// Create a new event registry with a maximum listener limit
    ///
    /// # Arguments
    ///
    /// * `max_listeners` - Maximum number of listeners allowed
    pub fn with_max_listeners(max_listeners: usize) -> Self {
        Self {
            listeners: Vec::new(),
            listener_names: HashMap::new(),
            max_listeners: Some(max_listeners),
            stats: RegistryStats::default(),
        }
    }

    /// Register an event listener
    ///
    /// The listener will be initialized and added to the registry if successful.
    /// Duplicate listener names are not allowed.
    ///
    /// # Arguments
    ///
    /// * `listener` - The event listener to register
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful registration, or an error if registration fails.
    ///
    /// # Errors
    ///
    /// - `WalletEventError::DuplicateEvent` - If a listener with the same name already exists
    /// - `WalletEventError::ConfigurationError` - If the maximum listener limit would be exceeded
    /// - Other errors from listener initialization
    pub async fn register(
        &mut self,
        mut listener: Box<dyn EventListener>,
    ) -> WalletEventResult<()> {
        let listener_name = listener.name().to_string();

        // Validate listener name
        if listener_name.is_empty() {
            return Err(WalletEventError::ConfigurationError {
                parameter: "listener_name".to_string(),
                message: "Listener name cannot be empty".to_string(),
            });
        }

        // Check for duplicate names
        if self.listener_names.contains_key(&listener_name) {
            return Err(WalletEventError::DuplicateEvent {
                event_id: listener_name,
            });
        }

        // Check listener limit
        if let Some(max) = self.max_listeners {
            if self.listeners.len() >= max {
                return Err(WalletEventError::ConfigurationError {
                    parameter: "max_listeners".to_string(),
                    message: format!(
                        "Maximum listener limit of {} exceeded (currently have {})",
                        max,
                        self.listeners.len()
                    ),
                });
            }
        }

        // Initialize the listener
        listener
            .initialize()
            .await
            .map_err(|e| WalletEventError::ListenerError {
                listener_name: listener_name.clone(),
                error: format!("Initialization failed: {}", e),
            })?;

        // Add to registry
        let index = self.listeners.len();
        self.listener_names.insert(listener_name.clone(), index);
        self.listeners.push(listener);
        self.stats.listeners_registered += 1;

        #[cfg(target_arch = "wasm32")]
        web_sys::console::log_1(&format!("Registered event listener: {}", listener_name).into());
        #[cfg(not(target_arch = "wasm32"))]
        println!("Registered event listener: {}", listener_name);

        Ok(())
    }

    /// Remove an event listener by name
    ///
    /// The listener will be cleaned up before removal.
    ///
    /// # Arguments
    ///
    /// * `listener_name` - Name of the listener to remove
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the listener was removed, or an error if not found.
    pub async fn remove(&mut self, listener_name: &str) -> WalletEventResult<()> {
        let index = self.listener_names.remove(listener_name).ok_or_else(|| {
            WalletEventError::EventNotFound {
                event_id: listener_name.to_string(),
            }
        })?;

        // Cleanup the listener before removal
        if let Err(e) = self.listeners[index].cleanup().await {
            #[cfg(target_arch = "wasm32")]
            web_sys::console::warn_1(
                &format!("Cleanup failed for listener '{}': {}", listener_name, e).into(),
            );
            #[cfg(not(target_arch = "wasm32"))]
            eprintln!("Cleanup failed for listener '{}': {}", listener_name, e);
        }

        // Remove from listeners vector
        self.listeners.remove(index);

        // Update indices in the name map for listeners that came after the removed one
        for (_, idx) in self.listener_names.iter_mut() {
            if *idx > index {
                *idx -= 1;
            }
        }

        self.stats.listeners_removed += 1;

        #[cfg(target_arch = "wasm32")]
        web_sys::console::log_1(&format!("Removed event listener: {}", listener_name).into());
        #[cfg(not(target_arch = "wasm32"))]
        println!("Removed event listener: {}", listener_name);

        Ok(())
    }

    /// Dispatch an event to all registered listeners
    ///
    /// Events are delivered to listeners in registration order. If a listener
    /// returns an error, it is logged but does not prevent delivery to other
    /// listeners.
    ///
    /// # Arguments
    ///
    /// * `event` - The event to dispatch to all listeners
    pub async fn dispatch(&mut self, event: SharedWalletEvent) {
        let event_type = self.get_event_type_name(&event);
        self.stats.total_events_dispatched += 1;
        *self
            .stats
            .events_by_type
            .entry(event_type.clone())
            .or_insert(0) += 1;

        #[cfg(target_arch = "wasm32")]
        web_sys::console::log_1(
            &format!(
                "Dispatching event: {} to {} listeners",
                event_type,
                self.listeners.len()
            )
            .into(),
        );
        #[cfg(not(target_arch = "wasm32"))]
        println!(
            "Dispatching event: {} to {} listeners",
            event_type,
            self.listeners.len()
        );

        for listener in &mut self.listeners {
            // Skip listeners that don't want this event type
            if !listener.wants_event(&event) {
                continue;
            }

            let listener_name = listener.name();
            self.stats.total_listener_calls += 1;

            // Handle the event with error isolation
            if let Err(e) = listener.handle_event(&event).await {
                self.stats.total_listener_errors += 1;
                *self
                    .stats
                    .errors_by_listener
                    .entry(listener_name.to_string())
                    .or_insert(0) += 1;

                // Log the error but continue with other listeners
                #[cfg(target_arch = "wasm32")]
                web_sys::console::error_1(
                    &format!(
                        "Event listener '{}' failed to handle {}: {}",
                        listener_name, event_type, e
                    )
                    .into(),
                );
                #[cfg(not(target_arch = "wasm32"))]
                eprintln!(
                    "Event listener '{}' failed to handle {}: {}",
                    listener_name, event_type, e
                );
            }
        }
    }

    /// Get the number of registered listeners
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    /// Check if a listener with the given name is registered
    pub fn has_listener(&self, listener_name: &str) -> bool {
        self.listener_names.contains_key(listener_name)
    }

    /// Get a list of all registered listener names
    pub fn get_listener_names(&self) -> Vec<String> {
        self.listener_names.keys().cloned().collect()
    }

    /// Get registry statistics
    pub fn get_stats(&self) -> &RegistryStats {
        &self.stats
    }

    /// Clear all statistics
    pub fn clear_stats(&mut self) {
        self.stats = RegistryStats::default();
    }

    /// Perform health check on all listeners
    ///
    /// Returns a map of listener names to their health status.
    pub fn health_check(&self) -> HashMap<String, bool> {
        self.listener_names
            .iter()
            .map(|(name, &index)| (name.clone(), self.listeners[index].is_healthy()))
            .collect()
    }

    /// Remove unhealthy listeners
    ///
    /// This method will check all listeners and remove any that report as unhealthy.
    /// Cleanup will be performed for removed listeners.
    pub async fn remove_unhealthy_listeners(&mut self) -> Vec<String> {
        let mut removed_listeners = Vec::new();
        let unhealthy_names: Vec<String> = self
            .listener_names
            .iter()
            .filter_map(|(name, &index)| {
                if !self.listeners[index].is_healthy() {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect();

        for name in unhealthy_names {
            if let Err(e) = self.remove(&name).await {
                #[cfg(target_arch = "wasm32")]
                web_sys::console::error_1(
                    &format!("Failed to remove unhealthy listener '{}': {}", name, e).into(),
                );
                #[cfg(not(target_arch = "wasm32"))]
                eprintln!("Failed to remove unhealthy listener '{}': {}", name, e);
            } else {
                removed_listeners.push(name);
            }
        }

        removed_listeners
    }

    /// Cleanup all listeners and clear the registry
    ///
    /// This method will call cleanup on all registered listeners and remove them.
    /// It should be called when the registry is no longer needed.
    pub async fn shutdown(&mut self) {
        #[cfg(target_arch = "wasm32")]
        web_sys::console::log_1(
            &format!(
                "Shutting down event registry with {} listeners",
                self.listeners.len()
            )
            .into(),
        );
        #[cfg(not(target_arch = "wasm32"))]
        println!(
            "Shutting down event registry with {} listeners",
            self.listeners.len()
        );

        // Cleanup all listeners
        for listener in &mut self.listeners {
            if let Err(e) = listener.cleanup().await {
                let listener_name = listener.name();
                #[cfg(target_arch = "wasm32")]
                web_sys::console::warn_1(
                    &format!("Cleanup failed for listener '{}': {}", listener_name, e).into(),
                );
                #[cfg(not(target_arch = "wasm32"))]
                eprintln!("Cleanup failed for listener '{}': {}", listener_name, e);
            }
        }

        // Clear all data
        self.listeners.clear();
        self.listener_names.clear();
        self.stats = RegistryStats::default();
    }

    // Private helper methods

    /// Get the string name for an event type
    fn get_event_type_name(&self, event: &SharedWalletEvent) -> String {
        match &**event {
            crate::events::types::WalletEvent::UtxoReceived { .. } => "UtxoReceived".to_string(),
            crate::events::types::WalletEvent::UtxoSpent { .. } => "UtxoSpent".to_string(),
            crate::events::types::WalletEvent::Reorg { .. } => "Reorg".to_string(),
        }
    }
}

impl Default for EventRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::types::{EventMetadata, UtxoReceivedPayload, WalletEvent};
    use std::sync::{Arc, Mutex};

    // Test listener for unit testing
    struct TestListener {
        name: &'static str,
        events_received: Arc<Mutex<Vec<String>>>,
        should_fail: bool,
        wants_all_events: bool,
    }

    impl TestListener {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                events_received: Arc::new(Mutex::new(Vec::new())),
                should_fail: false,
                wants_all_events: true,
            }
        }

        fn new_failing(name: &'static str) -> Self {
            Self {
                name,
                events_received: Arc::new(Mutex::new(Vec::new())),
                should_fail: true,
                wants_all_events: true,
            }
        }

        fn new_selective(name: &'static str) -> Self {
            Self {
                name,
                events_received: Arc::new(Mutex::new(Vec::new())),
                should_fail: false,
                wants_all_events: false,
            }
        }

        #[allow(dead_code)]
        fn get_events(&self) -> Vec<String> {
            self.events_received.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl EventListener for TestListener {
        async fn handle_event(
            &mut self,
            event: &SharedWalletEvent,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            if self.should_fail {
                return Err("Test listener intentional failure".into());
            }

            let event_type = match &**event {
                WalletEvent::UtxoReceived { .. } => "UtxoReceived",
                WalletEvent::UtxoSpent { .. } => "UtxoSpent",
                WalletEvent::Reorg { .. } => "Reorg",
            };

            self.events_received
                .lock()
                .unwrap()
                .push(event_type.to_string());
            Ok(())
        }

        fn name(&self) -> &'static str {
            self.name
        }

        fn wants_event(&self, event: &SharedWalletEvent) -> bool {
            if self.wants_all_events {
                return true;
            }

            // Selective listener only wants UtxoReceived events
            matches!(&**event, WalletEvent::UtxoReceived { .. })
        }
    }

    #[tokio::test]
    async fn test_registry_creation() {
        let registry = EventRegistry::new();
        assert_eq!(registry.listener_count(), 0);
        assert!(registry.get_listener_names().is_empty());
    }

    #[tokio::test]
    async fn test_listener_registration() {
        let mut registry = EventRegistry::new();
        let listener = TestListener::new("test_listener");

        assert!(registry.register(Box::new(listener)).await.is_ok());
        assert_eq!(registry.listener_count(), 1);
        assert!(registry.has_listener("test_listener"));
        assert_eq!(registry.get_listener_names(), vec!["test_listener"]);
    }

    #[tokio::test]
    async fn test_duplicate_listener_registration() {
        let mut registry = EventRegistry::new();
        let listener1 = TestListener::new("duplicate_name");
        let listener2 = TestListener::new("duplicate_name");

        assert!(registry.register(Box::new(listener1)).await.is_ok());
        assert_eq!(registry.listener_count(), 1);

        let result = registry.register(Box::new(listener2)).await;
        assert!(result.is_err());
        assert_eq!(registry.listener_count(), 1);
    }

    #[tokio::test]
    async fn test_listener_limit() {
        let mut registry = EventRegistry::with_max_listeners(2);

        let listener1 = TestListener::new("listener1");
        let listener2 = TestListener::new("listener2");
        let listener3 = TestListener::new("listener3");

        assert!(registry.register(Box::new(listener1)).await.is_ok());
        assert!(registry.register(Box::new(listener2)).await.is_ok());
        assert_eq!(registry.listener_count(), 2);

        let result = registry.register(Box::new(listener3)).await;
        assert!(result.is_err());
        assert_eq!(registry.listener_count(), 2);
    }

    #[tokio::test]
    async fn test_event_dispatch() {
        let mut registry = EventRegistry::new();
        let listener = TestListener::new("test_listener");
        let events_received = listener.events_received.clone();

        registry.register(Box::new(listener)).await.unwrap();

        // Create a test event
        let metadata = EventMetadata::new("test", "test_wallet");
        let payload = UtxoReceivedPayload::new(
            "test_utxo".to_string(),
            1000,
            100,
            "block_hash".to_string(),
            1234567890,
            "tx_hash".to_string(),
            0,
            "address".to_string(),
            0,
            "commitment".to_string(),
            0,
            "mainnet".to_string(),
        );

        let event = SharedWalletEvent::new(WalletEvent::UtxoReceived { metadata, payload });

        registry.dispatch(event).await;

        let events = events_received.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], "UtxoReceived");
    }

    #[tokio::test]
    async fn test_error_isolation() {
        let mut registry = EventRegistry::new();

        let listener1 = TestListener::new("working_listener");
        let listener2 = TestListener::new_failing("failing_listener");
        let listener3 = TestListener::new("another_working_listener");

        let events1 = listener1.events_received.clone();
        let events3 = listener3.events_received.clone();

        registry.register(Box::new(listener1)).await.unwrap();
        registry.register(Box::new(listener2)).await.unwrap();
        registry.register(Box::new(listener3)).await.unwrap();

        // Create a test event
        let metadata = EventMetadata::new("test", "test_wallet");
        let payload = UtxoReceivedPayload::new(
            "test_utxo".to_string(),
            1000,
            100,
            "block_hash".to_string(),
            1234567890,
            "tx_hash".to_string(),
            0,
            "address".to_string(),
            0,
            "commitment".to_string(),
            0,
            "mainnet".to_string(),
        );

        let event = SharedWalletEvent::new(WalletEvent::UtxoReceived { metadata, payload });

        registry.dispatch(event).await;

        // Both working listeners should have received the event
        assert_eq!(events1.lock().unwrap().len(), 1);
        assert_eq!(events3.lock().unwrap().len(), 1);

        // Check error statistics
        let stats = registry.get_stats();
        assert_eq!(stats.total_listener_errors, 1);
        assert!(stats.errors_by_listener.contains_key("failing_listener"));
    }

    #[tokio::test]
    async fn test_selective_event_handling() {
        let mut registry = EventRegistry::new();
        let selective_listener = TestListener::new_selective("selective_listener");
        let events_received = selective_listener.events_received.clone();

        registry
            .register(Box::new(selective_listener))
            .await
            .unwrap();

        // Create UtxoReceived event (should be handled)
        let metadata1 = EventMetadata::new("test", "test_wallet");
        let payload1 = UtxoReceivedPayload::new(
            "test_utxo".to_string(),
            1000,
            100,
            "block_hash".to_string(),
            1234567890,
            "tx_hash".to_string(),
            0,
            "address".to_string(),
            0,
            "commitment".to_string(),
            0,
            "mainnet".to_string(),
        );
        let event1 = SharedWalletEvent::new(WalletEvent::UtxoReceived {
            metadata: metadata1,
            payload: payload1,
        });

        registry.dispatch(event1).await;

        // Check that the selective listener received the UtxoReceived event
        let events = events_received.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], "UtxoReceived");
    }

    #[tokio::test]
    async fn test_listener_removal() {
        let mut registry = EventRegistry::new();
        let listener = TestListener::new("removable_listener");

        registry.register(Box::new(listener)).await.unwrap();
        assert_eq!(registry.listener_count(), 1);
        assert!(registry.has_listener("removable_listener"));

        assert!(registry.remove("removable_listener").await.is_ok());
        assert_eq!(registry.listener_count(), 0);
        assert!(!registry.has_listener("removable_listener"));
    }

    #[tokio::test]
    async fn test_registry_shutdown() {
        let mut registry = EventRegistry::new();
        let listener1 = TestListener::new("listener1");
        let listener2 = TestListener::new("listener2");

        registry.register(Box::new(listener1)).await.unwrap();
        registry.register(Box::new(listener2)).await.unwrap();
        assert_eq!(registry.listener_count(), 2);

        registry.shutdown().await;
        assert_eq!(registry.listener_count(), 0);
        assert!(registry.get_listener_names().is_empty());
    }

    #[tokio::test]
    async fn test_empty_listener_name_validation() {
        let mut registry = EventRegistry::new();

        // Test with empty name
        struct EmptyNameListener;

        #[async_trait]
        impl EventListener for EmptyNameListener {
            async fn handle_event(
                &mut self,
                _event: &SharedWalletEvent,
            ) -> Result<(), Box<dyn Error + Send + Sync>> {
                Ok(())
            }

            fn name(&self) -> &'static str {
                ""
            }
        }

        let result = registry.register(Box::new(EmptyNameListener)).await;
        assert!(result.is_err());
        assert_eq!(registry.listener_count(), 0);
    }

    #[tokio::test]
    async fn test_listener_removal_nonexistent() {
        let mut registry = EventRegistry::new();

        let result = registry.remove("nonexistent_listener").await;
        assert!(result.is_err());
        assert_eq!(registry.listener_count(), 0);
    }

    #[tokio::test]
    async fn test_health_check() {
        let mut registry = EventRegistry::new();

        // Test healthy listener
        struct HealthyListener;

        #[async_trait]
        impl EventListener for HealthyListener {
            async fn handle_event(
                &mut self,
                _event: &SharedWalletEvent,
            ) -> Result<(), Box<dyn Error + Send + Sync>> {
                Ok(())
            }

            fn name(&self) -> &'static str {
                "healthy_listener"
            }

            fn is_healthy(&self) -> bool {
                true
            }
        }

        // Test unhealthy listener
        struct UnhealthyListener;

        #[async_trait]
        impl EventListener for UnhealthyListener {
            async fn handle_event(
                &mut self,
                _event: &SharedWalletEvent,
            ) -> Result<(), Box<dyn Error + Send + Sync>> {
                Ok(())
            }

            fn name(&self) -> &'static str {
                "unhealthy_listener"
            }

            fn is_healthy(&self) -> bool {
                false
            }
        }

        registry.register(Box::new(HealthyListener)).await.unwrap();
        registry
            .register(Box::new(UnhealthyListener))
            .await
            .unwrap();
        assert_eq!(registry.listener_count(), 2);

        let health_status = registry.health_check();
        assert_eq!(health_status.len(), 2);
        assert_eq!(health_status.get("healthy_listener"), Some(&true));
        assert_eq!(health_status.get("unhealthy_listener"), Some(&false));
    }

    #[tokio::test]
    async fn test_remove_unhealthy_listeners() {
        let mut registry = EventRegistry::new();

        // Test healthy listener
        struct HealthyListener;

        #[async_trait]
        impl EventListener for HealthyListener {
            async fn handle_event(
                &mut self,
                _event: &SharedWalletEvent,
            ) -> Result<(), Box<dyn Error + Send + Sync>> {
                Ok(())
            }

            fn name(&self) -> &'static str {
                "healthy_listener"
            }

            fn is_healthy(&self) -> bool {
                true
            }
        }

        // Test unhealthy listener
        struct UnhealthyListener;

        #[async_trait]
        impl EventListener for UnhealthyListener {
            async fn handle_event(
                &mut self,
                _event: &SharedWalletEvent,
            ) -> Result<(), Box<dyn Error + Send + Sync>> {
                Ok(())
            }

            fn name(&self) -> &'static str {
                "unhealthy_listener"
            }

            fn is_healthy(&self) -> bool {
                false
            }
        }

        registry.register(Box::new(HealthyListener)).await.unwrap();
        registry
            .register(Box::new(UnhealthyListener))
            .await
            .unwrap();
        assert_eq!(registry.listener_count(), 2);

        let removed = registry.remove_unhealthy_listeners().await;
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], "unhealthy_listener");
        assert_eq!(registry.listener_count(), 1);
        assert!(registry.has_listener("healthy_listener"));
        assert!(!registry.has_listener("unhealthy_listener"));
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let mut registry = EventRegistry::new();
        let listener = TestListener::new("stats_listener");
        let events_received = listener.events_received.clone();

        registry.register(Box::new(listener)).await.unwrap();

        // Initial stats
        let stats = registry.get_stats();
        assert_eq!(stats.listeners_registered, 1);
        assert_eq!(stats.total_events_dispatched, 0);
        assert_eq!(stats.total_listener_calls, 0);

        // Create and dispatch events
        let metadata1 = EventMetadata::new("test", "test_wallet");
        let payload1 = UtxoReceivedPayload::new(
            "test_utxo1".to_string(),
            1000,
            100,
            "block_hash".to_string(),
            1234567890,
            "tx_hash".to_string(),
            0,
            "address".to_string(),
            0,
            "commitment".to_string(),
            0,
            "mainnet".to_string(),
        );
        let event1 = SharedWalletEvent::new(WalletEvent::UtxoReceived {
            metadata: metadata1,
            payload: payload1,
        });

        let metadata2 = EventMetadata::new("test", "test_wallet");
        let payload2 = UtxoReceivedPayload::new(
            "test_utxo2".to_string(),
            2000,
            101,
            "block_hash2".to_string(),
            1234567891,
            "tx_hash2".to_string(),
            0,
            "address2".to_string(),
            0,
            "commitment2".to_string(),
            0,
            "mainnet".to_string(),
        );
        let event2 = SharedWalletEvent::new(WalletEvent::UtxoReceived {
            metadata: metadata2,
            payload: payload2,
        });

        registry.dispatch(event1).await;
        registry.dispatch(event2).await;

        // Check updated stats
        let stats = registry.get_stats();
        assert_eq!(stats.total_events_dispatched, 2);
        assert_eq!(stats.total_listener_calls, 2);
        assert_eq!(stats.total_listener_errors, 0);
        assert_eq!(stats.events_by_type.get("UtxoReceived"), Some(&2));

        // Verify events were received
        let events = events_received.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], "UtxoReceived");
        assert_eq!(events[1], "UtxoReceived");
    }

    #[tokio::test]
    async fn test_statistics_clearing() {
        let mut registry = EventRegistry::new();
        let listener = TestListener::new("stats_listener");

        registry.register(Box::new(listener)).await.unwrap();

        // Dispatch an event to generate stats
        let metadata = EventMetadata::new("test", "test_wallet");
        let payload = UtxoReceivedPayload::new(
            "test_utxo".to_string(),
            1000,
            100,
            "block_hash".to_string(),
            1234567890,
            "tx_hash".to_string(),
            0,
            "address".to_string(),
            0,
            "commitment".to_string(),
            0,
            "mainnet".to_string(),
        );
        let event = SharedWalletEvent::new(WalletEvent::UtxoReceived { metadata, payload });

        registry.dispatch(event).await;

        let stats = registry.get_stats();
        assert_eq!(stats.total_events_dispatched, 1);
        assert_eq!(stats.listeners_registered, 1);

        // Clear stats
        registry.clear_stats();

        let stats = registry.get_stats();
        assert_eq!(stats.total_events_dispatched, 0);
        assert_eq!(stats.total_listener_calls, 0);
        assert_eq!(stats.listeners_registered, 0); // This is cleared too
        assert!(stats.events_by_type.is_empty());
    }

    #[tokio::test]
    async fn test_listener_initialization_failure() {
        let mut registry = EventRegistry::new();

        // Test listener that fails initialization
        struct FailingInitListener;

        #[async_trait]
        impl EventListener for FailingInitListener {
            async fn handle_event(
                &mut self,
                _event: &SharedWalletEvent,
            ) -> Result<(), Box<dyn Error + Send + Sync>> {
                Ok(())
            }

            fn name(&self) -> &'static str {
                "failing_init_listener"
            }

            async fn initialize(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
                Err("Initialization failed".into())
            }
        }

        let result = registry.register(Box::new(FailingInitListener)).await;
        assert!(result.is_err());
        assert_eq!(registry.listener_count(), 0);
    }

    #[tokio::test]
    async fn test_event_filtering_by_wants_event() {
        let mut registry = EventRegistry::new();

        // Listener that only wants UTXO spent events
        struct SpentOnlyListener {
            events_received: Arc<Mutex<Vec<String>>>,
        }

        impl SpentOnlyListener {
            fn new() -> Self {
                Self {
                    events_received: Arc::new(Mutex::new(Vec::new())),
                }
            }
        }

        #[async_trait]
        impl EventListener for SpentOnlyListener {
            async fn handle_event(
                &mut self,
                event: &SharedWalletEvent,
            ) -> Result<(), Box<dyn Error + Send + Sync>> {
                let event_type = match &**event {
                    WalletEvent::UtxoReceived { .. } => "UtxoReceived",
                    WalletEvent::UtxoSpent { .. } => "UtxoSpent",
                    WalletEvent::Reorg { .. } => "Reorg",
                };

                self.events_received
                    .lock()
                    .unwrap()
                    .push(event_type.to_string());
                Ok(())
            }

            fn name(&self) -> &'static str {
                "spent_only_listener"
            }

            fn wants_event(&self, event: &SharedWalletEvent) -> bool {
                matches!(&**event, WalletEvent::UtxoSpent { .. })
            }
        }

        let spent_listener = SpentOnlyListener::new();
        let events_received = spent_listener.events_received.clone();

        registry.register(Box::new(spent_listener)).await.unwrap();

        // Create UtxoReceived event (should be filtered out)
        let metadata1 = EventMetadata::new("test", "test_wallet");
        let payload1 = UtxoReceivedPayload::new(
            "test_utxo".to_string(),
            1000,
            100,
            "block_hash".to_string(),
            1234567890,
            "tx_hash".to_string(),
            0,
            "address".to_string(),
            0,
            "commitment".to_string(),
            0,
            "mainnet".to_string(),
        );
        let received_event = SharedWalletEvent::new(WalletEvent::UtxoReceived {
            metadata: metadata1,
            payload: payload1,
        });

        registry.dispatch(received_event).await;

        // Listener should not have received the event
        let events = events_received.lock().unwrap();
        assert_eq!(events.len(), 0);

        // Check that no listener calls were made due to filtering
        let stats = registry.get_stats();
        assert_eq!(stats.total_events_dispatched, 1);
        assert_eq!(stats.total_listener_calls, 0); // No calls because of filtering
    }

    #[tokio::test]
    async fn test_multiple_event_types() {
        let mut registry = EventRegistry::new();
        let listener = TestListener::new("multi_event_listener");
        let events_received = listener.events_received.clone();

        registry.register(Box::new(listener)).await.unwrap();

        // Create different types of events
        use crate::events::types::{ReorgPayload, UtxoSpentPayload};

        // UtxoReceived event
        let metadata1 = EventMetadata::new("test", "test_wallet");
        let payload1 = UtxoReceivedPayload::new(
            "test_utxo".to_string(),
            1000,
            100,
            "block_hash".to_string(),
            1234567890,
            "tx_hash".to_string(),
            0,
            "address".to_string(),
            0,
            "commitment".to_string(),
            0,
            "mainnet".to_string(),
        );
        let received_event = SharedWalletEvent::new(WalletEvent::UtxoReceived {
            metadata: metadata1,
            payload: payload1,
        });

        // UtxoSpent event
        let metadata2 = EventMetadata::new("test", "test_wallet");
        let payload2 = UtxoSpentPayload::new(
            "spent_utxo".to_string(),
            2000,
            50,
            200,
            "spending_block_hash".to_string(),
            1234567892,
            "spending_tx_hash".to_string(),
            1,
            "spending_address".to_string(),
            1,
            "spent_commitment".to_string(),
            "commitment".to_string(),
            false,
            "mainnet".to_string(),
        );
        let spent_event = SharedWalletEvent::new(WalletEvent::UtxoSpent {
            metadata: metadata2,
            payload: payload2,
        });

        // Reorg event
        let metadata3 = EventMetadata::new("test", "test_wallet");
        let payload3 = ReorgPayload::new(
            150,
            "old_block_hash".to_string(),
            "new_block_hash".to_string(),
            5,
            3,
            vec!["tx1".to_string(), "tx2".to_string()],
            vec!["utxo1".to_string()],
            -1000,
            "mainnet".to_string(),
            1234567893,
        );
        let reorg_event = SharedWalletEvent::new(WalletEvent::Reorg {
            metadata: metadata3,
            payload: payload3,
        });

        // Dispatch all events
        registry.dispatch(received_event).await;
        registry.dispatch(spent_event).await;
        registry.dispatch(reorg_event).await;

        // Verify all events were received
        let events = events_received.lock().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0], "UtxoReceived");
        assert_eq!(events[1], "UtxoSpent");
        assert_eq!(events[2], "Reorg");

        // Check statistics
        let stats = registry.get_stats();
        assert_eq!(stats.total_events_dispatched, 3);
        assert_eq!(stats.total_listener_calls, 3);
        assert_eq!(stats.events_by_type.get("UtxoReceived"), Some(&1));
        assert_eq!(stats.events_by_type.get("UtxoSpent"), Some(&1));
        assert_eq!(stats.events_by_type.get("Reorg"), Some(&1));
    }
}
