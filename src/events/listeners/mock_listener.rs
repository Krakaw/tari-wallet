//! Mock event listener for testing scenarios
//!
//! This module provides a mock implementation of the `EventListener` trait designed
//! specifically for testing purposes. It captures events and provides utilities for
//! making assertions about event sequences and content.
//!
//! # Features
//!
//! - **Event Capture**: Records all received events with timestamps
//! - **Thread Safety**: Uses Arc<Mutex<>> for safe concurrent access
//! - **Event Filtering**: Can be configured to capture only specific event types
//! - **Flexible Assertions**: Supports both count-based and content-based assertions
//! - **Builder Pattern**: Easy configuration with preset test scenarios
//! - **Deterministic Testing**: Full support for deterministic async testing with controlled time
//!
//! # Usage Examples
//!
//! ## Basic Event Capture
//! ```rust,ignore
//! use lightweight_wallet_libs::events::{EventDispatcher, WalletScanEvent};
//! use lightweight_wallet_libs::events::listeners::MockEventListener;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut dispatcher = EventDispatcher::new();
//! let mock = MockEventListener::new();
//! let captured_events = mock.get_captured_events();
//!
//! dispatcher.register(Box::new(mock))?;
//!
//! // Dispatch some events
//! let event = WalletScanEvent::scan_started(
//!     ScanConfig::default(),
//!     (0, 100),
//!     "test_wallet".to_string()
//! );
//! dispatcher.dispatch(event).await;
//!
//! // Assert on captured events
//! let events = captured_events.lock().unwrap();
//! assert_eq!(events.len(), 1);
//! assert!(events[0].contains("ScanStarted"));
//! # Ok(())
//! # }
//! ```
//!
//! ## Event Type Filtering
//! ```rust,ignore
//! // Only capture progress events
//! let mock = MockEventListener::builder()
//!     .capture_only(vec!["ScanProgress".to_string()])
//!     .build();
//!
//! // Only capture error and completion events
//! let mock = MockEventListener::builder()
//!     .capture_only(vec!["ScanError".to_string(), "ScanCompleted".to_string()])
//!     .build();
//! ```
//!
//! ## Assertion Helpers
//! ```rust,ignore
//! # async fn assertion_example() -> Result<(), Box<dyn std::error::Error>> {
//! let mock = MockEventListener::new();
//! let events = mock.get_captured_events();
//!
//! // ... dispatch events ...
//!
//! // Count-based assertions
//! mock.assert_event_count(5)?;
//! mock.assert_event_type_count("ScanProgress", 3)?;
//!
//! // Content-based assertions
//! mock.assert_contains_event_with_content("block_range")?;
//! mock.assert_last_event_type("ScanCompleted")?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Builder Pattern and Presets
//! ```rust,ignore
//! // Basic testing preset - captures all events
//! let mock = MockEventListener::builder()
//!     .testing_preset()
//!     .build();
//!
//! // Performance testing preset - minimal overhead
//! let mock = MockEventListener::builder()
//!     .performance_preset()
//!     .build();
//!
//! // Debug testing preset - detailed event capture
//! let mock = MockEventListener::builder()
//!     .debug_preset()
//!     .build();
//!
//! // Silent testing preset - count only, no content
//! let mock = MockEventListener::builder()
//!     .silent_preset()
//!     .build();
//!
//! // Error testing preset - only capture errors
//! let mock = MockEventListener::builder()
//!     .error_testing_preset()
//!     .build();
//! ```
//!
//! ## Deterministic Async Testing
//! ```rust,ignore
//! #[tokio::test(start_paused = true)]
//! async fn test_deterministic_scanning() {
//!     let mock = MockEventListener::new();
//!     
//!     // Spawn event producer with controlled timing
//!     tokio::spawn(async move {
//!         tokio::time::sleep(Duration::from_millis(100)).await;
//!         // ... dispatch events ...
//!     });
//!     
//!     // Wait deterministically without real time delays
//!     let result = mock.wait_for_event_count_deterministic(5, 1000).await;
//!     
//!     // Advance time in controlled increments
//!     tokio::time::advance(Duration::from_millis(100)).await;
//!     tokio::task::yield_now().await;
//!     
//!     assert!(result.is_ok());
//! }
//! ```
//!
//! ## Custom Polling Intervals
//! ```rust,ignore
//! // Wait with custom polling interval for better control
//! let result = mock.wait_for_event_type_with_interval(
//!     "ScanCompleted",
//!     Duration::from_secs(5),
//!     Duration::from_millis(100), // Poll every 100ms instead of 10ms
//! ).await;
//!
//! // Yield control without time advancement
//! mock.yield_now().await;
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::events::types::{EventType, SerializableEvent};
use crate::events::{EventListener, SharedEvent};

/// Configuration for the mock event listener
#[derive(Debug, Clone)]
pub struct MockListenerConfig {
    /// Whether to capture event content or just count events
    pub capture_content: bool,
    /// Maximum number of events to store in memory
    pub max_events: Option<usize>,
    /// Event types to capture (None means capture all)
    pub event_type_filter: Option<Vec<String>>,
    /// Whether to include timing information
    pub include_timing: bool,
    /// Whether to fail on specific event types (for error testing)
    pub fail_on_event_types: Vec<String>,
    /// Custom failure message for testing error handling
    pub failure_message: String,
}

impl Default for MockListenerConfig {
    fn default() -> Self {
        Self {
            capture_content: true,
            max_events: Some(1000),
            event_type_filter: None,
            include_timing: true,
            fail_on_event_types: Vec::new(),
            failure_message: "Mock listener test failure".to_string(),
        }
    }
}

/// Information about a captured event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedEvent {
    /// The type of event (e.g., "ScanStarted", "BlockProcessed")
    pub event_type: String,
    /// Event content as JSON string (if content capture is enabled)
    pub content: Option<String>,
    /// When the event was captured
    pub capture_time: SystemTime,
    /// Processing time for the event (if timing is enabled)
    pub processing_duration: Option<Duration>,
    /// Event metadata ID for correlation
    pub event_id: String,
    /// Source of the event
    pub source: String,
}

impl CapturedEvent {
    /// Create a new captured event
    pub fn new(
        event_type: String,
        content: Option<String>,
        event_id: String,
        source: String,
        processing_duration: Option<Duration>,
    ) -> Self {
        Self {
            event_type,
            content,
            capture_time: SystemTime::now(),
            processing_duration,
            event_id,
            source,
        }
    }

    /// Check if this event contains specific text in its content
    pub fn contains_content(&self, text: &str) -> bool {
        self.content
            .as_ref()
            .map_or(false, |content| content.contains(text))
    }

    /// Get the event as a compact summary string
    pub fn summary(&self) -> String {
        format!(
            "{} (id: {}, source: {})",
            self.event_type,
            &self.event_id[..8], // Show first 8 chars of ID
            self.source
        )
    }
}

/// Statistics about captured events
#[derive(Debug, Clone, Default, Serialize)]
pub struct MockListenerStats {
    /// Total number of events captured
    pub total_events: usize,
    /// Events by type
    pub events_by_type: HashMap<String, usize>,
    /// Total processing time across all events
    pub total_processing_time: Duration,
    /// Average processing time per event
    pub average_processing_time: Option<Duration>,
    /// First event capture time
    pub first_event_time: Option<SystemTime>,
    /// Last event capture time
    pub last_event_time: Option<SystemTime>,
    /// Events that caused failures (for error testing)
    pub failed_events: usize,
}

/// Builder for configuring MockEventListener
#[derive(Debug)]
pub struct MockListenerBuilder {
    config: MockListenerConfig,
}

impl MockListenerBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: MockListenerConfig::default(),
        }
    }

    /// Set whether to capture event content
    pub fn capture_content(mut self, capture: bool) -> Self {
        self.config.capture_content = capture;
        self
    }

    /// Set maximum number of events to store
    pub fn max_events(mut self, max: usize) -> Self {
        self.config.max_events = Some(max);
        self
    }

    /// Remove event limit (unlimited storage)
    pub fn unlimited_events(mut self) -> Self {
        self.config.max_events = None;
        self
    }

    /// Set event types to capture (filters out other types)
    pub fn capture_only(mut self, event_types: Vec<String>) -> Self {
        self.config.event_type_filter = Some(event_types);
        self
    }

    /// Include timing information for captured events
    pub fn include_timing(mut self, include: bool) -> Self {
        self.config.include_timing = include;
        self
    }

    /// Configure the listener to fail on specific event types (for error testing)
    pub fn fail_on_event_types(mut self, event_types: Vec<String>) -> Self {
        self.config.fail_on_event_types = event_types;
        self
    }

    /// Set custom failure message for error testing
    pub fn failure_message(mut self, message: String) -> Self {
        self.config.failure_message = message;
        self
    }

    /// Apply testing preset configuration
    pub fn testing_preset(mut self) -> Self {
        self.config = MockListenerConfig {
            capture_content: true,
            max_events: Some(100),
            event_type_filter: None,
            include_timing: true,
            fail_on_event_types: Vec::new(),
            failure_message: "Test failure".to_string(),
        };
        self
    }

    /// Apply performance preset configuration (minimal overhead)
    pub fn performance_preset(mut self) -> Self {
        self.config = MockListenerConfig {
            capture_content: false,
            max_events: Some(50),
            event_type_filter: None,
            include_timing: false,
            fail_on_event_types: Vec::new(),
            failure_message: "Performance test failure".to_string(),
        };
        self
    }

    /// Apply debug preset configuration (detailed capture)
    pub fn debug_preset(mut self) -> Self {
        self.config = MockListenerConfig {
            capture_content: true,
            max_events: None, // Unlimited
            event_type_filter: None,
            include_timing: true,
            fail_on_event_types: Vec::new(),
            failure_message: "Debug test failure".to_string(),
        };
        self
    }

    /// Apply silent preset configuration (count only)
    pub fn silent_preset(mut self) -> Self {
        self.config = MockListenerConfig {
            capture_content: false,
            max_events: Some(1000),
            event_type_filter: None,
            include_timing: false,
            fail_on_event_types: Vec::new(),
            failure_message: "Silent test failure".to_string(),
        };
        self
    }

    /// Apply error testing preset (capture errors only)
    pub fn error_testing_preset(mut self) -> Self {
        self.config = MockListenerConfig {
            capture_content: true,
            max_events: Some(50),
            event_type_filter: Some(vec!["ScanError".to_string()]),
            include_timing: true,
            fail_on_event_types: Vec::new(),
            failure_message: "Error test failure".to_string(),
        };
        self
    }

    /// Build the MockEventListener
    pub fn build(self) -> MockEventListener {
        MockEventListener::with_config(self.config)
    }
}

impl Default for MockListenerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock event listener that captures events for testing
#[derive(Clone)]
pub struct MockEventListener {
    /// Configuration for the listener
    config: MockListenerConfig,
    /// Captured events (thread-safe)
    captured_events: Arc<Mutex<Vec<CapturedEvent>>>,
    /// Statistics about captured events
    stats: Arc<Mutex<MockListenerStats>>,
}

impl MockEventListener {
    /// Create a new mock listener with default configuration
    pub fn new() -> Self {
        Self::with_config(MockListenerConfig::default())
    }

    /// Create a new mock listener with specific configuration
    pub fn with_config(config: MockListenerConfig) -> Self {
        Self {
            config,
            captured_events: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(Mutex::new(MockListenerStats::default())),
        }
    }

    /// Create a builder for configuring the mock listener
    pub fn builder() -> MockListenerBuilder {
        MockListenerBuilder::new()
    }

    /// Get a reference to the captured events (thread-safe)
    pub fn get_captured_events(&self) -> Arc<Mutex<Vec<CapturedEvent>>> {
        self.captured_events.clone()
    }

    /// Get current statistics
    pub fn get_stats(&self) -> MockListenerStats {
        self.stats.lock().unwrap().clone()
    }

    /// Clear all captured events and reset statistics
    pub fn clear(&self) {
        let mut events = self.captured_events.lock().unwrap();
        let mut stats = self.stats.lock().unwrap();
        events.clear();
        *stats = MockListenerStats::default();
    }

    /// Get the number of captured events
    pub fn event_count(&self) -> usize {
        self.captured_events.lock().unwrap().len()
    }

    /// Get the number of events of a specific type
    pub fn event_type_count(&self, event_type: &str) -> usize {
        self.captured_events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.event_type == event_type)
            .count()
    }

    /// Get all events of a specific type
    pub fn get_events_of_type(&self, event_type: &str) -> Vec<CapturedEvent> {
        self.captured_events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.event_type == event_type)
            .cloned()
            .collect()
    }

    /// Get the last captured event
    pub fn get_last_event(&self) -> Option<CapturedEvent> {
        self.captured_events.lock().unwrap().last().cloned()
    }

    /// Get the first captured event
    pub fn get_first_event(&self) -> Option<CapturedEvent> {
        self.captured_events.lock().unwrap().first().cloned()
    }

    /// Find events containing specific content
    pub fn find_events_with_content(&self, content: &str) -> Vec<CapturedEvent> {
        self.captured_events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.contains_content(content))
            .cloned()
            .collect()
    }

    /// Wait for a specific number of events with timeout
    ///
    /// This method supports deterministic async testing by using Tokio's time
    /// infrastructure when available (in tests with `tokio::test(start_paused = true)`).
    pub async fn wait_for_event_count(
        &self,
        expected_count: usize,
        timeout: Duration,
    ) -> Result<(), String> {
        self.wait_for_event_count_with_interval(expected_count, timeout, Duration::from_millis(10))
            .await
    }

    /// Wait for a specific number of events with configurable polling interval
    ///
    /// This allows for deterministic testing by controlling the polling interval.
    /// In tests, use a larger interval or control time with `tokio::time::advance()`.
    pub async fn wait_for_event_count_with_interval(
        &self,
        expected_count: usize,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<(), String> {
        let start = tokio::time::Instant::now();
        while start.elapsed() < timeout {
            if self.event_count() >= expected_count {
                return Ok(());
            }
            tokio::time::sleep(poll_interval).await;
        }
        Err(format!(
            "Timeout waiting for {} events, got {}",
            expected_count,
            self.event_count()
        ))
    }

    /// Wait for an event of a specific type with timeout
    ///
    /// This method supports deterministic async testing by using Tokio's time
    /// infrastructure when available (in tests with `tokio::test(start_paused = true)`).
    pub async fn wait_for_event_type(
        &self,
        event_type: &str,
        timeout: Duration,
    ) -> Result<CapturedEvent, String> {
        self.wait_for_event_type_with_interval(event_type, timeout, Duration::from_millis(10))
            .await
    }

    /// Wait for an event of a specific type with configurable polling interval
    ///
    /// This allows for deterministic testing by controlling the polling interval.
    /// In tests, use a larger interval or control time with `tokio::time::advance()`.
    pub async fn wait_for_event_type_with_interval(
        &self,
        event_type: &str,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<CapturedEvent, String> {
        let start = tokio::time::Instant::now();
        while start.elapsed() < timeout {
            if let Some(event) = self
                .captured_events
                .lock()
                .unwrap()
                .iter()
                .find(|e| e.event_type == event_type)
                .cloned()
            {
                return Ok(event);
            }
            tokio::time::sleep(poll_interval).await;
        }
        Err(format!(
            "Timeout waiting for event type '{}', got {} total events",
            event_type,
            self.event_count()
        ))
    }

    /// Wait for a specific number of events without timeout (deterministic testing)
    ///
    /// This method is designed for deterministic async testing where time is controlled.
    /// It polls continuously until the expected count is reached without any timeout.
    /// Use with `tokio::test(start_paused = true)` and `tokio::time::advance()`.
    pub async fn wait_for_event_count_deterministic(
        &self,
        expected_count: usize,
        max_iterations: usize,
    ) -> Result<(), String> {
        for _iteration in 0..max_iterations {
            if self.event_count() >= expected_count {
                return Ok(());
            }
            // Use a fixed interval that can be controlled by tokio test time
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Err(format!(
            "Maximum iterations ({}) reached waiting for {} events, got {}",
            max_iterations,
            expected_count,
            self.event_count()
        ))
    }

    /// Wait for an event type without timeout (deterministic testing)
    ///
    /// This method is designed for deterministic async testing where time is controlled.
    /// It polls continuously until the event type is found without any timeout.
    /// Use with `tokio::test(start_paused = true)` and `tokio::time::advance()`.
    pub async fn wait_for_event_type_deterministic(
        &self,
        event_type: &str,
        max_iterations: usize,
    ) -> Result<CapturedEvent, String> {
        for _iteration in 0..max_iterations {
            if let Some(event) = self
                .captured_events
                .lock()
                .unwrap()
                .iter()
                .find(|e| e.event_type == event_type)
                .cloned()
            {
                return Ok(event);
            }
            // Use a fixed interval that can be controlled by tokio test time
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Err(format!(
            "Maximum iterations ({}) reached waiting for event type '{}', got {} total events",
            max_iterations,
            event_type,
            self.event_count()
        ))
    }

    /// Yield control to allow async tasks to progress (deterministic testing)
    ///
    /// This method yields control to the async runtime without advancing real time.
    /// Useful for deterministic tests where you want to allow tasks to process
    /// without introducing real time delays.
    pub async fn yield_now(&self) {
        tokio::task::yield_now().await;
    }

    // Assertion helpers

    /// Assert that the exact number of events was captured
    pub fn assert_event_count(&self, expected: usize) -> Result<(), String> {
        let actual = self.event_count();
        if actual != expected {
            return Err(format!(
                "Expected {} events, but captured {}",
                expected, actual
            ));
        }
        Ok(())
    }

    /// Assert that at least the specified number of events was captured
    pub fn assert_min_event_count(&self, min_expected: usize) -> Result<(), String> {
        let actual = self.event_count();
        if actual < min_expected {
            return Err(format!(
                "Expected at least {} events, but captured {}",
                min_expected, actual
            ));
        }
        Ok(())
    }

    /// Assert that the exact number of events of a specific type was captured
    pub fn assert_event_type_count(&self, event_type: &str, expected: usize) -> Result<(), String> {
        let actual = self.event_type_count(event_type);
        if actual != expected {
            return Err(format!(
                "Expected {} '{}' events, but captured {}",
                expected, event_type, actual
            ));
        }
        Ok(())
    }

    /// Assert that at least one event contains specific content
    pub fn assert_contains_event_with_content(&self, content: &str) -> Result<(), String> {
        let matching_events = self.find_events_with_content(content);
        if matching_events.is_empty() {
            return Err(format!("No events found containing content: '{}'", content));
        }
        Ok(())
    }

    /// Assert that the last event is of a specific type
    pub fn assert_last_event_type(&self, expected_type: &str) -> Result<(), String> {
        match self.get_last_event() {
            Some(event) => {
                if event.event_type != expected_type {
                    return Err(format!(
                        "Last event was '{}', expected '{}'",
                        event.event_type, expected_type
                    ));
                }
                Ok(())
            }
            None => Err("No events captured".to_string()),
        }
    }

    /// Assert that the first event is of a specific type
    pub fn assert_first_event_type(&self, expected_type: &str) -> Result<(), String> {
        match self.get_first_event() {
            Some(event) => {
                if event.event_type != expected_type {
                    return Err(format!(
                        "First event was '{}', expected '{}'",
                        event.event_type, expected_type
                    ));
                }
                Ok(())
            }
            None => Err("No events captured".to_string()),
        }
    }

    /// Assert that events were captured in a specific order
    pub fn assert_event_sequence(&self, expected_types: &[&str]) -> Result<(), String> {
        let events = self.captured_events.lock().unwrap();
        if events.len() < expected_types.len() {
            return Err(format!(
                "Not enough events captured: got {}, need {}",
                events.len(),
                expected_types.len()
            ));
        }

        for (i, expected_type) in expected_types.iter().enumerate() {
            if events[i].event_type != *expected_type {
                return Err(format!(
                    "Event at position {} was '{}', expected '{}'",
                    i, events[i].event_type, expected_type
                ));
            }
        }
        Ok(())
    }

    /// Export captured events to JSON for analysis
    pub fn export_events_json(&self) -> Result<String, String> {
        let events = self.captured_events.lock().unwrap();
        serde_json::to_string_pretty(&*events).map_err(|e| e.to_string())
    }

    /// Export statistics to JSON for analysis
    pub fn export_stats_json(&self) -> Result<String, String> {
        let stats = self.get_stats();
        serde_json::to_string_pretty(&stats).map_err(|e| e.to_string())
    }

    // Private helper methods

    /// Check if we should capture this event type
    fn should_capture_event_type(&self, event_type: &str) -> bool {
        match &self.config.event_type_filter {
            Some(filter) => filter.contains(&event_type.to_string()),
            None => true,
        }
    }

    /// Check if we should fail on this event type (for error testing)
    fn should_fail_on_event_type(&self, event_type: &str) -> bool {
        self.config
            .fail_on_event_types
            .contains(&event_type.to_string())
    }

    /// Update statistics with a new event (for testing purposes)
    pub fn update_stats(&self, event_type: &str, processing_duration: Option<Duration>) {
        let mut stats = self.stats.lock().unwrap();
        stats.total_events += 1;
        *stats
            .events_by_type
            .entry(event_type.to_string())
            .or_insert(0) += 1;

        let now = SystemTime::now();
        if stats.first_event_time.is_none() {
            stats.first_event_time = Some(now);
        }
        stats.last_event_time = Some(now);

        if let Some(duration) = processing_duration {
            stats.total_processing_time += duration;
            stats.average_processing_time =
                Some(stats.total_processing_time / stats.total_events as u32);
        }
    }

    /// Enforce memory limits if configured
    fn enforce_memory_limits(&self) {
        if let Some(max_events) = self.config.max_events {
            let mut events = self.captured_events.lock().unwrap();
            if events.len() > max_events {
                let excess = events.len() - max_events;
                events.drain(0..excess);
            }
        }
    }
}

impl Default for MockEventListener {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventListener for MockEventListener {
    async fn handle_event(
        &mut self,
        event: &SharedEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = if self.config.include_timing {
            Some(Instant::now())
        } else {
            None
        };

        let event_type = event.event_type();
        let metadata = event.metadata();

        // Check if we should fail on this event type (for error testing)
        if self.should_fail_on_event_type(event_type) {
            self.stats.lock().unwrap().failed_events += 1;
            return Err(self.config.failure_message.clone().into());
        }

        // Check if we should capture this event type
        if !self.should_capture_event_type(event_type) {
            return Ok(());
        }

        let processing_duration = start_time.map(|start| start.elapsed());

        // Capture event content if configured
        let content = if self.config.capture_content {
            event.to_debug_json().ok()
        } else {
            None
        };

        let captured_event = CapturedEvent::new(
            event_type.to_string(),
            content,
            metadata.event_id.clone(),
            metadata.source.clone(),
            processing_duration,
        );

        // Store the event
        {
            let mut events = self.captured_events.lock().unwrap();
            events.push(captured_event);
        }

        // Update statistics
        self.update_stats(event_type, processing_duration);

        // Enforce memory limits
        self.enforce_memory_limits();

        Ok(())
    }

    fn name(&self) -> &'static str {
        "MockEventListener"
    }

    fn wants_event(&self, event: &SharedEvent) -> bool {
        self.should_capture_event_type(event.event_type())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::types::{ScanConfig, WalletScanEvent};
    use std::time::Duration;
    use tokio::time::sleep;

    #[test]
    fn test_mock_listener_creation() {
        let mock = MockEventListener::new();
        assert_eq!(mock.event_count(), 0);
        assert_eq!(mock.name(), "MockEventListener");
    }

    #[test]
    fn test_builder_pattern() {
        let mock = MockEventListener::builder()
            .capture_content(false)
            .max_events(50)
            .include_timing(false)
            .build();

        assert_eq!(mock.config.capture_content, false);
        assert_eq!(mock.config.max_events, Some(50));
        assert_eq!(mock.config.include_timing, false);
    }

    #[test]
    fn test_preset_configurations() {
        // Test testing preset
        let mock = MockEventListener::builder().testing_preset().build();
        assert!(mock.config.capture_content);
        assert_eq!(mock.config.max_events, Some(100));

        // Test performance preset
        let mock = MockEventListener::builder().performance_preset().build();
        assert!(!mock.config.capture_content);
        assert!(!mock.config.include_timing);

        // Test debug preset
        let mock = MockEventListener::builder().debug_preset().build();
        assert!(mock.config.capture_content);
        assert!(mock.config.max_events.is_none());

        // Test silent preset
        let mock = MockEventListener::builder().silent_preset().build();
        assert!(!mock.config.capture_content);

        // Test error testing preset
        let mock = MockEventListener::builder().error_testing_preset().build();
        assert_eq!(
            mock.config.event_type_filter,
            Some(vec!["ScanError".to_string()])
        );
    }

    #[tokio::test]
    async fn test_event_capture() {
        let mut mock = MockEventListener::new();
        let captured_events = mock.get_captured_events();

        // Create test events
        let event1 = WalletScanEvent::scan_started(
            ScanConfig::default(),
            (0, 100),
            "test_wallet".to_string(),
        );
        let event2 = WalletScanEvent::block_processed(
            1,
            "0x123".to_string(),
            1697123456,
            Duration::from_millis(100),
            5,
        );

        let shared_event1 = crate::events::SharedEvent::new(event1);
        let shared_event2 = crate::events::SharedEvent::new(event2);

        // Handle events
        mock.handle_event(&shared_event1).await.unwrap();
        mock.handle_event(&shared_event2).await.unwrap();

        // Check captured events
        let events = captured_events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "ScanStarted");
        assert_eq!(events[1].event_type, "BlockProcessed");
    }

    #[tokio::test]
    async fn test_event_type_filtering() {
        let mut mock = MockEventListener::builder()
            .capture_only(vec!["ScanStarted".to_string()])
            .build();

        let event1 = WalletScanEvent::scan_started(
            ScanConfig::default(),
            (0, 100),
            "test_wallet".to_string(),
        );
        let event2 = WalletScanEvent::block_processed(
            1,
            "0x123".to_string(),
            1697123456,
            Duration::from_millis(100),
            5,
        );

        let shared_event1 = crate::events::SharedEvent::new(event1);
        let shared_event2 = crate::events::SharedEvent::new(event2);

        mock.handle_event(&shared_event1).await.unwrap();
        mock.handle_event(&shared_event2).await.unwrap();

        // Only ScanStarted should be captured
        assert_eq!(mock.event_count(), 1);
        assert_eq!(mock.event_type_count("ScanStarted"), 1);
        assert_eq!(mock.event_type_count("BlockProcessed"), 0);
    }

    #[tokio::test]
    async fn test_failure_simulation() {
        let mut mock = MockEventListener::builder()
            .fail_on_event_types(vec!["ScanError".to_string()])
            .failure_message("Test failure".to_string())
            .build();

        let error_event =
            WalletScanEvent::scan_error("Test error".to_string(), None, None, None, true);
        let shared_event = crate::events::SharedEvent::new(error_event);

        // Should fail on ScanError events
        let result = mock.handle_event(&shared_event).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Test failure");

        let stats = mock.get_stats();
        assert_eq!(stats.failed_events, 1);
    }

    #[test]
    fn test_assertion_helpers() {
        let mock = MockEventListener::new();
        let captured_events = mock.get_captured_events();

        // Add some test events manually
        captured_events.lock().unwrap().push(CapturedEvent::new(
            "ScanStarted".to_string(),
            Some("test content".to_string()),
            "test-id-1".to_string(),
            "test_source".to_string(),
            None,
        ));
        captured_events.lock().unwrap().push(CapturedEvent::new(
            "ScanCompleted".to_string(),
            None,
            "test-id-2".to_string(),
            "test_source".to_string(),
            None,
        ));

        // Test assertions
        assert!(mock.assert_event_count(2).is_ok());
        assert!(mock.assert_event_count(3).is_err());

        assert!(mock.assert_event_type_count("ScanStarted", 1).is_ok());
        assert!(mock.assert_event_type_count("ScanStarted", 2).is_err());

        assert!(mock.assert_first_event_type("ScanStarted").is_ok());
        assert!(mock.assert_last_event_type("ScanCompleted").is_ok());

        assert!(mock
            .assert_contains_event_with_content("test content")
            .is_ok());
        assert!(mock
            .assert_contains_event_with_content("nonexistent")
            .is_err());

        assert!(mock
            .assert_event_sequence(&["ScanStarted", "ScanCompleted"])
            .is_ok());
        assert!(mock
            .assert_event_sequence(&["ScanCompleted", "ScanStarted"])
            .is_err());
    }

    #[tokio::test]
    async fn test_wait_for_events() {
        let mock = MockEventListener::new();
        let captured_events = mock.get_captured_events();

        // Start a task that adds events after a delay
        let captured_events_clone = captured_events.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(50)).await;
            captured_events_clone
                .lock()
                .unwrap()
                .push(CapturedEvent::new(
                    "ScanStarted".to_string(),
                    None,
                    "test-id".to_string(),
                    "test_source".to_string(),
                    None,
                ));
        });

        // Wait for the event
        let result = mock
            .wait_for_event_type("ScanStarted", Duration::from_millis(200))
            .await;
        assert!(result.is_ok());

        // Test timeout
        let result = mock
            .wait_for_event_type("NonExistent", Duration::from_millis(10))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn test_deterministic_async_wait_for_event_count() {
        let mock = MockEventListener::new();
        let captured_events = mock.get_captured_events();

        // Spawn a task that adds events at controlled time intervals
        let captured_events_clone = captured_events.clone();
        tokio::spawn(async move {
            for i in 0..3 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                captured_events_clone
                    .lock()
                    .unwrap()
                    .push(CapturedEvent::new(
                        format!("Event{}", i),
                        None,
                        format!("id-{}", i),
                        "test_source".to_string(),
                        None,
                    ));
            }
        });

        // Test deterministic waiting
        let wait_task = tokio::spawn({
            let mock = mock.clone();
            async move { mock.wait_for_event_count_deterministic(3, 1000).await }
        });

        // Advance time in controlled chunks to allow events to be added
        for _ in 0..3 {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await; // Allow the spawned task to run
        }

        // The wait should complete successfully
        let result = wait_task.await.unwrap();
        assert!(result.is_ok());
        assert_eq!(mock.event_count(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn test_deterministic_async_wait_for_event_type() {
        let mock = MockEventListener::new();
        let captured_events = mock.get_captured_events();

        // Spawn a task that adds different event types at controlled intervals
        let captured_events_clone = captured_events.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            captured_events_clone
                .lock()
                .unwrap()
                .push(CapturedEvent::new(
                    "Event1".to_string(),
                    None,
                    "id-1".to_string(),
                    "test_source".to_string(),
                    None,
                ));

            tokio::time::sleep(Duration::from_millis(50)).await;
            captured_events_clone
                .lock()
                .unwrap()
                .push(CapturedEvent::new(
                    "ScanStarted".to_string(),
                    None,
                    "id-2".to_string(),
                    "test_source".to_string(),
                    None,
                ));
        });

        // Test deterministic waiting for specific event type
        let wait_task = tokio::spawn({
            let mock = mock.clone();
            async move {
                mock.wait_for_event_type_deterministic("ScanStarted", 1000)
                    .await
            }
        });

        // Advance time to trigger event additions
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;

        // The wait should complete successfully and return the correct event
        let result = wait_task.await.unwrap();
        assert!(result.is_ok());
        let event = result.unwrap();
        assert_eq!(event.event_type, "ScanStarted");
        assert_eq!(mock.event_count(), 2);
    }

    #[tokio::test]
    async fn test_yield_now_functionality() {
        let mock = MockEventListener::new();
        let captured_events = mock.get_captured_events();

        // Spawn a task that adds an event immediately
        let captured_events_clone = captured_events.clone();
        tokio::spawn(async move {
            captured_events_clone
                .lock()
                .unwrap()
                .push(CapturedEvent::new(
                    "InstantEvent".to_string(),
                    None,
                    "instant-id".to_string(),
                    "test_source".to_string(),
                    None,
                ));
        });

        // Before yielding, the event might not be there yet
        assert_eq!(mock.event_count(), 0);

        // Yield control to allow the task to run
        mock.yield_now().await;

        // After yielding, the event should be there
        assert_eq!(mock.event_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_configurable_polling_intervals() {
        let mock = MockEventListener::new();
        let captured_events = mock.get_captured_events();

        // Add an event after a specific time
        let captured_events_clone = captured_events.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            captured_events_clone
                .lock()
                .unwrap()
                .push(CapturedEvent::new(
                    "DelayedEvent".to_string(),
                    None,
                    "delayed-id".to_string(),
                    "test_source".to_string(),
                    None,
                ));
        });

        // Test waiting with custom polling interval
        let wait_task = tokio::spawn({
            let mock = mock.clone();
            async move {
                mock.wait_for_event_count_with_interval(
                    1,
                    Duration::from_secs(2),
                    Duration::from_millis(100), // Custom polling interval
                )
                .await
            }
        });

        // Advance time to trigger the event
        tokio::time::advance(Duration::from_millis(600)).await;
        tokio::task::yield_now().await;

        // The wait should complete successfully
        let result = wait_task.await.unwrap();
        assert!(result.is_ok());
        assert_eq!(mock.event_count(), 1);
    }

    #[test]
    fn test_memory_limits() {
        let mock = MockEventListener::builder().max_events(2).build();
        let captured_events = mock.get_captured_events();

        // Add more events than the limit
        for i in 0..5 {
            captured_events.lock().unwrap().push(CapturedEvent::new(
                format!("Event{}", i),
                None,
                format!("id-{}", i),
                "test_source".to_string(),
                None,
            ));
            mock.enforce_memory_limits();
        }

        // Should only keep the last 2 events
        let events = captured_events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "Event3");
        assert_eq!(events[1].event_type, "Event4");
    }

    #[test]
    fn test_statistics() {
        let mock = MockEventListener::new();

        // Simulate some statistics updates
        mock.update_stats("ScanStarted", Some(Duration::from_millis(100)));
        mock.update_stats("ScanStarted", Some(Duration::from_millis(200)));
        mock.update_stats("BlockProcessed", Some(Duration::from_millis(150)));

        let stats = mock.get_stats();
        assert_eq!(stats.total_events, 3);
        assert_eq!(stats.events_by_type.get("ScanStarted"), Some(&2));
        assert_eq!(stats.events_by_type.get("BlockProcessed"), Some(&1));
        assert_eq!(stats.total_processing_time, Duration::from_millis(450));
        assert_eq!(
            stats.average_processing_time,
            Some(Duration::from_millis(150))
        );
    }

    #[test]
    fn test_export_functionality() {
        let mock = MockEventListener::new();
        let captured_events = mock.get_captured_events();

        captured_events.lock().unwrap().push(CapturedEvent::new(
            "ScanStarted".to_string(),
            Some("test content".to_string()),
            "test-id".to_string(),
            "test_source".to_string(),
            Some(Duration::from_millis(100)),
        ));

        // Test JSON export
        let events_json = mock.export_events_json().unwrap();
        assert!(events_json.contains("ScanStarted"));
        assert!(events_json.contains("test content"));

        // Update stats and test stats export
        mock.update_stats("ScanStarted", Some(Duration::from_millis(100)));
        let stats_json = mock.export_stats_json().unwrap();
        assert!(stats_json.contains("total_events"));
        assert!(stats_json.contains("ScanStarted"));
    }

    #[test]
    fn test_clear_functionality() {
        let mock = MockEventListener::new();
        let captured_events = mock.get_captured_events();

        // Add some events
        captured_events.lock().unwrap().push(CapturedEvent::new(
            "ScanStarted".to_string(),
            None,
            "test-id".to_string(),
            "test_source".to_string(),
            None,
        ));
        mock.update_stats("ScanStarted", Some(Duration::from_millis(100)));

        assert_eq!(mock.event_count(), 1);
        assert_eq!(mock.get_stats().total_events, 1);

        // Clear and verify
        mock.clear();
        assert_eq!(mock.event_count(), 0);
        assert_eq!(mock.get_stats().total_events, 0);
    }
}
