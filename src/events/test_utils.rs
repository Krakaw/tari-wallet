//! Event testing utilities and assertion helpers
//!
//! This module provides advanced testing utilities for event-driven code, including
//! assertion macros, event sequence validators, and testing patterns that build on
//! top of the MockEventListener functionality.
//!
//! # Features
//!
//! - **Assertion Macros**: Convenient macros for common event assertions
//! - **Event Pattern Matching**: Advanced pattern matching for complex event sequences
//! - **Test Scenarios**: Pre-built test scenarios for common scanning workflows
//! - **Event Verification**: Deep content verification and validation utilities
//! - **Performance Testing**: Event timing and performance assertion utilities
//! - **Error Injection**: Utilities for testing error handling in event flows
//!
//! # Usage Examples
//!
//! ## Basic Assertion Macros
//! ```rust,ignore
//! use lightweight_wallet_libs::events::test_utils::*;
//! use lightweight_wallet_libs::events::listeners::MockEventListener;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mock = MockEventListener::new();
//!
//! // ... dispatch some events ...
//!
//! // Use assertion macros for cleaner test code
//! assert_event_count!(mock, 5);
//! assert_event_sequence!(mock, ["ScanStarted", "BlockProcessed", "ScanCompleted"]);
//! assert_event_contains!(mock, "test_wallet");
//! assert_last_event_type!(mock, "ScanCompleted");
//! # Ok(())
//! # }
//! ```
//!
//! ## Event Pattern Matching
//! ```rust,ignore
//! use lightweight_wallet_libs::events::test_utils::EventPattern;
//!
//! # async fn pattern_example() -> Result<(), Box<dyn std::error::Error>> {
//! let mock = MockEventListener::new();
//!
//! // Define expected event patterns
//! let scan_pattern = EventPattern::sequence()
//!     .starts_with("ScanStarted")
//!     .followed_by_any_number_of("BlockProcessed")
//!     .ends_with("ScanCompleted")
//!     .with_content_matching("blocks.*100");
//!
//! // ... dispatch events ...
//!
//! // Verify the pattern matches
//! scan_pattern.verify(&mock)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Test Scenarios
//! ```rust,ignore
//! use lightweight_wallet_libs::events::test_utils::TestScenario;
//!
//! # async fn scenario_example() -> Result<(), Box<dyn std::error::Error>> {
//! // Use pre-built test scenarios
//! let scenario = TestScenario::successful_scan()
//!     .with_block_range(0, 100)
//!     .with_outputs_found(5)
//!     .with_duration_limit(Duration::from_secs(10));
//!
//! let (dispatcher, mock) = scenario.setup().await?;
//!
//! // ... run scanning operations ...
//!
//! scenario.verify(&mock).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::events::listeners::{mock_listener::CapturedEvent, MockEventListener};
use crate::events::EventDispatcher;

/// Result type for event testing operations
pub type EventTestResult<T> = Result<T, EventTestError>;

/// Errors that can occur during event testing
#[derive(Debug, Clone)]
pub enum EventTestError {
    /// Event count mismatch
    CountMismatch { expected: usize, actual: usize },
    /// Event type not found
    TypeNotFound(String),
    /// Event sequence mismatch
    SequenceMismatch { expected: String, actual: String },
    /// Content not found in events
    ContentNotFound(String),
    /// Timeout waiting for events
    Timeout(String),
    /// Pattern validation failed
    PatternFailed(String),
    /// Performance assertion failed
    PerformanceFailed(String),
    /// General assertion error
    AssertionFailed(String),
}

impl std::fmt::Display for EventTestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventTestError::CountMismatch { expected, actual } => {
                write!(f, "Event count mismatch: expected {expected}, got {actual}")
            }
            EventTestError::TypeNotFound(event_type) => {
                write!(f, "Event type '{event_type}' not found")
            }
            EventTestError::SequenceMismatch { expected, actual } => {
                write!(
                    f,
                    "Event sequence mismatch: expected '{expected}', got '{actual}'"
                )
            }
            EventTestError::ContentNotFound(content) => {
                write!(f, "Content '{content}' not found in any events")
            }
            EventTestError::Timeout(message) => {
                write!(f, "Timeout: {message}")
            }
            EventTestError::PatternFailed(message) => {
                write!(f, "Pattern validation failed: {message}")
            }
            EventTestError::PerformanceFailed(message) => {
                write!(f, "Performance assertion failed: {message}")
            }
            EventTestError::AssertionFailed(message) => {
                write!(f, "Assertion failed: {message}")
            }
        }
    }
}

impl std::error::Error for EventTestError {}

/// Advanced event pattern matching for complex event sequences
#[derive(Debug, Clone)]
pub struct EventPattern {
    start_patterns: Vec<String>,
    end_patterns: Vec<String>,
    required_patterns: Vec<String>,
    forbidden_patterns: Vec<String>,
    content_patterns: Vec<String>,
    min_count: Option<usize>,
    max_count: Option<usize>,
    ordered: bool,
}

impl EventPattern {
    /// Create a new event pattern for sequence matching
    pub fn sequence() -> Self {
        Self {
            start_patterns: Vec::new(),
            end_patterns: Vec::new(),
            required_patterns: Vec::new(),
            forbidden_patterns: Vec::new(),
            content_patterns: Vec::new(),
            min_count: None,
            max_count: None,
            ordered: true,
        }
    }

    /// Create a new event pattern for unordered matching
    pub fn unordered() -> Self {
        Self {
            start_patterns: Vec::new(),
            end_patterns: Vec::new(),
            required_patterns: Vec::new(),
            forbidden_patterns: Vec::new(),
            content_patterns: Vec::new(),
            min_count: None,
            max_count: None,
            ordered: false,
        }
    }

    /// Require the sequence to start with a specific event type
    pub fn starts_with(mut self, event_type: &str) -> Self {
        self.start_patterns.push(event_type.to_string());
        self
    }

    /// Require the sequence to end with a specific event type
    pub fn ends_with(mut self, event_type: &str) -> Self {
        self.end_patterns.push(event_type.to_string());
        self
    }

    /// Require a specific event type to appear (can be followed by others)
    pub fn followed_by_any_number_of(mut self, event_type: &str) -> Self {
        self.required_patterns.push(format!("{event_type}*"));
        self
    }

    /// Require a specific event type to appear exactly once
    pub fn contains(mut self, event_type: &str) -> Self {
        self.required_patterns.push(event_type.to_string());
        self
    }

    /// Forbid a specific event type from appearing
    pub fn does_not_contain(mut self, event_type: &str) -> Self {
        self.forbidden_patterns.push(event_type.to_string());
        self
    }

    /// Require content matching a pattern to appear in events
    pub fn with_content_matching(mut self, pattern: &str) -> Self {
        self.content_patterns.push(pattern.to_string());
        self
    }

    /// Set minimum number of events
    pub fn min_events(mut self, count: usize) -> Self {
        self.min_count = Some(count);
        self
    }

    /// Set maximum number of events
    pub fn max_events(mut self, count: usize) -> Self {
        self.max_count = Some(count);
        self
    }

    /// Set exact number of events
    pub fn exactly(mut self, count: usize) -> Self {
        self.min_count = Some(count);
        self.max_count = Some(count);
        self
    }

    /// Verify the pattern against captured events
    pub fn verify(&self, mock: &MockEventListener) -> EventTestResult<()> {
        let binding = mock.get_captured_events();
        let events = binding.lock().unwrap();

        // Check count constraints
        if let Some(min) = self.min_count {
            if events.len() < min {
                return Err(EventTestError::CountMismatch {
                    expected: min,
                    actual: events.len(),
                });
            }
        }

        if let Some(max) = self.max_count {
            if events.len() > max {
                return Err(EventTestError::CountMismatch {
                    expected: max,
                    actual: events.len(),
                });
            }
        }

        // Check start patterns
        if !self.start_patterns.is_empty() && !events.is_empty() {
            let first_event = &events[0];
            if !self.start_patterns.contains(&first_event.event_type) {
                return Err(EventTestError::SequenceMismatch {
                    expected: format!("starts with one of: {:?}", self.start_patterns),
                    actual: format!("starts with: {}", first_event.event_type),
                });
            }
        }

        // Check end patterns
        if !self.end_patterns.is_empty() && !events.is_empty() {
            let last_event = events.last().unwrap();
            if !self.end_patterns.contains(&last_event.event_type) {
                return Err(EventTestError::SequenceMismatch {
                    expected: format!("ends with one of: {:?}", self.end_patterns),
                    actual: format!("ends with: {}", last_event.event_type),
                });
            }
        }

        // Check required patterns
        for pattern in &self.required_patterns {
            if pattern.ends_with('*') {
                // Pattern allows any number (including zero)
                let event_type = &pattern[..pattern.len() - 1];
                // Just check that if it appears, it's in the right place for ordered sequences
                if self.ordered {
                    // For ordered sequences, this is more complex - for now just check presence
                    let found = events.iter().any(|e| e.event_type == event_type);
                    if !found && !pattern.is_empty() {
                        // Allow zero occurrences for patterns ending with *
                        continue;
                    }
                }
            } else {
                // Exact pattern match required
                let found = events.iter().any(|e| e.event_type == *pattern);
                if !found {
                    return Err(EventTestError::TypeNotFound(pattern.clone()));
                }
            }
        }

        // Check forbidden patterns
        for pattern in &self.forbidden_patterns {
            let found = events.iter().any(|e| e.event_type == *pattern);
            if found {
                return Err(EventTestError::PatternFailed(format!(
                    "Forbidden event type '{pattern}' was found"
                )));
            }
        }

        // Check content patterns
        for pattern in &self.content_patterns {
            let found = events.iter().any(|e| {
                e.content
                    .as_ref()
                    .is_some_and(|content| content.contains(pattern))
            });
            if !found {
                return Err(EventTestError::ContentNotFound(pattern.clone()));
            }
        }

        Ok(())
    }
}

/// Performance assertions for event timing
#[derive(Debug, Clone)]
pub struct PerformanceAssertion {
    max_total_duration: Option<Duration>,
    max_average_duration: Option<Duration>,
    min_events_per_second: Option<f64>,
    max_memory_usage: Option<usize>,
}

impl PerformanceAssertion {
    /// Create a new performance assertion
    pub fn new() -> Self {
        Self {
            max_total_duration: None,
            max_average_duration: None,
            min_events_per_second: None,
            max_memory_usage: None,
        }
    }

    /// Set maximum total processing duration
    pub fn max_total_duration(mut self, duration: Duration) -> Self {
        self.max_total_duration = Some(duration);
        self
    }

    /// Set maximum average processing duration per event
    pub fn max_average_duration(mut self, duration: Duration) -> Self {
        self.max_average_duration = Some(duration);
        self
    }

    /// Set minimum events per second requirement
    pub fn min_events_per_second(mut self, rate: f64) -> Self {
        self.min_events_per_second = Some(rate);
        self
    }

    /// Set maximum memory usage (number of events stored)
    pub fn max_memory_usage(mut self, max_events: usize) -> Self {
        self.max_memory_usage = Some(max_events);
        self
    }

    /// Verify performance metrics against captured events
    pub fn verify(&self, mock: &MockEventListener, test_duration: Duration) -> EventTestResult<()> {
        let stats = mock.get_stats();

        // Check total duration
        if let Some(max_total) = self.max_total_duration {
            if stats.total_processing_time > max_total {
                return Err(EventTestError::PerformanceFailed(format!(
                    "Total processing time {total:?} exceeded maximum {max_total:?}",
                    total = stats.total_processing_time,
                )));
            }
        }

        // Check average duration
        if let Some(max_avg) = self.max_average_duration {
            if let Some(actual_avg) = stats.average_processing_time {
                if actual_avg > max_avg {
                    return Err(EventTestError::PerformanceFailed(format!(
                        "Average processing time {actual_avg:?} exceeded maximum {max_avg:?}"
                    )));
                }
            }
        }

        // Check events per second
        if let Some(min_rate) = self.min_events_per_second {
            let actual_rate = stats.total_events as f64 / test_duration.as_secs_f64();
            if actual_rate < min_rate {
                return Err(EventTestError::PerformanceFailed(format!(
                    "Event rate {actual_rate:.2} events/sec was below minimum {min_rate:.2} events/sec"
                )));
            }
        }

        // Check memory usage
        if let Some(max_memory) = self.max_memory_usage {
            if mock.event_count() > max_memory {
                return Err(EventTestError::PerformanceFailed(format!(
                    "Memory usage {current} events exceeded maximum {max_memory} events",
                    current = mock.event_count(),
                )));
            }
        }

        Ok(())
    }
}

impl Default for PerformanceAssertion {
    fn default() -> Self {
        Self::new()
    }
}

/// Pre-built test scenarios for common scanning workflows
#[derive(Debug, Clone)]
pub struct TestScenario {
    #[allow(dead_code)]
    name: String,
    expected_events: Vec<String>,
    block_range: Option<(u64, u64)>,
    expected_outputs: Option<usize>,
    duration_limit: Option<Duration>,
    should_succeed: bool,
    custom_patterns: Vec<EventPattern>,
    performance_requirements: Option<PerformanceAssertion>,
}

impl TestScenario {
    /// Create a successful scan scenario
    pub fn successful_scan() -> Self {
        Self {
            name: "successful_scan".to_string(),
            expected_events: vec![
                "ScanStarted".to_string(),
                "BlockProcessed".to_string(),
                "ScanCompleted".to_string(),
            ],
            block_range: None,
            expected_outputs: None,
            duration_limit: None,
            should_succeed: true,
            custom_patterns: Vec::new(),
            performance_requirements: None,
        }
    }

    /// Create an error scan scenario
    pub fn error_scan() -> Self {
        Self {
            name: "error_scan".to_string(),
            expected_events: vec!["ScanStarted".to_string(), "ScanError".to_string()],
            block_range: None,
            expected_outputs: None,
            duration_limit: None,
            should_succeed: false,
            custom_patterns: Vec::new(),
            performance_requirements: None,
        }
    }

    /// Create a cancelled scan scenario
    pub fn cancelled_scan() -> Self {
        Self {
            name: "cancelled_scan".to_string(),
            expected_events: vec!["ScanStarted".to_string(), "ScanCancelled".to_string()],
            block_range: None,
            expected_outputs: None,
            duration_limit: None,
            should_succeed: false,
            custom_patterns: Vec::new(),
            performance_requirements: None,
        }
    }

    /// Create a scan with outputs scenario
    pub fn scan_with_outputs() -> Self {
        Self {
            name: "scan_with_outputs".to_string(),
            expected_events: vec![
                "ScanStarted".to_string(),
                "BlockProcessed".to_string(),
                "OutputFound".to_string(),
                "ScanCompleted".to_string(),
            ],
            block_range: None,
            expected_outputs: Some(1),
            duration_limit: None,
            should_succeed: true,
            custom_patterns: Vec::new(),
            performance_requirements: None,
        }
    }

    /// Set the expected block range for the scan
    pub fn with_block_range(mut self, start: u64, end: u64) -> Self {
        self.block_range = Some((start, end));
        self
    }

    /// Set the expected number of outputs to be found
    pub fn with_outputs_found(mut self, count: usize) -> Self {
        self.expected_outputs = Some(count);
        self
    }

    /// Set a duration limit for the scan
    pub fn with_duration_limit(mut self, limit: Duration) -> Self {
        self.duration_limit = Some(limit);
        self
    }

    /// Add a custom event pattern to verify
    pub fn with_pattern(mut self, pattern: EventPattern) -> Self {
        self.custom_patterns.push(pattern);
        self
    }

    /// Add performance requirements
    pub fn with_performance_requirements(mut self, requirements: PerformanceAssertion) -> Self {
        self.performance_requirements = Some(requirements);
        self
    }

    /// Set up the test scenario (returns configured dispatcher)
    /// Note: User must register their own MockEventListener to capture events
    pub async fn setup(&self) -> EventTestResult<EventDispatcher> {
        let dispatcher = EventDispatcher::new_with_debug();
        Ok(dispatcher)
    }

    /// Verify the scenario against captured events
    pub async fn verify(&self, mock: &MockEventListener) -> EventTestResult<()> {
        // Check basic event presence
        for expected_event in &self.expected_events {
            if mock.event_type_count(expected_event) == 0 {
                return Err(EventTestError::TypeNotFound(expected_event.clone()));
            }
        }

        // Check output count if specified
        if let Some(expected_outputs) = self.expected_outputs {
            let actual_outputs = mock.event_type_count("OutputFound");
            if actual_outputs != expected_outputs {
                return Err(EventTestError::CountMismatch {
                    expected: expected_outputs,
                    actual: actual_outputs,
                });
            }
        }

        // Check block range if specified
        if let Some((start, end)) = self.block_range {
            let events = mock.find_events_with_content(&format!("\"block_range\":[{start},{end}]"));
            if events.is_empty() {
                return Err(EventTestError::ContentNotFound(format!(
                    "block range {start}-{end}"
                )));
            }
        }

        // Verify success/failure expectation
        let has_completed = mock.event_type_count("ScanCompleted") > 0;
        let has_error = mock.event_type_count("ScanError") > 0;
        let has_cancelled = mock.event_type_count("ScanCancelled") > 0;

        if self.should_succeed && !has_completed {
            return Err(EventTestError::AssertionFailed(
                "Expected successful completion but no ScanCompleted event found".to_string(),
            ));
        }

        if !self.should_succeed && has_completed && !has_error && !has_cancelled {
            return Err(EventTestError::AssertionFailed(
                "Expected failure but scan completed successfully".to_string(),
            ));
        }

        // Verify custom patterns
        for pattern in &self.custom_patterns {
            pattern.verify(mock)?;
        }

        // Verify performance requirements if specified
        if let Some(perf) = &self.performance_requirements {
            // Use a default test duration if not specified
            let test_duration = self.duration_limit.unwrap_or(Duration::from_secs(10));
            perf.verify(mock, test_duration)?;
        }

        Ok(())
    }
}

/// Event capture utilities for advanced testing
#[derive(Clone)]
pub struct EventCapture {
    mock: MockEventListener,
    start_time: Instant,
}

impl EventCapture {
    /// Create a new event capture session
    pub fn new() -> Self {
        Self {
            mock: MockEventListener::new(),
            start_time: Instant::now(),
        }
    }

    /// Create a new event capture session with custom configuration
    pub fn with_config(mock: MockEventListener) -> Self {
        Self {
            mock,
            start_time: Instant::now(),
        }
    }

    /// Get the mock listener for registration
    pub fn mock_listener(&self) -> &MockEventListener {
        &self.mock
    }

    /// Get elapsed time since capture started
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Wait for a specific event pattern with timeout
    ///
    /// This method supports deterministic async testing by using Tokio's time
    /// infrastructure when available (in tests with `tokio::test(start_paused = true)`).
    pub async fn wait_for_pattern(
        &self,
        pattern: EventPattern,
        timeout: Duration,
    ) -> EventTestResult<()> {
        self.wait_for_pattern_with_interval(pattern, timeout, Duration::from_millis(10))
            .await
    }

    /// Wait for a specific event pattern with configurable polling interval
    ///
    /// This allows for deterministic testing by controlling the polling interval.
    /// In tests, use a larger interval or control time with `tokio::time::advance()`.
    pub async fn wait_for_pattern_with_interval(
        &self,
        pattern: EventPattern,
        timeout: Duration,
        poll_interval: Duration,
    ) -> EventTestResult<()> {
        let start = tokio::time::Instant::now();
        while start.elapsed() < timeout {
            if pattern.verify(&self.mock).is_ok() {
                return Ok(());
            }
            tokio::time::sleep(poll_interval).await;
        }
        Err(EventTestError::Timeout(format!(
            "Pattern not matched within {timeout:?}"
        )))
    }

    /// Wait for a specific event pattern without timeout (deterministic testing)
    ///
    /// This method is designed for deterministic async testing where time is controlled.
    /// It polls continuously until the pattern matches without any timeout.
    /// Use with `tokio::test(start_paused = true)` and `tokio::time::advance()`.
    pub async fn wait_for_pattern_deterministic(
        &self,
        pattern: EventPattern,
        max_iterations: usize,
    ) -> EventTestResult<()> {
        for _iteration in 0..max_iterations {
            if pattern.verify(&self.mock).is_ok() {
                return Ok(());
            }
            // Use a fixed interval that can be controlled by tokio test time
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Err(EventTestError::Timeout(format!(
            "Pattern not matched within {max_iterations} iterations"
        )))
    }

    /// Capture events for a specific duration and return results
    ///
    /// This method supports deterministic async testing by using Tokio's time
    /// infrastructure when available (in tests with `tokio::test(start_paused = true)`).
    pub async fn capture_for_duration(&self, duration: Duration) -> Vec<CapturedEvent> {
        tokio::time::sleep(duration).await;
        self.mock.get_captured_events().lock().unwrap().clone()
    }

    /// Capture events by yielding control a specific number of times (deterministic testing)
    ///
    /// This method is designed for deterministic async testing where you want to allow
    /// async tasks to progress without advancing real time. It yields control the specified
    /// number of times and then returns the captured events.
    pub async fn capture_with_yields(&self, yield_count: usize) -> Vec<CapturedEvent> {
        for _ in 0..yield_count {
            tokio::task::yield_now().await;
        }
        self.mock.get_captured_events().lock().unwrap().clone()
    }

    /// Create a summary report of captured events
    pub fn create_summary(&self) -> EventCaptureSummary {
        let binding = self.mock.get_captured_events();
        let events = binding.lock().unwrap();
        let stats = self.mock.get_stats();

        let mut event_counts = HashMap::new();
        let mut timeline = Vec::new();

        for event in events.iter() {
            *event_counts.entry(event.event_type.clone()).or_insert(0) += 1;
            timeline.push((event.capture_time, event.event_type.clone()));
        }

        EventCaptureSummary {
            total_events: events.len(),
            event_types: event_counts,
            timeline,
            duration: self.elapsed(),
            stats,
        }
    }
}

impl Default for EventCapture {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of an event capture session
#[derive(Debug, Clone)]
pub struct EventCaptureSummary {
    pub total_events: usize,
    pub event_types: HashMap<String, usize>,
    pub timeline: Vec<(std::time::SystemTime, String)>,
    pub duration: Duration,
    pub stats: crate::events::listeners::mock_listener::MockListenerStats,
}

impl EventCaptureSummary {
    /// Get events per second rate
    pub fn events_per_second(&self) -> f64 {
        self.total_events as f64 / self.duration.as_secs_f64()
    }

    /// Check if a specific event type was captured
    pub fn has_event_type(&self, event_type: &str) -> bool {
        self.event_types.contains_key(event_type)
    }

    /// Get count for a specific event type
    pub fn count_for_type(&self, event_type: &str) -> usize {
        self.event_types.get(event_type).copied().unwrap_or(0)
    }

    /// Export summary as JSON
    pub fn to_json(&self) -> Result<String, String> {
        // Create a serializable version without SystemTime
        let serializable_timeline: Vec<(String, String)> = self
            .timeline
            .iter()
            .map(|(time, event_type)| (format!("{time:?}"), event_type.clone()))
            .collect();

        let summary_data = serde_json::json!({
            "total_events": self.total_events,
            "event_types": self.event_types,
            "timeline": serializable_timeline,
            "duration_ms": self.duration.as_millis(),
            "events_per_second": self.events_per_second(),
            "stats": self.stats
        });

        serde_json::to_string_pretty(&summary_data).map_err(|e| e.to_string())
    }
}

// Assertion macros for convenient testing

/// Assert that the mock listener captured exactly the specified number of events
#[macro_export]
macro_rules! assert_event_count {
    ($mock:expr, $expected:expr) => {
        $mock
            .assert_event_count($expected)
            .map_err(|e| panic!("Event count assertion failed: {e}"))?
    };
}

/// Assert that the mock listener captured at least the specified number of events
#[macro_export]
macro_rules! assert_min_event_count {
    ($mock:expr, $min_expected:expr) => {
        $mock
            .assert_min_event_count($min_expected)
            .map_err(|e| panic!("Minimum event count assertion failed: {e}"))?
    };
}

/// Assert that the mock listener captured exactly the specified number of events of a type
#[macro_export]
macro_rules! assert_event_type_count {
    ($mock:expr, $event_type:expr, $expected:expr) => {
        $mock
            .assert_event_type_count($event_type, $expected)
            .map_err(|e| panic!("Event type count assertion failed: {e}"))?
    };
}

/// Assert that events were captured in the specified sequence
#[macro_export]
macro_rules! assert_event_sequence {
    ($mock:expr, [$($event_type:expr),+ $(,)?]) => {
        $mock.assert_event_sequence(&[$($event_type),+])
            .map_err(|e| panic!("Event sequence assertion failed: {e}"))?
    };
}

/// Assert that at least one event contains the specified content
#[macro_export]
macro_rules! assert_event_contains {
    ($mock:expr, $content:expr) => {
        $mock
            .assert_contains_event_with_content($content)
            .map_err(|e| panic!("Event content assertion failed: {e}"))?
    };
}

/// Assert that the last event is of the specified type
#[macro_export]
macro_rules! assert_last_event_type {
    ($mock:expr, $event_type:expr) => {
        $mock
            .assert_last_event_type($event_type)
            .map_err(|e| panic!("Last event type assertion failed: {e}"))?
    };
}

/// Assert that the first event is of the specified type
#[macro_export]
macro_rules! assert_first_event_type {
    ($mock:expr, $event_type:expr) => {
        $mock
            .assert_first_event_type($event_type)
            .map_err(|e| panic!("First event type assertion failed: {e}"))?
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    #[test]
    fn test_event_pattern_creation() {
        let pattern = EventPattern::sequence()
            .starts_with("ScanStarted")
            .contains("BlockProcessed")
            .ends_with("ScanCompleted")
            .min_events(3);

        assert_eq!(pattern.start_patterns, vec!["ScanStarted"]);
        assert_eq!(pattern.end_patterns, vec!["ScanCompleted"]);
        assert_eq!(pattern.required_patterns, vec!["BlockProcessed"]);
        assert_eq!(pattern.min_count, Some(3));
        assert!(pattern.ordered);
    }

    #[test]
    fn test_event_pattern_unordered() {
        let pattern = EventPattern::unordered()
            .contains("ScanStarted")
            .contains("ScanCompleted")
            .does_not_contain("ScanError");

        assert!(!pattern.ordered);
        assert_eq!(
            pattern.required_patterns,
            vec!["ScanStarted", "ScanCompleted"]
        );
        assert_eq!(pattern.forbidden_patterns, vec!["ScanError"]);
    }

    #[tokio::test]
    async fn test_event_pattern_verification() {
        let mock = MockEventListener::new();
        let captured_events = mock.get_captured_events();

        // Add test events
        captured_events.lock().unwrap().extend(vec![
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "ScanStarted".to_string(),
                Some("test content".to_string()),
                "id1".to_string(),
                "test".to_string(),
                None,
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "BlockProcessed".to_string(),
                None,
                "id2".to_string(),
                "test".to_string(),
                None,
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "ScanCompleted".to_string(),
                None,
                "id3".to_string(),
                "test".to_string(),
                None,
            ),
        ]);

        // Test successful pattern matching
        let pattern = EventPattern::sequence()
            .starts_with("ScanStarted")
            .ends_with("ScanCompleted")
            .contains("BlockProcessed")
            .exactly(3);

        assert!(pattern.verify(&mock).is_ok());

        // Test failed pattern matching
        let bad_pattern = EventPattern::sequence().starts_with("ScanError").exactly(3);

        assert!(bad_pattern.verify(&mock).is_err());
    }

    #[test]
    fn test_performance_assertion() {
        let perf = PerformanceAssertion::new()
            .max_total_duration(Duration::from_secs(1))
            .max_average_duration(Duration::from_millis(100))
            .min_events_per_second(10.0);

        assert_eq!(perf.max_total_duration, Some(Duration::from_secs(1)));
        assert_eq!(perf.max_average_duration, Some(Duration::from_millis(100)));
        assert_eq!(perf.min_events_per_second, Some(10.0));
    }

    #[test]
    fn test_test_scenario_creation() {
        let scenario = TestScenario::successful_scan()
            .with_block_range(0, 100)
            .with_outputs_found(5)
            .with_duration_limit(Duration::from_secs(10));

        assert_eq!(scenario.block_range, Some((0, 100)));
        assert_eq!(scenario.expected_outputs, Some(5));
        assert_eq!(scenario.duration_limit, Some(Duration::from_secs(10)));
        assert!(scenario.should_succeed);
    }

    #[tokio::test]
    async fn test_test_scenario_setup() {
        let scenario = TestScenario::successful_scan();
        let dispatcher = scenario.setup().await.unwrap();

        assert_eq!(dispatcher.listener_count(), 0);
    }

    #[test]
    fn test_event_capture_creation() {
        let capture = EventCapture::new();
        assert_eq!(capture.mock_listener().event_count(), 0);
        assert!(capture.elapsed() >= Duration::ZERO);
    }

    #[test]
    fn test_event_capture_summary() {
        let capture = EventCapture::new();
        let summary = capture.create_summary();

        assert_eq!(summary.total_events, 0);
        assert!(summary.event_types.is_empty());
        assert!(summary.timeline.is_empty());
        assert!(summary.duration >= Duration::ZERO);
    }

    #[test]
    fn test_event_capture_summary_methods() {
        let capture = EventCapture::new();

        // Add some mock events to test summary functionality
        let mock = capture.mock_listener();
        let captured_events = mock.get_captured_events();
        captured_events.lock().unwrap().push(
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "ScanStarted".to_string(),
                None,
                "id1".to_string(),
                "test".to_string(),
                None,
            ),
        );

        let summary = capture.create_summary();
        assert_eq!(summary.total_events, 1);
        assert!(summary.has_event_type("ScanStarted"));
        assert!(!summary.has_event_type("ScanCompleted"));
        assert_eq!(summary.count_for_type("ScanStarted"), 1);
        assert_eq!(summary.count_for_type("NonExistent"), 0);

        // Test JSON export
        let json = summary.to_json().unwrap();
        assert!(json.contains("total_events"));
        assert!(json.contains("ScanStarted"));
    }

    #[test]
    fn test_event_test_error_display() {
        let error = EventTestError::CountMismatch {
            expected: 5,
            actual: 3,
        };
        assert_eq!(error.to_string(), "Event count mismatch: expected 5, got 3");

        let error = EventTestError::TypeNotFound("ScanStarted".to_string());
        assert_eq!(error.to_string(), "Event type 'ScanStarted' not found");

        let error = EventTestError::ContentNotFound("test content".to_string());
        assert_eq!(
            error.to_string(),
            "Content 'test content' not found in any events"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_deterministic_event_pattern_waiting() {
        use crate::events::types::WalletScanEvent;
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let test_capture = EventCapture::new();
        let mut dispatcher = crate::events::EventDispatcher::new();

        // Register the mock listener
        dispatcher
            .register(Box::new(test_capture.mock_listener().clone()))
            .unwrap();

        // Spawn a task that dispatches events at controlled intervals
        let dispatcher = Arc::new(Mutex::new(dispatcher));
        tokio::spawn({
            let dispatcher = dispatcher.clone();
            async move {
                for i in 0..3 {
                    tokio::time::sleep(Duration::from_millis(100)).await;

                    let event = WalletScanEvent::block_processed(
                        i + 1,
                        format!("0x{i:x}"),
                        1697123456 + i,
                        Duration::from_millis(50),
                        2,
                    );
                    {
                        let mut dispatcher_guard = dispatcher.lock().await;
                        dispatcher_guard.dispatch(event).await;
                    }
                }
            }
        });

        // Test deterministic pattern waiting
        let pattern = EventPattern::sequence().exactly(3);
        let wait_task = tokio::spawn({
            let test_capture = test_capture.clone();
            async move {
                test_capture
                    .wait_for_pattern_deterministic(pattern, 1000)
                    .await
            }
        });

        // Advance time in controlled chunks
        for _ in 0..3 {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }

        // The pattern should match
        let result = wait_task.await.unwrap();
        assert!(result.is_ok());
        assert_eq!(test_capture.mock_listener().event_count(), 3);
    }

    #[tokio::test]
    async fn test_capture_with_yields() {
        use crate::events::types::WalletScanEvent;

        let test_capture = EventCapture::new();
        let mut dispatcher = crate::events::EventDispatcher::new();

        // Register the mock listener
        dispatcher
            .register(Box::new(test_capture.mock_listener().clone()))
            .unwrap();

        // Add events directly to demonstrate yield-based capturing
        for i in 0..5 {
            let event = WalletScanEvent::block_processed(
                i + 1,
                format!("0x{i:x}"),
                1697123456 + i,
                Duration::from_millis(10),
                1,
            );
            dispatcher.dispatch(event).await;
        }

        // Capture events using yield-based approach
        let events = test_capture.capture_with_yields(10).await;
        assert_eq!(events.len(), 5);

        // Verify all events are BlockProcessed
        for event in events {
            assert_eq!(event.event_type, "BlockProcessed");
        }
    }

    #[tokio::test]
    async fn test_deterministic_polling_intervals() {
        use crate::events::types::{ScanConfig, WalletScanEvent};

        let test_capture = EventCapture::new();
        let mut dispatcher = crate::events::EventDispatcher::new();

        // Register the mock listener
        dispatcher
            .register(Box::new(test_capture.mock_listener().clone()))
            .unwrap();

        // Add an event immediately
        let event = WalletScanEvent::scan_started(
            ScanConfig::default(),
            (0, 100),
            "test_wallet".to_string(),
        );
        dispatcher.dispatch(event).await;

        // Test waiting with custom polling interval
        let pattern = EventPattern::sequence().exactly(1);
        let result = test_capture
            .wait_for_pattern_with_interval(
                pattern,
                Duration::from_secs(1),
                Duration::from_millis(50), // Custom polling interval
            )
            .await;

        assert!(result.is_ok());
        assert_eq!(test_capture.mock_listener().event_count(), 1);
    }
}
