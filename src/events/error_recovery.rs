//! Error recovery and logging utilities for event listeners
//!
//! This module provides comprehensive error recovery mechanisms, retry logic,
//! circuit breakers, and structured logging for event listeners to ensure
//! robust operation in production environments.

use std::collections::HashMap;
// use std::sync::{Arc, Mutex}; // Unused imports
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime};

/// Configuration for error recovery behavior
#[derive(Debug, Clone)]
pub struct ErrorRecoveryConfig {
    /// Maximum number of consecutive errors before circuit breaker opens
    pub max_consecutive_errors: usize,
    /// Duration to wait before attempting to close circuit breaker
    pub circuit_breaker_timeout: Duration,
    /// Maximum number of retry attempts for recoverable errors
    pub max_retry_attempts: usize,
    /// Base delay between retry attempts (exponential backoff multiplier)
    pub retry_base_delay: Duration,
    /// Maximum delay between retry attempts
    pub retry_max_delay: Duration,
    /// Whether to enable detailed error logging
    pub enable_error_logging: bool,
    /// Maximum number of error records to keep in memory
    pub max_error_history: usize,
}

impl Default for ErrorRecoveryConfig {
    fn default() -> Self {
        Self {
            max_consecutive_errors: 5,
            circuit_breaker_timeout: Duration::from_secs(30),
            max_retry_attempts: 3,
            retry_base_delay: Duration::from_millis(100),
            retry_max_delay: Duration::from_secs(10),
            enable_error_logging: true,
            max_error_history: 100,
        }
    }
}

impl ErrorRecoveryConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum consecutive errors before circuit breaker opens
    pub fn with_max_consecutive_errors(mut self, max_errors: usize) -> Self {
        self.max_consecutive_errors = max_errors;
        self
    }

    /// Set circuit breaker timeout duration
    pub fn with_circuit_breaker_timeout(mut self, timeout: Duration) -> Self {
        self.circuit_breaker_timeout = timeout;
        self
    }

    /// Set maximum retry attempts
    pub fn with_max_retry_attempts(mut self, max_attempts: usize) -> Self {
        self.max_retry_attempts = max_attempts;
        self
    }

    /// Set retry delay configuration
    pub fn with_retry_delays(mut self, base_delay: Duration, max_delay: Duration) -> Self {
        self.retry_base_delay = base_delay;
        self.retry_max_delay = max_delay;
        self
    }

    /// Enable or disable error logging
    pub fn with_error_logging(mut self, enable: bool) -> Self {
        self.enable_error_logging = enable;
        self
    }

    /// Set maximum error history size
    pub fn with_max_error_history(mut self, max_history: usize) -> Self {
        self.max_error_history = max_history;
        self
    }

    /// Create a configuration optimized for production environments
    pub fn production() -> Self {
        Self {
            max_consecutive_errors: 10,
            circuit_breaker_timeout: Duration::from_secs(60),
            max_retry_attempts: 5,
            retry_base_delay: Duration::from_millis(200),
            retry_max_delay: Duration::from_secs(30),
            enable_error_logging: true,
            max_error_history: 200,
        }
    }

    /// Create a configuration optimized for development and testing
    pub fn development() -> Self {
        Self {
            max_consecutive_errors: 3,
            circuit_breaker_timeout: Duration::from_secs(10),
            max_retry_attempts: 2,
            retry_base_delay: Duration::from_millis(50),
            retry_max_delay: Duration::from_secs(2),
            enable_error_logging: true,
            max_error_history: 50,
        }
    }

    /// Create a configuration with disabled error recovery (for testing)
    pub fn disabled() -> Self {
        Self {
            max_consecutive_errors: usize::MAX,
            circuit_breaker_timeout: Duration::from_secs(0),
            max_retry_attempts: 0,
            retry_base_delay: Duration::from_millis(0),
            retry_max_delay: Duration::from_millis(0),
            enable_error_logging: false,
            max_error_history: 0,
        }
    }
}

/// States of the circuit breaker
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitBreakerState {
    /// Circuit is closed, requests are allowed through
    Closed,
    /// Circuit is open, requests are rejected
    Open,
    /// Circuit is half-open, testing if service has recovered
    HalfOpen,
}

/// Information about an error occurrence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRecord {
    /// Timestamp when the error occurred
    pub timestamp: SystemTime,
    /// Error message
    pub error_message: String,
    /// Error code or category
    pub error_code: Option<String>,
    /// Context information (e.g., event type, operation)
    pub context: HashMap<String, String>,
    /// Whether this error is considered recoverable
    pub is_recoverable: bool,
    /// Retry attempt number (if applicable)
    pub retry_attempt: Option<usize>,
    /// Duration since last error (for rate tracking)
    pub time_since_last_error: Option<Duration>,
}

impl ErrorRecord {
    /// Create a new error record
    pub fn new(error_message: String, is_recoverable: bool) -> Self {
        Self {
            timestamp: SystemTime::now(),
            error_message,
            error_code: None,
            context: HashMap::new(),
            is_recoverable,
            retry_attempt: None,
            time_since_last_error: None,
        }
    }

    /// Set error code
    pub fn with_error_code(mut self, code: String) -> Self {
        self.error_code = Some(code);
        self
    }

    /// Add context information
    pub fn with_context(mut self, key: String, value: String) -> Self {
        self.context.insert(key, value);
        self
    }

    /// Set retry attempt number
    pub fn with_retry_attempt(mut self, attempt: usize) -> Self {
        self.retry_attempt = Some(attempt);
        self
    }
}

/// Error recovery and monitoring system for event listeners
pub struct ErrorRecoveryManager {
    config: ErrorRecoveryConfig,
    consecutive_errors: usize,
    circuit_state: CircuitBreakerState,
    circuit_opened_at: Option<Instant>,
    error_history: Vec<ErrorRecord>,
    last_error_time: Option<Instant>,
    total_errors: usize,
    total_recoveries: usize,
    error_rates: HashMap<String, f64>,
}

impl ErrorRecoveryManager {
    /// Create a new error recovery manager with default configuration
    pub fn new() -> Self {
        Self::with_config(ErrorRecoveryConfig::default())
    }

    /// Create a new error recovery manager with custom configuration
    pub fn with_config(config: ErrorRecoveryConfig) -> Self {
        Self {
            config,
            consecutive_errors: 0,
            circuit_state: CircuitBreakerState::Closed,
            circuit_opened_at: None,
            error_history: Vec::new(),
            last_error_time: None,
            total_errors: 0,
            total_recoveries: 0,
            error_rates: HashMap::new(),
        }
    }

    /// Check if operations should be allowed based on circuit breaker state
    pub fn is_operation_allowed(&mut self) -> bool {
        match self.circuit_state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                // Check if enough time has passed to try half-open
                if let Some(opened_at) = self.circuit_opened_at {
                    if opened_at.elapsed() >= self.config.circuit_breaker_timeout {
                        self.circuit_state = CircuitBreakerState::HalfOpen;
                        self.log("Circuit breaker transitioning to half-open state");
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitBreakerState::HalfOpen => true,
        }
    }

    /// Record a successful operation
    pub fn record_success(&mut self) {
        match self.circuit_state {
            CircuitBreakerState::HalfOpen => {
                // Success in half-open state, close the circuit
                self.circuit_state = CircuitBreakerState::Closed;
                self.consecutive_errors = 0;
                self.circuit_opened_at = None;
                self.total_recoveries += 1;
                self.log("Circuit breaker closed after successful operation");
            }
            CircuitBreakerState::Closed => {
                // Reset error count on success
                if self.consecutive_errors > 0 {
                    self.consecutive_errors = 0;
                    self.log("Error count reset after successful operation");
                }
            }
            CircuitBreakerState::Open => {
                // Should not happen if is_operation_allowed is used correctly
            }
        }
    }

    /// Record an error and update circuit breaker state
    pub fn record_error(&mut self, mut error_record: ErrorRecord) -> bool {
        let now = Instant::now();

        // Calculate time since last error
        if let Some(last_error) = self.last_error_time {
            error_record.time_since_last_error = Some(now.duration_since(last_error));
        }
        self.last_error_time = Some(now);

        // Update error statistics
        self.total_errors += 1;
        self.consecutive_errors += 1;

        // Add to error history (with size limit)
        if self.config.enable_error_logging {
            self.error_history.push(error_record.clone());
            if self.error_history.len() > self.config.max_error_history {
                self.error_history.remove(0);
            }
        }

        // Update error rates by type
        if let Some(error_code) = &error_record.error_code {
            let count = self.error_rates.entry(error_code.clone()).or_insert(0.0);
            *count += 1.0;
        }

        // Check if circuit breaker should open
        let should_open_circuit = self.consecutive_errors >= self.config.max_consecutive_errors
            && self.circuit_state != CircuitBreakerState::Open;

        if should_open_circuit {
            self.circuit_state = CircuitBreakerState::Open;
            self.circuit_opened_at = Some(now);
            self.log(&format!(
                "Circuit breaker opened after {} consecutive errors",
                self.consecutive_errors
            ));
        }

        // Log the error if enabled
        if self.config.enable_error_logging {
            self.log(&format!(
                "Error recorded: {} (recoverable: {}, consecutive: {})",
                error_record.error_message, error_record.is_recoverable, self.consecutive_errors
            ));
        }

        error_record.is_recoverable
    }

    /// Calculate retry delay using exponential backoff
    pub fn calculate_retry_delay(&self, attempt: usize) -> Duration {
        if attempt == 0 {
            return self.config.retry_base_delay;
        }

        let multiplier = 2_u64.pow(attempt as u32);
        let delay = self.config.retry_base_delay * multiplier as u32;

        if delay > self.config.retry_max_delay {
            self.config.retry_max_delay
        } else {
            delay
        }
    }

    /// Check if a retry should be attempted
    pub fn should_retry(&self, attempt: usize, is_recoverable: bool) -> bool {
        is_recoverable
            && attempt < self.config.max_retry_attempts
            && self.circuit_state != CircuitBreakerState::Open
    }

    /// Get error statistics
    pub fn get_error_stats(&self) -> ErrorStats {
        let error_rate = if self.total_errors > 0 && self.total_recoveries > 0 {
            self.total_errors as f64 / (self.total_errors + self.total_recoveries) as f64
        } else if self.total_errors > 0 {
            1.0
        } else {
            0.0
        };

        let recent_errors = self
            .error_history
            .iter()
            .filter(|e| {
                if let Ok(elapsed) = e.timestamp.elapsed() {
                    elapsed < Duration::from_secs(300) // Last 5 minutes
                } else {
                    false
                }
            })
            .count();

        ErrorStats {
            total_errors: self.total_errors,
            consecutive_errors: self.consecutive_errors,
            total_recoveries: self.total_recoveries,
            circuit_state: self.circuit_state.clone(),
            error_rate,
            recent_errors,
            errors_by_type: self.error_rates.clone(),
        }
    }

    /// Get recent error history
    pub fn get_recent_errors(&self, limit: Option<usize>) -> Vec<ErrorRecord> {
        let limit = limit.unwrap_or(10);
        let start_idx = if self.error_history.len() > limit {
            self.error_history.len() - limit
        } else {
            0
        };

        self.error_history[start_idx..].to_vec()
    }

    /// Clear error history (useful for testing)
    pub fn clear_error_history(&mut self) {
        self.error_history.clear();
        self.consecutive_errors = 0;
        self.circuit_state = CircuitBreakerState::Closed;
        self.circuit_opened_at = None;
        self.last_error_time = None;
        self.total_errors = 0;
        self.total_recoveries = 0;
        self.error_rates.clear();
    }

    /// Get the error recovery configuration
    pub fn get_config(&self) -> &ErrorRecoveryConfig {
        &self.config
    }

    /// Internal logging method
    fn log(&self, message: &str) {
        if self.config.enable_error_logging {
            let log_message = format!("[ErrorRecovery] {}", message);

            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(&log_message.into());

            #[cfg(not(target_arch = "wasm32"))]
            println!("{}", log_message);
        }
    }
}

impl Default for ErrorRecoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Error statistics for monitoring and reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorStats {
    /// Total number of errors encountered
    pub total_errors: usize,
    /// Current consecutive error count
    pub consecutive_errors: usize,
    /// Total number of successful recoveries
    pub total_recoveries: usize,
    /// Current circuit breaker state
    pub circuit_state: CircuitBreakerState,
    /// Overall error rate (0.0 to 1.0)
    pub error_rate: f64,
    /// Number of recent errors (last 5 minutes)
    pub recent_errors: usize,
    /// Error counts by type/code
    pub errors_by_type: HashMap<String, f64>,
}

/// Trait for operations that can be retried with error recovery
pub trait RetryableOperation<T, E> {
    /// Execute the operation with automatic retry and error recovery
    #[allow(async_fn_in_trait)]
    async fn execute_with_retry(
        &self,
        error_manager: &mut ErrorRecoveryManager,
        context: HashMap<String, String>,
    ) -> Result<T, E>;
}

/// Macro to help implement RetryableOperation for async functions
#[macro_export]
macro_rules! impl_retryable_operation {
    ($name:ident, $operation:expr, $error_mapper:expr) => {
        pub struct $name<F>(pub F);

        #[async_trait::async_trait]
        impl<F, T, E, Fut> RetryableOperation<T, E> for $name<F>
        where
            F: Fn() -> Fut + Send + Sync,
            Fut: std::future::Future<Output = Result<T, E>> + Send,
            T: Send,
            E: Send + std::fmt::Display,
        {
            async fn execute_with_retry(
                &self,
                error_manager: &mut ErrorRecoveryManager,
                context: HashMap<String, String>,
            ) -> Result<T, E> {
                let mut attempt = 0;

                loop {
                    if !error_manager.is_operation_allowed() {
                        let error_record = ErrorRecord::new(
                            "Operation blocked by circuit breaker".to_string(),
                            false,
                        )
                        .with_error_code("CIRCUIT_BREAKER_OPEN".to_string());

                        for (key, value) in &context {
                            error_record = error_record.with_context(key.clone(), value.clone());
                        }

                        error_manager.record_error(error_record);
                        return Err($error_mapper("Circuit breaker is open"));
                    }

                    match (self.0)().await {
                        Ok(result) => {
                            error_manager.record_success();
                            return Ok(result);
                        }
                        Err(e) => {
                            let error_message = e.to_string();
                            let is_recoverable = attempt < error_manager.config.max_retry_attempts;

                            let mut error_record =
                                ErrorRecord::new(error_message.clone(), is_recoverable)
                                    .with_retry_attempt(attempt);

                            for (key, value) in &context {
                                error_record =
                                    error_record.with_context(key.clone(), value.clone());
                            }

                            let should_retry = error_manager.record_error(error_record);

                            if !should_retry || !error_manager.should_retry(attempt, true) {
                                return Err(e);
                            }

                            let delay = error_manager.calculate_retry_delay(attempt);
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                        }
                    }
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_error_recovery_config_builder() {
        let config = ErrorRecoveryConfig::new()
            .with_max_consecutive_errors(10)
            .with_circuit_breaker_timeout(Duration::from_secs(60))
            .with_max_retry_attempts(5);

        assert_eq!(config.max_consecutive_errors, 10);
        assert_eq!(config.circuit_breaker_timeout, Duration::from_secs(60));
        assert_eq!(config.max_retry_attempts, 5);
    }

    #[test]
    fn test_error_recovery_config_presets() {
        let production = ErrorRecoveryConfig::production();
        assert_eq!(production.max_consecutive_errors, 10);
        assert_eq!(production.circuit_breaker_timeout, Duration::from_secs(60));

        let development = ErrorRecoveryConfig::development();
        assert_eq!(development.max_consecutive_errors, 3);
        assert_eq!(development.circuit_breaker_timeout, Duration::from_secs(10));

        let disabled = ErrorRecoveryConfig::disabled();
        assert_eq!(disabled.max_consecutive_errors, usize::MAX);
        assert_eq!(disabled.max_retry_attempts, 0);
    }

    #[test]
    fn test_error_recovery_manager_basic() {
        let mut manager = ErrorRecoveryManager::new();

        // Initially should allow operations
        assert!(manager.is_operation_allowed());

        // Record a success
        manager.record_success();
        let stats = manager.get_error_stats();
        assert_eq!(stats.total_errors, 0);
        assert_eq!(stats.consecutive_errors, 0);
        assert_eq!(stats.circuit_state, CircuitBreakerState::Closed);
    }

    #[test]
    fn test_circuit_breaker_behavior() {
        let config = ErrorRecoveryConfig::new().with_max_consecutive_errors(2);
        let mut manager = ErrorRecoveryManager::with_config(config);

        // Should start closed
        assert_eq!(manager.circuit_state, CircuitBreakerState::Closed);
        assert!(manager.is_operation_allowed());

        // Record first error
        let error1 = ErrorRecord::new("Test error 1".to_string(), true);
        manager.record_error(error1);
        assert_eq!(manager.circuit_state, CircuitBreakerState::Closed);
        assert!(manager.is_operation_allowed());

        // Record second error - should open circuit
        let error2 = ErrorRecord::new("Test error 2".to_string(), true);
        manager.record_error(error2);
        assert_eq!(manager.circuit_state, CircuitBreakerState::Open);
        assert!(!manager.is_operation_allowed());

        let stats = manager.get_error_stats();
        assert_eq!(stats.total_errors, 2);
        assert_eq!(stats.consecutive_errors, 2);
    }

    #[test]
    fn test_retry_delay_calculation() {
        let config = ErrorRecoveryConfig::new()
            .with_retry_delays(Duration::from_millis(100), Duration::from_secs(5));
        let manager = ErrorRecoveryManager::with_config(config);

        assert_eq!(manager.calculate_retry_delay(0), Duration::from_millis(100));
        assert_eq!(manager.calculate_retry_delay(1), Duration::from_millis(200));
        assert_eq!(manager.calculate_retry_delay(2), Duration::from_millis(400));
        assert_eq!(manager.calculate_retry_delay(3), Duration::from_millis(800));

        // Should cap at max delay
        assert_eq!(manager.calculate_retry_delay(10), Duration::from_secs(5));
    }

    #[test]
    fn test_should_retry_logic() {
        let config = ErrorRecoveryConfig::new().with_max_retry_attempts(3);
        let manager = ErrorRecoveryManager::with_config(config);

        // Should retry for recoverable errors within attempt limit
        assert!(manager.should_retry(0, true));
        assert!(manager.should_retry(2, true));
        assert!(!manager.should_retry(3, true));

        // Should not retry for non-recoverable errors
        assert!(!manager.should_retry(0, false));
        assert!(!manager.should_retry(1, false));
    }

    #[test]
    fn test_error_record_builder() {
        let error = ErrorRecord::new("Test error".to_string(), true)
            .with_error_code("TEST_ERROR".to_string())
            .with_context("operation".to_string(), "test_operation".to_string())
            .with_retry_attempt(1);

        assert_eq!(error.error_message, "Test error");
        assert!(error.is_recoverable);
        assert_eq!(error.error_code, Some("TEST_ERROR".to_string()));
        assert_eq!(
            error.context.get("operation"),
            Some(&"test_operation".to_string())
        );
        assert_eq!(error.retry_attempt, Some(1));
    }

    #[test]
    fn test_error_history_management() {
        let config = ErrorRecoveryConfig::new().with_max_error_history(2);
        let mut manager = ErrorRecoveryManager::with_config(config);

        // Add errors
        let error1 = ErrorRecord::new("Error 1".to_string(), true);
        let error2 = ErrorRecord::new("Error 2".to_string(), true);
        let error3 = ErrorRecord::new("Error 3".to_string(), true);

        manager.record_error(error1);
        manager.record_error(error2);
        assert_eq!(manager.error_history.len(), 2);

        // Adding third error should remove first
        manager.record_error(error3);
        assert_eq!(manager.error_history.len(), 2);
        assert_eq!(manager.error_history[0].error_message, "Error 2");
        assert_eq!(manager.error_history[1].error_message, "Error 3");
    }

    #[test]
    fn test_clear_error_history() {
        let mut manager = ErrorRecoveryManager::new();

        // Add some errors
        let error = ErrorRecord::new("Test error".to_string(), true);
        manager.record_error(error);

        assert_eq!(manager.total_errors, 1);
        assert_eq!(manager.consecutive_errors, 1);

        // Clear history
        manager.clear_error_history();

        assert_eq!(manager.total_errors, 0);
        assert_eq!(manager.consecutive_errors, 0);
        assert_eq!(manager.circuit_state, CircuitBreakerState::Closed);
        assert!(manager.error_history.is_empty());
    }
}
