//! Cancellation token abstractions for scanning operations
//!
//! This module provides cancellation token implementations that work across
//! different environments (async runtimes, WASM, synchronous code) without
//! being tightly coupled to specific implementations like tokio.

use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

/// Generic cancellation token trait
/// 
/// Provides a common interface for cancellation that can be implemented
/// for different environments and use cases.
pub trait CancellationToken: Send + Sync + std::fmt::Debug {
    /// Check if cancellation has been requested
    fn is_cancelled(&self) -> bool;
    
    /// Request cancellation of the operation
    fn cancel(&self);
    
    /// Reset the cancellation state (useful for reusing tokens)
    fn reset(&self) {
        // Default implementation does nothing - not all tokens support reset
    }
}

/// Simple atomic boolean-based cancellation token
/// 
/// This is a basic implementation using `AtomicBool` that works in any
/// environment without dependencies on specific async runtimes.
#[derive(Debug, Clone)]
pub struct AtomicCancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl AtomicCancellationToken {
    /// Create a new atomic cancellation token
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a new pre-cancelled token
    pub fn cancelled() -> Self {
        let token = Self::new();
        token.cancel();
        token
    }

    /// Create a pair of (token, handle) where the handle can be used to cancel
    pub fn create_pair() -> (Self, CancellationHandle) {
        let token = Self::new();
        let handle = CancellationHandle {
            cancelled: token.cancelled.clone(),
        };
        (token, handle)
    }
}

impl Default for AtomicCancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationToken for AtomicCancellationToken {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.cancelled.store(false, Ordering::Relaxed);
    }
}

/// Handle for cancelling an operation
/// 
/// This provides a way to cancel operations from a different context
/// while maintaining separation between the token and cancellation trigger.
#[derive(Debug, Clone)]
pub struct CancellationHandle {
    cancelled: Arc<AtomicBool>,
}

impl CancellationHandle {
    /// Cancel the associated token
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Check if the token is cancelled
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Reset the cancellation state
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::Relaxed);
    }
}

/// Tokio-specific cancellation token wrapper
/// 
/// This wraps tokio's cancellation functionality while implementing
/// our generic trait, allowing seamless integration in tokio environments.
#[cfg(feature = "tokio")]
#[derive(Debug)]
pub struct TokioCancellationToken {
    receiver: tokio::sync::watch::Receiver<bool>,
    sender: Option<tokio::sync::watch::Sender<bool>>,
}

#[cfg(feature = "tokio")]
impl TokioCancellationToken {
    /// Create a new tokio cancellation token
    pub fn new() -> Self {
        let (sender, receiver) = tokio::sync::watch::channel(false);
        Self {
            receiver,
            sender: Some(sender),
        }
    }

    /// Create from existing tokio watch receiver
    pub fn from_receiver(receiver: tokio::sync::watch::Receiver<bool>) -> Self {
        Self {
            receiver,
            sender: None,
        }
    }

    /// Create a pair of (token, handle) for tokio environments
    pub fn create_pair() -> (Self, TokioCancellationHandle) {
        let (sender, receiver) = tokio::sync::watch::channel(false);
        let token = Self {
            receiver: receiver.clone(),
            sender: None,
        };
        let handle = TokioCancellationHandle { sender };
        (token, handle)
    }
}

#[cfg(feature = "tokio")]
impl Default for TokioCancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "tokio")]
impl CancellationToken for TokioCancellationToken {
    fn is_cancelled(&self) -> bool {
        *self.receiver.borrow()
    }

    fn cancel(&self) {
        if let Some(sender) = &self.sender {
            let _ = sender.send(true);
        }
    }

    fn reset(&self) {
        if let Some(sender) = &self.sender {
            let _ = sender.send(false);
        }
    }
}

/// Handle for cancelling tokio operations
#[cfg(feature = "tokio")]
#[derive(Debug)]
pub struct TokioCancellationHandle {
    sender: tokio::sync::watch::Sender<bool>,
}

#[cfg(feature = "tokio")]
impl TokioCancellationHandle {
    /// Cancel the associated token
    pub fn cancel(&self) -> Result<(), tokio::sync::watch::error::SendError<bool>> {
        self.sender.send(true)
    }

    /// Reset the cancellation state
    pub fn reset(&self) -> Result<(), tokio::sync::watch::error::SendError<bool>> {
        self.sender.send(false)
    }

    /// Check if any receivers are still listening
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
}

/// WASM-compatible cancellation token
/// 
/// This implementation works in WASM environments where threading
/// primitives may be limited.
#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
pub struct WasmCancellationToken {
    cancelled: std::rc::Rc<std::cell::Cell<bool>>,
}

#[cfg(target_arch = "wasm32")]
impl WasmCancellationToken {
    /// Create a new WASM cancellation token
    pub fn new() -> Self {
        Self {
            cancelled: std::rc::Rc::new(std::cell::Cell::new(false)),
        }
    }

    /// Create a pair of (token, handle) for WASM environments
    pub fn create_pair() -> (Self, WasmCancellationHandle) {
        let cancelled = std::rc::Rc::new(std::cell::Cell::new(false));
        let token = Self {
            cancelled: cancelled.clone(),
        };
        let handle = WasmCancellationHandle { cancelled };
        (token, handle)
    }
}

#[cfg(target_arch = "wasm32")]
impl Default for WasmCancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_arch = "wasm32")]
impl CancellationToken for WasmCancellationToken {
    fn is_cancelled(&self) -> bool {
        self.cancelled.get()
    }

    fn cancel(&self) {
        self.cancelled.set(true);
    }

    fn reset(&self) {
        self.cancelled.set(false);
    }
}

/// Handle for cancelling WASM operations
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
pub struct WasmCancellationHandle {
    cancelled: std::rc::Rc<std::cell::Cell<bool>>,
}

#[cfg(target_arch = "wasm32")]
impl WasmCancellationHandle {
    /// Cancel the associated token
    pub fn cancel(&self) {
        self.cancelled.set(true);
    }

    /// Check if the token is cancelled
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.get()
    }

    /// Reset the cancellation state
    pub fn reset(&self) {
        self.cancelled.set(false);
    }
}

/// A cancellation token that never cancels
/// 
/// Useful as a default implementation when cancellation is not needed
/// or supported in a particular context.
#[derive(Debug, Clone, Copy)]
pub struct NeverCancelToken;

impl CancellationToken for NeverCancelToken {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn cancel(&self) {
        // Does nothing - this token never cancels
    }
}

impl Default for NeverCancelToken {
    fn default() -> Self {
        NeverCancelToken
    }
}

/// A cancellation token that's always cancelled
/// 
/// Useful for testing or when you want to immediately abort operations.
#[derive(Debug, Clone, Copy)]
pub struct AlwaysCancelToken;

impl CancellationToken for AlwaysCancelToken {
    fn is_cancelled(&self) -> bool {
        true
    }

    fn cancel(&self) {
        // Already cancelled
    }
}

impl Default for AlwaysCancelToken {
    fn default() -> Self {
        AlwaysCancelToken
    }
}

/// Composite cancellation token that cancels when any of its children cancel
/// 
/// This allows combining multiple cancellation sources (e.g., user request,
/// timeout, system shutdown) into a single token.
#[derive(Debug)]
pub struct CompositeCancellationToken {
    tokens: Vec<Box<dyn CancellationToken>>,
}

impl CompositeCancellationToken {
    /// Create a new composite cancellation token
    pub fn new() -> Self {
        Self {
            tokens: Vec::new(),
        }
    }

    /// Add a child token to the composite
    pub fn add_token(&mut self, token: Box<dyn CancellationToken>) {
        self.tokens.push(token);
    }

    /// Add multiple tokens at once
    pub fn add_tokens(&mut self, tokens: Vec<Box<dyn CancellationToken>>) {
        self.tokens.extend(tokens);
    }

    /// Create from a vector of tokens
    pub fn from_tokens(tokens: Vec<Box<dyn CancellationToken>>) -> Self {
        Self { tokens }
    }
}

impl Default for CompositeCancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationToken for CompositeCancellationToken {
    fn is_cancelled(&self) -> bool {
        self.tokens.iter().any(|token| token.is_cancelled())
    }

    fn cancel(&self) {
        // Cancel all child tokens
        for token in &self.tokens {
            token.cancel();
        }
    }

    fn reset(&self) {
        // Reset all child tokens
        for token in &self.tokens {
            token.reset();
        }
    }
}

/// Timeout-based cancellation token
/// 
/// This token automatically cancels after a specified duration.
/// Note: This requires a background mechanism to track time.
#[derive(Debug)]
pub struct TimeoutCancellationToken {
    start_time: std::time::Instant,
    timeout: std::time::Duration,
    manual_cancel: Arc<AtomicBool>,
}

impl TimeoutCancellationToken {
    /// Create a new timeout cancellation token
    pub fn new(timeout: std::time::Duration) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            timeout,
            manual_cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Check if the timeout has elapsed
    pub fn is_timed_out(&self) -> bool {
        self.start_time.elapsed() >= self.timeout
    }

    /// Get remaining time before timeout
    pub fn remaining_time(&self) -> Option<std::time::Duration> {
        let elapsed = self.start_time.elapsed();
        if elapsed >= self.timeout {
            None
        } else {
            Some(self.timeout - elapsed)
        }
    }

    /// Reset the timeout (restart the timer)
    pub fn restart(&mut self) {
        self.start_time = std::time::Instant::now();
        self.manual_cancel.store(false, Ordering::Relaxed);
    }
}

impl CancellationToken for TimeoutCancellationToken {
    fn is_cancelled(&self) -> bool {
        self.manual_cancel.load(Ordering::Relaxed) || self.is_timed_out()
    }

    fn cancel(&self) {
        self.manual_cancel.store(true, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.manual_cancel.store(false, Ordering::Relaxed);
        // Note: Cannot reset start_time without &mut self
    }
}

/// Utility functions for working with cancellation tokens
pub mod utils {
    use super::*;

    /// Create a cancellation token appropriate for the current environment
    pub fn create_default_token() -> impl CancellationToken {
        #[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
        {
            TokioCancellationToken::new()
        }
        
        #[cfg(target_arch = "wasm32")]
        {
            WasmCancellationToken::new()
        }
        
        #[cfg(not(any(feature = "tokio", target_arch = "wasm32")))]
        {
            AtomicCancellationToken::new()
        }
    }

    /// Create a cancellation token with timeout
    pub fn create_timeout_token(timeout: std::time::Duration) -> TimeoutCancellationToken {
        TimeoutCancellationToken::new(timeout)
    }

    /// Create a composite token from multiple sources
    pub fn create_composite_token(
        tokens: Vec<Box<dyn CancellationToken>>
    ) -> CompositeCancellationToken {
        CompositeCancellationToken::from_tokens(tokens)
    }

    /// Check if cancellation is supported in the current environment
    pub fn is_cancellation_supported() -> bool {
        // Cancellation is always supported via atomic operations
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_atomic_cancellation_token() {
        let token = AtomicCancellationToken::new();
        assert!(!token.is_cancelled());
        
        token.cancel();
        assert!(token.is_cancelled());
        
        token.reset();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn test_cancellation_handle() {
        let (token, handle) = AtomicCancellationToken::create_pair();
        assert!(!token.is_cancelled());
        assert!(!handle.is_cancelled());
        
        handle.cancel();
        assert!(token.is_cancelled());
        assert!(handle.is_cancelled());
        
        handle.reset();
        assert!(!token.is_cancelled());
        assert!(!handle.is_cancelled());
    }

    #[test]
    fn test_never_cancel_token() {
        let token = NeverCancelToken;
        assert!(!token.is_cancelled());
        
        token.cancel();
        assert!(!token.is_cancelled()); // Still not cancelled
    }

    #[test]
    fn test_always_cancel_token() {
        let token = AlwaysCancelToken;
        assert!(token.is_cancelled());
        
        token.cancel();
        assert!(token.is_cancelled()); // Still cancelled
    }

    #[test]
    fn test_composite_cancellation_token() {
        let mut composite = CompositeCancellationToken::new();
        let token1 = AtomicCancellationToken::new();
        let token2 = AtomicCancellationToken::new();
        
        composite.add_token(Box::new(token1.clone()));
        composite.add_token(Box::new(token2.clone()));
        
        assert!(!composite.is_cancelled());
        
        token1.cancel();
        assert!(composite.is_cancelled());
    }

    #[test]
    fn test_timeout_cancellation_token() {
        let token = TimeoutCancellationToken::new(Duration::from_millis(1));
        assert!(!token.is_cancelled());
        
        // Wait for timeout
        std::thread::sleep(Duration::from_millis(2));
        assert!(token.is_cancelled());
        assert!(token.is_timed_out());
    }

    #[test]
    fn test_timeout_manual_cancel() {
        let token = TimeoutCancellationToken::new(Duration::from_secs(10));
        assert!(!token.is_cancelled());
        
        token.cancel();
        assert!(token.is_cancelled());
        assert!(!token.is_timed_out()); // Not timed out, manually cancelled
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn test_tokio_cancellation_token() {
        let (token, handle) = TokioCancellationToken::create_pair();
        assert!(!token.is_cancelled());
        
        handle.cancel().unwrap();
        assert!(token.is_cancelled());
    }
} 