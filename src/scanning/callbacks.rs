//! Callback traits for scanner progress and error handling
//!
//! This module provides trait-based abstractions for progress reporting and error
//! handling in the scanning process. This allows the core scanning logic to be
//! decoupled from specific UI implementations (console, web, GUI, etc.).

use std::time::{Duration, Instant};
use crate::data_structures::wallet_transaction::WalletState;

/// Progress information for scanning operations
#[derive(Debug, Clone)]
pub struct ScanProgress {
    /// Current block height being processed
    pub current_block: u64,
    /// Total number of blocks to process
    pub total_blocks: usize,
    /// Number of blocks processed so far
    pub blocks_processed: usize,
    /// Number of outputs found so far
    pub outputs_found: usize,
    /// Number of spent outputs detected so far
    pub inputs_found: usize,
    /// Time when scanning started
    pub start_time: Instant,
    /// Current wallet state
    pub wallet_state: Option<WalletState>,
    /// Current scanning phase
    pub phase: ScanPhase,
}

/// Scanning phases for progress reporting
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanPhase {
    /// Initializing scanner
    Initializing,
    /// Connecting to base node
    Connecting,
    /// Loading wallet information
    LoadingWallet,
    /// Scanning blocks for outputs
    ScanningBlocks,
    /// Processing found transactions
    ProcessingTransactions,
    /// Saving results to storage
    SavingResults,
    /// Scan completed successfully
    Completed,
    /// Scan was interrupted
    Interrupted,
    /// Scan failed with error
    Failed,
}

impl std::fmt::Display for ScanPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanPhase::Initializing => write!(f, "Initializing"),
            ScanPhase::Connecting => write!(f, "Connecting"),
            ScanPhase::LoadingWallet => write!(f, "Loading wallet"),
            ScanPhase::ScanningBlocks => write!(f, "Scanning blocks"),
            ScanPhase::ProcessingTransactions => write!(f, "Processing transactions"),
            ScanPhase::SavingResults => write!(f, "Saving results"),
            ScanPhase::Completed => write!(f, "Completed"),
            ScanPhase::Interrupted => write!(f, "Interrupted"),
            ScanPhase::Failed => write!(f, "Failed"),
        }
    }
}

impl ScanProgress {
    /// Create a new scan progress instance
    pub fn new(total_blocks: usize) -> Self {
        Self {
            current_block: 0,
            total_blocks,
            blocks_processed: 0,
            outputs_found: 0,
            inputs_found: 0,
            start_time: Instant::now(),
            wallet_state: None,
            phase: ScanPhase::Initializing,
        }
    }

    /// Update progress with new block information
    pub fn update_block_progress(
        &mut self, 
        block_height: u64, 
        found_outputs: usize, 
        spent_outputs: usize
    ) {
        self.current_block = block_height;
        self.blocks_processed += 1;
        self.outputs_found += found_outputs;
        self.inputs_found += spent_outputs;
    }

    /// Set the current scanning phase
    pub fn set_phase(&mut self, phase: ScanPhase) {
        self.phase = phase;
    }

    /// Update the wallet state
    pub fn update_wallet_state(&mut self, wallet_state: WalletState) {
        self.wallet_state = Some(wallet_state);
    }

    /// Get progress percentage (0.0 to 1.0)
    pub fn progress_percentage(&self) -> f64 {
        if self.total_blocks == 0 {
            return 1.0;
        }
        (self.blocks_processed as f64 / self.total_blocks as f64).min(1.0)
    }

    /// Get elapsed time since scan started
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Get estimated time remaining
    pub fn estimated_remaining(&self) -> Option<Duration> {
        if self.blocks_processed == 0 || self.blocks_processed >= self.total_blocks {
            return None;
        }
        
        let elapsed = self.elapsed();
        let blocks_per_second = self.blocks_processed as f64 / elapsed.as_secs_f64();
        let remaining_blocks = self.total_blocks - self.blocks_processed;
        let remaining_seconds = remaining_blocks as f64 / blocks_per_second;
        
        Some(Duration::from_secs_f64(remaining_seconds))
    }

    /// Get blocks per second processing rate
    pub fn blocks_per_second(&self) -> f64 {
        let elapsed = self.elapsed();
        if elapsed.as_secs_f64() == 0.0 {
            return 0.0;
        }
        self.blocks_processed as f64 / elapsed.as_secs_f64()
    }
}

/// Error handling information for scanning operations
#[derive(Debug, Clone)]
pub struct ScanError {
    /// The error that occurred
    pub error: String,
    /// Error details (if available)
    pub details: Option<String>,
    /// Block height where error occurred (if applicable)
    pub block_height: Option<u64>,
    /// Batch of blocks being processed when error occurred
    pub error_batch: Option<Vec<u64>>,
    /// Remaining blocks to be processed
    pub remaining_blocks: Vec<u64>,
    /// Whether this error is recoverable
    pub is_recoverable: bool,
    /// Suggested recovery actions
    pub recovery_suggestions: Vec<String>,
}

/// Error handling response from callback
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorResponse {
    /// Continue processing (skip the problematic block/batch)
    Continue,
    /// Retry the same operation
    Retry,
    /// Abort the entire scanning operation
    Abort,
}

/// Progress reporting callback trait
/// 
/// Implement this trait to receive progress updates during scanning operations.
/// This allows for different UI implementations (console, web, GUI) without
/// coupling the core scanning logic to specific output methods.
pub trait ProgressCallback: Send + Sync {
    /// Called when progress is updated
    fn on_progress(&self, progress: &ScanProgress);
    
    /// Called when scanning phase changes
    fn on_phase_change(&self, old_phase: ScanPhase, new_phase: ScanPhase);
    
    /// Called when scanning starts
    fn on_scan_start(&self, total_blocks: usize);
    
    /// Called when scanning completes successfully
    fn on_scan_complete(&self, final_state: &WalletState, stats: &ScanProgress);
    
    /// Called when scanning is interrupted
    fn on_scan_interrupted(&self, partial_state: &WalletState, stats: &ScanProgress);
}

/// Error handling callback trait
/// 
/// Implement this trait to handle errors during scanning operations.
/// This allows for different error handling strategies (interactive, automatic retry,
/// fail-fast) without coupling the core scanning logic to specific UI patterns.
pub trait ErrorCallback: Send + Sync {
    /// Called when an error occurs during scanning
    /// 
    /// The implementation should return an ErrorResponse indicating how to proceed.
    fn on_error(&self, error: &ScanError) -> ErrorResponse;
    
    /// Called when a recoverable error occurs with automatic retry
    fn on_retry(&self, error: &ScanError, attempt: usize, max_attempts: usize);
    
    /// Called when maximum retry attempts are exceeded
    fn on_max_retries_exceeded(&self, error: &ScanError) -> ErrorResponse;
}

/// Combined progress and error callback trait
/// 
/// Convenience trait that combines progress and error handling for simpler
/// implementations that need both capabilities.
pub trait ScanCallback: ProgressCallback + ErrorCallback {
    /// Called when the scanner needs to check if operation should be cancelled
    /// 
    /// Return true to cancel the scanning operation gracefully.
    fn should_cancel(&self) -> bool {
        false
    }
}

// Re-export CancellationToken from the cancellation module
pub use super::cancellation::CancellationToken;

/// Console-based progress callback implementation
/// 
/// Provides a simple console output implementation for progress reporting.
/// This is useful for CLI applications and can serve as an example for
/// implementing custom progress callbacks.
pub struct ConsoleProgressCallback {
    quiet: bool,
    frequency: usize,
    last_update: std::sync::Mutex<usize>,
}

impl ConsoleProgressCallback {
    /// Create a new console progress callback
    pub fn new(quiet: bool, frequency: usize) -> Self {
        Self {
            quiet,
            frequency,
            last_update: std::sync::Mutex::new(0),
        }
    }
}

impl ProgressCallback for ConsoleProgressCallback {
    fn on_progress(&self, progress: &ScanProgress) {
        if self.quiet {
            return;
        }
        
        // Only update every N blocks
        {
            let mut last = self.last_update.lock().unwrap();
            if progress.blocks_processed - *last < self.frequency {
                return;
            }
            *last = progress.blocks_processed;
        }
        
        // Use the animated progress bar if we have wallet state, otherwise fall back to simple display
        let progress_display = if let Some(wallet_state) = &progress.wallet_state {
            // Use the beautiful animated progress bar with balance information
            wallet_state.format_progress_bar(
                progress.blocks_processed as u64,
                progress.total_blocks as u64,
                progress.current_block,
                &format!("{:?}", progress.phase).replace("Blocks", "")
            )
        } else {
            // Fallback to simpler progress display
            let progress_percent = progress.progress_percentage() * 100.0;
            let blocks_per_sec = progress.blocks_per_second();
            let bar_width = 40;
            let filled_width = ((progress_percent / 100.0) * bar_width as f64) as usize;
            let bar = format!("{}{}",
                "█".repeat(filled_width),
                "░".repeat(bar_width - filled_width)
            );
            
            format!(
                "[{}] {:.1}% Block {} | {:.1} blocks/s | Found: {} outputs, {} spent",
                bar,
                progress_percent,
                crate::utils::number::format_number(progress.current_block),
                blocks_per_sec,
                crate::utils::number::format_number(progress.outputs_found),
                crate::utils::number::format_number(progress.inputs_found)
            )
        };
        
        print!("\r{}", progress_display);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
    }
    
    fn on_phase_change(&self, _old_phase: ScanPhase, new_phase: ScanPhase) {
        if !self.quiet {
            println!("\n📋 {}", new_phase);
        }
    }
    
    fn on_scan_start(&self, total_blocks: usize) {
        if !self.quiet {
            println!("🚀 Starting scan of {} blocks", total_blocks);
        }
    }
    
    fn on_scan_complete(&self, final_state: &WalletState, _stats: &ScanProgress) {
        if !self.quiet {
            println!("\n✅ Scan completed successfully!");
            let (inbound_count, outbound_count, _) = final_state.get_direction_counts();
            println!(
                "📊 Total: {} outputs found, {} outputs spent",
                inbound_count, outbound_count
            );
        }
    }
    
    fn on_scan_interrupted(&self, _partial_state: &WalletState, _stats: &ScanProgress) {
        if !self.quiet {
            println!("\n⚠️ Scan was interrupted");
        }
    }
}

/// Interactive console error callback implementation
/// 
/// Provides interactive error handling for CLI applications where users
/// can choose how to respond to errors.
pub struct InteractiveErrorCallback {
    quiet: bool,
}

impl InteractiveErrorCallback {
    /// Create a new interactive error callback
    pub fn new(quiet: bool) -> Self {
        Self { quiet }
    }
}

impl ErrorCallback for InteractiveErrorCallback {
    fn on_error(&self, error: &ScanError) -> ErrorResponse {
        if self.quiet || !error.is_recoverable {
            return ErrorResponse::Abort;
        }
        
        println!("\n❌ Error occurred during scanning:");
        println!("   Error: {}", error.error);
        if let Some(details) = &error.details {
            println!("   Details: {}", details);
        }
        if let Some(block_height) = error.block_height {
            println!("   Block height: {}", block_height);
        }
        
        println!("   How would you like to proceed?");
        print!("   Continue (y), Retry (r), or Abort (n): ");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            return ErrorResponse::Abort;
        }
        
        match input.trim().to_lowercase().as_str() {
            "y" | "yes" | "c" | "continue" => {
                println!("   ✅ Continuing scan...");
                ErrorResponse::Continue
            },
            "r" | "retry" => {
                println!("   🔄 Retrying...");
                ErrorResponse::Retry
            },
            _ => {
                println!("   🛑 Aborting scan");
                ErrorResponse::Abort
            }
        }
    }
    
    fn on_retry(&self, error: &ScanError, attempt: usize, max_attempts: usize) {
        if !self.quiet {
            println!("   🔄 Retrying operation (attempt {} of {})", attempt, max_attempts);
            if let Some(details) = &error.details {
                println!("   Previous error: {}", details);
            }
        }
    }
    
    fn on_max_retries_exceeded(&self, error: &ScanError) -> ErrorResponse {
        if !self.quiet {
            println!("   ⚠️ Maximum retry attempts exceeded");
            println!("   Final error: {}", error.error);
            print!("   Continue with next batch (y) or Abort (n): ");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            
            let mut input = String::new();
            if std::io::stdin().read_line(&mut input).is_ok() {
                match input.trim().to_lowercase().as_str() {
                    "y" | "yes" | "c" | "continue" => return ErrorResponse::Continue,
                    _ => {}
                }
            }
        }
        ErrorResponse::Abort
    }
}

/// Silent error callback that automatically chooses sensible defaults
/// 
/// Useful for non-interactive environments where errors should be handled
/// automatically without user intervention.
pub struct SilentErrorCallback {
    auto_retry: bool,
    max_retries: usize,
}

impl SilentErrorCallback {
    /// Create a new silent error callback
    pub fn new(auto_retry: bool, max_retries: usize) -> Self {
        Self { auto_retry, max_retries }
    }
}

impl ErrorCallback for SilentErrorCallback {
    fn on_error(&self, error: &ScanError) -> ErrorResponse {
        if error.is_recoverable && self.auto_retry {
            ErrorResponse::Retry
        } else if error.is_recoverable {
            ErrorResponse::Continue
        } else {
            ErrorResponse::Abort
        }
    }
    
    fn on_retry(&self, _error: &ScanError, _attempt: usize, _max_attempts: usize) {
        // Silent - no output
    }
    
    fn on_max_retries_exceeded(&self, error: &ScanError) -> ErrorResponse {
        if error.is_recoverable {
            ErrorResponse::Continue
        } else {
            ErrorResponse::Abort
        }
    }
}

/// No-op implementations for when callbacks are not needed
pub struct NoOpProgressCallback;
pub struct NoOpErrorCallback;

impl ProgressCallback for NoOpProgressCallback {
    fn on_progress(&self, _progress: &ScanProgress) {}
    fn on_phase_change(&self, _old_phase: ScanPhase, _new_phase: ScanPhase) {}
    fn on_scan_start(&self, _total_blocks: usize) {}
    fn on_scan_complete(&self, _final_state: &WalletState, _stats: &ScanProgress) {}
    fn on_scan_interrupted(&self, _partial_state: &WalletState, _stats: &ScanProgress) {}
}

impl ErrorCallback for NoOpErrorCallback {
    fn on_error(&self, _error: &ScanError) -> ErrorResponse {
        ErrorResponse::Abort
    }
    
    fn on_retry(&self, _error: &ScanError, _attempt: usize, _max_attempts: usize) {}
    fn on_max_retries_exceeded(&self, _error: &ScanError) -> ErrorResponse {
        ErrorResponse::Abort
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_progress() {
        let mut progress = ScanProgress::new(100);
        assert_eq!(progress.total_blocks, 100);
        assert_eq!(progress.progress_percentage(), 0.0);
        
        progress.update_block_progress(50, 5, 2);
        assert_eq!(progress.current_block, 50);
        assert_eq!(progress.blocks_processed, 1);
        assert_eq!(progress.outputs_found, 5);
        assert_eq!(progress.inputs_found, 2);
        
        progress.blocks_processed = 50;
        assert_eq!(progress.progress_percentage(), 0.5);
    }

    #[test]
    fn test_scan_phases() {
        let phase = ScanPhase::ScanningBlocks;
        assert_eq!(phase.to_string(), "Scanning blocks");
        
        assert_eq!(ScanPhase::Completed.to_string(), "Completed");
        assert_eq!(ScanPhase::Failed.to_string(), "Failed");
    }

    #[test]
    fn test_error_response() {
        assert_eq!(ErrorResponse::Continue, ErrorResponse::Continue);
        assert_ne!(ErrorResponse::Continue, ErrorResponse::Abort);
    }

    #[test]
    fn test_silent_error_callback() {
        let callback = SilentErrorCallback::new(true, 3);
        
        let recoverable_error = ScanError {
            error: "Test error".to_string(),
            details: None,
            block_height: Some(100),
            error_batch: None,
            remaining_blocks: vec![],
            is_recoverable: true,
            recovery_suggestions: vec![],
        };
        
        assert_eq!(callback.on_error(&recoverable_error), ErrorResponse::Retry);
        
        let non_recoverable_error = ScanError {
            error: "Fatal error".to_string(),
            details: None,
            block_height: None,
            error_batch: None,
            remaining_blocks: vec![],
            is_recoverable: false,
            recovery_suggestions: vec![],
        };
        
        assert_eq!(callback.on_error(&non_recoverable_error), ErrorResponse::Abort);
    }
} 