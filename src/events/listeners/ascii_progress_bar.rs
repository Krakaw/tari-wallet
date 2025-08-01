//! ASCII Progress Bar Listener for real-time scanning progress
//!
//! This listener provides a real-time ASCII progress bar display that matches
//! the original scanner progress bar functionality. It uses carriage return (`\r`)
//! to update the same line continuously, providing smooth progress feedback.

use async_trait::async_trait;
use std::error::Error;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::common::format_number;
use crate::events::{EventListener, SharedEvent, WalletScanEvent};

/// Configuration for ASCII progress bar display
#[derive(Debug, Clone)]
pub struct AsciiProgressBarConfig {
    /// Width of the progress bar in characters
    pub bar_width: usize,
    /// Minimum time between progress updates in milliseconds
    pub update_interval_ms: u64,
    /// Whether to show block per second calculation
    pub show_speed: bool,
    /// Whether to show ETA calculation
    pub show_eta: bool,
    /// Whether to show outputs found count
    pub show_outputs: bool,
    /// Whether to show spent outputs count
    pub show_spent: bool,
    /// Whether to use colored output
    pub use_colors: bool,
}

impl Default for AsciiProgressBarConfig {
    fn default() -> Self {
        Self {
            bar_width: 40,
            update_interval_ms: 100, // Update every 100ms max
            show_speed: true,
            show_eta: true,
            show_outputs: true,
            show_spent: true,
            use_colors: true,
        }
    }
}

impl AsciiProgressBarConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the progress bar width
    pub fn with_bar_width(mut self, width: usize) -> Self {
        self.bar_width = width.clamp(10, 100); // Reasonable limits
        self
    }

    /// Set the minimum update interval
    pub fn with_update_interval_ms(mut self, interval_ms: u64) -> Self {
        self.update_interval_ms = interval_ms.clamp(50, 5000); // 50ms to 5s
        self
    }

    /// Enable or disable speed display
    pub fn with_speed_display(mut self, enabled: bool) -> Self {
        self.show_speed = enabled;
        self
    }

    /// Enable or disable ETA display
    pub fn with_eta_display(mut self, enabled: bool) -> Self {
        self.show_eta = enabled;
        self
    }

    /// Enable or disable outputs count display
    pub fn with_outputs_display(mut self, enabled: bool) -> Self {
        self.show_outputs = enabled;
        self
    }

    /// Enable or disable spent outputs count display
    pub fn with_spent_display(mut self, enabled: bool) -> Self {
        self.show_spent = enabled;
        self
    }

    /// Enable or disable colored output
    pub fn with_colors(mut self, enabled: bool) -> Self {
        self.use_colors = enabled;
        self
    }

    /// Create a minimal configuration (smaller bar, less frequent updates)
    pub fn minimal() -> Self {
        Self {
            bar_width: 20,
            update_interval_ms: 500,
            show_speed: false,
            show_eta: false,
            show_outputs: false,
            show_spent: false,
            use_colors: false,
        }
    }

    /// Create a detailed configuration (larger bar, frequent updates, all info)
    pub fn detailed() -> Self {
        Self {
            bar_width: 50,
            update_interval_ms: 50,
            show_speed: true,
            show_eta: true,
            show_outputs: true,
            show_spent: true,
            use_colors: true,
        }
    }
}

/// Internal state for tracking progress statistics
#[derive(Debug, Clone)]
struct ProgressState {
    /// Number of blocks processed so far (stored in current_block from event)
    blocks_processed: u64,
    /// Total blocks to process
    total_blocks: u64,
    /// Current block height being processed
    current_block_height: u64,
    /// Current progress percentage
    progress_percent: f64,
    /// Processing speed in blocks per second
    blocks_per_sec: f64,
    /// Estimated time remaining
    eta: Option<Duration>,
    /// Number of outputs found
    outputs_found: usize,
    /// Number of spent outputs found
    spent_found: usize,
    /// Last update timestamp
    last_update: Instant,
    /// Whether scan is active
    scan_active: bool,
}

impl Default for ProgressState {
    fn default() -> Self {
        Self {
            blocks_processed: 0,
            total_blocks: 0,
            current_block_height: 0,
            progress_percent: 0.0,
            blocks_per_sec: 0.0,
            eta: None,
            outputs_found: 0,
            spent_found: 0,
            last_update: Instant::now(),
            scan_active: false,
        }
    }
}

/// ASCII Progress Bar Listener
///
/// Provides real-time progress bar display using carriage return to update
/// the same line continuously. This recreates the original scanner progress
/// bar experience within the event system architecture.
///
/// # Examples
///
/// ## Basic Usage
/// ```rust,ignore
/// use lightweight_wallet_libs::events::listeners::AsciiProgressBarListener;
///
/// let listener = AsciiProgressBarListener::new();
/// // Uses default 40-character bar with all features enabled
/// ```
///
/// ## Custom Configuration
/// ```rust,ignore
/// use lightweight_wallet_libs::events::listeners::{
///     AsciiProgressBarListener, AsciiProgressBarConfig
/// };
///
/// let config = AsciiProgressBarConfig::new()
///     .with_bar_width(50)
///     .with_update_interval_ms(50)
///     .with_colors(true);
///     
/// let listener = AsciiProgressBarListener::with_config(config);
/// ```
///
/// ## Minimal Configuration
/// ```rust,ignore
/// let listener = AsciiProgressBarListener::minimal();
/// // Small bar, less frequent updates, essential info only
/// ```
pub struct AsciiProgressBarListener {
    config: AsciiProgressBarConfig,
    state: Arc<Mutex<ProgressState>>,
}

impl AsciiProgressBarListener {
    /// Create a new ASCII progress bar listener with default configuration
    pub fn new() -> Self {
        Self {
            config: AsciiProgressBarConfig::default(),
            state: Arc::new(Mutex::new(ProgressState::default())),
        }
    }

    /// Create an ASCII progress bar listener with custom configuration
    pub fn with_config(config: AsciiProgressBarConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(ProgressState::default())),
        }
    }

    /// Create a minimal ASCII progress bar listener
    pub fn minimal() -> Self {
        Self::with_config(AsciiProgressBarConfig::minimal())
    }

    /// Create a detailed ASCII progress bar listener
    pub fn detailed() -> Self {
        Self::with_config(AsciiProgressBarConfig::detailed())
    }

    /// Display the progress bar with current state
    fn display_progress(&self, state: &ProgressState) {
        if !state.scan_active {
            return;
        }

        // Create ASCII progress bar
        let progress_fraction = state.progress_percent / 100.0;
        let filled_width = (progress_fraction * self.config.bar_width as f64) as usize;
        let filled_width = filled_width.min(self.config.bar_width);

        let progress_bar = format!(
            "{filled}{empty}",
            filled = "█".repeat(filled_width),
            empty = "░".repeat(self.config.bar_width - filled_width)
        );

        // Format ETA display
        let eta_display = if self.config.show_eta {
            if let Some(eta) = state.eta {
                let eta_secs = eta.as_secs();
                if eta_secs < 60 {
                    format!(" ETA: {eta_secs}s")
                } else if eta_secs < 3600 {
                    let minutes = eta_secs / 60;
                    let seconds = eta_secs % 60;
                    format!(" ETA: {minutes}m{seconds}s")
                } else {
                    let hours = eta_secs / 3600;
                    let minutes = (eta_secs % 3600) / 60;
                    format!(" ETA: {hours}h{minutes}m")
                }
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // Format speed display
        let speed_display = if self.config.show_speed {
            format!(" | {:.1} blocks/s", state.blocks_per_sec)
        } else {
            String::new()
        };

        // Format outputs display
        let outputs_display = if self.config.show_outputs || self.config.show_spent {
            let mut parts = Vec::new();
            if self.config.show_outputs {
                parts.push(format!("{} outputs", format_number(state.outputs_found)));
            }
            if self.config.show_spent {
                parts.push(format!("{} spent", format_number(state.spent_found)));
            }
            if !parts.is_empty() {
                format!(" | Found: {}", parts.join(", "))
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // Print the progress line using carriage return for real-time updates
        print!(
            "\r🔍 [{}] {:.1}% ({}/{}) | Block {}{}{}{}   ",
            progress_bar,
            state.progress_percent,
            format_number(state.blocks_processed), // Show blocks processed
            format_number(state.total_blocks),
            format_number(state.current_block_height),
            speed_display,
            outputs_display,
            eta_display
        );
        let _ = io::stdout().flush();
    }

    /// Clear the progress line (for when scan completes or is interrupted)
    fn clear_progress_line(&self) {
        // Clear the current line and move cursor to beginning
        print!("\r{}\r", " ".repeat(120)); // Clear with spaces
        let _ = io::stdout().flush();
    }

    /// Update progress state and display if enough time has passed
    fn update_progress(
        &self,
        blocks_processed: u64,
        total_blocks: u64,
        current_block_height: u64,
        percentage: f64,
        speed_blocks_per_second: f64,
        estimated_time_remaining: Option<Duration>,
    ) {
        if let Ok(mut state) = self.state.lock() {
            let now = Instant::now();
            let time_since_update = now.duration_since(state.last_update);

            // Only update if enough time has passed (rate limiting)
            if time_since_update.as_millis() < self.config.update_interval_ms as u128 {
                return;
            }

            // Update state
            state.blocks_processed = blocks_processed;
            state.current_block_height = current_block_height;
            state.total_blocks = total_blocks;
            state.progress_percent = percentage;
            state.blocks_per_sec = speed_blocks_per_second;
            state.eta = estimated_time_remaining;
            state.last_update = now;

            // Display the updated progress
            self.display_progress(&state);
        }
    }

    /// Mark scan as started
    fn start_scan(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.scan_active = true;
            state.last_update = Instant::now();
        }
    }

    /// Mark scan as finished and clear the progress line
    fn finish_scan(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.scan_active = false;
        }
        self.clear_progress_line();
    }
}

impl Default for AsciiProgressBarListener {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventListener for AsciiProgressBarListener {
    async fn handle_event(
        &mut self,
        event: &SharedEvent,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match &**event {
            WalletScanEvent::ScanStarted { .. } => {
                self.start_scan();
            }
            WalletScanEvent::ScanProgress {
                current_block,
                total_blocks,
                percentage,
                speed_blocks_per_second,
                estimated_time_remaining,
                ..
            } => {
                // Note: current_block now contains blocks_processed, not block height
                // We'll use it for both values since we don't have access to the actual block height
                self.update_progress(
                    *current_block, // blocks_processed
                    *total_blocks,
                    *current_block, // using same value for current_block_height (not ideal but functional)
                    *percentage,
                    *speed_blocks_per_second,
                    *estimated_time_remaining,
                );
            }
            WalletScanEvent::OutputFound { .. } => {
                // Output counts are now tracked via BlockProcessed events to avoid double counting
                // Individual OutputFound events are used for detailed logging but not counting
            }
            WalletScanEvent::SpentOutputFound { .. } => {
                // Spent output counts are now tracked via BlockProcessed events to avoid double counting
                // Individual SpentOutputFound events are used for detailed logging but not counting
            }
            WalletScanEvent::BlockProcessed {
                outputs_count,
                spent_outputs_count,
                ..
            } => {
                // Update output counts from block processing but don't display progress
                // Progress display is handled by ScanProgress events for better accuracy
                if let Ok(mut state) = self.state.lock() {
                    state.outputs_found += outputs_count;
                    state.spent_found += spent_outputs_count;
                    // Don't display progress here - let ScanProgress events handle it
                }
            }
            WalletScanEvent::ScanCompleted { .. }
            | WalletScanEvent::ScanError { .. }
            | WalletScanEvent::ScanCancelled { .. } => {
                self.finish_scan();
                // Add a newline after clearing the progress line so subsequent output appears on a new line
                println!();
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "AsciiProgressBarListener"
    }

    fn wants_event(&self, event: &SharedEvent) -> bool {
        // We want to handle progress-related events
        matches!(
            &**event,
            WalletScanEvent::ScanStarted { .. }
                | WalletScanEvent::ScanProgress { .. }
                | WalletScanEvent::OutputFound { .. }
                | WalletScanEvent::SpentOutputFound { .. }
                | WalletScanEvent::BlockProcessed { .. }
                | WalletScanEvent::ScanCompleted { .. }
                | WalletScanEvent::ScanError { .. }
                | WalletScanEvent::ScanCancelled { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::types::{EventMetadata, WalletScanEvent};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_progress_bar_creation() {
        let listener = AsciiProgressBarListener::new();
        assert_eq!(listener.name(), "AsciiProgressBarListener");
        assert_eq!(listener.config.bar_width, 40);
    }

    #[tokio::test]
    async fn test_progress_bar_with_config() {
        let config = AsciiProgressBarConfig::new()
            .with_bar_width(60)
            .with_update_interval_ms(200)
            .with_colors(false);

        let listener = AsciiProgressBarListener::with_config(config);
        assert_eq!(listener.config.bar_width, 60);
        assert_eq!(listener.config.update_interval_ms, 200);
        assert!(!listener.config.use_colors);
    }

    #[tokio::test]
    async fn test_progress_events() {
        // Use a config with minimal update interval for testing
        let config = AsciiProgressBarConfig::new().with_update_interval_ms(50);
        let mut listener = AsciiProgressBarListener::with_config(config);

        // Test scan started event
        let start_event = SharedEvent::new(WalletScanEvent::ScanStarted {
            metadata: EventMetadata::new("test"),
            config: crate::events::types::ScanConfig {
                batch_size: Some(10),
                timeout_seconds: Some(30),
                retry_attempts: Some(3),
                scan_mode: Some("test".to_string()),
                filters: HashMap::new(),
            },
            block_range: (1000, 2000),
            wallet_context: "test_context".to_string(),
        });

        assert!(listener.handle_event(&start_event).await.is_ok());

        // Verify scan was started
        {
            let state = listener.state.lock().unwrap();
            assert!(state.scan_active);
        }

        // Wait a bit to ensure the rate limiting allows the next update
        tokio::time::sleep(tokio::time::Duration::from_millis(60)).await;

        // Test progress event (current_block now contains blocks_processed)
        let progress_event = SharedEvent::new(WalletScanEvent::ScanProgress {
            metadata: EventMetadata::new("test"),
            current_block: 500, // This is blocks_processed now
            total_blocks: 2000,
            percentage: 50.0,
            speed_blocks_per_second: 10.5,
            estimated_time_remaining: Some(Duration::from_secs(60)),
        });

        assert!(listener.handle_event(&progress_event).await.is_ok());

        // Verify state was updated
        {
            let state = listener.state.lock().unwrap();
            assert_eq!(state.blocks_processed, 500);
            assert_eq!(state.current_block_height, 500); // Same value since we don't have separate height
            assert_eq!(state.total_blocks, 2000);
            assert_eq!(state.progress_percent, 50.0);
            assert!((state.blocks_per_sec - 10.5).abs() < 0.1);
            assert!(state.scan_active);
        }
    }

    #[tokio::test]
    async fn test_scan_completion() {
        let mut listener = AsciiProgressBarListener::new();

        // Start scan
        let start_event = SharedEvent::new(WalletScanEvent::ScanStarted {
            metadata: EventMetadata::new("test"),
            config: crate::events::types::ScanConfig {
                batch_size: Some(10),
                timeout_seconds: Some(30),
                retry_attempts: Some(3),
                scan_mode: Some("test".to_string()),
                filters: HashMap::new(),
            },
            block_range: (1000, 2000),
            wallet_context: "test_context".to_string(),
        });

        let _ = listener.handle_event(&start_event).await;

        // Complete scan
        let complete_event = SharedEvent::new(WalletScanEvent::ScanCompleted {
            metadata: EventMetadata::new("test"),
            final_statistics: HashMap::new(),
            success: true,
            total_duration: Duration::from_secs(120),
        });

        assert!(listener.handle_event(&complete_event).await.is_ok());

        // Verify scan is no longer active
        {
            let state = listener.state.lock().unwrap();
            assert!(!state.scan_active);
        }
    }

    #[tokio::test]
    async fn test_wants_event_filtering() {
        let listener = AsciiProgressBarListener::new();

        let progress_event = SharedEvent::new(WalletScanEvent::ScanProgress {
            metadata: EventMetadata::new("test"),
            current_block: 500, // This is blocks_processed now
            total_blocks: 2000,
            percentage: 50.0,
            speed_blocks_per_second: 10.5,
            estimated_time_remaining: Some(Duration::from_secs(60)),
        });

        assert!(listener.wants_event(&progress_event));
    }
}
