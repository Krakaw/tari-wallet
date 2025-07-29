//! Progress tracking and display utilities for wallet scanning.
//!
//! This module provides configurable progress tracking with support for
//! different output modes (detailed, summary, quiet) and progress bar
//! display functionality.
//!
//! The library provides progress data and calculations, while actual display
//! can be handled via callbacks or by the consuming application.

use std::time::{Duration, Instant};

/// Progress information for scanning operations
#[derive(Debug, Clone)]
pub struct ProgressInfo {
    /// Current block being processed
    pub current_block: u64,
    /// Total number of blocks to process
    pub total_blocks: usize,
    /// Number of blocks processed so far
    pub blocks_processed: usize,
    /// Number of wallet outputs found
    pub outputs_found: usize,
    /// Number of spent outputs found
    pub inputs_found: usize,
    /// Time when scanning started
    pub start_time: Instant,
    /// Progress percentage (0.0 to 100.0)
    pub progress_percent: f64,
    /// Processing speed in blocks per second
    pub blocks_per_sec: f64,
    /// Elapsed time since start
    pub elapsed: Duration,
    /// Estimated time remaining (if available)
    pub eta: Option<Duration>,
}

impl ProgressInfo {
    /// Check if this progress update should be displayed based on frequency
    pub fn should_display(&self, frequency: usize) -> bool {
        frequency > 0 && self.blocks_processed % frequency == 0
    }
}

/// Callback function type for progress updates
pub type ProgressCallback = Box<dyn Fn(&ProgressInfo) + Send + Sync>;

/// Configuration for progress tracking
#[derive(Debug, Clone)]
pub struct ProgressConfig {
    /// Update frequency (every N blocks)
    pub frequency: usize,
    /// Whether to suppress progress updates
    pub quiet: bool,
    /// Whether to calculate ETA
    pub calculate_eta: bool,
}

impl Default for ProgressConfig {
    fn default() -> Self {
        Self {
            frequency: 10,
            quiet: false,
            calculate_eta: true,
        }
    }
}

/// Progress tracker for wallet scanning operations
pub struct ProgressTracker {
    /// Current progress state
    current_block: u64,
    total_blocks: usize,
    blocks_processed: usize,
    outputs_found: usize,
    inputs_found: usize,
    start_time: Instant,

    /// Configuration
    config: ProgressConfig,

    /// Optional callback for progress updates
    callback: Option<ProgressCallback>,
}

impl ProgressTracker {
    /// Create a new progress tracker
    pub fn new(total_blocks: usize) -> Self {
        Self {
            current_block: 0,
            total_blocks,
            blocks_processed: 0,
            outputs_found: 0,
            inputs_found: 0,
            start_time: Instant::now(),
            config: ProgressConfig::default(),
            callback: None,
        }
    }

    /// Create a new progress tracker with custom configuration
    pub fn with_config(total_blocks: usize, config: ProgressConfig) -> Self {
        Self {
            current_block: 0,
            total_blocks,
            blocks_processed: 0,
            outputs_found: 0,
            inputs_found: 0,
            start_time: Instant::now(),
            config,
            callback: None,
        }
    }

    /// Set a progress callback function
    pub fn with_callback(mut self, callback: ProgressCallback) -> Self {
        self.callback = Some(callback);
        self
    }

    /// Update progress with new block information
    pub fn update(&mut self, block_height: u64, found_outputs: usize, spent_inputs: usize) {
        self.current_block = block_height;
        self.blocks_processed += 1;
        self.outputs_found += found_outputs;
        self.inputs_found += spent_inputs;

        // Generate progress info and call callback if configured
        if !self.config.quiet {
            let progress_info = self.get_progress_info();

            // Only call callback if this update should be displayed
            if progress_info.should_display(self.config.frequency) {
                if let Some(ref callback) = self.callback {
                    callback(&progress_info);
                }
            }
        }
    }

    /// Get current progress information
    pub fn get_progress_info(&self) -> ProgressInfo {
        let elapsed = self.start_time.elapsed();
        let progress_percent = if self.total_blocks > 0 {
            (self.blocks_processed as f64 / self.total_blocks as f64) * 100.0
        } else {
            0.0
        };

        let blocks_per_sec = if elapsed.as_secs_f64() > 0.0 {
            self.blocks_processed as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        // Calculate ETA if enabled and we have meaningful data
        let eta = if self.config.calculate_eta
            && self.blocks_processed > 0
            && blocks_per_sec > 0.0
            && self.blocks_processed < self.total_blocks
        {
            let remaining_blocks = self.total_blocks - self.blocks_processed;
            let eta_seconds = remaining_blocks as f64 / blocks_per_sec;
            Some(Duration::from_secs_f64(eta_seconds))
        } else {
            None
        };

        ProgressInfo {
            current_block: self.current_block,
            total_blocks: self.total_blocks,
            blocks_processed: self.blocks_processed,
            outputs_found: self.outputs_found,
            inputs_found: self.inputs_found,
            start_time: self.start_time,
            progress_percent,
            blocks_per_sec,
            elapsed,
            eta,
        }
    }

    /// Get total blocks to process
    pub fn total_blocks(&self) -> usize {
        self.total_blocks
    }

    /// Get blocks processed so far
    pub fn blocks_processed(&self) -> usize {
        self.blocks_processed
    }

    /// Get current block height
    pub fn current_block(&self) -> u64 {
        self.current_block
    }

    /// Get outputs found so far
    pub fn outputs_found(&self) -> usize {
        self.outputs_found
    }

    /// Get inputs found so far
    pub fn inputs_found(&self) -> usize {
        self.inputs_found
    }

    /// Check if scanning is complete
    pub fn is_complete(&self) -> bool {
        self.blocks_processed >= self.total_blocks
    }

    /// Get the configuration
    pub fn config(&self) -> &ProgressConfig {
        &self.config
    }

    /// Update the configuration
    pub fn set_config(&mut self, config: ProgressConfig) {
        self.config = config;
    }

    /// Update the total number of blocks to process
    pub fn set_total_blocks(&mut self, total_blocks: usize) {
        self.total_blocks = total_blocks;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_progress_tracker_creation() {
        let tracker = ProgressTracker::new(100);
        assert_eq!(tracker.total_blocks(), 100);
        assert_eq!(tracker.blocks_processed(), 0);
        assert_eq!(tracker.current_block(), 0);
        assert_eq!(tracker.outputs_found(), 0);
        assert_eq!(tracker.inputs_found(), 0);
        assert!(!tracker.is_complete());
    }

    #[test]
    fn test_progress_tracker_with_config() {
        let config = ProgressConfig {
            frequency: 5,
            quiet: true,
            calculate_eta: false,
        };
        let tracker = ProgressTracker::with_config(50, config);
        assert_eq!(tracker.total_blocks(), 50);
        assert_eq!(tracker.config().frequency, 5);
        assert!(tracker.config().quiet);
        assert!(!tracker.config().calculate_eta);
    }

    #[test]
    fn test_progress_tracker_updates() {
        let mut tracker = ProgressTracker::new(10);

        // Update with block data
        tracker.update(100, 5, 2);
        assert_eq!(tracker.current_block(), 100);
        assert_eq!(tracker.blocks_processed(), 1);
        assert_eq!(tracker.outputs_found(), 5);
        assert_eq!(tracker.inputs_found(), 2);

        // Another update
        tracker.update(101, 3, 1);
        assert_eq!(tracker.current_block(), 101);
        assert_eq!(tracker.blocks_processed(), 2);
        assert_eq!(tracker.outputs_found(), 8);
        assert_eq!(tracker.inputs_found(), 3);
    }

    #[test]
    fn test_progress_info_generation() {
        let mut tracker = ProgressTracker::new(100);
        tracker.update(50, 10, 5);

        let progress_info = tracker.get_progress_info();
        assert_eq!(progress_info.current_block, 50);
        assert_eq!(progress_info.total_blocks, 100);
        assert_eq!(progress_info.blocks_processed, 1);
        assert_eq!(progress_info.outputs_found, 10);
        assert_eq!(progress_info.inputs_found, 5);
        assert_eq!(progress_info.progress_percent, 1.0); // 1/100 * 100
    }

    #[test]
    fn test_progress_info_should_display() {
        let progress_info = ProgressInfo {
            current_block: 10,
            total_blocks: 100,
            blocks_processed: 10,
            outputs_found: 5,
            inputs_found: 2,
            start_time: Instant::now(),
            progress_percent: 10.0,
            blocks_per_sec: 1.0,
            elapsed: Duration::from_secs(10),
            eta: None,
        };

        // Should display every 5 blocks
        assert!(progress_info.should_display(5));
        assert!(progress_info.should_display(10));
        assert!(!progress_info.should_display(3));

        // Zero frequency means never display
        assert!(!progress_info.should_display(0));
    }

    #[test]
    fn test_progress_tracker_with_callback() {
        let callback_invoked = Arc::new(Mutex::new(false));
        let callback_invoked_clone = callback_invoked.clone();

        let callback: ProgressCallback = Box::new(move |_info| {
            *callback_invoked_clone.lock().unwrap() = true;
        });

        let config = ProgressConfig {
            frequency: 1, // Every block
            quiet: false,
            calculate_eta: true,
        };

        let mut tracker = ProgressTracker::with_config(10, config).with_callback(callback);

        // Should invoke callback on first update
        tracker.update(100, 1, 0);
        assert!(*callback_invoked.lock().unwrap());
    }

    #[test]
    fn test_progress_tracker_quiet_mode() {
        let callback_invoked = Arc::new(Mutex::new(false));
        let callback_invoked_clone = callback_invoked.clone();

        let callback: ProgressCallback = Box::new(move |_info| {
            *callback_invoked_clone.lock().unwrap() = true;
        });

        let config = ProgressConfig {
            frequency: 1,
            quiet: true, // Should not invoke callback
            calculate_eta: true,
        };

        let mut tracker = ProgressTracker::with_config(10, config).with_callback(callback);

        // Should not invoke callback in quiet mode
        tracker.update(100, 1, 0);
        assert!(!*callback_invoked.lock().unwrap());
    }

    #[test]
    fn test_progress_tracker_completion() {
        let mut tracker = ProgressTracker::new(3);
        assert!(!tracker.is_complete());

        tracker.update(100, 1, 0);
        assert!(!tracker.is_complete());

        tracker.update(101, 1, 0);
        assert!(!tracker.is_complete());

        tracker.update(102, 1, 0);
        assert!(tracker.is_complete());
    }

    #[test]
    fn test_progress_config_default() {
        let config = ProgressConfig::default();
        assert_eq!(config.frequency, 10);
        assert!(!config.quiet);
        assert!(config.calculate_eta);
    }

    #[test]
    fn test_progress_tracker_set_methods() {
        let mut tracker = ProgressTracker::new(100);

        // Test setting new total blocks
        tracker.set_total_blocks(200);
        assert_eq!(tracker.total_blocks(), 200);

        // Test setting new config
        let new_config = ProgressConfig {
            frequency: 5,
            quiet: true,
            calculate_eta: false,
        };
        tracker.set_config(new_config);
        assert_eq!(tracker.config().frequency, 5);
        assert!(tracker.config().quiet);
        assert!(!tracker.config().calculate_eta);
    }

    #[test]
    fn test_progress_info_eta_calculation() {
        let mut tracker = ProgressTracker::new(100);

        // Process some blocks to have meaningful data for ETA
        for i in 0..10 {
            tracker.update(i, 1, 0);
            // Small delay to ensure time passes
            std::thread::sleep(Duration::from_millis(1));
        }

        let progress_info = tracker.get_progress_info();
        assert!(progress_info.blocks_per_sec > 0.0);
        assert!(progress_info.eta.is_some());

        // Test with ETA disabled
        let config = ProgressConfig {
            frequency: 1,
            quiet: false,
            calculate_eta: false,
        };
        tracker.set_config(config);

        let progress_info = tracker.get_progress_info();
        assert!(progress_info.eta.is_none());
    }

    #[test]
    fn test_progress_info_edge_cases() {
        // Test with zero total blocks
        let tracker = ProgressTracker::new(0);
        let progress_info = tracker.get_progress_info();
        assert_eq!(progress_info.progress_percent, 0.0);

        // Test progress calculation with normal values
        let mut tracker = ProgressTracker::new(50);
        tracker.update(100, 1, 0);
        tracker.update(101, 1, 0);
        let progress_info = tracker.get_progress_info();
        assert_eq!(progress_info.progress_percent, 4.0); // 2/50 * 100

        // Test when all blocks are processed
        let mut tracker = ProgressTracker::new(2);
        tracker.update(100, 1, 0);
        tracker.update(101, 1, 0);
        let progress_info = tracker.get_progress_info();
        assert_eq!(progress_info.progress_percent, 100.0);
        assert!(tracker.is_complete());
    }

    #[test]
    fn test_progress_callback_frequency() {
        let callback_count = Arc::new(Mutex::new(0));
        let callback_count_clone = callback_count.clone();

        let callback: ProgressCallback = Box::new(move |_info| {
            *callback_count_clone.lock().unwrap() += 1;
        });

        let config = ProgressConfig {
            frequency: 3, // Every 3 blocks
            quiet: false,
            calculate_eta: true,
        };

        let mut tracker = ProgressTracker::with_config(10, config).with_callback(callback);

        // Update 5 times - should only trigger callback twice (at blocks 3 and 6)
        for i in 1..=5 {
            tracker.update(i, 1, 0);
        }

        assert_eq!(*callback_count.lock().unwrap(), 1); // Only block 3 triggers (blocks_processed=3)

        // One more update to reach block 6
        tracker.update(6, 1, 0);
        assert_eq!(*callback_count.lock().unwrap(), 2); // blocks_processed=6 triggers
    }

    #[test]
    fn test_progress_info_format_validation() {
        let start_time = Instant::now();
        let progress_info = ProgressInfo {
            current_block: 12345,
            total_blocks: 50000,
            blocks_processed: 10000,
            outputs_found: 25,
            inputs_found: 15,
            start_time,
            progress_percent: 20.0,
            blocks_per_sec: 10.5,
            elapsed: Duration::from_secs(120),
            eta: Some(Duration::from_secs(3600)),
        };

        // Verify all fields are accessible and have expected values
        assert_eq!(progress_info.current_block, 12345);
        assert_eq!(progress_info.total_blocks, 50000);
        assert_eq!(progress_info.blocks_processed, 10000);
        assert_eq!(progress_info.outputs_found, 25);
        assert_eq!(progress_info.inputs_found, 15);
        assert_eq!(progress_info.progress_percent, 20.0);
        assert_eq!(progress_info.blocks_per_sec, 10.5);
        assert_eq!(progress_info.elapsed, Duration::from_secs(120));
        assert_eq!(progress_info.eta, Some(Duration::from_secs(3600)));

        // Test should_display with various frequencies
        assert!(progress_info.should_display(100)); // 10000 % 100 == 0
        assert!(progress_info.should_display(1000)); // 10000 % 1000 == 0
        assert!(!progress_info.should_display(333)); // 10000 % 333 != 0
    }
}
