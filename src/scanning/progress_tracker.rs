//! Progress tracking utilities for scanning operations
//!
//! Provides unified progress reporting across different platforms and scanner types.
//! Handles progress calculation, formatting, and callback management.

use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};

use super::ScanProgress;

/// Progress tracker for scanning operations
#[derive(Debug, Clone)]
pub struct ProgressTracker {
    inner: Arc<Mutex<ProgressTrackerInner>>,
}

#[derive(Debug)]
struct ProgressTrackerInner {
    start_time: Instant,
    current_height: u64,
    target_height: u64,
    outputs_found: u64,
    total_value: u64,
    last_update: Instant,
    update_frequency: Duration,
}

impl ProgressTracker {
    /// Create a new progress tracker
    pub fn new(start_height: u64, target_height: u64) -> Self {
        let inner = ProgressTrackerInner {
            start_time: Instant::now(),
            current_height: start_height,
            target_height,
            outputs_found: 0,
            total_value: 0,
            last_update: Instant::now(),
            update_frequency: Duration::from_secs(1), // Update at most once per second
        };

        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Update progress with new values
    pub fn update(&self, height: u64, outputs_found: u64, total_value: u64) {
        if let Ok(mut inner) = self.inner.lock() {
            let now = Instant::now();
            
            // Only update if enough time has passed to avoid spam
            if now.duration_since(inner.last_update) >= inner.update_frequency {
                inner.current_height = height;
                inner.outputs_found = outputs_found;
                inner.total_value = total_value;
                inner.last_update = now;
            }
        }
    }

    /// Get current progress snapshot
    pub fn get_progress(&self) -> Option<ScanProgress> {
        if let Ok(inner) = self.inner.lock() {
            Some(ScanProgress {
                current_height: inner.current_height,
                target_height: inner.target_height,
                outputs_found: inner.outputs_found,
                total_value: inner.total_value,
                elapsed: inner.start_time.elapsed(),
            })
        } else {
            None
        }
    }

    /// Calculate completion percentage (0.0 to 1.0)
    pub fn completion_percentage(&self) -> f64 {
        if let Ok(inner) = self.inner.lock() {
            if inner.target_height <= inner.current_height {
                return 1.0;
            }
            
            let total_blocks = inner.target_height.saturating_sub(inner.current_height);
            if total_blocks == 0 {
                return 1.0;
            }
            
            let completed_blocks = inner.current_height.saturating_sub(inner.current_height);
            completed_blocks as f64 / total_blocks as f64
        } else {
            0.0
        }
    }

    /// Calculate estimated time remaining
    pub fn estimated_time_remaining(&self) -> Option<Duration> {
        if let Ok(inner) = self.inner.lock() {
            let elapsed = inner.start_time.elapsed();
            let completed_blocks = inner.current_height.saturating_sub(inner.current_height);
            let remaining_blocks = inner.target_height.saturating_sub(inner.current_height);
            
            if completed_blocks == 0 || remaining_blocks == 0 {
                return None;
            }
            
            let blocks_per_second = completed_blocks as f64 / elapsed.as_secs_f64();
            if blocks_per_second <= 0.0 {
                return None;
            }
            
            let estimated_seconds = remaining_blocks as f64 / blocks_per_second;
            Some(Duration::from_secs_f64(estimated_seconds))
        } else {
            None
        }
    }

    /// Set the update frequency for progress reporting
    pub fn set_update_frequency(&self, frequency: Duration) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.update_frequency = frequency;
        }
    }
}

/// Progress formatter for different output types
pub struct ProgressFormatter;

impl ProgressFormatter {
    /// Format progress as a human-readable string
    pub fn format_human_readable(progress: &ScanProgress) -> String {
        let percentage = if progress.target_height > 0 {
            (progress.current_height as f64 / progress.target_height as f64) * 100.0
        } else {
            0.0
        };

        let elapsed_str = Self::format_duration(progress.elapsed);
        
        format!(
            "Height: {} / {} ({:.1}%) | Outputs: {} | Value: {} µT | Elapsed: {}",
            progress.current_height,
            progress.target_height,
            percentage,
            progress.outputs_found,
            progress.total_value,
            elapsed_str
        )
    }

    /// Format progress as a progress bar
    pub fn format_progress_bar(progress: &ScanProgress, width: usize) -> String {
        let percentage = if progress.target_height > 0 {
            progress.current_height as f64 / progress.target_height as f64
        } else {
            0.0
        };

        let filled_width = (width as f64 * percentage) as usize;
        let empty_width = width.saturating_sub(filled_width);

        let filled = "█".repeat(filled_width);
        let empty = "░".repeat(empty_width);
        
        format!("[{}{}] {:.1}%", filled, empty, percentage * 100.0)
    }

    /// Format progress as JSON
    pub fn format_json(progress: &ScanProgress) -> serde_json::Value {
        serde_json::json!({
            "current_height": progress.current_height,
            "target_height": progress.target_height,
            "completion_percentage": if progress.target_height > 0 {
                (progress.current_height as f64 / progress.target_height as f64) * 100.0
            } else {
                0.0
            },
            "outputs_found": progress.outputs_found,
            "total_value": progress.total_value,
            "elapsed_seconds": progress.elapsed.as_secs(),
            "elapsed_formatted": Self::format_duration(progress.elapsed)
        })
    }

    /// Format a duration as a human-readable string
    fn format_duration(duration: Duration) -> String {
        let total_seconds = duration.as_secs();
        let hours = total_seconds / 3600;
        let minutes = (total_seconds % 3600) / 60;
        let seconds = total_seconds % 60;

        if hours > 0 {
            format!("{}h {}m {}s", hours, minutes, seconds)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, seconds)
        } else {
            format!("{}s", seconds)
        }
    }
}

/// Progress callback manager for handling multiple progress reporters
pub struct ProgressCallbackManager {
    callbacks: Vec<Box<dyn Fn(&ScanProgress) + Send + Sync>>,
}

impl ProgressCallbackManager {
    /// Create a new progress callback manager
    pub fn new() -> Self {
        Self {
            callbacks: Vec::new(),
        }
    }

    /// Add a progress callback
    pub fn add_callback<F>(&mut self, callback: F)
    where
        F: Fn(&ScanProgress) + Send + Sync + 'static,
    {
        self.callbacks.push(Box::new(callback));
    }

    /// Notify all callbacks with the current progress
    pub fn notify(&self, progress: &ScanProgress) {
        for callback in &self.callbacks {
            callback(progress);
        }
    }

    /// Add a console progress callback
    pub fn add_console_callback(&mut self, quiet: bool) {
        if !quiet {
            self.add_callback(move |progress| {
                let formatted = ProgressFormatter::format_human_readable(progress);
                println!("{}", formatted);
            });
        }
    }

    /// Add a progress bar callback
    pub fn add_progress_bar_callback(&mut self, width: usize) {
        self.add_callback(move |progress| {
            let bar = ProgressFormatter::format_progress_bar(progress, width);
            let human = ProgressFormatter::format_human_readable(progress);
            println!("{} {}", bar, human);
        });
    }

    /// Add a JSON progress callback
    pub fn add_json_callback(&mut self) {
        self.add_callback(|progress| {
            let json = ProgressFormatter::format_json(progress);
            println!("{}", json);
        });
    }
}

impl Default for ProgressCallbackManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_progress_tracker_creation() {
        let tracker = ProgressTracker::new(0, 1000);
        let progress = tracker.get_progress().unwrap();
        
        assert_eq!(progress.current_height, 0);
        assert_eq!(progress.target_height, 1000);
        assert_eq!(progress.outputs_found, 0);
        assert_eq!(progress.total_value, 0);
    }

    #[test]
    fn test_progress_tracker_update() {
        let tracker = ProgressTracker::new(0, 1000);
        tracker.update(500, 10, 5000);
        
        thread::sleep(Duration::from_millis(100)); // Ensure update frequency is met
        tracker.update(600, 15, 7500);
        
        let progress = tracker.get_progress().unwrap();
        assert_eq!(progress.current_height, 600);
        assert_eq!(progress.outputs_found, 15);
        assert_eq!(progress.total_value, 7500);
    }

    #[test]
    fn test_completion_percentage() {
        let tracker = ProgressTracker::new(0, 1000);
        tracker.update(250, 5, 1000);
        
        let percentage = tracker.completion_percentage();
        assert!((percentage - 0.25).abs() < 0.01); // Within 1% tolerance
    }

    #[test]
    fn test_progress_formatter_human_readable() {
        let progress = ScanProgress {
            current_height: 500,
            target_height: 1000,
            outputs_found: 10,
            total_value: 5000,
            elapsed: Duration::from_secs(120),
        };

        let formatted = ProgressFormatter::format_human_readable(&progress);
        assert!(formatted.contains("50.0%"));
        assert!(formatted.contains("Height: 500 / 1000"));
        assert!(formatted.contains("Outputs: 10"));
        assert!(formatted.contains("Value: 5000"));
    }

    #[test]
    fn test_progress_formatter_progress_bar() {
        let progress = ScanProgress {
            current_height: 500,
            target_height: 1000,
            outputs_found: 10,
            total_value: 5000,
            elapsed: Duration::from_secs(120),
        };

        let bar = ProgressFormatter::format_progress_bar(&progress, 20);
        assert!(bar.contains("50.0%"));
        assert!(bar.contains("["));
        assert!(bar.contains("]"));
    }

    #[test]
    fn test_progress_formatter_json() {
        let progress = ScanProgress {
            current_height: 500,
            target_height: 1000,
            outputs_found: 10,
            total_value: 5000,
            elapsed: Duration::from_secs(120),
        };

        let json = ProgressFormatter::format_json(&progress);
        assert_eq!(json["current_height"], 500);
        assert_eq!(json["target_height"], 1000);
        assert_eq!(json["outputs_found"], 10);
        assert_eq!(json["total_value"], 5000);
        assert_eq!(json["elapsed_seconds"], 120);
    }

    #[test]
    fn test_duration_formatting() {
        assert_eq!(ProgressFormatter::format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(ProgressFormatter::format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(ProgressFormatter::format_duration(Duration::from_secs(3665)), "1h 1m 5s");
    }

    #[test]
    fn test_progress_callback_manager() {
        let mut manager = ProgressCallbackManager::new();
        let called = Arc::new(Mutex::new(false));
        let called_clone = called.clone();

        manager.add_callback(move |_| {
            *called_clone.lock().unwrap() = true;
        });

        let progress = ScanProgress {
            current_height: 100,
            target_height: 1000,
            outputs_found: 5,
            total_value: 2500,
            elapsed: Duration::from_secs(60),
        };

        manager.notify(&progress);
        assert!(*called.lock().unwrap());
    }
}
