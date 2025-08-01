//! Progress tracking listener for monitoring and reporting wallet scan progress
//!
//! This listener replicates the functionality of the current progress_tracker system
//! by handling scan events and providing customizable progress tracking with callbacks.
//! It tracks scan statistics, calculates ETA, and reports progress at configurable intervals.

use async_trait::async_trait;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::events::{EventListener, SharedEvent, WalletScanEvent};

/// Progress information for scanning operations
///
/// This structure contains comprehensive information about the current state
/// of a wallet scanning operation, including timing, statistics, and projections.
#[derive(Debug, Clone)]
pub struct ScanProgressInfo {
    /// Current block being processed
    pub current_block: u64,
    /// Total number of blocks to process
    pub total_blocks: u64,
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
    /// Last block height processed
    pub last_block_height: u64,
    /// Whether the scan has been completed
    pub is_completed: bool,
    /// Whether the scan was cancelled
    pub is_cancelled: bool,
    /// Whether the scan had errors
    pub has_errors: bool,
}

impl ScanProgressInfo {
    /// Check if this progress update should be displayed based on frequency
    pub fn should_display(&self, frequency: usize) -> bool {
        frequency > 0
            && (self.blocks_processed % frequency == 0 || self.is_completed || self.is_cancelled)
    }

    /// Get a human-readable summary of the progress
    pub fn summary(&self) -> String {
        if self.is_completed {
            format!(
                "Scan completed: {blocks_processed} blocks processed, {outputs_found} outputs found in {elapsed:?}",
                blocks_processed = self.blocks_processed,
                outputs_found = self.outputs_found,
                elapsed = self.elapsed
            )
        } else if self.is_cancelled {
            format!(
                "Scan cancelled: {blocks_processed} blocks processed, {outputs_found} outputs found after {elapsed:?}",
                blocks_processed = self.blocks_processed,
                outputs_found = self.outputs_found,
                elapsed = self.elapsed
            )
        } else {
            let eta_str = self
                .eta
                .map(|eta| format!(", ETA: {eta:?}"))
                .unwrap_or_default();
            format!(
                "Progress: {progress_percent:.1}% ({blocks_processed}/{total_blocks}), {outputs_found} outputs found, {blocks_per_sec:.1} blocks/sec{eta_str}",
                progress_percent = self.progress_percent,
                blocks_processed = self.blocks_processed,
                total_blocks = self.total_blocks,
                outputs_found = self.outputs_found,
                blocks_per_sec = self.blocks_per_sec,
                eta_str = eta_str
            )
        }
    }
}

/// Callback function type for progress updates
pub type ProgressCallback = Arc<dyn Fn(&ScanProgressInfo) + Send + Sync>;

/// Callback function type for scan completion
pub type CompletionCallback = Arc<dyn Fn(&ScanProgressInfo) + Send + Sync>;

/// Callback function type for scan errors
pub type ErrorCallback = Arc<dyn Fn(&str, Option<u64>) + Send + Sync>;

/// Configuration for progress tracking
#[derive(Debug, Clone)]
pub struct ProgressTrackingConfig {
    /// Update frequency (every N blocks)
    pub frequency: usize,
    /// Whether to suppress progress updates
    pub quiet: bool,
    /// Whether to calculate ETA
    pub calculate_eta: bool,
    /// Minimum time between progress updates (to avoid spam)
    pub min_update_interval_ms: u64,
    /// Whether to track detailed statistics
    pub track_detailed_stats: bool,
}

impl Default for ProgressTrackingConfig {
    fn default() -> Self {
        Self {
            frequency: 10,
            quiet: false,
            calculate_eta: true,
            min_update_interval_ms: 1000, // 1 second
            track_detailed_stats: true,
        }
    }
}

/// Progress tracking listener that monitors scan progress and provides callbacks
///
/// This listener handles all progress-related events from wallet scanning operations,
/// maintaining statistics, calculating ETA, and providing customizable callbacks
/// for different types of progress updates.
///
/// # Features
///
/// - **Real-time progress tracking**: Monitors scan progress across all events
/// - **ETA calculation**: Provides estimated time remaining based on current speed
/// - **Customizable callbacks**: Support for progress, completion, and error callbacks
/// - **Statistics tracking**: Comprehensive statistics about the scan operation
/// - **Frequency control**: Configurable update frequency to control callback rate
/// - **Time-based throttling**: Minimum intervals between updates to prevent spam
///
/// # Usage
///
/// ```rust,ignore
/// use lightweight_wallet_libs::events::listeners::ProgressTrackingListener;
/// use lightweight_wallet_libs::events::EventDispatcher;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create with default configuration
/// let listener = ProgressTrackingListener::new();
///
/// // Or create with custom callbacks
/// let listener = ProgressTrackingListener::new()
///     .with_progress_callback(|progress| {
///         println!("Scan progress: {:.1}%", progress.progress_percent);
///     })
///     .with_completion_callback(|final_progress| {
///         println!("Scan completed! Found {} outputs", final_progress.outputs_found);
///     })
///     .with_error_callback(|error, block_height| {
///         eprintln!("Scan error at block {:?}: {}", block_height, error);
///     });
///
/// // Register with event dispatcher
/// let mut dispatcher = EventDispatcher::new();
/// dispatcher.register(Box::new(listener))?;
/// # Ok(())
/// # }
/// ```
pub struct ProgressTrackingListener {
    /// Progress tracking state (wrapped in Arc<Mutex<>> for thread safety)
    state: Arc<Mutex<ProgressState>>,
    /// Configuration for progress tracking
    config: ProgressTrackingConfig,
    /// Optional callback for progress updates
    progress_callback: Option<ProgressCallback>,
    /// Optional callback for scan completion
    completion_callback: Option<CompletionCallback>,
    /// Optional callback for scan errors
    error_callback: Option<ErrorCallback>,
    /// Whether to enable verbose logging
    verbose: bool,
}

/// Internal state for progress tracking
#[derive(Debug, Default)]
struct ProgressState {
    /// Current block being processed
    current_block: u64,
    /// Total number of blocks to process
    total_blocks: u64,
    /// Number of blocks processed so far
    blocks_processed: usize,
    /// Number of wallet outputs found
    outputs_found: usize,
    /// Number of spent outputs found
    inputs_found: usize,
    /// Time when scanning started
    start_time: Option<Instant>,
    /// Last update time (for throttling)
    last_update_time: Option<Instant>,
    /// Last block height processed
    last_block_height: u64,
    /// Whether the scan has been completed
    is_completed: bool,
    /// Whether the scan was cancelled
    is_cancelled: bool,
    /// Whether the scan had errors
    has_errors: bool,
    /// Block range from scan start
    block_range: Option<(u64, u64)>,
}

impl ProgressTrackingListener {
    /// Create a new progress tracking listener with default configuration
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ProgressState::default())),
            config: ProgressTrackingConfig::default(),
            progress_callback: None,
            completion_callback: None,
            error_callback: None,
            verbose: false,
        }
    }

    /// Create a new progress tracking listener with custom configuration
    pub fn with_config(config: ProgressTrackingConfig) -> Self {
        Self {
            state: Arc::new(Mutex::new(ProgressState::default())),
            config,
            progress_callback: None,
            completion_callback: None,
            error_callback: None,
            verbose: false,
        }
    }

    /// Create a builder for configuring the progress tracking listener
    pub fn builder() -> ProgressTrackingListenerBuilder {
        ProgressTrackingListenerBuilder::new()
    }

    /// Set a progress callback function
    pub fn with_progress_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&ScanProgressInfo) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Arc::new(callback));
        self
    }

    /// Set a completion callback function
    pub fn with_completion_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&ScanProgressInfo) + Send + Sync + 'static,
    {
        self.completion_callback = Some(Arc::new(callback));
        self
    }

    /// Set an error callback function
    pub fn with_error_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&str, Option<u64>) + Send + Sync + 'static,
    {
        self.error_callback = Some(Arc::new(callback));
        self
    }

    /// Enable or disable verbose logging
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Set the update frequency
    pub fn with_frequency(mut self, frequency: usize) -> Self {
        self.config.frequency = frequency;
        self
    }

    /// Enable or disable quiet mode
    pub fn with_quiet(mut self, quiet: bool) -> Self {
        self.config.quiet = quiet;
        self
    }

    /// Enable or disable ETA calculation
    pub fn with_eta_calculation(mut self, calculate_eta: bool) -> Self {
        self.config.calculate_eta = calculate_eta;
        self
    }

    /// Set the minimum update interval in milliseconds
    pub fn with_min_update_interval(mut self, interval_ms: u64) -> Self {
        self.config.min_update_interval_ms = interval_ms;
        self
    }

    /// Get current progress information
    pub fn get_progress_info(&self) -> Option<ScanProgressInfo> {
        let state = self.state.lock().ok()?;
        self.build_progress_info(&state)
    }

    /// Reset the progress tracking state (useful for new scans)
    pub fn reset(&self) {
        if let Ok(mut state) = self.state.lock() {
            *state = ProgressState::default();
        }
    }

    /// Handle ScanStarted event
    async fn handle_scan_started(
        &self,
        _config: &crate::events::types::ScanConfig,
        block_range: (u64, u64),
        _wallet_context: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Ok(mut state) = self.state.lock() {
            state.start_time = Some(Instant::now());
            state.block_range = Some(block_range);
            state.total_blocks = block_range.1 - block_range.0 + 1;
            state.current_block = block_range.0;
            state.blocks_processed = 0;
            state.outputs_found = 0;
            state.inputs_found = 0;
            state.is_completed = false;
            state.is_cancelled = false;
            state.has_errors = false;

            if self.verbose {
                self.log(&format!(
                    "Scan started: blocks {from}-{to} ({total} total)",
                    from = block_range.0,
                    to = block_range.1,
                    total = state.total_blocks
                ));
            }
        }

        Ok(())
    }

    /// Handle BlockProcessed event
    async fn handle_block_processed(
        &self,
        height: u64,
        _hash: &str,
        _timestamp: u64,
        _processing_duration: Duration,
        _outputs_count: usize,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let progress_info = {
            if let Ok(mut state) = self.state.lock() {
                state.current_block = height;
                state.last_block_height = height;
                state.blocks_processed += 1;
                // Note: We don't add to outputs_found here since that's handled in OutputFound events

                // Check if we should trigger a progress update
                let should_update = self.should_trigger_update(&state);

                if should_update {
                    if let Some(progress_info) = self.build_progress_info(&state) {
                        state.last_update_time = Some(Instant::now());
                        Some(progress_info)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        }; // Lock is released here

        if let Some(progress_info) = progress_info {
            self.trigger_progress_callback(&progress_info).await;
        }

        Ok(())
    }

    /// Handle OutputFound event
    async fn handle_output_found(
        &self,
        _output_data: &crate::events::types::OutputData,
        _block_info: &crate::events::types::BlockInfo,
        _address_info: &crate::events::types::AddressInfo,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Ok(mut state) = self.state.lock() {
            state.outputs_found += 1;

            if self.verbose {
                self.log(&format!(
                    "Output found at block {current_block} (total: {outputs_found})",
                    current_block = state.current_block,
                    outputs_found = state.outputs_found
                ));
            }
        }

        Ok(())
    }

    /// Handle ScanProgress event
    async fn handle_scan_progress(
        &self,
        current_block: u64,
        total_blocks: u64,
        percentage: f64,
        _speed_blocks_per_second: f64,
        _estimated_time_remaining: Option<Duration>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let progress_info = {
            if let Ok(mut state) = self.state.lock() {
                state.current_block = current_block;
                state.total_blocks = total_blocks;

                // Update blocks_processed based on progress
                state.blocks_processed = (percentage / 100.0 * total_blocks as f64) as usize;

                // Check if we should trigger a progress update
                let should_update = self.should_trigger_update(&state);

                if should_update {
                    if let Some(progress_info) = self.build_progress_info(&state) {
                        state.last_update_time = Some(Instant::now());
                        Some(progress_info)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        }; // Lock is released here

        if let Some(progress_info) = progress_info {
            self.trigger_progress_callback(&progress_info).await;
        }

        Ok(())
    }

    /// Handle ScanCompleted event
    async fn handle_scan_completed(
        &self,
        final_statistics: &std::collections::HashMap<String, u64>,
        success: bool,
        _total_duration: Duration,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let progress_info = {
            if let Ok(mut state) = self.state.lock() {
                state.is_completed = true;

                // Update statistics from final data if available
                if let Some(&blocks_count) = final_statistics.get("blocks_processed") {
                    state.blocks_processed = blocks_count as usize;
                }
                if let Some(&outputs_count) = final_statistics.get("outputs_found") {
                    state.outputs_found = outputs_count as usize;
                }

                self.build_progress_info(&state)
            } else {
                None
            }
        }; // Lock is released here

        if let Some(progress_info) = progress_info {
            if self.verbose {
                self.log(&format!("Scan completed: success={success}"));
            }

            self.trigger_completion_callback(&progress_info).await;
        }

        Ok(())
    }

    /// Handle ScanError event
    async fn handle_scan_error(
        &self,
        error_message: &str,
        _error_code: Option<&str>,
        block_height: Option<u64>,
        _retry_info: Option<&str>,
        _is_recoverable: bool,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Ok(mut state) = self.state.lock() {
            state.has_errors = true;
        }

        if self.verbose {
            self.log(&format!(
                "Scan error at block {block_height:?}: {error_message}"
            ));
        }

        self.trigger_error_callback(error_message, block_height)
            .await;

        Ok(())
    }

    /// Handle ScanCancelled event
    async fn handle_scan_cancelled(
        &self,
        reason: &str,
        final_statistics: &std::collections::HashMap<String, u64>,
        _partial_completion: Option<f64>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let progress_info = {
            if let Ok(mut state) = self.state.lock() {
                state.is_cancelled = true;

                // Update statistics from final data if available
                if let Some(&blocks_count) = final_statistics.get("blocks_processed") {
                    state.blocks_processed = blocks_count as usize;
                }
                if let Some(&outputs_count) = final_statistics.get("outputs_found") {
                    state.outputs_found = outputs_count as usize;
                }

                self.build_progress_info(&state)
            } else {
                None
            }
        }; // Lock is released here

        if let Some(progress_info) = progress_info {
            if self.verbose {
                self.log(&format!("Scan cancelled: {reason}"));
            }

            self.trigger_completion_callback(&progress_info).await;
        }

        Ok(())
    }

    /// Build progress info from current state
    fn build_progress_info(&self, state: &ProgressState) -> Option<ScanProgressInfo> {
        let start_time = state.start_time?;
        let elapsed = start_time.elapsed();

        let progress_percent = if state.total_blocks > 0 {
            (state.blocks_processed as f64 / state.total_blocks as f64) * 100.0
        } else {
            0.0
        };

        let blocks_per_sec = if elapsed.as_secs_f64() > 0.0 {
            state.blocks_processed as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        // Calculate ETA if enabled and we have meaningful data
        let eta = if self.config.calculate_eta
            && state.blocks_processed > 0
            && blocks_per_sec > 0.0
            && state.blocks_processed < state.total_blocks as usize
        {
            let remaining_blocks = state.total_blocks as usize - state.blocks_processed;
            let eta_seconds = remaining_blocks as f64 / blocks_per_sec;
            Some(Duration::from_secs_f64(eta_seconds))
        } else {
            None
        };

        Some(ScanProgressInfo {
            current_block: state.current_block,
            total_blocks: state.total_blocks,
            blocks_processed: state.blocks_processed,
            outputs_found: state.outputs_found,
            inputs_found: state.inputs_found,
            start_time,
            progress_percent,
            blocks_per_sec,
            elapsed,
            eta,
            last_block_height: state.last_block_height,
            is_completed: state.is_completed,
            is_cancelled: state.is_cancelled,
            has_errors: state.has_errors,
        })
    }

    /// Check if we should trigger a progress update
    fn should_trigger_update(&self, state: &ProgressState) -> bool {
        if self.config.quiet {
            return false;
        }

        // Always update on completion or cancellation
        if state.is_completed || state.is_cancelled {
            return true;
        }

        // Check frequency
        if self.config.frequency > 0 && state.blocks_processed % self.config.frequency != 0 {
            return false;
        }

        // Check minimum time interval
        if let Some(last_update) = state.last_update_time {
            let time_since_last = last_update.elapsed();
            if time_since_last.as_millis() < self.config.min_update_interval_ms as u128 {
                return false;
            }
        }

        true
    }

    /// Trigger progress callback if set
    async fn trigger_progress_callback(&self, progress_info: &ScanProgressInfo) {
        if let Some(ref callback) = self.progress_callback {
            callback(progress_info);
        }
    }

    /// Trigger completion callback if set
    async fn trigger_completion_callback(&self, progress_info: &ScanProgressInfo) {
        if let Some(ref callback) = self.completion_callback {
            callback(progress_info);
        }
    }

    /// Trigger error callback if set
    async fn trigger_error_callback(&self, error_message: &str, block_height: Option<u64>) {
        if let Some(ref callback) = self.error_callback {
            callback(error_message, block_height);
        }
    }

    /// Log a message (platform-specific)
    fn log(&self, message: &str) {
        let log_message = format!("[ProgressTrackingListener] {message}");

        #[cfg(target_arch = "wasm32")]
        web_sys::console::log_1(&log_message.into());

        #[cfg(not(target_arch = "wasm32"))]
        println!("{log_message}");
    }
}

impl Default for ProgressTrackingListener {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventListener for ProgressTrackingListener {
    async fn handle_event(
        &mut self,
        event: &SharedEvent,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match event.as_ref() {
            WalletScanEvent::ScanStarted {
                config,
                block_range,
                wallet_context,
                ..
            } => {
                self.handle_scan_started(config, *block_range, wallet_context)
                    .await
            }
            WalletScanEvent::BlockProcessed {
                height,
                hash,
                timestamp,
                processing_duration,
                outputs_count,
                ..
            } => {
                self.handle_block_processed(
                    *height,
                    hash,
                    *timestamp,
                    *processing_duration,
                    *outputs_count,
                )
                .await
            }
            WalletScanEvent::OutputFound {
                output_data,
                block_info,
                address_info,
                ..
            } => {
                self.handle_output_found(output_data, block_info, address_info)
                    .await
            }
            WalletScanEvent::SpentOutputFound { .. } => {
                // Track spent outputs in inputs_found counter
                if let Ok(mut state) = self.state.lock() {
                    state.inputs_found += 1;
                }
                Ok(())
            }
            WalletScanEvent::ScanProgress {
                current_block,
                total_blocks,
                percentage,
                speed_blocks_per_second,
                estimated_time_remaining,
                ..
            } => {
                self.handle_scan_progress(
                    *current_block,
                    *total_blocks,
                    *percentage,
                    *speed_blocks_per_second,
                    *estimated_time_remaining,
                )
                .await
            }
            WalletScanEvent::ScanCompleted {
                final_statistics,
                success,
                total_duration,
                ..
            } => {
                self.handle_scan_completed(final_statistics, *success, *total_duration)
                    .await
            }
            WalletScanEvent::ScanError {
                error_message,
                error_code,
                block_height,
                retry_info,
                is_recoverable,
                ..
            } => {
                self.handle_scan_error(
                    error_message,
                    error_code.as_deref(),
                    *block_height,
                    retry_info.as_deref(),
                    *is_recoverable,
                )
                .await
            }
            WalletScanEvent::ScanCancelled {
                reason,
                final_statistics,
                partial_completion,
                ..
            } => {
                self.handle_scan_cancelled(reason, final_statistics, *partial_completion)
                    .await
            }
        }
    }

    fn name(&self) -> &'static str {
        "ProgressTrackingListener"
    }

    /// Only handle events that are relevant to progress tracking
    fn wants_event(&self, event: &SharedEvent) -> bool {
        match event.as_ref() {
            WalletScanEvent::ScanStarted { .. }
            | WalletScanEvent::BlockProcessed { .. }
            | WalletScanEvent::OutputFound { .. }
            | WalletScanEvent::SpentOutputFound { .. }
            | WalletScanEvent::ScanProgress { .. }
            | WalletScanEvent::ScanCompleted { .. }
            | WalletScanEvent::ScanError { .. }
            | WalletScanEvent::ScanCancelled { .. } => true,
        }
    }
}

/// Builder for configuring ProgressTrackingListener
pub struct ProgressTrackingListenerBuilder {
    config: ProgressTrackingConfig,
    progress_callback: Option<ProgressCallback>,
    completion_callback: Option<CompletionCallback>,
    error_callback: Option<ErrorCallback>,
    verbose: bool,
}

impl ProgressTrackingListenerBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            config: ProgressTrackingConfig::default(),
            progress_callback: None,
            completion_callback: None,
            error_callback: None,
            verbose: false,
        }
    }

    /// Set the update frequency
    pub fn frequency(mut self, frequency: usize) -> Self {
        self.config.frequency = frequency;
        self
    }

    /// Enable or disable quiet mode
    pub fn quiet(mut self, quiet: bool) -> Self {
        self.config.quiet = quiet;
        self
    }

    /// Enable or disable ETA calculation
    pub fn calculate_eta(mut self, calculate_eta: bool) -> Self {
        self.config.calculate_eta = calculate_eta;
        self
    }

    /// Set the minimum update interval in milliseconds
    pub fn min_update_interval_ms(mut self, interval_ms: u64) -> Self {
        self.config.min_update_interval_ms = interval_ms;
        self
    }

    /// Enable or disable detailed statistics tracking
    pub fn track_detailed_stats(mut self, track_detailed_stats: bool) -> Self {
        self.config.track_detailed_stats = track_detailed_stats;
        self
    }

    /// Set a progress callback function
    pub fn with_progress_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&ScanProgressInfo) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Arc::new(callback));
        self
    }

    /// Set a completion callback function
    pub fn with_completion_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&ScanProgressInfo) + Send + Sync + 'static,
    {
        self.completion_callback = Some(Arc::new(callback));
        self
    }

    /// Set an error callback function
    pub fn with_error_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&str, Option<u64>) + Send + Sync + 'static,
    {
        self.error_callback = Some(Arc::new(callback));
        self
    }

    /// Enable verbose logging
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Apply silent preset configuration for minimal output
    ///
    /// This preset:
    /// - Sets quiet mode to true (no console output)
    /// - Disables verbose logging
    /// - Sets update frequency to 100 blocks
    /// - Disables ETA calculation for performance
    /// - Disables detailed statistics tracking
    ///
    /// Useful for background operations or when only callback-based progress is needed.
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ProgressTrackingListener::builder()
    ///     .silent_preset()
    ///     .with_progress_callback(|info| log::info!("Progress: {:.1}%", info.progress_percent))
    ///     .build();
    /// ```
    pub fn silent_preset(mut self) -> Self {
        self.config.quiet = true;
        self.config.frequency = 100;
        self.config.calculate_eta = false;
        self.config.track_detailed_stats = false;
        self.verbose = false;
        self
    }

    /// Apply console preset configuration for interactive use
    ///
    /// This preset:
    /// - Sets quiet mode to false (enables console output)
    /// - Enables verbose logging
    /// - Sets update frequency to 10 blocks for responsive feedback
    /// - Enables ETA calculation
    /// - Enables detailed statistics tracking
    /// - Sets minimum update interval to 500ms to avoid spam
    ///
    /// Ideal for interactive command-line tools and development.
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ProgressTrackingListener::builder()
    ///     .console_preset()
    ///     .build();
    /// ```
    pub fn console_preset(mut self) -> Self {
        self.config.quiet = false;
        self.config.frequency = 10;
        self.config.calculate_eta = true;
        self.config.track_detailed_stats = true;
        self.config.min_update_interval_ms = 500;
        self.verbose = true;
        self
    }

    /// Apply performance preset configuration for high-throughput scanning
    ///
    /// This preset:
    /// - Sets quiet mode to true (reduces I/O overhead)
    /// - Disables verbose logging
    /// - Sets update frequency to 500 blocks for minimal updates
    /// - Disables ETA calculation (saves CPU)
    /// - Disables detailed statistics tracking (saves memory)
    /// - Sets minimum update interval to 2000ms
    ///
    /// Optimized for maximum scanning performance with minimal progress overhead.
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ProgressTrackingListener::builder()
    ///     .performance_preset()
    ///     .with_progress_callback(|info| {
    ///         if info.blocks_processed % 1000 == 0 {
    ///             println!("Processed {} blocks", info.blocks_processed);
    ///         }
    ///     })
    ///     .build();
    /// ```
    pub fn performance_preset(mut self) -> Self {
        self.config.quiet = true;
        self.config.frequency = 500;
        self.config.calculate_eta = false;
        self.config.track_detailed_stats = false;
        self.config.min_update_interval_ms = 2000;
        self.verbose = false;
        self
    }

    /// Apply detailed preset configuration for comprehensive monitoring
    ///
    /// This preset:
    /// - Sets quiet mode to false (enables console output)
    /// - Enables verbose logging
    /// - Sets update frequency to 5 blocks for very frequent updates
    /// - Enables ETA calculation
    /// - Enables detailed statistics tracking
    /// - Sets minimum update interval to 250ms for rapid feedback
    ///
    /// Provides maximum visibility into the scanning process for debugging
    /// and detailed analysis.
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ProgressTrackingListener::builder()
    ///     .detailed_preset()
    ///     .with_progress_callback(|info| {
    ///         log::debug!("Detailed progress: {:?}", info);
    ///     })
    ///     .build();
    /// ```
    pub fn detailed_preset(mut self) -> Self {
        self.config.quiet = false;
        self.config.frequency = 5;
        self.config.calculate_eta = true;
        self.config.track_detailed_stats = true;
        self.config.min_update_interval_ms = 250;
        self.verbose = true;
        self
    }

    /// Apply CI preset configuration for continuous integration environments
    ///
    /// This preset:
    /// - Sets quiet mode to false but with less frequent updates
    /// - Disables verbose logging to reduce log volume
    /// - Sets update frequency to 50 blocks for periodic updates
    /// - Enables ETA calculation for time estimates
    /// - Enables detailed statistics for final reporting
    /// - Sets minimum update interval to 5000ms to prevent CI log spam
    ///
    /// Balances progress visibility with CI log cleanliness.
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = ProgressTrackingListener::builder()
    ///     .ci_preset()
    ///     .build();
    /// ```
    pub fn ci_preset(mut self) -> Self {
        self.config.quiet = false;
        self.config.frequency = 50;
        self.config.calculate_eta = true;
        self.config.track_detailed_stats = true;
        self.config.min_update_interval_ms = 5000;
        self.verbose = false;
        self
    }

    /// Build the configured ProgressTrackingListener
    pub fn build(self) -> ProgressTrackingListener {
        let mut listener =
            ProgressTrackingListener::with_config(self.config).with_verbose(self.verbose);

        if let Some(callback) = self.progress_callback {
            listener.progress_callback = Some(callback);
        }

        if let Some(callback) = self.completion_callback {
            listener.completion_callback = Some(callback);
        }

        if let Some(callback) = self.error_callback {
            listener.error_callback = Some(callback);
        }

        listener
    }
}

impl Default for ProgressTrackingListenerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::types::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn test_progress_tracking_listener_creation() {
        let listener = ProgressTrackingListener::new();
        assert_eq!(listener.name(), "ProgressTrackingListener");
        assert!(listener.get_progress_info().is_none()); // No scan started yet
    }

    #[tokio::test]
    async fn test_progress_tracking_listener_builder() {
        let callback_invoked = Arc::new(AtomicUsize::new(0));
        let callback_invoked_clone = callback_invoked.clone();

        let listener = ProgressTrackingListener::builder()
            .frequency(5)
            .quiet(false)
            .calculate_eta(true)
            .verbose(true)
            .with_progress_callback(move |_progress| {
                callback_invoked_clone.fetch_add(1, Ordering::SeqCst);
            })
            .build();

        assert_eq!(listener.config.frequency, 5);
        assert!(!listener.config.quiet);
        assert!(listener.config.calculate_eta);
        assert!(listener.verbose);
        assert!(listener.progress_callback.is_some());
    }

    #[tokio::test]
    async fn test_scan_started_event() {
        let listener = ProgressTrackingListener::new();

        let event = Arc::new(WalletScanEvent::scan_started(
            ScanConfig::default(),
            (1000, 2000),
            "test_wallet".to_string(),
        ));

        let mut listener_mut = listener;
        let result = listener_mut.handle_event(&event).await;
        assert!(result.is_ok());

        let progress_info = listener_mut.get_progress_info().unwrap();
        assert_eq!(progress_info.current_block, 1000);
        assert_eq!(progress_info.total_blocks, 1001); // 2000 - 1000 + 1
        assert_eq!(progress_info.blocks_processed, 0);
        assert!(!progress_info.is_completed);
    }

    #[tokio::test]
    async fn test_block_processed_event() {
        let listener = ProgressTrackingListener::new();

        // Start scan first
        let start_event = Arc::new(WalletScanEvent::scan_started(
            ScanConfig::default(),
            (1000, 1100),
            "test_wallet".to_string(),
        ));

        let mut listener_mut = listener;
        let _ = listener_mut.handle_event(&start_event).await;

        // Process a block
        let block_event = Arc::new(WalletScanEvent::block_processed(
            1001,
            "block_hash".to_string(),
            1697123456,
            Duration::from_millis(100),
            5,
        ));

        let result = listener_mut.handle_event(&block_event).await;
        assert!(result.is_ok());

        let progress_info = listener_mut.get_progress_info().unwrap();
        assert_eq!(progress_info.current_block, 1001);
        assert_eq!(progress_info.blocks_processed, 1);
        assert_eq!(progress_info.last_block_height, 1001);
    }

    #[tokio::test]
    async fn test_output_found_event() {
        let listener = ProgressTrackingListener::new();

        // Start scan first
        let start_event = Arc::new(WalletScanEvent::scan_started(
            ScanConfig::default(),
            (1000, 1100),
            "test_wallet".to_string(),
        ));

        let mut listener_mut = listener;
        let _ = listener_mut.handle_event(&start_event).await;

        // Process an output found event
        let output_data = OutputData::new(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            "range_proof_data".to_string(),
            1,
            true,
        )
        .with_amount(1000);

        let block_info = BlockInfo::new(1001, "block_hash".to_string(), 1697123456, 0);

        let address_info = AddressInfo::new(
            "tari1xyz123...".to_string(),
            "stealth".to_string(),
            "mainnet".to_string(),
        );

        let transaction_data = crate::events::types::TransactionData::new(
            2000,
            "MinedConfirmed".to_string(),
            "Inbound".to_string(),
            1697123456,
        );

        let output_event = Arc::new(WalletScanEvent::output_found(
            output_data,
            block_info,
            address_info,
            transaction_data,
        ));

        let result = listener_mut.handle_event(&output_event).await;
        assert!(result.is_ok());

        let progress_info = listener_mut.get_progress_info().unwrap();
        assert_eq!(progress_info.outputs_found, 1);
    }

    #[tokio::test]
    async fn test_scan_progress_event() {
        let listener = ProgressTrackingListener::new();

        // Start scan first
        let start_event = Arc::new(WalletScanEvent::scan_started(
            ScanConfig::default(),
            (1000, 1100),
            "test_wallet".to_string(),
        ));

        let mut listener_mut = listener;
        let _ = listener_mut.handle_event(&start_event).await;

        // Send progress event
        let progress_event = Arc::new(WalletScanEvent::scan_progress(
            1050,
            101,
            50.0,
            10.5,
            Some(Duration::from_secs(30)),
        ));

        let result = listener_mut.handle_event(&progress_event).await;
        assert!(result.is_ok());

        let progress_info = listener_mut.get_progress_info().unwrap();
        assert_eq!(progress_info.current_block, 1050);
        assert_eq!(progress_info.total_blocks, 101);
        assert_eq!(progress_info.blocks_processed, 50); // Based on 50% progress
    }

    #[tokio::test]
    async fn test_scan_completed_event() {
        let listener = ProgressTrackingListener::new();

        // Start scan first
        let start_event = Arc::new(WalletScanEvent::scan_started(
            ScanConfig::default(),
            (1000, 1100),
            "test_wallet".to_string(),
        ));

        let mut listener_mut = listener;
        let _ = listener_mut.handle_event(&start_event).await;

        // Complete the scan
        let mut final_stats = std::collections::HashMap::new();
        final_stats.insert("blocks_processed".to_string(), 101);
        final_stats.insert("outputs_found".to_string(), 25);

        let completed_event = Arc::new(WalletScanEvent::scan_completed(
            final_stats,
            true,
            Duration::from_secs(60),
        ));

        let result = listener_mut.handle_event(&completed_event).await;
        assert!(result.is_ok());

        let progress_info = listener_mut.get_progress_info().unwrap();
        assert_eq!(progress_info.blocks_processed, 101);
        assert_eq!(progress_info.outputs_found, 25);
        assert!(progress_info.is_completed);
        assert!(!progress_info.is_cancelled);
    }

    #[tokio::test]
    async fn test_scan_cancelled_event() {
        let listener = ProgressTrackingListener::new();

        // Start scan first
        let start_event = Arc::new(WalletScanEvent::scan_started(
            ScanConfig::default(),
            (1000, 1100),
            "test_wallet".to_string(),
        ));

        let mut listener_mut = listener;
        let _ = listener_mut.handle_event(&start_event).await;

        // Cancel the scan
        let mut final_stats = std::collections::HashMap::new();
        final_stats.insert("blocks_processed".to_string(), 50);
        final_stats.insert("outputs_found".to_string(), 10);

        let cancelled_event = Arc::new(WalletScanEvent::scan_cancelled(
            "User cancelled".to_string(),
            final_stats,
            Some(0.5),
        ));

        let result = listener_mut.handle_event(&cancelled_event).await;
        assert!(result.is_ok());

        let progress_info = listener_mut.get_progress_info().unwrap();
        assert_eq!(progress_info.blocks_processed, 50);
        assert_eq!(progress_info.outputs_found, 10);
        assert!(!progress_info.is_completed);
        assert!(progress_info.is_cancelled);
    }

    #[tokio::test]
    async fn test_scan_error_event() {
        let error_count = Arc::new(AtomicUsize::new(0));
        let error_count_clone = error_count.clone();

        let listener =
            ProgressTrackingListener::new().with_error_callback(move |_error, _block| {
                error_count_clone.fetch_add(1, Ordering::SeqCst);
            });

        let error_event = Arc::new(WalletScanEvent::scan_error(
            "Test error".to_string(),
            Some("ERR001".to_string()),
            Some(1050),
            None,
            true,
        ));

        let mut listener_mut = listener;
        let result = listener_mut.handle_event(&error_event).await;
        assert!(result.is_ok());
        assert_eq!(error_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_progress_callback_frequency() {
        let callback_count = Arc::new(AtomicUsize::new(0));
        let callback_count_clone = callback_count.clone();

        let listener = ProgressTrackingListener::builder()
            .frequency(3) // Every 3 blocks
            .min_update_interval_ms(0) // No time throttling for test
            .with_progress_callback(move |_progress| {
                callback_count_clone.fetch_add(1, Ordering::SeqCst);
            })
            .build();

        // Start scan
        let start_event = Arc::new(WalletScanEvent::scan_started(
            ScanConfig::default(),
            (1000, 1010),
            "test_wallet".to_string(),
        ));

        let mut listener_mut = listener;
        let _ = listener_mut.handle_event(&start_event).await;

        // Process 5 blocks - should trigger callback twice (at blocks 3 and 6)
        for i in 1..=5 {
            let block_event = Arc::new(WalletScanEvent::block_processed(
                1000 + i,
                format!("block_hash_{i}"),
                1697123456,
                Duration::from_millis(100),
                0,
            ));
            let _ = listener_mut.handle_event(&block_event).await;
        }

        assert_eq!(callback_count.load(Ordering::SeqCst), 1); // Only at blocks_processed=3
    }

    #[tokio::test]
    async fn test_event_filtering() {
        let listener = ProgressTrackingListener::new();

        // All relevant events should be wanted
        let scan_started = Arc::new(WalletScanEvent::scan_started(
            ScanConfig::default(),
            (0, 100),
            "test_wallet".to_string(),
        ));
        assert!(listener.wants_event(&scan_started));

        let block_processed = Arc::new(WalletScanEvent::block_processed(
            100,
            "block_hash".to_string(),
            1234567890,
            Duration::from_millis(100),
            5,
        ));
        assert!(listener.wants_event(&block_processed));
    }

    #[tokio::test]
    async fn test_progress_info_summary() {
        let progress_info = ScanProgressInfo {
            current_block: 1050,
            total_blocks: 2000,
            blocks_processed: 500,
            outputs_found: 25,
            inputs_found: 10,
            start_time: Instant::now(),
            progress_percent: 25.0,
            blocks_per_sec: 10.5,
            elapsed: Duration::from_secs(60),
            eta: Some(Duration::from_secs(180)),
            last_block_height: 1050,
            is_completed: false,
            is_cancelled: false,
            has_errors: false,
        };

        let summary = progress_info.summary();
        assert!(summary.contains("25.0%"));
        assert!(summary.contains("500/2000"));
        assert!(summary.contains("25 outputs"));
        assert!(summary.contains("10.5 blocks/sec"));
        assert!(summary.contains("ETA"));
    }

    #[tokio::test]
    async fn test_reset_functionality() {
        let listener = ProgressTrackingListener::new();

        // Start scan and process some blocks
        let start_event = Arc::new(WalletScanEvent::scan_started(
            ScanConfig::default(),
            (1000, 1100),
            "test_wallet".to_string(),
        ));

        let mut listener_mut = listener;
        let _ = listener_mut.handle_event(&start_event).await;

        // Verify state is set
        assert!(listener_mut.get_progress_info().is_some());

        // Reset and verify state is cleared
        listener_mut.reset();
        assert!(listener_mut.get_progress_info().is_none());
    }

    #[test]
    fn test_progress_tracking_listener_builder_presets() {
        // Test silent preset
        let silent_listener = ProgressTrackingListener::builder().silent_preset().build();
        assert!(silent_listener.config.quiet);
        assert_eq!(silent_listener.config.frequency, 100);
        assert!(!silent_listener.config.calculate_eta);
        assert!(!silent_listener.config.track_detailed_stats);
        assert!(!silent_listener.verbose);

        // Test console preset
        let console_listener = ProgressTrackingListener::builder().console_preset().build();
        assert!(!console_listener.config.quiet);
        assert_eq!(console_listener.config.frequency, 10);
        assert!(console_listener.config.calculate_eta);
        assert!(console_listener.config.track_detailed_stats);
        assert_eq!(console_listener.config.min_update_interval_ms, 500);
        assert!(console_listener.verbose);

        // Test performance preset
        let performance_listener = ProgressTrackingListener::builder()
            .performance_preset()
            .build();
        assert!(performance_listener.config.quiet);
        assert_eq!(performance_listener.config.frequency, 500);
        assert!(!performance_listener.config.calculate_eta);
        assert!(!performance_listener.config.track_detailed_stats);
        assert_eq!(performance_listener.config.min_update_interval_ms, 2000);
        assert!(!performance_listener.verbose);

        // Test detailed preset
        let detailed_listener = ProgressTrackingListener::builder()
            .detailed_preset()
            .build();
        assert!(!detailed_listener.config.quiet);
        assert_eq!(detailed_listener.config.frequency, 5);
        assert!(detailed_listener.config.calculate_eta);
        assert!(detailed_listener.config.track_detailed_stats);
        assert_eq!(detailed_listener.config.min_update_interval_ms, 250);
        assert!(detailed_listener.verbose);

        // Test CI preset
        let ci_listener = ProgressTrackingListener::builder().ci_preset().build();
        assert!(!ci_listener.config.quiet);
        assert_eq!(ci_listener.config.frequency, 50);
        assert!(ci_listener.config.calculate_eta);
        assert!(ci_listener.config.track_detailed_stats);
        assert_eq!(ci_listener.config.min_update_interval_ms, 5000);
        assert!(!ci_listener.verbose);
    }

    #[test]
    fn test_progress_tracking_listener_builder_preset_chaining() {
        let listener = ProgressTrackingListener::builder()
            .performance_preset() // Start with performance preset
            .frequency(25) // Override frequency
            .verbose(true) // Override verbose
            .build();

        // Should have the overridden values
        assert_eq!(listener.config.frequency, 25);
        assert!(listener.verbose);

        // Should retain other preset values
        assert!(listener.config.quiet);
        assert!(!listener.config.calculate_eta);
        assert!(!listener.config.track_detailed_stats);
    }

    #[test]
    fn test_progress_tracking_listener_builder_with_callbacks() {
        let progress_called = Arc::new(AtomicUsize::new(0));
        let progress_called_clone = progress_called.clone();

        let completion_called = Arc::new(AtomicUsize::new(0));
        let completion_called_clone = completion_called.clone();

        let error_called = Arc::new(AtomicUsize::new(0));
        let error_called_clone = error_called.clone();

        let listener = ProgressTrackingListener::builder()
            .console_preset()
            .with_progress_callback(move |_info| {
                progress_called_clone.fetch_add(1, Ordering::Relaxed);
            })
            .with_completion_callback(move |_info| {
                completion_called_clone.fetch_add(1, Ordering::Relaxed);
            })
            .with_error_callback(move |_error, _block| {
                error_called_clone.fetch_add(1, Ordering::Relaxed);
            })
            .build();

        // Verify the listener was configured correctly
        assert!(!listener.config.quiet);
        assert_eq!(listener.config.frequency, 10);
        assert!(listener.verbose);

        // Verify callbacks are set (we can't easily test execution without async setup)
        assert!(listener.progress_callback.is_some());
        assert!(listener.completion_callback.is_some());
        assert!(listener.error_callback.is_some());
    }
}
