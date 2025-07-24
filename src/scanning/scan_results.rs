//! Scan results and progress reporting for the scanner library

use crate::common::format_number;
use crate::data_structures::{
    transaction_output::LightweightTransactionOutput, wallet_output::LightweightWalletOutput,
    wallet_transaction::WalletState,
};
use crate::errors::{LightweightWalletError, LightweightWalletResult};
#[cfg(target_arch = "wasm32")]
use js_sys;
use serde::{Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use std::time::{Duration, Instant};

/// Structured progress reporting for scan operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    /// Current block height being scanned
    pub current_height: u64,
    /// Target block height to scan to (None if scanning to tip)
    pub target_height: Option<u64>,
    /// Number of blocks scanned so far
    pub blocks_scanned: u64,
    /// Total number of blocks to scan (None if unknown/scanning to tip)
    pub total_blocks: Option<u64>,
    /// Number of outputs found so far
    pub outputs_found: u64,
    /// Number of outputs spent so far
    pub outputs_spent: u64,
    /// Total value of outputs found so far (in MicroMinotari)
    pub total_value: u64,
    /// Current scan rate (blocks per second)
    pub scan_rate: f64,
    /// Time elapsed since scan started (seconds for WASM compatibility)
    #[cfg(target_arch = "wasm32")]
    pub elapsed_seconds: f64,
    #[cfg(not(target_arch = "wasm32"))]
    #[serde(with = "duration_serde")]
    pub elapsed: Duration,
    /// Estimated time remaining (seconds for WASM compatibility)
    #[cfg(target_arch = "wasm32")]
    pub estimated_remaining_seconds: Option<f64>,
    #[cfg(not(target_arch = "wasm32"))]
    #[serde(with = "duration_option_serde")]
    pub estimated_remaining: Option<Duration>,
    /// Current scan phase description
    pub phase: ScanPhase,
}

/// Different phases of the scanning operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanPhase {
    /// Initializing scanner and wallet
    Initializing,
    /// Connecting to blockchain node
    Connecting,
    /// Scanning blocks for outputs
    Scanning {
        batch_index: usize,
        total_batches: Option<usize>,
    },
    /// Processing and extracting wallet outputs
    Processing,
    /// Saving results to storage
    Saving,
    /// Completing scan and finalizing
    Finalizing,
    /// Scan completed successfully
    Completed,
    /// Scan was interrupted
    Interrupted,
    /// Error occurred during scanning
    Error(String),
}

impl Default for ScanPhase {
    fn default() -> Self {
        ScanPhase::Initializing
    }
}

impl ScanProgress {
    /// Create a new scan progress tracker
    pub fn new(start_height: u64, target_height: Option<u64>) -> Self {
        let total_blocks = target_height.map(|end| end.saturating_sub(start_height) + 1);

        Self {
            current_height: start_height,
            target_height,
            blocks_scanned: 0,
            total_blocks,
            outputs_found: 0,
            outputs_spent: 0,
            total_value: 0,
            scan_rate: 0.0,
            #[cfg(target_arch = "wasm32")]
            elapsed_seconds: 0.0,
            #[cfg(not(target_arch = "wasm32"))]
            elapsed: Duration::from_secs(0),
            #[cfg(target_arch = "wasm32")]
            estimated_remaining_seconds: None,
            #[cfg(not(target_arch = "wasm32"))]
            estimated_remaining: None,
            phase: ScanPhase::Initializing,
        }
    }

    /// Update progress with current scan state
    #[cfg(not(target_arch = "wasm32"))]
    pub fn update(
        &mut self,
        current_height: u64,
        blocks_scanned: u64,
        outputs_found: u64,
        outputs_spent: u64,
        total_value: u64,
        elapsed: Duration,
    ) {
        self.current_height = current_height;
        self.blocks_scanned = blocks_scanned;
        self.outputs_found = outputs_found;
        self.outputs_spent = outputs_spent;
        self.total_value = total_value;
        self.elapsed = elapsed;

        // Calculate scan rate (blocks per second)
        if elapsed.as_secs_f64() > 0.0 {
            self.scan_rate = blocks_scanned as f64 / elapsed.as_secs_f64();
        }

        // Calculate estimated time remaining
        if let Some(total) = self.total_blocks {
            let remaining_blocks = total.saturating_sub(blocks_scanned);
            if self.scan_rate > 0.0 && remaining_blocks > 0 {
                let remaining_seconds = remaining_blocks as f64 / self.scan_rate;
                self.estimated_remaining = Some(Duration::from_secs_f64(remaining_seconds));
            }
        }
    }

    /// Update progress with current scan state (WASM version with seconds)
    #[cfg(target_arch = "wasm32")]
    pub fn update_wasm(
        &mut self,
        current_height: u64,
        blocks_scanned: u64,
        outputs_found: u64,
        outputs_spent: u64,
        total_value: u64,
        elapsed_seconds: f64,
    ) {
        self.current_height = current_height;
        self.blocks_scanned = blocks_scanned;
        self.outputs_found = outputs_found;
        self.outputs_spent = outputs_spent;
        self.total_value = total_value;
        self.elapsed_seconds = elapsed_seconds;

        // Calculate scan rate (blocks per second)
        if elapsed_seconds > 0.0 {
            self.scan_rate = blocks_scanned as f64 / elapsed_seconds;
        }

        // Calculate estimated time remaining
        if let Some(total) = self.total_blocks {
            let remaining_blocks = total.saturating_sub(blocks_scanned);
            if self.scan_rate > 0.0 && remaining_blocks > 0 {
                let remaining_seconds = remaining_blocks as f64 / self.scan_rate;
                self.estimated_remaining_seconds = Some(remaining_seconds);
            }
        }
    }

    /// Set the current scan phase
    pub fn set_phase(&mut self, phase: ScanPhase) {
        self.phase = phase;
    }

    /// Get completion percentage (0.0 to 100.0)
    pub fn completion_percentage(&self) -> f64 {
        if let Some(total) = self.total_blocks {
            if total > 0 {
                return (self.blocks_scanned as f64 / total as f64) * 100.0;
            }
        }
        0.0
    }

    /// Check if scan is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.phase, ScanPhase::Completed)
    }

    /// Check if scan was interrupted
    pub fn is_interrupted(&self) -> bool {
        matches!(self.phase, ScanPhase::Interrupted)
    }

    /// Check if scan has an error
    pub fn has_error(&self) -> bool {
        matches!(self.phase, ScanPhase::Error(_))
    }

    /// Format a progress bar string for display
    pub fn format_progress_bar(&self, width: usize) -> String {
        let percentage = self.completion_percentage();
        let filled = ((percentage / 100.0) * width as f64) as usize;
        let empty = width.saturating_sub(filled);

        format!(
            "[{}{}] {:.1}% {} Block {} | 💰 {}T | 📈 {}T | 📉 {}T | {} TX",
            "█".repeat(filled),
            "░".repeat(empty),
            percentage,
            match self.phase {
                ScanPhase::Completed => "Complete",
                ScanPhase::Interrupted => "Interrupted",
                ScanPhase::Scanning { .. } => "Scanning",
                _ => "Processing",
            },
            format_number(self.current_height),
            format_tari_amount(self.total_value),
            format_tari_amount(self.total_value),
            format_tari_amount(0), // Spent amount - would need to track separately
            format_number(self.outputs_found)
        )
    }

    /// Create a summary string of the progress
    pub fn summary(&self) -> String {
        format!(
            "Block {}, {} outputs found, {} spent, {:.2} blocks/sec",
            format_number(self.current_height),
            format_number(self.outputs_found),
            format_number(self.outputs_spent),
            self.scan_rate
        )
    }
}

/// Comprehensive scan results management
#[derive(Debug, Clone)]
pub struct ScanResults {
    /// Scan configuration that was used
    pub scan_config_summary: ScanConfigSummary,
    /// Final wallet state after scanning
    pub wallet_state: WalletState,
    /// Block scan results
    pub block_results: Vec<BlockScanResult>,
    /// Final scan progress
    pub final_progress: ScanProgress,
    /// Scan start time (timestamp for WASM compatibility)
    #[cfg(target_arch = "wasm32")]
    pub start_timestamp: f64,
    #[cfg(not(target_arch = "wasm32"))]
    pub start_time: Instant,
    /// Scan end time (timestamp for WASM compatibility)
    #[cfg(target_arch = "wasm32")]
    pub end_timestamp: f64,
    #[cfg(not(target_arch = "wasm32"))]
    pub end_time: Instant,
    /// Whether the scan completed successfully
    pub completed_successfully: bool,
    /// Error message if scan failed
    pub error_message: Option<String>,
    /// Statistics about the scan
    pub statistics: ScanStatistics,
}

/// Summary of scan configuration (for results)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfigSummary {
    /// Starting block height
    pub start_height: u64,
    /// Ending block height (if specified)
    pub end_height: Option<u64>,
    /// Specific blocks scanned (if used)
    pub specific_blocks: Option<Vec<u64>>,
    /// Batch size used
    pub batch_size: u64,
    /// Total blocks scanned
    pub total_blocks_scanned: u64,
}

/// Detailed statistics about the scan operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    /// Total scan duration (seconds for WASM compatibility)
    #[cfg(target_arch = "wasm32")]
    pub total_duration_seconds: f64,
    #[cfg(not(target_arch = "wasm32"))]
    pub total_duration: Duration,
    /// Average scan rate (blocks per second)
    pub average_scan_rate: f64,
    /// Peak scan rate (blocks per second)
    pub peak_scan_rate: f64,
    /// Number of batches processed
    pub batches_processed: usize,
    /// Average batch processing time (seconds for WASM compatibility)
    #[cfg(target_arch = "wasm32")]
    pub average_batch_time_seconds: f64,
    #[cfg(not(target_arch = "wasm32"))]
    pub average_batch_time: Duration,
    /// Total outputs found
    pub total_outputs_found: u64,
    /// Total outputs spent
    pub total_outputs_spent: u64,
    /// Total value found (in MicroMinotari)
    pub total_value_found: u64,
    /// Total value spent (in MicroMinotari)  
    pub total_value_spent: u64,
    /// Net value change (found - spent)
    pub net_value_change: i64,
    /// Number of addresses that had activity
    pub active_addresses: u64,
    /// Number of transactions processed
    pub transactions_processed: u64,
    /// Storage operations performed
    pub storage_operations: StorageStatistics,
}

/// Statistics about storage operations during scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStatistics {
    /// Number of outputs saved to storage
    pub outputs_saved: u64,
    /// Number of transactions saved to storage
    pub transactions_saved: u64,
    /// Number of spent output updates
    pub spent_updates: u64,
    /// Total storage operation time (seconds for WASM compatibility)
    #[cfg(target_arch = "wasm32")]
    pub total_storage_time_seconds: f64,
    #[cfg(not(target_arch = "wasm32"))]
    pub total_storage_time: Duration,
    /// Average time per storage operation (seconds for WASM compatibility)
    #[cfg(target_arch = "wasm32")]
    pub average_storage_time_seconds: f64,
    #[cfg(not(target_arch = "wasm32"))]
    pub average_storage_time: Duration,
}

impl Default for StorageStatistics {
    fn default() -> Self {
        Self {
            outputs_saved: 0,
            transactions_saved: 0,
            spent_updates: 0,
            #[cfg(target_arch = "wasm32")]
            total_storage_time_seconds: 0.0,
            #[cfg(not(target_arch = "wasm32"))]
            total_storage_time: Duration::from_secs(0),
            #[cfg(target_arch = "wasm32")]
            average_storage_time_seconds: 0.0,
            #[cfg(not(target_arch = "wasm32"))]
            average_storage_time: Duration::from_secs(0),
        }
    }
}

impl ScanResults {
    /// Create new scan results (native version)
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(
        scan_config_summary: ScanConfigSummary,
        wallet_state: WalletState,
        final_progress: ScanProgress,
        start_time: Instant,
    ) -> Self {
        let end_time = Instant::now();
        let total_duration = end_time.duration_since(start_time);

        Self {
            scan_config_summary: scan_config_summary.clone(),
            wallet_state,
            block_results: Vec::new(),
            final_progress: final_progress.clone(),
            start_time,
            end_time,
            completed_successfully: final_progress.is_complete(),
            error_message: None,
            statistics: ScanStatistics {
                total_duration,
                average_scan_rate: final_progress.scan_rate,
                peak_scan_rate: final_progress.scan_rate,
                batches_processed: 0,
                average_batch_time: Duration::from_secs(0),
                total_outputs_found: final_progress.outputs_found,
                total_outputs_spent: final_progress.outputs_spent,
                total_value_found: final_progress.total_value,
                total_value_spent: 0, // Would need to calculate from wallet state
                net_value_change: final_progress.total_value as i64,
                active_addresses: 0, // Would need to calculate from results
                transactions_processed: scan_config_summary.total_blocks_scanned,
                storage_operations: StorageStatistics::default(),
            },
        }
    }

    /// Create new scan results (WASM version with timestamps)
    #[cfg(target_arch = "wasm32")]
    pub fn new(
        scan_config_summary: ScanConfigSummary,
        wallet_state: WalletState,
        final_progress: ScanProgress,
        start_timestamp: f64,
    ) -> Self {
        let end_timestamp = js_sys::Date::now();
        let total_duration_seconds = (end_timestamp - start_timestamp) / 1000.0;

        Self {
            scan_config_summary: scan_config_summary.clone(),
            wallet_state,
            block_results: Vec::new(),
            final_progress: final_progress.clone(),
            start_timestamp,
            end_timestamp,
            completed_successfully: final_progress.is_complete(),
            error_message: None,
            statistics: ScanStatistics {
                total_duration_seconds,
                average_scan_rate: final_progress.scan_rate,
                peak_scan_rate: final_progress.scan_rate,
                batches_processed: 0,
                average_batch_time_seconds: 0.0,
                total_outputs_found: final_progress.outputs_found,
                total_outputs_spent: final_progress.outputs_spent,
                total_value_found: final_progress.total_value,
                total_value_spent: 0, // Would need to calculate from wallet state
                net_value_change: final_progress.total_value as i64,
                active_addresses: 0, // Would need to calculate from results
                transactions_processed: scan_config_summary.total_blocks_scanned,
                storage_operations: StorageStatistics::default(),
            },
        }
    }

    /// Add block scan results
    pub fn add_block_results(&mut self, results: Vec<BlockScanResult>) {
        self.block_results.extend(results);
    }

    /// Set error state
    pub fn set_error(&mut self, error: String) {
        self.completed_successfully = false;
        self.error_message = Some(error.clone());
        self.final_progress.set_phase(ScanPhase::Error(error));
    }

    /// Set interrupted state
    pub fn set_interrupted(&mut self) {
        self.completed_successfully = false;
        self.final_progress.set_phase(ScanPhase::Interrupted);
    }

    /// Get scan duration (native version)
    #[cfg(not(target_arch = "wasm32"))]
    pub fn duration(&self) -> Duration {
        self.statistics.total_duration
    }

    /// Get scan duration in seconds (WASM version)
    #[cfg(target_arch = "wasm32")]
    pub fn duration_seconds(&self) -> f64 {
        self.statistics.total_duration_seconds
    }

    /// Get summary statistics (native version)
    #[cfg(not(target_arch = "wasm32"))]
    pub fn summary(&self) -> ScanResultSummary {
        ScanResultSummary {
            blocks_scanned: self.scan_config_summary.total_blocks_scanned,
            outputs_found: self.statistics.total_outputs_found,
            outputs_spent: self.statistics.total_outputs_spent,
            total_value_found: self.statistics.total_value_found,
            net_value_change: self.statistics.net_value_change,
            scan_duration: self.statistics.total_duration,
            average_scan_rate: self.statistics.average_scan_rate,
            completed_successfully: self.completed_successfully,
            error_message: self.error_message.clone(),
        }
    }

    /// Get summary statistics (WASM version)
    #[cfg(target_arch = "wasm32")]
    pub fn summary(&self) -> ScanResultSummary {
        ScanResultSummary {
            blocks_scanned: self.scan_config_summary.total_blocks_scanned,
            outputs_found: self.statistics.total_outputs_found,
            outputs_spent: self.statistics.total_outputs_spent,
            total_value_found: self.statistics.total_value_found,
            net_value_change: self.statistics.net_value_change,
            scan_duration_seconds: self.statistics.total_duration_seconds,
            average_scan_rate: self.statistics.average_scan_rate,
            completed_successfully: self.completed_successfully,
            error_message: self.error_message.clone(),
        }
    }

    /// Export summary to JSON (since full serialization is complex due to Instant fields)
    pub fn summary_to_json(&self) -> LightweightWalletResult<String> {
        serde_json::to_string_pretty(&self.summary()).map_err(|e| {
            LightweightWalletError::ConfigurationError(format!(
                "Failed to serialize scan result summary: {}",
                e
            ))
        })
    }
}

/// Simplified summary of scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultSummary {
    /// Number of blocks scanned
    pub blocks_scanned: u64,
    /// Number of outputs found
    pub outputs_found: u64,
    /// Number of outputs spent
    pub outputs_spent: u64,
    /// Total value found (in MicroMinotari)
    pub total_value_found: u64,
    /// Net value change (found - spent)
    pub net_value_change: i64,
    /// Scan duration (seconds for WASM compatibility)
    #[cfg(target_arch = "wasm32")]
    pub scan_duration_seconds: f64,
    #[cfg(not(target_arch = "wasm32"))]
    pub scan_duration: Duration,
    /// Average scan rate (blocks per second)
    pub average_scan_rate: f64,
    /// Whether scan completed successfully
    pub completed_successfully: bool,
    /// Error message if failed
    pub error_message: Option<String>,
}

/// Result of a block scan operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockScanResult {
    /// Block height
    pub height: u64,
    /// Block hash
    pub block_hash: Vec<u8>,
    /// Transaction outputs found in this block
    pub outputs: Vec<LightweightTransactionOutput>,
    /// Wallet outputs extracted from transaction outputs
    pub wallet_outputs: Vec<LightweightWalletOutput>,
    /// Timestamp when block was mined
    pub mined_timestamp: u64,
    /// Number of transactions in this block
    pub transaction_count: usize,
    /// Time taken to process this block (seconds for WASM compatibility)
    #[cfg(target_arch = "wasm32")]
    pub processing_time_seconds: Option<f64>,
    #[cfg(not(target_arch = "wasm32"))]
    pub processing_time: Option<Duration>,
    /// Any errors encountered processing this block
    pub errors: Vec<String>,
}

impl BlockScanResult {
    /// Create a new block scan result
    pub fn new(height: u64, block_hash: Vec<u8>, mined_timestamp: u64) -> Self {
        Self {
            height,
            block_hash,
            outputs: Vec::new(),
            wallet_outputs: Vec::new(),
            mined_timestamp,
            transaction_count: 0,
            #[cfg(target_arch = "wasm32")]
            processing_time_seconds: None,
            #[cfg(not(target_arch = "wasm32"))]
            processing_time: None,
            errors: Vec::new(),
        }
    }

    /// Add wallet outputs to the result
    pub fn add_wallet_outputs(&mut self, outputs: Vec<LightweightWalletOutput>) {
        self.wallet_outputs.extend(outputs);
    }

    /// Add transaction outputs to the result
    pub fn add_transaction_outputs(&mut self, outputs: Vec<LightweightTransactionOutput>) {
        self.outputs.extend(outputs);
    }

    /// Set processing time (native version)
    #[cfg(not(target_arch = "wasm32"))]
    pub fn set_processing_time(&mut self, duration: Duration) {
        self.processing_time = Some(duration);
    }

    /// Set processing time in seconds (WASM version)
    #[cfg(target_arch = "wasm32")]
    pub fn set_processing_time_seconds(&mut self, seconds: f64) {
        self.processing_time_seconds = Some(seconds);
    }

    /// Add an error
    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
    }

    /// Get total value of wallet outputs in this block
    pub fn total_value(&self) -> u64 {
        self.wallet_outputs
            .iter()
            .map(|wo| wo.value().as_u64())
            .sum()
    }

    /// Check if this block has any wallet outputs
    pub fn has_wallet_outputs(&self) -> bool {
        !self.wallet_outputs.is_empty()
    }
}

/// Progress callback type for scan operations
pub type ProgressCallback = Box<dyn Fn(&ScanProgress) + Send + Sync>;

/// Batch scan result for efficient processing
#[derive(Debug, Clone)]
pub struct BatchScanResult {
    /// Batch index
    pub batch_index: usize,
    /// Block heights in this batch
    pub block_heights: Vec<u64>,
    /// Individual block results
    pub block_results: Vec<BlockScanResult>,
    /// Batch processing time (seconds for WASM compatibility)
    #[cfg(target_arch = "wasm32")]
    pub processing_time_seconds: f64,
    #[cfg(not(target_arch = "wasm32"))]
    pub processing_time: Duration,
    /// Total outputs found in this batch
    pub outputs_found: u64,
    /// Total value found in this batch
    pub total_value: u64,
    /// Any batch-level errors
    pub errors: Vec<String>,
}

impl BatchScanResult {
    /// Create a new batch scan result
    pub fn new(batch_index: usize, block_heights: Vec<u64>) -> Self {
        Self {
            batch_index,
            block_heights,
            block_results: Vec::new(),
            #[cfg(target_arch = "wasm32")]
            processing_time_seconds: 0.0,
            #[cfg(not(target_arch = "wasm32"))]
            processing_time: Duration::from_secs(0),
            outputs_found: 0,
            total_value: 0,
            errors: Vec::new(),
        }
    }

    /// Add block results to the batch
    pub fn add_block_results(&mut self, mut results: Vec<BlockScanResult>) {
        // Update batch totals
        for result in &results {
            self.outputs_found += result.wallet_outputs.len() as u64;
            self.total_value += result.total_value();
        }
        self.block_results.append(&mut results);
    }

    /// Set batch processing time (native version)
    #[cfg(not(target_arch = "wasm32"))]
    pub fn set_processing_time(&mut self, duration: Duration) {
        self.processing_time = duration;
    }

    /// Set batch processing time in seconds (WASM version)
    #[cfg(target_arch = "wasm32")]
    pub fn set_processing_time_seconds(&mut self, seconds: f64) {
        self.processing_time_seconds = seconds;
    }

    /// Add a batch-level error
    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
    }
}

/// Helper function to format Tari amounts for display
fn format_tari_amount(micro_minotari: u64) -> String {
    let tari = micro_minotari as f64 / 1_000_000.0;
    format!("{:.6}", tari)
}

/// Helper function to create scan result summary from wallet state (native version)
#[cfg(not(target_arch = "wasm32"))]
pub fn create_scan_result_summary(
    wallet_state: &WalletState,
    start_height: u64,
    end_height: Option<u64>,
    duration: Duration,
) -> ScanResultSummary {
    let (total_received, total_spent, _, unspent_count, spent_count) = wallet_state.get_summary();
    let blocks_scanned = end_height.map(|end| end - start_height + 1).unwrap_or(0);

    ScanResultSummary {
        blocks_scanned,
        outputs_found: unspent_count as u64,
        outputs_spent: spent_count as u64,
        total_value_found: total_received,
        net_value_change: total_received as i64 - total_spent as i64,
        scan_duration: duration,
        average_scan_rate: if duration.as_secs_f64() > 0.0 {
            blocks_scanned as f64 / duration.as_secs_f64()
        } else {
            0.0
        },
        completed_successfully: true,
        error_message: None,
    }
}

/// Helper function to create scan result summary from wallet state (WASM version)
#[cfg(target_arch = "wasm32")]
pub fn create_scan_result_summary_wasm(
    wallet_state: &WalletState,
    start_height: u64,
    end_height: Option<u64>,
    duration_seconds: f64,
) -> ScanResultSummary {
    let (total_received, total_spent, _, unspent_count, spent_count) = wallet_state.get_summary();
    let blocks_scanned = end_height.map(|end| end - start_height + 1).unwrap_or(0);

    ScanResultSummary {
        blocks_scanned,
        outputs_found: unspent_count as u64,
        outputs_spent: spent_count as u64,
        total_value_found: total_received,
        net_value_change: total_received as i64 - total_spent as i64,
        scan_duration_seconds: duration_seconds,
        average_scan_rate: if duration_seconds > 0.0 {
            blocks_scanned as f64 / duration_seconds
        } else {
            0.0
        },
        completed_successfully: true,
        error_message: None,
    }
}

// Helper modules for Duration serialization (native only)
#[cfg(not(target_arch = "wasm32"))]
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod duration_option_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(d) => Some(d.as_secs()).serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs_opt: Option<u64> = Option::deserialize(deserializer)?;
        Ok(secs_opt.map(Duration::from_secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_structures::wallet_transaction::WalletState;
    #[cfg(not(target_arch = "wasm32"))]
    use std::time::{Duration, Instant};

    #[test]
    fn test_scan_phase_default() {
        let phase = ScanPhase::default();
        assert!(matches!(phase, ScanPhase::Initializing));
    }

    #[test]
    fn test_scan_phase_debug() {
        let phase = ScanPhase::Scanning {
            batch_index: 5,
            total_batches: Some(10),
        };
        let debug_str = format!("{:?}", phase);
        assert!(debug_str.contains("Scanning"));
        assert!(debug_str.contains("5"));
        assert!(debug_str.contains("10"));
    }

    #[test]
    fn test_scan_progress_new() {
        let progress = ScanProgress::new(1000, Some(2000));
        assert_eq!(progress.current_height, 1000);
        assert_eq!(progress.target_height, Some(2000));
        assert_eq!(progress.blocks_scanned, 0);
        assert_eq!(progress.total_blocks, Some(1001)); // 2000 - 1000 + 1
        assert_eq!(progress.outputs_found, 0);
        assert_eq!(progress.outputs_spent, 0);
        assert_eq!(progress.total_value, 0);
        assert_eq!(progress.scan_rate, 0.0);
        assert!(matches!(progress.phase, ScanPhase::Initializing));
    }

    #[test]
    fn test_scan_progress_new_open_ended() {
        let progress = ScanProgress::new(1000, None);
        assert_eq!(progress.current_height, 1000);
        assert_eq!(progress.target_height, None);
        assert_eq!(progress.total_blocks, None);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_scan_progress_update() {
        let mut progress = ScanProgress::new(1000, Some(2000));
        let elapsed = Duration::from_secs(10);

        progress.update(1500, 500, 25, 5, 1000000, elapsed);

        assert_eq!(progress.current_height, 1500);
        assert_eq!(progress.blocks_scanned, 500);
        assert_eq!(progress.outputs_found, 25);
        assert_eq!(progress.outputs_spent, 5);
        assert_eq!(progress.total_value, 1000000);
        assert_eq!(progress.elapsed, elapsed);

        // Scan rate should be calculated: 500 blocks / 10 seconds = 50 blocks/sec
        assert_eq!(progress.scan_rate, 50.0);

        // Estimated remaining should be calculated: 501 remaining blocks / 50 blocks/sec = ~10 seconds
        assert!(progress.estimated_remaining.is_some());
        let remaining = progress.estimated_remaining.unwrap();
        assert!((remaining.as_secs_f64() - 10.02).abs() < 0.1); // 501/50 = 10.02
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_scan_progress_update_wasm() {
        let mut progress = ScanProgress::new(1000, Some(2000));
        let elapsed_seconds = 10.0;

        progress.update_wasm(1500, 500, 25, 5, 1000000, elapsed_seconds);

        assert_eq!(progress.current_height, 1500);
        assert_eq!(progress.blocks_scanned, 500);
        assert_eq!(progress.outputs_found, 25);
        assert_eq!(progress.outputs_spent, 5);
        assert_eq!(progress.total_value, 1000000);
        assert_eq!(progress.elapsed_seconds, elapsed_seconds);

        // Scan rate should be calculated: 500 blocks / 10 seconds = 50 blocks/sec
        assert_eq!(progress.scan_rate, 50.0);

        // Estimated remaining should be calculated
        assert!(progress.estimated_remaining_seconds.is_some());
        let remaining = progress.estimated_remaining_seconds.unwrap();
        assert!((remaining - 10.02).abs() < 0.1); // 501/50 = 10.02
    }

    #[test]
    fn test_scan_progress_set_phase() {
        let mut progress = ScanProgress::new(1000, Some(2000));
        progress.set_phase(ScanPhase::Scanning {
            batch_index: 1,
            total_batches: Some(5),
        });

        assert!(matches!(
            progress.phase,
            ScanPhase::Scanning {
                batch_index: 1,
                total_batches: Some(5)
            }
        ));
    }

    #[test]
    fn test_scan_progress_completion_percentage() {
        let mut progress = ScanProgress::new(1000, Some(2000));

        // Initially 0%
        assert_eq!(progress.completion_percentage(), 0.0);

        // Update to 50% completion (500 out of 1001 blocks)
        progress.blocks_scanned = 500;
        let percentage = progress.completion_percentage();
        assert!((percentage - 49.95).abs() < 0.1); // 500/1001 ≈ 49.95%

        // Update to 100% completion
        progress.blocks_scanned = 1001;
        assert!((progress.completion_percentage() - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_scan_progress_completion_percentage_open_ended() {
        let progress = ScanProgress::new(1000, None);
        assert_eq!(progress.completion_percentage(), 0.0);
    }

    #[test]
    fn test_scan_progress_status_checks() {
        let mut progress = ScanProgress::new(1000, Some(2000));

        // Initially not complete, not interrupted, no error
        assert!(!progress.is_complete());
        assert!(!progress.is_interrupted());
        assert!(!progress.has_error());

        // Set to completed
        progress.set_phase(ScanPhase::Completed);
        assert!(progress.is_complete());
        assert!(!progress.is_interrupted());
        assert!(!progress.has_error());

        // Set to interrupted
        progress.set_phase(ScanPhase::Interrupted);
        assert!(!progress.is_complete());
        assert!(progress.is_interrupted());
        assert!(!progress.has_error());

        // Set to error
        progress.set_phase(ScanPhase::Error("Test error".to_string()));
        assert!(!progress.is_complete());
        assert!(!progress.is_interrupted());
        assert!(progress.has_error());
    }

    #[test]
    fn test_scan_progress_format_progress_bar() {
        let mut progress = ScanProgress::new(1000, Some(2000));
        progress.blocks_scanned = 500; // 50% completion
        progress.current_height = 1500;
        progress.outputs_found = 25;
        progress.total_value = 1000000;
        progress.set_phase(ScanPhase::Scanning {
            batch_index: 1,
            total_batches: Some(5),
        });

        let bar = progress.format_progress_bar(20);

        // Should contain progress bar elements
        assert!(bar.contains('['));
        assert!(bar.contains(']'));
        assert!(bar.contains("█")); // Filled portion
        assert!(bar.contains("░")); // Empty portion
                                    // Check for percentage - it's 500/1001 = 49.95%, so check for "49." or "50."
        assert!(bar.contains("49.") || bar.contains("50."));
        assert!(bar.contains("Scanning"));
        assert!(bar.contains("1,500")); // Current height formatted
        assert!(bar.contains("25")); // Outputs found
    }

    #[test]
    fn test_scan_progress_summary() {
        let mut progress = ScanProgress::new(1000, Some(2000));
        progress.current_height = 1500;
        progress.outputs_found = 25;
        progress.outputs_spent = 5;
        progress.scan_rate = 50.0;

        let summary = progress.summary();

        assert!(summary.contains("1,500"));
        assert!(summary.contains("25"));
        assert!(summary.contains("5"));
        assert!(summary.contains("50.00"));
    }

    #[test]
    fn test_scan_config_summary() {
        let summary = ScanConfigSummary {
            start_height: 1000,
            end_height: Some(2000),
            specific_blocks: None,
            batch_size: 100,
            total_blocks_scanned: 1001,
        };

        assert_eq!(summary.start_height, 1000);
        assert_eq!(summary.end_height, Some(2000));
        assert_eq!(summary.batch_size, 100);
        assert_eq!(summary.total_blocks_scanned, 1001);
    }

    #[test]
    fn test_storage_statistics_default() {
        let stats = StorageStatistics::default();
        assert_eq!(stats.outputs_saved, 0);
        assert_eq!(stats.transactions_saved, 0);
        assert_eq!(stats.spent_updates, 0);

        #[cfg(not(target_arch = "wasm32"))]
        assert_eq!(stats.total_storage_time, Duration::from_secs(0));
        #[cfg(target_arch = "wasm32")]
        assert_eq!(stats.total_storage_time_seconds, 0.0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_scan_results_new_native() {
        let scan_config = ScanConfigSummary {
            start_height: 1000,
            end_height: Some(2000),
            specific_blocks: None,
            batch_size: 100,
            total_blocks_scanned: 1001,
        };
        let wallet_state = WalletState::new();
        let mut progress = ScanProgress::new(1000, Some(2000));
        progress.set_phase(ScanPhase::Completed);
        progress.outputs_found = 25;
        progress.total_value = 1000000;
        progress.scan_rate = 50.0;

        let start_time = Instant::now();
        let results = ScanResults::new(scan_config, wallet_state, progress, start_time);

        assert!(results.completed_successfully);
        assert!(results.error_message.is_none());
        assert_eq!(results.statistics.total_outputs_found, 25);
        assert_eq!(results.statistics.total_value_found, 1000000);
        assert_eq!(results.statistics.average_scan_rate, 50.0);
        assert_eq!(results.statistics.transactions_processed, 1001);
    }

    #[test]
    fn test_scan_results_add_block_results() {
        let scan_config = ScanConfigSummary {
            start_height: 1000,
            end_height: Some(2000),
            specific_blocks: None,
            batch_size: 100,
            total_blocks_scanned: 1001,
        };
        let wallet_state = WalletState::new();
        let progress = ScanProgress::new(1000, Some(2000));

        #[cfg(not(target_arch = "wasm32"))]
        let mut results = ScanResults::new(scan_config, wallet_state, progress, Instant::now());
        #[cfg(target_arch = "wasm32")]
        let mut results = ScanResults::new(scan_config, wallet_state, progress, 0.0);

        let block_result = BlockScanResult::new(1000, vec![1, 2, 3, 4], 1234567890);
        results.add_block_results(vec![block_result]);

        assert_eq!(results.block_results.len(), 1);
        assert_eq!(results.block_results[0].height, 1000);
    }

    #[test]
    fn test_scan_results_set_error() {
        let scan_config = ScanConfigSummary {
            start_height: 1000,
            end_height: Some(2000),
            specific_blocks: None,
            batch_size: 100,
            total_blocks_scanned: 1001,
        };
        let wallet_state = WalletState::new();
        let progress = ScanProgress::new(1000, Some(2000));

        #[cfg(not(target_arch = "wasm32"))]
        let mut results = ScanResults::new(scan_config, wallet_state, progress, Instant::now());
        #[cfg(target_arch = "wasm32")]
        let mut results = ScanResults::new(scan_config, wallet_state, progress, 0.0);

        results.set_error("Test error".to_string());

        assert!(!results.completed_successfully);
        assert_eq!(results.error_message, Some("Test error".to_string()));
        assert!(results.final_progress.has_error());
    }

    #[test]
    fn test_scan_results_set_interrupted() {
        let scan_config = ScanConfigSummary {
            start_height: 1000,
            end_height: Some(2000),
            specific_blocks: None,
            batch_size: 100,
            total_blocks_scanned: 1001,
        };
        let wallet_state = WalletState::new();
        let progress = ScanProgress::new(1000, Some(2000));

        #[cfg(not(target_arch = "wasm32"))]
        let mut results = ScanResults::new(scan_config, wallet_state, progress, Instant::now());
        #[cfg(target_arch = "wasm32")]
        let mut results = ScanResults::new(scan_config, wallet_state, progress, 0.0);

        results.set_interrupted();

        assert!(!results.completed_successfully);
        assert!(results.final_progress.is_interrupted());
    }

    #[test]
    fn test_scan_results_summary_to_json() {
        let scan_config = ScanConfigSummary {
            start_height: 1000,
            end_height: Some(2000),
            specific_blocks: None,
            batch_size: 100,
            total_blocks_scanned: 1001,
        };
        let wallet_state = WalletState::new();
        let progress = ScanProgress::new(1000, Some(2000));

        #[cfg(not(target_arch = "wasm32"))]
        let results = ScanResults::new(scan_config, wallet_state, progress, Instant::now());
        #[cfg(target_arch = "wasm32")]
        let results = ScanResults::new(scan_config, wallet_state, progress, 0.0);

        let json_result = results.summary_to_json();
        assert!(json_result.is_ok());

        let json = json_result.unwrap();
        assert!(json.contains("blocks_scanned"));
        assert!(json.contains("completed_successfully"));
    }

    #[test]
    fn test_block_scan_result_new() {
        let result = BlockScanResult::new(1000, vec![1, 2, 3, 4], 1234567890);

        assert_eq!(result.height, 1000);
        assert_eq!(result.block_hash, vec![1, 2, 3, 4]);
        assert_eq!(result.mined_timestamp, 1234567890);
        assert_eq!(result.transaction_count, 0);
        assert!(result.outputs.is_empty());
        assert!(result.wallet_outputs.is_empty());
        assert!(result.errors.is_empty());

        #[cfg(not(target_arch = "wasm32"))]
        assert!(result.processing_time.is_none());
        #[cfg(target_arch = "wasm32")]
        assert!(result.processing_time_seconds.is_none());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_block_scan_result_set_processing_time() {
        let mut result = BlockScanResult::new(1000, vec![1, 2, 3, 4], 1234567890);
        let processing_time = Duration::from_millis(500);

        result.set_processing_time(processing_time);
        assert_eq!(result.processing_time, Some(processing_time));
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_block_scan_result_set_processing_time_seconds() {
        let mut result = BlockScanResult::new(1000, vec![1, 2, 3, 4], 1234567890);

        result.set_processing_time_seconds(0.5);
        assert_eq!(result.processing_time_seconds, Some(0.5));
    }

    #[test]
    fn test_block_scan_result_add_error() {
        let mut result = BlockScanResult::new(1000, vec![1, 2, 3, 4], 1234567890);

        result.add_error("Test error 1".to_string());
        result.add_error("Test error 2".to_string());

        assert_eq!(result.errors.len(), 2);
        assert_eq!(result.errors[0], "Test error 1");
        assert_eq!(result.errors[1], "Test error 2");
    }

    #[test]
    fn test_block_scan_result_has_wallet_outputs() {
        let mut result = BlockScanResult::new(1000, vec![1, 2, 3, 4], 1234567890);
        assert!(!result.has_wallet_outputs());

        // Note: LightweightWalletOutput creation requires complex setup,
        // so we'll test the basic structure
        result.wallet_outputs = vec![];
        assert!(!result.has_wallet_outputs());
    }

    #[test]
    fn test_batch_scan_result_new() {
        let block_heights = vec![1000, 1001, 1002];
        let batch = BatchScanResult::new(0, block_heights.clone());

        assert_eq!(batch.batch_index, 0);
        assert_eq!(batch.block_heights, block_heights);
        assert!(batch.block_results.is_empty());
        assert_eq!(batch.outputs_found, 0);
        assert_eq!(batch.total_value, 0);
        assert!(batch.errors.is_empty());

        #[cfg(not(target_arch = "wasm32"))]
        assert_eq!(batch.processing_time, Duration::from_secs(0));
        #[cfg(target_arch = "wasm32")]
        assert_eq!(batch.processing_time_seconds, 0.0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_batch_scan_result_set_processing_time() {
        let mut batch = BatchScanResult::new(0, vec![1000, 1001, 1002]);
        let processing_time = Duration::from_secs(5);

        batch.set_processing_time(processing_time);
        assert_eq!(batch.processing_time, processing_time);
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_batch_scan_result_set_processing_time_seconds() {
        let mut batch = BatchScanResult::new(0, vec![1000, 1001, 1002]);

        batch.set_processing_time_seconds(5.0);
        assert_eq!(batch.processing_time_seconds, 5.0);
    }

    #[test]
    fn test_batch_scan_result_add_error() {
        let mut batch = BatchScanResult::new(0, vec![1000, 1001, 1002]);

        batch.add_error("Batch error".to_string());

        assert_eq!(batch.errors.len(), 1);
        assert_eq!(batch.errors[0], "Batch error");
    }

    #[test]
    fn test_batch_scan_result_add_block_results() {
        let mut batch = BatchScanResult::new(0, vec![1000, 1001, 1002]);

        let mut block_result1 = BlockScanResult::new(1000, vec![1, 2, 3, 4], 1234567890);
        let mut block_result2 = BlockScanResult::new(1001, vec![5, 6, 7, 8], 1234567891);

        // Simulate some outputs (we can't easily create LightweightWalletOutput, so we'll verify the count)
        block_result1.wallet_outputs = vec![]; // Would contain actual outputs
        block_result2.wallet_outputs = vec![]; // Would contain actual outputs

        let results = vec![block_result1, block_result2];
        batch.add_block_results(results);

        assert_eq!(batch.block_results.len(), 2);
        assert_eq!(batch.block_results[0].height, 1000);
        assert_eq!(batch.block_results[1].height, 1001);
    }

    #[test]
    fn test_format_tari_amount() {
        assert_eq!(format_tari_amount(0), "0.000000");
        assert_eq!(format_tari_amount(1_000_000), "1.000000"); // 1 Tari
        assert_eq!(format_tari_amount(1_500_000), "1.500000"); // 1.5 Tari
        assert_eq!(format_tari_amount(123_456_789), "123.456789");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_create_scan_result_summary() {
        let wallet_state = WalletState::new();
        let start_height = 1000;
        let end_height = Some(2000);
        let duration = Duration::from_secs(60);

        let summary = create_scan_result_summary(&wallet_state, start_height, end_height, duration);

        assert_eq!(summary.blocks_scanned, 1001); // 2000 - 1000 + 1
        assert_eq!(summary.scan_duration, duration);
        assert!((summary.average_scan_rate - 16.683333333333334).abs() < 0.1); // 1001 blocks / 60 seconds
        assert!(summary.completed_successfully);
        assert!(summary.error_message.is_none());
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_create_scan_result_summary_wasm() {
        let wallet_state = WalletState::new();
        let start_height = 1000;
        let end_height = Some(2000);
        let duration_seconds = 60.0;

        let summary = create_scan_result_summary_wasm(
            &wallet_state,
            start_height,
            end_height,
            duration_seconds,
        );

        assert_eq!(summary.blocks_scanned, 1001); // 2000 - 1000 + 1
        assert_eq!(summary.scan_duration_seconds, duration_seconds);
        assert!((summary.average_scan_rate - 16.683333333333334).abs() < 0.1); // 1001 blocks / 60 seconds
        assert!(summary.completed_successfully);
        assert!(summary.error_message.is_none());
    }

    #[test]
    fn test_scan_progress_edge_cases() {
        // Test with zero elapsed time
        let mut progress = ScanProgress::new(1000, Some(2000));

        #[cfg(not(target_arch = "wasm32"))]
        progress.update(1100, 100, 10, 2, 500000, Duration::from_secs(0));
        #[cfg(target_arch = "wasm32")]
        progress.update_wasm(1100, 100, 10, 2, 500000, 0.0);

        assert_eq!(progress.scan_rate, 0.0); // Should not divide by zero

        #[cfg(not(target_arch = "wasm32"))]
        assert!(progress.estimated_remaining.is_none());
        #[cfg(target_arch = "wasm32")]
        assert!(progress.estimated_remaining_seconds.is_none());
    }

    #[test]
    fn test_scan_progress_no_remaining_blocks() {
        let mut progress = ScanProgress::new(1000, Some(2000));

        // Set blocks_scanned equal to total_blocks
        #[cfg(not(target_arch = "wasm32"))]
        progress.update(2000, 1001, 25, 5, 1000000, Duration::from_secs(10));
        #[cfg(target_arch = "wasm32")]
        progress.update_wasm(2000, 1001, 25, 5, 1000000, 10.0);

        // Should not calculate remaining time when no blocks remain
        #[cfg(not(target_arch = "wasm32"))]
        assert!(progress.estimated_remaining.is_none());
        #[cfg(target_arch = "wasm32")]
        assert!(progress.estimated_remaining_seconds.is_none());
    }

    #[test]
    fn test_scan_progress_serialization() {
        let progress = ScanProgress::new(1000, Some(2000));

        // Test that progress can be serialized/deserialized
        let json = serde_json::to_string(&progress).expect("Failed to serialize progress");
        let deserialized: ScanProgress =
            serde_json::from_str(&json).expect("Failed to deserialize progress");

        assert_eq!(deserialized.current_height, 1000);
        assert_eq!(deserialized.target_height, Some(2000));
        assert_eq!(deserialized.total_blocks, Some(1001));
    }

    #[test]
    fn test_scan_result_summary_serialization() {
        let summary = ScanResultSummary {
            blocks_scanned: 1001,
            outputs_found: 25,
            outputs_spent: 5,
            total_value_found: 1000000,
            net_value_change: 950000,
            #[cfg(not(target_arch = "wasm32"))]
            scan_duration: Duration::from_secs(60),
            #[cfg(target_arch = "wasm32")]
            scan_duration_seconds: 60.0,
            average_scan_rate: 16.68,
            completed_successfully: true,
            error_message: None,
        };

        let json = serde_json::to_string(&summary).expect("Failed to serialize summary");
        let deserialized: ScanResultSummary =
            serde_json::from_str(&json).expect("Failed to deserialize summary");

        assert_eq!(deserialized.blocks_scanned, 1001);
        assert_eq!(deserialized.outputs_found, 25);
        assert!(deserialized.completed_successfully);
    }
}
