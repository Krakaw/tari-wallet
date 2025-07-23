//! Progress reporting for scanner operations
//!
//! This module provides progress reporting functionality that can be used
//! by the scanner engine to report scanning progress in various formats.

use super::scan_results::ScanProgress;
use crate::common::format_number;
use crate::data_structures::wallet_transaction::WalletState;
use std::io::{self, Write};
use std::sync::Arc;
// use std::time::Instant; // Commented out as it's not used yet

/// Configuration for progress reporting
#[derive(Debug, Clone)]
pub struct ProgressReportConfig {
    /// Whether to show progress updates
    pub enabled: bool,
    /// Frequency of progress updates (every N blocks)
    pub update_frequency: usize,
    /// Whether to use colored output
    pub use_colors: bool,
    /// Maximum width of progress bars
    pub progress_bar_width: usize,
    /// Whether to show detailed wallet information in progress
    pub show_wallet_details: bool,
    /// Whether to show ETA estimates
    pub show_eta: bool,
}

impl Default for ProgressReportConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            update_frequency: 10,
            use_colors: true,
            progress_bar_width: 40,
            show_wallet_details: true,
            show_eta: true,
        }
    }
}

/// Different types of progress reports
#[derive(Debug, Clone)]
pub enum ProgressReportType {
    /// Scanning initialization
    Initializing,
    /// Connecting to blockchain
    Connecting,
    /// Actively scanning blocks
    Scanning {
        batch_index: usize,
        total_batches: Option<usize>,
    },
    /// Processing results
    Processing,
    /// Scan completed
    Completed,
    /// Scan was interrupted
    Interrupted,
}

/// Progress information for reporting
#[derive(Debug, Clone)]
pub struct ProgressInfo {
    /// Current block height being processed
    pub current_height: u64,
    /// Target/end block height
    pub target_height: Option<u64>,
    /// Number of outputs found so far
    pub outputs_found: u64,
    /// Number of outputs spent so far
    pub outputs_spent: u64,
    /// Total value found (in microTari)
    pub total_value: u64,
    /// Number of blocks scanned so far
    pub blocks_scanned: u64,
    /// Total blocks to scan
    pub total_blocks: Option<u64>,
    /// Elapsed time since start
    pub elapsed: std::time::Duration,
    /// Estimated remaining time
    pub estimated_remaining: Option<std::time::Duration>,
    /// Current scan rate (blocks per second)
    pub scan_rate: f64,
    /// Type of progress report
    pub report_type: ProgressReportType,
    /// Optional wallet state for detailed reporting
    pub wallet_state: Option<Arc<WalletState>>,
}

impl From<ScanProgress> for ProgressInfo {
    fn from(progress: ScanProgress) -> Self {
        let report_type = match progress.phase {
            super::scan_results::ScanPhase::Initializing => ProgressReportType::Initializing,
            super::scan_results::ScanPhase::Connecting => ProgressReportType::Connecting,
            super::scan_results::ScanPhase::Scanning {
                batch_index,
                total_batches,
            } => ProgressReportType::Scanning {
                batch_index,
                total_batches,
            },
            super::scan_results::ScanPhase::Processing => ProgressReportType::Processing,
            super::scan_results::ScanPhase::Completed => ProgressReportType::Completed,
            super::scan_results::ScanPhase::Saving => ProgressReportType::Processing,
            super::scan_results::ScanPhase::Finalizing => ProgressReportType::Completed,
            super::scan_results::ScanPhase::Interrupted => ProgressReportType::Interrupted,
            super::scan_results::ScanPhase::Error(_) => ProgressReportType::Interrupted,
        };

        Self {
            current_height: progress.current_height,
            target_height: progress.target_height,
            outputs_found: progress.outputs_found,
            outputs_spent: progress.outputs_spent,
            total_value: progress.total_value,
            blocks_scanned: progress.blocks_scanned,
            total_blocks: progress.total_blocks,
            elapsed: progress.elapsed,
            estimated_remaining: progress.estimated_remaining,
            scan_rate: progress.scan_rate,
            report_type,
            wallet_state: None,
        }
    }
}

/// Progress reporter trait for different output formats
pub trait ProgressReporter: Send + Sync {
    /// Report scan initialization
    fn report_initialization(&self, config: &ProgressReportConfig);

    /// Report connection status
    fn report_connection(&self, message: &str, config: &ProgressReportConfig);

    /// Report scanning progress
    fn report_progress(&self, progress: &ProgressInfo, config: &ProgressReportConfig);

    /// Report scan completion
    fn report_completion(&self, progress: &ProgressInfo, config: &ProgressReportConfig);

    /// Report scan interruption
    fn report_interruption(&self, progress: &ProgressInfo, config: &ProgressReportConfig);

    /// Report error during scanning
    fn report_error(&self, error: &str, block_height: Option<u64>, config: &ProgressReportConfig);

    /// Flush any pending output
    fn flush(&self) -> io::Result<()>;
}

/// Console-based progress reporter with formatted output
#[derive(Debug, Default)]
pub struct ConsoleProgressReporter;

impl ConsoleProgressReporter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a progress bar string
    fn create_progress_bar(
        &self,
        current: u64,
        total: Option<u64>,
        width: usize,
        phase: &str,
    ) -> String {
        if let Some(total) = total {
            let progress_percent = if total > 0 {
                (current as f64 / total as f64) * 100.0
            } else {
                100.0
            };

            let filled_width = ((progress_percent / 100.0) * width as f64) as usize;
            let bar = format!(
                "{}{}",
                "█".repeat(filled_width.min(width)),
                "░".repeat(width.saturating_sub(filled_width))
            );

            format!(
                "[{}] {:.1}% {} ({}/{})",
                bar,
                progress_percent,
                phase,
                format_number(current),
                format_number(total)
            )
        } else {
            format!("⏳ {} - Block {}", phase, format_number(current))
        }
    }

    /// Create a detailed progress line with wallet information
    fn create_detailed_progress(
        &self,
        progress: &ProgressInfo,
        config: &ProgressReportConfig,
    ) -> String {
        let phase_str = match &progress.report_type {
            ProgressReportType::Initializing => "Initializing",
            ProgressReportType::Connecting => "Connecting",
            ProgressReportType::Scanning {
                batch_index,
                total_batches,
            } => {
                if let Some(total) = total_batches {
                    &format!("Scanning (Batch {}/{})", batch_index, total)
                } else {
                    "Scanning"
                }
            }
            ProgressReportType::Processing => "Processing",
            ProgressReportType::Completed => "Complete",
            ProgressReportType::Interrupted => "Interrupted",
        };

        let mut progress_line = self.create_progress_bar(
            progress.blocks_scanned,
            progress.total_blocks,
            config.progress_bar_width,
            phase_str,
        );

        if config.show_wallet_details && progress.outputs_found > 0 {
            let balance_t = progress.total_value as f64 / 1_000_000.0;
            progress_line.push_str(&format!(
                " | 💰 {:.6}T | 📊 {} outputs",
                balance_t,
                format_number(progress.outputs_found)
            ));
        }

        if config.show_eta && progress.scan_rate > 0.0 {
            if let Some(eta) = progress.estimated_remaining {
                progress_line.push_str(&format!(" | ETA: {}s", eta.as_secs()));
            }
            progress_line.push_str(&format!(" | {:.1} blocks/s", progress.scan_rate));
        }

        progress_line
    }
}

impl ProgressReporter for ConsoleProgressReporter {
    fn report_initialization(&self, config: &ProgressReportConfig) {
        if config.enabled {
            println!("🚀 Initializing scanner...");
        }
    }

    fn report_connection(&self, message: &str, config: &ProgressReportConfig) {
        if config.enabled {
            println!("🌐 {}", message);
        }
    }

    fn report_progress(&self, progress: &ProgressInfo, config: &ProgressReportConfig) {
        if !config.enabled {
            return;
        }

        match progress.report_type {
            ProgressReportType::Scanning { .. } => {
                // Only show progress updates at the specified frequency
                if progress.blocks_scanned % config.update_frequency as u64 == 0
                    || matches!(progress.report_type, ProgressReportType::Completed)
                {
                    let progress_line = self.create_detailed_progress(progress, config);
                    print!("\r{}", progress_line);
                    let _ = io::stdout().flush();
                }
            }
            ProgressReportType::Processing => {
                println!("\n📊 Processing scan results...");
            }
            ProgressReportType::Initializing => {
                println!("🔄 Preparing to scan...");
            }
            ProgressReportType::Connecting => {
                println!("🔗 Connecting to blockchain...");
            }
            _ => {
                // Other progress types handled by specific methods
            }
        }
    }

    fn report_completion(&self, progress: &ProgressInfo, config: &ProgressReportConfig) {
        if !config.enabled {
            return;
        }

        // Final progress line
        let final_progress = self.create_detailed_progress(progress, config);
        println!("\r{}", final_progress);

        println!("\n✅ Scan completed successfully!");
        if progress.outputs_found > 0 {
            println!(
                "📊 Found {} outputs totaling {:.6} T in {:.2} seconds",
                format_number(progress.outputs_found),
                progress.total_value as f64 / 1_000_000.0,
                progress.elapsed.as_secs_f64()
            );
        }
    }

    fn report_interruption(&self, progress: &ProgressInfo, config: &ProgressReportConfig) {
        if !config.enabled {
            return;
        }

        println!("\n⚠️  Scan was interrupted");
        if progress.outputs_found > 0 {
            println!(
                "📊 Partial results: {} outputs totaling {:.6} T",
                format_number(progress.outputs_found),
                progress.total_value as f64 / 1_000_000.0
            );
        }
    }

    fn report_error(&self, error: &str, block_height: Option<u64>, config: &ProgressReportConfig) {
        if !config.enabled {
            return;
        }

        if let Some(height) = block_height {
            eprintln!("\n❌ Error at block {}: {}", format_number(height), error);
        } else {
            eprintln!("\n❌ Error: {}", error);
        }
    }

    fn flush(&self) -> io::Result<()> {
        io::stdout().flush()
    }
}

/// Quiet progress reporter that only shows essential information
#[derive(Debug, Default)]
pub struct QuietProgressReporter;

impl QuietProgressReporter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ProgressReporter for QuietProgressReporter {
    fn report_initialization(&self, _config: &ProgressReportConfig) {
        // Silent initialization
    }

    fn report_connection(&self, _message: &str, _config: &ProgressReportConfig) {
        // Silent connection
    }

    fn report_progress(&self, _progress: &ProgressInfo, _config: &ProgressReportConfig) {
        // Silent progress updates
    }

    fn report_completion(&self, progress: &ProgressInfo, _config: &ProgressReportConfig) {
        // Only show final summary
        if progress.outputs_found > 0 {
            println!(
                "Scan completed: {} outputs, {:.6} T",
                format_number(progress.outputs_found),
                progress.total_value as f64 / 1_000_000.0
            );
        } else {
            println!("Scan completed: no outputs found");
        }
    }

    fn report_interruption(&self, progress: &ProgressInfo, _config: &ProgressReportConfig) {
        if progress.outputs_found > 0 {
            println!(
                "Scan interrupted: {} outputs, {:.6} T",
                format_number(progress.outputs_found),
                progress.total_value as f64 / 1_000_000.0
            );
        } else {
            println!("Scan interrupted: no outputs found");
        }
    }

    fn report_error(&self, error: &str, block_height: Option<u64>, _config: &ProgressReportConfig) {
        if let Some(height) = block_height {
            eprintln!("Error at block {}: {}", format_number(height), error);
        } else {
            eprintln!("Error: {}", error);
        }
    }

    fn flush(&self) -> io::Result<()> {
        io::stdout().flush()
    }
}

/// Creates a progress reporter based on configuration
pub fn create_progress_reporter(quiet: bool) -> Box<dyn ProgressReporter> {
    if quiet {
        Box::new(QuietProgressReporter::new())
    } else {
        Box::new(ConsoleProgressReporter::new())
    }
}

/// Converts a wallet state to progress info for enhanced reporting
pub fn progress_with_wallet_state(
    mut progress: ProgressInfo,
    wallet_state: &WalletState,
) -> ProgressInfo {
    progress.outputs_found = wallet_state.transactions.len() as u64;
    let (total_received, _, _, _, spent_count) = wallet_state.get_summary();
    progress.total_value = total_received;
    progress.outputs_spent = spent_count as u64;
    progress.wallet_state = Some(Arc::new(wallet_state.clone()));
    progress
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_report_config_default() {
        let config = ProgressReportConfig::default();
        assert!(config.enabled);
        assert_eq!(config.update_frequency, 10);
        assert!(config.use_colors);
        assert_eq!(config.progress_bar_width, 40);
    }

    #[test]
    fn test_progress_info_from_scan_progress() {
        let scan_progress = ScanProgress {
            current_height: 1000,
            target_height: Some(2000),
            outputs_found: 5,
            outputs_spent: 2,
            total_value: 1_000_000,
            blocks_scanned: 500,
            total_blocks: Some(1000),
            elapsed: std::time::Duration::from_secs(60),
            estimated_remaining: Some(std::time::Duration::from_secs(60)),
            scan_rate: 8.33,
            phase: super::scan_results::ScanPhase::Scanning {
                batch_index: 5,
                total_batches: Some(10),
            },
        };

        let progress_info = ProgressInfo::from(scan_progress);
        assert_eq!(progress_info.current_height, 1000);
        assert_eq!(progress_info.outputs_found, 5);
        assert!(matches!(
            progress_info.report_type,
            ProgressReportType::Scanning {
                batch_index: 5,
                total_batches: Some(10)
            }
        ));
    }

    #[test]
    fn test_console_progress_reporter_creation() {
        let reporter = ConsoleProgressReporter::new();
        // Should not panic and should be created successfully
        assert!(std::mem::size_of_val(&reporter) > 0);
    }

    #[test]
    fn test_create_progress_reporter() {
        let quiet_reporter = create_progress_reporter(true);
        let console_reporter = create_progress_reporter(false);

        // Both should be created successfully
        assert!(std::mem::size_of_val(&*quiet_reporter) > 0);
        assert!(std::mem::size_of_val(&*console_reporter) > 0);
    }
}
