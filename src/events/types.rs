//! Event type definitions and data structures for wallet scanning operations

use std::collections::HashMap;

/// Configuration data for scanning operations
#[derive(Debug, Clone, Default)]
pub struct ScanConfig {
    pub batch_size: Option<usize>,
    pub timeout_seconds: Option<u64>,
    pub retry_attempts: Option<u32>,
}

/// Core event types emitted during wallet scanning operations
#[derive(Debug, Clone)]
pub enum WalletScanEvent {
    /// Emitted when a scan operation begins
    ScanStarted {
        config: ScanConfig,
        block_range: (u64, u64),
        wallet_context: String,
    },
    /// Emitted when a block is processed
    BlockProcessed {
        height: u64,
        hash: String,
        timestamp: u64,
        processing_duration_ms: u64,
        outputs_count: usize,
    },
    /// Emitted when an output is found for the wallet
    OutputFound {
        output_data: String, // Placeholder for now
        block_height: u64,
        address_info: String,
    },
    /// Emitted periodically to report scan progress
    ScanProgress {
        current_block: u64,
        total_blocks: u64,
        percentage: f64,
        speed_blocks_per_second: f64,
        estimated_time_remaining_seconds: Option<u64>,
    },
    /// Emitted when scan completes successfully
    ScanCompleted {
        final_statistics: HashMap<String, u64>,
        success: bool,
    },
    /// Emitted when an error occurs during scanning
    ScanError {
        error_message: String,
        block_height: Option<u64>,
        retry_info: Option<String>,
    },
    /// Emitted when scanning is cancelled
    ScanCancelled {
        reason: String,
        final_statistics: HashMap<String, u64>,
    },
}
