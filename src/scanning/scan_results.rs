//! Scan results and progress reporting for the scanner library

use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::data_structures::{
    transaction_output::LightweightTransactionOutput,
    wallet_output::LightweightWalletOutput,
};

/// Structured progress reporting for scan operations
#[derive(Debug, Clone)]
pub struct ScanProgress {
    /// Current block height being scanned
    pub current_height: u64,
    /// Target block height to scan to
    pub target_height: u64,
    /// Number of outputs found so far
    pub outputs_found: u64,
    /// Total value of outputs found so far (in MicroMinotari)
    pub total_value: u64,
    /// Time elapsed since scan started
    pub elapsed: Duration,
}

/// Comprehensive scan results management
#[derive(Debug, Clone)]
pub struct ScanResults {
    /// Block scan results
    pub block_results: Vec<BlockScanResult>,
    /// Total wallet outputs found
    pub total_wallet_outputs: u64,
    /// Total value found (in MicroMinotari)
    pub total_value: u64,
    /// Number of addresses scanned
    pub addresses_scanned: u64,
    /// Number of accounts scanned
    pub accounts_scanned: u64,
    /// Scan duration
    pub scan_duration: Duration,
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
}
