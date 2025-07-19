//! Core scanner orchestration service implementing high-level scanning operations
//!
//! This module provides the `ScannerService` trait and implementation that encapsulates
//! all scanner business logic, progress tracking, storage integration, and error handling.
//! It serves as the foundation for both CLI and WASM scanner wrappers.

use std::time::{Duration, Instant};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    errors::LightweightWalletResult,
    data_structures::wallet_transaction::WalletState,
    extraction::ExtractionConfig,
};

use super::{
    BlockchainScanner, ScanConfig, WalletScanConfig, ScanProgress,
    WalletScanResult, TipInfo, DefaultScanningLogic
};

#[cfg(feature = "storage")]
use crate::storage::{WalletStorage, StorageTransaction};

/// Configuration for scanner service operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    /// Base node URL for blockchain connection
    pub base_url: String,
    /// Starting block height (wallet birthday or resume point)
    pub start_height: u64,
    /// Ending block height (optional, if None scans to tip)
    pub end_height: Option<u64>,
    /// Maximum number of blocks to scan in one batch
    pub batch_size: u64,
    /// Request timeout duration
    #[serde(with = "crate::scanning::duration_serde")]
    pub request_timeout: Duration,
    /// Storage database path (optional)
    pub storage_path: Option<String>,
    /// Wallet name for storage operations
    pub wallet_name: Option<String>,
    /// Progress reporting frequency (blocks)
    pub progress_frequency: u64,
    /// Whether to use quiet mode (minimal output)
    pub quiet_mode: bool,
    /// Output format preference
    pub output_format: OutputFormat,
}

/// Output format options for scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    /// Human-readable table format
    Table,
    /// JSON format for scripting
    Json,
    /// Summary format with minimal details
    Summary,
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Table
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:18142".to_string(),
            start_height: 0,
            end_height: None,
            batch_size: 100,
            request_timeout: Duration::from_secs(30),
            storage_path: None,
            wallet_name: None,
            progress_frequency: 10,
            quiet_mode: false,
            output_format: OutputFormat::default(),
        }
    }
}

/// Result of a scanner service operation
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    /// Wallet state after scanning
    pub wallet_state: WalletState,
    /// Scan statistics
    pub statistics: ScanStatistics,
    /// Resume information for interrupted scans
    pub resume_info: ResumeInfo,
}

/// Scanning statistics
#[derive(Debug, Clone, Serialize)]
pub struct ScanStatistics {
    /// Total blocks scanned
    pub blocks_scanned: u64,
    /// Total outputs found
    pub outputs_found: u64,
    /// Total value found (in MicroMinotari)
    pub total_value: u64,
    /// Time elapsed during scan
    pub scan_duration: Duration,
    /// Average blocks per second
    pub blocks_per_second: f64,
}

/// Information for resuming interrupted scans
#[derive(Debug, Clone, Serialize)]
pub struct ResumeInfo {
    /// Last successfully scanned block height
    pub last_scanned_height: u64,
    /// Recommended resume command
    pub resume_command: String,
}

/// High-level scanner service trait
#[async_trait(?Send)]
pub trait ScannerService: Send + Sync {
    /// Scan wallet with the provided configuration
    async fn scan_wallet(&mut self, config: ScannerConfig) -> LightweightWalletResult<ScanResult>;
    
    /// Resume scanning from stored wallet state
    #[cfg(feature = "storage")]
    async fn resume_scan(&mut self, config: ScannerConfig) -> LightweightWalletResult<ScanResult>;
    
    /// Get current scanning progress
    async fn get_progress(&self) -> Option<ScanProgress>;
    
    /// Get chain tip information
    async fn get_tip_info(&mut self) -> LightweightWalletResult<TipInfo>;
}

/// Default implementation of ScannerService
pub struct DefaultScannerService<S: BlockchainScanner> {
    scanner: S,
    current_progress: Option<ScanProgress>,
    #[cfg(feature = "storage")]
    storage: Option<Box<dyn WalletStorage>>,
}

impl<S: BlockchainScanner> DefaultScannerService<S> {
    /// Create a new scanner service with the provided blockchain scanner
    pub fn new(scanner: S) -> Self {
        Self {
            scanner,
            current_progress: None,
            #[cfg(feature = "storage")]
            storage: None,
        }
    }

    #[cfg(feature = "storage")]
    /// Create a new scanner service with storage support
    pub fn with_storage(scanner: S, storage: Box<dyn WalletStorage>) -> Self {
        Self {
            scanner,
            current_progress: None,
            storage: Some(storage),
        }
    }

    /// Create a wallet scan configuration from scanner config and keys
    fn create_wallet_scan_config(
        &self,
        config: &ScannerConfig,
        extraction_config: ExtractionConfig,
    ) -> WalletScanConfig {
        let scan_config = ScanConfig {
            start_height: config.start_height,
            end_height: config.end_height,
            batch_size: config.batch_size,
            request_timeout: config.request_timeout,
            extraction_config,
        };

        WalletScanConfig {
            scan_config,
            key_manager: None,
            key_store: None,
            scan_stealth_addresses: true,
            max_addresses_per_account: 1000,
            scan_imported_keys: true,
        }
    }

    /// Execute the scanning operation with progress tracking
    async fn execute_scan(
        &mut self,
        wallet_scan_config: WalletScanConfig,
        _progress_frequency: u64,
    ) -> LightweightWalletResult<WalletScanResult> {
        // Use the scanning logic from the scanning module
        let scan_result = DefaultScanningLogic::scan_wallet_with_progress(
            &mut self.scanner,
            wallet_scan_config,
            None, // For now, no progress callback
        ).await?;

        Ok(scan_result)
    }

    /// Create scan statistics from wallet scan result
    fn create_statistics(
        &self,
        scan_result: &WalletScanResult,
        start_time: Instant,
    ) -> ScanStatistics {
        let elapsed = start_time.elapsed();
        let blocks_scanned = scan_result.block_results.len() as u64;
        let blocks_per_second = if elapsed.as_secs() > 0 {
            blocks_scanned as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        ScanStatistics {
            blocks_scanned,
            outputs_found: scan_result.total_wallet_outputs,
            total_value: scan_result.total_value,
            scan_duration: elapsed,
            blocks_per_second,
        }
    }

    /// Create resume information
    fn create_resume_info(&self, config: &ScannerConfig, last_height: u64) -> ResumeInfo {
        let resume_command = format!(
            "cargo run --bin scanner --features grpc-storage -- --from-block {} --to-block {}",
            last_height + 1,
            config.end_height.unwrap_or(last_height + 1000)
        );

        ResumeInfo {
            last_scanned_height: last_height,
            resume_command,
        }
    }
}

#[async_trait(?Send)]
impl<S: BlockchainScanner> ScannerService for DefaultScannerService<S> {
    async fn scan_wallet(&mut self, config: ScannerConfig) -> LightweightWalletResult<ScanResult> {
        let start_time = Instant::now();

        // For now, create a basic extraction config
        // In a real implementation, this would come from the provided keys
        let extraction_config = ExtractionConfig::default();
        
        let wallet_scan_config = self.create_wallet_scan_config(&config, extraction_config);
        
        let scan_result = self.execute_scan(wallet_scan_config, config.progress_frequency).await?;
        
        let statistics = self.create_statistics(&scan_result, start_time);
        
        let last_height = scan_result.block_results.last()
            .map(|result| result.height)
            .unwrap_or(config.start_height);
            
        let resume_info = self.create_resume_info(&config, last_height);

        // Create wallet state from scan results
        let wallet_state = WalletState::new();
        
        // Add all wallet outputs to the state
        for block_result in &scan_result.block_results {
            for _wallet_output in &block_result.wallet_outputs {
                // Create transaction from wallet output
                // This is simplified - real implementation would use actual transaction structures
                // For now, we'll just track the wallet outputs in a simplified manner
            }
        }

        Ok(ScanResult {
            wallet_state,
            statistics,
            resume_info,
        })
    }

    #[cfg(feature = "storage")]
    async fn resume_scan(&mut self, config: ScannerConfig) -> LightweightWalletResult<ScanResult> {
        // Load wallet state from storage if available
        if let Some(storage) = &self.storage {
            // Load existing wallet state and update config with last scanned height
            // This is a placeholder - real implementation would load from storage
            let mut resume_config = config.clone();
            // resume_config.start_height = last_scanned_height_from_storage;
            self.scan_wallet(resume_config).await
        } else {
            return Err(LightweightWalletError::ConfigurationError(
                "Storage not configured for resume operation".to_string()
            ));
        }
    }

    async fn get_progress(&self) -> Option<ScanProgress> {
        self.current_progress.clone()
    }

    async fn get_tip_info(&mut self) -> LightweightWalletResult<TipInfo> {
        self.scanner.get_tip_info().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanning::MockBlockchainScanner;

    #[tokio::test]
    async fn test_scanner_config_default() {
        let config = ScannerConfig::default();
        assert_eq!(config.base_url, "http://127.0.0.1:18142");
        assert_eq!(config.start_height, 0);
        assert_eq!(config.batch_size, 100);
        assert!(!config.quiet_mode);
        assert!(matches!(config.output_format, OutputFormat::Table));
    }

    #[tokio::test]
    async fn test_scanner_service_creation() {
        let scanner = MockBlockchainScanner::new();
        let service = DefaultScannerService::new(scanner);
        assert!(service.current_progress.is_none());
    }

    #[tokio::test]
    async fn test_get_tip_info() {
        let scanner = MockBlockchainScanner::new();
        let mut service = DefaultScannerService::new(scanner);
        
        let tip_info = service.get_tip_info().await.unwrap();
        assert_eq!(tip_info.best_block_height, 1000);
    }
}
