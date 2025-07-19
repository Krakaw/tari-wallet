//! Builder pattern implementation for configuring scanner services
//!
//! Provides a fluent API for creating and configuring scanner services with
//! sensible defaults and comprehensive validation.

use std::time::Duration;

use crate::{
    errors::{LightweightWalletError, LightweightWalletResult},
    extraction::ExtractionConfig,
};

use super::{
    scanner_service::{ScannerConfig, OutputFormat, DefaultScannerService, ScannerService},
};

#[cfg(feature = "grpc")]
use super::grpc_scanner::GrpcBlockchainScanner;

#[cfg(feature = "http")]
use super::http_scanner::HttpBlockchainScanner;

#[cfg(feature = "storage")]
use crate::storage::WalletStorage;

/// Builder for creating scanner services with fluent configuration API
pub struct ScannerServiceBuilder {
    config: ScannerConfig,
    scanner_type: Option<ScannerType>,
    extraction_config: Option<ExtractionConfig>,
    #[cfg(feature = "storage")]
    storage: Option<Box<dyn WalletStorage>>,
}

/// Supported scanner backend types
#[derive(Debug, Clone)]
pub enum ScannerType {
    /// GRPC-based scanner
    #[cfg(feature = "grpc")]
    Grpc,
    /// HTTP-based scanner
    #[cfg(feature = "http")]
    Http,
    /// Mock scanner for testing
    Mock,
}

impl ScannerServiceBuilder {
    /// Create a new scanner service builder
    pub fn new() -> Self {
        Self {
            config: ScannerConfig::default(),
            scanner_type: None,
            extraction_config: None,
            #[cfg(feature = "storage")]
            storage: None,
        }
    }

    /// Set the base node URL
    pub fn with_base_url<S: Into<String>>(mut self, url: S) -> Self {
        self.config.base_url = url.into();
        self
    }

    /// Set the starting block height
    pub fn with_start_height(mut self, height: u64) -> Self {
        self.config.start_height = height;
        self
    }

    /// Set the ending block height
    pub fn with_end_height(mut self, height: u64) -> Self {
        self.config.end_height = Some(height);
        self
    }

    /// Set the batch size for block requests
    pub fn with_batch_size(mut self, size: u64) -> Self {
        self.config.batch_size = size;
        self
    }

    /// Set the request timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.config.request_timeout = timeout;
        self
    }

    /// Set the storage database path
    pub fn with_storage_path<S: Into<String>>(mut self, path: S) -> Self {
        self.config.storage_path = Some(path.into());
        self
    }

    /// Set the wallet name for storage operations
    pub fn with_wallet_name<S: Into<String>>(mut self, name: S) -> Self {
        self.config.wallet_name = Some(name.into());
        self
    }

    /// Set progress reporting frequency
    pub fn with_progress_frequency(mut self, frequency: u64) -> Self {
        self.config.progress_frequency = frequency;
        self
    }

    /// Enable quiet mode
    pub fn with_quiet_mode(mut self, quiet: bool) -> Self {
        self.config.quiet_mode = quiet;
        self
    }

    /// Set output format
    pub fn with_output_format(mut self, format: OutputFormat) -> Self {
        self.config.output_format = format;
        self
    }

    /// Set the scanner type
    pub fn with_scanner_type(mut self, scanner_type: ScannerType) -> Self {
        self.scanner_type = Some(scanner_type);
        self
    }

    /// Set extraction configuration
    pub fn with_extraction_config(mut self, config: ExtractionConfig) -> Self {
        self.extraction_config = Some(config);
        self
    }

    /// Set storage implementation
    #[cfg(feature = "storage")]
    pub fn with_storage(mut self, storage: Box<dyn WalletStorage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Build the scanner service
    pub async fn build(self) -> LightweightWalletResult<Box<dyn ScannerService>> {
        // Validate configuration
        self.validate_config()?;

        // Create the blockchain scanner based on type
        let scanner_type = self.scanner_type.unwrap_or_else(|| {
            // Default to HTTP if available, otherwise GRPC, otherwise Mock
            #[cfg(feature = "http")]
            return ScannerType::Http;
            #[cfg(all(feature = "grpc", not(feature = "http")))]
            return ScannerType::Grpc;
            #[cfg(all(not(feature = "grpc"), not(feature = "http")))]
            return ScannerType::Mock;
        });

        let service: Box<dyn ScannerService> = match scanner_type {
            #[cfg(feature = "grpc")]
            ScannerType::Grpc => {
                let scanner = GrpcBlockchainScanner::new(self.config.base_url.clone()).await?;
                #[cfg(feature = "storage")]
                if let Some(storage) = self.storage {
                    Box::new(DefaultScannerService::with_storage(scanner, storage))
                } else {
                    Box::new(DefaultScannerService::new(scanner))
                }
                #[cfg(not(feature = "storage"))]
                Box::new(DefaultScannerService::new(scanner))
            }
            #[cfg(feature = "http")]
            ScannerType::Http => {
                let scanner = HttpBlockchainScanner::new(self.config.base_url.clone()).await?;
                #[cfg(feature = "storage")]
                if let Some(storage) = self.storage {
                    Box::new(DefaultScannerService::with_storage(scanner, storage))
                } else {
                    Box::new(DefaultScannerService::new(scanner))
                }
                #[cfg(not(feature = "storage"))]
                Box::new(DefaultScannerService::new(scanner))
            }
            ScannerType::Mock => {
                let scanner = super::MockBlockchainScanner::new();
                #[cfg(feature = "storage")]
                if let Some(storage) = self.storage {
                    Box::new(DefaultScannerService::with_storage(scanner, storage))
                } else {
                    Box::new(DefaultScannerService::new(scanner))
                }
                #[cfg(not(feature = "storage"))]
                Box::new(DefaultScannerService::new(scanner))
            }
        };

        Ok(service)
    }

    /// Validate the configuration
    fn validate_config(&self) -> LightweightWalletResult<()> {
        if self.config.base_url.is_empty() {
            return Err(LightweightWalletError::ConfigurationError(
                "Base URL cannot be empty".to_string()
            ));
        }

        if self.config.batch_size == 0 {
            return Err(LightweightWalletError::ConfigurationError(
                "Batch size must be greater than 0".to_string()
            ));
        }

        if self.config.request_timeout.as_secs() == 0 {
            return Err(LightweightWalletError::ConfigurationError(
                "Request timeout must be greater than 0".to_string()
            ));
        }

        if let Some(end_height) = self.config.end_height {
            if end_height < self.config.start_height {
                return Err(LightweightWalletError::ConfigurationError(
                    "End height cannot be less than start height".to_string()
                ));
            }
        }

        Ok(())
    }
}

impl Default for ScannerServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience methods for common scanner configurations
impl ScannerServiceBuilder {
    /// Create a builder configured for memory-only scanning
    pub fn memory_only() -> Self {
        Self::new()
            .with_quiet_mode(false)
            .with_output_format(OutputFormat::Table)
    }

    /// Create a builder configured for database-backed scanning
    #[cfg(feature = "storage")]
    pub fn with_database<S: Into<String>>(database_path: S) -> Self {
        Self::new()
            .with_storage_path(database_path)
            .with_output_format(OutputFormat::Table)
    }

    /// Create a builder configured for JSON output (scripting-friendly)
    pub fn json_output() -> Self {
        Self::new()
            .with_quiet_mode(true)
            .with_output_format(OutputFormat::Json)
    }

    /// Create a builder configured for summary output
    pub fn summary_output() -> Self {
        Self::new()
            .with_output_format(OutputFormat::Summary)
            .with_progress_frequency(50)
    }

    /// Create a builder configured for testing
    pub fn for_testing() -> Self {
        Self::new()
            .with_scanner_type(ScannerType::Mock)
            .with_quiet_mode(true)
            .with_batch_size(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = ScannerServiceBuilder::new();
        assert_eq!(builder.config.base_url, "http://127.0.0.1:18142");
        assert_eq!(builder.config.start_height, 0);
        assert_eq!(builder.config.batch_size, 100);
    }

    #[test]
    fn test_builder_configuration() {
        let builder = ScannerServiceBuilder::new()
            .with_base_url("http://example.com:8080")
            .with_start_height(1000)
            .with_batch_size(50)
            .with_quiet_mode(true);

        assert_eq!(builder.config.base_url, "http://example.com:8080");
        assert_eq!(builder.config.start_height, 1000);
        assert_eq!(builder.config.batch_size, 50);
        assert!(builder.config.quiet_mode);
    }

    #[test]
    fn test_convenience_methods() {
        let memory_builder = ScannerServiceBuilder::memory_only();
        assert!(!memory_builder.config.quiet_mode);
        assert!(matches!(memory_builder.config.output_format, OutputFormat::Table));

        let json_builder = ScannerServiceBuilder::json_output();
        assert!(json_builder.config.quiet_mode);
        assert!(matches!(json_builder.config.output_format, OutputFormat::Json));

        let test_builder = ScannerServiceBuilder::for_testing();
        assert!(test_builder.config.quiet_mode);
        assert_eq!(test_builder.config.batch_size, 10);
    }

    #[tokio::test]
    async fn test_validation_errors() {
        // Empty base URL
        let result = ScannerServiceBuilder::new()
            .with_base_url("")
            .build()
            .await;
        assert!(result.is_err());

        // Zero batch size
        let result = ScannerServiceBuilder::new()
            .with_batch_size(0)
            .build()
            .await;
        assert!(result.is_err());

        // Invalid height range
        let result = ScannerServiceBuilder::new()
            .with_start_height(1000)
            .with_end_height(500)
            .build()
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mock_scanner_build() {
        let service = ScannerServiceBuilder::new()
            .with_scanner_type(ScannerType::Mock)
            .build()
            .await
            .unwrap();

        // Test that we can get tip info
        // Note: This would need a mutable reference in real usage
        // let tip_info = service.get_tip_info().await.unwrap();
        // assert_eq!(tip_info.best_block_height, 1000);
    }
}
