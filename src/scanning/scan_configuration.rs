//! Scan configuration management for the scanner library

use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::extraction::ExtractionConfig;

/// Comprehensive configuration structure for all scan parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfiguration {
    /// Starting block height (wallet birthday)
    pub start_height: u64,
    /// Ending block height (optional, if None scans to tip)
    pub end_height: Option<u64>,
    /// Maximum number of blocks to scan in one request
    pub batch_size: u64,
    /// Timeout for requests
    #[serde(with = "duration_serde")]
    pub request_timeout: Duration,
}

impl Default for ScanConfiguration {
    fn default() -> Self {
        Self {
            start_height: 0,
            end_height: None,
            batch_size: 100,
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// Wallet source for initialization options
#[derive(Debug, Clone)]
pub enum WalletSource {
    /// Create from seed phrase
    SeedPhrase(String),
    /// Create from view key
    ViewKey(String),
    /// Use existing wallet
    Existing,
}

/// Wallet context for scanner initialization
#[derive(Debug, Clone)]
pub struct WalletContext {
    /// Wallet source
    pub source: WalletSource,
    /// Extraction configuration
    pub extraction_config: ExtractionConfig,
}

// Helper module for Duration serialization
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
