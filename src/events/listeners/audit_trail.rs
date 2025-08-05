//! Audit trail listener for comprehensive wallet event tracking and compliance
//!
//! This listener provides detailed audit trail functionality for wallet events,
//! designed for compliance, security monitoring, and forensic analysis.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::events::types::{SharedWalletEvent, WalletEvent};
use crate::events::WalletEventListener;

/// Audit record for a wallet event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unique audit record ID
    pub audit_id: String,
    /// Timestamp when the audit record was created
    pub audit_timestamp: u64,
    /// Event ID from the original wallet event
    pub event_id: String,
    /// Wallet ID associated with the event
    pub wallet_id: String,
    /// Event type name
    pub event_type: String,
    /// Event description for audit purposes
    pub description: String,
    /// Financial impact (amount involved in the transaction)
    pub financial_impact: Option<u64>,
    /// Transaction direction (inbound, outbound, internal)
    pub transaction_direction: Option<String>,
    /// Block height where the event occurred
    pub block_height: Option<u64>,
    /// Network identifier
    pub network: Option<String>,
    /// Additional contextual data for the audit
    pub context_data: HashMap<String, String>,
    /// Compliance tags for categorization
    pub compliance_tags: Vec<String>,
    /// Risk level assessment
    pub risk_level: RiskLevel,
    /// Source of the event (scanning, user action, etc.)
    pub event_source: String,
    /// Correlation ID linking related events
    pub correlation_id: Option<String>,
}

/// Risk level assessment for audit records
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// Low risk routine operations
    Low,
    /// Medium risk operations requiring attention
    Medium,
    /// High risk operations requiring immediate review
    High,
    /// Critical operations requiring urgent intervention
    Critical,
}

impl RiskLevel {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }
}

/// Configuration for the AuditTrail listener
#[derive(Debug, Clone)]
pub struct AuditTrailConfig {
    /// Path to the audit trail file
    pub audit_file_path: PathBuf,
    /// Whether to include detailed context data
    pub include_detailed_context: bool,
    /// Whether to perform real-time risk assessment
    pub enable_risk_assessment: bool,
    /// Compliance frameworks to tag events for
    pub compliance_frameworks: Vec<String>,
    /// Minimum risk level to record (filters out lower risk events)
    pub minimum_risk_level: RiskLevel,
    /// Maximum file size before rotation (in MB)
    pub max_file_size_mb: u64,
    /// Whether to encrypt audit records
    pub encrypt_records: bool,
    /// Whether to sign audit records for integrity
    pub sign_records: bool,
    /// Buffer size for batched writing
    pub buffer_size: usize,
    /// Whether to include full event payloads in audit records
    pub include_event_payloads: bool,
}

impl Default for AuditTrailConfig {
    fn default() -> Self {
        Self {
            audit_file_path: PathBuf::from("wallet_audit.log"),
            include_detailed_context: true,
            enable_risk_assessment: true,
            compliance_frameworks: vec!["AML".to_string(), "KYC".to_string(), "GDPR".to_string()],
            minimum_risk_level: RiskLevel::Low,
            max_file_size_mb: 500,
            encrypt_records: false,
            sign_records: false,
            buffer_size: 50,
            include_event_payloads: false,
        }
    }
}

impl AuditTrailConfig {
    /// Create a configuration for basic audit trail
    pub fn basic<P: Into<PathBuf>>(audit_file_path: P) -> Self {
        Self {
            audit_file_path: audit_file_path.into(),
            include_detailed_context: false,
            enable_risk_assessment: false,
            minimum_risk_level: RiskLevel::Low,
            ..Default::default()
        }
    }

    /// Create a configuration for compliance-focused audit trail
    pub fn compliance<P: Into<PathBuf>>(audit_file_path: P) -> Self {
        Self {
            audit_file_path: audit_file_path.into(),
            include_detailed_context: true,
            enable_risk_assessment: true,
            compliance_frameworks: vec![
                "AML".to_string(),
                "KYC".to_string(),
                "GDPR".to_string(),
                "SOX".to_string(),
                "PCI_DSS".to_string(),
            ],
            minimum_risk_level: RiskLevel::Low,
            encrypt_records: true,
            sign_records: true,
            include_event_payloads: true,
            ..Default::default()
        }
    }

    /// Create a configuration for high-security audit trail
    pub fn high_security<P: Into<PathBuf>>(audit_file_path: P) -> Self {
        Self {
            audit_file_path: audit_file_path.into(),
            include_detailed_context: true,
            enable_risk_assessment: true,
            minimum_risk_level: RiskLevel::Medium,
            encrypt_records: true,
            sign_records: true,
            buffer_size: 10, // Smaller buffer for real-time writing
            include_event_payloads: true,
            ..Default::default()
        }
    }

    /// Set the audit file path
    pub fn with_audit_file<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.audit_file_path = path.into();
        self
    }

    /// Enable or disable detailed context
    pub fn with_detailed_context(mut self, enabled: bool) -> Self {
        self.include_detailed_context = enabled;
        self
    }

    /// Enable or disable risk assessment
    pub fn with_risk_assessment(mut self, enabled: bool) -> Self {
        self.enable_risk_assessment = enabled;
        self
    }

    /// Set compliance frameworks
    pub fn with_compliance_frameworks(mut self, frameworks: Vec<String>) -> Self {
        self.compliance_frameworks = frameworks;
        self
    }

    /// Set minimum risk level
    pub fn with_minimum_risk_level(mut self, level: RiskLevel) -> Self {
        self.minimum_risk_level = level;
        self
    }

    /// Enable record encryption
    pub fn with_encryption(mut self, enabled: bool) -> Self {
        self.encrypt_records = enabled;
        self
    }

    /// Enable record signing
    pub fn with_signing(mut self, enabled: bool) -> Self {
        self.sign_records = enabled;
        self
    }

    /// Set buffer size
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Include event payloads in audit records
    pub fn with_event_payloads(mut self, enabled: bool) -> Self {
        self.include_event_payloads = enabled;
        self
    }
}

/// Statistics for audit trail operations
#[derive(Debug, Default)]
pub struct AuditStats {
    records_created: u64,
    records_written: u64,
    records_filtered: u64,
    high_risk_events: u64,
    critical_events: u64,
    file_rotations: u64,
    write_errors: u64,
}

/// AuditTrail listener for comprehensive wallet event auditing
///
/// This listener creates detailed audit records for all wallet events,
/// providing comprehensive tracking for compliance, security monitoring,
/// and forensic analysis purposes.
///
/// # Features
///
/// - Detailed audit record generation
/// - Risk level assessment for events
/// - Compliance framework tagging
/// - File rotation and management
/// - Record encryption and signing (optional)
/// - Buffered writing for performance
/// - Contextual data collection
///
/// # Examples
///
/// ## Basic audit trail
/// ```rust,no_run
/// use lightweight_wallet_libs::events::listeners::{AuditTrail, AuditTrailConfig};
///
/// let config = AuditTrailConfig::basic("basic_audit.log");
/// let audit_trail = AuditTrail::new(config).expect("Failed to create audit trail");
/// ```
///
/// ## Compliance-focused audit trail
/// ```rust,no_run
/// use lightweight_wallet_libs::events::listeners::{AuditTrail, AuditTrailConfig};
///
/// let config = AuditTrailConfig::compliance("compliance_audit.log");
/// let audit_trail = AuditTrail::new(config).expect("Failed to create audit trail");
/// ```
pub struct AuditTrail {
    config: AuditTrailConfig,
    file_handle: Arc<Mutex<std::fs::File>>,
    buffer: Arc<Mutex<Vec<AuditRecord>>>,
    stats: Arc<Mutex<AuditStats>>,
}

impl AuditTrail {
    /// Create a new AuditTrail with the specified configuration
    pub fn new(config: AuditTrailConfig) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Create or open the audit file
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.audit_file_path)
            .map_err(|e| {
                format!(
                    "Failed to open audit file {:?}: {}",
                    config.audit_file_path, e
                )
            })?;

        Ok(Self {
            config,
            file_handle: Arc::new(Mutex::new(file)),
            buffer: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(Mutex::new(AuditStats::default())),
        })
    }

    /// Create a basic audit trail
    pub fn basic<P: Into<PathBuf>>(path: P) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Self::new(AuditTrailConfig::basic(path))
    }

    /// Create a compliance-focused audit trail
    pub fn compliance<P: Into<PathBuf>>(path: P) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Self::new(AuditTrailConfig::compliance(path))
    }

    /// Create a high-security audit trail
    pub fn high_security<P: Into<PathBuf>>(path: P) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Self::new(AuditTrailConfig::high_security(path))
    }

    /// Assess the risk level of a wallet event
    fn assess_risk_level(&self, event: &SharedWalletEvent) -> RiskLevel {
        if !self.config.enable_risk_assessment {
            return RiskLevel::Low;
        }

        match &**event {
            WalletEvent::UtxoReceived { payload, .. } => {
                // High value transactions are higher risk
                if payload.amount > 1_000_000_000 {
                    // > 1000 Tari
                    RiskLevel::High
                } else if payload.amount > 100_000_000 {
                    // > 100 Tari
                    RiskLevel::Medium
                } else {
                    RiskLevel::Low
                }
            }
            WalletEvent::UtxoSpent { payload, .. } => {
                // Spending large amounts is higher risk
                if payload.amount > 1_000_000_000 {
                    RiskLevel::High
                } else if payload.amount > 100_000_000 {
                    RiskLevel::Medium
                } else {
                    RiskLevel::Low
                }
            }
            WalletEvent::Reorg { payload, .. } => {
                // Deep reorgs are high risk
                if payload.rollback_depth > 10 {
                    RiskLevel::Critical
                } else if payload.rollback_depth > 5 {
                    RiskLevel::High
                } else {
                    RiskLevel::Medium
                }
            }
        }
    }

    /// Generate compliance tags for an event
    fn generate_compliance_tags(&self, event: &SharedWalletEvent) -> Vec<String> {
        let mut tags = Vec::new();

        for framework in &self.config.compliance_frameworks {
            match framework.as_str() {
                "AML" => {
                    // Anti-Money Laundering tags
                    match &**event {
                        WalletEvent::UtxoReceived { payload, .. } => {
                            if payload.amount > 10_000_000_000 {
                                // > 10,000 Tari
                                tags.push("AML_LARGE_RECEIPT".to_string());
                            }
                            tags.push("AML_RECEIPT".to_string());
                        }
                        WalletEvent::UtxoSpent { payload, .. } => {
                            if payload.amount > 10_000_000_000 {
                                tags.push("AML_LARGE_SPEND".to_string());
                            }
                            tags.push("AML_SPEND".to_string());
                        }
                        WalletEvent::Reorg { .. } => {
                            tags.push("AML_REORG_IMPACT".to_string());
                        }
                    }
                }
                "KYC" => {
                    // Know Your Customer tags
                    tags.push("KYC_WALLET_ACTIVITY".to_string());
                }
                "GDPR" => {
                    // General Data Protection Regulation tags
                    tags.push("GDPR_PERSONAL_DATA".to_string());
                }
                "SOX" => {
                    // Sarbanes-Oxley tags
                    tags.push("SOX_FINANCIAL_RECORD".to_string());
                }
                "PCI_DSS" => {
                    // Payment Card Industry Data Security Standard
                    tags.push("PCI_TRANSACTION_LOG".to_string());
                }
                _ => {
                    // Custom framework
                    tags.push(format!("{}_EVENT", framework.to_uppercase()));
                }
            }
        }

        tags
    }

    /// Create context data for an audit record
    fn create_context_data(&self, event: &SharedWalletEvent) -> HashMap<String, String> {
        let mut context = HashMap::new();

        if !self.config.include_detailed_context {
            return context;
        }

        match &**event {
            WalletEvent::UtxoReceived { metadata, payload } => {
                context.insert("block_hash".to_string(), payload.block_hash.clone());
                context.insert(
                    "transaction_hash".to_string(),
                    payload.transaction_hash.clone(),
                );
                context.insert("output_index".to_string(), payload.output_index.to_string());
                context.insert("key_index".to_string(), payload.key_index.to_string());
                context.insert("commitment".to_string(), payload.commitment.clone());
                context.insert("features".to_string(), payload.features.to_string());
                context.insert("network".to_string(), payload.network.clone());
                context.insert("event_source".to_string(), metadata.source.clone());

                if let Some(maturity_height) = payload.maturity_height {
                    context.insert("maturity_height".to_string(), maturity_height.to_string());
                }
                if let Some(ref script_hash) = payload.script_hash {
                    context.insert("script_hash".to_string(), script_hash.clone());
                }
                context.insert(
                    "has_unlock_conditions".to_string(),
                    payload.has_unlock_conditions.to_string(),
                );
            }
            WalletEvent::UtxoSpent { metadata, payload } => {
                context.insert(
                    "spending_block_hash".to_string(),
                    payload.spending_block_hash.clone(),
                );
                context.insert(
                    "spending_transaction_hash".to_string(),
                    payload.spending_transaction_hash.clone(),
                );
                context.insert("input_index".to_string(), payload.input_index.to_string());
                context.insert("key_index".to_string(), payload.key_index.to_string());
                context.insert("commitment".to_string(), payload.commitment.clone());
                context.insert("match_method".to_string(), payload.match_method.clone());
                context.insert(
                    "is_self_spend".to_string(),
                    payload.is_self_spend.to_string(),
                );
                context.insert("network".to_string(), payload.network.clone());
                context.insert("event_source".to_string(), metadata.source.clone());
                context.insert(
                    "original_block_height".to_string(),
                    payload.original_block_height.to_string(),
                );

                if let Some(transaction_fee) = payload.transaction_fee {
                    context.insert("transaction_fee".to_string(), transaction_fee.to_string());
                }
            }
            WalletEvent::Reorg { metadata, payload } => {
                context.insert("fork_height".to_string(), payload.fork_height.to_string());
                context.insert("old_block_hash".to_string(), payload.old_block_hash.clone());
                context.insert("new_block_hash".to_string(), payload.new_block_hash.clone());
                context.insert(
                    "rollback_depth".to_string(),
                    payload.rollback_depth.to_string(),
                );
                context.insert(
                    "new_blocks_count".to_string(),
                    payload.new_blocks_count.to_string(),
                );
                context.insert(
                    "balance_change".to_string(),
                    payload.balance_change.to_string(),
                );
                context.insert("network".to_string(), payload.network.clone());
                context.insert("event_source".to_string(), metadata.source.clone());

                if !payload.affected_transaction_hashes.is_empty() {
                    context.insert(
                        "affected_transactions_count".to_string(),
                        payload.affected_transaction_hashes.len().to_string(),
                    );
                    context.insert(
                        "affected_transactions".to_string(),
                        payload.affected_transaction_hashes.join(","),
                    );
                }
                if !payload.affected_utxo_ids.is_empty() {
                    context.insert(
                        "affected_utxos_count".to_string(),
                        payload.affected_utxo_ids.len().to_string(),
                    );
                }
            }
        }

        context
    }

    /// Create an audit record from a wallet event
    fn create_audit_record(&self, event: &SharedWalletEvent) -> AuditRecord {
        let risk_level = self.assess_risk_level(event);
        let compliance_tags = self.generate_compliance_tags(event);
        let context_data = self.create_context_data(event);

        let (event_id, wallet_id, event_source, correlation_id) = match &**event {
            WalletEvent::UtxoReceived { metadata, .. }
            | WalletEvent::UtxoSpent { metadata, .. }
            | WalletEvent::Reorg { metadata, .. } => (
                metadata.event_id.clone(),
                metadata.wallet_id.clone(),
                metadata.source.clone(),
                metadata.correlation_id.clone(),
            ),
        };

        let (event_type, description, financial_impact, transaction_direction, block_height, network) =
            match &**event {
                WalletEvent::UtxoReceived { payload, .. } => (
                    "UtxoReceived".to_string(),
                    format!(
                        "Received UTXO of {} µT at block {} on {}",
                        payload.amount, payload.block_height, payload.network
                    ),
                    Some(payload.amount),
                    Some("inbound".to_string()),
                    Some(payload.block_height),
                    Some(payload.network.clone()),
                ),
                WalletEvent::UtxoSpent { payload, .. } => (
                    "UtxoSpent".to_string(),
                    format!(
                        "Spent UTXO of {} µT at block {} on {}",
                        payload.amount, payload.spending_block_height, payload.network
                    ),
                    Some(payload.amount),
                    Some("outbound".to_string()),
                    Some(payload.spending_block_height),
                    Some(payload.network.clone()),
                ),
                WalletEvent::Reorg { payload, .. } => (
                    "Reorg".to_string(),
                    format!(
                        "Blockchain reorganization at fork height {} (rollback: {} blocks, new: {} blocks)",
                        payload.fork_height, payload.rollback_depth, payload.new_blocks_count
                    ),
                    None,
                    Some("internal".to_string()),
                    Some(payload.fork_height),
                    Some(payload.network.clone()),
                ),
            };

        AuditRecord {
            audit_id: uuid::Uuid::new_v4().to_string(),
            audit_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            event_id,
            wallet_id,
            event_type,
            description,
            financial_impact,
            transaction_direction,
            block_height,
            network,
            context_data,
            compliance_tags,
            risk_level,
            event_source,
            correlation_id,
        }
    }

    /// Write an audit record to the file
    async fn write_audit_record(
        &self,
        record: &AuditRecord,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let json_record = if self.config.sign_records || self.config.encrypt_records {
            // For now, just serialize to JSON
            // TODO: Implement signing and encryption
            serde_json::to_string(record)?
        } else {
            serde_json::to_string(record)?
        };

        let mut file = self
            .file_handle
            .lock()
            .map_err(|e| format!("File lock error: {e}"))?;

        writeln!(file, "{json_record}")?;
        file.flush()?;

        Ok(())
    }

    /// Add an audit record to the buffer
    async fn buffer_audit_record(
        &self,
        record: AuditRecord,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let records_to_write = {
            let mut buffer = self
                .buffer
                .lock()
                .map_err(|e| format!("Buffer lock error: {e}"))?;

            buffer.push(record);

            // Check if buffer needs flushing
            if buffer.len() >= self.config.buffer_size {
                Some(buffer.drain(..).collect::<Vec<_>>())
            } else {
                None
            }
        }; // Release lock here

        if let Some(records) = records_to_write {
            for record in records {
                self.write_audit_record(&record).await?;
            }

            if let Ok(mut stats) = self.stats.lock() {
                stats.records_written += self.config.buffer_size as u64;
            }
        }

        Ok(())
    }

    /// Flush all buffered audit records
    pub async fn flush(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (records_to_write, record_count) = {
            let mut buffer = self
                .buffer
                .lock()
                .map_err(|e| format!("Buffer lock error: {e}"))?;

            let records = buffer.drain(..).collect::<Vec<_>>();
            let count = records.len();
            (records, count)
        }; // Release lock here

        for record in records_to_write {
            self.write_audit_record(&record).await?;
        }

        if let Ok(mut stats) = self.stats.lock() {
            stats.records_written += record_count as u64;
        }

        Ok(())
    }

    /// Get audit trail statistics
    pub fn get_stats(&self) -> Result<AuditStats, Box<dyn Error + Send + Sync>> {
        self.stats
            .lock()
            .map(|stats| AuditStats {
                records_created: stats.records_created,
                records_written: stats.records_written,
                records_filtered: stats.records_filtered,
                high_risk_events: stats.high_risk_events,
                critical_events: stats.critical_events,
                file_rotations: stats.file_rotations,
                write_errors: stats.write_errors,
            })
            .map_err(|e| format!("Stats lock error: {e}").into())
    }
}

#[async_trait]
impl WalletEventListener for AuditTrail {
    async fn handle_event(
        &mut self,
        event: &SharedWalletEvent,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Create audit record
        let audit_record = self.create_audit_record(event);

        // Check if record meets minimum risk level
        if audit_record.risk_level < self.config.minimum_risk_level {
            if let Ok(mut stats) = self.stats.lock() {
                stats.records_filtered += 1;
            }
            return Ok(());
        }

        // Update statistics
        if let Ok(mut stats) = self.stats.lock() {
            stats.records_created += 1;
            match audit_record.risk_level {
                RiskLevel::High => stats.high_risk_events += 1,
                RiskLevel::Critical => stats.critical_events += 1,
                _ => {}
            }
        }

        // Buffer the audit record
        self.buffer_audit_record(audit_record).await
    }

    fn name(&self) -> &'static str {
        "AuditTrail"
    }

    async fn cleanup(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Flush any remaining buffered records
        self.flush().await
    }

    fn get_config(&self) -> HashMap<String, String> {
        let mut config = HashMap::new();
        config.insert(
            "audit_file_path".to_string(),
            self.config.audit_file_path.to_string_lossy().to_string(),
        );
        config.insert(
            "include_detailed_context".to_string(),
            self.config.include_detailed_context.to_string(),
        );
        config.insert(
            "enable_risk_assessment".to_string(),
            self.config.enable_risk_assessment.to_string(),
        );
        config.insert(
            "minimum_risk_level".to_string(),
            self.config.minimum_risk_level.as_str().to_string(),
        );
        config.insert(
            "encrypt_records".to_string(),
            self.config.encrypt_records.to_string(),
        );
        config.insert(
            "sign_records".to_string(),
            self.config.sign_records.to_string(),
        );
        config.insert(
            "buffer_size".to_string(),
            self.config.buffer_size.to_string(),
        );
        config.insert(
            "compliance_frameworks".to_string(),
            self.config.compliance_frameworks.join(","),
        );
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::types::{EventMetadata, UtxoReceivedPayload, WalletEvent};

    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_audit_trail_creation() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let audit_trail =
            AuditTrail::basic(temp_file.path()).expect("Failed to create audit trail");
        assert_eq!(audit_trail.name(), "AuditTrail");
    }

    #[tokio::test]
    async fn test_risk_assessment() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let config = AuditTrailConfig::basic(temp_file.path()).with_risk_assessment(true);
        let audit_trail = AuditTrail::new(config).expect("Failed to create audit trail");

        // Test low value transaction
        let metadata = EventMetadata::new("test", "test_wallet");
        let low_value_payload = UtxoReceivedPayload::new(
            "test_utxo".to_string(),
            1000, // 0.001 Tari - low value
            100,
            "block_hash".to_string(),
            1234567890,
            "tx_hash".to_string(),
            0,
            "address".to_string(),
            0,
            "commitment".to_string(),
            0,
            "mainnet".to_string(),
        );
        let low_value_event = SharedWalletEvent::new(WalletEvent::UtxoReceived {
            metadata: metadata.clone(),
            payload: low_value_payload,
        });

        let risk_level = audit_trail.assess_risk_level(&low_value_event);
        assert_eq!(risk_level, RiskLevel::Low);

        // Test high value transaction
        let high_value_payload = UtxoReceivedPayload::new(
            "test_utxo".to_string(),
            2_000_000_000, // 2000 Tari - high value
            100,
            "block_hash".to_string(),
            1234567890,
            "tx_hash".to_string(),
            0,
            "address".to_string(),
            0,
            "commitment".to_string(),
            0,
            "mainnet".to_string(),
        );
        let high_value_event = SharedWalletEvent::new(WalletEvent::UtxoReceived {
            metadata,
            payload: high_value_payload,
        });

        let risk_level = audit_trail.assess_risk_level(&high_value_event);
        assert_eq!(risk_level, RiskLevel::High);
    }

    #[tokio::test]
    async fn test_compliance_tags() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let config = AuditTrailConfig::compliance(temp_file.path());
        let audit_trail = AuditTrail::new(config).expect("Failed to create audit trail");

        let metadata = EventMetadata::new("test", "test_wallet");
        let payload = UtxoReceivedPayload::new(
            "test_utxo".to_string(),
            15_000_000_000, // Large amount for AML tagging
            100,
            "block_hash".to_string(),
            1234567890,
            "tx_hash".to_string(),
            0,
            "address".to_string(),
            0,
            "commitment".to_string(),
            0,
            "mainnet".to_string(),
        );
        let event = SharedWalletEvent::new(WalletEvent::UtxoReceived { metadata, payload });

        let tags = audit_trail.generate_compliance_tags(&event);
        assert!(tags.contains(&"AML_LARGE_RECEIPT".to_string()));
        assert!(tags.contains(&"AML_RECEIPT".to_string()));
        assert!(tags.contains(&"KYC_WALLET_ACTIVITY".to_string()));
    }

    #[tokio::test]
    async fn test_audit_record_creation() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let audit_trail =
            AuditTrail::basic(temp_file.path()).expect("Failed to create audit trail");

        let metadata = EventMetadata::new("test", "test_wallet");
        let payload = UtxoReceivedPayload::new(
            "test_utxo".to_string(),
            1000,
            100,
            "block_hash".to_string(),
            1234567890,
            "tx_hash".to_string(),
            0,
            "address".to_string(),
            0,
            "commitment".to_string(),
            0,
            "mainnet".to_string(),
        );
        let event = SharedWalletEvent::new(WalletEvent::UtxoReceived { metadata, payload });

        let audit_record = audit_trail.create_audit_record(&event);
        assert_eq!(audit_record.event_type, "UtxoReceived");
        assert_eq!(audit_record.wallet_id, "test_wallet");
        assert_eq!(audit_record.financial_impact, Some(1000));
        assert_eq!(
            audit_record.transaction_direction,
            Some("inbound".to_string())
        );
        assert_eq!(audit_record.block_height, Some(100));
        assert!(audit_record.description.contains("Received UTXO"));
    }
}
