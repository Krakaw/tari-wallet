//! Output formatting for scanner results
//!
//! This module provides various output formatters for displaying scan results
//! in different formats (JSON, summary, detailed, etc.)

use super::scan_results::ScanResults;
use crate::common::format_number;
use crate::data_structures::{
    transaction::TransactionDirection,
    wallet_transaction::{WalletState, WalletTransaction},
};
use serde_json::{json, Value};
// use std::collections::HashMap; // Commented out as it's not used yet
use std::io::{self, Write};

/// Output format types supported by the scanner
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Detailed transaction-by-transaction output
    Detailed,
    /// Summary with key statistics
    Summary,
    /// JSON format for programmatic consumption
    Json,
    /// Minimal quiet output
    Quiet,
}

impl OutputFormat {
    /// Parse output format from string
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "detailed" => Ok(OutputFormat::Detailed),
            "summary" => Ok(OutputFormat::Summary),
            "json" => Ok(OutputFormat::Json),
            "quiet" => Ok(OutputFormat::Quiet),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }

    /// Get the string representation of the format
    pub fn as_str(&self) -> &'static str {
        match self {
            OutputFormat::Detailed => "detailed",
            OutputFormat::Summary => "summary",
            OutputFormat::Json => "json",
            OutputFormat::Quiet => "quiet",
        }
    }
}

/// Configuration for output formatting
#[derive(Debug, Clone)]
pub struct OutputConfig {
    /// Output format to use
    pub format: OutputFormat,
    /// Whether to use colored output (ignored for JSON)
    pub use_colors: bool,
    /// Whether to show timestamps
    pub show_timestamps: bool,
    /// Whether to show block details
    pub show_block_details: bool,
    /// Maximum number of transactions to show in detailed mode
    pub max_transactions_detailed: Option<usize>,
    /// Whether to include metadata in JSON output
    pub include_metadata: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Summary,
            use_colors: true,
            show_timestamps: true,
            show_block_details: true,
            max_transactions_detailed: None,
            include_metadata: true,
        }
    }
}

/// Scanner configuration display information
#[derive(Debug, Clone)]
pub struct ScanConfigDisplay {
    /// Starting block height
    pub start_height: u64,
    /// Ending block height
    pub end_height: u64,
    /// Specific blocks being scanned (if any)
    pub specific_blocks: Option<Vec<u64>>,
    /// Total number of blocks scanned
    pub total_blocks: u64,
    /// Batch size used
    pub batch_size: u64,
}

/// Output formatter trait for different display formats
pub trait OutputFormatter: Send + Sync {
    /// Display scan configuration information
    fn display_scan_info(
        &self,
        config_display: &ScanConfigDisplay,
        output_config: &OutputConfig,
    ) -> io::Result<()>;

    /// Display scan results
    fn display_scan_results(
        &self,
        results: &ScanResults,
        output_config: &OutputConfig,
    ) -> io::Result<()>;

    /// Display wallet activity summary
    fn display_wallet_activity(
        &self,
        wallet_state: &WalletState,
        scan_range: (u64, u64),
        output_config: &OutputConfig,
    ) -> io::Result<()>;

    /// Display error message
    fn display_error(&self, error: &str, output_config: &OutputConfig) -> io::Result<()>;

    /// Flush any pending output
    fn flush(&self) -> io::Result<()>;
}

/// Console-based output formatter
#[derive(Debug, Default)]
pub struct ConsoleFormatter;

impl ConsoleFormatter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Format a transaction for display
    fn format_transaction(
        &self,
        tx: &WalletTransaction,
        index: usize,
        _output_config: &OutputConfig,
    ) -> String {
        let direction_symbol = match tx.transaction_direction {
            TransactionDirection::Inbound => "📥",
            TransactionDirection::Outbound => "📤",
            TransactionDirection::Unknown => "❓",
        };

        let amount_display = match tx.transaction_direction {
            TransactionDirection::Inbound => format!("+{} μT", format_number(tx.value)),
            TransactionDirection::Outbound => format!("-{} μT", format_number(tx.value)),
            TransactionDirection::Unknown => format!("±{} μT", format_number(tx.value)),
        };

        let maturity_indicator = if tx.transaction_status.is_coinbase() && !tx.is_mature {
            " (IMMATURE)"
        } else {
            ""
        };

        let mut result = match tx.transaction_direction {
            TransactionDirection::Inbound => {
                let status = if tx.is_spent {
                    format!(
                        "SPENT in block {}",
                        format_number(tx.spent_in_block.unwrap_or(0))
                    )
                } else {
                    "UNSPENT".to_string()
                };

                format!(
                    "{}. {} Block {}, Output #{}: {} ({:.6} T) - {} [{}{}]",
                    format_number(index + 1),
                    direction_symbol,
                    format_number(tx.block_height),
                    format_number(tx.output_index.unwrap_or(0)),
                    amount_display,
                    tx.value as f64 / 1_000_000.0,
                    status,
                    tx.transaction_status,
                    maturity_indicator
                )
            }
            TransactionDirection::Outbound => {
                format!(
                    "{}. {} Block {}, Input #{}: {} ({:.6} T) - SPENDING [{}]",
                    format_number(index + 1),
                    direction_symbol,
                    format_number(tx.block_height),
                    format_number(tx.input_index.unwrap_or(0)),
                    amount_display,
                    tx.value as f64 / 1_000_000.0,
                    tx.transaction_status
                )
            }
            TransactionDirection::Unknown => {
                format!(
                    "{}. {} Block {}: {} ({:.6} T) - UNKNOWN [{}{}]",
                    format_number(index + 1),
                    direction_symbol,
                    format_number(tx.block_height),
                    amount_display,
                    tx.value as f64 / 1_000_000.0,
                    tx.transaction_status,
                    maturity_indicator
                )
            }
        };

        // Add spending details for spent inbound transactions
        if tx.transaction_direction == TransactionDirection::Inbound && tx.is_spent {
            if let Some(spent_block) = tx.spent_in_block {
                if let Some(spent_input) = tx.spent_in_input {
                    result.push_str(&format!(
                        "\n   └─ Spent as input #{} in block {}",
                        format_number(spent_input),
                        format_number(spent_block)
                    ));
                }
            }
        }

        result
    }

    /// Display wallet activity in detailed format
    fn display_detailed_wallet_activity(
        &self,
        wallet_state: &WalletState,
        scan_range: (u64, u64),
        output_config: &OutputConfig,
    ) -> io::Result<()> {
        let (from_block, to_block) = scan_range;

        if wallet_state.transactions.is_empty() {
            println!(
                "💡 No wallet activity found in blocks {} to {}",
                format_number(from_block),
                format_number(to_block)
            );
            if from_block > 1 {
                println!("   ⚠️  Note: Scanning from block {} - wallet history before this block was not checked", format_number(from_block));
                println!("   💡 For complete history, try scanning from block 1");
            }
            return Ok(());
        }

        // Display summary first
        self.display_wallet_summary(wallet_state, scan_range)?;

        println!("\n📋 DETAILED TRANSACTION HISTORY");
        println!("===============================");

        // Sort transactions by block height for chronological order
        let mut sorted_transactions: Vec<_> =
            wallet_state.transactions.iter().enumerate().collect();
        sorted_transactions.sort_by_key(|(_, tx)| tx.block_height);

        // Limit the number of transactions shown if configured
        let transactions_to_show = if let Some(max) = output_config.max_transactions_detailed {
            sorted_transactions.into_iter().take(max).collect()
        } else {
            sorted_transactions
        };

        for (original_index, tx) in transactions_to_show {
            println!(
                "{}",
                self.format_transaction(tx, original_index, output_config)
            );
        }

        // Show truncation notice if applicable
        if let Some(max) = output_config.max_transactions_detailed {
            if wallet_state.transactions.len() > max {
                println!(
                    "\n⚠️  Showing {} of {} transactions (truncated for readability)",
                    format_number(max),
                    format_number(wallet_state.transactions.len())
                );
            }
        }

        Ok(())
    }

    /// Display wallet summary
    fn display_wallet_summary(
        &self,
        wallet_state: &WalletState,
        scan_range: (u64, u64),
    ) -> io::Result<()> {
        let (from_block, to_block) = scan_range;
        let (total_received, total_spent, balance, _unspent_count, _spent_count) =
            wallet_state.get_summary();
        let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();

        println!("🏦 WALLET ACTIVITY SUMMARY");
        println!("========================");
        println!(
            "Scan range: Block {} to {} ({} blocks)",
            format_number(from_block),
            format_number(to_block),
            format_number(to_block - from_block + 1)
        );

        println!(
            "📥 Inbound:  {} transactions, {} μT ({:.6} T)",
            format_number(inbound_count),
            format_number(total_received),
            total_received as f64 / 1_000_000.0
        );
        println!(
            "📤 Outbound: {} transactions, {} μT ({:.6} T)",
            format_number(outbound_count),
            format_number(total_spent),
            total_spent as f64 / 1_000_000.0
        );
        println!(
            "💰 Current balance: {} μT ({:.6} T)",
            format_number(balance),
            balance as f64 / 1_000_000.0
        );
        println!(
            "📊 Total activity: {} transactions",
            format_number(wallet_state.transactions.len())
        );

        Ok(())
    }
}

impl OutputFormatter for ConsoleFormatter {
    fn display_scan_info(
        &self,
        config_display: &ScanConfigDisplay,
        _output_config: &OutputConfig,
    ) -> io::Result<()> {
        if let Some(ref specific_blocks) = config_display.specific_blocks {
            println!(
                "🔍 Scanning {} specific blocks: {}",
                format_number(specific_blocks.len()),
                if specific_blocks.len() <= 10 {
                    specific_blocks
                        .iter()
                        .map(|h| format_number(*h))
                        .collect::<Vec<_>>()
                        .join(", ")
                } else {
                    format!(
                        "{}..{} and {} others",
                        format_number(specific_blocks[0]),
                        format_number(specific_blocks.last().copied().unwrap_or(0)),
                        format_number(specific_blocks.len() - 2)
                    )
                }
            );
        } else {
            println!(
                "🔍 Scanning blocks {} to {} ({} blocks total)...",
                format_number(config_display.start_height),
                format_number(config_display.end_height),
                format_number(config_display.total_blocks)
            );
        }

        println!();
        Ok(())
    }

    fn display_scan_results(
        &self,
        results: &ScanResults,
        output_config: &OutputConfig,
    ) -> io::Result<()> {
        match output_config.format {
            OutputFormat::Detailed => {
                self.display_detailed_wallet_activity(
                    &results.wallet_state,
                    (
                        results.scan_config_summary.start_height,
                        results
                            .scan_config_summary
                            .end_height
                            .unwrap_or(results.scan_config_summary.start_height),
                    ),
                    output_config,
                )?;
            }
            OutputFormat::Summary => {
                self.display_wallet_summary(
                    &results.wallet_state,
                    (
                        results.scan_config_summary.start_height,
                        results
                            .scan_config_summary
                            .end_height
                            .unwrap_or(results.scan_config_summary.start_height),
                    ),
                )?;
            }
            OutputFormat::Json => {
                // JSON output handled by JsonFormatter
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "JSON format not supported by ConsoleFormatter",
                ));
            }
            OutputFormat::Quiet => {
                // Minimal output
                let (_total_received, _, balance, _, _) = results.wallet_state.get_summary();
                if results.wallet_state.transactions.is_empty() {
                    println!("No activity found");
                } else {
                    println!(
                        "Found {} transactions, balance: {:.6} T",
                        format_number(results.wallet_state.transactions.len()),
                        balance as f64 / 1_000_000.0
                    );
                }
            }
        }

        Ok(())
    }

    fn display_wallet_activity(
        &self,
        wallet_state: &WalletState,
        scan_range: (u64, u64),
        output_config: &OutputConfig,
    ) -> io::Result<()> {
        match output_config.format {
            OutputFormat::Detailed => {
                self.display_detailed_wallet_activity(wallet_state, scan_range, output_config)
            }
            OutputFormat::Summary | OutputFormat::Quiet => {
                self.display_wallet_summary(wallet_state, scan_range)
            }
            OutputFormat::Json => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "JSON format not supported by ConsoleFormatter",
            )),
        }
    }

    fn display_error(&self, error: &str, _output_config: &OutputConfig) -> io::Result<()> {
        eprintln!("❌ {}", error);
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        io::stdout().flush()
    }
}

/// JSON output formatter
#[derive(Debug, Default)]
pub struct JsonFormatter;

impl JsonFormatter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert wallet state to JSON value
    fn wallet_state_to_json(&self, wallet_state: &WalletState, include_metadata: bool) -> Value {
        let (total_received, total_spent, balance, unspent_count, spent_count) =
            wallet_state.get_summary();
        let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();

        let mut json_obj = json!({
            "summary": {
                "total_transactions": wallet_state.transactions.len(),
                "inbound_count": inbound_count,
                "outbound_count": outbound_count,
                "total_received": total_received,
                "total_spent": total_spent,
                "current_balance": balance,
                "unspent_outputs": unspent_count,
                "spent_outputs": spent_count
            }
        });

        if include_metadata {
            let transactions: Vec<Value> = wallet_state
                .transactions
                .iter()
                .map(|tx| {
                    json!({
                        "block_height": tx.block_height,
                        "transaction_direction": match tx.transaction_direction {
                            TransactionDirection::Inbound => "inbound",
                            TransactionDirection::Outbound => "outbound",
                            TransactionDirection::Unknown => "unknown",
                        },
                        "value": tx.value,
                        "is_spent": tx.is_spent,
                        "is_mature": tx.is_mature,
                        "output_index": tx.output_index,
                        "input_index": tx.input_index,
                        "spent_in_block": tx.spent_in_block,
                        "spent_in_input": tx.spent_in_input,
                        "transaction_status": tx.transaction_status.to_string(),
                    })
                })
                .collect();

            json_obj["transactions"] = Value::Array(transactions);
        }

        json_obj
    }
}

impl OutputFormatter for JsonFormatter {
    fn display_scan_info(
        &self,
        config_display: &ScanConfigDisplay,
        _output_config: &OutputConfig,
    ) -> io::Result<()> {
        let config_json = json!({
            "scan_config": {
                "start_height": config_display.start_height,
                "end_height": config_display.end_height,
                "specific_blocks": config_display.specific_blocks,
                "total_blocks": config_display.total_blocks,
                "batch_size": config_display.batch_size
            }
        });

        println!("{}", serde_json::to_string_pretty(&config_json).unwrap());
        Ok(())
    }

    fn display_scan_results(
        &self,
        results: &ScanResults,
        output_config: &OutputConfig,
    ) -> io::Result<()> {
        let json_output =
            self.wallet_state_to_json(&results.wallet_state, output_config.include_metadata);
        println!("{}", serde_json::to_string_pretty(&json_output).unwrap());
        Ok(())
    }

    fn display_wallet_activity(
        &self,
        wallet_state: &WalletState,
        scan_range: (u64, u64),
        output_config: &OutputConfig,
    ) -> io::Result<()> {
        let mut json_output =
            self.wallet_state_to_json(wallet_state, output_config.include_metadata);

        // Add scan range information
        json_output["scan_info"] = json!({
            "start_block": scan_range.0,
            "end_block": scan_range.1,
            "blocks_scanned": scan_range.1 - scan_range.0 + 1
        });

        println!("{}", serde_json::to_string_pretty(&json_output).unwrap());
        Ok(())
    }

    fn display_error(&self, error: &str, _output_config: &OutputConfig) -> io::Result<()> {
        let error_json = json!({
            "error": error
        });
        eprintln!("{}", serde_json::to_string_pretty(&error_json).unwrap());
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        io::stdout().flush()
    }
}

/// Creates an output formatter based on the configuration
pub fn create_output_formatter(format: OutputFormat) -> Box<dyn OutputFormatter> {
    match format {
        OutputFormat::Json => Box::new(JsonFormatter::new()),
        OutputFormat::Detailed | OutputFormat::Summary | OutputFormat::Quiet => {
            Box::new(ConsoleFormatter::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_from_str() {
        assert_eq!(
            OutputFormat::from_str("detailed").unwrap(),
            OutputFormat::Detailed
        );
        assert_eq!(
            OutputFormat::from_str("summary").unwrap(),
            OutputFormat::Summary
        );
        assert_eq!(OutputFormat::from_str("json").unwrap(), OutputFormat::Json);
        assert_eq!(
            OutputFormat::from_str("quiet").unwrap(),
            OutputFormat::Quiet
        );
        assert!(OutputFormat::from_str("invalid").is_err());
    }

    #[test]
    fn test_output_format_as_str() {
        assert_eq!(OutputFormat::Detailed.as_str(), "detailed");
        assert_eq!(OutputFormat::Summary.as_str(), "summary");
        assert_eq!(OutputFormat::Json.as_str(), "json");
        assert_eq!(OutputFormat::Quiet.as_str(), "quiet");
    }

    #[test]
    fn test_output_config_default() {
        let config = OutputConfig::default();
        assert_eq!(config.format, OutputFormat::Summary);
        assert!(config.use_colors);
        assert!(config.show_timestamps);
        assert!(config.include_metadata);
    }

    #[test]
    fn test_create_output_formatter() {
        let console_formatter = create_output_formatter(OutputFormat::Summary);
        let json_formatter = create_output_formatter(OutputFormat::Json);

        // Should create successfully (both are ZSTs but boxed trait objects have metadata)
        // Test that they can be used successfully instead of checking size
        assert!(console_formatter.as_ref() as *const _ as *const () != std::ptr::null());
        assert!(json_formatter.as_ref() as *const _ as *const () != std::ptr::null());
    }
}
