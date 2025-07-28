//! Enhanced Tari Wallet Scanner
//!
//! A comprehensive wallet scanner that tracks all transactions across blocks,
//! maintains complete transaction history, and provides accurate running balances.

#![cfg(not(target_arch = "wasm32"))]
//!
//! ## Features
//! - Cross-block transaction tracking
//! - Complete wallet state management
//! - Running balance calculation
//! - Clean, user-friendly output with bash-style progress bars
//! - Automatic scan from wallet birthday to chain tip
//! - **Batch processing for improved performance (up to 100 blocks per batch)**
//! - **Graceful error handling with resume functionality**
//!
//! ## Error Handling & Interruption
//! When GRPC errors occur (e.g., "message length too large"), the scanner will:
//! - Display the exact block height and error details
//! - Offer interactive options: Continue (y), Skip block (s), or Abort (n)
//! - Provide resume commands for easy restart from the failed point
//! - Example: `cargo run --bin scanner --features grpc-storage -- --from-block 25000 --to-block 30000`
//!
//! **Graceful Ctrl+C Support:**
//! - Press Ctrl+C to cleanly interrupt any scan
//! - Partial results are preserved and displayed
//! - Automatic resume command generation for continuing from interruption point
//!
//! ## Usage
//! ```bash
//! # Scan with wallet from birthday to tip using seed phrase (memory only)
//! cargo run --bin scanner --features grpc-storage -- --seed-phrase "your seed phrase here"
//!
//! # Scan using private view key (hex format, 64 characters, memory only)
//! cargo run --bin scanner --features grpc-storage -- --view-key "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab"
//!
//! # Scan specific range with view key (memory only)
//! cargo run --bin scanner --features grpc-storage -- --view-key "your_view_key_here" --from-block 34920 --to-block 34930
//!
//! # Scan specific blocks only (memory only)
//! cargo run --bin scanner --features grpc-storage -- --seed-phrase "your seed phrase" --blocks 1000,2000,5000,10000
//!
//! # Use custom base node URL (memory only)
//! cargo run --bin scanner --features grpc-storage -- --seed-phrase "your seed phrase" --base-url "http://192.168.1.100:18142"
//!
//! # Quiet mode with JSON output (script-friendly, memory only)
//! cargo run --bin scanner --features grpc-storage -- --view-key "your_view_key" --quiet --format json
//!
//! # Summary output with minimal progress updates (memory only)
//! cargo run --bin scanner --features grpc-storage -- --seed-phrase "your seed phrase" --format summary --progress-frequency 50
//!
//! # *** DATABASE STORAGE FEATURES (requires 'grpc-storage' feature) ***
//! # Resume scanning from stored wallet (uses default database ./wallet.db)
//! # If multiple wallets exist, scanner will show a list to choose from
//! cargo run --bin scanner --features grpc-storage
//!
//! # Resume from specific database file
//! cargo run --bin scanner --features grpc-storage -- --database custom_wallet.db
//!
//! # Resume from specific wallet in database
//! cargo run --bin scanner --features grpc-storage -- --wallet-name "my-wallet"
//!
//! # Use in-memory database (useful for testing)
//! cargo run --bin scanner --features grpc-storage -- --database ":memory:"
//!
//! # *** WALLET MANAGEMENT FEATURES ***
//! # Use specific wallet for scanning
//! cargo run --bin scanner --features grpc-storage -- --database wallet.db --wallet-name "my-wallet"
//!
//! # Interactive wallet selection:
//! # - If no wallet exists: prompts to create one (if keys provided) or shows error
//! # - If one wallet exists: automatically uses it
//! # - If multiple wallets exist: shows interactive list to choose from
//! cargo run --bin scanner --features grpc-storage -- --database wallet.db
//!
//! # NOTE: To list or create wallets, use the wallet binary:
//! cargo run --bin wallet --features storage list-wallets
//! cargo run --bin wallet --features storage create-wallet "seed phrase" --name "wallet-name"
//!
//! # Show help
//! cargo run --bin scanner --features grpc-storage -- --help
//! ```
//!
//! ## View Key vs Seed Phrase
//!
//! **Seed Phrase Mode:**
//! - Full wallet functionality
//! - Automatic wallet birthday detection
//! - Requires seed phrase security
//! - Uses memory-only storage when keys provided
//!
//! **View Key Mode:**
//! - View-only access with encrypted data decryption
//! - Starts from genesis by default (can be overridden)
//! - More secure for monitoring purposes
//! - View key format: 64-character hex string (32 bytes)
//! - Uses memory-only storage when keys provided
//!
//! **Database Resume Mode:**
//! - No keys required - loads from stored wallet
//! - Automatically resumes from last scanned block
//! - Persistent transaction history

#[cfg(feature = "grpc")]
use clap::Parser;

#[cfg(feature = "grpc")]
use lightweight_wallet_libs::{
    common::format_number,
    data_structures::{
        payment_id::PaymentId, transaction::TransactionDirection, wallet_transaction::WalletState,
    },
    errors::LightweightWalletResult,
    scanning::{
        BinaryScanConfig, BlockchainScanner, GrpcScannerBuilder, OutputFormat, ProgressInfo,
        ScanResult, ScannerStorage, WalletScannerStruct,
    },
    KeyManagementError, LightweightWalletError,
};
#[cfg(feature = "grpc")]
use tari_utilities::ByteArray;
#[cfg(feature = "grpc")]
use tokio::signal;

// Background writer imports moved to src/scanning/background_writer.rs

/// Enhanced Tari Wallet Scanner CLI
#[cfg(feature = "grpc")]
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    /// Seed phrase for the wallet (uses memory-only storage when provided)
    #[arg(
        short,
        long,
        help = "Seed phrase for the wallet (uses memory-only storage)"
    )]
    seed_phrase: Option<String>,

    /// Private view key in hex format (alternative to seed phrase, uses memory-only storage)
    #[arg(
        long,
        help = "Private view key in hex format (64 characters). Uses memory-only storage. Not required when resuming from database"
    )]
    view_key: Option<String>,

    /// Base URL for the Tari base node GRPC endpoint
    #[arg(
        short,
        long,
        default_value = "http://127.0.0.1:18142",
        help = "Base URL for Tari base node GRPC"
    )]
    base_url: String,

    /// Starting block height for scanning
    #[arg(
        long,
        help = "Starting block height (defaults to wallet birthday or last scanned block)"
    )]
    from_block: Option<u64>,

    /// Ending block height for scanning
    #[arg(long, help = "Ending block height (defaults to current tip)")]
    to_block: Option<u64>,

    /// Specific block heights to scan (comma-separated)
    #[arg(
        long,
        help = "Specific block heights to scan (comma-separated). If provided, overrides from-block and to-block",
        value_delimiter = ','
    )]
    blocks: Option<Vec<u64>>,

    /// Batch size for scanning
    #[arg(long, default_value = "10", help = "Batch size for scanning")]
    batch_size: usize,

    /// Progress update frequency
    #[arg(long, default_value = "10", help = "Update progress every N blocks")]
    progress_frequency: usize,

    /// Quiet mode - minimal output
    #[arg(short, long, help = "Quiet mode - only show essential information")]
    quiet: bool,

    /// Output format
    #[arg(
        long,
        default_value = "summary",
        help = "Output format: detailed, summary, json"
    )]
    format: String,

    /// Database file path for storing transactions
    #[arg(
        long,
        default_value = "./wallet.db",
        help = "SQLite database file path for storing transactions. Only used when no keys are provided"
    )]
    database: String,

    /// Wallet name to use for scanning (when using database storage)
    #[arg(
        long,
        help = "Wallet name to use for scanning. If not provided with database, will prompt for selection or creation"
    )]
    wallet_name: Option<String>,
}

// BinaryScanConfig moved to src/scanning/scan_config.rs

// OutputFormat moved to src/scanning/scan_config.rs

// BackgroundWriter, BackgroundWriterCommand, and ScannerStorage moved to src/scanning/

// ScannerStorage implementation moved to src/scanning/storage_manager.rs
// The implementation methods will be moved in tasks 3.5, 3.6, and 3.7

// Display helper functions for the scanner binary
#[cfg(feature = "storage")]
async fn display_storage_info(
    storage_backend: &ScannerStorage,
    config: &BinaryScanConfig,
) -> LightweightWalletResult<()> {
    if config.quiet {
        return Ok(());
    }

    if storage_backend.is_memory_only {
        println!("💭 Using in-memory storage (transactions will not be persisted)");
        return Ok(());
    }

    if let Some(db_path) = &config.database_path {
        println!("💾 Using SQLite database: {db_path}");
    } else {
        println!("💾 Using in-memory database");
    }

    // Show existing data if any
    let stats = storage_backend.get_statistics().await?;
    if stats.total_transactions > 0 {
        println!(
            "📄 Existing data: {} transactions, balance: {:.6} T, blocks: {}-{}",
            format_number(stats.total_transactions),
            stats.current_balance as f64 / 1_000_000.0,
            format_number(stats.lowest_block.unwrap_or(0)),
            format_number(stats.highest_block.unwrap_or(0))
        );
    }

    Ok(())
}

#[cfg(feature = "storage")]
async fn display_completion_info(
    storage_backend: &ScannerStorage,
    config: &BinaryScanConfig,
) -> LightweightWalletResult<()> {
    if config.quiet {
        return Ok(());
    }

    if storage_backend.is_memory_only {
        println!("💭 Transactions stored in memory only (not persisted)");
        return Ok(());
    }

    let stats = storage_backend.get_statistics().await?;
    println!(
        "💾 Database updated: {} total transactions stored",
        format_number(stats.total_transactions)
    );
    println!(
        "📍 Next scan can resume from block {}",
        format_number(stats.highest_block.unwrap_or(0) + 1)
    );

    // Also show UTXO output count if available
    let utxo_count = storage_backend.get_unspent_outputs_count().await?;
    if utxo_count > 0 {
        println!("🔗 UTXO outputs stored: {}", format_number(utxo_count));
    }

    Ok(())
}

// ScanContext moved to src/scanning/scan_config.rs

// Progress display function for the scanner binary
#[cfg(feature = "grpc")]
#[allow(dead_code)]
fn display_progress(progress_info: &ProgressInfo) {
    print!("\r🔍 Progress: {:.1}% ({}/{}) | Block {} | {:.1} blocks/s | Found: {} outputs, {} spent   ",
        progress_info.progress_percent,
        format_number(progress_info.blocks_processed),
        format_number(progress_info.total_blocks),
        format_number(progress_info.current_block),
        progress_info.blocks_per_sec,
        format_number(progress_info.outputs_found),
        format_number(progress_info.inputs_found)
    );
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
}

#[cfg(feature = "grpc")]
pub struct BlockHeightRange {
    pub from_block: u64,
    pub to_block: u64,
    pub block_heights: Option<Vec<u64>>,
}

#[cfg(feature = "grpc")]
impl BlockHeightRange {
    pub fn new(from_block: u64, to_block: u64, block_heights: Option<Vec<u64>>) -> Self {
        Self {
            from_block,
            to_block,
            block_heights,
        }
    }

    pub fn into_scan_config(self, args: &CliArgs) -> LightweightWalletResult<BinaryScanConfig> {
        let output_format = args
            .format
            .parse()
            .map_err(|e: String| KeyManagementError::key_derivation_failed(&e))?;

        Ok(BinaryScanConfig {
            from_block: self.from_block,
            to_block: self.to_block,
            block_heights: self.block_heights,
            progress_frequency: args.progress_frequency,
            quiet: args.quiet,
            output_format,
            batch_size: args.batch_size,
            database_path: Some(args.database.clone()),
            wallet_name: args.wallet_name.clone(),
            explicit_from_block: args.from_block,
            use_database: args.seed_phrase.is_none() && args.view_key.is_none(),
        })
    }
}

/// Handle errors during block scanning (updated for batch processing)
#[cfg(feature = "grpc")]
#[allow(dead_code)]
fn handle_scan_error(
    error_block_height: u64,
    remaining_blocks: &[u64],
    has_specific_blocks: bool,
    to_block: u64,
) -> bool {
    // Ask user if they want to continue
    print!("   Continue scanning remaining blocks? (y/n/s=skip this batch/block): ");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false; // Abort on input error
    }
    let choice = input.trim().to_lowercase();

    match choice.as_str() {
        "y" | "yes" => {
            println!("   ✅ Continuing scan from next batch/block...");
            true // Continue
        }
        "s" | "skip" => {
            println!("   ⏭️  Skipping problematic batch/block and continuing...");
            true // Continue (skip this batch/block)
        }
        _ => {
            println!(
                "   🛑 Scan aborted by user at block {}",
                format_number(error_block_height)
            );
            println!("\n💡 To resume from this point, run:");
            if has_specific_blocks {
                let remaining_blocks_str: Vec<String> =
                    remaining_blocks.iter().map(|b| b.to_string()).collect();
                if remaining_blocks_str.len() <= 20 {
                    println!("   cargo run --bin scanner --features grpc-storage -- --seed-phrase \"your seed phrase\" --blocks {}", 
                        remaining_blocks_str.join(","));
                } else {
                    // For large lists, show range instead
                    let first_block = remaining_blocks.first().unwrap_or(&error_block_height);
                    let last_block = remaining_blocks.last().unwrap_or(&to_block);
                    println!("   cargo run --bin scanner --features grpc-storage -- --seed-phrase \"your seed phrase\" --from-block {} --to-block {}", format_number(*first_block), format_number(*last_block));
                }
            } else {
                println!("   cargo run --bin scanner --features grpc-storage -- --seed-phrase \"your seed phrase\" --from-block {} --to-block {}", format_number(error_block_height), format_number(to_block));
            }
            false // Abort
        }
    }
}

/// Result type that can indicate if scan was interrupted
#[cfg(feature = "grpc")]

/// Display scan configuration information
#[cfg(feature = "grpc")]
#[allow(dead_code)]
fn display_scan_info(config: &BinaryScanConfig, block_heights: &[u64], has_specific_blocks: bool) {
    if has_specific_blocks {
        println!(
            "🔍 Scanning {} specific blocks: {:?}",
            format_number(block_heights.len()),
            if block_heights.len() <= 10 {
                block_heights
                    .iter()
                    .map(|h| format_number(*h))
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                format!(
                    "{}..{} and {} others",
                    format_number(block_heights[0]),
                    format_number(block_heights.last().copied().unwrap_or(0)),
                    format_number(block_heights.len() - 2)
                )
            }
        );
    } else {
        let block_range = config.to_block - config.from_block + 1;
        println!(
            "🔍 Scanning blocks {} to {} ({} blocks total)...",
            format_number(config.from_block),
            format_number(config.to_block),
            format_number(block_range)
        );
    }

    println!();
}

#[cfg(feature = "grpc")]
fn display_wallet_activity(wallet_state: &WalletState, from_block: u64, to_block: u64) {
    let (total_received, total_spent, balance, unspent_count, spent_count) =
        wallet_state.get_summary();
    let total_count = wallet_state.transactions.len();

    if total_count == 0 {
        println!(
            "💡 No wallet activity found in blocks {} to {}",
            format_number(from_block),
            format_number(to_block)
        );
        if from_block > 1 {
            println!("   ⚠️  Note: Scanning from block {} - wallet history before this block was not checked", format_number(from_block));
            println!("   💡 For complete history, try: cargo run --bin scanner --features grpc-storage -- --seed-phrase \"your seed phrase\" --from-block 1");
        }
        return;
    }

    println!("🏦 WALLET ACTIVITY SUMMARY");
    println!("========================");
    println!(
        "Scan range: Block {} to {} ({} blocks)",
        format_number(from_block),
        format_number(to_block),
        format_number(to_block - from_block + 1)
    );

    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();
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
        format_number(total_count)
    );
    println!();

    if !wallet_state.transactions.is_empty() {
        println!("📋 DETAILED TRANSACTION HISTORY");
        println!("===============================");

        // Sort transactions by block height for chronological order
        let mut sorted_transactions: Vec<_> =
            wallet_state.transactions.iter().enumerate().collect();
        sorted_transactions.sort_by_key(|(_, tx)| tx.block_height);

        // Create a mapping from commitments to transactions for spent tracking
        let mut commitment_to_inbound: std::collections::HashMap<
            Vec<u8>,
            &lightweight_wallet_libs::data_structures::wallet_transaction::WalletTransaction,
        > = std::collections::HashMap::new();
        for tx in &wallet_state.transactions {
            if tx.transaction_direction == TransactionDirection::Inbound {
                commitment_to_inbound.insert(tx.commitment.as_bytes().to_vec(), tx);
            }
        }

        for (original_index, tx) in sorted_transactions {
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

            // Different display format for inbound vs outbound
            match tx.transaction_direction {
                TransactionDirection::Inbound => {
                    let status = if tx.is_spent {
                        format!(
                            "SPENT in block {}",
                            format_number(tx.spent_in_block.unwrap_or(0))
                        )
                    } else {
                        "UNSPENT".to_string()
                    };

                    println!(
                        "{}. {} Block {}, Output #{}: {} ({:.6} T) - {} [{}{}]",
                        format_number(original_index + 1),
                        direction_symbol,
                        format_number(tx.block_height),
                        format_number(tx.output_index.unwrap_or(0)),
                        amount_display,
                        tx.value as f64 / 1_000_000.0,
                        status,
                        tx.transaction_status,
                        maturity_indicator
                    );

                    // Show spending details if this output was spent
                    if tx.is_spent {
                        if let Some(spent_block) = tx.spent_in_block {
                            if let Some(spent_input) = tx.spent_in_input {
                                println!(
                                    "   └─ Spent as input #{} in block {}",
                                    format_number(spent_input),
                                    format_number(spent_block)
                                );
                            }
                        }
                    }
                }
                TransactionDirection::Outbound => {
                    println!(
                        "{}. {} Block {}, Input #{}: {} ({:.6} T) - SPENDING [{}]",
                        format_number(original_index + 1),
                        direction_symbol,
                        format_number(tx.block_height),
                        format_number(tx.input_index.unwrap_or(0)),
                        amount_display,
                        tx.value as f64 / 1_000_000.0,
                        tx.transaction_status
                    );

                    // Try to find which output this is spending
                    let commitment_bytes = tx.commitment.as_bytes().to_vec();
                    if let Some(original_tx) = commitment_to_inbound.get(&commitment_bytes) {
                        println!(
                            "   └─ Spending output from block {} (output #{})",
                            format_number(original_tx.block_height),
                            format_number(original_tx.output_index.unwrap_or(0))
                        );
                    }
                }
                TransactionDirection::Unknown => {
                    println!(
                        "{}. {} Block {}: {} ({:.6} T) - UNKNOWN [{}]",
                        format_number(original_index + 1),
                        direction_symbol,
                        format_number(tx.block_height),
                        amount_display,
                        tx.value as f64 / 1_000_000.0,
                        tx.transaction_status
                    );
                }
            }

            // Show payment ID if not empty
            match &tx.payment_id {
                PaymentId::Empty => {}
                PaymentId::Open { user_data, .. } if !user_data.is_empty() => {
                    // Try to decode as UTF-8 string
                    if let Ok(text) = std::str::from_utf8(user_data) {
                        if text
                            .chars()
                            .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                        {
                            println!("   💬 Payment ID: \"{text}\"");
                        } else {
                            println!("   💬 Payment ID (hex): {}", hex::encode(user_data));
                        }
                    } else {
                        println!("   💬 Payment ID (hex): {}", hex::encode(user_data));
                    }
                }
                PaymentId::TransactionInfo { user_data, .. } if !user_data.is_empty() => {
                    // Convert the binary data to utf8 string if possible otherwise print as hex
                    if let Ok(text) = std::str::from_utf8(user_data) {
                        println!("   💬 Payment ID: \"{text}\"");
                    } else {
                        println!("   💬 Payment ID (hex): {}", hex::encode(user_data));
                    }
                }
                _ => {
                    let user_data_str = tx.payment_id.user_data_as_string();
                    if !user_data_str.is_empty() {
                        println!("   💬 Payment ID: \"{user_data_str}\"");
                    }
                }
            }
        }
        println!();
    }

    // Show balance breakdown
    let unspent_value = wallet_state.get_unspent_value();

    println!("💰 BALANCE BREAKDOWN");
    println!("===================");
    println!(
        "Unspent outputs: {} ({:.6} T)",
        format_number(unspent_count),
        unspent_value as f64 / 1_000_000.0
    );
    println!(
        "Spent outputs: {} ({:.6} T)",
        format_number(spent_count),
        total_spent as f64 / 1_000_000.0
    );
    println!(
        "Total wallet activity: {} transactions",
        format_number(total_count)
    );

    // Show detailed transaction analysis
    let (inbound_count, outbound_count, unknown_count) = wallet_state.get_direction_counts();
    let inbound_transactions = wallet_state.get_inbound_transactions();
    let outbound_transactions = wallet_state.get_outbound_transactions();

    // Calculate values for inbound and outbound
    let total_inbound_value: u64 = inbound_transactions.iter().map(|tx| tx.value).sum();
    let total_outbound_value: u64 = outbound_transactions.iter().map(|tx| tx.value).sum();

    if !wallet_state.transactions.is_empty() {
        println!();
        println!("📊 TRANSACTION FLOW ANALYSIS");
        println!("============================");
        println!(
            "📥 Inbound:  {} transactions, {:.6} T total",
            format_number(inbound_count),
            total_inbound_value as f64 / 1_000_000.0
        );
        println!(
            "📤 Outbound: {} transactions, {:.6} T total",
            format_number(outbound_count),
            total_outbound_value as f64 / 1_000_000.0
        );
        if unknown_count > 0 {
            println!("❓ Unknown:  {} transactions", format_number(unknown_count));
        }

        // Show transaction status breakdown
        let mut status_counts = std::collections::HashMap::new();
        let mut coinbase_immature = 0;
        for tx in &wallet_state.transactions {
            *status_counts.entry(tx.transaction_status).or_insert(0) += 1;
            if tx.transaction_status.is_coinbase() && !tx.is_mature {
                coinbase_immature += 1;
            }
        }

        println!();
        println!("📊 TRANSACTION STATUS BREAKDOWN");
        println!("==============================");
        for (status, count) in status_counts {
            if status.is_coinbase() && coinbase_immature > 0 {
                println!(
                    "{}: {} ({} immature)",
                    status,
                    format_number(count),
                    format_number(coinbase_immature)
                );
            } else {
                println!("{}: {}", status, format_number(count));
            }
        }

        // Show net flow
        let net_flow = total_inbound_value as i64 - total_outbound_value as i64;
        println!();
        println!("📊 NET FLOW SUMMARY");
        println!("==================");
        println!(
            "Net flow: {:.6} T ({})",
            net_flow as f64 / 1_000_000.0,
            if net_flow > 0 {
                "📈 Positive"
            } else if net_flow < 0 {
                "📉 Negative"
            } else {
                "⚖️  Neutral"
            }
        );
        println!(
            "Current balance: {:.6} T",
            wallet_state.get_balance() as f64 / 1_000_000.0
        );
    }
}

#[cfg(feature = "grpc")]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = CliArgs::parse();

    // Validate input arguments
    let keys_provided = args.seed_phrase.is_some() || args.view_key.is_some();

    match (&args.seed_phrase, &args.view_key) {
        (Some(_), Some(_)) => {
            eprintln!("❌ Error: Cannot specify both --seed-phrase and --view-key. Choose one.");
            std::process::exit(1);
        }
        (None, None) => {
            // Allow no keys - will try to load from database
            if !args.quiet {
                println!("🔑 No keys provided - will load from database...");
            }
        }
        _ => {} // Valid: exactly one is provided
    }

    if !args.quiet {
        println!("🚀 Enhanced Tari Wallet Scanner");
        println!("===============================");
    }

    // Create scan context based on input method (or defer if resuming from database)
    let (scan_context, default_from_block) = if keys_provided {
        if let Some(seed_phrase) = &args.seed_phrase {
            if !args.quiet {
                println!("🔨 Creating wallet from seed phrase...");
            }
            let (scan_context, default_from_block) =
                lightweight_wallet_libs::scanning::create_wallet_from_seed_phrase(seed_phrase)?;
            (Some(scan_context), default_from_block)
        } else if let Some(view_key_hex) = &args.view_key {
            if !args.quiet {
                println!("🔑 Creating scan context from view key...");
            }
            let (scan_context, default_from_block) =
                lightweight_wallet_libs::scanning::create_wallet_from_view_key(view_key_hex)?;
            (Some(scan_context), default_from_block)
        } else {
            unreachable!("Keys provided but neither seed phrase nor view key found");
        }
    } else {
        // Keys will be loaded from database wallet
        if !args.quiet {
            println!("🔑 Will load wallet keys from database...");
        }
        (None, args.from_block.unwrap_or(0)) // Default from block will be set from wallet birthday
    };

    // Connect to base node
    if !args.quiet {
        println!("🌐 Connecting to Tari base node...");
    }
    let mut scanner = GrpcScannerBuilder::new()
        .with_base_url(args.base_url.clone())
        .with_timeout(std::time::Duration::from_secs(30))
        .build()
        .await
        .map_err(|e| {
            if !args.quiet {
                eprintln!("❌ Failed to connect to Tari base node: {e}");
                eprintln!("💡 Make sure tari_base_node is running with GRPC enabled on port 18142");
            }
            e
        })?;

    if !args.quiet {
        println!("✅ Connected to Tari base node successfully");
    }

    // Get blockchain tip and determine scan range
    let tip_info = scanner.get_tip_info().await?;
    if !args.quiet {
        println!(
            "📊 Current blockchain tip: block {}",
            format_number(tip_info.best_block_height)
        );
    }

    let to_block = args.to_block.unwrap_or(tip_info.best_block_height);

    // Create temporary config for storage operations (will be recreated with correct from_block later)
    let temp_block_height_range = BlockHeightRange::new(0, to_block, args.blocks.clone());
    let temp_config = temp_block_height_range.into_scan_config(&args)?;

    // Create storage backend - use database when no keys provided, memory when keys provided
    let mut storage_backend = if keys_provided {
        // Keys provided - use memory-only storage
        ScannerStorage::new_memory()
    } else {
        // No keys provided - use database storage
        #[cfg(feature = "storage")]
        {
            ScannerStorage::new_with_database(&args.database).await?
        }
        #[cfg(not(feature = "storage"))]
        {
            ScannerStorage::new_memory()
        }
    };

    // Handle wallet operations for database storage (only when no keys provided)
    #[cfg(feature = "storage")]
    let (loaded_scan_context, wallet_birthday) = if keys_provided {
        // Keys provided directly - skip database operations entirely
        (None, None)
    } else {
        // No keys provided - use database storage
        let loaded_context = storage_backend
            .handle_wallet_operations(&temp_config, scan_context.as_ref())
            .await?;

        // Get wallet birthday if we have a wallet
        let wallet_birthday = if args.from_block.is_none() {
            storage_backend.get_wallet_birthday().await?
        } else {
            None
        };

        (loaded_context, wallet_birthday)
    };

    #[cfg(not(feature = "storage"))]
    let (loaded_scan_context, wallet_birthday): (Option<ScanContext>, Option<u64>) = (None, None);

    // Use loaded scan context if we didn't have one initially, or fall back to provided scan context
    let final_scan_context = if let Some(loaded_context) = loaded_scan_context {
        loaded_context
    } else if let Some(context) = scan_context {
        context
    } else {
        return Err(LightweightWalletError::InvalidArgument {
            argument: "scan_context".to_string(),
            value: "None".to_string(),
            message: "No scan context available - provide keys or use existing wallet".to_string(),
        });
    };

    // Storage backend already has wallet_id set from wallet operations

    // Calculate final default from block (outside conditional compilation)
    let final_default_from_block = wallet_birthday.unwrap_or(default_from_block);

    // Now calculate the from_block using the final_default_from_block
    let from_block = args.from_block.unwrap_or(final_default_from_block);

    // Update the config with the correct from_block
    let block_height_range = BlockHeightRange::new(from_block, to_block, args.blocks.clone());
    let config = block_height_range.into_scan_config(&args)?;

    // Start background writer for non-WASM32 architectures (if using database storage)
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    if !storage_backend.is_memory_only {
        if !args.quiet {
            println!("🚀 Starting background database writer...");
        }
        storage_backend
            .start_background_writer(&args.database)
            .await?;
    }

    // Display storage info and existing data
    if !args.quiet {
        display_storage_info(&storage_backend, &config).await?;
    }

    // Setup cancellation mechanism
    let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);

    // Setup ctrl-c handling
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
        let _ = cancel_tx.send(true);
    };

    // Perform the scan with cancellation support using the library's WalletScanner
    let mut wallet_scanner = WalletScannerStruct::new();
    let scan_result = tokio::select! {
        result = wallet_scanner.scan(&mut scanner, &final_scan_context, &config, &mut storage_backend, &mut cancel_rx) => {
            Some(result)
        }
        _ = ctrl_c => {
            if !args.quiet {
                println!("\n\n🛑 Scan interrupted by user (Ctrl+C)");
                println!("📊 Waiting for current batch to complete...\n");
            }
            // Give a moment for the scan to notice the cancellation
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            None
        }
    };

    match scan_result {
        Some(Ok(ScanResult::Completed(wallet_state))) => {
            // Display results based on output format
            match config.output_format {
                OutputFormat::Json => display_json_results(&wallet_state),
                OutputFormat::Summary => display_summary_results(&wallet_state, &config),
                OutputFormat::Detailed => {
                    display_wallet_activity(&wallet_state, config.from_block, config.to_block)
                }
            }

            // Display storage completion info and verify data integrity
            if !args.quiet {
                display_completion_info(&storage_backend, &config).await?;

                // Verify that transaction flow data was persisted correctly
                #[cfg(feature = "storage")]
                if storage_backend.wallet_id.is_some() {
                    let stats = storage_backend.get_statistics().await?;
                    // Show the stored values
                    println!(
                        "Database total received: {}",
                        format_number(stats.total_received)
                    );
                    println!("Database total spent: {}", format_number(stats.total_spent));
                    println!("Database balance: {}", format_number(stats.current_balance));
                    println!(
                        "Database inbound count: {}",
                        format_number(stats.inbound_count)
                    );
                    println!(
                        "Database outbound count: {}",
                        format_number(stats.outbound_count)
                    );
                }
            }
        }
        Some(Ok(ScanResult::Interrupted(wallet_state))) => {
            if !args.quiet {
                println!("⚠️  Scan was interrupted but collected partial data:\n");
            }

            // Display partial results based on output format
            match config.output_format {
                OutputFormat::Json => display_json_results(&wallet_state),
                OutputFormat::Summary => display_summary_results(&wallet_state, &config),
                OutputFormat::Detailed => {
                    display_wallet_activity(&wallet_state, config.from_block, config.to_block)
                }
            }

            if !args.quiet {
                println!("\n🔄 To resume scanning from where you left off, use:");
                println!("   cargo run --bin scanner --features grpc-storage -- <your-options> --from-block {}", 
                    format_number(wallet_state.transactions.iter()
                        .map(|tx| tx.block_height)
                        .max()
                        .map(|h| h + 1)
                        .unwrap_or(config.from_block))
                );
            }
            std::process::exit(130); // Standard exit code for SIGINT
        }
        Some(Err(e)) => {
            if !args.quiet {
                eprintln!("❌ Scan failed: {e}");
            }
            return Err(e);
        }
        None => {
            // Should not happen with our new implementation, but handle gracefully
            if !args.quiet {
                println!("💡 Scan was interrupted before completion.");
                println!(
                    "⚡ To resume, use the same command with appropriate --from-block parameter."
                );
            }
            std::process::exit(130); // Standard exit code for SIGINT
        }
    }

    // Stop background writer gracefully
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    if !storage_backend.is_memory_only {
        if !args.quiet {
            println!("🛑 Stopping background database writer...");
        }
        storage_backend.stop_background_writer().await?;
    }

    Ok(())
}

/// Display results in JSON format
#[cfg(feature = "grpc")]
fn display_json_results(wallet_state: &WalletState) {
    // Simple JSON-like output for now
    let (total_received, total_spent, balance, unspent_count, spent_count) =
        wallet_state.get_summary();
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();

    println!("{{");
    println!("  \"summary\": {{");
    println!(
        "    \"total_transactions\": {},",
        format_number(wallet_state.transactions.len())
    );
    println!("    \"inbound_count\": {},", format_number(inbound_count));
    println!("    \"outbound_count\": {},", format_number(outbound_count));
    println!("    \"total_received\": {},", format_number(total_received));
    println!("    \"total_spent\": {},", format_number(total_spent));
    println!("    \"current_balance\": {},", format_number(balance));
    println!("    \"unspent_outputs\": {},", format_number(unspent_count));
    println!("    \"spent_outputs\": {}", format_number(spent_count));
    println!("  }}");
    println!("}}");
}

/// Display summary results
#[cfg(feature = "grpc")]
fn display_summary_results(wallet_state: &WalletState, config: &BinaryScanConfig) {
    let (total_received, total_spent, balance, unspent_count, spent_count) =
        wallet_state.get_summary();
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();

    println!("📊 WALLET SCAN SUMMARY");
    println!("=====================");
    println!(
        "Scan range: Block {} to {}",
        format_number(config.from_block),
        format_number(config.to_block)
    );
    println!(
        "Total transactions: {}",
        format_number(wallet_state.transactions.len())
    );
    println!(
        "Inbound: {} transactions ({:.6} T)",
        format_number(inbound_count),
        total_received as f64 / 1_000_000.0
    );
    println!(
        "Outbound: {} transactions ({:.6} T)",
        format_number(outbound_count),
        total_spent as f64 / 1_000_000.0
    );
    println!("Current balance: {:.6} T", balance as f64 / 1_000_000.0);
    println!("Unspent outputs: {}", format_number(unspent_count));
    println!("Spent outputs: {}", format_number(spent_count));
}

#[cfg(not(feature = "grpc"))]
fn main() {
    eprintln!("This example requires the 'grpc' feature to be enabled.");
    eprintln!("Run with: cargo run --bin scanner --features grpc");
    std::process::exit(1);
}

#[cfg(target_arch = "wasm32")]
fn main() {
    eprintln!("This binary is not for wasm32 targets.");
    std::process::exit(1);
}
