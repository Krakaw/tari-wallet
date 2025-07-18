//! Enhanced Tari Wallet Scanner
//!
//! A thin CLI wrapper around the lightweight wallet library's enhanced scanning functionality.
//! This provides all the same features as before but uses the library's abstractions for
//! better maintainability and reusability.
//!
//! ## Features
//! - Cross-block transaction tracking
//! - Complete wallet state management
//! - Running balance calculation
//! - Clean, user-friendly output with progress bars
//! - Automatic scan from wallet birthday to chain tip
//! - Batch processing for improved performance
//! - Graceful error handling with resume functionality
//! - Ctrl+C cancellation support
//!
//! ## Usage Examples
//! ```bash
//! # Scan with seed phrase (memory-only)
//! cargo run --bin scanner --features grpc-storage -- --seed-phrase "your seed phrase here"
//!
//! # Scan with view key (memory-only)
//! cargo run --bin scanner --features grpc-storage -- --view-key "hex_view_key_64_chars"
//!
//! # Scan specific range
//! cargo run --bin scanner --features grpc-storage -- --view-key "key" --from-block 34920 --to-block 34930
//!
//! # Resume from database
//! cargo run --bin scanner --features grpc-storage
//!
//! # JSON output for scripts
//! cargo run --bin scanner --features grpc-storage -- --view-key "key" --quiet --format json
//! ```

#[cfg(feature = "grpc")]
use clap::Parser;
#[cfg(feature = "grpc")]
use lightweight_wallet_libs::{
    scanning::{
        EnhancedScannerBuilder, EnhancedScanConfig, WalletScanContext, OutputFormat,
        GrpcScannerBuilder, ConsoleProgressCallback, InteractiveErrorCallback,
        AtomicCancellationToken, EnhancedScanResult, ScanPhase,
    },
    storage::{ScannerStorageConfig, WalletSelectionStrategy},
    wallet::Wallet,
    data_structures::wallet_transaction::WalletState,
    errors::LightweightWalletResult,
    utils::number::format_number,
};
#[cfg(feature = "grpc")]
use std::time::Duration;
#[cfg(feature = "grpc")]
use tokio::signal;

/// Enhanced Tari Wallet Scanner CLI
#[cfg(feature = "grpc")]
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Seed phrase for the wallet (uses memory-only storage when provided)
    #[arg(short, long, help = "Seed phrase for the wallet (uses memory-only storage)")]
    seed_phrase: Option<String>,

    /// Private view key in hex format (64 characters, uses memory-only storage)
    #[arg(long, help = "Private view key in hex format (64 characters). Uses memory-only storage")]
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
    #[arg(long, help = "Starting block height (defaults to wallet birthday or last scanned block)")]
    from_block: Option<u64>,

    /// Ending block height for scanning
    #[arg(long, help = "Ending block height (defaults to current tip)")]
    to_block: Option<u64>,

    /// Specific block heights to scan (comma-separated)
    #[arg(
        long,
        help = "Specific block heights to scan (comma-separated). Overrides from-block and to-block",
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
        help = "Wallet name to use for scanning. If not provided with database, will prompt for selection"
    )]
    wallet_name: Option<String>,
}

/// Main scanner function
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

    // Parse output format
    let output_format: OutputFormat = args.format.parse().map_err(|e: String| {
        lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
            argument: "format".to_string(),
            value: args.format.clone(),
            message: e,
        }
    })?;

    // Create scan context if keys are provided
    let scan_context = if keys_provided {
        if let Some(seed_phrase) = &args.seed_phrase {
            if !args.quiet {
                println!("🔨 Creating wallet from seed phrase...");
            }
            let wallet = Wallet::new_from_seed_phrase(seed_phrase, None)?;
            Some(WalletScanContext::from_wallet(&wallet)?)
        } else if let Some(view_key_hex) = &args.view_key {
            if !args.quiet {
                println!("🔑 Creating scan context from view key...");
            }
            Some(WalletScanContext::from_view_key(view_key_hex)?)
        } else {
            None
        }
    } else {
        None
    };

    // Connect to base node
    if !args.quiet {
        println!("🌐 Connecting to Tari base node...");
    }
    let grpc_scanner = GrpcScannerBuilder::new()
        .with_base_url(args.base_url.clone())
        .with_timeout(Duration::from_secs(30))
        .build()
        .await
        .map_err(|e| {
            if !args.quiet {
                eprintln!("❌ Failed to connect to Tari base node: {}", e);
                eprintln!("💡 Make sure tari_base_node is running with GRPC enabled on port 18142");
            }
            e
        })?;

    if !args.quiet {
        println!("✅ Connected to Tari base node successfully");
    }

    // Get blockchain tip
    let tip_info = grpc_scanner.get_tip_info().await?;
    if !args.quiet {
        println!(
            "📊 Current blockchain tip: block {}",
            format_number(tip_info.best_block_height)
        );
    }

    let to_block = args.to_block.unwrap_or(tip_info.best_block_height);

    // Create scan configuration
    let mut scan_config = if let Some(blocks) = args.blocks {
        EnhancedScanConfig::for_specific_blocks(blocks)
    } else {
        let from_block = if let Some(explicit_from) = args.from_block {
            explicit_from
        } else if let Some(ref context) = scan_context {
            if context.has_entropy() {
                // For seed phrase mode, use wallet birthday
                let wallet = Wallet::new_from_seed_phrase(
                    args.seed_phrase.as_ref().unwrap(), None
                )?;
                wallet.birthday()
            } else {
                // For view key mode, start from genesis
                0
            }
        } else {
            // Database mode - will be set from wallet birthday
            0
        };
        
        EnhancedScanConfig::new(from_block, to_block)
    };

    // Configure scan settings
    scan_config = scan_config
        .with_batch_size(args.batch_size)
        .with_progress_frequency(args.progress_frequency)
        .with_output_format(output_format.clone())
        .with_request_timeout(Duration::from_secs(30));

    if args.from_block.is_some() {
        scan_config = scan_config.with_explicit_from_block(args.from_block.unwrap());
    }

    // Create storage configuration
    let storage_config = if keys_provided {
        // Memory-only storage when keys are provided
        ScannerStorageConfig::memory()
    } else {
        // Database storage when no keys provided
        ScannerStorageConfig::database(&args.database)
            .with_wallet_name(args.wallet_name.clone().unwrap_or_default())
    };

    // Build the enhanced scanner
    let mut enhanced_scanner = if keys_provided {
        // Memory-only mode
        EnhancedScannerBuilder::new()
            .with_scanner(grpc_scanner)
            .with_scan_config(scan_config)
            .build()?
            .with_scan_context(scan_context.unwrap())
    } else {
        // Database mode (requires storage feature)
        #[cfg(feature = "storage")]
        {
            EnhancedScannerBuilder::new()
                .with_scanner(grpc_scanner)
                .with_storage_config(storage_config)
                .with_scan_config(scan_config)
                .build_with_storage()
                .await?
        }
        #[cfg(not(feature = "storage"))]
        {
            eprintln!("❌ Database mode requires the 'storage' feature to be enabled.");
            eprintln!("💡 Either provide --seed-phrase or --view-key, or compile with 'storage' feature.");
            std::process::exit(1);
        }
    };

    // Initialize wallet for database mode
    #[cfg(feature = "storage")]
    if !keys_provided {
        let wallet_strategy = if let Some(wallet_name) = &args.wallet_name {
            WalletSelectionStrategy::Named(wallet_name.clone())
        } else {
            WalletSelectionStrategy::Interactive
        };

        let selection_callback = |wallets: &[lightweight_wallet_libs::storage::StoredWallet]| {
            if args.quiet {
                return Some(0); // Auto-select first wallet in quiet mode
            }

            println!("\n📂 Available wallets:");
            for (i, wallet) in wallets.iter().enumerate() {
                let wallet_type = if wallet.has_seed_phrase() { "Full" } else { "View-only" };
                let resume_info = if wallet.get_resume_block() > 0 {
                    format!(" (resume from block {})", format_number(wallet.get_resume_block()))
                } else {
                    String::new()
                };
                println!("{}. {} - {}{}", i + 1, wallet.name, wallet_type, resume_info);
            }

            print!("\nSelect wallet (1-{}), or 'q' to quit: ", wallets.len());
            std::io::Write::flush(&mut std::io::stdout()).unwrap();

            let mut input = String::new();
            if std::io::stdin().read_line(&mut input).is_err() {
                return None;
            }

            let choice = input.trim().to_lowercase();
            if choice == "q" || choice == "quit" {
                std::process::exit(0);
            }

            match choice.parse::<usize>() {
                Ok(selection) if selection >= 1 && selection <= wallets.len() => {
                    Some(selection - 1)
                }
                _ => {
                    eprintln!("Invalid selection. Please enter 1-{} or 'q'.", wallets.len());
                    None
                }
            }
        };

        enhanced_scanner.initialize_wallet(wallet_strategy, Some(&selection_callback)).await?;
    }

    // Set up progress and error callbacks
    let progress_callback = if !args.quiet {
        Some(ConsoleProgressCallback::new(false, args.progress_frequency))
    } else {
        None
    };

    let error_callback = if !args.quiet {
        Some(InteractiveErrorCallback::new(false))
    } else {
        None
    };

    // Set up cancellation token for Ctrl+C
    let (cancel_token, cancel_handle) = AtomicCancellationToken::create_pair();
    
    // Handle Ctrl+C
    let ctrl_c_handle = cancel_handle.clone();
    let ctrl_c_task = tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
        ctrl_c_handle.cancel();
    });

    // Perform the scan
    let scan_result = enhanced_scanner.scan_wallet(
        progress_callback.as_ref().map(|cb| cb as &dyn lightweight_wallet_libs::scanning::EnhancedProgressCallback),
        error_callback.as_ref().map(|cb| cb as &dyn lightweight_wallet_libs::scanning::ErrorCallback),
        Some(&cancel_token),
    ).await;

    // Cancel the ctrl-c task
    ctrl_c_task.abort();

    // Handle scan results
    match scan_result {
        Ok(EnhancedScanResult::Completed(wallet_state)) => {
            if !args.quiet {
                println!("\n✅ Scan completed successfully!");
            }
            display_results(&wallet_state, &output_format, &enhanced_scanner.config());
        }
        Ok(EnhancedScanResult::Interrupted(wallet_state)) => {
            if !args.quiet {
                println!("\n⚠️ Scan was interrupted but collected partial data:");
            }
            display_results(&wallet_state, &output_format, &enhanced_scanner.config());
            
            if !args.quiet {
                let resume_block = wallet_state.transactions.iter()
                    .map(|tx| tx.block_height)
                    .max()
                    .map(|h| h + 1)
                    .unwrap_or(enhanced_scanner.config().from_block);
                    
                println!("\n🔄 To resume scanning from where you left off, use:");
                println!("   cargo run --bin scanner --features grpc-storage -- <your-options> --from-block {}", 
                    format_number(resume_block));
            }
            std::process::exit(130); // Standard exit code for SIGINT
        }
        Ok(EnhancedScanResult::Failed(error)) => {
            eprintln!("❌ Scan failed: {}", error);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Scanner error: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Display scan results in the requested format
#[cfg(feature = "grpc")]
fn display_results(wallet_state: &WalletState, format: &OutputFormat, config: &EnhancedScanConfig) {
    match format {
        OutputFormat::Json => display_json_results(wallet_state),
        OutputFormat::Summary => display_summary_results(wallet_state, config),
        OutputFormat::Detailed => display_detailed_results(wallet_state, config),
    }
}

/// Display results in JSON format
#[cfg(feature = "grpc")]
fn display_json_results(wallet_state: &WalletState) {
    let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();

    println!("{{");
    println!("  \"summary\": {{");
    println!("    \"total_transactions\": {},", wallet_state.transactions.len());
    println!("    \"inbound_count\": {},", inbound_count);
    println!("    \"outbound_count\": {},", outbound_count);
    println!("    \"total_received\": {},", total_received);
    println!("    \"total_spent\": {},", total_spent);
    println!("    \"current_balance\": {},", balance);
    println!("    \"unspent_outputs\": {},", unspent_count);
    println!("    \"spent_outputs\": {}", spent_count);
    println!("  }}");
    println!("}}");
}

/// Display summary results
#[cfg(feature = "grpc")]
fn display_summary_results(wallet_state: &WalletState, config: &EnhancedScanConfig) {
    let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();

    println!("📊 WALLET SCAN SUMMARY");
    println!("=====================");
    println!(
        "Scan range: Block {} to {}",
        format_number(config.from_block),
        format_number(config.to_block)
    );
    println!("Total transactions: {}", format_number(wallet_state.transactions.len()));
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

/// Display detailed results with full transaction history
#[cfg(feature = "grpc")]
fn display_detailed_results(wallet_state: &WalletState, config: &EnhancedScanConfig) {
    // First show the summary
    display_summary_results(wallet_state, config);

    if wallet_state.transactions.is_empty() {
        println!("\n💡 No wallet activity found in the scanned range.");
        return;
    }

    println!("\n📋 DETAILED TRANSACTION HISTORY");
    println!("===============================");

    // Sort transactions by block height for chronological order
    let mut sorted_transactions: Vec<_> = wallet_state.transactions.iter().enumerate().collect();
    sorted_transactions.sort_by_key|(_, tx)| tx.block_height);

    for (original_index, tx) in sorted_transactions {
        let direction_symbol = match tx.transaction_direction {
            lightweight_wallet_libs::data_structures::transaction::TransactionDirection::Inbound => "📥",
            lightweight_wallet_libs::data_structures::transaction::TransactionDirection::Outbound => "📤",
            _ => "❓",
        };

        let amount_display = match tx.transaction_direction {
            lightweight_wallet_libs::data_structures::transaction::TransactionDirection::Inbound => {
                format!("+{} μT", format_number(tx.value))
            }
            lightweight_wallet_libs::data_structures::transaction::TransactionDirection::Outbound => {
                format!("-{} μT", format_number(tx.value))
            }
            _ => format!("±{} μT", format_number(tx.value)),
        };

        let status = if tx.is_spent {
            format!("SPENT in block {}", format_number(tx.spent_in_block.unwrap_or(0)))
        } else {
            "UNSPENT".to_string()
        };

        let maturity_indicator = if tx.transaction_status.is_coinbase() && !tx.is_mature {
            " (IMMATURE)"
        } else {
            ""
        };

        println!(
            "{}. {} Block {}: {} ({:.6} T) - {} [{}{}]",
            format_number(original_index + 1),
            direction_symbol,
            format_number(tx.block_height),
            amount_display,
            tx.value as f64 / 1_000_000.0,
            status,
            tx.transaction_status,
            maturity_indicator
        );

        // Show payment ID if present
        let payment_id_str = tx.payment_id.user_data_as_string();
        if !payment_id_str.is_empty() {
            println!("   💬 Payment ID: \"{}\"", payment_id_str);
        }
    }

    // Show balance breakdown
    let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
    
    println!("\n💰 BALANCE BREAKDOWN");
    println!("===================");
    println!(
        "Total received: {:.6} T ({} transactions)",
        total_received as f64 / 1_000_000.0,
        unspent_count + spent_count
    );
    println!(
        "Total spent: {:.6} T ({} transactions)",
        total_spent as f64 / 1_000_000.0,
        spent_count
    );
    println!(
        "Current balance: {:.6} T ({} unspent outputs)",
        balance as f64 / 1_000_000.0,
        unspent_count
    );
}

/// Fallback main for when GRPC feature is not enabled
#[cfg(not(feature = "grpc"))]
fn main() {
    eprintln!("This scanner requires the 'grpc' feature to be enabled.");
    eprintln!("Run with: cargo run --bin scanner --features grpc");
    std::process::exit(1);
}
