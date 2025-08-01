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
    // Core library utilities
    common::format_number,
    errors::LightweightWalletResult,
    // Scanning library components (main business logic)
    scanning::{
        // Wallet creation functions
        create_wallet_from_seed_phrase,
        create_wallet_from_view_key,
        // Configuration types
        BinaryScanConfig,
        // Scanner types
        BlockchainScanner,
        GrpcScannerBuilder,
        OutputFormat,
        WalletScannerConfig,
        WalletScannerStruct,
    },
    KeyManagementError,
    LightweightWalletError,
};

// Add conditional imports for storage feature
#[cfg(all(feature = "grpc", feature = "storage"))]
use lightweight_wallet_libs::scanning::ScannerStorage;

// Add conditional imports for non-storage feature
#[cfg(all(feature = "grpc", not(feature = "storage")))]
use lightweight_wallet_libs::scanning::MemoryDataProcessor;

#[cfg(feature = "grpc")]
use tokio::signal;

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
        default_value = "http://grpc.tari.com",
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

    /// Timeout for blockchain operations in seconds
    #[arg(
        long,
        default_value = "30",
        help = "Timeout for blockchain operations in seconds"
    )]
    timeout: u64,

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

// CLI-focused display helpers using library components
//
// These functions preserve the original user experience while delegating
// business logic to library storage methods. Critical for maintaining
// identical progress display, error messages, and output formats.

/// Display storage configuration and existing data using library storage methods
#[cfg(feature = "storage")]
async fn display_storage_info(
    storage_backend: &ScannerStorage,
    config: &BinaryScanConfig,
) -> LightweightWalletResult<()> {
    if config.quiet {
        return Ok(());
    }

    // Display storage mode
    if storage_backend.is_memory_only {
        println!("💭 Using in-memory storage (transactions will not be persisted)");
        return Ok(());
    }

    if let Some(db_path) = &config.database_path {
        println!("💾 Using SQLite database: {db_path}");
    } else {
        println!("💾 Using in-memory database");
    }

    // Use library method to get statistics and display existing data
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

/// Display completion information using library storage methods
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

    // Use library methods to get storage statistics and UTXO counts
    let stats = storage_backend.get_statistics().await?;
    println!(
        "💾 Database updated: {} total transactions stored",
        format_number(stats.total_transactions)
    );
    println!(
        "📍 Next scan can resume from block {}",
        format_number(stats.highest_block.unwrap_or(0) + 1)
    );

    // Use library method to get UTXO count
    let utxo_count = storage_backend.get_unspent_outputs_count().await?;
    if utxo_count > 0 {
        println!("🔗 UTXO outputs stored: {}", format_number(utxo_count));
    }

    Ok(())
}

// Progress display is now handled by the ConsoleLoggingListener in the event system

#[cfg(feature = "grpc")]
fn create_scan_config(
    args: &CliArgs,
    from_block: u64,
    to_block: u64,
) -> LightweightWalletResult<BinaryScanConfig> {
    let output_format: OutputFormat = args
        .format
        .parse()
        .map_err(|e: String| KeyManagementError::key_derivation_failed(&e))?;

    Ok(BinaryScanConfig {
        from_block,
        to_block,
        block_heights: args.blocks.clone(),
        progress_frequency: args.progress_frequency,
        quiet: args.quiet,
        output_format,
        batch_size: args.batch_size,
        database_path: Some(args.database.clone()),
        wallet_name: args.wallet_name.clone(),
        explicit_from_block: args.from_block,
        use_database: {
            #[cfg(feature = "storage")]
            {
                args.seed_phrase.is_none() && args.view_key.is_none()
            }
            #[cfg(not(feature = "storage"))]
            {
                false
            }
        },
    })
}

/// Create WalletScannerConfig from CLI arguments
#[cfg(feature = "grpc")]
fn create_wallet_scanner_config(args: &CliArgs) -> WalletScannerConfig {
    WalletScannerConfig {
        event_emitter: None, // Will be set separately with event system
        batch_size: args.batch_size,
        timeout: Some(std::time::Duration::from_secs(args.timeout)),
        verbose_logging: !args.quiet,
        retry_config: Default::default(), // Use default retry config
    }
}

/// Create both scan config and wallet scanner config from CLI arguments
#[cfg(feature = "grpc")]
fn create_scanner_configs(
    args: &CliArgs,
    from_block: u64,
    to_block: u64,
) -> LightweightWalletResult<(BinaryScanConfig, WalletScannerConfig)> {
    let scan_config = create_scan_config(args, from_block, to_block)?;
    let wallet_scanner_config = create_wallet_scanner_config(args);
    Ok((scan_config, wallet_scanner_config))
}

/// Handle interactive wallet selection when multiple wallets exist in database
#[cfg(feature = "storage")]
async fn handle_interactive_wallet_selection(
    storage_backend: &ScannerStorage,
    args: &CliArgs,
) -> LightweightWalletResult<u32> {
    let wallets = storage_backend.get_wallet_selection_info().await?;

    if wallets.is_empty() {
        return Err(LightweightWalletError::ResourceNotFound(
            "No wallets found in database".to_string(),
        ));
    }

    // Display wallet options
    if !args.quiet {
        println!();
        for (index, wallet) in wallets.iter().enumerate() {
            let wallet_type = if wallet.seed_phrase.is_some() {
                "Full wallet"
            } else {
                "View-only"
            };
            let last_scanned = if let Some(block) = wallet.latest_scanned_block {
                if block > 0 {
                    format!("(last scanned: block {block})")
                } else {
                    "(never scanned)".to_string()
                }
            } else {
                "(never scanned)".to_string()
            };

            println!(
                "  {}: {} [{}] {}",
                index + 1,
                wallet.name,
                wallet_type,
                last_scanned
            );
        }
        println!();
        print!("Enter wallet number (1-{}): ", wallets.len());
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        // Read user input
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).map_err(|e| {
            LightweightWalletError::StorageError(format!("Failed to read user input: {e}"))
        })?;

        let choice: usize =
            input
                .trim()
                .parse()
                .map_err(|_| LightweightWalletError::InvalidArgument {
                    argument: "wallet_selection".to_string(),
                    value: input.trim().to_string(),
                    message: "Invalid wallet number".to_string(),
                })?;

        if choice == 0 || choice > wallets.len() {
            return Err(LightweightWalletError::InvalidArgument {
                argument: "wallet_selection".to_string(),
                value: choice.to_string(),
                message: format!("Wallet number must be between 1 and {}", wallets.len()),
            });
        }

        let selected_wallet = &wallets[choice - 1];
        if !args.quiet {
            println!("✅ Selected wallet: {}", selected_wallet.name);
        }

        Ok(selected_wallet.id.expect("Wallet should have an ID"))
    } else {
        // In quiet mode, default to the first wallet
        Ok(wallets[0].id.expect("Wallet should have an ID"))
    }
}

// Main scanner binary implementation

#[cfg(feature = "grpc")]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    main_unified().await
}

/// Unified main function that handles both storage and non-storage modes
#[cfg(feature = "grpc")]
async fn main_unified() -> LightweightWalletResult<()> {
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
            // Handle no keys based on storage feature availability
            #[cfg(feature = "storage")]
            {
                if !args.quiet {
                    println!("🔑 No keys provided - will load from database...");
                }
            }
            #[cfg(not(feature = "storage"))]
            {
                eprintln!("❌ Error: When storage feature is disabled, you must provide either --seed-phrase or --view-key");
                eprintln!("💡 Run with: cargo run --bin scanner --features grpc-storage -- <your-options>");
                std::process::exit(1);
            }
        }
        _ => {} // Valid: exactly one is provided
    }

    if !args.quiet {
        #[cfg(feature = "storage")]
        let title = "🚀 Enhanced Tari Wallet Scanner";
        #[cfg(not(feature = "storage"))]
        let title = "🚀 Enhanced Tari Wallet Scanner (No Storage)";

        println!("{title}");
        println!("{}", "=".repeat(title.len() - 2)); // Account for emoji
    }

    // Create scan context based on input method (or defer if resuming from database)
    let (scan_context, default_from_block) = if keys_provided {
        if let Some(seed_phrase) = &args.seed_phrase {
            if !args.quiet {
                println!("🔨 Creating wallet from seed phrase...");
            }
            let (scan_context, default_from_block) = create_wallet_from_seed_phrase(seed_phrase)?;
            (Some(scan_context), default_from_block)
        } else if let Some(view_key_hex) = &args.view_key {
            if !args.quiet {
                println!("🔑 Creating scan context from view key...");
            }
            let (scan_context, default_from_block) = create_wallet_from_view_key(view_key_hex)?;
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
        .with_timeout(std::time::Duration::from_secs(args.timeout))
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
    #[cfg(feature = "storage")]
    let (temp_config, _) = create_scanner_configs(&args, 0, to_block)?;

    // Create storage backend - use database when available and no keys provided, memory otherwise
    #[cfg(feature = "storage")]
    let mut storage_backend = if keys_provided {
        // Keys provided - use memory-only storage
        ScannerStorage::new_memory()
    } else {
        // No keys provided - use database storage
        ScannerStorage::new_with_database(&args.database).await?
    };

    #[cfg(not(feature = "storage"))]
    let _storage_backend = (); // No storage backend for non-storage builds

    // Handle wallet operations for database storage (only when no keys provided)
    #[cfg(feature = "storage")]
    let (loaded_scan_context, wallet_birthday) = if keys_provided {
        // Keys provided directly - skip database operations entirely
        (None, None)
    } else {
        // No keys provided - use database storage
        let loaded_context = match storage_backend
            .handle_wallet_operations(&temp_config, scan_context.as_ref())
            .await
        {
            Ok(context) => context,
            Err(LightweightWalletError::InvalidArgument {
                argument, value, ..
            }) if argument == "wallet_selection" && value == "multiple_wallets" => {
                // Handle interactive wallet selection
                if !args.quiet {
                    println!("📝 Multiple wallets found in database. Please select one:");
                }

                let wallet_id =
                    handle_interactive_wallet_selection(&storage_backend, &args).await?;
                storage_backend.set_wallet_id(Some(wallet_id));

                // Now load the scan context
                storage_backend
                    .load_scan_context_from_wallet(args.quiet)
                    .await?
            }
            Err(e) => return Err(e),
        };

        // Get wallet birthday if we have a wallet
        let wallet_birthday = if args.from_block.is_none() {
            storage_backend.get_wallet_birthday().await?
        } else {
            None
        };

        (loaded_context, wallet_birthday)
    };

    #[cfg(not(feature = "storage"))]
    let (loaded_scan_context, wallet_birthday): (
        Option<lightweight_wallet_libs::scanning::ScanContext>,
        Option<u64>,
    ) = (None, None);

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

    // Validate block range
    if from_block > to_block {
        return Err(LightweightWalletError::InvalidArgument {
            argument: "block_range".to_string(),
            value: format!("{from_block}-{to_block}"),
            message: format!(
                "Starting block ({from_block}) cannot be greater than ending block ({to_block})"
            ),
        });
    }

    // Create final configs with the correct from_block
    let (config, scanner_config) = create_scanner_configs(&args, from_block, to_block)?;

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

    // Display storage info and existing data (only for storage builds)
    #[cfg(feature = "storage")]
    if !args.quiet {
        display_storage_info(&storage_backend, &config).await?;
    }

    #[cfg(not(feature = "storage"))]
    if !args.quiet {
        println!("💭 Using in-memory storage (transactions will not be persisted)");
        println!(
            "🔍 Scanning blocks {} to {} ({} blocks total)...",
            format_number(from_block),
            format_number(to_block),
            format_number(to_block - from_block + 1)
        );
    }

    // Setup cancellation mechanism
    let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);

    // Setup ctrl-c handling
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
        let _ = cancel_tx.send(true);
    };

    // Create data processor for non-storage builds (before the select block)
    #[cfg(not(feature = "storage"))]
    let mut data_processor = MemoryDataProcessor::new();

    // Create wallet scanner with event system instead of progress callback

    // Create event system components
    use lightweight_wallet_libs::events::{
        listeners::{AsciiProgressBarListener, ProgressTrackingListener},
        EventDispatcher,
    };
    use lightweight_wallet_libs::scanning::event_emitter::ScanEventEmitter;

    let mut event_dispatcher = EventDispatcher::new();

    // Add ASCII progress bar listener for real-time progress display
    let progress_bar_listener = if args.quiet {
        AsciiProgressBarListener::minimal()
    } else {
        AsciiProgressBarListener::detailed()
    };
    let _ = event_dispatcher.register(Box::new(progress_bar_listener));

    // Add progress tracking listener for ETA calculations
    let progress_listener = ProgressTrackingListener::new();
    let _ = event_dispatcher.register(Box::new(progress_listener));

    // Add database storage listener if using database storage (only available with storage feature)
    #[cfg(feature = "storage")]
    if !storage_backend.is_memory_only {
        use lightweight_wallet_libs::events::listeners::DatabaseStorageListener;
        if let Some(db_path) = &config.database_path {
            match DatabaseStorageListener::new(db_path).await {
                Ok(mut db_listener) => {
                    db_listener.set_wallet_id(storage_backend.wallet_id);
                    if !args.quiet && storage_backend.wallet_id.is_some() {
                        println!(
                            "🔗 Database event listener configured for wallet ID: {:?}",
                            storage_backend.wallet_id
                        );
                    }
                    let _ = event_dispatcher.register(Box::new(db_listener));
                }
                Err(e) => {
                    if !args.quiet {
                        eprintln!("⚠️  Warning: Could not create database event listener: {e}");
                        eprintln!("   Continuing with memory-only event handling...");
                    }
                }
            }
        }
    }

    // Create event emitter and wallet scanner
    let event_emitter = ScanEventEmitter::new(event_dispatcher, "wallet_scanner".to_string())
        .with_fire_and_forget(true);
    let mut wallet_scanner =
        WalletScannerStruct::from_config(scanner_config).with_event_emitter(event_emitter);

    // Perform the scan with cancellation support using unified event system
    let scan_result = tokio::select! {
        result = {
            #[cfg(feature = "storage")]
            {
                wallet_scanner.scan(&mut scanner, &final_scan_context, &config, &mut cancel_rx)
            }
            #[cfg(not(feature = "storage"))]
            {
                // For non-storage builds, use scan_with_processor with memory processor
                wallet_scanner.scan_with_processor(
                    &mut scanner,
                    &final_scan_context,
                    from_block,
                    to_block,
                    &mut data_processor,
                    &mut cancel_rx
                )
            }
        } => {
            Some(result)
        }
        _ = ctrl_c => {
            if !args.quiet {
                println!("\n\n🛑 Scan interrupted by user (Ctrl+C)");
                println!("📊 Waiting for current batch to complete...\n");
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            None
        }
    };

    match scan_result {
        Some(Ok(result)) => {
            // Display results using the library's display methods
            result.display(&config);

            // Handle interrupted scans
            if result.is_interrupted() {
                if !args.quiet {
                    println!("⚠️  Scan was interrupted but collected partial data:\n");
                    #[cfg(feature = "storage")]
                    let resume_template =
                        "cargo run --bin scanner --features grpc-storage -- <your-options>";
                    #[cfg(not(feature = "storage"))]
                    let resume_template =
                        "cargo run --bin scanner --features grpc -- <your-options>";

                    if let Some(resume_cmd) = result.resume_command(resume_template) {
                        println!("   {resume_cmd}");
                    }
                }
                std::process::exit(130); // Standard exit code for SIGINT
            }

            // Display storage completion info (only for storage builds)
            #[cfg(feature = "storage")]
            if !args.quiet {
                display_completion_info(&storage_backend, &config).await?;
            }

            #[cfg(not(feature = "storage"))]
            if !args.quiet {
                println!("💭 Scan completed using in-memory storage");
            }
        }
        Some(Err(e)) => {
            if !args.quiet {
                eprintln!("❌ Scan failed: {e}");
            }
            return Err(e);
        }
        None => {
            if !args.quiet {
                println!("💡 Scan was interrupted before completion.");
                #[cfg(feature = "storage")]
                println!(
                    "⚡ To resume, use the same command with appropriate --from-block parameter."
                );
                #[cfg(not(feature = "storage"))]
                println!("⚡ To resume, re-run the same command with appropriate --from-block parameter.");
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
