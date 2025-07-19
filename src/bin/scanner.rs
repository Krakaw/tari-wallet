//! Lightweight CLI wrapper around ScannerService for blockchain scanning operations
//!
//! This binary provides a command-line interface for scanning the Tari blockchain
//! for wallet outputs using the scanner service layer. It delegates all business
//! logic to the ScannerService while handling CLI interactions and output formatting.

use clap::Parser;
use tracing_subscriber;

use lightweight_wallet_libs::{
    errors::LightweightWalletResult,
    scanning::{ScannerServiceBuilder, ServiceScannerType, ServiceScannerConfig, OutputFormat},
    wallet::Wallet,
};

#[cfg(feature = "storage")]
use lightweight_wallet_libs::storage::{SqliteStorage, WalletStorage};

/// Enhanced Tari Wallet Scanner
///
/// A comprehensive wallet scanner that uses the service layer for blockchain scanning.
/// Supports both memory-only and database-backed scanning with comprehensive
/// progress tracking and output formatting.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Seed phrase for wallet (24 words, space-separated, wrapped in quotes)
    #[arg(
        short,
        long,
        help = "Seed phrase for wallet recovery (24 words, space-separated, wrapped in quotes)"
    )]
    seed_phrase: Option<String>,

    /// Private view key (hex format, 64 characters)
    #[arg(
        short = 'k',
        long,
        help = "Private view key in hex format (64 characters, 32 bytes)"
    )]
    view_key: Option<String>,

    /// Base URL for the Tari base node endpoint
    #[arg(
        short,
        long,
        default_value = "http://127.0.0.1:18142",
        help = "Base URL for Tari base node (GRPC or HTTP)"
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
        help = "Output format: table, summary, json"
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

/// Parse output format string to OutputFormat enum
fn parse_output_format(format_str: &str) -> LightweightWalletResult<OutputFormat> {
    match format_str.to_lowercase().as_str() {
        "table" | "detailed" => Ok(OutputFormat::Table),
        "summary" => Ok(OutputFormat::Summary),
        "json" => Ok(OutputFormat::Json),
        _ => Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
            argument: "format".to_string(),
            value: format_str.to_string(),
            message: format!(
                "Invalid output format: {}. Valid options: table, summary, json",
                format_str
            ),
        }),
    }
}

/// Enhanced Tari Wallet Scanner
#[cfg(feature = "grpc")]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = CliArgs::parse();

    // Validate arguments
    validate_arguments(&args)?;

    if !args.quiet {
        println!("🚀 Enhanced Tari Wallet Scanner (Service-based)");
        println!("============================================");
    }

    // Create scanner service configuration
    let service_config = create_service_config(&args).await?;
    
    // Build and execute scanner service
    let mut scanner_service = create_scanner_service(&service_config, &args).await?;

    // Execute scan
    if !args.quiet {
        println!("🔍 Starting blockchain scan...");
    }

    let scan_result = scanner_service.scan_wallet(service_config).await?;

    // Display results (simplified)
    display_results(&scan_result, &args);

    if !args.quiet {
        println!("✅ Scan completed successfully!");
    }

    Ok(())
}

#[cfg(not(feature = "grpc"))]
fn main() {
    eprintln!("❌ Error: Scanner binary requires 'grpc' feature to be enabled.");
    eprintln!("💡 Tip: Run with: cargo run --bin scanner --features grpc");
    std::process::exit(1);
}

/// Validate command line arguments
fn validate_arguments(args: &CliArgs) -> LightweightWalletResult<()> {
    // Check for conflicting key arguments
    match (&args.seed_phrase, &args.view_key) {
        (Some(_), Some(_)) => {
            return Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
                argument: "keys".to_string(),
                value: "both".to_string(),
                message: "Cannot specify both --seed-phrase and --view-key. Choose one.".to_string(),
            });
        }
        (None, None) => {
            if !args.quiet {
                println!("🔑 No keys provided - will load from database...");
            }
        }
        _ => {} // Valid: exactly one is provided
    }

    Ok(())
}

/// Create scanner service configuration
async fn create_service_config(args: &CliArgs) -> LightweightWalletResult<ServiceScannerConfig> {
    let start_height = if let Some(seed_phrase) = &args.seed_phrase {
        // Use wallet birthday if available
        let wallet = Wallet::new_from_seed_phrase(seed_phrase, None)?;
        args.from_block.unwrap_or(wallet.birthday())
    } else {
        args.from_block.unwrap_or(0)
    };

    Ok(ServiceScannerConfig {
        base_url: args.base_url.clone(),
        start_height,
        end_height: args.to_block,
        batch_size: args.batch_size as u64,
        request_timeout: std::time::Duration::from_secs(30),
        storage_path: if args.seed_phrase.is_some() || args.view_key.is_some() {
            None // Memory-only when keys are provided
        } else {
            Some(args.database.clone())
        },
        wallet_name: args.wallet_name.clone(),
        progress_frequency: args.progress_frequency as u64,
        quiet_mode: args.quiet,
        output_format: parse_output_format(&args.format)?,
    })
}

/// Create scanner service with appropriate backend
#[cfg(feature = "grpc")]
async fn create_scanner_service(
    config: &ServiceScannerConfig,
    args: &CliArgs,
) -> LightweightWalletResult<Box<dyn lightweight_wallet_libs::scanning::ScannerService>> {
    if !args.quiet {
        println!("🌐 Connecting to Tari base node...");
    }

    let builder = ScannerServiceBuilder::new()
        .with_base_url(&config.base_url)
        .with_start_height(config.start_height)
        .with_batch_size(config.batch_size)
        .with_timeout(config.request_timeout)
        .with_quiet_mode(config.quiet_mode)
        .with_output_format(config.output_format.clone())
        .with_scanner_type(ServiceScannerType::Grpc);

    #[cfg(feature = "storage")]
    let builder = if let Some(storage_path) = &config.storage_path {
        let storage: Box<dyn WalletStorage> = if storage_path == ":memory:" {
            Box::new(SqliteStorage::new_in_memory().await?)
        } else {
            Box::new(SqliteStorage::new(storage_path).await?)
        };
        
        builder.with_storage(storage)
    } else {
        builder
    };

    let scanner_service = builder.build().await?;

    if !args.quiet {
        println!("✅ Connected to base node successfully");
    }

    Ok(scanner_service)
}

/// Display scan results
fn display_results(result: &lightweight_wallet_libs::scanning::ScanResult, args: &CliArgs) {
    match parse_output_format(&args.format).unwrap_or(OutputFormat::Summary) {
        OutputFormat::Table => {
            println!();
            println!("📊 Scan Results");
            println!("================");
            println!("Blocks Scanned: {}", result.statistics.blocks_scanned);
            println!("Outputs Found: {}", result.statistics.outputs_found);
            println!("Total Value: {} µT", result.statistics.total_value);
            println!("Scan Duration: {:.2}s", result.statistics.scan_duration.as_secs_f64());
            println!("Blocks/sec: {:.2}", result.statistics.blocks_per_second);
            
            println!();
            println!("💰 Wallet Summary");
            println!("=================");
            println!("Current Balance: {} µT", result.wallet_state.get_balance());
            println!("Transaction Count: {}", result.wallet_state.transaction_count());
        }
        OutputFormat::Summary => {
            println!("Scan Summary: {} blocks, {} outputs, {} µT, {:.1}s", 
                result.statistics.blocks_scanned,
                result.statistics.outputs_found,
                result.statistics.total_value,
                result.statistics.scan_duration.as_secs_f64()
            );
            
            println!("Wallet Balance: {} µT ({} transactions)",
                result.wallet_state.get_balance(),
                result.wallet_state.transaction_count()
            );
        }
        OutputFormat::Json => {
            let json_result = serde_json::json!({
                "statistics": {
                    "blocks_scanned": result.statistics.blocks_scanned,
                    "outputs_found": result.statistics.outputs_found,
                    "total_value": result.statistics.total_value,
                    "scan_duration_seconds": result.statistics.scan_duration.as_secs_f64(),
                    "blocks_per_second": result.statistics.blocks_per_second
                },
                "wallet": {
                    "balance": result.wallet_state.get_balance(),
                    "transaction_count": result.wallet_state.transaction_count()
                },
                "resume": {
                    "last_scanned_height": result.resume_info.last_scanned_height,
                    "resume_command": result.resume_info.resume_command
                }
            });

            println!("{}", serde_json::to_string_pretty(&json_result).unwrap_or_else(|_| "{}".to_string()));
        }
    }
}
