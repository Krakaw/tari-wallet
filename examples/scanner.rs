//! Enhanced Tari Wallet Scanner
//! 
//! A comprehensive wallet scanner that tracks all transactions across blocks,
//! maintains complete transaction history, and provides accurate running balances.
//!
//! ## Features
//! - Cross-block transaction tracking
//! - Complete wallet state management
//! - Running balance calculation
//! - Clean, user-friendly output with bash-style progress bars
//! - Automatic scan from wallet birthday to chain tip
//! - **Graceful error handling with resume functionality**
//!
//! ## Error Handling
//! When GRPC errors occur (e.g., "message length too large"), the scanner will:
//! - Display the exact block height and error details
//! - Offer interactive options: Continue (y), Skip block (s), or Abort (n)
//! - Provide resume commands for easy restart from the failed point
//! - Example: `cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --from-block 25000 --to-block 30000`
//!
//! ## Usage
//! ```bash
//! # Scan with wallet from birthday to tip using seed phrase
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase here"
//!
//! # Scan using private view key (hex format, 64 characters)
//! cargo run --example scanner --features grpc -- --view-key "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab"
//!
//! # Scan specific range with view key
//! cargo run --example scanner --features grpc -- --view-key "your_view_key_here" --from-block 34920 --to-block 34930
//!
//! # Scan specific blocks only
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --blocks 1000,2000,5000,10000
//!
//! # Use custom base node URL
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --base-url "http://192.168.1.100:18142"
//!
//! # Quiet mode with JSON output (script-friendly)
//! cargo run --example scanner --features grpc -- --view-key "your_view_key" --quiet --format json
//!
//! # Summary output with minimal progress updates
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --format summary --progress-frequency 50
//!
//! # Resume from a specific block after error
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --from-block 25000 --to-block 30000
//!
//! # Show help
//! cargo run --example scanner --features grpc -- --help
//! ```
//!
//! ## View Key vs Seed Phrase
//! 
//! **Seed Phrase Mode:**
//! - Full wallet functionality including range proof rewinding
//! - Automatic wallet birthday detection
//! - Requires seed phrase security
//! 
//! **View Key Mode:**
//! - View-only access with encrypted data decryption
//! - Range proof rewinding is limited (no seed entropy)
//! - Starts from genesis by default (can be overridden)
//! - More secure for monitoring purposes
//! - View key format: 64-character hex string (32 bytes)

#[cfg(feature = "grpc")]
use lightweight_wallet_libs::{
    scanning::{GrpcScannerBuilder, GrpcBlockchainScanner, BlockchainScanner},
    key_management::{key_derivation, seed_phrase::{mnemonic_to_bytes, CipherSeed}},
    extraction::RangeProofRewindService,
    wallet::Wallet,
    errors::{LightweightWalletResult},
    KeyManagementError,
    data_structures::{
        types::PrivateKey,
        payment_id::PaymentId,
        wallet_transaction::WalletState,
        transaction::TransactionDirection,
        block::Block,
    },
};
#[cfg(feature = "grpc")]
use tari_utilities::ByteArray;
#[cfg(feature = "grpc")]
use tokio::time::Instant;
#[cfg(feature = "grpc")]
use clap::Parser;

/// Enhanced Tari Wallet Scanner CLI
#[cfg(feature = "grpc")]
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Seed phrase for the wallet (required unless --view-key is provided)
    #[arg(short, long, help = "Seed phrase for the wallet")]
    seed_phrase: Option<String>,

    /// Private view key in hex format (alternative to seed phrase)
    #[arg(long, help = "Private view key in hex format (64 characters). Alternative to --seed-phrase")]
    view_key: Option<String>,

    /// Base URL for the Tari base node GRPC endpoint
    #[arg(short, long, default_value = "http://127.0.0.1:18142", help = "Base URL for Tari base node GRPC")]
    base_url: String,

    /// Starting block height for scanning
    #[arg(long, help = "Starting block height (defaults to wallet birthday or 0 for view-key mode)")]
    from_block: Option<u64>,

    /// Ending block height for scanning
    #[arg(long, help = "Ending block height (defaults to current tip)")]
    to_block: Option<u64>,

    /// Specific block heights to scan (comma-separated)
    #[arg(long, help = "Specific block heights to scan (comma-separated). If provided, overrides from-block and to-block", value_delimiter = ',')]
    blocks: Option<Vec<u64>>,

    /// Progress update frequency
    #[arg(long, default_value = "10", help = "Update progress every N blocks")]
    progress_frequency: usize,

    /// Quiet mode - minimal output
    #[arg(short, long, help = "Quiet mode - only show essential information")]
    quiet: bool,

    /// Output format
    #[arg(long, default_value = "detailed", help = "Output format: detailed, summary, json")]
    format: String,
}

/// Configuration for wallet scanning
#[cfg(feature = "grpc")]
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub from_block: u64,
    pub to_block: u64,
    pub block_heights: Option<Vec<u64>>,
    pub progress_frequency: usize,
    pub quiet: bool,
    pub output_format: OutputFormat,
}

/// Output format options
#[cfg(feature = "grpc")]
#[derive(Debug, Clone)]
pub enum OutputFormat {
    Detailed,
    Summary,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "detailed" => Ok(OutputFormat::Detailed),
            "summary" => Ok(OutputFormat::Summary),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!("Invalid output format: {}. Valid options: detailed, summary, json", s)),
        }
    }
}

/// Wallet scanning context
#[cfg(feature = "grpc")]
pub struct ScanContext {
    pub view_key: PrivateKey,
    pub entropy: [u8; 16],
    pub range_proof_service: RangeProofRewindService,
}

impl ScanContext {
    pub fn from_wallet(wallet: &Wallet) -> LightweightWalletResult<Self> {
        // Setup wallet keys
        let seed_phrase = wallet.export_seed_phrase()?;
        let encrypted_bytes = mnemonic_to_bytes(&seed_phrase)?;
        let cipher_seed = CipherSeed::from_enciphered_bytes(&encrypted_bytes, None)?;
        let entropy = cipher_seed.entropy();
        
        let entropy_array: [u8; 16] = entropy.try_into()
            .map_err(|_| KeyManagementError::key_derivation_failed("Invalid entropy length"))?;
        
        let view_key_raw = key_derivation::derive_private_key_from_entropy(
            &entropy_array, 
            "data encryption", 
            0
        )?;
        let view_key = PrivateKey::new(view_key_raw.as_bytes().try_into().expect("Should convert to array"));
        
        // Initialize range proof rewinding service
        let range_proof_service = RangeProofRewindService::new()?;
        
        Ok(Self {
            view_key,
            entropy: entropy_array,
            range_proof_service,
        })
    }

    pub fn from_view_key(view_key_hex: &str) -> LightweightWalletResult<Self> {
        // Parse the hex view key
        let view_key_bytes = hex::decode(view_key_hex)
            .map_err(|_| KeyManagementError::key_derivation_failed("Invalid hex format for view key"))?;
        
        if view_key_bytes.len() != 32 {
            return Err(KeyManagementError::key_derivation_failed(
                "View key must be exactly 32 bytes (64 hex characters)"
            ).into());
        }

        let view_key_array: [u8; 32] = view_key_bytes.try_into()
            .map_err(|_| KeyManagementError::key_derivation_failed("Failed to convert view key to array"))?;
        
        let view_key = PrivateKey::new(view_key_array);
        
        // Initialize range proof rewinding service
        let range_proof_service = RangeProofRewindService::new()?;
        
        // Note: Without seed entropy, range proof rewinding will be limited
        // We use a zero entropy array as a fallback
        let entropy = [0u8; 16];
        
        Ok(Self {
            view_key,
            entropy,
            range_proof_service,
        })
    }

    pub fn has_entropy(&self) -> bool {
        self.entropy != [0u8; 16]
    }
}

/// Progress tracking for scanning
#[cfg(feature = "grpc")]
pub struct ScanProgress {
    pub current_block: u64,
    pub total_blocks: usize,
    pub blocks_processed: usize,
    pub outputs_found: usize,
    pub inputs_found: usize,
    pub start_time: Instant,
}

impl ScanProgress {
    pub fn new(total_blocks: usize) -> Self {
        Self {
            current_block: 0,
            total_blocks,
            blocks_processed: 0,
            outputs_found: 0,
            inputs_found: 0,
            start_time: Instant::now(),
        }
    }

    pub fn update(&mut self, block_height: u64, found_outputs: usize, spent_outputs: usize) {
        self.current_block = block_height;
        self.blocks_processed += 1;
        self.outputs_found += found_outputs;
        self.inputs_found += spent_outputs;
    }

    pub fn display_progress(&self, quiet: bool, frequency: usize) {
        if quiet || self.blocks_processed % frequency != 0 {
            return;
        }

        let progress_percent = (self.blocks_processed as f64 / self.total_blocks as f64) * 100.0;
        let elapsed = self.start_time.elapsed();
        let blocks_per_sec = self.blocks_processed as f64 / elapsed.as_secs_f64();
        
        print!("\r🔍 Progress: {:.1}% ({}/{}) | Block {} | {:.1} blocks/s | Found: {} outputs, {} spent   ",
            progress_percent,
            self.blocks_processed,
            self.total_blocks,
            self.current_block,
            blocks_per_sec,
            self.outputs_found,
            self.inputs_found
        );
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
    }
}

pub struct BlockHeightRange {
    pub from_block: u64,
    pub to_block: u64,
    pub block_heights: Option<Vec<u64>>,
}

impl BlockHeightRange {
    pub fn new(from_block: u64, to_block: u64, block_heights: Option<Vec<u64>>) -> Self {
        Self { from_block, to_block, block_heights }
    }

    pub fn into_scan_config(self, args: &CliArgs) -> LightweightWalletResult<ScanConfig> {
        let output_format = args.format.parse()
            .map_err(|e: String| KeyManagementError::key_derivation_failed(&e))?;

        Ok(ScanConfig {
            from_block: self.from_block,
            to_block: self.to_block,
            block_heights: self.block_heights,
            progress_frequency: args.progress_frequency,
            quiet: args.quiet,
            output_format,
        })
    }
}

/// Handle errors during block scanning
#[cfg(feature = "grpc")]
fn handle_scan_error(
    block_height: u64,
    remaining_blocks: &[u64],
    has_specific_blocks: bool,
    to_block: u64,
) -> bool {
    // Ask user if they want to continue
    print!("   Continue scanning remaining blocks? (y/n/s=skip this block): ");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false; // Abort on input error
    }
    let choice = input.trim().to_lowercase();
    
    match choice.as_str() {
        "y" | "yes" => {
            println!("   ✅ Continuing scan from next block...");
            true // Continue
        },
        "s" | "skip" => {
            println!("   ⏭️  Skipping block {} and continuing...", block_height);
            true // Continue (skip this block)
        },
        _ => {
            println!("   🛑 Scan aborted by user at block {}", block_height);
            println!("\n💡 To resume from this point, run:");
            if has_specific_blocks {
                let remaining_blocks_str: Vec<String> = remaining_blocks.iter().map(|b| b.to_string()).collect();
                println!("   cargo run --example scanner --features grpc -- --seed-phrase \"your seed phrase\" --blocks {}", 
                    remaining_blocks_str.join(","));
            } else {
                println!("   cargo run --example scanner --features grpc -- --seed-phrase \"your seed phrase\" --from-block {} --to-block {}", block_height, to_block);
            }
            false // Abort
        }
    }
}

/// Core scanning logic - simplified and focused
#[cfg(feature = "grpc")]
async fn scan_wallet_across_blocks(
    scanner: &mut GrpcBlockchainScanner,
    scan_context: &ScanContext,
    config: &ScanConfig,
) -> LightweightWalletResult<WalletState> {
    let has_specific_blocks = config.block_heights.is_some();
    let block_heights = config.block_heights.clone().unwrap_or_else(|| {
        (config.from_block..=config.to_block).collect()
    });

    if !config.quiet {
        display_scan_info(&config, &block_heights, has_specific_blocks);
    }

    let mut wallet_state = WalletState::new(); // No Arc<Mutex> needed!
    let mut progress = ScanProgress::new(block_heights.len());

    for (block_index, &block_height) in block_heights.iter().enumerate() {
        progress.display_progress(config.quiet, config.progress_frequency);
        
        let block_info = match scanner.get_block_by_height(block_height).await {
            Ok(Some(block)) => block,
            Ok(None) => {
                if !config.quiet {
                    println!("\n⚠️  Block {} not found, skipping...", block_height);
                }
                continue;
            },
                         Err(e) => {
                 println!("\n❌ Error scanning block {}: {}", block_height, e);
                 println!("   Block height: {}", block_height);
                 println!("   Error details: {:?}", e);
                 
                 let remaining_blocks = &block_heights[block_index..];
                 if handle_scan_error(block_height, remaining_blocks, has_specific_blocks, config.to_block) {
                     continue;  // Continue or skip
                 } else {
                     return Err(e); // Abort
                 }
             }
        };
        
        // Process block using the Block struct
        let block = Block::from_block_info(block_info);
        let (found_outputs, spent_outputs) = block.scan_for_wallet_activity(
            &scan_context.view_key,
            &scan_context.entropy,
            &mut wallet_state,
            &scan_context.range_proof_service,
        )?;

        progress.update(block_height, found_outputs, spent_outputs);

        // Show detailed results if not quiet and found something
        if !config.quiet && (found_outputs > 0 || spent_outputs > 0) {
            println!("\n🎯 Block {}: {} outputs found, {} outputs spent", 
                block_height, found_outputs, spent_outputs);
        }
    }

    if !config.quiet {
        let scan_elapsed = progress.start_time.elapsed();
        println!("\n✅ Scan complete in {:.2}s!", scan_elapsed.as_secs_f64());
        println!("📊 Total: {} outputs found, {} outputs spent", progress.outputs_found, progress.inputs_found);
    }

    Ok(wallet_state)
}

/// Display scan configuration information
#[cfg(feature = "grpc")]
fn display_scan_info(config: &ScanConfig, block_heights: &[u64], has_specific_blocks: bool) {
    if has_specific_blocks {
        println!("🔍 Scanning {} specific blocks: {:?}", block_heights.len(), 
            if block_heights.len() <= 10 { 
                block_heights.iter().map(|h| h.to_string()).collect::<Vec<_>>().join(", ")
            } else {
                format!("{}..{} and {} others", block_heights[0], block_heights.last().unwrap(), block_heights.len() - 2)
            });
    } else {
        let block_range = config.to_block - config.from_block + 1;
        println!("🔍 Scanning blocks {} to {} ({} blocks total)...", 
            config.from_block, config.to_block, block_range);
    }

    // Warning about scanning limitations
    if config.from_block > 1 && !has_specific_blocks {
        println!("⚠️  WARNING: Starting scan from block {} (not genesis)", config.from_block);
        println!("   📍 This will MISS any wallet outputs received before block {}", config.from_block);
        println!("   💡 For complete transaction history, consider scanning from genesis (--from-block 1)");
    }
    println!();
}

#[cfg(feature = "grpc")]
fn display_wallet_activity(wallet_state: &WalletState, from_block: u64, to_block: u64) {
    let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
    let total_count = wallet_state.transactions.len();
    
    if total_count == 0 {
        println!("💡 No wallet activity found in blocks {} to {}", from_block, to_block);
        if from_block > 1 {
            println!("   ⚠️  Note: Scanning from block {} - wallet history before this block was not checked", from_block);
            println!("   💡 For complete history, try: cargo run --example scanner --features grpc -- --seed-phrase \"your seed phrase\" --from-block 1");
        }
        return;
    }
    
    println!("🏦 WALLET ACTIVITY SUMMARY");
    println!("========================");
    println!("Scan range: Block {} to {} ({} blocks)", from_block, to_block, to_block - from_block + 1);
    
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();
    println!("📥 Inbound:  {} transactions, {} μT ({:.6} T)", inbound_count, total_received, total_received as f64 / 1_000_000.0);
    println!("📤 Outbound: {} transactions, {} μT ({:.6} T)", outbound_count, total_spent, total_spent as f64 / 1_000_000.0);
    println!("💰 Current balance: {} μT ({:.6} T)", balance, balance as f64 / 1_000_000.0);
    println!("📊 Total activity: {} transactions", total_count);
    println!();
    
    if !wallet_state.transactions.is_empty() {
        println!("📋 TRANSACTION HISTORY (Chronological)");
        println!("=====================================");
        
        // Sort transactions by block height for chronological order
        let mut sorted_transactions: Vec<_> = wallet_state.transactions.iter().enumerate().collect();
        sorted_transactions.sort_by_key(|(_, tx)| tx.block_height);
        
        for (original_index, tx) in sorted_transactions {
            let direction_symbol = match tx.transaction_direction {
                TransactionDirection::Inbound => "📥",
                TransactionDirection::Outbound => "📤",
                TransactionDirection::Unknown => "❓",
            };
            
            let amount_display = match tx.transaction_direction {
                TransactionDirection::Inbound => format!("+{} μT", tx.value),
                TransactionDirection::Outbound => format!("-{} μT", tx.value),
                TransactionDirection::Unknown => format!("±{} μT", tx.value),
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
                        format!("LATER SPENT in block {}", tx.spent_in_block.unwrap_or(0))
                    } else {
                        "UNSPENT".to_string()
                    };
                    
                    println!("{}. {} Block {}, Output #{}: {} ({:.6} T) - {} [{}{}]", 
                        original_index + 1,
                        direction_symbol,
                        tx.block_height,
                        tx.output_index.unwrap_or(0),
                        amount_display,
                        tx.value as f64 / 1_000_000.0,
                        status,
                        tx.transaction_status,
                        maturity_indicator
                    );
                },
                TransactionDirection::Outbound => {
                    println!("{}. {} Block {}, Input #{}: {} ({:.6} T) - SPENT [{}]", 
                        original_index + 1,
                        direction_symbol,
                        tx.block_height,
                        tx.input_index.unwrap_or(0),
                        amount_display,
                        tx.value as f64 / 1_000_000.0,
                        tx.transaction_status
                    );
                },
                TransactionDirection::Unknown => {
                    println!("{}. {} Block {}: {} ({:.6} T) - UNKNOWN [{}]", 
                        original_index + 1,
                        direction_symbol,
                        tx.block_height,
                        amount_display,
                        tx.value as f64 / 1_000_000.0,
                        tx.transaction_status
                    );
                }
            }
            
            // Show payment ID if not empty
            match &tx.payment_id {
                PaymentId::Empty => {},
                PaymentId::Open { user_data, .. } if !user_data.is_empty() => {
                    // Try to decode as UTF-8 string
                    if let Ok(text) = std::str::from_utf8(user_data) {
                        if text.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                            println!("   💬 Payment ID: \"{}\"", text);
                        } else {
                            println!("   💬 Payment ID (hex): {}", hex::encode(user_data));
                        }
                    } else {
                        println!("   💬 Payment ID (hex): {}", hex::encode(user_data));
                    }
                },
                PaymentId::TransactionInfo { user_data, .. } if !user_data.is_empty() => {
                    // Convert the binary data to utf8 string if possible otherwise print as hex    
                    if let Ok(text) = std::str::from_utf8(user_data) {
                        println!("   💬 Payment ID: \"{}\"", text);
                    } else {
                        println!("   💬 Payment ID (hex): {}", hex::encode(user_data));
                    }
                },
                _ => {
                    println!("   💬 Payment ID: {:#?}", tx.payment_id.user_data_as_string());
                }
            }
        }
        println!();
    }
    
    // Show balance breakdown
    let unspent_value = wallet_state.get_unspent_value();
        
    println!("💰 BALANCE BREAKDOWN");
    println!("===================");
    println!("Unspent outputs: {} ({:.6} T)", unspent_count, unspent_value as f64 / 1_000_000.0);
    println!("Spent outputs: {} ({:.6} T)", spent_count, total_spent as f64 / 1_000_000.0);
    println!("Total wallet activity: {} transactions", total_count);
    
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
        println!("📥 Inbound:  {} transactions, {:.6} T total", inbound_count, total_inbound_value as f64 / 1_000_000.0);
        println!("📤 Outbound: {} transactions, {:.6} T total", outbound_count, total_outbound_value as f64 / 1_000_000.0);
        if unknown_count > 0 {
            println!("❓ Unknown:  {} transactions", unknown_count);
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
                println!("{}: {} ({} immature)", status, count, coinbase_immature);
            } else {
                println!("{}: {}", status, count);
            }
        }
        
        // Show net flow
        let net_flow = total_inbound_value as i64 - total_outbound_value as i64;
        println!();
        println!("📊 NET FLOW SUMMARY");
        println!("==================");
        println!("Net flow: {:.6} T ({})", net_flow as f64 / 1_000_000.0, 
            if net_flow > 0 { "📈 Positive" } else if net_flow < 0 { "📉 Negative" } else { "⚖️  Neutral" });
        println!("Current balance: {:.6} T", wallet_state.get_balance() as f64 / 1_000_000.0);
    }
}

#[cfg(feature = "grpc")]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = CliArgs::parse();

    // Validate input arguments
    match (&args.seed_phrase, &args.view_key) {
        (Some(_), Some(_)) => {
            eprintln!("❌ Error: Cannot specify both --seed-phrase and --view-key. Choose one.");
            std::process::exit(1);
        },
        (None, None) => {
            eprintln!("❌ Error: Must specify either --seed-phrase or --view-key.");
            eprintln!("💡 Use --help for usage information.");
            std::process::exit(1);
        },
        _ => {} // Valid: exactly one is provided
    }

    if !args.quiet {
        println!("🚀 Enhanced Tari Wallet Scanner");
        println!("===============================");
    }

    // Create scan context based on input method
    let (scan_context, default_from_block) = if let Some(seed_phrase) = &args.seed_phrase {
        if !args.quiet {
            println!("🔨 Creating wallet from seed phrase...");
        }
        let wallet = Wallet::new_from_seed_phrase(seed_phrase, None)?;
        let scan_context = ScanContext::from_wallet(&wallet)?;
        let default_from_block = wallet.birthday();
        (scan_context, default_from_block)
    } else if let Some(view_key_hex) = &args.view_key {
        if !args.quiet {
            println!("🔑 Creating scan context from view key...");
            if !args.quiet {
                println!("⚠️  Note: Range proof rewinding will be limited without seed entropy");
            }
        }
        let scan_context = ScanContext::from_view_key(view_key_hex)?;
        let default_from_block = 0; // Start from genesis when using view key only
        (scan_context, default_from_block)
    } else {
        unreachable!("Validation above ensures exactly one option is provided");
    };

    // Connect to base node
    if !args.quiet {
        println!("🌐 Connecting to Tari base node...");
    }
    let mut scanner = GrpcScannerBuilder::new()
        .with_base_url(args.base_url.clone())
        .with_timeout(std::time::Duration::from_secs(30))
        .build().await
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

    // Get blockchain tip and determine scan range
    let tip_info = scanner.get_tip_info().await?;
    if !args.quiet {
        println!("📊 Current blockchain tip: block {}", tip_info.best_block_height);
    }

    let to_block = args.to_block.unwrap_or(tip_info.best_block_height);
    let from_block = args.from_block.unwrap_or(default_from_block);

    let block_height_range = BlockHeightRange::new(from_block, to_block, args.blocks.clone());
    let config = block_height_range.into_scan_config(&args)?;

    // Perform the scan
    let wallet_state = scan_wallet_across_blocks(&mut scanner, &scan_context, &config).await?;
    
    // Display results based on output format
    match config.output_format {
        OutputFormat::Json => display_json_results(&wallet_state),
        OutputFormat::Summary => display_summary_results(&wallet_state, &config),
        OutputFormat::Detailed => display_wallet_activity(&wallet_state, config.from_block, config.to_block),
    }
    
    if !args.quiet {
        println!("✅ Scan completed successfully!");
    }
    
    Ok(())
}

/// Display results in JSON format
#[cfg(feature = "grpc")]
fn display_json_results(wallet_state: &WalletState) {
    // Simple JSON-like output for now
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
fn display_summary_results(wallet_state: &WalletState, config: &ScanConfig) {
    let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();
    
    println!("📊 WALLET SCAN SUMMARY");
    println!("=====================");
    println!("Scan range: Block {} to {}", config.from_block, config.to_block);
    println!("Total transactions: {}", wallet_state.transactions.len());
    println!("Inbound: {} transactions ({:.6} T)", inbound_count, total_received as f64 / 1_000_000.0);
    println!("Outbound: {} transactions ({:.6} T)", outbound_count, total_spent as f64 / 1_000_000.0);
    println!("Current balance: {:.6} T", balance as f64 / 1_000_000.0);
    println!("Unspent outputs: {}", unspent_count);
    println!("Spent outputs: {}", spent_count);
}

#[cfg(not(feature = "grpc"))]
fn main() {
    eprintln!("This example requires the 'grpc' feature to be enabled.");
    eprintln!("Run with: cargo run --example scanner --features grpc");
    std::process::exit(1);
} 