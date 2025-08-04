#![cfg(not(target_arch = "wasm32"))]

#[cfg(feature = "storage")]
use clap::{Parser, Subcommand};

#[cfg(feature = "storage")]
use lightweight_wallet_libs::data_structures::address::TariAddressFeatures;
#[cfg(feature = "storage")]
use lightweight_wallet_libs::wallet::Wallet;

// Storage-related imports
#[cfg(feature = "storage")]
use lightweight_wallet_libs::{
    common::format_number,
    data_structures::types::PrivateKey,
    key_management::{
        key_derivation,
        seed_phrase::{mnemonic_to_bytes, CipherSeed},
    },
    storage::{SqliteStorage, StoredWallet, WalletStorage},
    WalletError,
};

/// Tari Wallet CLI
#[cfg(feature = "storage")]
#[derive(Parser)]
#[command(name = "wallet")]
#[command(about = "Tari Wallet CLI - Generate wallets, addresses, and manage database storage")]
#[command(version, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[cfg(feature = "storage")]
#[derive(Subcommand)]
enum Commands {
    /// Generate a new wallet with seed phrase and one-sided address
    Generate {
        /// Network to use (mainnet, esmeralda, stagenet)
        #[arg(long, default_value = "mainnet")]
        network: String,

        /// Payment ID as UTF-8 string (e.g., "my-payment-123")
        #[arg(long)]
        payment_id: Option<String>,

        /// Optional passphrase for CipherSeed encryption/decryption
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Generate a one-sided address from existing seed phrase
    NewAddress {
        /// Seed phrase for the wallet
        seed_phrase: String,

        /// Network to use (mainnet, esmeralda, stagenet)
        #[arg(long, default_value = "mainnet")]
        network: String,

        /// Payment ID as UTF-8 string (e.g., "my-payment-123")
        #[arg(long)]
        payment_id: Option<String>,

        /// Optional passphrase for CipherSeed encryption/decryption
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// List all wallets stored in database
    List {
        /// Database file path
        #[arg(long, default_value = "./wallet.db")]
        database: String,
    },

    /// Create and store a new wallet in database from seed phrase or view key
    AddWallet {
        /// Seed phrase for the wallet (mutually exclusive with view-key)
        #[arg(long)]
        seed_phrase: Option<String>,

        /// Private view key as hex string (mutually exclusive with seed-phrase)
        #[arg(long)]
        view_key: Option<String>,

        /// Wallet name (required)
        #[arg(long)]
        name: String,

        /// Database file path
        #[arg(long, default_value = "./wallet.db")]
        database: String,

        /// Network to use (mainnet, esmeralda, stagenet)
        #[arg(long, default_value = "mainnet")]
        network: String,

        /// Optional passphrase for CipherSeed encryption/decryption (only used with seed-phrase)
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Query wallet information and balances
    Query {
        /// Database file path
        #[arg(long, default_value = "./wallet.db")]
        database: String,

        /// Wallet name (if not provided, will prompt for selection)
        #[arg(long)]
        wallet_name: Option<String>,

        #[command(subcommand)]
        query_command: QueryCommands,
    },

    /// Clear all data from database
    ClearDatabase {
        /// Database file path
        #[arg(long, default_value = "./wallet.db")]
        database: String,

        /// Do not prompt for confirmation
        #[arg(long, default_value = "false")]
        no_prompt: bool,
    },
}

#[cfg(feature = "storage")]
#[derive(Subcommand)]
enum QueryCommands {
    /// Show wallet balance and summary
    Balance,

    /// List unspent transaction outputs (UTXOs)
    Utxos {
        /// Show only mature UTXOs
        #[arg(long)]
        mature_only: bool,
    },

    /// Show wallet information and statistics
    Info,

    /// Show transaction history
    Transactions {
        /// Number of recent transactions to show (default: all)
        #[arg(long)]
        limit: Option<usize>,
    },
}

// Async main function to support database operations
#[cfg(feature = "storage")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            network,
            payment_id,
            passphrase,
        } => {
            handle_generate(network, payment_id, passphrase).await?;
        }
        Commands::NewAddress {
            seed_phrase,
            network,
            payment_id,
            passphrase,
        } => {
            handle_new_address(seed_phrase, network, payment_id, passphrase).await?;
        }
        Commands::List { database } => {
            handle_list_wallets(database).await?;
        }
        Commands::AddWallet {
            seed_phrase,
            view_key,
            name,
            database,
            network,
            passphrase,
        } => {
            handle_create_wallet(seed_phrase, view_key, name, database, network, passphrase)
                .await?;
        }
        Commands::Query {
            database,
            wallet_name,
            query_command,
        } => match query_command {
            QueryCommands::Balance => {
                handle_balance(database, wallet_name).await?;
            }
            QueryCommands::Utxos { mature_only } => {
                handle_utxo(database, wallet_name, mature_only).await?;
            }
            QueryCommands::Info => {
                handle_info(database, wallet_name).await?;
            }
            QueryCommands::Transactions { limit } => {
                handle_transactions(database, wallet_name, limit).await?;
            }
        },
        Commands::ClearDatabase {
            database,
            no_prompt,
        } => {
            handle_clear_database(database, no_prompt).await?;
        }
    }

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn main() {
    eprintln!("This binary is not for wasm32 targets.");
    std::process::exit(1);
}

// Non-storage version for when storage feature is not enabled
#[cfg(not(feature = "storage"))]
fn main() {
    eprintln!("❌ Error: This wallet binary requires the 'storage' feature to be enabled for full CLI functionality.");
    eprintln!("💡 Run with: cargo run --bin wallet --features storage");
    eprintln!();
    eprintln!("Available commands:");
    eprintln!("  generate        Generate a new wallet with seed phrase and one-sided address");
    eprintln!("  new-address     Generate a one-sided address from existing seed phrase");
    eprintln!("  list            List all wallets stored in database");
    eprintln!(
        "  add-wallet      Create and store a new wallet in database from seed phrase or view key"
    );
    eprintln!("  query           Query wallet information and balances");
    eprintln!("    balance       Show wallet balance and summary");
    eprintln!("    utxos         List unspent transaction outputs (UTXOs)");
    eprintln!("    info          Show wallet information and statistics");
    eprintln!("    transactions  Show transaction history");
    eprintln!("  clear-database  Clear all data from database");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  cargo run --bin wallet --features storage generate --help");
    eprintln!("  cargo run --bin wallet --features storage list");
    eprintln!("  cargo run --bin wallet --features storage query balance");
    eprintln!("  cargo run --bin wallet --features storage query --wallet-name my-wallet utxos");
    eprintln!("  cargo run --bin wallet --features storage query --database custom.db info");
    eprintln!("  cargo run --bin wallet --features storage query transactions --limit 10");
    std::process::exit(1);
}

// Storage-enabled versions of functions
#[cfg(feature = "storage")]
async fn handle_generate(
    network: String,
    payment_id: Option<String>,
    passphrase: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate network
    if !is_valid_network(&network) {
        eprintln!(
            "Error: Invalid network '{network}'. Valid networks: mainnet, esmeralda, stagenet"
        );
        return Ok(());
    }

    let payment_id_bytes = payment_id.map(|s| s.as_bytes().to_vec());
    let passphrase_ref = passphrase.as_deref();

    // Generate new wallet
    match Wallet::generate_new_with_seed_phrase(passphrase_ref) {
        Ok(mut wallet) => {
            wallet.set_network(network.clone());

            // Get seed phrase
            match wallet.export_seed_phrase() {
                Ok(seed) => {
                    println!("Seed: {seed}");

                    // Generate one-sided address using dual address method to support payment ID
                    match wallet.get_dual_address(
                        TariAddressFeatures::create_one_sided_only(),
                        payment_id_bytes,
                    ) {
                        Ok(address) => {
                            println!("Base58: {}", address.to_base58());
                            println!("Emoji: {}", address.to_emoji_string());
                            println!("Birthday: {}", wallet.birthday());

                            // Print additional info if payment ID was provided
                            if address.features().contains(TariAddressFeatures::PAYMENT_ID) {
                                println!("Payment ID included: Yes");
                            }
                        }
                        Err(e) => eprintln!("Error generating address: {e}"),
                    }
                }
                Err(e) => eprintln!("Error exporting seed: {e}"),
            }
        }
        Err(e) => eprintln!("Error creating wallet: {e}"),
    }

    Ok(())
}

#[cfg(feature = "storage")]
async fn handle_new_address(
    seed_phrase: String,
    network: String,
    payment_id: Option<String>,
    passphrase: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate network
    if !is_valid_network(&network) {
        eprintln!(
            "Error: Invalid network '{network}'. Valid networks: mainnet, esmeralda, stagenet"
        );
        return Ok(());
    }

    let payment_id_bytes = payment_id.map(|s| s.as_bytes().to_vec());
    let passphrase_ref = passphrase.as_deref();

    // Create wallet from seed
    match Wallet::new_from_seed_phrase(&seed_phrase, passphrase_ref) {
        Ok(mut wallet) => {
            wallet.set_network(network.clone());

            // Generate one-sided address using dual address method to support payment ID
            match wallet.get_dual_address(
                TariAddressFeatures::create_one_sided_only(),
                payment_id_bytes,
            ) {
                Ok(address) => {
                    println!("Base58: {}", address.to_base58());
                    println!("Emoji: {}", address.to_emoji_string());

                    // Print additional info if payment ID was provided
                    if address.features().contains(TariAddressFeatures::PAYMENT_ID) {
                        println!("Payment ID included: Yes");
                    }
                }
                Err(e) => eprintln!("Error generating address: {e}"),
            }
        }
        Err(e) => eprintln!("Error creating wallet from seed: {e}"),
    }

    Ok(())
}

/// Show wallet balance and summary
#[cfg(feature = "storage")]
async fn handle_balance(
    database_path: String,
    wallet_name: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let storage: Box<dyn WalletStorage> = if database_path == ":memory:" {
        Box::new(SqliteStorage::new_in_memory().await?)
    } else {
        Box::new(SqliteStorage::new(&database_path).await?)
    };

    storage.initialize().await?;

    let wallet = select_wallet(&*storage, wallet_name).await?;
    let stats = storage.get_wallet_statistics(wallet.id).await?;

    println!("💰 WALLET BALANCE - {}", wallet.name);
    println!("==================={}", "=".repeat(wallet.name.len()));
    println!(
        "Current balance: {} μT ({:.6} T)",
        format_number(stats.current_balance),
        stats.current_balance as f64 / 1_000_000.0
    );
    println!(
        "Total received:  {} μT ({:.6} T)",
        format_number(stats.total_received),
        stats.total_received as f64 / 1_000_000.0
    );
    println!(
        "Total spent:     {} μT ({:.6} T)",
        format_number(stats.total_spent),
        stats.total_spent as f64 / 1_000_000.0
    );
    println!();
    println!("📊 Transaction Summary:");
    println!(
        "  Inbound transactions:  {}",
        format_number(stats.inbound_count)
    );
    println!(
        "  Outbound transactions: {}",
        format_number(stats.outbound_count)
    );
    println!(
        "  Unspent outputs:       {}",
        format_number(stats.unspent_count)
    );
    println!(
        "  Spent outputs:         {}",
        format_number(stats.spent_count)
    );

    if let (Some(lowest), Some(highest)) = (stats.lowest_block, stats.highest_block) {
        println!(
            "  Block range:           {} to {}",
            format_number(lowest),
            format_number(highest)
        );
    }

    if let Some(latest_scanned) = stats.latest_scanned_block {
        println!("  Latest scanned block:  {}", format_number(latest_scanned));
    }

    Ok(())
}

/// List unspent transaction outputs (UTXOs)
#[cfg(feature = "storage")]
async fn handle_utxo(
    database_path: String,
    wallet_name: Option<String>,
    mature_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let storage: Box<dyn WalletStorage> = if database_path == ":memory:" {
        Box::new(SqliteStorage::new_in_memory().await?)
    } else {
        Box::new(SqliteStorage::new(&database_path).await?)
    };

    storage.initialize().await?;

    let wallet = select_wallet(&*storage, wallet_name).await?;
    let utxos = storage.get_unspent_outputs(wallet.id.unwrap()).await?;

    let filtered_utxos: Vec<_> = if mature_only {
        // For now, we'll assume all UTXOs are mature since we don't have current block height here
        // In a full implementation, you'd pass the current block height and filter based on maturity
        utxos
    } else {
        utxos
    };

    println!("🔗 UNSPENT OUTPUTS (UTXOs) - {}", wallet.name);
    println!(
        "=========================={}",
        "=".repeat(wallet.name.len())
    );

    if filtered_utxos.is_empty() {
        println!("No unspent outputs found.");
        return Ok(());
    }

    let mut total_value = 0u64;

    for (index, utxo) in filtered_utxos.iter().enumerate() {
        total_value += utxo.value;

        let maturity_info = if utxo.maturity > 0 {
            format!(" (maturity: {})", format_number(utxo.maturity))
        } else {
            String::new()
        };

        let script_lock_info = if utxo.script_lock_height > 0 {
            format!(" (script lock: {})", format_number(utxo.script_lock_height))
        } else {
            String::new()
        };

        println!(
            "{}. Value: {} μT ({:.6} T){}{}",
            index + 1,
            format_number(utxo.value),
            utxo.value as f64 / 1_000_000.0,
            maturity_info,
            script_lock_info
        );

        if let Some(mined_height) = utxo.mined_height {
            println!("   Block height: {}", format_number(mined_height));
        }

        println!("   Commitment: {}", hex::encode(&utxo.commitment[..8]));

        if !utxo.input_data.is_empty() {
            if let Ok(text) = std::str::from_utf8(&utxo.input_data) {
                if text
                    .chars()
                    .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                {
                    println!("   Input data: \"{text}\"");
                } else {
                    println!(
                        "   Input data (hex): {}",
                        hex::encode(&utxo.input_data[..std::cmp::min(32, utxo.input_data.len())])
                    );
                }
            } else {
                println!(
                    "   Input data (hex): {}",
                    hex::encode(&utxo.input_data[..std::cmp::min(32, utxo.input_data.len())])
                );
            }
        }
        println!();
    }

    println!("📊 Summary:");
    println!("  Total UTXOs: {}", format_number(filtered_utxos.len()));
    println!(
        "  Total value: {} μT ({:.6} T)",
        format_number(total_value),
        total_value as f64 / 1_000_000.0
    );

    Ok(())
}

/// Show wallet information and statistics
#[cfg(feature = "storage")]
async fn handle_info(
    database_path: String,
    wallet_name: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let storage: Box<dyn WalletStorage> = if database_path == ":memory:" {
        Box::new(SqliteStorage::new_in_memory().await?)
    } else {
        Box::new(SqliteStorage::new(&database_path).await?)
    };

    storage.initialize().await?;

    let wallet = select_wallet(&*storage, wallet_name).await?;
    let stats = storage.get_wallet_statistics(wallet.id).await?;

    println!("🏦 WALLET INFORMATION - {}", wallet.name);
    println!("======================={}", "=".repeat(wallet.name.len()));

    let wallet_type = if wallet.has_seed_phrase() {
        "Full wallet (with seed phrase)"
    } else if wallet.can_spend() {
        "Full wallet (spending keys only)"
    } else {
        "View-only wallet"
    };

    println!("Wallet type:    {wallet_type}");
    println!("Birthday block: {}", format_number(wallet.birthday_block));

    if let Some(latest_scanned) = stats.latest_scanned_block {
        println!("Latest scanned: {}", format_number(latest_scanned));
        if latest_scanned > wallet.birthday_block {
            println!(
                "Scanned blocks: {}",
                format_number(latest_scanned - wallet.birthday_block + 1)
            );
        }
    }

    println!();
    println!("💰 Balance Information:");
    println!(
        "  Current balance: {} μT ({:.6} T)",
        format_number(stats.current_balance),
        stats.current_balance as f64 / 1_000_000.0
    );
    println!(
        "  Total received:  {} μT ({:.6} T)",
        format_number(stats.total_received),
        stats.total_received as f64 / 1_000_000.0
    );
    println!(
        "  Total spent:     {} μT ({:.6} T)",
        format_number(stats.total_spent),
        stats.total_spent as f64 / 1_000_000.0
    );

    println!();
    println!("📊 Transaction Statistics:");
    println!(
        "  Total transactions: {}",
        format_number(stats.total_transactions)
    );
    println!(
        "  Inbound:            {}",
        format_number(stats.inbound_count)
    );
    println!(
        "  Outbound:           {}",
        format_number(stats.outbound_count)
    );

    println!();
    println!("🔗 Output Statistics:");
    println!("  Unspent outputs: {}", format_number(stats.unspent_count));
    println!("  Spent outputs:   {}", format_number(stats.spent_count));

    if let (Some(lowest), Some(highest)) = (stats.lowest_block, stats.highest_block) {
        println!();
        println!("📊 Block Range:");
        println!("  First activity: Block {}", format_number(lowest));
        println!("  Last activity:  Block {}", format_number(highest));
        println!(
            "  Block span:     {} blocks",
            format_number(highest - lowest + 1)
        );
    }

    if wallet.has_seed_phrase() {
        println!();
        println!("🔐 Security:");
        println!("  Seed phrase: Available (use 'wallet export-seed' to view)");
        println!("  Can spend:   Yes");
    } else if wallet.can_spend() {
        println!();
        println!("🔐 Security:");
        println!("  Seed phrase: Not available");
        println!("  Can spend:   Yes (private keys available)");
    } else {
        println!();
        println!("🔐 Security:");
        println!("  Seed phrase: Not available");
        println!("  Can spend:   No (view-only)");
    }

    Ok(())
}

/// Show transaction history
#[cfg(feature = "storage")]
async fn handle_transactions(
    database_path: String,
    wallet_name: Option<String>,
    limit: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let storage: Box<dyn WalletStorage> = if database_path == ":memory:" {
        Box::new(SqliteStorage::new_in_memory().await?)
    } else {
        Box::new(SqliteStorage::new(&database_path).await?)
    };

    storage.initialize().await?;

    let wallet = select_wallet(&*storage, wallet_name).await?;

    // Create filter for the specific wallet
    use lightweight_wallet_libs::storage::TransactionFilter;
    let filter = TransactionFilter {
        wallet_id: wallet.id,
        limit,
        ..Default::default()
    };

    let mut transactions = storage.get_transactions(Some(filter)).await?;

    // Sort transactions by block height (newest first)
    transactions.sort_by(|a, b| b.block_height.cmp(&a.block_height));

    if let Some(limit_count) = limit {
        transactions.truncate(limit_count);
    }

    println!("📋 TRANSACTION HISTORY - {}", wallet.name);
    println!("========================{}", "=".repeat(wallet.name.len()));

    if transactions.is_empty() {
        println!("No transactions found.");
        return Ok(());
    }

    for (index, tx) in transactions.iter().enumerate() {
        let direction_symbol = match tx.transaction_direction {
            lightweight_wallet_libs::data_structures::transaction::TransactionDirection::Inbound => "📥",
            lightweight_wallet_libs::data_structures::transaction::TransactionDirection::Outbound => "📤",
            lightweight_wallet_libs::data_structures::transaction::TransactionDirection::Unknown => "❓",
        };

        let amount_display = match tx.transaction_direction {
            lightweight_wallet_libs::data_structures::transaction::TransactionDirection::Inbound => format!("+{} μT", format_number(tx.value)),
            lightweight_wallet_libs::data_structures::transaction::TransactionDirection::Outbound => format!("-{} μT", format_number(tx.value)),
            lightweight_wallet_libs::data_structures::transaction::TransactionDirection::Unknown => format!("±{} μT", format_number(tx.value)),
        };

        let status_text = if tx.is_spent { "SPENT" } else { "UNSPENT" };

        println!(
            "{}. {} Block {}: {} ({:.6} T) - {} [{}]",
            index + 1,
            direction_symbol,
            format_number(tx.block_height),
            amount_display,
            tx.value as f64 / 1_000_000.0,
            status_text,
            tx.transaction_status
        );

        // Show payment ID if available
        if !tx.payment_id.user_data_as_string().is_empty() {
            println!(
                "   💬 Payment ID: \"{}\"",
                tx.payment_id.user_data_as_string()
            );
        }

        // Show spending details for outbound transactions
        if tx.transaction_direction
            == lightweight_wallet_libs::data_structures::transaction::TransactionDirection::Outbound
        {
            if let Some(input_index) = tx.input_index {
                println!("   └─ Spent as input #{}", format_number(input_index));
            }
        }

        // Show spending details for spent inbound transactions
        if tx.transaction_direction
            == lightweight_wallet_libs::data_structures::transaction::TransactionDirection::Inbound
            && tx.is_spent
        {
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

    let stats = storage.get_wallet_statistics(wallet.id).await?;
    println!();
    println!("📊 Summary:");
    if let Some(_limit_count) = limit {
        println!(
            "  Showing {} of {} total transactions",
            format_number(transactions.len()),
            format_number(stats.total_transactions)
        );
    } else {
        println!(
            "  Total transactions: {}",
            format_number(stats.total_transactions)
        );
    }
    println!(
        "  Current balance: {} μT ({:.6} T)",
        format_number(stats.current_balance),
        stats.current_balance as f64 / 1_000_000.0
    );

    Ok(())
}

/// Select a wallet from the database, with interactive selection if multiple wallets exist
#[cfg(feature = "storage")]
async fn select_wallet(
    storage: &dyn WalletStorage,
    wallet_name: Option<String>,
) -> Result<StoredWallet, Box<dyn std::error::Error>> {
    // If wallet name is specified, try to find it
    if let Some(name) = wallet_name {
        if let Some(wallet) = storage.get_wallet_by_name(&name).await? {
            return Ok(wallet);
        } else {
            return Err(format!("Wallet '{name}' not found").into());
        }
    }

    // Get all wallets
    let wallets = storage.list_wallets().await?;

    if wallets.is_empty() {
        Err("No wallets found in database. Use 'wallet add-wallet' to create one.".into())
    } else if wallets.len() == 1 {
        println!("📂 Using wallet: {}", wallets[0].name);
        return Ok(wallets[0].clone());
    } else {
        // Multiple wallets - prompt for selection
        println!("\n📂 Available wallets in database:");
        println!("================================");

        for (index, wallet) in wallets.iter().enumerate() {
            let wallet_type = if wallet.has_seed_phrase() {
                "Full wallet"
            } else if wallet.can_spend() {
                "Spending wallet"
            } else {
                "View-only"
            };

            println!(
                "{}. {} - {} (birthday: block {})",
                index + 1,
                wallet.name,
                wallet_type,
                format_number(wallet.birthday_block)
            );
        }

        println!("\nSelect a wallet:");
        print!(
            "Enter wallet number (1-{}), or 'q' to quit: ",
            wallets.len()
        );
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let choice = input.trim().to_lowercase();

        if choice == "q" || choice == "quit" {
            println!("👋 Operation cancelled.");
            std::process::exit(0);
        }

        match choice.parse::<usize>() {
            Ok(selection) if selection >= 1 && selection <= wallets.len() => {
                let selected_wallet = &wallets[selection - 1];
                println!("✅ Selected wallet: {}", selected_wallet.name);
                Ok(selected_wallet.clone())
            }
            _ => Err(format!(
                "Invalid selection. Please enter a number between 1 and {}, or 'q' to quit.",
                wallets.len()
            )
            .into()),
        }
    }
}

/// List all wallets stored in the database
#[cfg(feature = "storage")]
async fn handle_list_wallets(database_path: String) -> Result<(), Box<dyn std::error::Error>> {
    // Create storage connection
    let storage: Box<dyn WalletStorage> = if database_path == ":memory:" {
        Box::new(SqliteStorage::new_in_memory().await?)
    } else {
        Box::new(SqliteStorage::new(&database_path).await?)
    };

    storage.initialize().await?;

    // List wallets
    let wallets = storage.list_wallets().await?;
    if wallets.is_empty() {
        println!("📂 No wallets found in database: {database_path}");
    } else {
        println!("📂 Available wallets in database: {database_path}");
        for wallet in &wallets {
            let wallet_type = if wallet.has_seed_phrase() {
                "Full (seed phrase)"
            } else if wallet.can_spend() {
                "Full (keys)"
            } else {
                "View-only"
            };

            println!(
                "  • {} - {} (birthday: block {})",
                wallet.name,
                wallet_type,
                format_number(wallet.birthday_block)
            );
        }
    }

    Ok(())
}

/// Create and store a new wallet in the database
#[cfg(feature = "storage")]
async fn handle_create_wallet(
    seed_phrase: Option<String>,
    view_key: Option<String>,
    wallet_name: String,
    database_path: String,
    network: String,
    passphrase: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate that exactly one of seed_phrase or view_key is provided
    match (&seed_phrase, &view_key) {
        (Some(_), Some(_)) => {
            eprintln!(
                "Error: Cannot specify both --seed-phrase and --view-key. Please provide only one."
            );
            return Ok(());
        }
        (None, None) => {
            eprintln!("Error: Must specify either --seed-phrase or --view-key.");
            return Ok(());
        }
        _ => {} // Exactly one is provided, continue
    }

    // Validate network
    if !is_valid_network(&network) {
        eprintln!(
            "Error: Invalid network '{network}'. Valid networks: mainnet, esmeralda, stagenet"
        );
        return Ok(());
    }

    let passphrase_ref = passphrase.as_deref();

    // Create storage connection
    let storage: Box<dyn WalletStorage> = if database_path == ":memory:" {
        Box::new(SqliteStorage::new_in_memory().await?)
    } else {
        Box::new(SqliteStorage::new(&database_path).await?)
    };

    storage.initialize().await?;

    // Check if wallet name already exists
    if storage.wallet_name_exists(&wallet_name).await? {
        eprintln!("Error: Wallet name '{wallet_name}' already exists");
        return Ok(());
    }

    let stored_wallet = if let Some(seed_phrase) = seed_phrase {
        // Create wallet from seed phrase
        let wallet = Wallet::new_from_seed_phrase(&seed_phrase, passphrase_ref)?;

        // Derive view key and spend key from seed phrase
        let encrypted_bytes = mnemonic_to_bytes(&seed_phrase)?;
        let cipher_seed = CipherSeed::from_enciphered_bytes(&encrypted_bytes, passphrase_ref)?;
        let entropy = cipher_seed.entropy();

        let entropy_array: [u8; 16] = entropy.try_into().map_err(|_| {
            WalletError::KeyManagementError(
                lightweight_wallet_libs::KeyManagementError::key_derivation_failed(
                    "Invalid entropy length",
                ),
            )
        })?;

        // Derive view key
        let view_key_raw =
            key_derivation::derive_private_key_from_entropy(&entropy_array, "data encryption", 0)?;
        let view_key = PrivateKey::new({
            use tari_utilities::ByteArray;
            view_key_raw.as_bytes().try_into().map_err(|_| {
                WalletError::KeyManagementError(
                    lightweight_wallet_libs::KeyManagementError::key_derivation_failed(
                        "Failed to convert view key",
                    ),
                )
            })?
        });

        // For now, use view key as spend key - this should be properly derived from seed in production
        let spend_key = view_key.clone();

        // Create stored wallet with seed phrase
        StoredWallet::from_seed_phrase(
            wallet_name.clone(),
            seed_phrase.to_string(),
            view_key,
            spend_key,
            wallet.birthday(), // Use wallet birthday
        )
    } else if let Some(view_key_hex) = view_key {
        // Create view-only wallet from view key
        let view_key_bytes =
            hex::decode(&view_key_hex).map_err(|_| "Invalid hex format for view key")?;

        if view_key_bytes.len() != 32 {
            return Err("View key must be exactly 32 bytes (64 hex characters)".into());
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&view_key_bytes);
        let view_key = PrivateKey::new(key_array);

        // Create view-only wallet (no spend key, no seed phrase)
        StoredWallet::view_only(
            wallet_name.clone(),
            view_key,
            0, // Default birthday block - user should scan from appropriate block
        )
    } else {
        unreachable!("Validation should have caught this case");
    };

    // Save wallet to database
    let wallet_id = storage.save_wallet(&stored_wallet).await?;

    let wallet_type = if stored_wallet.has_seed_phrase() {
        "full wallet with seed phrase"
    } else {
        "view-only wallet"
    };

    println!(
        "✅ Created {wallet_type} '{wallet_name}' with ID {wallet_id} in database: {database_path}"
    );
    println!(
        "   Birthday: block {}",
        format_number(stored_wallet.birthday_block)
    );
    println!("   Network: {network}");

    if !stored_wallet.has_seed_phrase() {
        println!("   ⚠️  This is a view-only wallet - you cannot spend from it");
        println!("   💡 To scan from a specific block, use the scanner with --from-block option");
    }

    Ok(())
}

/// Clear all data from the database
#[cfg(feature = "storage")]
async fn handle_clear_database(
    database_path: String,
    no_prompt: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if database_path == ":memory:" {
        println!("Cannot clear in-memory database");
        return Ok(());
    }

    // Confirm action
    println!("⚠️  WARNING: This will permanently delete ALL data from: {database_path}");
    let confirmation = if !no_prompt {
        print!("Are you sure you want to continue? (yes/no): ");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        input.trim().to_lowercase()
    } else {
        "yes".to_string()
    };

    if confirmation != "yes" && confirmation != "y" {
        println!("Operation cancelled");
        return Ok(());
    }

    // Create storage connection
    let storage: Box<dyn WalletStorage> = Box::new(SqliteStorage::new(&database_path).await?);
    storage.initialize().await?;

    // Clear all data
    storage.clear_all_transactions().await?;

    println!("✅ Database cleared successfully: {database_path}");

    Ok(())
}

#[cfg(feature = "storage")]
fn is_valid_network(network: &str) -> bool {
    matches!(network, "mainnet" | "esmeralda" | "stagenet")
}
