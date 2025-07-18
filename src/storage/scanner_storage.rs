//! Scanner storage abstraction for lightweight wallet libraries
//!
//! This module provides a clean abstraction for scanner storage operations,
//! separating storage concerns from user interaction. This enables the scanning
//! functionality to be used in different environments (CLI, WASM, library) without
//! being tightly coupled to specific UI patterns.

use std::path::Path;
use crate::{
    data_structures::{
        wallet_transaction::{WalletTransaction, WalletState},
        types::{PrivateKey, CompressedCommitment},
    },
    errors::{LightweightWalletResult, LightweightWalletError},
    storage::{WalletStorage, StoredWallet, StoredOutput, StorageStats, OutputStatus},
    scanning::{WalletScanContext, derive_entropy_from_seed_phrase},
};

#[cfg(feature = "storage")]
use crate::storage::SqliteStorage;

/// Scanner storage configuration
#[derive(Debug, Clone)]
pub struct ScannerStorageConfig {
    /// Database file path (or ":memory:" for in-memory)
    pub database_path: String,
    /// Target wallet name (if specified)
    pub wallet_name: Option<String>,
    /// Whether to use memory-only storage
    pub use_memory_storage: bool,
}

impl ScannerStorageConfig {
    /// Create config for database storage
    pub fn database<P: AsRef<Path>>(path: P) -> Self {
        Self {
            database_path: path.as_ref().to_string_lossy().to_string(),
            wallet_name: None,
            use_memory_storage: false,
        }
    }

    /// Create config for in-memory storage
    pub fn memory() -> Self {
        Self {
            database_path: ":memory:".to_string(),
            wallet_name: None,
            use_memory_storage: true,
        }
    }

    /// Set target wallet name
    pub fn with_wallet_name(mut self, name: String) -> Self {
        self.wallet_name = Some(name);
        self
    }

    /// Check if using database storage
    pub fn uses_database(&self) -> bool {
        !self.use_memory_storage
    }
}

/// Wallet selection strategy for scanner storage
#[derive(Debug, Clone)]
pub enum WalletSelectionStrategy {
    /// Use a specific wallet by name
    Named(String),
    /// Use the first available wallet
    First,
    /// Create a new wallet if none exist
    CreateDefault(WalletScanContext),
    /// Use interactive selection (requires callback)
    Interactive,
}

/// Wallet selection result from storage operations
#[derive(Debug, Clone)]
pub struct WalletSelectionResult {
    /// Selected wallet ID
    pub wallet_id: u32,
    /// Selected wallet information
    pub wallet: StoredWallet,
    /// Whether this wallet was newly created
    pub newly_created: bool,
}

/// Callback for interactive wallet selection
/// 
/// The callback receives a list of available wallets and should return the selected index,
/// or None to abort selection.
pub type WalletSelectionCallback = dyn Fn(&[StoredWallet]) -> Option<usize> + Send + Sync;

/// Scanner storage abstraction that works in different environments
/// 
/// This provides a clean interface for scanner storage operations without
/// coupling to CLI-specific user interaction patterns. Storage operations
/// are separated from UI concerns to enable use in libraries, WASM, etc.
pub struct ScannerStorage {
    #[cfg(feature = "storage")]
    storage: Option<Box<dyn WalletStorage>>,
    wallet_id: Option<u32>,
    is_memory_only: bool,
    config: ScannerStorageConfig,
}

impl ScannerStorage {
    /// Create a new memory-only scanner storage
    pub fn new_memory() -> Self {
        Self {
            #[cfg(feature = "storage")]
            storage: None,
            wallet_id: None,
            is_memory_only: true,
            config: ScannerStorageConfig::memory(),
        }
    }

    /// Create scanner storage with database backend
    #[cfg(feature = "storage")]
    pub async fn new_with_database(config: ScannerStorageConfig) -> LightweightWalletResult<Self> {
        let storage: Box<dyn WalletStorage> = if config.database_path == ":memory:" {
            Box::new(SqliteStorage::new_in_memory().await?)
        } else {
            Box::new(SqliteStorage::new(&config.database_path).await?)
        };

        storage.initialize().await?;

        Ok(Self {
            storage: Some(storage),
            wallet_id: None,
            is_memory_only: false,
            config,
        })
    }

    /// Get storage configuration
    pub fn config(&self) -> &ScannerStorageConfig {
        &self.config
    }

    /// Check if using memory-only storage
    pub fn is_memory_only(&self) -> bool {
        self.is_memory_only
    }

    /// Get current wallet ID (if any)
    pub fn wallet_id(&self) -> Option<u32> {
        self.wallet_id
    }

    /// Check if a wallet is currently selected
    pub fn has_wallet(&self) -> bool {
        self.wallet_id.is_some()
    }

    /// List available wallets in storage
    #[cfg(feature = "storage")]
    pub async fn list_wallets(&self) -> LightweightWalletResult<Vec<StoredWallet>> {
        if let Some(storage) = &self.storage {
            storage.list_wallets().await
        } else {
            Ok(Vec::new())
        }
    }

    /// Select or create a wallet using the specified strategy
    #[cfg(feature = "storage")]
    pub async fn select_wallet(
        &mut self,
        strategy: WalletSelectionStrategy,
        selection_callback: Option<&WalletSelectionCallback>,
    ) -> LightweightWalletResult<WalletSelectionResult> {
        let storage = self.storage.as_ref()
            .ok_or_else(|| LightweightWalletError::ConfigurationError(
                "No storage backend available".to_string()
            ))?;

        match strategy {
            WalletSelectionStrategy::Named(name) => {
                if let Some(wallet) = storage.get_wallet_by_name(&name).await? {
                    self.wallet_id = wallet.id;
                    Ok(WalletSelectionResult {
                        wallet_id: wallet.id.unwrap(),
                        wallet,
                        newly_created: false,
                    })
                } else {
                    Err(LightweightWalletError::ResourceNotFound(format!(
                        "Wallet '{}' not found", name
                    )))
                }
            },
            WalletSelectionStrategy::First => {
                let wallets = storage.list_wallets().await?;
                if let Some(wallet) = wallets.first() {
                    self.wallet_id = wallet.id;
                    Ok(WalletSelectionResult {
                        wallet_id: wallet.id.unwrap(),
                        wallet: wallet.clone(),
                        newly_created: false,
                    })
                } else {
                    Err(LightweightWalletError::ResourceNotFound(
                        "No wallets available".to_string()
                    ))
                }
            },
            WalletSelectionStrategy::CreateDefault(scan_context) => {
                let wallets = storage.list_wallets().await?;
                if wallets.is_empty() {
                    // Create a default wallet
                    let wallet = StoredWallet::view_only(
                        "default".to_string(), 
                        scan_context.view_key.clone(), 
                        0
                    );
                    let wallet_id = storage.save_wallet(&wallet).await?;
                    let mut saved_wallet = wallet;
                    saved_wallet.id = Some(wallet_id);
                    
                    self.wallet_id = Some(wallet_id);
                    Ok(WalletSelectionResult {
                        wallet_id,
                        wallet: saved_wallet,
                        newly_created: true,
                    })
                } else {
                    // Use first available wallet
                    let wallet = &wallets[0];
                    self.wallet_id = wallet.id;
                    Ok(WalletSelectionResult {
                        wallet_id: wallet.id.unwrap(),
                        wallet: wallet.clone(),
                        newly_created: false,
                    })
                }
            },
            WalletSelectionStrategy::Interactive => {
                let wallets = storage.list_wallets().await?;
                
                if wallets.is_empty() {
                    return Err(LightweightWalletError::ResourceNotFound(
                        "No wallets available and no keys provided to create one".to_string()
                    ));
                }

                let callback = selection_callback.ok_or_else(|| {
                    LightweightWalletError::ConfigurationError(
                        "Interactive selection requires a callback function".to_string()
                    )
                })?;

                if let Some(selected_index) = callback(&wallets) {
                    if selected_index < wallets.len() {
                        let wallet = &wallets[selected_index];
                        self.wallet_id = wallet.id;
                        Ok(WalletSelectionResult {
                            wallet_id: wallet.id.unwrap(),
                            wallet: wallet.clone(),
                            newly_created: false,
                        })
                    } else {
                        Err(LightweightWalletError::InvalidArgument {
                            argument: "wallet_selection".to_string(),
                            value: selected_index.to_string(),
                            message: format!("Invalid selection index {}, only {} wallets available", 
                                selected_index, wallets.len()),
                        })
                    }
                } else {
                    Err(LightweightWalletError::OperationNotSupported(
                        "Wallet selection cancelled by user".to_string()
                    ))
                }
            }
        }
    }

    /// Load scan context from the currently selected wallet
    #[cfg(feature = "storage")]
    pub async fn load_scan_context(&self) -> LightweightWalletResult<Option<WalletScanContext>> {
        let storage = self.storage.as_ref()
            .ok_or_else(|| LightweightWalletError::ConfigurationError(
                "No storage backend available".to_string()
            ))?;

        let wallet_id = self.wallet_id
            .ok_or_else(|| LightweightWalletError::ConfigurationError(
                "No wallet selected".to_string()
            ))?;

        if let Some(wallet) = storage.get_wallet_by_id(wallet_id).await? {
            let view_key = wallet.get_view_key().map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to get view key: {}", e))
            })?;

            // Create entropy array - derive from seed phrase if available
            let entropy = if wallet.has_seed_phrase() {
                if let Some(seed_phrase) = &wallet.seed_phrase {
                    match derive_entropy_from_seed_phrase(seed_phrase) {
                        Ok(entropy_array) => entropy_array,
                        Err(_) => [0u8; 16], // Fallback to view-key mode
                    }
                } else {
                    [0u8; 16]
                }
            } else {
                [0u8; 16] // View-only wallet
            };

            Ok(Some(WalletScanContext { view_key, entropy }))
        } else {
            Err(LightweightWalletError::ResourceNotFound(format!(
                "Wallet with ID {} not found", wallet_id
            )))
        }
    }

    /// Get wallet birthday (resume block) for the current wallet
    #[cfg(feature = "storage")]
    pub async fn get_wallet_birthday(&self) -> LightweightWalletResult<Option<u64>> {
        if let (Some(storage), Some(wallet_id)) = (&self.storage, self.wallet_id) {
            if let Some(wallet) = storage.get_wallet_by_id(wallet_id).await? {
                Ok(Some(wallet.get_resume_block()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Save transactions to storage
    #[cfg(feature = "storage")]
    pub async fn save_transactions(
        &self,
        transactions: &[WalletTransaction],
    ) -> LightweightWalletResult<()> {
        if let (Some(storage), Some(wallet_id)) = (&self.storage, self.wallet_id) {
            storage.save_transactions(wallet_id, transactions).await
        } else {
            Ok(()) // Memory-only mode
        }
    }

    /// Save UTXO outputs to storage
    #[cfg(feature = "storage")]
    pub async fn save_outputs(&self, outputs: &[StoredOutput]) -> LightweightWalletResult<Vec<u32>> {
        if let Some(storage) = &self.storage {
            storage.save_outputs(outputs).await
        } else {
            Ok(Vec::new()) // Memory-only mode
        }
    }

    /// Update wallet's latest scanned block
    #[cfg(feature = "storage")]
    pub async fn update_wallet_scanned_block(&self, block_height: u64) -> LightweightWalletResult<()> {
        if let (Some(storage), Some(wallet_id)) = (&self.storage, self.wallet_id) {
            storage.update_wallet_scanned_block(wallet_id, block_height).await
        } else {
            Ok(()) // Memory-only mode
        }
    }

    /// Mark outputs as spent in storage
    #[cfg(feature = "storage")]
    pub async fn mark_outputs_spent(
        &self, 
        spent_outputs: &[(Vec<u8>, u64, usize)]
    ) -> LightweightWalletResult<()> {
        if let Some(storage) = &self.storage {
            for (commitment, block_height, input_index) in spent_outputs {
                if let Some(mut output) = storage.get_output_by_commitment(commitment).await? {
                    // Calculate transaction ID
                    let tx_id = generate_transaction_id(*block_height, *input_index);
                    
                    // Update the output as spent
                    output.status = OutputStatus::Spent as u32;
                    output.spent_in_tx_id = Some(tx_id);
                    
                    // Save the updated output
                    storage.update_output(&output).await?;
                }
            }
        }
        Ok(())
    }

    /// Get storage statistics
    #[cfg(feature = "storage")]
    pub async fn get_statistics(&self) -> LightweightWalletResult<StorageStats> {
        if let Some(storage) = &self.storage {
            storage.get_wallet_statistics(self.wallet_id).await
        } else {
            // Return empty statistics for memory-only mode
            Ok(StorageStats {
                total_transactions: 0,
                inbound_count: 0,
                outbound_count: 0,
                unspent_count: 0,
                spent_count: 0,
                total_received: 0,
                total_spent: 0,
                current_balance: 0,
                lowest_block: None,
                highest_block: None,
                latest_scanned_block: None,
            })
        }
    }

    /// Get unspent outputs count
    #[cfg(feature = "storage")]
    pub async fn get_unspent_outputs_count(&self) -> LightweightWalletResult<usize> {
        if let (Some(storage), Some(wallet_id)) = (&self.storage, self.wallet_id) {
            let outputs = storage.get_unspent_outputs(wallet_id).await?;
            Ok(outputs.len())
        } else {
            Ok(0)
        }
    }

    /// Create a wallet selection strategy from configuration
    pub fn create_wallet_strategy(
        &self,
        scan_context: Option<&WalletScanContext>,
    ) -> WalletSelectionStrategy {
        if let Some(wallet_name) = &self.config.wallet_name {
            WalletSelectionStrategy::Named(wallet_name.clone())
        } else if let Some(context) = scan_context {
            WalletSelectionStrategy::CreateDefault(context.clone())
        } else {
            WalletSelectionStrategy::Interactive
        }
    }
}

/// Generate a deterministic transaction ID from block height and input index
/// This is used for UTXO spending tracking
fn generate_transaction_id(block_height: u64, input_index: usize) -> u64 {
    // Create a deterministic transaction ID by combining block height and input index
    // Format: [32-bit block_height][32-bit input_index]
    let tx_id = ((block_height & 0xFFFFFFFF) << 32) | (input_index as u64 & 0xFFFFFFFF);
    
    // Ensure we don't return 0 (which is often treated as "no transaction")
    if tx_id == 0 { 1 } else { tx_id }
}

/// Memory-only storage implementation for environments without database storage
pub struct MemoryStorage {
    wallet_state: WalletState,
    has_wallet: bool,
}

impl MemoryStorage {
    /// Create a new memory storage instance
    pub fn new() -> Self {
        Self {
            wallet_state: WalletState::new(),
            has_wallet: false,
        }
    }

    /// Set that a wallet is being used (for memory storage)
    pub fn set_has_wallet(&mut self, has_wallet: bool) {
        self.has_wallet = has_wallet;
    }

    /// Get the wallet state
    pub fn wallet_state(&self) -> &WalletState {
        &self.wallet_state
    }

    /// Get mutable wallet state
    pub fn wallet_state_mut(&mut self) -> &mut WalletState {
        &mut self.wallet_state
    }

    /// Check if a wallet is configured
    pub fn has_wallet(&self) -> bool {
        self.has_wallet
    }

    /// Save transactions (no-op for memory storage, transactions are in wallet_state)
    pub fn save_transactions(&self, _transactions: &[WalletTransaction]) -> LightweightWalletResult<()> {
        Ok(()) // No-op - transactions are already in wallet_state
    }

    /// Get statistics from wallet state
    pub fn get_statistics(&self) -> StorageStats {
        let (total_received, total_spent, current_balance, unspent_count, spent_count) = 
            self.wallet_state.get_summary();
        let (inbound_count, outbound_count, _) = self.wallet_state.get_direction_counts();

        // Find block range from transactions
        let mut lowest_block = None;
        let mut highest_block = None;
        
        for tx in &self.wallet_state.transactions {
            let block = tx.block_height;
            if lowest_block.is_none() || block < lowest_block.unwrap() {
                lowest_block = Some(block);
            }
            if highest_block.is_none() || block > highest_block.unwrap() {
                highest_block = Some(block);
            }
        }

        StorageStats {
            total_transactions: self.wallet_state.transactions.len(),
            inbound_count,
            outbound_count,
            unspent_count,
            spent_count,
            total_received,
            total_spent,
            current_balance,
            lowest_block,
            highest_block,
            latest_scanned_block: highest_block,
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_storage_config() {
        let config = ScannerStorageConfig::database("./test.db");
        assert_eq!(config.database_path, "./test.db");
        assert!(!config.use_memory_storage);
        assert!(config.uses_database());

        let memory_config = ScannerStorageConfig::memory();
        assert_eq!(memory_config.database_path, ":memory:");
        assert!(memory_config.use_memory_storage);
        assert!(!memory_config.uses_database());
    }

    #[test]
    fn test_memory_storage() {
        let mut storage = MemoryStorage::new();
        assert!(!storage.has_wallet());
        
        storage.set_has_wallet(true);
        assert!(storage.has_wallet());

        let stats = storage.get_statistics();
        assert_eq!(stats.total_transactions, 0);
        assert_eq!(stats.current_balance, 0);
    }

    #[test]
    fn test_generate_transaction_id() {
        let tx_id1 = generate_transaction_id(1000, 5);
        let tx_id2 = generate_transaction_id(1000, 6);
        let tx_id3 = generate_transaction_id(1001, 5);
        
        // Should be deterministic
        assert_eq!(tx_id1, generate_transaction_id(1000, 5));
        
        // Should be different for different inputs
        assert_ne!(tx_id1, tx_id2);
        assert_ne!(tx_id1, tx_id3);
        
        // Should never be zero
        assert_ne!(generate_transaction_id(0, 0), 0);
    }
} 