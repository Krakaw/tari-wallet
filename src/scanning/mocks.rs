//! Mock implementations for storage and network layers for deterministic testing
//!
//! This module provides mock implementations of key traits used in the scanning library
//! to enable deterministic testing without requiring real storage or network connections.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::{
    data_structures::{
        transaction::TransactionDirection,
        types::CompressedCommitment,
        wallet_transaction::{WalletState, WalletTransaction},
    },
    errors::{LightweightWalletError, LightweightWalletResult},
    storage::storage_trait::{
        OutputFilter, OutputStatus, StorageStats, StoredOutput, StoredWallet, TransactionFilter,
        WalletStorage,
    },
};

use crate::data_structures::transaction_output::LightweightTransactionOutput;

use super::{BlockInfo, BlockScanResult, BlockchainScanner, ScanConfig, TipInfo};

/// Mock storage implementation for deterministic testing
#[derive(Debug, Clone)]
pub struct MockWalletStorage {
    /// In-memory storage for wallets
    wallets: Arc<Mutex<HashMap<u32, StoredWallet>>>,
    /// In-memory storage for outputs
    outputs: Arc<Mutex<HashMap<u32, StoredOutput>>>,
    /// In-memory storage for transactions with wallet_id mapping
    transactions: Arc<Mutex<HashMap<u32, (u32, WalletTransaction)>>>, // (tx_id, (wallet_id, transaction))
    /// Next available wallet ID
    next_wallet_id: Arc<Mutex<u32>>,
    /// Next available output ID
    next_output_id: Arc<Mutex<u32>>,
    /// Next available transaction ID
    next_transaction_id: Arc<Mutex<u32>>,
    /// Simulated failure modes for testing error conditions
    failure_modes: Arc<Mutex<MockFailureModes>>,
}

#[derive(Debug, Clone, Default)]
pub struct MockFailureModes {
    /// Fail next save_wallet call
    pub fail_save_wallet: bool,
    /// Fail next save_transaction call
    pub fail_save_transaction: bool,
    /// Fail next save_output call
    pub fail_save_output: bool,
    /// Fail next get operation
    pub fail_get_operations: bool,
    /// Return specific error message for next operation
    pub next_error_message: Option<String>,
}

impl Default for MockWalletStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MockWalletStorage {
    /// Create a new mock storage instance
    pub fn new() -> Self {
        Self {
            wallets: Arc::new(Mutex::new(HashMap::new())),
            outputs: Arc::new(Mutex::new(HashMap::new())),
            transactions: Arc::new(Mutex::new(HashMap::new())),
            next_wallet_id: Arc::new(Mutex::new(1)),
            next_output_id: Arc::new(Mutex::new(1)),
            next_transaction_id: Arc::new(Mutex::new(1)),
            failure_modes: Arc::new(Mutex::new(MockFailureModes::default())),
        }
    }

    /// Reset the mock storage to empty state
    pub fn reset(&self) {
        self.wallets.lock().unwrap().clear();
        self.outputs.lock().unwrap().clear();
        self.transactions.lock().unwrap().clear();
        *self.next_wallet_id.lock().unwrap() = 1;
        *self.next_output_id.lock().unwrap() = 1;
        *self.next_transaction_id.lock().unwrap() = 1;
        *self.failure_modes.lock().unwrap() = MockFailureModes::default();
    }

    /// Set failure mode for testing error conditions
    pub fn set_failure_mode(&self, mode: MockFailureModes) {
        *self.failure_modes.lock().unwrap() = mode;
    }

    /// Get the current failure modes
    pub fn get_failure_modes(&self) -> MockFailureModes {
        self.failure_modes.lock().unwrap().clone()
    }

    /// Check if an operation should fail and return the appropriate error
    fn check_failure(&self, operation: &str) -> LightweightWalletResult<()> {
        let mut modes = self.failure_modes.lock().unwrap();

        // Check for specific error to return
        if let Some(error_msg) = modes.next_error_message.take() {
            return Err(LightweightWalletError::StorageError(error_msg));
        }

        // Check operation-specific failures
        match operation {
            "save_wallet" if modes.fail_save_wallet => {
                modes.fail_save_wallet = false; // Reset after use
                Err(LightweightWalletError::StorageError(
                    "Mock failure: save_wallet".to_string(),
                ))
            }
            "save_transaction" if modes.fail_save_transaction => {
                modes.fail_save_transaction = false; // Reset after use
                Err(LightweightWalletError::StorageError(
                    "Mock failure: save_transaction".to_string(),
                ))
            }
            "save_output" if modes.fail_save_output => {
                modes.fail_save_output = false; // Reset after use
                Err(LightweightWalletError::StorageError(
                    "Mock failure: save_output".to_string(),
                ))
            }
            "get" if modes.fail_get_operations => {
                modes.fail_get_operations = false; // Reset after use
                Err(LightweightWalletError::StorageError(
                    "Mock failure: get operation".to_string(),
                ))
            }
            _ => Ok(()),
        }
    }

    /// Get next available wallet ID
    fn next_wallet_id(&self) -> u32 {
        let mut id = self.next_wallet_id.lock().unwrap();
        let result = *id;
        *id += 1;
        result
    }

    /// Get next available output ID
    fn next_output_id(&self) -> u32 {
        let mut id = self.next_output_id.lock().unwrap();
        let result = *id;
        *id += 1;
        result
    }

    /// Get next available transaction ID
    fn next_transaction_id(&self) -> u32 {
        let mut id = self.next_transaction_id.lock().unwrap();
        let result = *id;
        *id += 1;
        result
    }
}

#[async_trait]
impl WalletStorage for MockWalletStorage {
    async fn initialize(&self) -> LightweightWalletResult<()> {
        // Mock storage is always initialized
        Ok(())
    }

    // === Wallet Management Methods ===

    async fn save_wallet(&self, wallet: &StoredWallet) -> LightweightWalletResult<u32> {
        self.check_failure("save_wallet")?;

        let mut wallets = self.wallets.lock().unwrap();
        let wallet_id = wallet.id.unwrap_or_else(|| self.next_wallet_id());

        let mut stored_wallet = wallet.clone();
        stored_wallet.id = Some(wallet_id);

        wallets.insert(wallet_id, stored_wallet);
        Ok(wallet_id)
    }

    async fn get_wallet_by_id(
        &self,
        wallet_id: u32,
    ) -> LightweightWalletResult<Option<StoredWallet>> {
        self.check_failure("get")?;
        let wallets = self.wallets.lock().unwrap();
        Ok(wallets.get(&wallet_id).cloned())
    }

    async fn get_wallet_by_name(
        &self,
        name: &str,
    ) -> LightweightWalletResult<Option<StoredWallet>> {
        self.check_failure("get")?;
        let wallets = self.wallets.lock().unwrap();
        Ok(wallets.values().find(|w| w.name == name).cloned())
    }

    async fn list_wallets(&self) -> LightweightWalletResult<Vec<StoredWallet>> {
        self.check_failure("get")?;
        let wallets = self.wallets.lock().unwrap();
        Ok(wallets.values().cloned().collect())
    }

    async fn delete_wallet(&self, wallet_id: u32) -> LightweightWalletResult<bool> {
        let mut wallets = self.wallets.lock().unwrap();
        let removed = wallets.remove(&wallet_id).is_some();

        // Also remove associated transactions and outputs
        if removed {
            let mut transactions = self.transactions.lock().unwrap();
            transactions.retain(|_, (tx_wallet_id, _)| *tx_wallet_id != wallet_id);

            let mut outputs = self.outputs.lock().unwrap();
            outputs.retain(|_, output| output.wallet_id != wallet_id);
        }

        Ok(removed)
    }

    async fn wallet_name_exists(&self, name: &str) -> LightweightWalletResult<bool> {
        self.check_failure("get")?;
        let wallets = self.wallets.lock().unwrap();
        Ok(wallets.values().any(|w| w.name == name))
    }

    async fn update_wallet_scanned_block(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> LightweightWalletResult<()> {
        let mut wallets = self.wallets.lock().unwrap();
        if let Some(wallet) = wallets.get_mut(&wallet_id) {
            wallet.latest_scanned_block = Some(block_height);
        }
        Ok(())
    }

    // === Transaction Management Methods ===

    async fn save_transaction(
        &self,
        wallet_id: u32,
        transaction: &WalletTransaction,
    ) -> LightweightWalletResult<()> {
        self.check_failure("save_transaction")?;

        let mut transactions = self.transactions.lock().unwrap();
        let tx_id = self.next_transaction_id();

        transactions.insert(tx_id, (wallet_id, transaction.clone()));
        Ok(())
    }

    async fn save_transactions(
        &self,
        wallet_id: u32,
        transactions: &[WalletTransaction],
    ) -> LightweightWalletResult<()> {
        for transaction in transactions {
            self.save_transaction(wallet_id, transaction).await?;
        }
        Ok(())
    }

    async fn update_transaction(
        &self,
        transaction: &WalletTransaction,
    ) -> LightweightWalletResult<()> {
        let mut transactions = self.transactions.lock().unwrap();

        // Find transaction by commitment and update
        for (_, (_, stored_tx)) in transactions.iter_mut() {
            if stored_tx.commitment == transaction.commitment {
                *stored_tx = transaction.clone();
                return Ok(());
            }
        }

        Err(LightweightWalletError::StorageError(
            "Transaction not found".to_string(),
        ))
    }

    async fn mark_transaction_spent(
        &self,
        commitment: &CompressedCommitment,
        spent_in_block: u64,
        _spent_in_input: usize,
    ) -> LightweightWalletResult<bool> {
        let mut transactions = self.transactions.lock().unwrap();

        for (_, (_, transaction)) in transactions.iter_mut() {
            if &transaction.commitment == commitment {
                // Create a new transaction with updated spent status
                let mut updated_tx = transaction.clone();
                updated_tx.is_spent = true;
                updated_tx.spent_in_block = Some(spent_in_block);
                *transaction = updated_tx;
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn mark_transactions_spent_batch(
        &self,
        spent_commitments: &[(CompressedCommitment, u64, usize)],
    ) -> LightweightWalletResult<usize> {
        let mut count = 0;
        for (commitment, block_height, input_index) in spent_commitments {
            if self
                .mark_transaction_spent(commitment, *block_height, *input_index)
                .await?
            {
                count += 1;
            }
        }
        Ok(count)
    }

    async fn get_transaction_by_commitment(
        &self,
        commitment: &CompressedCommitment,
    ) -> LightweightWalletResult<Option<WalletTransaction>> {
        self.check_failure("get")?;
        let transactions = self.transactions.lock().unwrap();
        Ok(transactions
            .values()
            .find(|(_, tx)| &tx.commitment == commitment)
            .map(|(_, tx)| tx.clone()))
    }

    async fn get_transactions(
        &self,
        filter: Option<TransactionFilter>,
    ) -> LightweightWalletResult<Vec<WalletTransaction>> {
        self.check_failure("get")?;
        let transactions = self.transactions.lock().unwrap();
        let mut results: Vec<WalletTransaction> = transactions
            .values()
            .filter_map(|(wallet_id, tx)| {
                // Apply wallet_id filter if specified
                if let Some(ref filter) = filter {
                    if let Some(filter_wallet_id) = filter.wallet_id {
                        if *wallet_id != filter_wallet_id {
                            return None;
                        }
                    }
                }
                Some(tx.clone())
            })
            .collect();

        if let Some(filter) = filter {
            if let Some(direction) = filter.direction {
                results.retain(|tx| tx.transaction_direction == direction);
            }
            if let Some(status) = filter.status {
                results.retain(|tx| tx.transaction_status == status);
            }
            if let Some((from, to)) = filter.block_height_range {
                results.retain(|tx| tx.block_height >= from && tx.block_height <= to);
            }
            if let Some(limit) = filter.limit {
                results.truncate(limit);
            }
        }

        Ok(results)
    }

    async fn load_wallet_state(&self, wallet_id: u32) -> LightweightWalletResult<WalletState> {
        self.check_failure("get")?;
        let transactions = self.transactions.lock().unwrap();
        let wallet_transactions: Vec<WalletTransaction> = transactions
            .values()
            .filter_map(|(tx_wallet_id, tx)| {
                if *tx_wallet_id == wallet_id {
                    Some(tx.clone())
                } else {
                    None
                }
            })
            .collect();

        let mut wallet_state = WalletState::new();
        for transaction in wallet_transactions {
            wallet_state.add_received_output(
                transaction.block_height,
                transaction.output_index.unwrap_or(0),
                transaction.commitment.clone(),
                transaction.output_hash.clone(),
                transaction.value,
                transaction.payment_id,
                transaction.transaction_status,
                transaction.transaction_direction,
                transaction.is_mature,
            );
        }

        Ok(wallet_state)
    }

    async fn get_statistics(&self) -> LightweightWalletResult<StorageStats> {
        self.check_failure("get")?;
        let transactions = self.transactions.lock().unwrap();

        let total_transactions = transactions.len();
        let inbound_count = transactions
            .values()
            .filter(|(_, tx)| tx.transaction_direction == TransactionDirection::Inbound)
            .count();
        let outbound_count = transactions
            .values()
            .filter(|(_, tx)| tx.transaction_direction == TransactionDirection::Outbound)
            .count();
        let unspent_count = transactions.values().filter(|(_, tx)| !tx.is_spent).count();
        let spent_count = transactions.values().filter(|(_, tx)| tx.is_spent).count();

        let total_received: u64 = transactions
            .values()
            .filter(|(_, tx)| tx.transaction_direction == TransactionDirection::Inbound)
            .map(|(_, tx)| tx.value)
            .sum();

        let total_spent: u64 = transactions
            .values()
            .filter(|(_, tx)| tx.transaction_direction == TransactionDirection::Outbound)
            .map(|(_, tx)| tx.value)
            .sum();

        let current_balance = total_received as i64 - total_spent as i64;

        let highest_block = transactions.values().map(|(_, tx)| tx.block_height).max();
        let lowest_block = transactions.values().map(|(_, tx)| tx.block_height).min();

        Ok(StorageStats {
            total_transactions,
            inbound_count,
            outbound_count,
            unspent_count,
            spent_count,
            total_received,
            total_spent,
            current_balance,
            highest_block,
            lowest_block,
            latest_scanned_block: None, // Would need to track this separately
        })
    }

    async fn get_wallet_statistics(
        &self,
        wallet_id: Option<u32>,
    ) -> LightweightWalletResult<StorageStats> {
        if let Some(wallet_id) = wallet_id {
            let filter = TransactionFilter::new().with_wallet_id(wallet_id);
            let transactions = self.get_transactions(Some(filter)).await?;

            let total_transactions = transactions.len();
            let inbound_count = transactions
                .iter()
                .filter(|tx| tx.transaction_direction == TransactionDirection::Inbound)
                .count();
            let outbound_count = transactions
                .iter()
                .filter(|tx| tx.transaction_direction == TransactionDirection::Outbound)
                .count();
            let unspent_count = transactions.iter().filter(|tx| !tx.is_spent).count();
            let spent_count = transactions.iter().filter(|tx| tx.is_spent).count();

            let total_received: u64 = transactions
                .iter()
                .filter(|tx| tx.transaction_direction == TransactionDirection::Inbound)
                .map(|tx| tx.value)
                .sum();

            let total_spent: u64 = transactions
                .iter()
                .filter(|tx| tx.transaction_direction == TransactionDirection::Outbound)
                .map(|tx| tx.value)
                .sum();

            let current_balance = total_received as i64 - total_spent as i64;

            let highest_block = transactions.iter().map(|tx| tx.block_height).max();
            let lowest_block = transactions.iter().map(|tx| tx.block_height).min();

            Ok(StorageStats {
                total_transactions,
                inbound_count,
                outbound_count,
                unspent_count,
                spent_count,
                total_received,
                total_spent,
                current_balance,
                highest_block,
                lowest_block,
                latest_scanned_block: None,
            })
        } else {
            self.get_statistics().await
        }
    }

    async fn get_transactions_by_block_range(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> LightweightWalletResult<Vec<WalletTransaction>> {
        self.check_failure("get")?;
        let transactions = self.transactions.lock().unwrap();
        Ok(transactions
            .values()
            .filter(|(_, tx)| tx.block_height >= from_block && tx.block_height <= to_block)
            .map(|(_, tx)| tx.clone())
            .collect())
    }

    async fn get_unspent_transactions(&self) -> LightweightWalletResult<Vec<WalletTransaction>> {
        self.check_failure("get")?;
        let transactions = self.transactions.lock().unwrap();
        Ok(transactions
            .values()
            .filter(|(_, tx)| !tx.is_spent)
            .map(|(_, tx)| tx.clone())
            .collect())
    }

    async fn get_spent_transactions(&self) -> LightweightWalletResult<Vec<WalletTransaction>> {
        self.check_failure("get")?;
        let transactions = self.transactions.lock().unwrap();
        Ok(transactions
            .values()
            .filter(|(_, tx)| tx.is_spent)
            .map(|(_, tx)| tx.clone())
            .collect())
    }

    async fn has_commitment(
        &self,
        commitment: &CompressedCommitment,
    ) -> LightweightWalletResult<bool> {
        self.check_failure("get")?;
        let transactions = self.transactions.lock().unwrap();
        Ok(transactions
            .values()
            .any(|(_, tx)| &tx.commitment == commitment))
    }

    async fn get_highest_block(&self) -> LightweightWalletResult<Option<u64>> {
        self.check_failure("get")?;
        let transactions = self.transactions.lock().unwrap();
        Ok(transactions.values().map(|(_, tx)| tx.block_height).max())
    }

    async fn get_lowest_block(&self) -> LightweightWalletResult<Option<u64>> {
        self.check_failure("get")?;
        let transactions = self.transactions.lock().unwrap();
        Ok(transactions.values().map(|(_, tx)| tx.block_height).min())
    }

    async fn clear_all_transactions(&self) -> LightweightWalletResult<()> {
        self.transactions.lock().unwrap().clear();
        Ok(())
    }

    async fn get_transaction_count(&self) -> LightweightWalletResult<usize> {
        self.check_failure("get")?;
        let transactions = self.transactions.lock().unwrap();
        Ok(transactions.len())
    }

    async fn close(&self) -> LightweightWalletResult<()> {
        // Mock storage doesn't need to close connections
        Ok(())
    }

    // === UTXO Output Management Methods ===

    async fn save_output(&self, output: &StoredOutput) -> LightweightWalletResult<u32> {
        self.check_failure("save_output")?;

        let mut outputs = self.outputs.lock().unwrap();
        let output_id = output.id.unwrap_or_else(|| self.next_output_id());

        let mut stored_output = output.clone();
        stored_output.id = Some(output_id);

        outputs.insert(output_id, stored_output);
        Ok(output_id)
    }

    async fn save_outputs(&self, outputs: &[StoredOutput]) -> LightweightWalletResult<Vec<u32>> {
        let mut ids = Vec::new();
        for output in outputs {
            ids.push(self.save_output(output).await?);
        }
        Ok(ids)
    }

    async fn update_output(&self, output: &StoredOutput) -> LightweightWalletResult<()> {
        let mut outputs = self.outputs.lock().unwrap();
        if let Some(id) = output.id {
            outputs.insert(id, output.clone());
            Ok(())
        } else {
            Err(LightweightWalletError::StorageError(
                "Output ID is required for update".to_string(),
            ))
        }
    }

    async fn mark_output_spent(
        &self,
        output_id: u32,
        spent_in_tx_id: u64,
    ) -> LightweightWalletResult<()> {
        let mut outputs = self.outputs.lock().unwrap();
        if let Some(output) = outputs.get_mut(&output_id) {
            output.status = OutputStatus::Spent as u32;
            output.spent_in_tx_id = Some(spent_in_tx_id);
            Ok(())
        } else {
            Err(LightweightWalletError::StorageError(
                "Output not found".to_string(),
            ))
        }
    }

    async fn get_output_by_id(
        &self,
        output_id: u32,
    ) -> LightweightWalletResult<Option<StoredOutput>> {
        self.check_failure("get")?;
        let outputs = self.outputs.lock().unwrap();
        Ok(outputs.get(&output_id).cloned())
    }

    async fn get_output_by_commitment(
        &self,
        commitment: &[u8],
    ) -> LightweightWalletResult<Option<StoredOutput>> {
        self.check_failure("get")?;
        let outputs = self.outputs.lock().unwrap();
        Ok(outputs
            .values()
            .find(|output| output.commitment == commitment)
            .cloned())
    }

    async fn get_outputs(
        &self,
        filter: Option<OutputFilter>,
    ) -> LightweightWalletResult<Vec<StoredOutput>> {
        self.check_failure("get")?;
        let outputs = self.outputs.lock().unwrap();
        let mut results: Vec<StoredOutput> = outputs.values().cloned().collect();

        if let Some(filter) = filter {
            if let Some(wallet_id) = filter.wallet_id {
                results.retain(|output| output.wallet_id == wallet_id);
            }
            if let Some(status) = filter.status {
                results.retain(|output| output.status == status as u32);
            }
            if let Some(min_value) = filter.min_value {
                results.retain(|output| output.value >= min_value);
            }
            if let Some(max_value) = filter.max_value {
                results.retain(|output| output.value <= max_value);
            }
            if let Some(spendable_height) = filter.spendable_at_height {
                results.retain(|output| output.can_spend_at_height(spendable_height));
            }
            if let Some(limit) = filter.limit {
                results.truncate(limit);
            }
        }

        Ok(results)
    }

    async fn get_unspent_outputs(
        &self,
        wallet_id: u32,
    ) -> LightweightWalletResult<Vec<StoredOutput>> {
        let filter = OutputFilter::new()
            .with_wallet_id(wallet_id)
            .with_status(OutputStatus::Unspent);
        self.get_outputs(Some(filter)).await
    }

    async fn get_spendable_outputs(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> LightweightWalletResult<Vec<StoredOutput>> {
        let filter = OutputFilter::new()
            .with_wallet_id(wallet_id)
            .spendable_at(block_height);
        self.get_outputs(Some(filter)).await
    }

    async fn get_spendable_balance(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> LightweightWalletResult<u64> {
        let spendable_outputs = self.get_spendable_outputs(wallet_id, block_height).await?;
        Ok(spendable_outputs.iter().map(|output| output.value).sum())
    }

    async fn delete_output(&self, output_id: u32) -> LightweightWalletResult<bool> {
        let mut outputs = self.outputs.lock().unwrap();
        Ok(outputs.remove(&output_id).is_some())
    }

    async fn clear_outputs(&self, wallet_id: u32) -> LightweightWalletResult<()> {
        let mut outputs = self.outputs.lock().unwrap();
        outputs.retain(|_, output| output.wallet_id != wallet_id);
        Ok(())
    }

    async fn get_output_count(&self, wallet_id: u32) -> LightweightWalletResult<usize> {
        self.check_failure("get")?;
        let outputs = self.outputs.lock().unwrap();
        Ok(outputs
            .values()
            .filter(|output| output.wallet_id == wallet_id)
            .count())
    }
}

/// Mock blockchain scanner for deterministic testing
#[derive(Debug, Clone)]
pub struct MockBlockchainScanner {
    /// Predefined blocks to return for scanning
    blocks: Arc<Mutex<HashMap<u64, BlockInfo>>>,
    /// Mock tip information
    tip_info: Arc<Mutex<TipInfo>>,
    /// Predefined transaction outputs for UTXO searches
    utxos: Arc<Mutex<HashMap<Vec<u8>, LightweightTransactionOutput>>>,
    /// Network delay simulation (ms)
    network_delay: Duration,
    /// Failure modes for testing error conditions
    failure_modes: Arc<Mutex<MockNetworkFailureModes>>,
}

#[derive(Debug, Clone, Default)]
pub struct MockNetworkFailureModes {
    /// Fail next scan_blocks call
    pub fail_scan_blocks: bool,
    /// Fail next get_tip_info call
    pub fail_get_tip_info: bool,
    /// Fail next search_utxos call
    pub fail_search_utxos: bool,
    /// Fail next fetch_utxos call
    pub fail_fetch_utxos: bool,
    /// Return specific error message for next operation
    pub next_error_message: Option<String>,
    /// Simulate network timeout
    pub simulate_timeout: bool,
    /// Return empty results for next scan
    pub return_empty_results: bool,
}

impl Default for MockBlockchainScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBlockchainScanner {
    /// Create a new mock blockchain scanner
    pub fn new() -> Self {
        Self {
            blocks: Arc::new(Mutex::new(HashMap::new())),
            tip_info: Arc::new(Mutex::new(TipInfo {
                best_block_height: 1000,
                best_block_hash: vec![1, 2, 3, 4],
                accumulated_difficulty: vec![5, 6, 7, 8],
                pruned_height: 500,
                timestamp: 1234567890,
            })),
            utxos: Arc::new(Mutex::new(HashMap::new())),
            network_delay: Duration::from_millis(0),
            failure_modes: Arc::new(Mutex::new(MockNetworkFailureModes::default())),
        }
    }

    /// Add a mock block for testing
    pub fn add_block(&self, block: BlockInfo) {
        let mut blocks = self.blocks.lock().unwrap();
        blocks.insert(block.height, block);
    }

    /// Add multiple mock blocks
    pub fn add_blocks(&self, blocks: Vec<BlockInfo>) {
        for block in blocks {
            self.add_block(block);
        }
    }

    /// Set the mock tip information
    pub fn set_tip_info(&self, tip_info: TipInfo) {
        *self.tip_info.lock().unwrap() = tip_info;
    }

    /// Add a mock UTXO for search operations
    pub fn add_utxo(&self, hash: Vec<u8>, output: LightweightTransactionOutput) {
        let mut utxos = self.utxos.lock().unwrap();
        utxos.insert(hash, output);
    }

    /// Set network delay simulation
    pub fn set_network_delay(&mut self, delay: Duration) {
        self.network_delay = delay;
    }

    /// Set failure modes for testing error conditions
    pub fn set_failure_modes(&self, modes: MockNetworkFailureModes) {
        *self.failure_modes.lock().unwrap() = modes;
    }

    /// Reset the scanner to default state
    pub fn reset(&self) {
        self.blocks.lock().unwrap().clear();
        self.utxos.lock().unwrap().clear();
        *self.failure_modes.lock().unwrap() = MockNetworkFailureModes::default();
    }

    /// Check if an operation should fail and return appropriate error
    async fn check_failure(&self, operation: &str) -> LightweightWalletResult<()> {
        let mut modes = self.failure_modes.lock().unwrap();

        // Simulate network delay
        if !self.network_delay.is_zero() {
            drop(modes); // Release lock during delay
            tokio::time::sleep(self.network_delay).await;
            modes = self.failure_modes.lock().unwrap();
        }

        // Check for timeout simulation
        if modes.simulate_timeout {
            modes.simulate_timeout = false; // Reset after use
            return Err(LightweightWalletError::NetworkError(
                "Mock timeout: operation timed out".to_string(),
            ));
        }

        // Check for specific error to return
        if let Some(error_msg) = modes.next_error_message.take() {
            return Err(LightweightWalletError::NetworkError(error_msg));
        }

        // Check operation-specific failures
        match operation {
            "scan_blocks" if modes.fail_scan_blocks => {
                modes.fail_scan_blocks = false; // Reset after use
                Err(LightweightWalletError::NetworkError(
                    "Mock failure: scan_blocks".to_string(),
                ))
            }
            "get_tip_info" if modes.fail_get_tip_info => {
                modes.fail_get_tip_info = false; // Reset after use
                Err(LightweightWalletError::NetworkError(
                    "Mock failure: get_tip_info".to_string(),
                ))
            }
            "search_utxos" if modes.fail_search_utxos => {
                modes.fail_search_utxos = false; // Reset after use
                Err(LightweightWalletError::NetworkError(
                    "Mock failure: search_utxos".to_string(),
                ))
            }
            "fetch_utxos" if modes.fail_fetch_utxos => {
                modes.fail_fetch_utxos = false; // Reset after use
                Err(LightweightWalletError::NetworkError(
                    "Mock failure: fetch_utxos".to_string(),
                ))
            }
            _ => Ok(()),
        }
    }
}

#[async_trait(?Send)]
impl BlockchainScanner for MockBlockchainScanner {
    async fn scan_blocks(
        &mut self,
        config: ScanConfig,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
        self.check_failure("scan_blocks").await?;

        let modes = self.failure_modes.lock().unwrap();
        if modes.return_empty_results {
            return Ok(Vec::new());
        }
        drop(modes);

        let blocks = self.blocks.lock().unwrap();
        let mut results = Vec::new();

        let start_height = config.start_height;
        let end_height = config
            .end_height
            .unwrap_or(start_height + config.batch_size);

        for height in start_height..=end_height {
            if let Some(block) = blocks.get(&height) {
                // Process the block using default scanning logic
                let block_result = BlockScanResult {
                    height: block.height,
                    block_hash: block.hash.clone(),
                    outputs: block.outputs.clone(),
                    wallet_outputs: Vec::new(), // Would be populated by scanning logic
                    mined_timestamp: block.timestamp,
                };
                results.push(block_result);
            }
        }

        Ok(results)
    }

    async fn get_tip_info(&mut self) -> LightweightWalletResult<TipInfo> {
        self.check_failure("get_tip_info").await?;
        Ok(self.tip_info.lock().unwrap().clone())
    }

    async fn search_utxos(
        &mut self,
        commitments: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<Vec<BlockScanResult>> {
        self.check_failure("search_utxos").await?;

        let utxos = self.utxos.lock().unwrap();
        let mut found_outputs = Vec::new();

        for commitment in commitments {
            if let Some(output) = utxos.get(&commitment) {
                found_outputs.push(output.clone());
            }
        }

        // Return as a single block result for simplicity
        if !found_outputs.is_empty() {
            Ok(vec![BlockScanResult {
                height: 1,
                block_hash: vec![0, 1, 2, 3],
                outputs: found_outputs,
                wallet_outputs: Vec::new(),
                mined_timestamp: 1234567890,
            }])
        } else {
            Ok(Vec::new())
        }
    }

    async fn fetch_utxos(
        &mut self,
        hashes: Vec<Vec<u8>>,
    ) -> LightweightWalletResult<Vec<LightweightTransactionOutput>> {
        self.check_failure("fetch_utxos").await?;

        let utxos = self.utxos.lock().unwrap();
        let mut results = Vec::new();

        for hash in hashes {
            if let Some(output) = utxos.get(&hash) {
                results.push(output.clone());
            }
        }

        Ok(results)
    }

    async fn get_blocks_by_heights(
        &mut self,
        heights: Vec<u64>,
    ) -> LightweightWalletResult<Vec<BlockInfo>> {
        self.check_failure("get_blocks").await?;

        let modes = self.failure_modes.lock().unwrap();
        if modes.return_empty_results {
            return Ok(Vec::new());
        }
        drop(modes);

        let blocks = self.blocks.lock().unwrap();
        let mut results = Vec::new();

        for height in heights {
            if let Some(block) = blocks.get(&height) {
                results.push(block.clone());
            }
        }

        Ok(results)
    }

    async fn get_block_by_height(
        &mut self,
        height: u64,
    ) -> LightweightWalletResult<Option<BlockInfo>> {
        self.check_failure("get_blocks").await?;

        let blocks = self.blocks.lock().unwrap();
        Ok(blocks.get(&height).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_wallet_storage_basic_operations() {
        let storage = MockWalletStorage::new();

        // Test initialize
        assert!(storage.initialize().await.is_ok());

        // Test wallet operations
        let wallet = StoredWallet::view_only(
            "test_wallet".to_string(),
            crate::data_structures::types::PrivateKey::new([1u8; 32]),
            0,
        );

        let wallet_id = storage.save_wallet(&wallet).await.unwrap();
        assert_eq!(wallet_id, 1);

        let retrieved = storage.get_wallet_by_id(wallet_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "test_wallet");
    }

    #[tokio::test]
    async fn test_mock_wallet_storage_failure_modes() {
        let storage = MockWalletStorage::new();

        // Test save_wallet failure
        storage.set_failure_mode(MockFailureModes {
            fail_save_wallet: true,
            ..Default::default()
        });

        let wallet = StoredWallet::view_only(
            "test_wallet".to_string(),
            crate::data_structures::types::PrivateKey::new([1u8; 32]),
            0,
        );

        let result = storage.save_wallet(&wallet).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Mock failure: save_wallet"));
    }

    #[tokio::test]
    async fn test_mock_blockchain_scanner_basic_operations() {
        let mut scanner = MockBlockchainScanner::new();

        // Test get_tip_info
        let tip = scanner.get_tip_info().await.unwrap();
        assert_eq!(tip.best_block_height, 1000);

        // Test empty scan
        let config = ScanConfig::default();
        let results = scanner.scan_blocks(config).await.unwrap();
        assert!(results.is_empty()); // No blocks added yet
    }

    #[tokio::test]
    async fn test_mock_blockchain_scanner_failure_modes() {
        let mut scanner = MockBlockchainScanner::new();

        // Test scan_blocks failure
        scanner.set_failure_modes(MockNetworkFailureModes {
            fail_scan_blocks: true,
            ..Default::default()
        });

        let config = ScanConfig::default();
        let result = scanner.scan_blocks(config).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Mock failure: scan_blocks"));
    }
}
