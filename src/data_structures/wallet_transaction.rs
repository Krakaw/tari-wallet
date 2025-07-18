//! Wallet transaction structures for lightweight wallets
//! 
//! This module contains structures for tracking wallet transactions and state
//! across blocks, including transaction metadata and spending status.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use borsh::{BorshDeserialize, BorshSerialize};

use crate::data_structures::{
    types::CompressedCommitment,
    payment_id::PaymentId,
    transaction::{TransactionStatus, TransactionDirection},
};
use crate::utils::number::format_number;

/// A wallet transaction representing either a received output or spent input
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct WalletTransaction {
    /// Block height where this transaction was found
    pub block_height: u64,
    /// Output index if this is a received output
    pub output_index: Option<usize>,
    /// Input index if this represents a spent transaction
    pub input_index: Option<usize>,
    /// Commitment of the output/input
    pub commitment: CompressedCommitment,
    /// Output hash from HTTP response (for identification and matching)
    pub output_hash: Option<Vec<u8>>,
    /// Value in microMinotari
    pub value: u64,
    /// Associated payment ID
    pub payment_id: PaymentId,
    /// Whether this output has been spent
    pub is_spent: bool,
    /// Block height where this output was spent (if spent)
    pub spent_in_block: Option<u64>,
    /// Input index where this output was spent (if spent)
    pub spent_in_input: Option<usize>,
    /// Transaction status
    pub transaction_status: TransactionStatus,
    /// Transaction direction (inbound/outbound)
    pub transaction_direction: TransactionDirection,
    /// Whether this transaction is mature (can be spent)
    pub is_mature: bool,
}

impl WalletTransaction {
    /// Create a new wallet transaction
    pub fn new(
        block_height: u64,
        output_index: Option<usize>,
        input_index: Option<usize>,
        commitment: CompressedCommitment,
        output_hash: Option<Vec<u8>>,
        value: u64,
        payment_id: PaymentId,
        transaction_status: TransactionStatus,
        transaction_direction: TransactionDirection,
        is_mature: bool,
    ) -> Self {
        Self {
            block_height,
            output_index,
            input_index,
            commitment,
            output_hash,
            value,
            payment_id,
            is_spent: false,
            spent_in_block: None,
            spent_in_input: None,
            transaction_status,
            transaction_direction,
            is_mature,
        }
    }

    /// Mark this transaction as spent
    pub fn mark_spent(&mut self, block_height: u64, input_index: usize) {
        self.is_spent = true;
        self.spent_in_block = Some(block_height);
        self.spent_in_input = Some(input_index);
    }

    /// Check if this is a coinbase transaction
    pub fn is_coinbase(&self) -> bool {
        self.transaction_status.is_coinbase()
    }

    /// Check if this transaction is confirmed
    pub fn is_confirmed(&self) -> bool {
        self.transaction_status.is_confirmed()
    }

    /// Get the commitment as hex string
    pub fn commitment_hex(&self) -> String {
        hex::encode(self.commitment.as_bytes())
    }

    /// Get the output hash as hex string (if available)
    pub fn output_hash_hex(&self) -> Option<String> {
        self.output_hash.as_ref().map(|hash| hex::encode(hash))
    }
}

/// Wallet state tracking all transactions and balances
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(from = "WalletStateSerde")]
pub struct WalletState {
    /// All wallet transactions
    pub transactions: Vec<WalletTransaction>,
    /// Map from commitment bytes to transaction index for fast lookup
    #[serde(skip)]
    #[borsh(skip)]
    outputs_by_commitment: HashMap<Vec<u8>, usize>,
    /// Map from output hash bytes to transaction index for fast lookup
    #[serde(skip)]
    #[borsh(skip)]
    outputs_by_hash: HashMap<Vec<u8>, usize>,
    /// Running balance in microMinotari (can be negative)
    running_balance: i64,
    /// Total received in microMinotari
    total_received: u64,
    /// Total spent in microMinotari
    total_spent: u64,
    /// Number of unspent outputs
    unspent_count: usize,
    /// Number of spent outputs
    spent_count: usize,
}

impl Default for WalletState {
    fn default() -> Self {
        Self::new()
    }
}

impl WalletState {
    /// Create a new empty wallet state
    pub fn new() -> Self {
        Self {
            transactions: Vec::new(),
            outputs_by_commitment: HashMap::new(),
            outputs_by_hash: HashMap::new(),
            running_balance: 0,
            total_received: 0,
            total_spent: 0,
            unspent_count: 0,
            spent_count: 0,
        }
    }

    /// Rebuild the commitment index from transactions
    pub fn rebuild_commitment_index(&mut self) {
        self.outputs_by_commitment.clear();
        self.outputs_by_hash.clear();
        for (index, transaction) in self.transactions.iter().enumerate() {
            // Index by commitment
            self.outputs_by_commitment.insert(transaction.commitment.as_bytes().to_vec(), index);
            
            // Index by output hash if available
            if let Some(ref output_hash) = transaction.output_hash {
                self.outputs_by_hash.insert(output_hash.clone(), index);
            }
        }
    }

    /// Add a received output to the wallet state
    pub fn add_received_output(
        &mut self,
        block_height: u64,
        output_index: usize,
        commitment: CompressedCommitment,
        output_hash: Option<Vec<u8>>,
        value: u64,
        payment_id: PaymentId,
        transaction_status: TransactionStatus,
        transaction_direction: TransactionDirection,
        is_mature: bool,
    ) {
        let transaction = WalletTransaction::new(
            block_height,
            Some(output_index),
            None,
            commitment.clone(),
            output_hash.clone(),
            value,
            payment_id,
            transaction_status,
            transaction_direction,
            is_mature,
        );

        let tx_index = self.transactions.len();
        
        // Index by commitment
        self.outputs_by_commitment.insert(commitment.as_bytes().to_vec(), tx_index);
        
        // Index by output hash if available - CRITICAL for spent detection
        if let Some(hash) = output_hash {
            self.outputs_by_hash.insert(hash.clone(), tx_index);
            
            // Debug logging for output hash indexing
            #[cfg(all(target_arch = "wasm32"))]
            {
                let hash_hex = hex::encode(&hash);
                web_sys::console::log_1(&format!("📝 INDEXED OUTPUT: Hash {} -> Value {} μT (total tracked: {})", 
                    hash_hex, value, self.outputs_by_hash.len()).into());
            }
        }
        
        self.transactions.push(transaction);
        
        self.total_received += value;
        self.running_balance += value as i64;
        self.unspent_count += 1;
    }

    /// Mark an output as spent and create an outbound transaction record
    pub fn mark_output_spent(
        &mut self,
        commitment: &CompressedCommitment,
        block_height: u64,
        input_index: usize,
    ) -> bool {
        let commitment_bytes = commitment.as_bytes().to_vec();
        if let Some(&tx_index) = self.outputs_by_commitment.get(&commitment_bytes) {
            if let Some(transaction) = self.transactions.get_mut(tx_index) {
                if !transaction.is_spent {
                    transaction.mark_spent(block_height, input_index);
                    
                    // Use the value from our stored transaction, not the input
                    let spent_value = transaction.value;
                    
                    // Update balance and counters for the spent inbound transaction
                    self.total_spent += spent_value;
                    self.running_balance -= spent_value as i64;
                    self.unspent_count -= 1;
                    self.spent_count += 1;
                    
                    // Create an outbound transaction record for the spending
                    // (this is just for tracking/display, doesn't affect balance)
                    let outbound_transaction = WalletTransaction::new(
                        block_height,
                        None, // No output index for spending
                        Some(input_index),
                        commitment.clone(),
                        None, // No output_hash for spending
                        spent_value,
                        transaction.payment_id.clone(),
                        TransactionStatus::MinedConfirmed, // Spending is confirmed when mined
                        TransactionDirection::Outbound,
                        true, // Always mature since we're spending
                    );
                    
                    self.transactions.push(outbound_transaction);
                    
                    return true;
                }
            }
        }
        false
    }

    /// Mark an output as spent by output hash and create an outbound transaction record
    /// This is used when we have the output hash from HTTP inputs array
    pub fn mark_output_spent_by_hash(
        &mut self,
        output_hash: &[u8],
        block_height: u64,
        input_index: usize,
    ) -> bool {
        if let Some(&tx_index) = self.outputs_by_hash.get(output_hash) {
            if let Some(transaction) = self.transactions.get_mut(tx_index) {
                if !transaction.is_spent {
                    transaction.mark_spent(block_height, input_index);
                    
                    // Use the value from our stored transaction, not the input
                    let spent_value = transaction.value;
                    
                    // Update balance and counters for the spent inbound transaction
                    self.total_spent += spent_value;
                    self.running_balance -= spent_value as i64;
                    self.unspent_count -= 1;
                    self.spent_count += 1;
                    
                    // Create an outbound transaction record for the spending
                    // (this is just for tracking/display, doesn't affect balance)
                    let outbound_transaction = WalletTransaction::new(
                        block_height,
                        None, // No output index for spending
                        Some(input_index),
                        transaction.commitment.clone(),
                        Some(output_hash.to_vec()), // Include the output hash that was spent
                        spent_value,
                        transaction.payment_id.clone(),
                        TransactionStatus::MinedConfirmed, // Spending is confirmed when mined
                        TransactionDirection::Outbound,
                        true, // Always mature since we're spending
                    );
                    
                    self.transactions.push(outbound_transaction);
                    
                    return true;
                }
            }
        } else {
            // Debug logging for failed hash lookup
            #[cfg(all(target_arch = "wasm32"))]
            {
                let hash_hex = hex::encode(output_hash);
                web_sys::console::log_1(&format!("🔍 OUTPUT HASH LOOKUP FAILED: {} (not found in {} tracked hashes)", 
                    hash_hex, self.outputs_by_hash.len()).into());
            }
        }
        false
    }

    /// Get summary statistics (total_received, total_spent, balance, unspent_count, spent_count)
    pub fn get_summary(&self) -> (u64, u64, i64, usize, usize) {
        (self.total_received, self.total_spent, self.running_balance, self.unspent_count, self.spent_count)
    }

    /// Get total value of unspent outputs (only considers inbound transactions)
    pub fn get_unspent_value(&self) -> u64 {
        self.transactions.iter()
            .filter(|tx| tx.transaction_direction == TransactionDirection::Inbound && !tx.is_spent)
            .map(|tx| tx.value)
            .sum()
    }

    /// Get current balance in microMinotari
    pub fn get_balance(&self) -> i64 {
        self.running_balance
    }

    /// Get total number of transactions
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Get unspent transactions (only inbound transactions)
    pub fn get_unspent_transactions(&self) -> Vec<&WalletTransaction> {
        self.transactions.iter().filter(|tx| tx.transaction_direction == TransactionDirection::Inbound && !tx.is_spent).collect()
    }

    /// Get spent transactions (only inbound transactions that have been spent)
    pub fn get_spent_transactions(&self) -> Vec<&WalletTransaction> {
        self.transactions.iter().filter(|tx| tx.transaction_direction == TransactionDirection::Inbound && tx.is_spent).collect()
    }

    /// Get inbound transactions
    pub fn get_inbound_transactions(&self) -> Vec<&WalletTransaction> {
        self.transactions.iter().filter(|tx| tx.transaction_direction == TransactionDirection::Inbound).collect()
    }

    /// Get outbound transactions
    pub fn get_outbound_transactions(&self) -> Vec<&WalletTransaction> {
        self.transactions.iter().filter(|tx| tx.transaction_direction == TransactionDirection::Outbound).collect()
    }

    /// Get transaction counts by direction (inbound, outbound, unknown)
    pub fn get_direction_counts(&self) -> (usize, usize, usize) {
        let mut inbound = 0;
        let mut outbound = 0;
        let mut unknown = 0;
        
        for tx in &self.transactions {
            match tx.transaction_direction {
                TransactionDirection::Inbound => inbound += 1,
                TransactionDirection::Outbound => outbound += 1,
                TransactionDirection::Unknown => unknown += 1,
            }
        }
        
        (inbound, outbound, unknown)
    }

    /// Get the number of tracked output hashes (for debugging)
    pub fn get_tracked_hash_count(&self) -> usize {
        self.outputs_by_hash.len()
    }

    /// Get all tracked output hashes (for debugging) - returns (hash, transaction_index, value, is_spent)
    pub fn get_tracked_hashes(&self) -> Vec<(Vec<u8>, usize, u64, bool)> {
        self.outputs_by_hash.iter().map(|(hash, &tx_index)| {
            if let Some(tx) = self.transactions.get(tx_index) {
                (hash.clone(), tx_index, tx.value, tx.is_spent)
            } else {
                (hash.clone(), tx_index, 0, false)
            }
        }).collect()
    }

    /// Create an enhanced progress bar with balance information
    pub fn format_progress_bar(&self, current: u64, total: u64, block_height: u64, phase: &str) -> String {
        let progress_percent = (current as f64 / total as f64) * 100.0;
        let bar_width = 40; // Shorter bar to make room for balance info
        let filled_width = ((progress_percent / 100.0) * bar_width as f64) as usize;
        let bar = format!("{}{}",
            "█".repeat(filled_width),
            "░".repeat(bar_width - filled_width)
        );
        
        let unspent_value = self.get_unspent_value();
        let balance_t = self.running_balance as f64 / 1_000_000.0;
        let unspent_t = unspent_value as f64 / 1_000_000.0;
        let spent_t = self.total_spent as f64 / 1_000_000.0;
        
        format!(
            "[{}] {:.1}% {} Block {} | 💰 {:.6}T | 📈 {:.6}T | 📉 {:.6}T | {} TX",
            bar, 
            progress_percent, 
            phase,
            format_number(block_height),
            balance_t,
            unspent_t, 
            spent_t,
            format_number(self.transactions.len())
        )
    }
}

/// Helper struct for serde deserialization
#[derive(Deserialize)]
struct WalletStateSerde {
    transactions: Vec<WalletTransaction>,
    running_balance: i64,
    total_received: u64,
    total_spent: u64,
    unspent_count: usize,
    spent_count: usize,
}

impl From<WalletStateSerde> for WalletState {
    fn from(serde_state: WalletStateSerde) -> Self {
        let mut state = WalletState {
            transactions: serde_state.transactions,
            outputs_by_commitment: HashMap::new(),
            outputs_by_hash: HashMap::new(),
            running_balance: serde_state.running_balance,
            total_received: serde_state.total_received,
            total_spent: serde_state.total_spent,
            unspent_count: serde_state.unspent_count,
            spent_count: serde_state.spent_count,
        };
        state.rebuild_commitment_index();
        state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_structures::{
        types::CompressedCommitment,
        payment_id::PaymentId,
        transaction::{TransactionStatus, TransactionDirection},
    };

    #[test]
    fn test_wallet_transaction_creation() {
        let commitment = CompressedCommitment::new([1u8; 32]);
        let tx = WalletTransaction::new(
            100,
            Some(0),
            None,
            commitment.clone(),
            None,
            1000000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );

        assert_eq!(tx.block_height, 100);
        assert_eq!(tx.output_index, Some(0));
        assert_eq!(tx.value, 1000000);
        assert!(!tx.is_spent);
        assert!(tx.is_mature);
        assert_eq!(tx.commitment, commitment);
    }

    #[test]
    fn test_wallet_transaction_mark_spent() {
        let commitment = CompressedCommitment::new([1u8; 32]);
        let mut tx = WalletTransaction::new(
            100,
            Some(0),
            None,
            commitment,
            None,
            1000000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );

        assert!(!tx.is_spent);
        tx.mark_spent(200, 5);
        assert!(tx.is_spent);
        assert_eq!(tx.spent_in_block, Some(200));
        assert_eq!(tx.spent_in_input, Some(5));
    }

    #[test]
    fn test_wallet_state_creation() {
        let state = WalletState::new();
        assert_eq!(state.transactions.len(), 0);
        assert_eq!(state.get_balance(), 0);
        assert_eq!(state.get_unspent_value(), 0);
        let (received, spent, balance, unspent_count, spent_count) = state.get_summary();
        assert_eq!(received, 0);
        assert_eq!(spent, 0);
        assert_eq!(balance, 0);
        assert_eq!(unspent_count, 0);
        assert_eq!(spent_count, 0);
    }

    #[test]
    fn test_wallet_state_add_received_output() {
        let mut state = WalletState::new();
        let commitment = CompressedCommitment::new([1u8; 32]);
        
        state.add_received_output(
            100,
            0,
            commitment,
            None, // No output_hash in test
            1000000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );

        assert_eq!(state.transactions.len(), 1);
        assert_eq!(state.get_balance(), 1000000);
        assert_eq!(state.get_unspent_value(), 1000000);
        let (received, spent, balance, unspent_count, spent_count) = state.get_summary();
        assert_eq!(received, 1000000);
        assert_eq!(spent, 0);
        assert_eq!(balance, 1000000);
        assert_eq!(unspent_count, 1);
        assert_eq!(spent_count, 0);
    }

    #[test]
    fn test_wallet_state_mark_output_spent() {
        let mut state = WalletState::new();
        let commitment = CompressedCommitment::new([1u8; 32]);
        
        // Add an output
        state.add_received_output(
            100,
            0,
            commitment.clone(),
            None, // No output_hash in test
            1000000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );

        assert_eq!(state.transactions.len(), 1);
        assert_eq!(state.get_inbound_transactions().len(), 1);
        assert_eq!(state.get_outbound_transactions().len(), 0);

        // Mark it as spent
        let marked = state.mark_output_spent(&commitment, 200, 5);
        assert!(marked);

        assert_eq!(state.get_balance(), 0);
        assert_eq!(state.get_unspent_value(), 0);
        let (received, spent, balance, unspent_count, spent_count) = state.get_summary();
        assert_eq!(received, 1000000);
        assert_eq!(spent, 1000000);
        assert_eq!(balance, 0);
        assert_eq!(unspent_count, 0);
        assert_eq!(spent_count, 1);

        // Should now have 2 transactions: inbound and outbound
        assert_eq!(state.transactions.len(), 2);
        assert_eq!(state.get_inbound_transactions().len(), 1);
        assert_eq!(state.get_outbound_transactions().len(), 1);

        // Original transaction should be marked as spent
        assert!(state.transactions[0].is_spent);
        assert_eq!(state.transactions[0].spent_in_block, Some(200));
        assert_eq!(state.transactions[0].spent_in_input, Some(5));
        assert_eq!(state.transactions[0].transaction_direction, TransactionDirection::Inbound);

        // New outbound transaction should exist
        let outbound_tx = &state.transactions[1];
        assert_eq!(outbound_tx.transaction_direction, TransactionDirection::Outbound);
        assert_eq!(outbound_tx.block_height, 200);
        assert_eq!(outbound_tx.input_index, Some(5));
        assert_eq!(outbound_tx.output_index, None);
        assert_eq!(outbound_tx.value, 1000000);
        assert_eq!(outbound_tx.commitment, commitment);
    }

    #[test]
    fn test_wallet_state_mark_nonexistent_output_spent() {
        let mut state = WalletState::new();
        let commitment = CompressedCommitment::new([1u8; 32]);
        
        // Try to mark a non-existent output as spent
        let marked = state.mark_output_spent(&commitment, 200, 5);
        assert!(!marked);
        
        assert_eq!(state.get_balance(), 0);
        assert_eq!(state.transactions.len(), 0);
    }

    #[test]
    fn test_wallet_state_get_filtered_transactions() {
        let mut state = WalletState::new();
        let commitment1 = CompressedCommitment::new([1u8; 32]);
        let commitment2 = CompressedCommitment::new([2u8; 32]);
        
        // Add two outputs
        state.add_received_output(
            100, 0, commitment1.clone(), None, 1000000, PaymentId::Empty,
            TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
        );
        state.add_received_output(
            200, 1, commitment2, None, 2000000, PaymentId::Empty,
            TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
        );

        // Spend one
        state.mark_output_spent(&commitment1, 300, 0);

        let unspent = state.get_unspent_transactions();
        let spent = state.get_spent_transactions();

        assert_eq!(unspent.len(), 1);
        assert_eq!(spent.len(), 1);
        assert_eq!(unspent[0].value, 2000000);
        assert_eq!(spent[0].value, 1000000);
    }

    #[test]
    fn test_wallet_transaction_coinbase_detection() {
        let commitment = CompressedCommitment::new([1u8; 32]);
        let coinbase_tx = WalletTransaction::new(
            100, Some(0), None, commitment.clone(), None, 1000000, PaymentId::Empty,
            TransactionStatus::CoinbaseConfirmed, TransactionDirection::Inbound, true,
        );
        
        let regular_tx = WalletTransaction::new(
            100, Some(0), None, commitment, None, 1000000, PaymentId::Empty,
            TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
        );

        assert!(coinbase_tx.is_coinbase());
        assert!(!regular_tx.is_coinbase());
    }

    #[test]
    fn test_transaction_direction_counts() {
        let mut state = WalletState::new();
        let commitment1 = CompressedCommitment::new([1u8; 32]);
        let commitment2 = CompressedCommitment::new([2u8; 32]);
        
        // Add inbound transactions
        state.add_received_output(
            100, 0, commitment1.clone(), None, 1000000, PaymentId::Empty,
            TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
        );
        state.add_received_output(
            200, 1, commitment2.clone(), None, 2000000, PaymentId::Empty,
            TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
        );

        // Initial state: 2 inbound, 0 outbound
        let (inbound, outbound, unknown) = state.get_direction_counts();
        assert_eq!(inbound, 2);
        assert_eq!(outbound, 0);
        assert_eq!(unknown, 0);

        // Spend one output - should create outbound transaction
        state.mark_output_spent(&commitment1, 300, 0);

        // Final state: 2 inbound, 1 outbound
        let (inbound, outbound, unknown) = state.get_direction_counts();
        assert_eq!(inbound, 2);
        assert_eq!(outbound, 1);
        assert_eq!(unknown, 0);

        // Verify transaction lists
        assert_eq!(state.get_inbound_transactions().len(), 2);
        assert_eq!(state.get_outbound_transactions().len(), 1);
        assert_eq!(state.transactions.len(), 3);
    }

    #[test]
    fn test_serialization() {
        use serde_json;

        let mut state = WalletState::new();
        let commitment = CompressedCommitment::new([1u8; 32]);
        
        state.add_received_output(
            100, 0, commitment, None, 1000000, PaymentId::Empty,
            TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
        );

        // Test JSON serialization
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: WalletState = serde_json::from_str(&json).unwrap();
        assert_eq!(state.transactions.len(), deserialized.transactions.len());
        assert_eq!(state.get_balance(), deserialized.get_balance());

        // Test borsh serialization
        let bytes = borsh::to_vec(&state).unwrap();
        let deserialized: WalletState = borsh::from_slice(&bytes).unwrap();
        assert_eq!(state.transactions.len(), deserialized.transactions.len());
        assert_eq!(state.get_balance(), deserialized.get_balance());
    }
} 