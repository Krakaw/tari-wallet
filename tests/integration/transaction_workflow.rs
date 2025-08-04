//! Transaction creation, signing, and broadcasting workflow integration tests
//!
//! Tests the complete transaction lifecycle from creation to signing to broadcasting,
//! including validation, fee calculation, and error handling.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use lightweight_wallet_libs::crypto::signing::{
    derive_tari_signing_key, sign_message_with_hex_output, verify_message_from_hex,
};
use lightweight_wallet_libs::data_structures::{
    address::{TariAddress, TariAddressFeatures},
    types::{CompressedPublicKey, MicroMinotari, PrivateKey},
};
use lightweight_wallet_libs::errors::{WalletError, ValidationError};

use lightweight_wallet_libs::wallet::*;

use tari_crypto::keys::PublicKey;
use tari_crypto::ristretto::RistrettoPublicKey;

/// Mock transaction structure for testing
#[derive(Debug, Clone)]
struct MockTransaction {
    inputs: Vec<MockTransactionInput>,
    outputs: Vec<MockTransactionOutput>,
    fee: MicroMinotari,
    lock_height: u64,
    signature: Option<MockTransactionSignature>,
}

#[derive(Debug, Clone)]
struct MockTransactionInput {
    output_hash: Vec<u8>,
    #[allow(dead_code)]
    commitment: Vec<u8>,
    value: MicroMinotari,
    #[allow(dead_code)]
    script: Vec<u8>,
}

#[derive(Debug, Clone)]
struct MockTransactionOutput {
    commitment: Vec<u8>,
    value: MicroMinotari,
    #[allow(dead_code)]
    script: Vec<u8>,
    #[allow(dead_code)]
    recipient_address: Option<TariAddress>,
    #[allow(dead_code)]
    sender_offset_public_key: CompressedPublicKey,
}

#[derive(Debug, Clone)]
struct MockTransactionSignature {
    signature_hex: String,
    nonce_hex: String,
    public_key: RistrettoPublicKey,
}

/// Transaction builder for testing workflows
#[derive(Debug)]
struct MockTransactionBuilder {
    inputs: Vec<MockTransactionInput>,
    outputs: Vec<MockTransactionOutput>,
    fee: MicroMinotari,
    lock_height: u64,
    wallet: Option<Wallet>,
}

impl MockTransactionBuilder {
    fn new() -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: MicroMinotari::from(100), // Default fee
            lock_height: 0,
            wallet: None,
        }
    }

    fn with_wallet(mut self, wallet: Wallet) -> Self {
        self.wallet = Some(wallet);
        self
    }

    fn add_input(mut self, output_hash: Vec<u8>, commitment: Vec<u8>, value: u64) -> Self {
        let input = MockTransactionInput {
            output_hash,
            commitment,
            value: MicroMinotari::from(value),
            script: vec![],
        };
        self.inputs.push(input);
        self
    }

    fn add_output(mut self, recipient: TariAddress, value: u64) -> Self {
        let output = MockTransactionOutput {
            commitment: vec![0x42; 32], // Mock commitment
            value: MicroMinotari::from(value),
            script: vec![],
            recipient_address: Some(recipient),
            sender_offset_public_key: CompressedPublicKey::from_private_key(&PrivateKey::new(
                [0x01; 32],
            )),
        };
        self.outputs.push(output);
        self
    }

    fn with_fee(mut self, fee: u64) -> Self {
        self.fee = MicroMinotari::from(fee);
        self
    }

    fn with_lock_height(mut self, lock_height: u64) -> Self {
        self.lock_height = lock_height;
        self
    }

    fn build(self) -> Result<MockTransaction, WalletError> {
        // Validate transaction
        let total_input: u64 = self.inputs.iter().map(|i| i.value.as_u64()).sum();
        let total_output: u64 = self.outputs.iter().map(|o| o.value.as_u64()).sum();
        let total_with_fee = total_output + self.fee.as_u64();

        if total_input < total_with_fee {
            return Err(WalletError::ValidationError(
                ValidationError::TransactionValidationFailed(format!(
                    "Insufficient funds: input {total_input} < output {total_output} + fee {}",
                    self.fee.as_u64()
                )),
            ));
        }

        Ok(MockTransaction {
            inputs: self.inputs,
            outputs: self.outputs,
            fee: self.fee,
            lock_height: self.lock_height,
            signature: None,
        })
    }

    fn build_and_sign(self) -> Result<MockTransaction, WalletError> {
        let wallet = self.wallet.clone();
        let mut transaction = self.build()?;

        // Sign transaction if wallet is available
        if let Some(wallet) = wallet {
            let signature = MockTransactionBuilder::sign_transaction(&transaction, &wallet)?;
            transaction.signature = Some(signature);
        }

        Ok(transaction)
    }

    fn sign_transaction(
        transaction: &MockTransaction,
        wallet: &Wallet,
    ) -> Result<MockTransactionSignature, WalletError> {
        // Get wallet's signing key
        let seed_phrase = wallet.export_seed_phrase().map_err(|_| {
            WalletError::ValidationError(ValidationError::TransactionValidationFailed(
                "Cannot sign transaction without seed phrase".to_string(),
            ))
        })?;

        let signing_key = derive_tari_signing_key(&seed_phrase, None)?;
        let public_key = RistrettoPublicKey::from_secret_key(&signing_key);

        // Create transaction message for signing
        let transaction_message = Self::create_transaction_message(transaction);

        // Sign the transaction
        let (signature_hex, nonce_hex) =
            sign_message_with_hex_output(&signing_key, &transaction_message)?;

        Ok(MockTransactionSignature {
            signature_hex,
            nonce_hex,
            public_key,
        })
    }

    fn create_transaction_message(transaction: &MockTransaction) -> String {
        // Create a deterministic message from transaction data
        let mut message_parts = Vec::new();

        // Add inputs
        for input in &transaction.inputs {
            message_parts.push(format!("input:{}", hex::encode(&input.output_hash)));
        }

        // Add outputs
        for output in &transaction.outputs {
            message_parts.push(format!(
                "output:{}:{}",
                output.value.as_u64(),
                hex::encode(&output.commitment)
            ));
        }

        // Add fee and lock height
        message_parts.push(format!("fee:{}", transaction.fee.as_u64()));
        message_parts.push(format!("lock:{}", transaction.lock_height));

        message_parts.join("|")
    }
}

/// Mock transaction pool for broadcasting simulation
#[derive(Debug)]
struct MockTransactionPool {
    transactions: HashMap<String, MockTransaction>,
    network_latency_ms: u64,
    failure_rate: f32,
}

impl MockTransactionPool {
    fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            network_latency_ms: 100,
            failure_rate: 0.0,
        }
    }

    fn with_latency(mut self, latency_ms: u64) -> Self {
        self.network_latency_ms = latency_ms;
        self
    }

    #[allow(dead_code)]
    fn with_failure_rate(mut self, failure_rate: f32) -> Self {
        self.failure_rate = failure_rate;
        self
    }

    async fn broadcast_transaction(
        &mut self,
        transaction: MockTransaction,
    ) -> Result<String, WalletError> {
        // Simulate network latency
        if self.network_latency_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.network_latency_ms)).await;
        }

        // Simulate random failures
        if self.failure_rate > 0.0 && rand::random::<f32>() < self.failure_rate {
            return Err(WalletError::NetworkError(
                "Transaction broadcast failed".to_string(),
            ));
        }

        // Validate transaction before accepting
        self.validate_transaction(&transaction)?;

        // Generate transaction ID
        let tx_id = format!("tx_{}", self.transactions.len());

        // Store transaction
        self.transactions.insert(tx_id.clone(), transaction);

        Ok(tx_id)
    }

    fn validate_transaction(
        &self,
        transaction: &MockTransaction,
    ) -> Result<(), WalletError> {
        // Check signature is present
        if transaction.signature.is_none() {
            return Err(WalletError::ValidationError(
                ValidationError::TransactionValidationFailed(
                    "Transaction must be signed".to_string(),
                ),
            ));
        }

        // Check balance
        let total_input: u64 = transaction.inputs.iter().map(|i| i.value.as_u64()).sum();
        let total_output: u64 = transaction.outputs.iter().map(|o| o.value.as_u64()).sum();
        let total_with_fee = total_output + transaction.fee.as_u64();

        if total_input < total_with_fee {
            return Err(WalletError::ValidationError(
                ValidationError::TransactionValidationFailed("Insufficient funds".to_string()),
            ));
        }

        // Check minimum fee
        if transaction.fee.as_u64() < 100 {
            return Err(WalletError::ValidationError(
                ValidationError::TransactionValidationFailed("Fee too low".to_string()),
            ));
        }

        Ok(())
    }

    fn get_transaction(&self, tx_id: &str) -> Option<&MockTransaction> {
        self.transactions.get(tx_id)
    }

    fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
}

/// Test basic transaction creation workflow
#[tokio::test]
async fn test_transaction_creation_workflow() {
    // Setup wallets
    let sender_wallet =
        Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate sender wallet");

    let mut receiver_wallet =
        Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate receiver wallet");
    receiver_wallet.set_network("mainnet".to_string());

    // Generate receiver address
    let receiver_address = receiver_wallet
        .get_dual_address(
            TariAddressFeatures::create_interactive_and_one_sided(),
            None,
        )
        .expect("Failed to generate receiver address");

    // Create transaction inputs (simulate owned UTXOs)
    let input1_hash = vec![0x01; 32];
    let input1_commitment = vec![0x02; 32];
    let input2_hash = vec![0x03; 32];
    let input2_commitment = vec![0x04; 32];

    // Build transaction
    let transaction = MockTransactionBuilder::new()
        .with_wallet(sender_wallet.clone())
        .add_input(input1_hash, input1_commitment, 1000000) // 1 Tari
        .add_input(input2_hash, input2_commitment, 2000000) // 2 Tari
        .add_output(receiver_address, 2500000) // 2.5 Tari to receiver
        .with_fee(100000) // 0.1 Tari fee
        .with_lock_height(0)
        .build()
        .expect("Failed to build transaction");

    // Verify transaction structure
    assert_eq!(transaction.inputs.len(), 2);
    assert_eq!(transaction.outputs.len(), 1);
    assert_eq!(transaction.fee.as_u64(), 100000);
    assert_eq!(transaction.lock_height, 0);

    // Verify balance
    let total_input: u64 = transaction.inputs.iter().map(|i| i.value.as_u64()).sum();
    let total_output: u64 = transaction.outputs.iter().map(|o| o.value.as_u64()).sum();
    assert_eq!(total_input, 3000000); // 3 Tari
    assert_eq!(total_output, 2500000); // 2.5 Tari
    assert_eq!(
        total_input - total_output - transaction.fee.as_u64(),
        400000
    ); // 0.4 Tari change

    println!("✓ Transaction creation workflow test passed");
    println!(
        "  Inputs: {} µT, Outputs: {} µT, Fee: {} µT",
        total_input,
        total_output,
        transaction.fee.as_u64()
    );
}

/// Test transaction signing workflow
#[tokio::test]
async fn test_transaction_signing_workflow() {
    // Setup wallet with seed phrase
    let wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

    // Generate recipient address
    let mut recipient_wallet =
        Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate recipient wallet");
    recipient_wallet.set_network("stagenet".to_string());

    let recipient_address = recipient_wallet
        .get_single_address(TariAddressFeatures::create_interactive_only())
        .expect("Failed to generate recipient address");

    // Build and sign transaction
    let signed_transaction = MockTransactionBuilder::new()
        .with_wallet(wallet.clone())
        .add_input(vec![0x10; 32], vec![0x11; 32], 5000000) // 5 Tari
        .add_output(recipient_address.clone(), 4500000) // 4.5 Tari
        .with_fee(500000) // 0.5 Tari fee
        .build_and_sign()
        .expect("Failed to build and sign transaction");

    // Verify signature is present
    assert!(signed_transaction.signature.is_some());
    let signature = signed_transaction.signature.as_ref().unwrap();

    // Verify signature components
    assert!(!signature.signature_hex.is_empty());
    assert!(!signature.nonce_hex.is_empty());
    assert!(signature.signature_hex.len() == 64); // 32 bytes as hex
    assert!(signature.nonce_hex.len() == 64); // 32 bytes as hex

    // Verify signature is valid
    let transaction_message =
        MockTransactionBuilder::create_transaction_message(&signed_transaction);

    let is_valid = verify_message_from_hex(
        &signature.public_key,
        &transaction_message,
        &signature.signature_hex,
        &signature.nonce_hex,
    )
    .expect("Failed to verify signature");

    assert!(is_valid, "Transaction signature is invalid");

    // Test signature consistency
    let signed_transaction2 = MockTransactionBuilder::new()
        .with_wallet(wallet)
        .add_input(vec![0x10; 32], vec![0x11; 32], 5000000)
        .add_output(recipient_address, 4500000)
        .with_fee(500000)
        .build_and_sign()
        .expect("Failed to build second transaction");

    let signature2 = signed_transaction2.signature.as_ref().unwrap();

    // Signatures should use same public key but different nonces
    assert_eq!(signature.public_key, signature2.public_key);
    assert_ne!(signature.nonce_hex, signature2.nonce_hex); // Random nonces

    println!("✓ Transaction signing workflow test passed");
    println!("  Signature valid: {is_valid}");
    println!(
        "  Public key consistent: {}",
        signature.public_key == signature2.public_key,
    );
}

/// Test transaction broadcasting workflow
#[tokio::test]
async fn test_transaction_broadcasting_workflow() {
    // Setup
    let wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

    let mut recipient_wallet =
        Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate recipient wallet");
    recipient_wallet.set_network("localnet".to_string());

    let recipient_address = recipient_wallet
        .get_dual_address(TariAddressFeatures::create_one_sided_only(), None)
        .expect("Failed to generate recipient address");

    let mut tx_pool = MockTransactionPool::new().with_latency(50);

    // Create and sign transaction
    let signed_transaction = MockTransactionBuilder::new()
        .with_wallet(wallet)
        .add_input(vec![0x20; 32], vec![0x21; 32], 10000000) // 10 Tari
        .add_output(recipient_address, 9000000) // 9 Tari
        .with_fee(1000000) // 1 Tari fee
        .build_and_sign()
        .expect("Failed to build and sign transaction");

    // Broadcast transaction
    let start_time = Instant::now();
    let tx_id = tx_pool
        .broadcast_transaction(signed_transaction.clone())
        .await
        .expect("Failed to broadcast transaction");
    let broadcast_duration = start_time.elapsed();

    // Verify broadcast results
    assert!(!tx_id.is_empty());
    assert!(broadcast_duration >= Duration::from_millis(45)); // Network latency
    assert_eq!(tx_pool.transaction_count(), 1);

    // Verify transaction in pool
    let pooled_transaction = tx_pool
        .get_transaction(&tx_id)
        .expect("Transaction not found in pool");

    assert_eq!(
        pooled_transaction.inputs.len(),
        signed_transaction.inputs.len()
    );
    assert_eq!(
        pooled_transaction.outputs.len(),
        signed_transaction.outputs.len()
    );
    assert_eq!(pooled_transaction.fee, signed_transaction.fee);

    println!("✓ Transaction broadcasting workflow test passed");
    println!("  Transaction ID: {tx_id}");
    println!("  Broadcast duration: {broadcast_duration:?}");
}

/// Test transaction validation and error handling
#[tokio::test]
async fn test_transaction_validation_workflow() {
    let wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

    let mut recipient_wallet =
        Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate recipient wallet");
    recipient_wallet.set_network("mainnet".to_string());

    let recipient_address = recipient_wallet
        .get_single_address(TariAddressFeatures::create_interactive_only())
        .expect("Failed to generate recipient address");

    let mut tx_pool = MockTransactionPool::new();

    // Test insufficient funds
    let insufficient_funds_result = MockTransactionBuilder::new()
        .with_wallet(wallet.clone())
        .add_input(vec![0x30; 32], vec![0x31; 32], 1000000) // 1 Tari
        .add_output(recipient_address.clone(), 2000000) // 2 Tari (more than input)
        .with_fee(100000) // 0.1 Tari fee
        .build();

    assert!(insufficient_funds_result.is_err());
    if let Err(e) = insufficient_funds_result {
        assert!(e.to_string().contains("Insufficient funds"));
    }

    // Test fee too low
    let low_fee_transaction = MockTransactionBuilder::new()
        .with_wallet(wallet.clone())
        .add_input(vec![0x32; 32], vec![0x33; 32], 1000000) // 1 Tari
        .add_output(recipient_address.clone(), 900000) // 0.9 Tari
        .with_fee(50) // Very low fee
        .build_and_sign()
        .expect("Failed to build transaction");

    let low_fee_result = tx_pool.broadcast_transaction(low_fee_transaction).await;
    assert!(low_fee_result.is_err());
    if let Err(e) = low_fee_result {
        assert!(e.to_string().contains("Fee too low"));
    }

    // Test unsigned transaction
    let unsigned_transaction = MockTransactionBuilder::new()
        .add_input(vec![0x34; 32], vec![0x35; 32], 1000000)
        .add_output(recipient_address, 800000)
        .with_fee(200000)
        .build()
        .expect("Failed to build unsigned transaction");

    let unsigned_result = tx_pool.broadcast_transaction(unsigned_transaction).await;
    assert!(unsigned_result.is_err());
    if let Err(e) = unsigned_result {
        assert!(e.to_string().contains("must be signed"));
    }

    println!("✓ Transaction validation workflow test passed");
}

/// Test fee calculation and optimization
#[tokio::test]
async fn test_fee_calculation_workflow() {
    let wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

    let mut recipient_wallet =
        Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate recipient wallet");
    recipient_wallet.set_network("esmeralda".to_string());

    let recipient_address = recipient_wallet
        .get_dual_address(
            TariAddressFeatures::create_interactive_and_one_sided(),
            None,
        )
        .expect("Failed to generate recipient address");

    // Test different fee levels
    let fee_levels = vec![
        (100, "minimum"),   // Minimum fee
        (1000, "low"),      // Low priority
        (10000, "normal"),  // Normal priority
        (50000, "high"),    // High priority
        (100000, "urgent"), // Urgent priority
    ];

    for (fee_amount, priority) in fee_levels {
        let transaction = MockTransactionBuilder::new()
            .with_wallet(wallet.clone())
            .add_input(vec![0x40; 32], vec![0x41; 32], 1000000) // 1 Tari
            .add_output(recipient_address.clone(), 1000000 - fee_amount - 1000) // Adjust for fee
            .with_fee(fee_amount)
            .build_and_sign()
            .unwrap_or_else(|_| panic!("Failed to build {priority} priority transaction"));

        assert_eq!(transaction.fee.as_u64(), fee_amount);

        // Calculate fee rate (µT per byte, simulated)
        let estimated_tx_size = 500; // bytes
        let fee_rate = fee_amount as f64 / estimated_tx_size as f64;

        println!("  {priority} priority: {fee_amount} µT fee ({fee_rate:.2} µT/byte)");
    }

    // Test dynamic fee calculation based on transaction size
    let single_input_tx = MockTransactionBuilder::new()
        .with_wallet(wallet.clone())
        .add_input(vec![0x50; 32], vec![0x51; 32], 5000000)
        .add_output(recipient_address.clone(), 4000000)
        .with_fee(1000000)
        .build_and_sign()
        .expect("Failed to build single input transaction");

    let multi_input_tx = MockTransactionBuilder::new()
        .with_wallet(wallet.clone())
        .add_input(vec![0x52; 32], vec![0x53; 32], 2000000)
        .add_input(vec![0x54; 32], vec![0x55; 32], 2000000)
        .add_input(vec![0x56; 32], vec![0x57; 32], 1000000)
        .add_output(recipient_address, 4000000)
        .with_fee(1000000)
        .build_and_sign()
        .expect("Failed to build multi input transaction");

    // Multi-input transaction should ideally have higher fee due to larger size
    assert_eq!(single_input_tx.inputs.len(), 1);
    assert_eq!(multi_input_tx.inputs.len(), 3);

    println!("✓ Fee calculation workflow test passed");
    println!(
        "  Single input transaction: 1 input, {} µT fee",
        single_input_tx.fee.as_u64()
    );
    println!(
        "  Multi input transaction: {} inputs, {} µT fee",
        multi_input_tx.inputs.len(),
        multi_input_tx.fee.as_u64()
    );
}

/// Test transaction batching and concurrent operations
#[tokio::test]
async fn test_transaction_batching_workflow() {
    let wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

    // Create multiple recipient addresses
    let mut recipients = Vec::new();
    for i in 0..5 {
        let mut recipient_wallet = Wallet::generate_new_with_seed_phrase(None)
            .expect("Failed to generate recipient wallet");
        recipient_wallet.set_network("mainnet".to_string());

        let address = recipient_wallet
            .get_single_address(TariAddressFeatures::create_one_sided_only())
            .expect("Failed to generate recipient address");

        recipients.push((address, format!("recipient_{i}")));
    }

    let mut tx_pool = MockTransactionPool::new().with_latency(20);

    // Create batch of transactions
    let mut transactions = Vec::new();
    let _broadcast_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    for (i, (recipient_address, recipient_name)) in recipients.into_iter().enumerate() {
        let transaction = MockTransactionBuilder::new()
            .with_wallet(wallet.clone())
            .add_input(
                vec![(0x60 + i) as u8; 32],
                vec![(0x61 + i) as u8; 32],
                1000000,
            )
            .add_output(recipient_address, 800000)
            .with_fee(200000)
            .build_and_sign()
            .unwrap_or_else(|_| panic!("Failed to build transaction for {recipient_name}"));

        transactions.push((transaction, recipient_name));
    }

    // Broadcast transactions concurrently (simulated)
    let start_time = Instant::now();
    let mut tx_ids = Vec::new();

    for (transaction, recipient_name) in transactions {
        let tx_id = tx_pool
            .broadcast_transaction(transaction)
            .await
            .unwrap_or_else(|_| panic!("Failed to broadcast transaction to {recipient_name}"));
        tx_ids.push((tx_id, recipient_name));
    }

    let total_duration = start_time.elapsed();

    // Verify all transactions were broadcast
    assert_eq!(tx_ids.len(), 5);
    assert_eq!(tx_pool.transaction_count(), 5);

    // Verify transaction IDs are unique
    let mut unique_ids = std::collections::HashSet::new();
    for (tx_id, _) in &tx_ids {
        assert!(
            unique_ids.insert(tx_id.clone()),
            "Duplicate transaction ID: {tx_id}"
        );
    }

    println!("✓ Transaction batching workflow test passed");
    println!(
        "  Broadcast {} transactions in {:?}",
        tx_ids.len(),
        total_duration
    );
    for (tx_id, recipient) in tx_ids {
        println!("    {recipient} -> {tx_id}");
    }
}

/// Test complex transaction scenarios
#[tokio::test]
async fn test_complex_transaction_scenarios() {
    let wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

    // Scenario 1: Transaction with multiple outputs (fan-out)
    let mut recipients = Vec::new();
    for _i in 0..3 {
        let mut recipient_wallet = Wallet::generate_new_with_seed_phrase(None)
            .expect("Failed to generate recipient wallet");
        recipient_wallet.set_network("stagenet".to_string());

        let address = recipient_wallet
            .get_dual_address(TariAddressFeatures::create_interactive_only(), None)
            .expect("Failed to generate recipient address");

        recipients.push(address);
    }

    let fan_out_tx = MockTransactionBuilder::new()
        .with_wallet(wallet.clone())
        .add_input(vec![0x70; 32], vec![0x71; 32], 10000000) // 10 Tari
        .add_output(recipients[0].clone(), 3000000) // 3 Tari
        .add_output(recipients[1].clone(), 3000000) // 3 Tari
        .add_output(recipients[2].clone(), 3000000) // 3 Tari
        .with_fee(1000000) // 1 Tari fee
        .build_and_sign()
        .expect("Failed to build fan-out transaction");

    assert_eq!(fan_out_tx.outputs.len(), 3);

    // Scenario 2: Transaction with multiple inputs (fan-in)
    let fan_in_tx = MockTransactionBuilder::new()
        .with_wallet(wallet.clone())
        .add_input(vec![0x72; 32], vec![0x73; 32], 2000000) // 2 Tari
        .add_input(vec![0x74; 32], vec![0x75; 32], 3000000) // 3 Tari
        .add_input(vec![0x76; 32], vec![0x77; 32], 1000000) // 1 Tari
        .add_output(recipients[0].clone(), 5500000) // 5.5 Tari
        .with_fee(500000) // 0.5 Tari fee
        .build_and_sign()
        .expect("Failed to build fan-in transaction");

    assert_eq!(fan_in_tx.inputs.len(), 3);

    // Scenario 3: Transaction with time lock
    let time_locked_tx = MockTransactionBuilder::new()
        .with_wallet(wallet.clone())
        .add_input(vec![0x78; 32], vec![0x79; 32], 5000000) // 5 Tari
        .add_output(recipients[0].clone(), 4000000) // 4 Tari
        .with_fee(1000000) // 1 Tari fee
        .with_lock_height(1000000) // Lock until block 1,000,000
        .build_and_sign()
        .expect("Failed to build time-locked transaction");

    assert_eq!(time_locked_tx.lock_height, 1000000);

    // Verify all complex transactions
    let mut tx_pool = MockTransactionPool::new();

    let fan_out_id = tx_pool
        .broadcast_transaction(fan_out_tx)
        .await
        .expect("Failed to broadcast fan-out transaction");

    let fan_in_id = tx_pool
        .broadcast_transaction(fan_in_tx)
        .await
        .expect("Failed to broadcast fan-in transaction");

    let time_locked_id = tx_pool
        .broadcast_transaction(time_locked_tx)
        .await
        .expect("Failed to broadcast time-locked transaction");

    assert_eq!(tx_pool.transaction_count(), 3);

    println!("✓ Complex transaction scenarios test passed");
    println!("  Fan-out transaction: {fan_out_id}");
    println!("  Fan-in transaction: {fan_in_id}");
    println!("  Time-locked transaction: {time_locked_id}");
}
