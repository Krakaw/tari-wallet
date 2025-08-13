use tari_common_types::{
    key_branches::TransactionKeyManagerBranch,
    tari_address::{TariAddress, TariAddressFeatures},
    transaction::TxId,
    types::{ComAndPubSignature, CompressedPublicKey},
    wallet_types::WalletType,
};
use tari_script::{script, ExecutionStack, TariScript};
use tari_transaction_components::{
    key_manager::{TariKeyId, TransactionKeyManagerInterface},
    tari_amount::MicroMinotari,
    transaction_components::{
        covenants::Covenant,
        memo_field::{MemoField, TxType},
        transaction_metadata::TransactionMetadata,
        EncryptedData, OutputFeatures, TransactionOutput, TransactionOutputVersion, WalletOutput,
    },
};
use tari_utilities::SafePassword;

use crate::{
    key_manager::TransactionKeyManager,
    models::{
        marshal_output_pair::{MarshalOutputPair, OutputPair},
        types::{
            get_supported_version, OneSidedTransactionInfo, PaymentRecipient,
            PrepareOneSidedTransactionForSigningResult,
        },
    },
    prepare::input_selector::{InputSelector, UtxoSelection},
    util::key_id::make_key_id_export_safe,
    SerializationError, StoredOutput, Wallet, WalletError, WalletResult, WalletStorage,
};

pub struct OneSidedTransaction<TWalletStorage: WalletStorage + Clone + 'static> {
    database: TWalletStorage,
    wallet_id: u32,
    wallet: Wallet,
    transaction_key_manager: TransactionKeyManager<TWalletStorage>,
}

impl<TWalletStorage: WalletStorage + Clone + 'static> OneSidedTransaction<TWalletStorage> {
    fn new(
        database: TWalletStorage,
        wallet_id: u32,
        wallet: Wallet,
        transaction_key_manager: TransactionKeyManager<TWalletStorage>,
    ) -> Self {
        Self {
            database,
            wallet_id,
            wallet,
            transaction_key_manager,
        }
    }

    pub async fn build(
        passphrase: Option<SafePassword>,
        database: TWalletStorage,
        wallet_id: u32,
    ) -> WalletResult<Self> {
        let stored_wallet = database.get_wallet_by_id(wallet_id).await?.ok_or_else(|| {
            WalletError::ResourceNotFound(format!("Wallet with ID {} not found", wallet_id,))
        })?;
        let seed_phrase = stored_wallet.seed_phrase.ok_or_else(|| {
            WalletError::InternalError(format!(
                "Wallet with ID {} does not have a seed phrase",
                wallet_id,
            ))
        })?;
        let passphrase_str: Option<String> = passphrase
            .clone()
            .map(|p| String::from_utf8(p.reveal().clone()).expect("invalid phrase"));
        let wallet = Wallet::new_from_seed_phrase(&seed_phrase, passphrase_str.as_deref())?;

        let transaction_key_manager = TransactionKeyManager::build(
            passphrase.clone(),
            database.clone(),
            &wallet,
            WalletType::default(),
            wallet_id,
        )
        .await?;

        Ok(Self::new(
            database,
            wallet_id,
            wallet,
            transaction_key_manager,
        ))
    }

    async fn build_marshal_output_pair(
        &self,
        output: WalletOutput,
        sender_offset_key_id: Option<TariKeyId>,
    ) -> WalletResult<MarshalOutputPair> {
        let nonce = self
            .transaction_key_manager
            .get_next_key(TransactionKeyManagerBranch::KernelNonce.get_branch_key())
            .await?;
        let output_pair = OutputPair {
            output,
            kernel_nonce: nonce.key_id,
            sender_offset_key_id,
        };

        MarshalOutputPair::marshal(&self.transaction_key_manager.as_interface(), output_pair).await
    }

    async fn build_change_output(
        &self,
        unspent_outputs: &UtxoSelection,
        sender_address: &TariAddress,
        original_payment_id: &MemoField,
        recipient: &PaymentRecipient,
    ) -> WalletResult<Option<MarshalOutputPair>> {
        if !unspent_outputs.requires_change_output {
            return Ok(None);
        }

        let change_amount = unspent_outputs
            .total_value
            .checked_sub(unspent_outputs.fee_with_change)
            .ok_or_else(|| {
                WalletError::InsufficientFunds(format!(
                    "You are spending more than you're providing: provided {}, required {}.",
                    unspent_outputs.total_value, unspent_outputs.fee_with_change
                ))
            })?;
        if change_amount <= MicroMinotari::zero() {
            return Ok(None);
        }

        let sender_offset_public = self
            .transaction_key_manager
            .get_next_key(TransactionKeyManagerBranch::SenderOffset.get_branch_key())
            .await
            .map_err(|e| e.to_string())?;

        let (change_commitment_mask_key, change_script_key) = self
            .transaction_key_manager
            .get_next_commitment_mask_and_script_key()
            .await?;

        let sender_one_sided = true;
        let payment_id_recipient_address = match original_payment_id.get_type() {
            TxType::PaymentToOther => recipient.address.clone(),
            TxType::PaymentToSelf
            | TxType::CoinSplit
            | TxType::CoinJoin
            | TxType::ValidatorNodeRegistration
            | TxType::CodeTemplateRegistration
            | TxType::ClaimAtomicSwap
            | TxType::HtlcAtomicSwapRefund => sender_address.clone(),
            _ => TariAddress::default(),
        };
        let payment_id = MemoField::new_transaction_info(
            payment_id_recipient_address,
            recipient.amount,
            unspent_outputs.fee_with_change + change_amount,
            sender_one_sided,
            original_payment_id.get_type(),
            Vec::new(),
            original_payment_id.payment_id_as_bytes(),
        )
        .map_err(|e| e.to_string())?;

        let change_script =
            script!(PushPubKey(Box::new(change_script_key.pub_key))).map_err(|e| e.to_string())?;

        let encrypted_data = self
            .transaction_key_manager
            .encrypt_data_for_recovery(
                &change_commitment_mask_key.key_id,
                None,
                change_amount.as_u64(),
                payment_id.clone(),
            )
            .await
            .map_err(|e| e.to_string())?;

        let output_version = TransactionOutputVersion::get_current_version();
        let features = OutputFeatures::default();
        let covenant = Covenant::default();
        let minimum_value_promise = MicroMinotari::zero();
        let metadata_message = TransactionOutput::metadata_signature_message_from_parts(
            &output_version,
            &change_script,
            &features,
            &covenant,
            &encrypted_data,
            &minimum_value_promise,
        );
        let metadata_sig = self
            .transaction_key_manager
            .get_metadata_signature(
                &change_commitment_mask_key.key_id,
                &change_amount.into(),
                &sender_offset_public.key_id,
                &output_version,
                &metadata_message,
                features.range_proof_type,
            )
            .await
            .map_err(|e| e.to_string())?;

        let export_safe_change_script_key_id =
            make_key_id_export_safe(&self.transaction_key_manager, &change_script_key.key_id)
                .await?;
        let change_wallet_output = WalletOutput::new_current_version(
            change_amount,
            change_commitment_mask_key.key_id,
            features,
            change_script,
            ExecutionStack::default(),
            export_safe_change_script_key_id,
            sender_offset_public.pub_key.clone(),
            metadata_sig,
            0,
            Covenant::default(),
            encrypted_data,
            minimum_value_promise,
            payment_id,
            &self.transaction_key_manager.as_interface(),
        )
        .await
        .map_err(|e| e.to_string())?;

        Ok(Some(
            self.build_marshal_output_pair(change_wallet_output, Some(sender_offset_public.key_id))
                .await?,
        ))
    }

    async fn get_inputs(
        &self,
        unspent_outputs: &UtxoSelection,
    ) -> WalletResult<Vec<MarshalOutputPair>> {
        let mut result = vec![];
        for utxo in &unspent_outputs.utxos {
            let wallet_output = self.wallet_output_from_stored_output(utxo.clone()).await?;
            let input = self.build_marshal_output_pair(wallet_output, None).await?;
            result.push(input);
        }
        Ok(result)
    }

    pub async fn prepare(
        &self,
        dest_address: TariAddress,
        amount: MicroMinotari,
        fee_per_gram: MicroMinotari,
        payment_id: MemoField,
    ) -> WalletResult<PrepareOneSidedTransactionForSigningResult> {
        let recipient = PaymentRecipient {
            amount,
            output_features: OutputFeatures::default(),
            address: dest_address.clone(),
        };
        let sender_address = self
            .wallet
            .get_dual_address(
                crate::data_structures::TariAddressFeatures::create_one_sided_only(),
                None,
            )?
            .into();

        let payment_id = get_payment_id(&sender_address, &dest_address, fee_per_gram, payment_id);
        let metadata = TransactionMetadata::default();
        let tx_id = TxId::new_random();

        let input_selector = InputSelector::new(self.wallet_id, self.database.clone());
        let unspent_outputs = input_selector
            .fetch_unspent_outputs(amount, fee_per_gram)
            .await?;

        let inputs = self.get_inputs(&unspent_outputs).await?;

        let change_output = self
            .build_change_output(&unspent_outputs, &sender_address, &payment_id, &recipient)
            .await?;

        let info = OneSidedTransactionInfo {
            payment_id,
            recipient,
            change_output,
            inputs,
            outputs: vec![],
            metadata,
            sender_address,
        };

        Ok(PrepareOneSidedTransactionForSigningResult {
            version: get_supported_version(),
            tx_id,
            info,
        })
    }

    async fn wallet_output_from_stored_output(
        &self,
        o: StoredOutput,
    ) -> WalletResult<WalletOutput> {
        // TODO: spending key id is not stored in db
        let spending_key_id = TariKeyId::default();
        // TODO: output features are not stored in db
        let features = OutputFeatures::default();
        // TODO: input data is not stored in db
        let input_data = ExecutionStack::default();
        // TODO: script key id and script private key is not stored in db
        let export_safe_script_key_id = TariKeyId::default();
        // TODO: sender offset public key is not stored in db
        let sender_offset_public_key = CompressedPublicKey::default();
        // TODO: metadata signature is not stored in db
        let metadata_signature = ComAndPubSignature::default();
        // TODO: script lock height is not stored in db
        let script_lock_height = 0;
        // TODO: covenant is not stored in db
        let covenant = Covenant::default();
        let encrypted_data = EncryptedData::from_bytes(&o.encrypted_data)
            .map_err(|e| WalletError::ConversionError(e.to_string()))?;
        // TODO: minimum_value_promise is not stored in db
        let minimum_value_promise = MicroMinotari(0);
        // TODO: payment id is not stored in db
        let payment_id = MemoField::default();

        let script_bytes = &hex::decode(o.script).map_err(SerializationError::from)?;
        let script = TariScript::from_bytes(script_bytes)?;

        let wallet_output = WalletOutput::new_current_version(
            MicroMinotari(o.value),
            spending_key_id,
            features,
            script,
            input_data,
            export_safe_script_key_id,
            sender_offset_public_key,
            metadata_signature,
            script_lock_height,
            covenant,
            encrypted_data,
            minimum_value_promise,
            payment_id,
            &self.transaction_key_manager.as_interface(),
        )
        .await?;
        Ok(wallet_output)
    }
}

fn get_payment_id(
    sender_address: &TariAddress,
    dest_address: &TariAddress,
    fee_per_gram: MicroMinotari,
    payment_id: MemoField,
) -> MemoField {
    let mut payment_id = payment_id.clone();
    if dest_address
        .features()
        .contains(TariAddressFeatures::PAYMENT_ID)
    {
        payment_id = MemoField::open(
            dest_address.get_memo_field_payment_id_bytes(),
            TxType::PaymentToOther,
        );
    }
    payment_id
        .clone()
        .add_sender_address(
            sender_address.clone(),
            true,
            fee_per_gram,
            if dest_address == sender_address {
                Some(TxType::PaymentToSelf)
            } else {
                Some(TxType::PaymentToOther)
            },
        )
        .unwrap_or(payment_id)
}
