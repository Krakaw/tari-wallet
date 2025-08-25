use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use tari_common_types::wallet_types::WalletType;
use tari_transaction_components::{
    crypto_factories::CryptoFactories,
    key_manager::{TransactionKeyManagerInterface, TransactionKeyManagerWrapper},
};

use crate::{
    key_manager::TransactionKeyManagerWalletStorage, CipherSeed, EncryptionError, WalletResult,
    WalletStorage,
};

#[derive(Clone)]
pub struct TransactionKeyManager(TransactionKeyManagerWrapper<TransactionKeyManagerWalletStorage>);

impl TransactionKeyManager {
    pub async fn build(
        database: Arc<dyn WalletStorage>,
        master_seed: CipherSeed,
        wallet_type: WalletType,
        wallet_id: u32,
    ) -> WalletResult<Self> {
        let storage = TransactionKeyManagerWalletStorage::build(database, wallet_id).await?;
        let seed = tari_common_types::seeds::cipher_seed::CipherSeed::from_enciphered_bytes(
            &master_seed.encipher(None)?,
            None,
        )
        .map_err(|err| EncryptionError::DecryptionFailed(err.to_string()))?;
        let wrapper = TransactionKeyManagerWrapper::new(
            seed,
            storage.clone(),
            CryptoFactories::default(),
            wallet_type.into(),
        )?;
        Ok(Self(wrapper))
    }

    pub fn as_interface(&self) -> impl TransactionKeyManagerInterface + 'static {
        self.0.clone()
    }
}

impl Deref for TransactionKeyManager {
    type Target = TransactionKeyManagerWrapper<TransactionKeyManagerWalletStorage>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TransactionKeyManager {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
