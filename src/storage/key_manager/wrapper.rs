use tari_common_types::{seeds::cipher_seed::CipherSeed, wallet_types::WalletType};
use tari_transaction_components::{
    crypto_factories::CryptoFactories, key_manager::TransactionKeyManagerWrapper,
};
use tari_utilities::SafePassword;

use crate::{
    key_manager::TransactionKeyManagerWalletStorage, EncryptionError, Wallet, WalletResult,
    WalletStorage,
};

pub struct TransactionKeyManager<TWalletStorage: WalletStorage + Clone + 'static> {
    pub storage: TransactionKeyManagerWalletStorage<TWalletStorage>,
    pub wrapper: TransactionKeyManagerWrapper<TransactionKeyManagerWalletStorage<TWalletStorage>>,
}

impl<TWalletStorage: WalletStorage + Clone + 'static> TransactionKeyManager<TWalletStorage> {
    pub async fn build(
        passphrase: Option<SafePassword>, // passphrase to decrypt the wallet
        database: TWalletStorage,
        wallet: &Wallet,
        wallet_type: WalletType,
        wallet_id: u32,
    ) -> WalletResult<Self> {
        let master_seed = CipherSeed::from_enciphered_bytes(&wallet.master_key_bytes(), passphrase)
            .map_err(|err| EncryptionError::InvalidEncryptionKey(err.to_string()))?;
        let storage =
            TransactionKeyManagerWalletStorage::build(database.clone(), wallet_id).await?;
        let wrapper = TransactionKeyManagerWrapper::new(
            master_seed,
            storage.clone(),
            CryptoFactories::default(),
            wallet_type.into(),
        )?;
        Ok(Self { storage, wrapper })
    }
}
