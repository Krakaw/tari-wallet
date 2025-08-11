use crate::unsigned_transaction::UnsignedTransaction;

pub struct TransactionSigner {
    pub unsigned_transaction: UnsignedTransaction,
}

impl TransactionSigner {
    pub fn new(unsigned_transaction: UnsignedTransaction) -> Self {
        Self {
            unsigned_transaction,
        }
    }

    pub fn sign_message(&self) {}
}
