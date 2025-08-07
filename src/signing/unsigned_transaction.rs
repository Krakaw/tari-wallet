use crate::data_structures::TariAddress;

pub struct PaymentRecipient {
    pub amount: u64,
}

pub struct UnsignedTransaction {
    pub amount: u64,
    pub recipient_address: TariAddress,
    pub sender_address: TariAddress,
    // TODO:
    // inputs (to spend)
    // change_output
    // payment_id
    // metadata
}
