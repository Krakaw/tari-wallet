use std::io::Result;

use borsh::{BorshDeserialize, BorshSerialize};

use super::byte_counter::ByteCounter;

pub trait FromBytes<T: BorshDeserialize> {
    fn borsh_from_bytes(buf: &mut &[u8]) -> Result<T>;
}

impl<T: BorshDeserialize> FromBytes<T> for T {
    fn borsh_from_bytes(buf: &mut &[u8]) -> Result<T> {
        T::deserialize(buf)
    }
}

pub trait SerializedSize {
    fn get_serialized_size(&self) -> Result<usize>;
}

impl<T: BorshSerialize> SerializedSize for T {
    fn get_serialized_size(&self) -> Result<usize> {
        let mut counter = ByteCounter::new();
        self.serialize(&mut counter)?;
        Ok(counter.get())
    }
}
