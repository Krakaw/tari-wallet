use serde::{Deserialize, Serialize};

/// Output status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputStatus {
    Unspent = 0,
    Spent = 1,
    Locked = 2,
    Frozen = 3,
}

impl From<u32> for OutputStatus {
    fn from(value: u32) -> Self {
        match value {
            0 => OutputStatus::Unspent,
            1 => OutputStatus::Spent,
            2 => OutputStatus::Locked,
            3 => OutputStatus::Frozen,
            _ => OutputStatus::Unspent,
        }
    }
}

impl From<OutputStatus> for u32 {
    fn from(status: OutputStatus) -> Self {
        status as u32
    }
}
