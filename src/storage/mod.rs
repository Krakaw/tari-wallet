//! Storage abstraction layer for wallet transactions
//!
//! This module provides a trait-based storage system that allows different
//! storage backends to be used for persisting wallet transaction data.
//! The current implementation includes SQLite support with room for additional
//! backends like PostgreSQL, MongoDB, or other databases.

#[cfg(feature = "storage")]
pub mod connection_pool;
#[cfg(feature = "storage")]
pub mod event_storage;
pub mod output_status;
#[cfg(feature = "storage")]
pub mod performance_optimizations;
#[cfg(feature = "storage")]
pub mod sqlite;
#[cfg(feature = "storage")]
pub mod storage_trait;
pub mod stored_output;

#[cfg(feature = "storage")]
pub use connection_pool::*;
#[cfg(feature = "storage")]
pub use event_storage::*;
pub use output_status::*;
#[cfg(feature = "storage")]
pub use performance_optimizations::*;
#[cfg(feature = "storage")]
pub use sqlite::*;

#[cfg(feature = "storage")]
pub use storage_trait::*;

pub use stored_output::*;
