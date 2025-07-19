//! WASM service module organization for WebAssembly-specific functionality
//!
//! This module provides WASM-optimized scanning services and utilities
//! that bridge between the core library functionality and JavaScript environments.

pub mod scanner_service;
pub mod types;

// Re-export WASM scanner types
pub use scanner_service::{WasmScannerService, WasmScanResult, WasmBlockInfo, WasmScanConfig};
pub use types::{WasmTransactionOutput, WasmWalletOutput, WasmProgressInfo};
