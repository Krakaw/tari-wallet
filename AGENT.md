# Tari Lightweight Wallet Libraries - Agent Instructions

## Build/Test Commands
- `cargo test` - Run all unit tests
- `cargo test --all-features` - Run tests with all features enabled
- `cargo test --features grpc` - Run tests with GRPC blockchain scanning
- `cargo test --features storage` - Run tests with database storage
- `cargo test test_name` - Run specific test by name
- `cargo check` - Fast compile check without building
- `cargo build --release` - Production build
- `wasm-pack test --node --features wasm` - WASM-specific tests
- `wasm-pack build --target web` - Build WASM module for web

## Architecture & Structure
- **Core modules**: `wallet/` (master keys, addresses), `key_management/` (BIP39-like mnemonics), `data_structures/` (addresses, types)
- **Crypto**: `validation/` (range proofs, commitments), `extraction/` (UTXO processing), `crypto/` (primitives)
- **Storage**: Optional SQLite database support with `storage/` module
- **Scanning**: GRPC-based blockchain scanning with `scanning/` module for UTXO discovery
- **Features**: `grpc` (blockchain scanning), `storage` (SQLite), `wasm` (WebAssembly), `http` (web APIs)
- **Database**: SQLite (`wallet.db`) for persistent storage when `storage` feature enabled

## Code Style & Conventions
- **Naming**: snake_case files/functions, PascalCase types, SCREAMING_SNAKE_CASE constants
- **Imports**: std first, external crates alphabetical, local crate imports last
- **Error handling**: thiserror-based hierarchical errors, Result types, `?` operator
- **Documentation**: `//!` module docs, `///` function docs with Arguments/Returns sections
- **Features**: Use `#[cfg(feature = "...")]` for conditional compilation
- **Security**: Zeroize sensitive data, use SafeArray for keys, no secrets in logs
- **Types**: Use domain-specific types like `CompressedPublicKey`, `PrivateKey`, `MicroMinotari`
