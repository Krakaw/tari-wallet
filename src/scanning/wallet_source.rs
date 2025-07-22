//! Wallet source and context for scanner initialization
//!
//! This module defines the different ways a wallet can be provided to the scanner
//! and the context needed for wallet operations during scanning.

use crate::data_structures::types::PrivateKey;
use crate::errors::LightweightWalletError;
use crate::wallet::Wallet;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Different sources for wallet initialization in the scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletSource {
    /// Create wallet from a mnemonic seed phrase with optional passphrase
    SeedPhrase {
        /// BIP39 mnemonic seed phrase (12-24 words)
        phrase: String,
        /// Optional passphrase for additional entropy
        passphrase: Option<String>,
    },
    /// Create wallet from a raw view key (64 hex characters)
    ViewKey {
        /// Private view key in hex format
        view_key_hex: String,
        /// Optional wallet birthday for scanning optimization
        birthday: Option<u64>,
    },
    /// Use an existing wallet instance
    ExistingWallet {
        /// Pre-created wallet instance  
        #[serde(skip, default)]
        wallet: Option<Wallet>,
    },
    /// Generate a completely new random wallet
    GenerateNew {
        /// Optional passphrase (for future use)
        passphrase: Option<String>,
    },
}

/// Context holding the initialized wallet and related scanning metadata
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct WalletContext {
    /// The initialized wallet instance
    pub wallet: Wallet,
    /// The view key extracted from the wallet
    #[zeroize(skip)]
    pub view_key: PrivateKey,
    /// Additional entropy for scanning operations
    pub entropy: [u8; 32],
    /// Source information for debugging/logging
    #[zeroize(skip)]
    pub source_type: WalletSourceType,
}

/// Simplified enum for tracking the type of wallet source (for logging/debugging)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum WalletSourceType {
    SeedPhrase,
    ViewKey,
    ExistingWallet,
    GeneratedNew,
}

impl WalletSource {
    /// Initialize a wallet from this source
    pub fn initialize_wallet(self) -> Result<WalletContext, LightweightWalletError> {
        match self {
            WalletSource::SeedPhrase { phrase, passphrase } => {
                let wallet = Wallet::new_from_seed_phrase(&phrase, passphrase.as_deref())?;
                let view_key = wallet.get_view_key()?;
                let entropy = wallet.get_entropy()?;
                
                Ok(WalletContext {
                    wallet,
                    view_key,
                    entropy,
                    source_type: WalletSourceType::SeedPhrase,
                })
            }
            WalletSource::ViewKey { view_key_hex, birthday } => {
                // Create a view-only wallet from the view key
                let view_key = parse_view_key(&view_key_hex)?;
                let birthday = birthday.unwrap_or_else(|| Wallet::current_birthday());
                
                // Create wallet with zero master key (view-only)
                let wallet = Wallet::new([0u8; 32], birthday);
                
                // Use the view key as entropy for now
                let view_key_bytes = view_key.as_bytes().to_vec();
                let mut entropy = [0u8; 32];
                entropy.copy_from_slice(&view_key_bytes);
                
                Ok(WalletContext {
                    wallet,
                    view_key,
                    entropy,
                    source_type: WalletSourceType::ViewKey,
                })
            }
            WalletSource::ExistingWallet { wallet } => {
                let wallet = wallet.ok_or_else(|| LightweightWalletError::InvalidArgument {
                    argument: "existing_wallet".to_string(),
                    value: "None".to_string(),
                    message: "No wallet provided for ExistingWallet variant".to_string(),
                })?;
                let view_key = wallet.get_view_key()?;
                let entropy = wallet.get_entropy()?;
                
                Ok(WalletContext {
                    wallet,
                    view_key,
                    entropy,
                    source_type: WalletSourceType::ExistingWallet,
                })
            }
            WalletSource::GenerateNew { passphrase: _ } => {
                let wallet = Wallet::generate_new(None);
                let view_key = wallet.get_view_key()?;
                let entropy = wallet.get_entropy()?;
                
                Ok(WalletContext {
                    wallet,
                    view_key,
                    entropy,
                    source_type: WalletSourceType::GeneratedNew,
                })
            }
        }
    }
    
    /// Create a WalletSource from a seed phrase
    pub fn from_seed_phrase(phrase: impl Into<String>, passphrase: Option<impl Into<String>>) -> Self {
        Self::SeedPhrase {
            phrase: phrase.into(),
            passphrase: passphrase.map(|p| p.into()),
        }
    }
    
    /// Create a WalletSource from a view key
    pub fn from_view_key(view_key_hex: impl Into<String>, birthday: Option<u64>) -> Self {
        Self::ViewKey {
            view_key_hex: view_key_hex.into(),
            birthday,
        }
    }
    
    /// Create a WalletSource from an existing wallet
    pub fn from_existing_wallet(wallet: Wallet) -> Self {
        Self::ExistingWallet { wallet: Some(wallet) }
    }
    
    /// Create a WalletSource for generating a new wallet
    pub fn generate_new(passphrase: Option<impl Into<String>>) -> Self {
        Self::GenerateNew {
            passphrase: passphrase.map(|p| p.into()),
        }
    }
}

impl fmt::Display for WalletSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletSource::SeedPhrase { passphrase, .. } => {
                if passphrase.is_some() {
                    write!(f, "Seed phrase (with passphrase)")
                } else {
                    write!(f, "Seed phrase")
                }
            }
            WalletSource::ViewKey { birthday, .. } => {
                if let Some(b) = birthday {
                    write!(f, "View key (birthday: {})", b)
                } else {
                    write!(f, "View key")
                }
            }
            WalletSource::ExistingWallet { .. } => write!(f, "Existing wallet"),
            WalletSource::GenerateNew { passphrase } => {
                if passphrase.is_some() {
                    write!(f, "Generated new (with passphrase)")
                } else {
                    write!(f, "Generated new")
                }
            }
        }
    }
}

impl fmt::Display for WalletSourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletSourceType::SeedPhrase => write!(f, "seed_phrase"),
            WalletSourceType::ViewKey => write!(f, "view_key"),
            WalletSourceType::ExistingWallet => write!(f, "existing_wallet"),
            WalletSourceType::GeneratedNew => write!(f, "generated_new"),
        }
    }
}

/// Parse a hex-encoded view key into a PrivateKey
fn parse_view_key(view_key_hex: &str) -> Result<PrivateKey, LightweightWalletError> {
    let view_key_bytes = hex::decode(view_key_hex).map_err(|_| {
        LightweightWalletError::InvalidArgument {
            argument: "view_key_hex".to_string(),
            value: view_key_hex.to_string(),
            message: "Invalid hex format for view key".to_string(),
        }
    })?;

    if view_key_bytes.len() != 32 {
        return Err(LightweightWalletError::InvalidArgument {
            argument: "view_key_hex".to_string(),
            value: format!("{} bytes", view_key_bytes.len()),
            message: "View key must be exactly 32 bytes".to_string(),
        });
    }

    let view_key_array: [u8; 32] = view_key_bytes.try_into().map_err(|_| {
        LightweightWalletError::InvalidArgument {
            argument: "view_key_bytes".to_string(),
            value: "byte_conversion".to_string(),
            message: "Failed to convert view key bytes to array".to_string(),
        }
    })?;

    Ok(PrivateKey::new(view_key_array))
}

// Implement Zeroize manually for WalletContext to ensure sensitive data is cleared
impl Zeroize for WalletContext {
    fn zeroize(&mut self) {
        self.wallet.zeroize();
        self.entropy.zeroize();
        // view_key and source_type are marked with #[zeroize(skip)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_source_from_seed_phrase() {
        let source = WalletSource::from_seed_phrase("test phrase", Some("passphrase"));
        match source {
            WalletSource::SeedPhrase { phrase, passphrase } => {
                assert_eq!(phrase, "test phrase");
                assert_eq!(passphrase, Some("passphrase".to_string()));
            }
            _ => panic!("Expected SeedPhrase variant"),
        }
    }

    #[test]
    fn test_wallet_source_from_view_key() {
        let view_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let source = WalletSource::from_view_key(view_key, Some(12345));
        match source {
            WalletSource::ViewKey { view_key_hex, birthday } => {
                assert_eq!(view_key_hex, view_key);
                assert_eq!(birthday, Some(12345));
            }
            _ => panic!("Expected ViewKey variant"),
        }
    }

    #[test]
    fn test_wallet_source_generate_new() {
        let source = WalletSource::generate_new(None::<String>);
        match source {
            WalletSource::GenerateNew { passphrase } => {
                assert!(passphrase.is_none());
            }
            _ => panic!("Expected GenerateNew variant"),
        }
    }

    #[test]
    fn test_parse_view_key_valid() {
        let view_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let result = parse_view_key(view_key_hex);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_view_key_invalid_hex() {
        let view_key_hex = "invalid_hex";
        let result = parse_view_key(view_key_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_view_key_wrong_length() {
        let view_key_hex = "0123456789abcdef"; // Too short
        let result = parse_view_key(view_key_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_wallet_source_display() {
        let seed_source = WalletSource::from_seed_phrase("test", Some("pass"));
        assert_eq!(seed_source.to_string(), "Seed phrase (with passphrase)");

        let view_source = WalletSource::from_view_key("abc", None);
        assert_eq!(view_source.to_string(), "View key");

        let gen_source = WalletSource::generate_new(None::<String>);
        assert_eq!(gen_source.to_string(), "Generated new");
    }
}
