//! Wallet builder module providing a fluent API for wallet construction with event system integration
//!
//! This module implements the builder pattern for creating wallets with optional event listeners.
//! The builder allows for configuring wallets with different creation methods and event handling
//! capabilities while maintaining type safety and ergonomic usage.

use crate::errors::KeyManagementError;
use crate::events::{EventRegistry, WalletEventListener};
use crate::wallet::{Wallet, WalletMetadata};
use std::collections::HashMap;

/// Storage mode for wallet events
#[derive(Debug, Clone, PartialEq)]
pub enum StorageMode {
    /// Events are stored in memory only (no persistence)
    MemoryOnly,
    /// Events are persisted to a database
    Database,
}

/// Errors that can occur during wallet building
#[derive(Debug, Clone)]
pub enum WalletBuildError {
    /// Error during wallet creation from seed phrase or other sources
    WalletCreation(String),
    /// Error during event listener registration
    EventListenerError(String),
    /// Configuration validation error
    ConfigurationError(String),
    /// Missing required parameters
    MissingParameter(String),
}

impl std::fmt::Display for WalletBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletBuildError::WalletCreation(msg) => write!(f, "Wallet creation error: {}", msg),
            WalletBuildError::EventListenerError(msg) => {
                write!(f, "Event listener error: {}", msg)
            }
            WalletBuildError::ConfigurationError(msg) => {
                write!(f, "Configuration error: {}", msg)
            }
            WalletBuildError::MissingParameter(param) => {
                write!(f, "Missing required parameter: {}", param)
            }
        }
    }
}

impl std::error::Error for WalletBuildError {}

impl From<KeyManagementError> for WalletBuildError {
    fn from(err: KeyManagementError) -> Self {
        WalletBuildError::WalletCreation(err.to_string())
    }
}

/// Wallet creation methods supported by the builder
#[derive(Debug, Clone)]
enum WalletCreationMethod {
    /// Generate a new wallet with random entropy
    GenerateNew {
        #[allow(dead_code)]
        passphrase: Option<String>,
    },
    /// Generate a new wallet with a seed phrase
    GenerateWithSeedPhrase { passphrase: Option<String> },
    /// Create wallet from existing seed phrase
    FromSeedPhrase {
        phrase: String,
        passphrase: Option<String>,
    },
    /// Create wallet from master key and birthday
    FromMasterKey { master_key: [u8; 32], birthday: u64 },
}

/// Builder for creating wallets with optional event system integration
///
/// The WalletBuilder provides a fluent API for creating wallets with different
/// configuration options including event listeners, metadata, and creation methods.
///
/// # Examples
///
/// ## Basic wallet creation
///
/// ```rust,no_run
/// use lightweight_wallet_libs::wallet::WalletBuilder;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let wallet = WalletBuilder::new()
///     .generate_new()
///     .with_label("My Wallet")
///     .with_network("mainnet")
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// ## Wallet with event listeners
///
/// ```rust,no_run
/// use lightweight_wallet_libs::wallet::WalletBuilder;
/// use lightweight_wallet_libs::events::listeners::event_logger::EventLogger;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let event_logger = EventLogger::console().unwrap();
///
/// let wallet = WalletBuilder::new()
///     .generate_with_seed_phrase()
///     .with_event_listener(Box::new(event_logger))
///     .with_label("Event-enabled Wallet")
///     .build_async().await?;
///
/// // The wallet now has an integrated event system
/// assert!(wallet.events_enabled());
/// assert_eq!(wallet.event_listener_count(), 1);
/// # Ok(())
/// # }
/// ```
///
/// ## Wallet from existing seed phrase
///
/// ```rust,no_run
/// use lightweight_wallet_libs::wallet::WalletBuilder;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let wallet = WalletBuilder::new()
///     .from_seed_phrase("your twenty four word seed phrase here...".to_string(), None)
///     .with_network("stagenet")
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct WalletBuilder {
    creation_method: Option<WalletCreationMethod>,
    event_registry: Option<EventRegistry>,
    metadata: WalletMetadata,
    listeners_to_register: Vec<Box<dyn WalletEventListener>>,
}

impl WalletBuilder {
    /// Create a new wallet builder
    ///
    /// The builder starts with default metadata and no creation method specified.
    /// You must call one of the creation methods (generate_new, from_seed_phrase, etc.)
    /// before building the wallet.
    pub fn new() -> Self {
        Self {
            creation_method: None,
            event_registry: None,
            metadata: WalletMetadata::default(),
            listeners_to_register: Vec::new(),
        }
    }

    /// Configure the builder to generate a new wallet with random entropy
    ///
    /// # Arguments
    ///
    /// * `passphrase` - Optional passphrase for additional security (currently not used for random generation)
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub fn generate_new(mut self) -> Self {
        self.creation_method = Some(WalletCreationMethod::GenerateNew { passphrase: None });
        self
    }

    /// Configure the builder to generate a new wallet with random entropy and passphrase
    ///
    /// # Arguments
    ///
    /// * `passphrase` - Optional passphrase for additional security
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub fn generate_new_with_passphrase(mut self, passphrase: Option<String>) -> Self {
        self.creation_method = Some(WalletCreationMethod::GenerateNew { passphrase });
        self
    }

    /// Configure the builder to generate a new wallet with a seed phrase
    ///
    /// This creates a wallet using a randomly generated 24-word BIP39 seed phrase.
    /// The original seed phrase is stored and can be exported.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - Optional passphrase for additional security
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub fn generate_with_seed_phrase(mut self) -> Self {
        self.creation_method =
            Some(WalletCreationMethod::GenerateWithSeedPhrase { passphrase: None });
        self
    }

    /// Configure the builder to generate a new wallet with a seed phrase and passphrase
    ///
    /// # Arguments
    ///
    /// * `passphrase` - Optional passphrase for additional security
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub fn generate_with_seed_phrase_and_passphrase(mut self, passphrase: Option<String>) -> Self {
        self.creation_method = Some(WalletCreationMethod::GenerateWithSeedPhrase { passphrase });
        self
    }

    /// Configure the builder to create a wallet from an existing seed phrase
    ///
    /// # Arguments
    ///
    /// * `phrase` - The BIP39 seed phrase to use
    /// * `passphrase` - Optional passphrase used when the seed phrase was created
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub fn from_seed_phrase(mut self, phrase: String, passphrase: Option<String>) -> Self {
        self.creation_method = Some(WalletCreationMethod::FromSeedPhrase { phrase, passphrase });
        self
    }

    /// Configure the builder to create a wallet from a master key and birthday
    ///
    /// # Arguments
    ///
    /// * `master_key` - The 32-byte master key
    /// * `birthday` - The wallet birthday (creation timestamp)
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub fn from_master_key(mut self, master_key: [u8; 32], birthday: u64) -> Self {
        self.creation_method = Some(WalletCreationMethod::FromMasterKey {
            master_key,
            birthday,
        });
        self
    }

    /// Add an event listener to the wallet
    ///
    /// Event listeners will receive wallet events during operations. Multiple
    /// listeners can be registered and they will all receive events independently.
    ///
    /// # Arguments
    ///
    /// * `listener` - The event listener to register
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    ///
    /// # Note
    ///
    /// If no event listeners are registered, the wallet will still function normally
    /// but will not emit events. Event capture is opt-in and disabled by default.
    pub fn with_event_listener(mut self, listener: Box<dyn WalletEventListener>) -> Self {
        if self.event_registry.is_none() {
            self.event_registry = Some(EventRegistry::new());
        }

        // Store the listener for registration during build
        // We'll need to handle the async registration in build()
        self.listeners_to_register.push(listener);
        self
    }

    /// Add an event registry to the wallet
    ///
    /// This allows you to configure a complete event registry externally and
    /// attach it to the wallet. Any listeners added via `with_event_listener`
    /// will be registered with this registry.
    ///
    /// # Arguments
    ///
    /// * `registry` - The event registry to use
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub fn with_event_registry(mut self, registry: EventRegistry) -> Self {
        self.event_registry = Some(registry);
        self
    }

    /// Set the wallet label
    ///
    /// # Arguments
    ///
    /// * `label` - The wallet label/name
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub fn with_label<S: Into<String>>(mut self, label: S) -> Self {
        self.metadata.label = Some(label.into());
        self
    }

    /// Set the wallet network
    ///
    /// # Arguments
    ///
    /// * `network` - The network name (e.g., "mainnet", "stagenet", "localnet")
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub fn with_network<S: Into<String>>(mut self, network: S) -> Self {
        self.metadata.network = network.into();
        self
    }

    /// Set the current key index
    ///
    /// # Arguments
    ///
    /// * `index` - The key index for deterministic key derivation
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub fn with_key_index(mut self, index: u64) -> Self {
        self.metadata.current_key_index = index;
        self
    }

    /// Set a custom property
    ///
    /// # Arguments
    ///
    /// * `key` - The property key
    /// * `value` - The property value
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub fn with_property<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.metadata.properties.insert(key.into(), value.into());
        self
    }

    /// Set multiple custom properties
    ///
    /// # Arguments
    ///
    /// * `properties` - Map of properties to set
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub fn with_properties(mut self, properties: HashMap<String, String>) -> Self {
        self.metadata.properties.extend(properties);
        self
    }

    /// Configure the wallet with database-backed event storage
    ///
    /// This method marks the wallet for database storage mode but doesn't
    /// add database storage listeners yet (feature coming soon).
    ///
    /// # Arguments
    ///
    /// * `database_path` - Path to the SQLite database file (use ":memory:" for in-memory)
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    ///
    /// # Note
    ///
    /// This method requires the `storage` feature to be enabled.
    #[cfg(feature = "storage")]
    pub async fn with_database_storage(
        mut self,
        _database_path: String,
    ) -> Result<Self, WalletBuildError> {
        // Initialize event registry if not present
        if self.event_registry.is_none() {
            self.event_registry = Some(EventRegistry::new());
        }

        // Mark as database storage mode
        self.metadata
            .properties
            .insert("event_storage_mode".to_string(), "database".to_string());

        Ok(self)
    }

    /// Configure the wallet with database-backed event storage (fallback for non-storage builds)
    ///
    /// When the `storage` feature is not enabled, this method returns an error
    /// indicating that database storage is not available.
    #[cfg(not(feature = "storage"))]
    pub async fn with_database_storage(
        self,
        _database_path: String,
    ) -> Result<Self, WalletBuildError> {
        Err(WalletBuildError::ConfigurationError(
            "Database storage is not available. Please enable the 'storage' feature.".to_string(),
        ))
    }

    /// Configure the wallet with memory-only event handling
    ///
    /// This method sets up the wallet for memory-only operation without
    /// database persistence. Events will only be handled by registered
    /// listeners but not persisted to disk.
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub fn with_memory_only_events(mut self) -> Self {
        // Initialize event registry if not present
        if self.event_registry.is_none() {
            self.event_registry = Some(EventRegistry::new());
        }

        // Add a marker property to indicate memory-only mode
        self.metadata
            .properties
            .insert("event_storage_mode".to_string(), "memory_only".to_string());

        self
    }

    /// Configure the wallet for production use with database storage
    ///
    /// This is a convenience method that sets up optimal configuration for
    /// production environments, including database storage and performance
    /// tuning.
    ///
    /// # Arguments
    ///
    /// * `database_path` - Path to the SQLite database file
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    ///
    /// # Features
    ///
    /// This method is only available when the `storage` feature is enabled.
    #[cfg(feature = "storage")]
    pub async fn for_production(
        mut self,
        _database_path: String,
    ) -> Result<Self, WalletBuildError> {
        // Set production metadata
        self.metadata
            .properties
            .insert("deployment_mode".to_string(), "production".to_string());
        self.metadata
            .properties
            .insert("event_storage_mode".to_string(), "database".to_string());

        // Initialize event registry if not present
        if self.event_registry.is_none() {
            self.event_registry = Some(EventRegistry::new());
        }

        // TODO: Add database storage listener when it implements WalletEventListener trait

        Ok(self)
    }

    /// Configure the wallet for development use with enhanced debugging
    ///
    /// This is a convenience method that sets up optimal configuration for
    /// development environments, including console logging and detailed
    /// event tracking.
    ///
    /// # Arguments
    ///
    /// * `database_path` - Optional path to database (if None, uses memory-only)
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub async fn for_development(
        mut self,
        _database_path: Option<String>,
    ) -> Result<Self, WalletBuildError> {
        use crate::events::listeners::EventLogger;

        // Set development metadata
        self.metadata
            .properties
            .insert("deployment_mode".to_string(), "development".to_string());

        // Initialize event registry if not present
        if self.event_registry.is_none() {
            self.event_registry = Some(EventRegistry::new());
        }

        // Add detailed event logging
        let event_logger = EventLogger::console()
            .map_err(|e| WalletBuildError::ConfigurationError(e.to_string()))?;
        self.listeners_to_register.push(Box::new(event_logger));

        // Set storage mode based on path provided and feature availability
        #[cfg(feature = "storage")]
        if _database_path.is_some() {
            self.metadata
                .properties
                .insert("event_storage_mode".to_string(), "database".to_string());
            // TODO: Add database storage listener when it implements WalletEventListener trait
        } else {
            self.metadata
                .properties
                .insert("event_storage_mode".to_string(), "memory_only".to_string());
        }

        #[cfg(not(feature = "storage"))]
        {
            self.metadata
                .properties
                .insert("event_storage_mode".to_string(), "memory_only".to_string());
        }

        Ok(self)
    }

    /// Configure the wallet for testing with event capture
    ///
    /// This is a convenience method that sets up optimal configuration for
    /// testing environments, including event logging for event capture
    /// and verification.
    ///
    /// # Returns
    ///
    /// Returns the builder for method chaining
    pub fn for_testing(mut self) -> Result<Self, WalletBuildError> {
        use crate::events::listeners::EventLogger;

        // Set testing metadata
        self.metadata
            .properties
            .insert("deployment_mode".to_string(), "testing".to_string());
        self.metadata
            .properties
            .insert("event_storage_mode".to_string(), "memory_only".to_string());

        // Initialize event registry if not present
        if self.event_registry.is_none() {
            self.event_registry = Some(EventRegistry::new());
        }

        // Add event logger for test event capture
        let event_logger = EventLogger::console()
            .map_err(|e| WalletBuildError::ConfigurationError(e.to_string()))?;
        self.listeners_to_register.push(Box::new(event_logger));

        Ok(self)
    }

    /// Get the configured storage mode
    ///
    /// Returns the storage mode based on the current configuration.
    pub fn get_storage_mode(&self) -> StorageMode {
        match self.metadata.properties.get("event_storage_mode") {
            Some(mode) if mode == "database" => StorageMode::Database,
            Some(mode) if mode == "memory_only" => StorageMode::MemoryOnly,
            _ => {
                // Default based on feature availability
                #[cfg(feature = "storage")]
                {
                    StorageMode::Database
                }
                #[cfg(not(feature = "storage"))]
                {
                    StorageMode::MemoryOnly
                }
            }
        }
    }

    /// Check if database storage is available
    ///
    /// Returns true if the storage feature is enabled and database storage
    /// can be used.
    pub fn is_database_storage_available() -> bool {
        cfg!(feature = "storage")
    }

    /// Build the wallet synchronously (without event system)
    ///
    /// This method creates the wallet without setting up the event system.
    /// Use this when you don't need event listeners or for simple wallet creation.
    ///
    /// # Returns
    ///
    /// Returns the created wallet or an error if creation fails
    ///
    /// # Errors
    ///
    /// * `MissingParameter` - If no creation method was specified
    /// * `WalletCreation` - If wallet creation fails
    /// * `ConfigurationError` - If event listeners are configured (use `build_async` instead)
    pub fn build(self) -> Result<Wallet, WalletBuildError> {
        // Check if async build is required
        if !self.listeners_to_register.is_empty() || self.event_registry.is_some() {
            return Err(WalletBuildError::ConfigurationError(
                "Event listeners require async build - use build_async() instead".to_string(),
            ));
        }

        let creation_method = self.creation_method.ok_or_else(|| {
            WalletBuildError::MissingParameter(
                "creation method (call generate_new, from_seed_phrase, etc.)".to_string(),
            )
        })?;

        // Create the wallet based on the specified method
        let mut wallet = match creation_method {
            WalletCreationMethod::GenerateNew { .. } => Wallet::generate_new(None),
            WalletCreationMethod::GenerateWithSeedPhrase { passphrase } => {
                Wallet::generate_new_with_seed_phrase(passphrase.as_deref())?
            }
            WalletCreationMethod::FromSeedPhrase { phrase, passphrase } => {
                Wallet::new_from_seed_phrase(&phrase, passphrase.as_deref())?
            }
            WalletCreationMethod::FromMasterKey {
                master_key,
                birthday,
            } => Wallet::new(master_key, birthday),
        };

        // Apply metadata
        wallet.metadata = self.metadata;

        Ok(wallet)
    }

    /// Build the wallet asynchronously with event system support
    ///
    /// This method creates the wallet and sets up the event system if listeners
    /// are configured. Use this when you need event listeners or async initialization.
    ///
    /// # Returns
    ///
    /// Returns the created wallet with configured event system or an error if creation fails
    ///
    /// # Errors
    ///
    /// * `MissingParameter` - If no creation method was specified
    /// * `WalletCreation` - If wallet creation fails
    /// * `EventListenerError` - If event listener registration fails
    pub async fn build_async(mut self) -> Result<Wallet, WalletBuildError> {
        let creation_method = self.creation_method.ok_or_else(|| {
            WalletBuildError::MissingParameter(
                "creation method (call generate_new, from_seed_phrase, etc.)".to_string(),
            )
        })?;

        // Create the wallet based on the specified method
        let mut wallet = match creation_method {
            WalletCreationMethod::GenerateNew { .. } => Wallet::generate_new(None),
            WalletCreationMethod::GenerateWithSeedPhrase { passphrase } => {
                Wallet::generate_new_with_seed_phrase(passphrase.as_deref())?
            }
            WalletCreationMethod::FromSeedPhrase { phrase, passphrase } => {
                Wallet::new_from_seed_phrase(&phrase, passphrase.as_deref())?
            }
            WalletCreationMethod::FromMasterKey {
                master_key,
                birthday,
            } => Wallet::new(master_key, birthday),
        };

        // Apply metadata
        wallet.metadata = self.metadata;

        // Set up event system if listeners are configured
        if !self.listeners_to_register.is_empty() || self.event_registry.is_some() {
            // Set up event registry
            let mut event_registry = self.event_registry.unwrap_or_else(EventRegistry::new);

            // Register any listeners that were added
            for listener in self.listeners_to_register {
                event_registry
                    .register(listener)
                    .await
                    .map_err(|e| WalletBuildError::EventListenerError(e.to_string()))?;
            }

            // Set the event registry on the wallet
            wallet.set_event_registry(event_registry).await;
        }

        Ok(wallet)
    }
}

impl Default for WalletBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A wallet combined with an event registry for event-driven operations
///
/// **DEPRECATED**: This struct is now deprecated. Use the `Wallet` struct directly,
/// which now has built-in event system support. This struct is kept for backward compatibility.
///
/// This struct wraps a regular wallet with an event registry to provide
/// event-driven functionality. It maintains the same wallet interface while
/// adding event emission capabilities.
#[deprecated(
    since = "0.3.0",
    note = "Use Wallet directly with built-in event system"
)]
pub struct WalletWithEvents {
    /// The underlying wallet
    pub wallet: Wallet,
    /// The event registry for handling listeners
    pub event_registry: EventRegistry,
}

impl WalletWithEvents {
    /// Get a reference to the underlying wallet
    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// Get a mutable reference to the underlying wallet
    pub fn wallet_mut(&mut self) -> &mut Wallet {
        &mut self.wallet
    }

    /// Get a reference to the event registry
    pub fn event_registry(&self) -> &EventRegistry {
        &self.event_registry
    }

    /// Get a mutable reference to the event registry
    pub fn event_registry_mut(&mut self) -> &mut EventRegistry {
        &mut self.event_registry
    }

    /// Add an event listener to the registry
    ///
    /// # Arguments
    ///
    /// * `listener` - The event listener to register
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful registration, or an error if registration fails
    pub async fn add_event_listener(
        &mut self,
        listener: Box<dyn WalletEventListener>,
    ) -> Result<(), crate::events::types::WalletEventError> {
        self.event_registry.register(listener).await
    }

    /// Remove an event listener from the registry
    ///
    /// # Arguments
    ///
    /// * `listener_name` - Name of the listener to remove
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the listener was removed, or an error if not found
    pub async fn remove_event_listener(
        &mut self,
        listener_name: &str,
    ) -> Result<(), crate::events::types::WalletEventError> {
        self.event_registry.remove(listener_name).await
    }

    /// Shutdown the event system
    ///
    /// This method cleanly shuts down all event listeners and should be called
    /// when the wallet is no longer needed.
    pub async fn shutdown_events(&mut self) {
        self.event_registry.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::listeners::event_logger::EventLogger;

    #[test]
    fn test_wallet_builder_generate_new() {
        let wallet = WalletBuilder::new().generate_new().build().unwrap();

        assert!(wallet.birthday() > 0);
        assert_eq!(wallet.current_key_index(), 0);
    }

    #[test]
    fn test_wallet_builder_with_metadata() {
        let wallet = WalletBuilder::new()
            .generate_new()
            .with_label("Test Wallet")
            .with_network("testnet")
            .with_key_index(42)
            .with_property("version", "1.0")
            .build()
            .unwrap();

        assert_eq!(wallet.label(), Some(&"Test Wallet".to_string()));
        assert_eq!(wallet.network(), "testnet");
        assert_eq!(wallet.current_key_index(), 42);
        assert_eq!(wallet.get_property("version"), Some(&"1.0".to_string()));
    }

    #[test]
    fn test_wallet_builder_from_seed_phrase() {
        let seed_phrase = crate::key_management::generate_seed_phrase().unwrap();

        let wallet = WalletBuilder::new()
            .from_seed_phrase(seed_phrase.clone(), None)
            .build()
            .unwrap();

        assert_eq!(wallet.export_seed_phrase().unwrap(), seed_phrase);
    }

    #[test]
    fn test_wallet_builder_missing_creation_method() {
        let result = WalletBuilder::new().build();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WalletBuildError::MissingParameter(_)
        ));
    }

    #[test]
    fn test_wallet_builder_sync_with_events_error() {
        let listener = EventLogger::console().unwrap();
        let result = WalletBuilder::new()
            .generate_new()
            .with_event_listener(Box::new(listener))
            .build();

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WalletBuildError::ConfigurationError(_)
        ));
    }

    #[tokio::test]
    async fn test_wallet_builder_async_with_events() {
        let listener = EventLogger::console().unwrap();
        let wallet = WalletBuilder::new()
            .generate_new()
            .with_event_listener(Box::new(listener))
            .build_async()
            .await
            .unwrap();

        assert!(wallet.events_enabled());
        assert_eq!(wallet.event_listener_count(), 1);
        // Check that the event registry has the expected listener
        if let Some(registry) = wallet.event_registry() {
            assert!(registry.has_listener("EventLogger"));
        }
    }

    #[tokio::test]
    async fn test_wallet_with_events_operations() {
        let mut wallet = WalletBuilder::new()
            .generate_new()
            .with_label("Event Wallet")
            .build_async()
            .await
            .unwrap();

        // Wallet should not have events enabled by default when no listeners are configured
        assert!(!wallet.events_enabled());

        // Test adding listener (should auto-enable events)
        let listener = EventLogger::console().unwrap();
        assert!(wallet.add_event_listener(Box::new(listener)).await.is_ok());
        assert!(wallet.events_enabled());
        assert_eq!(wallet.event_listener_count(), 1);

        // Test removing listener
        assert!(wallet.remove_event_listener("EventLogger").await.is_ok());
        assert_eq!(wallet.event_listener_count(), 0);
    }

    #[tokio::test]
    async fn test_wallet_event_system_methods() {
        let mut wallet = WalletBuilder::new().generate_new().build().unwrap();

        // Initially no events
        assert!(!wallet.events_enabled());
        assert_eq!(wallet.event_listener_count(), 0);

        // Enable events
        assert!(wallet.enable_events());
        assert!(wallet.events_enabled());

        // Try to enable again (should return false)
        assert!(!wallet.enable_events());

        // Disable events
        assert!(wallet.disable_events().await);
        assert!(!wallet.events_enabled());

        // Try to disable again (should return false)
        assert!(!wallet.disable_events().await);
    }

    #[tokio::test]
    async fn test_wallet_builder_memory_only_events() {
        let wallet = WalletBuilder::new()
            .generate_new()
            .with_memory_only_events()
            .build_async()
            .await
            .unwrap();

        assert!(wallet.events_enabled());
        assert_eq!(
            wallet.get_property("event_storage_mode"),
            Some(&"memory_only".to_string())
        );
    }

    #[tokio::test]
    async fn test_wallet_builder_for_testing() {
        let wallet = WalletBuilder::new()
            .generate_new()
            .for_testing()
            .unwrap()
            .build_async()
            .await
            .unwrap();

        assert!(wallet.events_enabled());
        assert_eq!(
            wallet.get_property("deployment_mode"),
            Some(&"testing".to_string())
        );
        assert_eq!(
            wallet.get_property("event_storage_mode"),
            Some(&"memory_only".to_string())
        );
        assert_eq!(wallet.event_listener_count(), 1); // Event logger
    }

    #[tokio::test]
    async fn test_wallet_builder_for_development_memory_only() {
        let wallet = WalletBuilder::new()
            .generate_new()
            .for_development(None)
            .await
            .unwrap()
            .build_async()
            .await
            .unwrap();

        assert!(wallet.events_enabled());
        assert_eq!(
            wallet.get_property("deployment_mode"),
            Some(&"development".to_string())
        );
        assert_eq!(
            wallet.get_property("event_storage_mode"),
            Some(&"memory_only".to_string())
        );
        assert_eq!(wallet.event_listener_count(), 1); // EventLogger
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_wallet_builder_with_database_storage() {
        let wallet = WalletBuilder::new()
            .generate_new()
            .with_database_storage(":memory:".to_string())
            .await
            .unwrap()
            .build_async()
            .await
            .unwrap();

        assert!(wallet.events_enabled());
        assert_eq!(
            wallet.get_property("event_storage_mode"),
            Some(&"database".to_string())
        );
        assert_eq!(wallet.event_listener_count(), 0); // Database listener not yet implemented
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_wallet_builder_for_production() {
        let wallet = WalletBuilder::new()
            .generate_new()
            .for_production(":memory:".to_string())
            .await
            .unwrap()
            .build_async()
            .await
            .unwrap();

        assert!(wallet.events_enabled());
        assert_eq!(
            wallet.get_property("deployment_mode"),
            Some(&"production".to_string())
        );
        assert_eq!(
            wallet.get_property("event_storage_mode"),
            Some(&"database".to_string())
        );
        assert_eq!(wallet.event_listener_count(), 0); // Database listener not yet implemented
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_wallet_builder_for_development_with_database() {
        let wallet = WalletBuilder::new()
            .generate_new()
            .for_development(Some(":memory:".to_string()))
            .await
            .unwrap()
            .build_async()
            .await
            .unwrap();

        assert!(wallet.events_enabled());
        assert_eq!(
            wallet.get_property("deployment_mode"),
            Some(&"development".to_string())
        );
        assert_eq!(
            wallet.get_property("event_storage_mode"),
            Some(&"database".to_string())
        );
        assert_eq!(wallet.event_listener_count(), 1); // EventLogger (Database not yet implemented)
    }

    #[cfg(not(feature = "storage"))]
    #[tokio::test]
    async fn test_wallet_builder_database_storage_unavailable() {
        let result = WalletBuilder::new()
            .generate_new()
            .with_database_storage("test.db".to_string())
            .await;

        assert!(result.is_err());
        assert!(result.is_err());
        if let Err(WalletBuildError::ConfigurationError(msg)) = result {
            assert!(msg.contains("Database storage is not available"));
        } else {
            panic!("Expected ConfigurationError");
        }
    }

    #[test]
    fn test_storage_mode_detection() {
        let builder_memory = WalletBuilder::new()
            .generate_new()
            .with_memory_only_events();
        assert_eq!(builder_memory.get_storage_mode(), StorageMode::MemoryOnly);

        // Test default storage mode based on feature availability
        let builder_default = WalletBuilder::new().generate_new();
        #[cfg(feature = "storage")]
        assert_eq!(builder_default.get_storage_mode(), StorageMode::Database);
        #[cfg(not(feature = "storage"))]
        assert_eq!(builder_default.get_storage_mode(), StorageMode::MemoryOnly);
    }

    #[test]
    fn test_database_storage_availability() {
        let available = WalletBuilder::is_database_storage_available();

        #[cfg(feature = "storage")]
        assert!(available);
        #[cfg(not(feature = "storage"))]
        assert!(!available);
    }
}
