//! SQLite Event Listener for storing wallet events in database
//!
//! This listener provides direct integration with the main SQLite storage
//! to store wallet events in the wallet_events table. It's designed to be
//! used in the scanner binary for persistent event storage.

#[cfg(feature = "storage")]
use async_trait::async_trait;
#[cfg(feature = "storage")]
use std::sync::Arc;
#[cfg(feature = "storage")]
use tokio::sync::RwLock;

#[cfg(feature = "storage")]
use crate::{
    events::{
        types::{WalletEventError, WalletEventResult, WalletScanEvent},
        EventListener, SharedEvent,
    },
    storage::{
        event_storage::{EventStorage, StoredEvent},
        sqlite::SqliteStorage,
    },
};

/// SQLite Event Listener that stores events directly in the main database
///
/// This listener integrates with the main SqliteStorage to store wallet events
/// in the wallet_events table. It's designed for use in the scanner binary
/// where we want to persist all scanning events for audit trails and replay.
#[cfg(feature = "storage")]
pub struct SqliteEventListener {
    /// Reference to the main SQLite storage backend
    storage: Arc<SqliteStorage>,
    /// Optional wallet ID to filter events (if None, stores all events)
    wallet_id: Arc<RwLock<Option<String>>>,
    /// Whether to store events immediately or batch them
    immediate_storage: bool,
}

#[cfg(feature = "storage")]
impl SqliteEventListener {
    /// Create a new SQLite event listener
    pub fn new(storage: Arc<SqliteStorage>) -> Self {
        Self {
            storage,
            wallet_id: Arc::new(RwLock::new(None)),
            immediate_storage: true,
        }
    }

    /// Create a new SQLite event listener with wallet ID filtering
    pub fn with_wallet_id(storage: Arc<SqliteStorage>, wallet_id: String) -> Self {
        Self {
            storage,
            wallet_id: Arc::new(RwLock::new(Some(wallet_id))),
            immediate_storage: true,
        }
    }

    /// Set whether to store events immediately (true) or batch them (false)
    pub fn with_immediate_storage(mut self, immediate: bool) -> Self {
        self.immediate_storage = immediate;
        self
    }

    /// Set the wallet ID for event filtering
    pub async fn set_wallet_id(&self, wallet_id: Option<String>) {
        let mut guard = self.wallet_id.write().await;
        *guard = wallet_id;
    }

    /// Get the current wallet ID
    pub async fn get_wallet_id(&self) -> Option<String> {
        self.wallet_id.read().await.clone()
    }

    /// Convert WalletScanEvent to StoredEvent for database storage
    fn convert_to_stored_event(
        &self,
        event: &WalletScanEvent,
        wallet_id: &str,
        sequence_number: u64,
    ) -> WalletEventResult<StoredEvent> {
        let event_type = match event {
            WalletScanEvent::ScanStarted { .. } => "SCAN_STARTED",
            WalletScanEvent::BlockProcessed { .. } => "BLOCK_PROCESSED",
            WalletScanEvent::OutputFound { .. } => "OUTPUT_FOUND",
            WalletScanEvent::SpentOutputFound { .. } => "SPENT_OUTPUT_FOUND",
            WalletScanEvent::ScanProgress { .. } => "SCAN_PROGRESS",
            WalletScanEvent::ScanCompleted { .. } => "SCAN_COMPLETED",
            WalletScanEvent::ScanError { .. } => "SCAN_ERROR",
            WalletScanEvent::ScanCancelled { .. } => "SCAN_CANCELLED",
        };

        let payload_json = serde_json::to_string(event)
            .map_err(|e| WalletEventError::serialization(&e.to_string(), "WalletScanEvent"))?;

        let metadata = serde_json::json!({
            "listener": "SqliteEventListener",
            "immediate_storage": self.immediate_storage,
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });

        let metadata_json = serde_json::to_string(&metadata)
            .map_err(|e| WalletEventError::serialization(&e.to_string(), "metadata"))?;

        Ok(StoredEvent::new(
            uuid::Uuid::new_v4().to_string(),
            wallet_id.to_string(),
            event_type.to_string(),
            sequence_number,
            payload_json,
            metadata_json,
            "wallet_scanner".to_string(),
            None, // No correlation ID for now
            std::time::SystemTime::now(),
        ))
    }
}

#[cfg(feature = "storage")]
#[async_trait]
impl EventListener for SqliteEventListener {
    async fn handle_event(
        &mut self,
        event: &SharedEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check if we have a wallet ID filter
        let wallet_id = match self.get_wallet_id().await {
            Some(id) => id,
            None => {
                // No wallet ID set - skip storing this event
                // This can happen in memory-only mode or before wallet initialization
                return Ok(());
            }
        };

        // Get next sequence number for this wallet
        let sequence_number = self
            .storage
            .get_next_sequence_number(&wallet_id)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        // Convert to stored event
        let stored_event = self
            .convert_to_stored_event(event, &wallet_id, sequence_number)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        // Store the event in the database
        if self.immediate_storage {
            self.storage
                .store_event(&stored_event)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        } else {
            // For batch storage, we would need to implement a buffering mechanism
            // For now, just store immediately
            self.storage
                .store_event(&stored_event)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "SqliteEventListener"
    }
}

#[cfg(feature = "storage")]
impl std::fmt::Debug for SqliteEventListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteEventListener")
            .field("immediate_storage", &self.immediate_storage)
            .finish()
    }
}

#[cfg(test)]
#[cfg(feature = "storage")]
mod tests {
    use super::*;
    use crate::{
        events::types::{EventMetadata, ScanStartedPayload, WalletScanEvent},
        storage::sqlite::SqliteStorage,
    };
    use std::sync::Arc;

    async fn create_test_storage() -> Arc<SqliteStorage> {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();
        Arc::new(storage)
    }

    #[tokio::test]
    async fn test_sqlite_event_listener_creation() {
        let storage = create_test_storage().await;
        let listener = SqliteEventListener::new(storage.clone());

        assert_eq!(listener.name(), "SqliteEventListener");
        assert!(listener.get_wallet_id().await.is_none());
    }

    #[tokio::test]
    async fn test_sqlite_event_listener_with_wallet_id() {
        let storage = create_test_storage().await;
        let wallet_id = "test-wallet-123".to_string();
        let listener = SqliteEventListener::with_wallet_id(storage.clone(), wallet_id.clone());

        assert_eq!(listener.get_wallet_id().await, Some(wallet_id));
    }

    #[tokio::test]
    async fn test_store_scan_started_event() {
        let storage = create_test_storage().await;
        let wallet_id = "test-wallet-123".to_string();
        let mut listener = SqliteEventListener::with_wallet_id(storage.clone(), wallet_id.clone());

        // Create a test scan started event
        let event = WalletScanEvent::ScanStarted {
            metadata: EventMetadata {
                event_id: "test-event-1".to_string(),
                timestamp: std::time::SystemTime::now(),
                sequence_number: 1,
                wallet_id: wallet_id.clone(),
                correlation_id: None,
                source: "test".to_string(),
            },
            payload: ScanStartedPayload {
                from_block: 1000,
                to_block: 2000,
                estimated_duration: None,
            },
        };

        // Handle the event
        listener.handle_event(&event).await.unwrap();

        // Verify it was stored in the database
        let stored_events = storage.get_wallet_events(&wallet_id).await.unwrap();
        assert_eq!(stored_events.len(), 1);
        assert_eq!(stored_events[0].event_type, "SCAN_STARTED");
        assert_eq!(stored_events[0].wallet_id, wallet_id);
        assert_eq!(stored_events[0].sequence_number, 1);
    }

    #[tokio::test]
    async fn test_no_wallet_id_skips_storage() {
        let storage = create_test_storage().await;
        let mut listener = SqliteEventListener::new(storage.clone());

        // Create a test event
        let event = WalletScanEvent::ScanStarted {
            metadata: EventMetadata {
                event_id: "test-event-1".to_string(),
                timestamp: std::time::SystemTime::now(),
                sequence_number: 1,
                wallet_id: "some-wallet".to_string(),
                correlation_id: None,
                source: "test".to_string(),
            },
            payload: ScanStartedPayload {
                from_block: 1000,
                to_block: 2000,
                estimated_duration: None,
            },
        };

        // Handle the event (should not store anything)
        listener.handle_event(&event).await.unwrap();

        // Verify no events were stored
        let filter = crate::storage::event_storage::EventFilter::new();
        let stored_events = storage.get_events(&filter).await.unwrap();
        assert_eq!(stored_events.len(), 0);
    }
}
