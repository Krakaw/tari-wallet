//! Event storage implementation for wallet events
//!
//! This module provides SQLite-based storage for wallet events, implementing
//! an append-only event log with proper indexing and querying capabilities.

#[cfg(feature = "storage")]
use async_trait::async_trait;
#[cfg(feature = "storage")]
use rusqlite::{params, Row};
#[cfg(feature = "storage")]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(feature = "storage")]
use tokio_rusqlite::Connection;

#[cfg(feature = "storage")]
use crate::events::types::{WalletEventError, WalletEventResult};

/// Stored event representation in the database
#[cfg(feature = "storage")]
#[derive(Debug, Clone)]
pub struct StoredEvent {
    /// Auto-incrementing primary key
    pub id: Option<u64>,
    /// Event ID (UUID string)
    pub event_id: String,
    /// Wallet ID this event belongs to
    pub wallet_id: String,
    /// Event type (e.g., "UTXO_RECEIVED", "UTXO_SPENT", "REORG")
    pub event_type: String,
    /// Sequence number for ordering (per wallet)
    pub sequence_number: u64,
    /// JSON-serialized event payload
    pub payload_json: String,
    /// Event metadata as JSON
    pub metadata_json: String,
    /// Event source component
    pub source: String,
    /// Optional correlation ID for related events
    pub correlation_id: Option<String>,
    /// Timestamp when event was created
    pub timestamp: SystemTime,
    /// Timestamp when event was stored in database
    pub stored_at: SystemTime,
}

impl StoredEvent {
    /// Create a new stored event
    pub fn new(
        event_id: String,
        wallet_id: String,
        event_type: String,
        sequence_number: u64,
        payload_json: String,
        metadata_json: String,
        source: String,
        correlation_id: Option<String>,
        timestamp: SystemTime,
    ) -> Self {
        Self {
            id: None,
            event_id,
            wallet_id,
            event_type,
            sequence_number,
            payload_json,
            metadata_json,
            source,
            correlation_id,
            timestamp,
            stored_at: SystemTime::now(),
        }
    }
}

/// Filter criteria for querying events
#[cfg(feature = "storage")]
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// Filter by wallet ID
    pub wallet_id: Option<String>,
    /// Filter by event type
    pub event_type: Option<String>,
    /// Filter by sequence number range (inclusive)
    pub sequence_range: Option<(u64, u64)>,
    /// Filter by timestamp range (inclusive)
    pub timestamp_range: Option<(SystemTime, SystemTime)>,
    /// Filter by correlation ID
    pub correlation_id: Option<String>,
    /// Filter by source component
    pub source: Option<String>,
    /// Limit number of results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
    /// Order by sequence number (default: ascending)
    pub order_by_sequence_desc: bool,
}

impl EventFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Set wallet ID filter
    pub fn with_wallet_id(mut self, wallet_id: String) -> Self {
        self.wallet_id = Some(wallet_id);
        self
    }

    /// Set event type filter
    pub fn with_event_type(mut self, event_type: String) -> Self {
        self.event_type = Some(event_type);
        self
    }

    /// Set sequence number range filter
    pub fn with_sequence_range(mut self, from: u64, to: u64) -> Self {
        self.sequence_range = Some((from, to));
        self
    }

    /// Set timestamp range filter
    pub fn with_timestamp_range(mut self, from: SystemTime, to: SystemTime) -> Self {
        self.timestamp_range = Some((from, to));
        self
    }

    /// Set correlation ID filter
    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Set source filter
    pub fn with_source(mut self, source: String) -> Self {
        self.source = Some(source);
        self
    }

    /// Set limit for results
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set offset for pagination
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Order by sequence number descending (newest first)
    pub fn order_desc(mut self) -> Self {
        self.order_by_sequence_desc = true;
        self
    }
}

/// Event storage trait for different storage backends
#[cfg(feature = "storage")]
#[async_trait]
pub trait EventStorage {
    /// Initialize the storage backend (create tables, indexes, etc.)
    async fn initialize(&self) -> WalletEventResult<()>;

    /// Store a new event (append-only)
    async fn store_event(&self, event: &StoredEvent) -> WalletEventResult<u64>;

    /// Store multiple events in a batch (transactional)
    async fn store_events_batch(&self, events: &[StoredEvent]) -> WalletEventResult<Vec<u64>>;

    /// Retrieve events matching the given filter
    async fn get_events(&self, filter: &EventFilter) -> WalletEventResult<Vec<StoredEvent>>;

    /// Get a specific event by ID
    async fn get_event_by_id(&self, event_id: &str) -> WalletEventResult<Option<StoredEvent>>;

    /// Get the latest sequence number for a wallet
    async fn get_latest_sequence(&self, wallet_id: &str) -> WalletEventResult<Option<u64>>;

    /// Get event count for a wallet
    async fn get_event_count(&self, wallet_id: &str) -> WalletEventResult<u64>;

    /// Get events since a specific sequence number (for replay)
    async fn get_events_since_sequence(
        &self,
        wallet_id: &str,
        sequence: u64,
    ) -> WalletEventResult<Vec<StoredEvent>>;

    /// Check if an event exists by ID
    async fn event_exists(&self, event_id: &str) -> WalletEventResult<bool>;

    /// Get storage statistics
    async fn get_storage_stats(&self) -> WalletEventResult<EventStorageStats>;

    // Additional specialized query operations for task 4.2

    /// Get all events for a specific wallet, ordered by sequence number
    async fn get_wallet_events(&self, wallet_id: &str) -> WalletEventResult<Vec<StoredEvent>>;

    /// Get events for a wallet within a specific sequence range
    async fn get_wallet_events_in_range(
        &self,
        wallet_id: &str,
        from_sequence: u64,
        to_sequence: u64,
    ) -> WalletEventResult<Vec<StoredEvent>>;

    /// Get the first N events for a wallet (oldest first)
    async fn get_wallet_events_head(
        &self,
        wallet_id: &str,
        limit: usize,
    ) -> WalletEventResult<Vec<StoredEvent>>;

    /// Get the last N events for a wallet (newest first)
    async fn get_wallet_events_tail(
        &self,
        wallet_id: &str,
        limit: usize,
    ) -> WalletEventResult<Vec<StoredEvent>>;

    /// Get events by specific sequence numbers
    async fn get_events_by_sequences(
        &self,
        wallet_id: &str,
        sequences: &[u64],
    ) -> WalletEventResult<Vec<StoredEvent>>;

    /// Get a specific event by wallet_id and sequence number
    async fn get_event_by_sequence(
        &self,
        wallet_id: &str,
        sequence: u64,
    ) -> WalletEventResult<Option<StoredEvent>>;

    /// Insert a new event with automatic sequence number assignment
    async fn insert_event(
        &self,
        wallet_id: &str,
        event_type: &str,
        payload_json: String,
        metadata_json: String,
        source: &str,
        correlation_id: Option<String>,
    ) -> WalletEventResult<(u64, u64)>; // Returns (db_id, sequence_number)

    /// Insert multiple events with automatic sequence number assignment
    async fn insert_events_batch(
        &self,
        wallet_id: &str,
        events: &[(String, String, String, String, Option<String>)], // (event_type, payload, metadata, source, correlation_id)
    ) -> WalletEventResult<Vec<(u64, u64)>>; // Returns vec of (db_id, sequence_number)

    /// Get event count by type for a wallet
    async fn get_event_count_by_type(
        &self,
        wallet_id: &str,
    ) -> WalletEventResult<std::collections::HashMap<String, u64>>;

    /// Check sequence number continuity for a wallet (detect gaps)
    async fn validate_sequence_continuity(&self, wallet_id: &str) -> WalletEventResult<Vec<u64>>; // Returns missing sequence numbers

    // Enhanced automatic assignment methods for task 4.3

    /// Create a new event with automatic ID, timestamp, and sequence assignment
    /// This is the primary method for creating events with full automation
    async fn create_event(
        &self,
        wallet_id: &str,
        event_type: &str,
        payload_json: String,
        source: &str,
    ) -> WalletEventResult<StoredEvent>;

    /// Create a new event with automatic assignment and optional correlation
    async fn create_event_with_correlation(
        &self,
        wallet_id: &str,
        event_type: &str,
        payload_json: String,
        source: &str,
        correlation_id: String,
    ) -> WalletEventResult<StoredEvent>;

    /// Create multiple events with automatic assignment in a single transaction
    async fn create_events_batch(
        &self,
        wallet_id: &str,
        events: &[(String, String, String)], // (event_type, payload_json, source)
    ) -> WalletEventResult<Vec<StoredEvent>>;

    /// Get the next sequence number that would be assigned for a wallet
    async fn get_next_sequence_number(&self, wallet_id: &str) -> WalletEventResult<u64>;

    /// Validate that a sequence number is available for a wallet
    async fn is_sequence_available(
        &self,
        wallet_id: &str,
        sequence: u64,
    ) -> WalletEventResult<bool>;
}

/// Statistics about event storage
#[cfg(feature = "storage")]
#[derive(Debug, Clone)]
pub struct EventStorageStats {
    /// Total number of events stored
    pub total_events: u64,
    /// Number of unique wallets with events
    pub unique_wallets: u64,
    /// Number of events by type
    pub events_by_type: std::collections::HashMap<String, u64>,
    /// Oldest event timestamp
    pub oldest_event: Option<SystemTime>,
    /// Newest event timestamp
    pub newest_event: Option<SystemTime>,
    /// Storage size in bytes (if available)
    pub storage_size_bytes: Option<u64>,
}

/// SQLite implementation of event storage
#[cfg(feature = "storage")]
pub struct SqliteEventStorage {
    connection: Connection,
}

#[cfg(feature = "storage")]
impl SqliteEventStorage {
    /// Create a new SQLite event storage instance
    pub async fn new(connection: Connection) -> WalletEventResult<Self> {
        let storage = Self { connection };
        storage.initialize().await?;
        Ok(storage)
    }

    /// Create the database schema for events
    async fn create_schema(&self) -> WalletEventResult<()> {
        let sql = r#"
            -- Wallet events table (append-only event log)
            CREATE TABLE IF NOT EXISTS wallet_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                wallet_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                source TEXT NOT NULL,
                correlation_id TEXT,
                timestamp INTEGER NOT NULL, -- Unix timestamp in seconds
                stored_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                
                -- Ensure sequence numbers are unique per wallet
                UNIQUE(wallet_id, sequence_number)
            );

            -- Indexes for efficient querying
            CREATE INDEX IF NOT EXISTS idx_events_wallet_id ON wallet_events(wallet_id);
            CREATE INDEX IF NOT EXISTS idx_events_event_type ON wallet_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_sequence ON wallet_events(wallet_id, sequence_number);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON wallet_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_correlation ON wallet_events(correlation_id);
            CREATE INDEX IF NOT EXISTS idx_events_source ON wallet_events(source);
            CREATE INDEX IF NOT EXISTS idx_events_stored_at ON wallet_events(stored_at);
            
            -- Compound indexes for common query patterns
            CREATE INDEX IF NOT EXISTS idx_events_wallet_type ON wallet_events(wallet_id, event_type);
            CREATE INDEX IF NOT EXISTS idx_events_wallet_time ON wallet_events(wallet_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type_time ON wallet_events(event_type, timestamp);
            
            -- View for easy querying of recent events
            CREATE VIEW IF NOT EXISTS recent_wallet_events AS
            SELECT * FROM wallet_events 
            ORDER BY stored_at DESC 
            LIMIT 1000;

            -- Trigger to ensure append-only behavior (prevent updates/deletes)
            CREATE TRIGGER IF NOT EXISTS prevent_event_updates
            BEFORE UPDATE ON wallet_events
            BEGIN
                SELECT RAISE(ABORT, 'Updates to wallet_events are not allowed - append-only table');
            END;

            CREATE TRIGGER IF NOT EXISTS prevent_event_deletes
            BEFORE DELETE ON wallet_events
            BEGIN
                SELECT RAISE(ABORT, 'Deletes from wallet_events are not allowed - append-only table');
            END;
        "#;

        self.connection
            .call(move |conn| Ok(conn.execute_batch(sql)?))
            .await
            .map_err(|e| {
                WalletEventError::storage(
                    "create_schema",
                    format!("Failed to create event schema: {e}"),
                )
            })?;

        Ok(())
    }

    /// Convert database row to StoredEvent
    fn row_to_stored_event(row: &Row) -> rusqlite::Result<StoredEvent> {
        let timestamp_secs: i64 = row.get("timestamp")?;
        let stored_at_secs: i64 = row.get("stored_at")?;

        let timestamp = UNIX_EPOCH + std::time::Duration::from_secs(timestamp_secs as u64);
        let stored_at = UNIX_EPOCH + std::time::Duration::from_secs(stored_at_secs as u64);

        Ok(StoredEvent {
            id: Some(row.get::<_, i64>("id")? as u64),
            event_id: row.get("event_id")?,
            wallet_id: row.get("wallet_id")?,
            event_type: row.get("event_type")?,
            sequence_number: row.get::<_, i64>("sequence_number")? as u64,
            payload_json: row.get("payload_json")?,
            metadata_json: row.get("metadata_json")?,
            source: row.get("source")?,
            correlation_id: row.get("correlation_id")?,
            timestamp,
            stored_at,
        })
    }

    /// Build WHERE clause and parameters from filter
    fn build_filter_clause(filter: &EventFilter) -> (String, Vec<Box<dyn rusqlite::ToSql + Send>>) {
        let mut conditions = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql + Send>> = Vec::new();

        if let Some(ref wallet_id) = filter.wallet_id {
            conditions.push("wallet_id = ?".to_string());
            params.push(Box::new(wallet_id.clone()));
        }

        if let Some(ref event_type) = filter.event_type {
            conditions.push("event_type = ?".to_string());
            params.push(Box::new(event_type.clone()));
        }

        if let Some((from, to)) = filter.sequence_range {
            conditions.push("sequence_number BETWEEN ? AND ?".to_string());
            params.push(Box::new(from as i64));
            params.push(Box::new(to as i64));
        }

        if let Some((from, to)) = filter.timestamp_range {
            let from_secs = from
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let to_secs = to.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
            conditions.push("timestamp BETWEEN ? AND ?".to_string());
            params.push(Box::new(from_secs));
            params.push(Box::new(to_secs));
        }

        if let Some(ref correlation_id) = filter.correlation_id {
            conditions.push("correlation_id = ?".to_string());
            params.push(Box::new(correlation_id.clone()));
        }

        if let Some(ref source) = filter.source {
            conditions.push("source = ?".to_string());
            params.push(Box::new(source.clone()));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        (where_clause, params)
    }
}

#[cfg(feature = "storage")]
#[async_trait]
impl EventStorage for SqliteEventStorage {
    async fn initialize(&self) -> WalletEventResult<()> {
        self.create_schema().await
    }

    async fn store_event(&self, event: &StoredEvent) -> WalletEventResult<u64> {
        let event_clone = event.clone();
        let timestamp_secs = event_clone
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.connection
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO wallet_events 
                    (event_id, wallet_id, event_type, sequence_number, payload_json, 
                     metadata_json, source, correlation_id, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                    params![
                        event_clone.event_id,
                        event_clone.wallet_id,
                        event_clone.event_type,
                        event_clone.sequence_number as i64,
                        event_clone.payload_json,
                        event_clone.metadata_json,
                        event_clone.source,
                        event_clone.correlation_id,
                        timestamp_secs,
                    ],
                )?;
                Ok(conn.last_insert_rowid() as u64)
            })
            .await
            .map_err(|e| {
                WalletEventError::storage("store_event", format!("Failed to store event: {e}"))
            })
    }

    async fn store_events_batch(&self, events: &[StoredEvent]) -> WalletEventResult<Vec<u64>> {
        if events.is_empty() {
            return Ok(Vec::new());
        }

        let events_clone = events.to_vec();
        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;
                let mut event_ids = Vec::new();

                for event in &events_clone {
                    let timestamp_secs = event
                        .timestamp
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    tx.execute(
                        r#"
                        INSERT INTO wallet_events 
                        (event_id, wallet_id, event_type, sequence_number, payload_json, 
                         metadata_json, source, correlation_id, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        "#,
                        params![
                            event.event_id,
                            event.wallet_id,
                            event.event_type,
                            event.sequence_number as i64,
                            event.payload_json,
                            event.metadata_json,
                            event.source,
                            event.correlation_id,
                            timestamp_secs,
                        ],
                    )?;
                    event_ids.push(tx.last_insert_rowid() as u64);
                }

                tx.commit()?;
                Ok(event_ids)
            })
            .await
            .map_err(|e| {
                WalletEventError::storage(
                    "store_events_batch",
                    format!("Failed to store events batch: {e}"),
                )
            })
    }

    async fn get_events(&self, filter: &EventFilter) -> WalletEventResult<Vec<StoredEvent>> {
        let filter_clone = filter.clone();
        self.connection
            .call(move |conn| {
                let mut base_query = "SELECT * FROM wallet_events".to_string();
                let (where_clause, params) = Self::build_filter_clause(&filter_clone);

                if !where_clause.is_empty() {
                    base_query.push(' ');
                    base_query.push_str(&where_clause);
                }

                // Add ordering
                if filter_clone.order_by_sequence_desc {
                    base_query.push_str(" ORDER BY sequence_number DESC");
                } else {
                    base_query.push_str(" ORDER BY sequence_number ASC");
                }

                // Add limit and offset
                if let Some(limit) = filter_clone.limit {
                    base_query.push_str(&format!(" LIMIT {limit}"));
                }

                if let Some(offset) = filter_clone.offset {
                    base_query.push_str(&format!(" OFFSET {offset}"));
                }

                let mut stmt = conn.prepare(&base_query)?;
                let param_refs: Vec<&dyn rusqlite::ToSql> = params
                    .iter()
                    .map(|p| p.as_ref() as &dyn rusqlite::ToSql)
                    .collect();

                let rows = stmt.query_map(&param_refs[..], Self::row_to_stored_event)?;

                let mut events = Vec::new();
                for row in rows {
                    events.push(row?);
                }

                Ok(events)
            })
            .await
            .map_err(|e| {
                WalletEventError::storage("get_events", format!("Failed to get events: {e}"))
            })
    }

    async fn get_event_by_id(&self, event_id: &str) -> WalletEventResult<Option<StoredEvent>> {
        let event_id_owned = event_id.to_string();
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT * FROM wallet_events WHERE event_id = ?")?;
                let mut rows =
                    stmt.query_map(params![event_id_owned], Self::row_to_stored_event)?;

                if let Some(row) = rows.next() {
                    Ok(Some(row?))
                } else {
                    Ok(None)
                }
            })
            .await
            .map_err(|e| {
                WalletEventError::storage(
                    "get_event_by_id",
                    format!("Failed to get event by ID: {e}"),
                )
            })
    }

    async fn get_latest_sequence(&self, wallet_id: &str) -> WalletEventResult<Option<u64>> {
        let wallet_id_owned = wallet_id.to_string();
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT MAX(sequence_number) FROM wallet_events WHERE wallet_id = ?",
                )?;
                let sequence: Option<i64> =
                    stmt.query_row(params![wallet_id_owned], |row| row.get(0))?;
                Ok(sequence.map(|s| s as u64))
            })
            .await
            .map_err(|e| {
                WalletEventError::storage(
                    "get_latest_sequence",
                    format!("Failed to get latest sequence: {e}"),
                )
            })
    }

    async fn get_event_count(&self, wallet_id: &str) -> WalletEventResult<u64> {
        let wallet_id_owned = wallet_id.to_string();
        self.connection
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT COUNT(*) FROM wallet_events WHERE wallet_id = ?")?;
                let count: i64 = stmt.query_row(params![wallet_id_owned], |row| row.get(0))?;
                Ok(count as u64)
            })
            .await
            .map_err(|e| {
                WalletEventError::storage(
                    "get_event_count",
                    format!("Failed to get event count: {e}"),
                )
            })
    }

    async fn get_events_since_sequence(
        &self,
        wallet_id: &str,
        sequence: u64,
    ) -> WalletEventResult<Vec<StoredEvent>> {
        let filter = EventFilter::new()
            .with_wallet_id(wallet_id.to_string())
            .with_sequence_range(sequence + 1, u64::MAX);

        self.get_events(&filter).await
    }

    async fn event_exists(&self, event_id: &str) -> WalletEventResult<bool> {
        let event_id_owned = event_id.to_string();
        self.connection
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT 1 FROM wallet_events WHERE event_id = ? LIMIT 1")?;
                let exists = stmt.exists(params![event_id_owned])?;
                Ok(exists)
            })
            .await
            .map_err(|e| {
                WalletEventError::storage(
                    "event_exists",
                    format!("Failed to check event existence: {e}"),
                )
            })
    }

    async fn get_storage_stats(&self) -> WalletEventResult<EventStorageStats> {
        self.connection
            .call(|conn| {
                // Get total events and unique wallets
                let mut stmt = conn.prepare(
                    "SELECT COUNT(*) as total, COUNT(DISTINCT wallet_id) as unique_wallets FROM wallet_events",
                )?;
                let (total_events, unique_wallets): (i64, i64) = stmt.query_row([], |row| {
                    Ok((row.get("total")?, row.get("unique_wallets")?))
                })?;

                // Get events by type
                let mut stmt = conn.prepare(
                    "SELECT event_type, COUNT(*) as count FROM wallet_events GROUP BY event_type",
                )?;
                let type_rows = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>("event_type")?, row.get::<_, i64>("count")?))
                })?;

                let mut events_by_type = std::collections::HashMap::new();
                for row in type_rows {
                    let (event_type, count) = row?;
                    events_by_type.insert(event_type, count as u64);
                }

                // Get oldest and newest timestamps
                let mut stmt = conn.prepare(
                    "SELECT MIN(timestamp) as oldest, MAX(timestamp) as newest FROM wallet_events",
                )?;
                let (oldest_secs, newest_secs): (Option<i64>, Option<i64>) = stmt.query_row([], |row| {
                    Ok((row.get("oldest")?, row.get("newest")?))
                })?;

                let oldest_event = oldest_secs.map(|s| UNIX_EPOCH + std::time::Duration::from_secs(s as u64));
                let newest_event = newest_secs.map(|s| UNIX_EPOCH + std::time::Duration::from_secs(s as u64));

                Ok(EventStorageStats {
                    total_events: total_events as u64,
                    unique_wallets: unique_wallets as u64,
                    events_by_type,
                    oldest_event,
                    newest_event,
                    storage_size_bytes: None, // SQLite file size would need additional query
                })
            })
            .await
            .map_err(|e| {
                WalletEventError::storage("get_storage_stats", format!("Failed to get storage stats: {e}"))
            })
    }

    // Implementation of specialized query operations for task 4.2

    async fn get_wallet_events(&self, wallet_id: &str) -> WalletEventResult<Vec<StoredEvent>> {
        let filter = EventFilter::new().with_wallet_id(wallet_id.to_string());
        self.get_events(&filter).await
    }

    async fn get_wallet_events_in_range(
        &self,
        wallet_id: &str,
        from_sequence: u64,
        to_sequence: u64,
    ) -> WalletEventResult<Vec<StoredEvent>> {
        let filter = EventFilter::new()
            .with_wallet_id(wallet_id.to_string())
            .with_sequence_range(from_sequence, to_sequence);
        self.get_events(&filter).await
    }

    async fn get_wallet_events_head(
        &self,
        wallet_id: &str,
        limit: usize,
    ) -> WalletEventResult<Vec<StoredEvent>> {
        let filter = EventFilter::new()
            .with_wallet_id(wallet_id.to_string())
            .with_limit(limit);
        self.get_events(&filter).await
    }

    async fn get_wallet_events_tail(
        &self,
        wallet_id: &str,
        limit: usize,
    ) -> WalletEventResult<Vec<StoredEvent>> {
        let filter = EventFilter::new()
            .with_wallet_id(wallet_id.to_string())
            .with_limit(limit)
            .order_desc();
        self.get_events(&filter).await
    }

    async fn get_events_by_sequences(
        &self,
        wallet_id: &str,
        sequences: &[u64],
    ) -> WalletEventResult<Vec<StoredEvent>> {
        if sequences.is_empty() {
            return Ok(Vec::new());
        }

        let wallet_id_owned = wallet_id.to_string();
        let sequences_owned = sequences.to_vec();

        self.connection
            .call(move |conn| {
                let placeholders = sequences_owned
                    .iter()
                    .map(|_| "?")
                    .collect::<Vec<_>>()
                    .join(", ");
                let query = format!(
                    "SELECT * FROM wallet_events WHERE wallet_id = ? AND sequence_number IN ({}) ORDER BY sequence_number ASC",
                    placeholders
                );

                let mut params: Vec<Box<dyn rusqlite::ToSql + Send>> = Vec::new();
                params.push(Box::new(wallet_id_owned));
                for seq in sequences_owned {
                    params.push(Box::new(seq as i64));
                }

                let mut stmt = conn.prepare(&query)?;
                let param_refs: Vec<&dyn rusqlite::ToSql> = params
                    .iter()
                    .map(|p| p.as_ref() as &dyn rusqlite::ToSql)
                    .collect();

                let rows = stmt.query_map(&param_refs[..], Self::row_to_stored_event)?;

                let mut events = Vec::new();
                for row in rows {
                    events.push(row?);
                }

                Ok(events)
            })
            .await
            .map_err(|e| {
                WalletEventError::storage("get_events_by_sequences", format!("Failed to get events by sequences: {e}"))
            })
    }

    async fn get_event_by_sequence(
        &self,
        wallet_id: &str,
        sequence: u64,
    ) -> WalletEventResult<Option<StoredEvent>> {
        let wallet_id_owned = wallet_id.to_string();
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT * FROM wallet_events WHERE wallet_id = ? AND sequence_number = ?",
                )?;
                let mut rows = stmt.query_map(
                    params![wallet_id_owned, sequence as i64],
                    Self::row_to_stored_event,
                )?;

                if let Some(row) = rows.next() {
                    Ok(Some(row?))
                } else {
                    Ok(None)
                }
            })
            .await
            .map_err(|e| {
                WalletEventError::storage(
                    "get_event_by_sequence",
                    format!("Failed to get event by sequence: {e}"),
                )
            })
    }

    async fn insert_event(
        &self,
        wallet_id: &str,
        event_type: &str,
        payload_json: String,
        metadata_json: String,
        source: &str,
        correlation_id: Option<String>,
    ) -> WalletEventResult<(u64, u64)> {
        let wallet_id_owned = wallet_id.to_string();
        let event_type_owned = event_type.to_string();
        let source_owned = source.to_string();

        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;

                // Get next sequence number
                let sequence_number: u64 = {
                    let mut stmt = tx.prepare(
                        "SELECT COALESCE(MAX(sequence_number), 0) + 1 FROM wallet_events WHERE wallet_id = ?",
                    )?;
                    stmt.query_row(params![&wallet_id_owned], |row| {
                        let seq: i64 = row.get(0)?;
                        Ok(seq as u64)
                    })?
                };

                // Generate event ID
                let event_id = uuid::Uuid::new_v4().to_string();
                let timestamp_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                // Insert event
                tx.execute(
                    r#"
                    INSERT INTO wallet_events 
                    (event_id, wallet_id, event_type, sequence_number, payload_json, 
                     metadata_json, source, correlation_id, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                    params![
                        event_id,
                        wallet_id_owned,
                        event_type_owned,
                        sequence_number as i64,
                        payload_json,
                        metadata_json,
                        source_owned,
                        correlation_id,
                        timestamp_secs,
                    ],
                )?;

                let db_id = tx.last_insert_rowid() as u64;
                tx.commit()?;

                Ok((db_id, sequence_number))
            })
            .await
            .map_err(|e| {
                WalletEventError::storage("insert_event", format!("Failed to insert event: {e}"))
            })
    }

    async fn insert_events_batch(
        &self,
        wallet_id: &str,
        events: &[(String, String, String, String, Option<String>)],
    ) -> WalletEventResult<Vec<(u64, u64)>> {
        if events.is_empty() {
            return Ok(Vec::new());
        }

        let wallet_id_owned = wallet_id.to_string();
        let events_owned = events.to_vec();

        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;
                let mut results = Vec::new();

                // Get current max sequence number
                let mut current_sequence: u64 = {
                    let mut stmt = tx.prepare(
                        "SELECT COALESCE(MAX(sequence_number), 0) FROM wallet_events WHERE wallet_id = ?",
                    )?;
                    stmt.query_row(params![&wallet_id_owned], |row| {
                        let seq: i64 = row.get(0)?;
                        Ok(seq as u64)
                    })?
                };

                for (event_type, payload_json, metadata_json, source, correlation_id) in events_owned {
                    current_sequence += 1;
                    let event_id = uuid::Uuid::new_v4().to_string();
                    let timestamp_secs = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    tx.execute(
                        r#"
                        INSERT INTO wallet_events 
                        (event_id, wallet_id, event_type, sequence_number, payload_json, 
                         metadata_json, source, correlation_id, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        "#,
                        params![
                            event_id,
                            wallet_id_owned,
                            event_type,
                            current_sequence as i64,
                            payload_json,
                            metadata_json,
                            source,
                            correlation_id,
                            timestamp_secs,
                        ],
                    )?;

                    let db_id = tx.last_insert_rowid() as u64;
                    results.push((db_id, current_sequence));
                }

                tx.commit()?;
                Ok(results)
            })
            .await
            .map_err(|e| {
                WalletEventError::storage("insert_events_batch", format!("Failed to insert events batch: {e}"))
            })
    }

    async fn get_event_count_by_type(
        &self,
        wallet_id: &str,
    ) -> WalletEventResult<std::collections::HashMap<String, u64>> {
        let wallet_id_owned = wallet_id.to_string();
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT event_type, COUNT(*) as count FROM wallet_events WHERE wallet_id = ? GROUP BY event_type",
                )?;
                let rows = stmt.query_map(params![wallet_id_owned], |row| {
                    Ok((row.get::<_, String>("event_type")?, row.get::<_, i64>("count")?))
                })?;

                let mut result = std::collections::HashMap::new();
                for row in rows {
                    let (event_type, count) = row?;
                    result.insert(event_type, count as u64);
                }

                Ok(result)
            })
            .await
            .map_err(|e| {
                WalletEventError::storage("get_event_count_by_type", format!("Failed to get event count by type: {e}"))
            })
    }

    async fn validate_sequence_continuity(&self, wallet_id: &str) -> WalletEventResult<Vec<u64>> {
        let wallet_id_owned = wallet_id.to_string();
        self.connection
            .call(move |conn| {
                // Get all sequence numbers for the wallet
                let mut stmt = conn.prepare(
                    "SELECT sequence_number FROM wallet_events WHERE wallet_id = ? ORDER BY sequence_number ASC",
                )?;
                let rows = stmt.query_map(params![wallet_id_owned], |row| {
                    Ok(row.get::<_, i64>("sequence_number")? as u64)
                })?;

                let mut sequences = Vec::new();
                for row in rows {
                    sequences.push(row?);
                }

                // Find missing sequence numbers
                let mut missing = Vec::new();
                if !sequences.is_empty() {
                    for expected in 1..=sequences[sequences.len() - 1] {
                        if !sequences.contains(&expected) {
                            missing.push(expected);
                        }
                    }
                }

                Ok(missing)
            })
            .await
            .map_err(|e| {
                WalletEventError::storage("validate_sequence_continuity", format!("Failed to validate sequence continuity: {e}"))
            })
    }

    // Enhanced automatic assignment methods implementation for task 4.3

    async fn create_event(
        &self,
        wallet_id: &str,
        event_type: &str,
        payload_json: String,
        source: &str,
    ) -> WalletEventResult<StoredEvent> {
        let wallet_id_owned = wallet_id.to_string();
        let event_type_owned = event_type.to_string();
        let source_owned = source.to_string();

        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;

                // Get next sequence number atomically
                let sequence_number: u64 = {
                    let mut stmt = tx.prepare(
                        "SELECT COALESCE(MAX(sequence_number), 0) + 1 FROM wallet_events WHERE wallet_id = ?",
                    )?;
                    stmt.query_row(params![&wallet_id_owned], |row| {
                        let seq: i64 = row.get(0)?;
                        Ok(seq as u64)
                    })?
                };

                // Generate automatic values
                let event_id = uuid::Uuid::new_v4().to_string();
                let timestamp = SystemTime::now();
                let timestamp_secs = timestamp
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                // Create basic metadata automatically
                let metadata_json = serde_json::json!({
                    "created_at": timestamp_secs,
                    "auto_generated": true,
                    "wallet_id": wallet_id_owned,
                    "sequence": sequence_number
                }).to_string();

                // Insert event
                tx.execute(
                    r#"
                    INSERT INTO wallet_events 
                    (event_id, wallet_id, event_type, sequence_number, payload_json, 
                     metadata_json, source, correlation_id, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                    params![
                        event_id,
                        wallet_id_owned,
                        event_type_owned,
                        sequence_number as i64,
                        payload_json,
                        metadata_json,
                        source_owned,
                        None::<String>, // No correlation_id for basic create
                        timestamp_secs,
                    ],
                )?;

                let db_id = tx.last_insert_rowid() as u64;
                tx.commit()?;

                // Return the created event
                Ok(StoredEvent {
                    id: Some(db_id),
                    event_id,
                    wallet_id: wallet_id_owned,
                    event_type: event_type_owned,
                    sequence_number,
                    payload_json,
                    metadata_json,
                    source: source_owned,
                    correlation_id: None,
                    timestamp,
                    stored_at: SystemTime::now(), // Approximate, DB will have exact value
                })
            })
            .await
            .map_err(|e| {
                WalletEventError::storage("create_event", format!("Failed to create event: {e}"))
            })
    }

    async fn create_event_with_correlation(
        &self,
        wallet_id: &str,
        event_type: &str,
        payload_json: String,
        source: &str,
        correlation_id: String,
    ) -> WalletEventResult<StoredEvent> {
        let wallet_id_owned = wallet_id.to_string();
        let event_type_owned = event_type.to_string();
        let source_owned = source.to_string();

        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;

                // Get next sequence number atomically
                let sequence_number: u64 = {
                    let mut stmt = tx.prepare(
                        "SELECT COALESCE(MAX(sequence_number), 0) + 1 FROM wallet_events WHERE wallet_id = ?",
                    )?;
                    stmt.query_row(params![&wallet_id_owned], |row| {
                        let seq: i64 = row.get(0)?;
                        Ok(seq as u64)
                    })?
                };

                // Generate automatic values
                let event_id = uuid::Uuid::new_v4().to_string();
                let timestamp = SystemTime::now();
                let timestamp_secs = timestamp
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                // Create enhanced metadata with correlation info
                let metadata_json = serde_json::json!({
                    "created_at": timestamp_secs,
                    "auto_generated": true,
                    "wallet_id": wallet_id_owned,
                    "sequence": sequence_number,
                    "correlation_id": correlation_id
                }).to_string();

                // Insert event
                tx.execute(
                    r#"
                    INSERT INTO wallet_events 
                    (event_id, wallet_id, event_type, sequence_number, payload_json, 
                     metadata_json, source, correlation_id, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                    params![
                        event_id,
                        wallet_id_owned,
                        event_type_owned,
                        sequence_number as i64,
                        payload_json,
                        metadata_json,
                        source_owned,
                        Some(correlation_id.clone()),
                        timestamp_secs,
                    ],
                )?;

                let db_id = tx.last_insert_rowid() as u64;
                tx.commit()?;

                // Return the created event
                Ok(StoredEvent {
                    id: Some(db_id),
                    event_id,
                    wallet_id: wallet_id_owned,
                    event_type: event_type_owned,
                    sequence_number,
                    payload_json,
                    metadata_json,
                    source: source_owned,
                    correlation_id: Some(correlation_id),
                    timestamp,
                    stored_at: SystemTime::now(), // Approximate, DB will have exact value
                })
            })
            .await
            .map_err(|e| {
                WalletEventError::storage("create_event_with_correlation", format!("Failed to create event with correlation: {e}"))
            })
    }

    async fn create_events_batch(
        &self,
        wallet_id: &str,
        events: &[(String, String, String)], // (event_type, payload_json, source)
    ) -> WalletEventResult<Vec<StoredEvent>> {
        if events.is_empty() {
            return Ok(Vec::new());
        }

        let wallet_id_owned = wallet_id.to_string();
        let events_owned = events.to_vec();

        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;
                let mut results = Vec::new();

                // Get current max sequence number
                let mut current_sequence: u64 = {
                    let mut stmt = tx.prepare(
                        "SELECT COALESCE(MAX(sequence_number), 0) FROM wallet_events WHERE wallet_id = ?",
                    )?;
                    stmt.query_row(params![&wallet_id_owned], |row| {
                        let seq: i64 = row.get(0)?;
                        Ok(seq as u64)
                    })?
                };

                let batch_timestamp = SystemTime::now();
                let batch_timestamp_secs = batch_timestamp
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                for (event_type, payload_json, source) in events_owned {
                    current_sequence += 1;
                    let event_id = uuid::Uuid::new_v4().to_string();

                    // Create metadata for each event in batch
                    let metadata_json = serde_json::json!({
                        "created_at": batch_timestamp_secs,
                        "auto_generated": true,
                        "wallet_id": wallet_id_owned,
                        "sequence": current_sequence,
                        "batch_operation": true
                    }).to_string();

                    tx.execute(
                        r#"
                        INSERT INTO wallet_events 
                        (event_id, wallet_id, event_type, sequence_number, payload_json, 
                         metadata_json, source, correlation_id, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        "#,
                        params![
                            event_id,
                            wallet_id_owned,
                            event_type,
                            current_sequence as i64,
                            payload_json,
                            metadata_json,
                            source,
                            None::<String>, // No correlation for batch operations
                            batch_timestamp_secs,
                        ],
                    )?;

                    let db_id = tx.last_insert_rowid() as u64;
                    results.push(StoredEvent {
                        id: Some(db_id),
                        event_id,
                        wallet_id: wallet_id_owned.clone(),
                        event_type,
                        sequence_number: current_sequence,
                        payload_json,
                        metadata_json,
                        source,
                        correlation_id: None,
                        timestamp: batch_timestamp,
                        stored_at: SystemTime::now(), // Approximate, DB will have exact value
                    });
                }

                tx.commit()?;
                Ok(results)
            })
            .await
            .map_err(|e| {
                WalletEventError::storage("create_events_batch", format!("Failed to create events batch: {e}"))
            })
    }

    async fn get_next_sequence_number(&self, wallet_id: &str) -> WalletEventResult<u64> {
        let wallet_id_owned = wallet_id.to_string();
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT COALESCE(MAX(sequence_number), 0) + 1 FROM wallet_events WHERE wallet_id = ?",
                )?;
                let sequence: i64 = stmt.query_row(params![wallet_id_owned], |row| row.get(0))?;
                Ok(sequence as u64)
            })
            .await
            .map_err(|e| {
                WalletEventError::storage("get_next_sequence_number", format!("Failed to get next sequence number: {e}"))
            })
    }

    async fn is_sequence_available(
        &self,
        wallet_id: &str,
        sequence: u64,
    ) -> WalletEventResult<bool> {
        let wallet_id_owned = wallet_id.to_string();
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT 1 FROM wallet_events WHERE wallet_id = ? AND sequence_number = ? LIMIT 1",
                )?;
                let exists = stmt.exists(params![wallet_id_owned, sequence as i64])?;
                Ok(!exists) // Available if it doesn't exist
            })
            .await
            .map_err(|e| {
                WalletEventError::storage("is_sequence_available", format!("Failed to check sequence availability: {e}"))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[tokio::test]
    async fn test_stored_event_creation() {
        let event = StoredEvent::new(
            "test-event-id".to_string(),
            "test-wallet-id".to_string(),
            "UTXO_RECEIVED".to_string(),
            1,
            "{}".to_string(),
            "{}".to_string(),
            "test-source".to_string(),
            Some("correlation-123".to_string()),
            SystemTime::now(),
        );

        assert_eq!(event.event_id, "test-event-id");
        assert_eq!(event.wallet_id, "test-wallet-id");
        assert_eq!(event.event_type, "UTXO_RECEIVED");
        assert_eq!(event.sequence_number, 1);
        assert!(event.correlation_id.is_some());
    }

    #[test]
    fn test_event_filter_builder() {
        let filter = EventFilter::new()
            .with_wallet_id("wallet-123".to_string())
            .with_event_type("UTXO_RECEIVED".to_string())
            .with_limit(10)
            .order_desc();

        assert_eq!(filter.wallet_id, Some("wallet-123".to_string()));
        assert_eq!(filter.event_type, Some("UTXO_RECEIVED".to_string()));
        assert_eq!(filter.limit, Some(10));
        assert!(filter.order_by_sequence_desc);
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_sqlite_event_storage_creation() {
        use tokio_rusqlite::Connection;

        let conn = Connection::open(":memory:").await.unwrap();
        let storage = SqliteEventStorage::new(conn).await.unwrap();

        // Schema should be created successfully
        let stats = storage.get_storage_stats().await.unwrap();
        assert_eq!(stats.total_events, 0);
        assert_eq!(stats.unique_wallets, 0);
    }
}
