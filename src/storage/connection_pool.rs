//! Connection pooling for SQLite event storage
//!
//! This module provides connection pooling capabilities for high-throughput
//! event storage scenarios. Connection pooling helps manage concurrent database
//! access and improves performance under load.

#[cfg(feature = "storage")]
use crate::events::types::{WalletEventError, WalletEventResult};
#[cfg(feature = "storage")]
use std::sync::Arc;
#[cfg(feature = "storage")]
use std::time::Duration;
#[cfg(feature = "storage")]
use tokio::sync::{Mutex, Semaphore};
#[cfg(feature = "storage")]
use tokio::time::timeout;
#[cfg(feature = "storage")]
use tokio_rusqlite::Connection;

/// Configuration for SQLite connection pool
#[cfg(feature = "storage")]
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    /// Maximum number of connections in the pool
    pub max_connections: usize,
    /// Minimum number of connections to maintain
    pub min_connections: usize,
    /// Timeout for acquiring a connection from the pool
    pub connection_timeout: Duration,
    /// Timeout for individual database operations
    pub operation_timeout: Duration,
    /// Database file path
    pub database_path: String,
    /// SQLite connection options
    pub sqlite_options: SqliteConnectionOptions,
}

/// SQLite connection configuration options
#[cfg(feature = "storage")]
#[derive(Debug, Clone)]
pub struct SqliteConnectionOptions {
    /// Enable WAL (Write-Ahead Logging) mode for better concurrency
    pub enable_wal_mode: bool,
    /// Set synchronous mode (OFF, NORMAL, FULL)
    pub synchronous_mode: SynchronousMode,
    /// Set journal mode
    pub journal_mode: JournalMode,
    /// Cache size in KB
    pub cache_size_kb: i64,
    /// Busy timeout in milliseconds
    pub busy_timeout_ms: u32,
    /// Enable foreign key constraints
    pub enable_foreign_keys: bool,
}

/// SQLite synchronous mode options
#[cfg(feature = "storage")]
#[derive(Debug, Clone)]
pub enum SynchronousMode {
    /// No sync - fastest but least safe
    Off,
    /// Normal sync - balanced
    Normal,
    /// Full sync - slowest but safest
    Full,
}

/// SQLite journal mode options
#[cfg(feature = "storage")]
#[derive(Debug, Clone)]
pub enum JournalMode {
    /// Delete journal files after transactions
    Delete,
    /// Write-Ahead Logging for better concurrency
    Wal,
    /// Memory-based journaling
    Memory,
}

#[cfg(feature = "storage")]
impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            min_connections: 2,
            connection_timeout: Duration::from_secs(30),
            operation_timeout: Duration::from_secs(60),
            database_path: "wallet_events.db".to_string(),
            sqlite_options: SqliteConnectionOptions::default(),
        }
    }
}

#[cfg(feature = "storage")]
impl Default for SqliteConnectionOptions {
    fn default() -> Self {
        Self {
            enable_wal_mode: true,
            synchronous_mode: SynchronousMode::Normal,
            journal_mode: JournalMode::Wal,
            cache_size_kb: 4096,    // 4MB cache
            busy_timeout_ms: 30000, // 30 seconds
            enable_foreign_keys: true,
        }
    }
}

#[cfg(feature = "storage")]
impl SqliteConnectionOptions {
    /// Create high-performance configuration for event storage workloads
    pub fn high_performance() -> Self {
        Self {
            enable_wal_mode: true,
            synchronous_mode: SynchronousMode::Normal,
            journal_mode: JournalMode::Wal,
            cache_size_kb: 8192,    // 8MB cache
            busy_timeout_ms: 60000, // 60 seconds
            enable_foreign_keys: true,
        }
    }

    /// Create configuration optimized for safety over performance
    pub fn high_safety() -> Self {
        Self {
            enable_wal_mode: false,
            synchronous_mode: SynchronousMode::Full,
            journal_mode: JournalMode::Delete,
            cache_size_kb: 2048,    // 2MB cache
            busy_timeout_ms: 30000, // 30 seconds
            enable_foreign_keys: true,
        }
    }
}

/// A connection wrapper that tracks usage statistics
#[cfg(feature = "storage")]
#[derive(Debug)]
struct PooledConnection {
    connection: Connection,
    #[allow(dead_code)]
    created_at: std::time::Instant,
    last_used: std::time::Instant,
    use_count: u64,
}

#[cfg(feature = "storage")]
impl PooledConnection {
    async fn new(
        database_path: &str,
        options: &SqliteConnectionOptions,
    ) -> WalletEventResult<Self> {
        let connection = Connection::open(database_path).await.map_err(|e| {
            WalletEventError::storage("connection_pool", format!("Failed to open database: {e}"))
        })?;

        // Configure the connection with the specified options
        Self::configure_connection(&connection, options).await?;

        Ok(Self {
            connection,
            created_at: std::time::Instant::now(),
            last_used: std::time::Instant::now(),
            use_count: 0,
        })
    }

    async fn configure_connection(
        connection: &Connection,
        options: &SqliteConnectionOptions,
    ) -> WalletEventResult<()> {
        let options_clone = options.clone();
        connection
            .call(move |conn| {
                // Set synchronous mode - this returns the new synchronous mode
                let sync_mode = match options_clone.synchronous_mode {
                    SynchronousMode::Off => "OFF",
                    SynchronousMode::Normal => "NORMAL",
                    SynchronousMode::Full => "FULL",
                };
                let mut stmt = conn.prepare(&format!("PRAGMA synchronous = {sync_mode}"))?;
                let _rows: Vec<rusqlite::Result<_>> = stmt.query_map([], |_| Ok(()))?.collect();

                // Set journal mode - this returns the new journal mode so we need to consume the result
                let journal_mode = match options_clone.journal_mode {
                    JournalMode::Delete => "DELETE",
                    JournalMode::Wal => "WAL",
                    JournalMode::Memory => "MEMORY",
                };
                let mut stmt = conn.prepare(&format!("PRAGMA journal_mode = {journal_mode}"))?;
                let _rows: Vec<rusqlite::Result<_>> = stmt.query_map([], |_| Ok(()))?.collect();

                // Set cache size (negative value means KB) - this returns the new cache size
                let mut stmt = conn.prepare(&format!(
                    "PRAGMA cache_size = -{}",
                    options_clone.cache_size_kb
                ))?;
                let _rows: Vec<rusqlite::Result<_>> = stmt.query_map([], |_| Ok(()))?.collect();

                // Set busy timeout - this returns the new timeout value
                let mut stmt = conn.prepare(&format!(
                    "PRAGMA busy_timeout = {}",
                    options_clone.busy_timeout_ms
                ))?;
                let _rows: Vec<rusqlite::Result<_>> = stmt.query_map([], |_| Ok(()))?.collect();

                // Enable/disable foreign keys - this returns the new foreign key setting
                let fk_setting = if options_clone.enable_foreign_keys {
                    "ON"
                } else {
                    "OFF"
                };
                let mut stmt = conn.prepare(&format!("PRAGMA foreign_keys = {fk_setting}"))?;
                let _rows: Vec<rusqlite::Result<_>> = stmt.query_map([], |_| Ok(()))?.collect();

                // Additional WAL mode optimizations
                if options_clone.enable_wal_mode {
                    // Set WAL autocheckpoint for better performance - this returns the new autocheckpoint value
                    let mut stmt = conn.prepare("PRAGMA wal_autocheckpoint = 1000")?;
                    let _rows: Vec<rusqlite::Result<_>> = stmt.query_map([], |_| Ok(()))?.collect();
                    // Perform WAL checkpoint - this returns results so we need to consume them
                    let mut stmt = conn.prepare("PRAGMA wal_checkpoint(TRUNCATE)")?;
                    let _rows: Vec<rusqlite::Result<_>> = stmt.query_map([], |_| Ok(()))?.collect();
                }

                Ok(())
            })
            .await
            .map_err(|e| {
                WalletEventError::storage(
                    "connection_config",
                    format!("Failed to configure connection: {e}"),
                )
            })?;

        Ok(())
    }

    fn mark_used(&mut self) {
        self.last_used = std::time::Instant::now();
        self.use_count += 1;
    }

    #[allow(dead_code)]
    fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    #[allow(dead_code)]
    fn idle_time(&self) -> Duration {
        self.last_used.elapsed()
    }
}

/// Statistics about connection pool usage
#[cfg(feature = "storage")]
#[derive(Debug, Clone)]
pub struct ConnectionPoolStats {
    /// Current number of connections in the pool
    pub active_connections: usize,
    /// Number of connections currently in use
    pub connections_in_use: usize,
    /// Total number of connection acquisitions
    pub total_acquisitions: u64,
    /// Total number of connection timeouts
    pub timeout_count: u64,
    /// Average connection acquisition time
    pub avg_acquisition_time: Duration,
    /// Peak number of connections
    pub peak_connections: usize,
}

/// Connection pool for SQLite event storage
#[cfg(feature = "storage")]
#[derive(Clone)]
pub struct ConnectionPool {
    config: ConnectionPoolConfig,
    connections: Arc<Mutex<Vec<PooledConnection>>>,
    semaphore: Arc<Semaphore>,
    stats: Arc<Mutex<ConnectionPoolStats>>,
}

#[cfg(feature = "storage")]
impl ConnectionPool {
    /// Create a new connection pool with the given configuration
    pub async fn new(config: ConnectionPoolConfig) -> WalletEventResult<Self> {
        let pool = Self {
            semaphore: Arc::new(Semaphore::new(config.max_connections)),
            connections: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(Mutex::new(ConnectionPoolStats {
                active_connections: 0,
                connections_in_use: 0,
                total_acquisitions: 0,
                timeout_count: 0,
                avg_acquisition_time: Duration::ZERO,
                peak_connections: 0,
            })),
            config,
        };

        // Pre-populate with minimum connections
        pool.ensure_min_connections().await?;

        Ok(pool)
    }

    /// Create a connection pool with default configuration
    pub async fn with_database_path(database_path: String) -> WalletEventResult<Self> {
        let config = ConnectionPoolConfig {
            database_path,
            ..ConnectionPoolConfig::default()
        };
        Self::new(config).await
    }

    /// Create a high-performance connection pool
    pub async fn high_performance(database_path: String) -> WalletEventResult<Self> {
        let config = ConnectionPoolConfig {
            database_path,
            max_connections: 20,
            min_connections: 5,
            sqlite_options: SqliteConnectionOptions::high_performance(),
            ..ConnectionPoolConfig::default()
        };
        Self::new(config).await
    }

    /// Acquire a connection from the pool
    pub async fn acquire(&self) -> WalletEventResult<PooledConnectionGuard> {
        let start_time = std::time::Instant::now();

        // Wait for an available slot in the semaphore
        let permit = timeout(
            self.config.connection_timeout,
            self.semaphore.clone().acquire_owned(),
        )
        .await
        .map_err(|_| {
            // Update timeout statistics
            let mut stats = futures::executor::block_on(self.stats.lock());
            stats.timeout_count += 1;
            drop(stats);

            WalletEventError::storage(
                "connection_pool",
                "Timeout waiting for available connection",
            )
        })?
        .map_err(|_| {
            WalletEventError::storage("connection_pool", "Connection pool semaphore closed")
        })?;

        // Try to get an existing connection or create a new one
        let mut connections = self.connections.lock().await;
        let connection = if let Some(mut conn) = connections.pop() {
            conn.mark_used();
            conn
        } else {
            // Create a new connection
            PooledConnection::new(&self.config.database_path, &self.config.sqlite_options).await?
        };

        // Update statistics
        let acquisition_time = start_time.elapsed();
        let mut stats = self.stats.lock().await;
        stats.total_acquisitions += 1;
        stats.connections_in_use += 1;
        stats.avg_acquisition_time = if stats.total_acquisitions == 1 {
            acquisition_time
        } else {
            (stats.avg_acquisition_time + acquisition_time) / 2
        };
        drop(stats);

        Ok(PooledConnectionGuard {
            connection: Some(connection),
            pool: self,
            permit,
        })
    }

    /// Return a connection to the pool
    async fn return_connection(&self, mut connection: PooledConnection) {
        let mut connections = self.connections.lock().await;

        // Update usage tracking
        connection.mark_used();

        // Only return to pool if we haven't exceeded max connections
        if connections.len() < self.config.max_connections {
            connections.push(connection);
        }
        // Otherwise, let the connection drop (it will be closed)

        // Update statistics
        let mut stats = self.stats.lock().await;
        stats.connections_in_use = stats.connections_in_use.saturating_sub(1);
        stats.active_connections = connections.len();
        stats.peak_connections = stats.peak_connections.max(connections.len());
    }

    /// Ensure minimum connections are available in the pool
    async fn ensure_min_connections(&self) -> WalletEventResult<()> {
        let mut connections = self.connections.lock().await;

        while connections.len() < self.config.min_connections {
            let connection =
                PooledConnection::new(&self.config.database_path, &self.config.sqlite_options)
                    .await?;
            connections.push(connection);
        }

        // Update statistics
        let mut stats = self.stats.lock().await;
        stats.active_connections = connections.len();
        stats.peak_connections = stats.peak_connections.max(connections.len());

        Ok(())
    }

    /// Get current pool statistics
    pub async fn get_stats(&self) -> ConnectionPoolStats {
        self.stats.lock().await.clone()
    }

    /// Get pool configuration
    pub fn get_config(&self) -> &ConnectionPoolConfig {
        &self.config
    }

    /// Close all connections in the pool
    pub async fn close(&self) {
        let mut connections = self.connections.lock().await;
        connections.clear(); // This will drop all connections

        let mut stats = self.stats.lock().await;
        stats.active_connections = 0;
        stats.connections_in_use = 0;
    }
}

/// RAII guard for pooled connections
#[cfg(feature = "storage")]
pub struct PooledConnectionGuard<'a> {
    connection: Option<PooledConnection>,
    pool: &'a ConnectionPool,
    #[allow(dead_code)]
    permit: tokio::sync::OwnedSemaphorePermit,
}

#[cfg(feature = "storage")]
impl<'a> PooledConnectionGuard<'a> {
    /// Get a reference to the underlying connection
    pub fn connection(&self) -> &Connection {
        &self.connection.as_ref().unwrap().connection
    }

    /// Execute an operation with timeout
    pub async fn execute_with_timeout<F, R>(&self, operation: F) -> WalletEventResult<R>
    where
        F: std::future::Future<Output = Result<R, tokio_rusqlite::Error>>,
    {
        timeout(self.pool.config.operation_timeout, operation)
            .await
            .map_err(|_| {
                WalletEventError::storage("connection_pool", "Database operation timeout")
            })?
            .map_err(|e| {
                WalletEventError::storage(
                    "connection_pool",
                    format!("Database operation failed: {e}"),
                )
            })
    }
}

#[cfg(feature = "storage")]
impl<'a> Drop for PooledConnectionGuard<'a> {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            // Clone the pool for the async operation
            let pool = self.pool.clone();

            // Return the connection to the pool asynchronously
            tokio::spawn(async move {
                pool.return_connection(connection).await;
            });
        }
        // Permit is automatically returned when dropped
    }
}

#[cfg(feature = "storage")]
impl std::fmt::Display for SynchronousMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SynchronousMode::Off => write!(f, "OFF"),
            SynchronousMode::Normal => write!(f, "NORMAL"),
            SynchronousMode::Full => write!(f, "FULL"),
        }
    }
}

#[cfg(feature = "storage")]
impl std::fmt::Display for JournalMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalMode::Delete => write!(f, "DELETE"),
            JournalMode::Wal => write!(f, "WAL"),
            JournalMode::Memory => write!(f, "MEMORY"),
        }
    }
}

#[cfg(feature = "storage")]
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_connection_pool_creation() {
        let temp_file = NamedTempFile::new().unwrap();
        let database_path = temp_file.path().to_string_lossy().to_string();

        // Use configuration without WAL mode to avoid potential test issues
        let config = ConnectionPoolConfig {
            database_path,
            sqlite_options: SqliteConnectionOptions {
                enable_wal_mode: false,
                journal_mode: JournalMode::Memory,
                ..SqliteConnectionOptions::default()
            },
            ..ConnectionPoolConfig::default()
        };
        let pool = ConnectionPool::new(config).await.unwrap();
        let stats = pool.get_stats().await;

        assert_eq!(stats.active_connections, 2); // Default min_connections
        assert_eq!(stats.connections_in_use, 0);
        assert_eq!(stats.total_acquisitions, 0);
    }

    #[tokio::test]
    async fn test_connection_acquisition_and_return() {
        let temp_file = NamedTempFile::new().unwrap();
        let database_path = temp_file.path().to_string_lossy().to_string();

        let pool = ConnectionPool::with_database_path(database_path)
            .await
            .unwrap();

        {
            let conn = pool.acquire().await.unwrap();
            let stats = pool.get_stats().await;
            assert_eq!(stats.connections_in_use, 1);

            // Use the connection
            let _connection = conn.connection();
        } // Connection should be returned here

        // Give a moment for the async return to complete
        tokio::time::sleep(Duration::from_millis(10)).await;

        let stats = pool.get_stats().await;
        assert_eq!(stats.connections_in_use, 0);
        assert_eq!(stats.total_acquisitions, 1);
    }

    #[tokio::test]
    async fn test_concurrent_connections() {
        let temp_file = NamedTempFile::new().unwrap();
        let database_path = temp_file.path().to_string_lossy().to_string();

        let pool = Arc::new(
            ConnectionPool::with_database_path(database_path)
                .await
                .unwrap(),
        );

        let mut handles = Vec::new();

        // Spawn multiple concurrent tasks that acquire connections
        for _ in 0..5 {
            let pool_clone = pool.clone();
            let handle = tokio::spawn(async move {
                let _conn = pool_clone.acquire().await.unwrap();
                // Simulate some work
                tokio::time::sleep(Duration::from_millis(100)).await;
                // Connection is returned when dropped
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Give a moment for async returns to complete
        tokio::time::sleep(Duration::from_millis(50)).await;

        let stats = pool.get_stats().await;
        assert_eq!(stats.connections_in_use, 0);
        assert_eq!(stats.total_acquisitions, 5);
    }

    #[tokio::test]
    async fn test_high_performance_config() {
        let temp_file = NamedTempFile::new().unwrap();
        let database_path = temp_file.path().to_string_lossy().to_string();

        let pool = ConnectionPool::high_performance(database_path)
            .await
            .unwrap();
        let config = pool.get_config();

        assert_eq!(config.max_connections, 20);
        assert_eq!(config.min_connections, 5);
        assert!(config.sqlite_options.enable_wal_mode);
        assert_eq!(config.sqlite_options.cache_size_kb, 8192);
    }
}
