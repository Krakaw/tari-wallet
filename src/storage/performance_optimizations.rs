//! SQLite performance optimizations for high-throughput scanning
//!
//! This module provides performance optimizations specifically designed for the
//! wallet scanner's high-throughput database write scenarios.

#[cfg(feature = "storage")]
use crate::errors::WalletResult;
#[cfg(feature = "storage")]
use tokio_rusqlite::Connection;

/// High-performance SQLite configuration for wallet scanning
#[cfg(feature = "storage")]
pub struct SqlitePerformanceConfig {
    /// Enable WAL (Write-Ahead Logging) mode for better concurrency
    pub enable_wal_mode: bool,
    /// Set synchronous mode (0=OFF, 1=NORMAL, 2=FULL)
    pub synchronous_mode: u8,
    /// Cache size in KB (negative values are in pages)
    pub cache_size_kb: i32,
    /// Page size in bytes (4096, 8192, 16384, 32768, 65536)
    pub page_size: u32,
    /// Temporary storage mode (0=default, 1=file, 2=memory)
    pub temp_store: u8,
    /// Journal size limit in bytes
    pub journal_size_limit: u64,
    /// Memory map size in bytes (0 = disabled)
    pub mmap_size: u64,
    /// Busy timeout in milliseconds
    pub busy_timeout_ms: u32,
    /// Enable automatic index creation (DANGEROUS for production - can create suboptimal indexes)
    pub enable_automatic_index: bool,
}

#[cfg(feature = "storage")]
impl Default for SqlitePerformanceConfig {
    fn default() -> Self {
        Self::production_optimized() // Safe default for production use
    }
}

#[cfg(feature = "storage")]
impl SqlitePerformanceConfig {
    /// Conservative performance settings for general use
    pub fn conservative() -> Self {
        Self {
            enable_wal_mode: true,
            synchronous_mode: 2,   // FULL - maximum safety
            cache_size_kb: 32_000, // 32MB
            page_size: 4096,
            temp_store: 2,                        // Memory
            journal_size_limit: 64 * 1024 * 1024, // 64MB
            mmap_size: 128 * 1024 * 1024,         // 128MB
            busy_timeout_ms: 5000,
            enable_automatic_index: false, // Disabled for predictable performance
        }
    }

    /// High-performance settings optimized for scanning operations
    /// WARNING: Uses synchronous=OFF which can cause data corruption on system crashes
    /// Only use when data can be regenerated or for non-critical operations
    pub fn high_performance() -> Self {
        Self {
            enable_wal_mode: true,
            synchronous_mode: 0,                   // OFF - fastest, but UNSAFE
            cache_size_kb: 128_000,                // 128MB cache
            page_size: 8192,                       // Larger pages for better I/O
            temp_store: 2,                         // Memory temp storage
            journal_size_limit: 256 * 1024 * 1024, // 256MB
            mmap_size: 512 * 1024 * 1024,          // 512MB memory mapping
            busy_timeout_ms: 10000,
            enable_automatic_index: false, // Disabled for predictable performance
        }
    }

    /// Ultra-fast settings for development/testing (data safety compromised)
    /// DANGER: This configuration sacrifices data integrity for maximum speed
    /// Never use with important data - database corruption possible on crashes
    pub fn ultra_fast() -> Self {
        Self {
            enable_wal_mode: true,
            synchronous_mode: 0,                   // OFF - EXTREMELY UNSAFE
            cache_size_kb: 256_000,                // 256MB cache
            page_size: 16384,                      // Large pages
            temp_store: 2,                         // Memory
            journal_size_limit: 512 * 1024 * 1024, // 512MB
            mmap_size: 1024 * 1024 * 1024,         // 1GB memory mapping
            busy_timeout_ms: 15000,
            enable_automatic_index: true, // Enabled for development convenience
        }
    }

    /// Production-safe high performance settings
    pub fn production_optimized() -> Self {
        Self {
            enable_wal_mode: true,
            synchronous_mode: 1,   // NORMAL - good balance of speed and safety
            cache_size_kb: 64_000, // 64MB cache
            page_size: 8192,       // Good for bulk operations
            temp_store: 2,         // Memory temp storage
            journal_size_limit: 128 * 1024 * 1024, // 128MB
            mmap_size: 256 * 1024 * 1024, // 256MB memory mapping
            busy_timeout_ms: 8000,
            enable_automatic_index: false, // Disabled for predictable performance
        }
    }

    /// Apply performance configuration to SQLite connection
    pub async fn apply_to_connection(&self, connection: &Connection) -> WalletResult<()> {
        // Enable WAL mode for better concurrency (use pragma_update for settings)
        if self.enable_wal_mode {
            connection
                .call(|conn| {
                    conn.pragma_update(None, "journal_mode", "WAL")?;
                    Ok(())
                })
                .await
                .map_err(|e| {
                    crate::WalletError::StorageError(format!("Failed to enable WAL mode: {e}"))
                })?;
        }

        // Set synchronous mode (accepts values, use pragma_update)
        connection
            .call({
                let sync_mode = self.synchronous_mode;
                move |conn| {
                    conn.pragma_update(None, "synchronous", sync_mode)?;
                    Ok(())
                }
            })
            .await
            .map_err(|e| {
                crate::WalletError::StorageError(format!("Failed to set synchronous mode: {e}"))
            })?;

        // Set cache size (negative values = KB directly, positive = pages)
        connection
            .call({
                let cache_size = -self.cache_size_kb; // Negative = KB directly
                move |conn| {
                    conn.pragma_update(None, "cache_size", cache_size)?;
                    Ok(())
                }
            })
            .await
            .map_err(|e| {
                crate::WalletError::StorageError(format!("Failed to set cache size: {e}"))
            })?;

        // Set page size (must be done before any tables are created)
        connection
            .call({
                let page_size = self.page_size;
                move |conn| {
                    conn.pragma_update(None, "page_size", page_size)?;
                    Ok(())
                }
            })
            .await
            .map_err(|e| {
                crate::WalletError::StorageError(format!("Failed to set page size: {e}"))
            })?;

        // Set temp store mode
        connection
            .call({
                let temp_store = self.temp_store;
                move |conn| {
                    conn.pragma_update(None, "temp_store", temp_store)?;
                    Ok(())
                }
            })
            .await
            .map_err(|e| {
                crate::WalletError::StorageError(format!("Failed to set temp store: {e}"))
            })?;

        // Set journal size limit
        connection
            .call({
                let journal_limit = self.journal_size_limit;
                move |conn| {
                    conn.pragma_update(None, "journal_size_limit", journal_limit as i64)?;
                    Ok(())
                }
            })
            .await
            .map_err(|e| {
                crate::WalletError::StorageError(format!("Failed to set journal size limit: {e}"))
            })?;

        // Set memory mapping size
        if self.mmap_size > 0 {
            connection
                .call({
                    let mmap_size = self.mmap_size;
                    move |conn| {
                        conn.pragma_update(None, "mmap_size", mmap_size as i64)?;
                        Ok(())
                    }
                })
                .await
                .map_err(|e| {
                    crate::WalletError::StorageError(format!("Failed to set mmap size: {e}"))
                })?;
        }

        // Set busy timeout
        connection
            .call({
                let timeout = self.busy_timeout_ms;
                move |conn| {
                    conn.pragma_update(None, "busy_timeout", timeout)?;
                    Ok(())
                }
            })
            .await
            .map_err(|e| {
                crate::WalletError::StorageError(format!("Failed to set busy timeout: {e}"))
            })?;

        Ok(())
    }

    /// Get recommended batch size based on configuration
    pub fn recommended_batch_size(&self) -> usize {
        match self.synchronous_mode {
            0 => 200, // OFF mode can handle larger batches
            1 => 100, // NORMAL mode moderate batches
            _ => 50,  // FULL mode smaller batches
        }
    }

    /// Check if configuration is suitable for production
    pub fn is_production_safe(&self) -> bool {
        // Synchronous OFF mode is not safe for production
        self.synchronous_mode > 0
    }

    /// Apply additional optimizations for scanning workloads
    pub async fn apply_scanning_optimizations(&self, connection: &Connection) -> WalletResult<()> {
        let enable_auto_index = self.enable_automatic_index;

        // Optimize for write-heavy workloads
        connection
            .call(move |conn| {
                // Reduce checkpoint frequency for better write performance (use pragma_update)
                conn.pragma_update(None, "wal_autocheckpoint", 10000)?;

                // Optimize query planner for large datasets (this one uses execute)
                conn.execute("PRAGMA optimize", [])?;

                // Enable automatic index creation if configured (DANGEROUS for production)
                if enable_auto_index {
                    conn.pragma_update(None, "automatic_index", "ON")?;
                }

                Ok(())
            })
            .await
            .map_err(|e| {
                crate::WalletError::StorageError(format!(
                    "Failed to apply scanning optimizations: {e}"
                ))
            })?;

        Ok(())
    }
}

/// Batch operation utilities for high-performance database writes
#[cfg(feature = "storage")]
pub struct BatchOperations;

#[cfg(feature = "storage")]
impl BatchOperations {
    /// Calculate optimal batch size based on system resources and data size
    pub fn calculate_optimal_batch_size(
        avg_item_size_bytes: usize,
        available_memory_mb: usize,
        target_memory_usage_percent: f32,
    ) -> usize {
        let target_memory_bytes =
            (available_memory_mb * 1024 * 1024) as f32 * target_memory_usage_percent;
        let batch_size = (target_memory_bytes / avg_item_size_bytes as f32) as usize;

        // Constrain to reasonable bounds
        batch_size.clamp(10, 1000)
    }

    /// Recommend batch configuration for different workload types
    pub fn recommend_batch_config(workload_type: &str) -> (usize, SqlitePerformanceConfig) {
        match workload_type {
            "scanning" => (100, SqlitePerformanceConfig::production_optimized()), // Safe for production use
            "production" => (75, SqlitePerformanceConfig::production_optimized()),
            "development" => (200, SqlitePerformanceConfig::ultra_fast()),
            "high_performance" => (150, SqlitePerformanceConfig::high_performance()), // Explicit unsafe mode
            "conservative" => (50, SqlitePerformanceConfig::conservative()),
            _ => (100, SqlitePerformanceConfig::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_config_presets() {
        let conservative = SqlitePerformanceConfig::conservative();
        assert_eq!(conservative.synchronous_mode, 2); // FULL mode for maximum safety
        assert!(conservative.is_production_safe());

        let high_perf = SqlitePerformanceConfig::high_performance();
        assert_eq!(high_perf.synchronous_mode, 0);
        assert!(!high_perf.is_production_safe());

        let production = SqlitePerformanceConfig::production_optimized();
        assert_eq!(production.synchronous_mode, 1);
        assert!(production.is_production_safe());
    }

    #[test]
    fn test_batch_size_calculations() {
        // Test reasonable batch size calculation
        let batch_size = BatchOperations::calculate_optimal_batch_size(
            1024, // 1KB per item
            100,  // 100MB available
            0.1,  // Use 10% of memory
        );
        assert!((10..=1000).contains(&batch_size));

        // Test edge cases - very large items with small memory should hit minimum
        let small_batch = BatchOperations::calculate_optimal_batch_size(100000, 1, 0.1);
        assert_eq!(small_batch, 10); // Should be minimum

        let large_batch = BatchOperations::calculate_optimal_batch_size(1, 1000, 0.9);
        assert_eq!(large_batch, 1000); // Should be maximum
    }

    #[test]
    fn test_workload_recommendations() {
        let (batch_size, config) = BatchOperations::recommend_batch_config("scanning");
        assert_eq!(batch_size, 100);
        assert_eq!(config.synchronous_mode, 1); // Now uses production_optimized (safe)
        assert!(config.is_production_safe());

        let (batch_size, config) = BatchOperations::recommend_batch_config("production");
        assert_eq!(batch_size, 75);
        assert!(config.is_production_safe());

        let (batch_size, config) = BatchOperations::recommend_batch_config("high_performance");
        assert_eq!(batch_size, 150);
        assert_eq!(config.synchronous_mode, 0); // Explicit unsafe mode
        assert!(!config.is_production_safe());
    }
}
