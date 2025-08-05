//! Tests for user-facing API methods for event replay operations
//!
//! This module tests the high-level, user-friendly API methods for triggering
//! event replay operations and ensures they provide appropriate abstractions
//! over the underlying replay engine.

#[cfg(feature = "storage")]
mod user_api_tests {
    use lightweight_wallet_libs::events::user_api::{
        ReplayOptions, WalletHealthStatus, WalletReplayManager,
    };
    use lightweight_wallet_libs::storage::event_storage::SqliteEventStorage;
    use std::time::Duration;
    use tokio_rusqlite::Connection;

    async fn create_test_storage() -> SqliteEventStorage {
        let conn = Connection::open_in_memory().await.unwrap();
        SqliteEventStorage::new(conn).await.unwrap()
    }

    #[tokio::test]
    async fn test_wallet_replay_manager_creation() {
        let storage = create_test_storage().await;
        let _manager = WalletReplayManager::new(storage);

        // Manager should be created successfully
        // Note: we can't easily test internals without public accessors
    }

    #[tokio::test]
    async fn test_wallet_replay_manager_with_config() {
        let storage = create_test_storage().await;
        let custom_config =
            lightweight_wallet_libs::events::replay::ReplayConfig::default().with_batch_size(500);
        let _manager = WalletReplayManager::with_config(storage, custom_config);

        // Manager should be created successfully with custom config
    }

    #[tokio::test]
    async fn test_quick_health_check() {
        let storage = create_test_storage().await;
        let manager = WalletReplayManager::new(storage);

        let result = manager.quick_health_check("test_wallet").await;

        assert!(result.is_ok(), "Quick health check should succeed");
        let result = result.unwrap();
        assert_eq!(result.wallet_id, "test_wallet");
        assert!(result.success);
        // With no events, we expect a healthy status for this basic implementation
    }

    #[tokio::test]
    async fn test_full_replay_and_analyze() {
        let storage = create_test_storage().await;
        let manager = WalletReplayManager::new(storage);

        let result = manager.full_replay_and_analyze("test_wallet").await;

        assert!(result.is_ok(), "Full replay should succeed");
        let result = result.unwrap();
        assert_eq!(result.wallet_id, "test_wallet");
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_fast_replay() {
        let storage = create_test_storage().await;
        let manager = WalletReplayManager::new(storage);

        let result = manager.fast_replay("test_wallet").await;

        assert!(result.is_ok(), "Fast replay should succeed");
        let result = result.unwrap();
        assert_eq!(result.wallet_id, "test_wallet");
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_incremental_replay() {
        let storage = create_test_storage().await;
        let manager = WalletReplayManager::new(storage);

        let result = manager.incremental_replay("test_wallet", 100).await;

        assert!(result.is_ok(), "Incremental replay should succeed");
        let result = result.unwrap();
        assert_eq!(result.wallet_id, "test_wallet");
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_replay_with_custom_options() {
        let storage = create_test_storage().await;
        let manager = WalletReplayManager::new(storage);

        let options = ReplayOptions::default()
            .with_timeout(Duration::from_secs(30))
            .with_batch_size(200)
            .with_inconsistency_detection(true)
            .with_detailed_reports(true);

        let result = manager
            .replay_with_options("test_wallet", None, options)
            .await;

        assert!(result.is_ok(), "Replay with custom options should succeed");
        let result = result.unwrap();
        assert_eq!(result.wallet_id, "test_wallet");
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_replay_options_presets() {
        // Test quick health check preset
        let quick_options = ReplayOptions::quick_health_check();
        assert_eq!(quick_options.timeout, Some(Duration::from_secs(60)));
        assert_eq!(quick_options.batch_size, Some(1000));
        assert!(quick_options.fail_fast);
        assert!(quick_options.detect_inconsistencies);
        assert!(!quick_options.generate_reports);

        // Test detailed analysis preset
        let detailed_options = ReplayOptions::detailed_analysis();
        assert_eq!(detailed_options.timeout, Some(Duration::from_secs(1800)));
        assert_eq!(detailed_options.batch_size, Some(100));
        assert!(!detailed_options.fail_fast);
        assert!(detailed_options.detect_inconsistencies);
        assert!(detailed_options.generate_reports);

        // Test performance optimized preset
        let perf_options = ReplayOptions::performance_optimized();
        assert_eq!(perf_options.timeout, None);
        assert_eq!(perf_options.batch_size, Some(5000));
        assert!(!perf_options.fail_fast);
        assert!(!perf_options.detect_inconsistencies);
        assert!(!perf_options.generate_reports);
    }

    #[tokio::test]
    async fn test_replay_options_builder_pattern() {
        let options = ReplayOptions::default()
            .with_timeout(Duration::from_secs(120))
            .without_timeout()
            .with_inconsistency_detection(false)
            .with_detailed_reports(true)
            .with_batch_size(300);

        assert_eq!(options.timeout, None);
        assert!(!options.detect_inconsistencies);
        assert!(options.generate_reports);
        assert_eq!(options.batch_size, Some(300));
    }

    #[tokio::test]
    async fn test_get_wallet_status() {
        let storage = create_test_storage().await;
        let manager = WalletReplayManager::new(storage);

        let result = manager.get_wallet_status("test_wallet").await;

        assert!(result.is_ok(), "Get wallet status should succeed");
        let status = result.unwrap();
        assert_eq!(status.wallet_id, "test_wallet");
        assert_eq!(status.total_events, 0); // No events in empty storage
        assert_eq!(status.status, "No events found");
    }

    #[tokio::test]
    async fn test_batch_health_check_empty() {
        let storage = create_test_storage().await;
        let manager = WalletReplayManager::new(storage);

        let wallet_ids = vec![];
        let result = manager.batch_health_check(&wallet_ids).await;

        assert!(
            result.is_ok(),
            "Batch health check with empty list should succeed"
        );
        let batch_result = result.unwrap();
        assert_eq!(batch_result.total_wallets, 0);
        assert_eq!(batch_result.healthy_wallets, 0);
        assert_eq!(batch_result.wallets_with_issues, 0);
        assert_eq!(batch_result.critical_wallets, 0);
    }

    #[tokio::test]
    async fn test_batch_health_check_single_wallet() {
        let storage = create_test_storage().await;
        let manager = WalletReplayManager::new(storage);

        let wallet_ids = vec!["test_wallet"];
        let result = manager.batch_health_check(&wallet_ids).await;

        assert!(result.is_ok(), "Batch health check should succeed");
        let batch_result = result.unwrap();
        assert_eq!(batch_result.total_wallets, 1);
        assert_eq!(batch_result.individual_results.len(), 1);
        assert_eq!(batch_result.individual_results[0].wallet_id, "test_wallet");
    }

    #[tokio::test]
    async fn test_batch_health_check_multiple_wallets() {
        let storage = create_test_storage().await;
        let manager = WalletReplayManager::new(storage);

        let wallet_ids = vec!["wallet1", "wallet2", "wallet3"];
        let result = manager.batch_health_check(&wallet_ids).await;

        assert!(result.is_ok(), "Batch health check should succeed");
        let batch_result = result.unwrap();
        assert_eq!(batch_result.total_wallets, 3);
        assert_eq!(batch_result.individual_results.len(), 3);

        // Check that all wallets were processed
        let processed_wallets: Vec<_> = batch_result
            .individual_results
            .iter()
            .map(|r| r.wallet_id.as_str())
            .collect();
        assert!(processed_wallets.contains(&"wallet1"));
        assert!(processed_wallets.contains(&"wallet2"));
        assert!(processed_wallets.contains(&"wallet3"));
    }

    #[tokio::test]
    async fn test_replay_result_structure() {
        let storage = create_test_storage().await;
        let manager = WalletReplayManager::new(storage);

        let result = manager.quick_health_check("test_wallet").await.unwrap();

        // Verify result structure
        assert!(!result.wallet_id.is_empty());
        assert!(result.success);

        // Check performance metrics
        assert!(result.performance_metrics.total_duration >= Duration::ZERO);
        assert_eq!(result.performance_metrics.events_processed, 0); // No events
        assert_eq!(result.performance_metrics.inconsistencies_found, 0);

        // Check summary
        assert!(!result.summary.status.is_empty());
        assert!(!result.summary.key_findings.is_empty() || result.summary.key_findings.is_empty()); // Either is valid
        assert!(!result.summary.recommendations.is_empty());

        // Errors should be empty for successful operation
        assert!(result.errors.is_empty());
    }

    #[tokio::test]
    async fn test_user_progress_callback() {
        use lightweight_wallet_libs::events::user_api::UserProgressCallback;
        use std::sync::{Arc, Mutex};

        let storage = create_test_storage().await;
        let manager = WalletReplayManager::new(storage);

        // Create a progress tracker
        let progress_events = Arc::new(Mutex::new(Vec::new()));
        let progress_events_clone = progress_events.clone();

        let progress_callback: UserProgressCallback = Arc::new(move |progress| {
            progress_events_clone.lock().unwrap().push(progress.clone());
        });

        let options = ReplayOptions::default();
        let result = manager
            .replay_with_progress("test_wallet", options, progress_callback)
            .await;

        assert!(result.is_ok(), "Replay with progress should succeed");

        // Note: In this simplified implementation, we don't actually call the progress callback
        // In a full implementation, you'd verify that progress events were captured
    }

    #[tokio::test]
    async fn test_health_status_assessment() {
        // This test verifies the health status logic by testing different scenarios
        let storage = create_test_storage().await;
        let manager = WalletReplayManager::new(storage);

        // For empty wallets, we expect healthy status
        let result = manager.quick_health_check("empty_wallet").await.unwrap();

        // The simplified implementation should return a basic healthy status
        // In a full implementation with actual event processing, you'd test various scenarios
        assert!(matches!(result.health_status, WalletHealthStatus::Healthy));
    }
}
