//! Tests for inconsistency detection functionality in event replay system
//!
//! This module tests the ability to detect various types of inconsistencies
//! in replayed wallet state and generate detailed reports.

#[cfg(feature = "storage")]
mod inconsistency_detection_tests {
    use lightweight_wallet_libs::events::replay::{
        EventReplayEngine, InconsistencySeverity, InconsistencyType, ReplayConfig,
        ReplayedWalletState, RiskLevel, SpentUtxoState, StateReliability, UtxoState,
    };
    use lightweight_wallet_libs::storage::event_storage::SqliteEventStorage;
    use std::collections::HashMap;
    use std::time::SystemTime;
    use tokio_rusqlite::Connection;

    /// Create a test replayed wallet state with various inconsistencies
    fn create_inconsistent_wallet_state() -> ReplayedWalletState {
        let mut utxos = HashMap::new();
        let mut spent_utxos = HashMap::new();

        // Create a normal UTXO
        let normal_utxo = UtxoState {
            utxo_id: "utxo_1".to_string(),
            amount: 1000,
            block_height: 100,
            transaction_hash: "tx_hash_1".to_string(),
            output_index: 0,
            receiving_address: "address_1".to_string(),
            key_index: 1,
            commitment: "commitment_1".to_string(),
            received_at: SystemTime::now(),
            is_mature: true,
            maturity_height: Some(95),
        };
        utxos.insert("utxo_1".to_string(), normal_utxo);

        // Create a UTXO with ID mismatch (inconsistency)
        let mismatched_utxo = UtxoState {
            utxo_id: "utxo_2_different".to_string(), // Different from HashMap key
            amount: 2000,
            block_height: 110,
            transaction_hash: "tx_hash_2".to_string(),
            output_index: 0,
            receiving_address: "address_2".to_string(),
            key_index: 2,
            commitment: "commitment_2".to_string(),
            received_at: SystemTime::now(),
            is_mature: true,
            maturity_height: None,
        };
        utxos.insert("utxo_2".to_string(), mismatched_utxo);

        // Create a UTXO with zero value (inconsistency)
        let zero_value_utxo = UtxoState {
            utxo_id: "utxo_3".to_string(),
            amount: 0, // Zero value inconsistency
            block_height: 120,
            transaction_hash: "tx_hash_3".to_string(),
            output_index: 0,
            receiving_address: "address_3".to_string(),
            key_index: 3,
            commitment: "commitment_3".to_string(),
            received_at: SystemTime::now(),
            is_mature: true,
            maturity_height: None,
        };
        utxos.insert("utxo_3".to_string(), zero_value_utxo);

        // Create a UTXO with maturity inconsistency
        let immature_utxo = UtxoState {
            utxo_id: "utxo_4".to_string(),
            amount: 3000,
            block_height: 50, // Block height less than maturity height
            transaction_hash: "tx_hash_4".to_string(),
            output_index: 0,
            receiving_address: "address_4".to_string(),
            key_index: 4,
            commitment: "commitment_4".to_string(),
            received_at: SystemTime::now(),
            is_mature: true, // But marked as mature (inconsistency)
            maturity_height: Some(100),
        };
        utxos.insert("utxo_4".to_string(), immature_utxo);

        // Create a UTXO with empty fields (inconsistency)
        let empty_fields_utxo = UtxoState {
            utxo_id: "utxo_5".to_string(),
            amount: 1500,
            block_height: 130,
            transaction_hash: "".to_string(), // Empty transaction hash
            output_index: 0,
            receiving_address: "address_5".to_string(),
            key_index: 5,
            commitment: "".to_string(), // Empty commitment
            received_at: SystemTime::now(),
            is_mature: true,
            maturity_height: None,
        };
        utxos.insert("utxo_5".to_string(), empty_fields_utxo);

        // Create a spent UTXO with temporal inconsistency
        let original_utxo = UtxoState {
            utxo_id: "spent_utxo_1".to_string(),
            amount: 5000,
            block_height: 200,
            transaction_hash: "spent_tx_1".to_string(),
            output_index: 0,
            receiving_address: "spent_address_1".to_string(),
            key_index: 10,
            commitment: "spent_commitment_1".to_string(),
            received_at: SystemTime::now(),
            is_mature: true,
            maturity_height: None,
        };

        let spent_utxo = SpentUtxoState {
            original_utxo,
            spent_at: SystemTime::now() - std::time::Duration::from_secs(3600), // Spent before received
            spent_block_height: 190, // Spent at lower block height than received
            spending_transaction_hash: "spending_tx_1".to_string(),
        };
        spent_utxos.insert("spent_utxo_1".to_string(), spent_utxo);

        // Create a UTXO that exists in both collections (critical inconsistency)
        let duplicate_utxo_original = UtxoState {
            utxo_id: "duplicate_utxo".to_string(),
            amount: 4000,
            block_height: 150,
            transaction_hash: "dup_tx".to_string(),
            output_index: 0,
            receiving_address: "dup_address".to_string(),
            key_index: 15,
            commitment: "dup_commitment".to_string(),
            received_at: SystemTime::now(),
            is_mature: true,
            maturity_height: None,
        };

        let duplicate_utxo_spent = SpentUtxoState {
            original_utxo: duplicate_utxo_original.clone(),
            spent_at: SystemTime::now(),
            spent_block_height: 160,
            spending_transaction_hash: "dup_spending_tx".to_string(),
        };

        // Add to both collections (inconsistency)
        utxos.insert("duplicate_utxo".to_string(), duplicate_utxo_original);
        spent_utxos.insert("duplicate_utxo".to_string(), duplicate_utxo_spent);

        ReplayedWalletState {
            wallet_id: "test_wallet".to_string(),
            utxos,
            spent_utxos,
            total_balance: 999999, // Wrong balance (should be sum of UTXOs)
            transaction_count: 10,
            highest_block: 200,
            last_sequence: 50,
            last_updated: SystemTime::now(),
        }
    }

    async fn create_test_storage() -> SqliteEventStorage {
        let conn = Connection::open_in_memory().await.unwrap();
        SqliteEventStorage::new(conn).await.unwrap()
    }

    #[tokio::test]
    async fn test_detect_internal_inconsistencies() {
        let storage = create_test_storage().await;
        let config = ReplayConfig::default();
        let engine = EventReplayEngine::new(storage, config);

        let inconsistent_state = create_inconsistent_wallet_state();
        let report = engine
            .detect_inconsistencies(&inconsistent_state)
            .await
            .unwrap();

        // Should detect UTXO ID mismatch
        let internal_issues: Vec<_> = report
            .inconsistencies
            .iter()
            .filter(|i| matches!(i.issue_type, InconsistencyType::InternalStateInconsistency))
            .collect();

        assert!(
            !internal_issues.is_empty(),
            "Should detect internal state inconsistencies"
        );

        // Should find the ID mismatch for utxo_2
        let id_mismatch = internal_issues.iter().find(|i| {
            i.description.contains("utxo_2") && i.description.contains("utxo_2_different")
        });
        assert!(id_mismatch.is_some(), "Should detect UTXO ID mismatch");
    }

    #[tokio::test]
    async fn test_detect_logical_inconsistencies() {
        let storage = create_test_storage().await;
        let config = ReplayConfig::default();
        let engine = EventReplayEngine::new(storage, config);

        let inconsistent_state = create_inconsistent_wallet_state();
        let report = engine
            .detect_inconsistencies(&inconsistent_state)
            .await
            .unwrap();

        // Should detect logical inconsistencies
        let logical_issues: Vec<_> = report
            .inconsistencies
            .iter()
            .filter(|i| matches!(i.issue_type, InconsistencyType::LogicalInconsistency))
            .collect();

        assert!(
            !logical_issues.is_empty(),
            "Should detect logical inconsistencies"
        );

        // Should detect zero-value UTXO
        let zero_value = logical_issues
            .iter()
            .find(|i| i.description.contains("zero value"));
        assert!(zero_value.is_some(), "Should detect zero-value UTXO");

        // Should detect maturity inconsistency
        let maturity_issue = logical_issues.iter().find(|i| {
            i.description.contains("mature") && i.description.contains("maturity height")
        });
        assert!(
            maturity_issue.is_some(),
            "Should detect maturity inconsistency"
        );

        // Should detect duplicate UTXO across collections
        let duplicate_issue = logical_issues
            .iter()
            .find(|i| i.description.contains("both unspent and spent"));
        assert!(duplicate_issue.is_some(), "Should detect duplicate UTXO");

        // The duplicate issue should be critical
        if let Some(issue) = duplicate_issue {
            assert!(matches!(issue.severity, InconsistencySeverity::Critical));
        }
    }

    #[tokio::test]
    async fn test_detect_temporal_inconsistencies() {
        let storage = create_test_storage().await;
        let config = ReplayConfig::default();
        let engine = EventReplayEngine::new(storage, config);

        let inconsistent_state = create_inconsistent_wallet_state();
        let report = engine
            .detect_inconsistencies(&inconsistent_state)
            .await
            .unwrap();

        // Should detect temporal inconsistencies
        let temporal_issues: Vec<_> = report
            .inconsistencies
            .iter()
            .filter(|i| matches!(i.issue_type, InconsistencyType::TemporalInconsistency))
            .collect();

        assert!(
            !temporal_issues.is_empty(),
            "Should detect temporal inconsistencies"
        );

        // Should detect spent before received issue
        let spent_before_received = temporal_issues
            .iter()
            .find(|i| i.description.contains("spent before it was received"));
        assert!(
            spent_before_received.is_some(),
            "Should detect spent-before-received"
        );

        // Should detect block height inconsistency
        let block_height_issue = temporal_issues
            .iter()
            .find(|i| i.description.contains("before it was confirmed"));
        assert!(
            block_height_issue.is_some(),
            "Should detect block height inconsistency"
        );
    }

    #[tokio::test]
    async fn test_detect_balance_inconsistencies() {
        let storage = create_test_storage().await;
        let config = ReplayConfig::default();
        let engine = EventReplayEngine::new(storage, config);

        let inconsistent_state = create_inconsistent_wallet_state();
        let report = engine
            .detect_inconsistencies(&inconsistent_state)
            .await
            .unwrap();

        // Should detect balance inconsistencies
        let balance_issues: Vec<_> = report
            .inconsistencies
            .iter()
            .filter(|i| matches!(i.issue_type, InconsistencyType::BalanceInconsistency))
            .collect();

        assert!(
            !balance_issues.is_empty(),
            "Should detect balance inconsistencies"
        );

        // Should detect balance mismatch
        let balance_mismatch = balance_issues
            .iter()
            .find(|i| i.description.contains("Total balance mismatch"));
        assert!(balance_mismatch.is_some(), "Should detect balance mismatch");

        // Balance mismatch should be critical
        if let Some(issue) = balance_mismatch {
            assert!(matches!(issue.severity, InconsistencySeverity::Critical));
        }
    }

    #[tokio::test]
    async fn test_detect_utxo_state_inconsistencies() {
        let storage = create_test_storage().await;
        let config = ReplayConfig::default();
        let engine = EventReplayEngine::new(storage, config);

        let inconsistent_state = create_inconsistent_wallet_state();
        let report = engine
            .detect_inconsistencies(&inconsistent_state)
            .await
            .unwrap();

        // Should detect UTXO state inconsistencies
        let utxo_state_issues: Vec<_> = report
            .inconsistencies
            .iter()
            .filter(|i| matches!(i.issue_type, InconsistencyType::UtxoStateInconsistency))
            .collect();

        assert!(
            !utxo_state_issues.is_empty(),
            "Should detect UTXO state inconsistencies"
        );

        // Should detect empty transaction hash
        let empty_tx_hash = utxo_state_issues
            .iter()
            .find(|i| i.description.contains("empty transaction hash"));
        assert!(
            empty_tx_hash.is_some(),
            "Should detect empty transaction hash"
        );

        // Should detect empty commitment
        let empty_commitment = utxo_state_issues
            .iter()
            .find(|i| i.description.contains("empty commitment"));
        assert!(empty_commitment.is_some(), "Should detect empty commitment");
    }

    #[tokio::test]
    async fn test_severity_summary() {
        let storage = create_test_storage().await;
        let config = ReplayConfig::default();
        let engine = EventReplayEngine::new(storage, config);

        let inconsistent_state = create_inconsistent_wallet_state();
        let report = engine
            .detect_inconsistencies(&inconsistent_state)
            .await
            .unwrap();

        // Should have multiple severity levels
        assert!(
            report.severity_summary.critical_count > 0,
            "Should have critical issues"
        );
        assert!(
            report.severity_summary.major_count > 0,
            "Should have major issues"
        );
        assert!(
            report.severity_summary.minor_count > 0,
            "Should have minor issues"
        );

        // Overall risk should be high due to critical issues
        assert!(matches!(
            report.severity_summary.overall_risk,
            RiskLevel::High
        ));

        // State should be unreliable due to critical issues
        assert!(matches!(
            report.severity_summary.state_reliability,
            StateReliability::Unreliable
        ));
    }

    #[tokio::test]
    async fn test_generate_detailed_report() {
        let storage = create_test_storage().await;
        let config = ReplayConfig::default();
        let engine = EventReplayEngine::new(storage, config);

        let inconsistent_state = create_inconsistent_wallet_state();
        let report = engine
            .detect_inconsistencies(&inconsistent_state)
            .await
            .unwrap();

        let detailed_report = engine.generate_detailed_report(&report);

        // Should contain key sections
        assert!(detailed_report.contains("# Wallet Event Replay Inconsistency Report"));
        assert!(detailed_report.contains("## Risk Assessment"));
        assert!(detailed_report.contains("## Issue Severity Breakdown"));
        assert!(detailed_report.contains("## Replayed State Summary"));
        assert!(detailed_report.contains("## Detailed Issues"));
        assert!(detailed_report.contains("## Recommendations"));

        // Should contain specific inconsistency types
        assert!(detailed_report.contains("InternalStateInconsistency"));
        assert!(detailed_report.contains("LogicalInconsistency"));
        assert!(detailed_report.contains("TemporalInconsistency"));
        assert!(detailed_report.contains("BalanceInconsistency"));
        assert!(detailed_report.contains("UtxoStateInconsistency"));

        // Should indicate high risk due to critical issues
        assert!(detailed_report.contains("IMMEDIATE ACTION REQUIRED"));
    }

    #[tokio::test]
    async fn test_clean_state_detection() {
        let storage = create_test_storage().await;
        let config = ReplayConfig::default();
        let engine = EventReplayEngine::new(storage, config);

        // Create a clean, consistent state
        let mut clean_utxos = HashMap::new();
        let clean_utxo = UtxoState {
            utxo_id: "clean_utxo_1".to_string(),
            amount: 1000,
            block_height: 100,
            transaction_hash: "clean_tx_1".to_string(),
            output_index: 0,
            receiving_address: "clean_address_1".to_string(),
            key_index: 1,
            commitment: "clean_commitment_1".to_string(),
            received_at: SystemTime::now(),
            is_mature: true,
            maturity_height: Some(95),
        };
        clean_utxos.insert("clean_utxo_1".to_string(), clean_utxo);

        let clean_state = ReplayedWalletState {
            wallet_id: "clean_wallet".to_string(),
            utxos: clean_utxos,
            spent_utxos: HashMap::new(),
            total_balance: 1000, // Correct balance
            transaction_count: 1,
            highest_block: 100,
            last_sequence: 1,
            last_updated: SystemTime::now(),
        };

        let report = engine.detect_inconsistencies(&clean_state).await.unwrap();

        // Should have no issues
        assert_eq!(report.total_issues, 0, "Clean state should have no issues");
        assert_eq!(report.severity_summary.critical_count, 0);
        assert_eq!(report.severity_summary.major_count, 0);
        assert_eq!(report.severity_summary.minor_count, 0);
        assert!(matches!(
            report.severity_summary.overall_risk,
            RiskLevel::None
        ));
        assert!(matches!(
            report.severity_summary.state_reliability,
            StateReliability::Reliable
        ));

        let detailed_report = engine.generate_detailed_report(&report);
        assert!(detailed_report.contains("No Issues Found"));
        assert!(detailed_report.contains("ALL CLEAR"));
    }
}
