//! Integration test examples demonstrating event capture functionality
//!
//! This module provides complete examples showing how to use the event capture
//! and assertion utilities for testing event-driven wallet scanning code.

#[cfg(test)]
mod integration_examples {
    use crate::events::{
        listeners::MockEventListener,
        types::{ScanConfig, WalletScanEvent},
        EventCapture, EventDispatcher, EventPattern, PerformanceAssertion, TestScenario,
    };
    use std::time::Duration;

    /// Example: Basic event capture and assertion
    #[tokio::test]
    async fn example_basic_event_capture() {
        // Set up event dispatcher with mock listener
        let mut dispatcher = EventDispatcher::new_with_debug();
        let mock = MockEventListener::builder().testing_preset().build();

        dispatcher.register(Box::new(mock)).unwrap();

        // Simulate a scanning workflow
        let scan_started = WalletScanEvent::scan_started(
            ScanConfig::default().with_batch_size(10),
            (0, 100),
            "test_wallet".to_string(),
        );
        dispatcher.dispatch(scan_started).await;

        let block_processed = WalletScanEvent::block_processed(
            1,
            "0x123abc".to_string(),
            1697123456,
            Duration::from_millis(100),
            5,
        );
        dispatcher.dispatch(block_processed).await;

        let scan_completed = WalletScanEvent::scan_completed(
            std::collections::HashMap::from([
                ("blocks_processed".to_string(), 100),
                ("outputs_found".to_string(), 5),
            ]),
            true,
            Duration::from_secs(10),
        );
        dispatcher.dispatch(scan_completed).await;

        // Use assertion macros for clean testing
        let listeners = dispatcher.listeners.iter().collect::<Vec<_>>();
        if let Some(_listener) = listeners.first() {
            // Note: In real usage, you'd have a reference to your mock
            // For this example, we'll create a new mock to demonstrate the API
            let test_mock = MockEventListener::new();
            let captured_events = test_mock.get_captured_events();

            // Simulate the events being captured
            captured_events.lock().unwrap().extend(vec![
                crate::events::listeners::mock_listener::CapturedEvent::new(
                    "ScanStarted".to_string(),
                    Some("batch_size: 10".to_string()),
                    "id1".to_string(),
                    "wallet_scanner".to_string(),
                    None,
                ),
                crate::events::listeners::mock_listener::CapturedEvent::new(
                    "BlockProcessed".to_string(),
                    Some("height: 1".to_string()),
                    "id2".to_string(),
                    "wallet_scanner".to_string(),
                    Some(Duration::from_millis(100)),
                ),
                crate::events::listeners::mock_listener::CapturedEvent::new(
                    "ScanCompleted".to_string(),
                    Some("success: true".to_string()),
                    "id3".to_string(),
                    "wallet_scanner".to_string(),
                    None,
                ),
            ]);

            // Demonstrate assertions
            assert!(test_mock.assert_event_count(3).is_ok());
            assert!(test_mock.assert_event_type_count("ScanStarted", 1).is_ok());
            assert!(test_mock
                .assert_event_type_count("BlockProcessed", 1)
                .is_ok());
            assert!(test_mock
                .assert_event_type_count("ScanCompleted", 1)
                .is_ok());
            assert!(test_mock.assert_first_event_type("ScanStarted").is_ok());
            assert!(test_mock.assert_last_event_type("ScanCompleted").is_ok());
            assert!(test_mock
                .assert_contains_event_with_content("batch_size: 10")
                .is_ok());
        }
    }

    /// Example: Advanced pattern matching for complex event sequences
    #[tokio::test]
    async fn example_advanced_pattern_matching() {
        let mock = MockEventListener::new();
        let captured_events = mock.get_captured_events();

        // Simulate a complex scanning sequence
        captured_events.lock().unwrap().extend(vec![
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "ScanStarted".to_string(),
                Some("test_wallet".to_string()),
                "id1".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "BlockProcessed".to_string(),
                None,
                "id2".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "BlockProcessed".to_string(),
                None,
                "id3".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "OutputFound".to_string(),
                Some("amount: 1000".to_string()),
                "id4".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "ScanCompleted".to_string(),
                None,
                "id5".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
        ]);

        // Define a pattern for successful scan with outputs
        let pattern = EventPattern::sequence()
            .starts_with("ScanStarted")
            .followed_by_any_number_of("BlockProcessed")
            .contains("OutputFound")
            .ends_with("ScanCompleted")
            .with_content_matching("test_wallet")
            .min_events(4);

        // Verify the pattern matches
        assert!(pattern.verify(&mock).is_ok());

        // Test a pattern that should fail
        let bad_pattern = EventPattern::sequence().starts_with("ScanError").exactly(5);

        assert!(bad_pattern.verify(&mock).is_err());
    }

    /// Example: Performance testing with assertions
    #[tokio::test]
    async fn example_performance_testing() {
        let mock = MockEventListener::builder().include_timing(true).build();

        // Simulate events with timing information
        let captured_events = mock.get_captured_events();
        captured_events.lock().unwrap().extend(vec![
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "BlockProcessed".to_string(),
                None,
                "id1".to_string(),
                "wallet_scanner".to_string(),
                Some(Duration::from_millis(50)),
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "BlockProcessed".to_string(),
                None,
                "id2".to_string(),
                "wallet_scanner".to_string(),
                Some(Duration::from_millis(75)),
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "BlockProcessed".to_string(),
                None,
                "id3".to_string(),
                "wallet_scanner".to_string(),
                Some(Duration::from_millis(60)),
            ),
        ]);

        // Update stats manually for this test
        mock.update_stats("BlockProcessed", Some(Duration::from_millis(50)));
        mock.update_stats("BlockProcessed", Some(Duration::from_millis(75)));
        mock.update_stats("BlockProcessed", Some(Duration::from_millis(60)));

        // Define performance requirements
        let perf_assertion = PerformanceAssertion::new()
            .max_total_duration(Duration::from_millis(200))
            .max_average_duration(Duration::from_millis(70))
            .min_events_per_second(1.0);

        // Verify performance meets requirements
        let test_duration = Duration::from_secs(3); // 3 events in 3 seconds = 1 eps
        assert!(perf_assertion.verify(&mock, test_duration).is_ok());

        // Test failure case
        let strict_perf =
            PerformanceAssertion::new().max_average_duration(Duration::from_millis(40)); // Too strict

        assert!(strict_perf.verify(&mock, test_duration).is_err());
    }

    /// Example: Test scenarios for different scanning outcomes
    #[tokio::test]
    async fn example_test_scenarios() {
        // Test successful scan scenario
        let success_scenario = TestScenario::successful_scan()
            .with_block_range(0, 100)
            .with_outputs_found(3)
            .with_duration_limit(Duration::from_secs(30));

        let mock = MockEventListener::new();
        let captured_events = mock.get_captured_events();

        // Simulate successful scan events
        captured_events.lock().unwrap().extend(vec![
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "ScanStarted".to_string(),
                Some("\"block_range\":[0,100]".to_string()),
                "id1".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "BlockProcessed".to_string(),
                None,
                "id2".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "OutputFound".to_string(),
                None,
                "id3".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "OutputFound".to_string(),
                None,
                "id4".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "OutputFound".to_string(),
                None,
                "id5".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "ScanCompleted".to_string(),
                None,
                "id6".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
        ]);

        // Verify the scenario
        assert!(success_scenario.verify(&mock).await.is_ok());

        // Test error scenario
        let error_scenario = TestScenario::error_scan();
        let error_mock = MockEventListener::new();
        let error_events = error_mock.get_captured_events();

        error_events.lock().unwrap().extend(vec![
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "ScanStarted".to_string(),
                None,
                "id1".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "ScanError".to_string(),
                Some("Network timeout".to_string()),
                "id2".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
        ]);

        assert!(error_scenario.verify(&error_mock).await.is_ok());
    }

    /// Example: Event capture session with timing and analysis
    #[tokio::test]
    async fn example_event_capture_session() {
        let capture = EventCapture::new();
        let mock = capture.mock_listener();

        // Simulate some events during capture
        let captured_events = mock.get_captured_events();
        captured_events.lock().unwrap().extend(vec![
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "ScanStarted".to_string(),
                Some("wallet_123".to_string()),
                "id1".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "BlockProcessed".to_string(),
                None,
                "id2".to_string(),
                "wallet_scanner".to_string(),
                Some(Duration::from_millis(100)),
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "ScanCompleted".to_string(),
                None,
                "id3".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
        ]);

        // Create summary and analyze results
        let summary = capture.create_summary();
        assert_eq!(summary.total_events, 3);
        assert!(summary.has_event_type("ScanStarted"));
        assert!(summary.has_event_type("BlockProcessed"));
        assert!(summary.has_event_type("ScanCompleted"));
        assert_eq!(summary.count_for_type("BlockProcessed"), 1);

        // Export to JSON for external analysis
        let json_export = summary.to_json().unwrap();
        assert!(json_export.contains("total_events"));
        assert!(json_export.contains("ScanStarted"));

        // Test pattern waiting (with immediate success since events are already there)
        let pattern = EventPattern::sequence()
            .contains("ScanStarted")
            .contains("ScanCompleted");

        assert!(capture
            .wait_for_pattern(pattern, Duration::from_millis(100))
            .await
            .is_ok());
    }

    /// Example: Comprehensive integration test combining all features
    #[tokio::test]
    async fn example_comprehensive_integration() {
        // Set up a complete test environment
        let mut dispatcher = EventDispatcher::new_with_debug();
        let mock = MockEventListener::builder().testing_preset().build();

        dispatcher.register(Box::new(mock)).unwrap();

        // Define the expected workflow pattern
        let workflow_pattern = EventPattern::sequence()
            .starts_with("ScanStarted")
            .followed_by_any_number_of("BlockProcessed")
            .ends_with("ScanCompleted")
            .min_events(3)
            .with_content_matching("integration_test");

        // Define performance requirements
        let performance_req = PerformanceAssertion::new()
            .max_total_duration(Duration::from_secs(1))
            .min_events_per_second(0.1); // Very lenient for test

        // Create test scenario
        let scenario = TestScenario::successful_scan()
            .with_block_range(1000, 1100)
            .with_pattern(workflow_pattern)
            .with_performance_requirements(performance_req.clone());

        // For this example, we'll simulate the events being captured
        // In real usage, these would come from actual scanning operations
        let test_mock = MockEventListener::new();
        let captured_events = test_mock.get_captured_events();

        captured_events.lock().unwrap().extend(vec![
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "ScanStarted".to_string(),
                Some("integration_test \"block_range\":[1000,1100]".to_string()),
                "id1".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "BlockProcessed".to_string(),
                None,
                "id2".to_string(),
                "wallet_scanner".to_string(),
                Some(Duration::from_millis(100)),
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "BlockProcessed".to_string(),
                None,
                "id3".to_string(),
                "wallet_scanner".to_string(),
                Some(Duration::from_millis(150)),
            ),
            crate::events::listeners::mock_listener::CapturedEvent::new(
                "ScanCompleted".to_string(),
                None,
                "id4".to_string(),
                "wallet_scanner".to_string(),
                None,
            ),
        ]);

        // Update timing stats
        test_mock.update_stats("BlockProcessed", Some(Duration::from_millis(100)));
        test_mock.update_stats("BlockProcessed", Some(Duration::from_millis(150)));

        // Verify all aspects of the test
        let verify_result = scenario.verify(&test_mock).await;
        if let Err(e) = &verify_result {
            println!("Scenario verification failed: {}", e);
        }
        assert!(verify_result.is_ok());

        // Additional detailed assertions
        assert!(test_mock
            .assert_event_sequence(&[
                "ScanStarted",
                "BlockProcessed",
                "BlockProcessed",
                "ScanCompleted"
            ])
            .is_ok());

        assert!(test_mock
            .assert_contains_event_with_content("integration_test")
            .is_ok());

        // Verify performance meets requirements
        let test_duration = Duration::from_secs(2); // 4 events in 2s = 2 eps (exactly meets requirement)
        assert!(performance_req.verify(&test_mock, test_duration).is_ok());
    }
}
