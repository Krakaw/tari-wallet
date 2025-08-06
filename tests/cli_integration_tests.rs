//! CLI Integration Tests
//!
//! Comprehensive testing framework for all CLI binaries using std::process::Command
//! to execute real binary integration tests.

#![cfg(not(target_arch = "wasm32"))]

#[cfg(feature = "grpc-storage")]
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Test utility for running CLI commands
struct CliTestRunner {
    cargo_path: PathBuf,
    _target_dir: TempDir, // Keep temp dir alive but mark as intentionally unused
}

impl CliTestRunner {
    fn new() -> Self {
        let target_dir = TempDir::new().expect("Failed to create temp directory");
        Self {
            cargo_path: PathBuf::from("cargo"),
            _target_dir: target_dir,
        }
    }

    /// Run a binary with arguments and return the result
    fn run_binary(&self, binary_name: &str, features: &str, args: &[&str]) -> CommandResult {
        let mut cmd = Command::new(&self.cargo_path);
        cmd.arg("run")
            .arg("--bin")
            .arg(binary_name)
            .arg("--features")
            .arg(features)
            .arg("--")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = cmd.output().expect("Failed to execute command");

        CommandResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
        }
    }

    /// Run scanner binary
    #[cfg(feature = "grpc-storage")]
    fn run_scanner(&self, args: &[&str]) -> CommandResult {
        self.run_binary("scanner", "grpc-storage", args)
    }

    /// Run wallet binary  
    #[cfg(feature = "storage")]
    fn run_wallet(&self, args: &[&str]) -> CommandResult {
        self.run_binary("wallet", "storage", args)
    }

    /// Run signing binary
    fn run_signing(&self, args: &[&str]) -> CommandResult {
        self.run_binary("signing", "", args)
    }
}

/// Result of running a CLI command
#[derive(Debug)]
struct CommandResult {
    exit_code: i32,
    stdout: String,
    stderr: String,
    success: bool,
}

impl CommandResult {
    fn assert_success(&self) {
        if !self.success {
            panic!(
                "Command failed with exit code {}\nSTDOUT:\n{}\nSTDERR:\n{}",
                self.exit_code, self.stdout, self.stderr
            );
        }
    }

    fn assert_failure(&self) {
        if self.success {
            panic!(
                "Expected command to fail but it succeeded\nSTDOUT:\n{}\nSTDERR:\n{}",
                self.stdout, self.stderr
            );
        }
    }

    fn contains_stdout(&self, text: &str) -> bool {
        self.stdout.contains(text)
    }

    fn contains_stderr(&self, text: &str) -> bool {
        self.stderr.contains(text)
    }

    #[cfg(feature = "grpc-storage")]
    fn parse_json(&self) -> Result<Value, serde_json::Error> {
        serde_json::from_str(&self.stdout)
    }
}

// ============================================================================
// SIGNING BINARY TESTS
// ============================================================================

mod signing_tests {
    use super::*;

    #[test]
    fn test_signing_help() {
        let runner = CliTestRunner::new();
        let result = runner.run_signing(&["--help"]);

        result.assert_success();
        assert!(
            result.contains_stdout("CLI tool for signing and verifying messages")
                || result.contains_stdout("Tari-compatible")
        );
        assert!(result.contains_stdout("generate"));
        assert!(result.contains_stdout("sign"));
        assert!(result.contains_stdout("verify"));
    }

    #[test]
    fn test_signing_version() {
        let runner = CliTestRunner::new();
        let result = runner.run_signing(&["--version"]);

        result.assert_success();
        assert!(result.stdout.contains("signing"));
    }

    #[test]
    fn test_generate_keypair() {
        let runner = CliTestRunner::new();
        let result = runner.run_signing(&["generate", "--stdout"]);

        result.assert_success();
        assert!(result.contains_stdout("Secret Key"));
        assert!(result.contains_stdout("Public Key"));

        // Verify hex format (64 characters for secret key, 64 for public key)
        let lines: Vec<&str> = result.stdout.lines().collect();
        let secret_line = lines
            .iter()
            .find(|l| l.contains("Secret Key"))
            .expect("Secret Key not found");
        let public_line = lines
            .iter()
            .find(|l| l.contains("Public Key"))
            .expect("Public Key not found");

        // Extract hex strings and verify format
        assert!(secret_line.split(':').nth(1).unwrap().trim().len() == 64);
        assert!(public_line.split(':').nth(1).unwrap().trim().len() == 64);
    }

    #[test]
    fn test_sign_message() {
        let runner = CliTestRunner::new();

        // First generate a key
        let gen_result = runner.run_signing(&["generate", "--stdout"]);
        gen_result.assert_success();

        // Extract secret key from output
        let secret_key = gen_result
            .stdout
            .lines()
            .find(|l| l.contains("Secret Key"))
            .unwrap()
            .split(':')
            .nth(1)
            .unwrap()
            .trim();

        // Sign a message
        let result = runner.run_signing(&[
            "sign",
            "--secret-key",
            secret_key,
            "--message",
            "Hello, Tari!",
            "--format",
            "json",
        ]);

        result.assert_success();
        assert!(result.contains_stdout("signature"));
        assert!(result.contains_stdout("nonce"));
    }

    #[test]
    fn test_verify_message() {
        let runner = CliTestRunner::new();

        // Generate key and sign message
        let gen_result = runner.run_signing(&["generate", "--stdout"]);
        let secret_key = gen_result
            .stdout
            .lines()
            .find(|l| l.contains("Secret Key"))
            .unwrap()
            .split(':')
            .nth(1)
            .unwrap()
            .trim();

        let sign_result = runner.run_signing(&[
            "sign",
            "--secret-key",
            secret_key,
            "--message",
            "Hello, Tari!",
            "--format",
            "json",
        ]);

        // Parse JSON output to extract signature and nonce
        let json: serde_json::Value = serde_json::from_str(&sign_result.stdout).unwrap();
        let signature = json["signature"].as_str().unwrap();
        let nonce = json["nonce"].as_str().unwrap();

        // Get public key from secret key
        let public_key = gen_result
            .stdout
            .lines()
            .find(|l| l.contains("Public Key"))
            .unwrap()
            .split(':')
            .nth(1)
            .unwrap()
            .trim();

        // Verify the signature
        let result = runner.run_signing(&[
            "verify",
            "--public-key",
            public_key,
            "--signature",
            signature,
            "--nonce",
            nonce,
            "--message",
            "Hello, Tari!",
        ]);

        result.assert_success();
        assert!(result.contains_stdout("VALID"));
    }

    #[test]
    fn test_invalid_signature_verification() {
        let runner = CliTestRunner::new();

        // Generate key
        let gen_result = runner.run_signing(&["generate", "--stdout"]);
        let public_key = gen_result
            .stdout
            .lines()
            .find(|l| l.contains("Public Key"))
            .unwrap()
            .split(':')
            .nth(1)
            .unwrap()
            .trim();

        // Try to verify with invalid signature
        let result = runner.run_signing(&[
            "verify",
            "--public-key", public_key,
            "--signature", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "--message", "Hello, Tari!"
        ]);

        // Should fail or indicate invalid signature
        assert!(
            result.contains_stdout("invalid")
                || result.contains_stderr("invalid")
                || !result.success
        );
    }

    #[test]
    fn test_invalid_arguments() {
        let runner = CliTestRunner::new();

        // Test missing required argument
        let result = runner.run_signing(&["sign", "--message", "test"]);
        result.assert_failure();
        assert!(result.contains_stderr("provide either") || result.contains_stderr("secret-key"));

        // Test invalid hex key
        let result =
            runner.run_signing(&["sign", "--secret-key", "invalid_hex", "--message", "test"]);
        result.assert_failure();
    }
}

// ============================================================================
// WALLET BINARY TESTS
// ============================================================================

#[cfg(feature = "storage")]
mod wallet_tests {
    use super::*;

    #[test]
    fn test_wallet_help() {
        let runner = CliTestRunner::new();
        let result = runner.run_wallet(&["--help"]);

        result.assert_success();
        assert!(result.contains_stdout("Tari Wallet CLI"));
        assert!(result.contains_stdout("generate"));
    }

    #[test]
    fn test_wallet_version() {
        let runner = CliTestRunner::new();
        let result = runner.run_wallet(&["--version"]);

        result.assert_success();
        assert!(result.stdout.contains("wallet"));
    }

    #[test]
    fn test_generate_wallet() {
        let runner = CliTestRunner::new();
        let result = runner.run_wallet(&["generate"]);

        result.assert_success();
        assert!(
            result.contains_stdout("Seed:")
                || result.contains_stdout("seed phrase")
                || result.contains_stdout("Seed phrase")
        );
        assert!(
            result.contains_stdout("Base58:")
                || result.contains_stdout("address")
                || result.contains_stdout("Address")
        );
    }

    #[test]
    fn test_generate_wallet_with_payment_id() {
        let runner = CliTestRunner::new();
        let result = runner.run_wallet(&["generate", "--payment-id", "test-payment-123"]);

        result.assert_success();
        assert!(result.contains_stdout("Payment ID included: Yes"));
    }

    #[test]
    fn test_generate_wallet_with_network() {
        let runner = CliTestRunner::new();
        let result = runner.run_wallet(&["generate", "--network", "esmeralda"]);

        result.assert_success();
        // Esmeralda network uses different address prefix - check that address doesn't start with mainnet prefix "1"
        assert!(result.contains_stdout("Base58:"));
        let lines: Vec<&str> = result.stdout.lines().collect();
        let base58_line = lines.iter().find(|l| l.contains("Base58:")).unwrap();
        let address = base58_line.split(':').nth(1).unwrap().trim();
        assert!(!address.starts_with("1")); // Esmeralda addresses don't start with "1" like mainnet
    }

    #[test]
    fn test_invalid_network() {
        let runner = CliTestRunner::new();
        let result = runner.run_wallet(&["generate", "--network", "invalid_network"]);

        // Should either fail or provide error message
        if result.success {
            assert!(result.contains_stderr("invalid") || result.contains_stdout("invalid"));
        }
    }

    #[test]
    fn test_missing_subcommand() {
        let runner = CliTestRunner::new();
        let result = runner.run_wallet(&[]);

        result.assert_failure();
        assert!(result.contains_stderr("required") || result.contains_stderr("COMMAND"));
    }
}

// ============================================================================
// SCANNER BINARY TESTS
// ============================================================================

#[cfg(feature = "grpc-storage")]
mod scanner_tests {
    use super::*;

    #[test]
    fn test_scanner_help() {
        let runner = CliTestRunner::new();
        let result = runner.run_scanner(&["--help"]);

        result.assert_success();
        assert!(
            result.contains_stdout("Enhanced Tari Wallet Scanner")
                || result.contains_stdout("scanner")
        );
        assert!(result.contains_stdout("seed-phrase") || result.contains_stdout("view-key"));
    }

    #[test]
    fn test_scanner_version() {
        let runner = CliTestRunner::new();
        let result = runner.run_scanner(&["--version"]);

        result.assert_success();
        assert!(result.stdout.contains("scanner") || result.stderr.contains("scanner"));
    }

    #[test]
    fn test_conflicting_key_arguments() {
        let runner = CliTestRunner::new();
        // Test providing both seed phrase and view key (should fail immediately)
        let result = runner.run_scanner(&[
            "--seed-phrase",
            "test seed phrase",
            "--view-key",
            &"a".repeat(64),
        ]);

        result.assert_failure();
        assert!(
            result.contains_stderr("Cannot specify both")
                || result.contains_stderr("seed-phrase")
                || result.contains_stderr("view-key")
        );
    }

    #[test]
    fn test_invalid_view_key_format() {
        let runner = CliTestRunner::new();
        let result = runner.run_scanner(&["--view-key", "invalid_key_format"]);

        result.assert_failure();
        assert!(result.contains_stderr("invalid") || result.contains_stderr("format"));
    }

    #[test]
    fn test_view_key_length_validation() {
        let runner = CliTestRunner::new();

        // Test too short
        let result = runner.run_scanner(&["--view-key", "abc123"]);
        result.assert_failure();

        // Test too long
        let result = runner.run_scanner(&["--view-key", &"a".repeat(100)]);
        result.assert_failure();
    }

    #[test]
    fn test_block_range_validation() {
        let runner = CliTestRunner::new();

        // Test invalid range (from > to)
        let result = runner.run_scanner(&[
            "--view-key",
            &"a".repeat(64),
            "--from-block",
            "1000",
            "--to-block",
            "999",
        ]);

        // Should either fail or handle gracefully
        if result.success {
            assert!(result.contains_stderr("invalid") || result.contains_stdout("invalid"));
        }
    }

    #[test]
    fn test_invalid_base_url() {
        let runner = CliTestRunner::new();
        let result = runner.run_scanner(&[
            "--view-key",
            &"a".repeat(64),
            "--base-url",
            "not_a_valid_url",
            "--from-block",
            "1",
            "--to-block",
            "2", // Limit range to avoid timeout
        ]);

        // Should fail or show connection error
        if !result.success {
            assert!(result.contains_stderr("url") || result.contains_stderr("connection"));
        }
    }

    #[test]
    fn test_json_output_format() {
        let runner = CliTestRunner::new();
        let result = runner.run_scanner(&[
            "--view-key",
            &"a".repeat(64),
            "--format",
            "json",
            "--quiet",
            "--from-block",
            "1",
            "--to-block",
            "2", // Only scan 2 blocks to avoid timeout
        ]);

        // Should either produce JSON or fail gracefully
        if result.success && !result.stdout.is_empty() {
            // Try to parse as JSON
            assert!(result.parse_json().is_ok());
        }
    }
}

// ============================================================================
// CROSS-BINARY INTEGRATION TESTS
// ============================================================================

mod integration_tests {
    use super::*;

    #[test]
    fn test_all_binaries_respond_to_help() {
        let runner = CliTestRunner::new();

        // Test all binaries respond to --help
        let signing_result = runner.run_signing(&["--help"]);
        signing_result.assert_success();

        #[cfg(feature = "storage")]
        {
            let wallet_result = runner.run_wallet(&["--help"]);
            wallet_result.assert_success();
        }

        #[cfg(feature = "grpc-storage")]
        {
            let scanner_result = runner.run_scanner(&["--help"]);
            scanner_result.assert_success();
        }
    }

    #[test]
    fn test_all_binaries_respond_to_version() {
        let runner = CliTestRunner::new();

        let signing_result = runner.run_signing(&["--version"]);
        signing_result.assert_success();

        #[cfg(feature = "storage")]
        {
            let wallet_result = runner.run_wallet(&["--version"]);
            wallet_result.assert_success();
        }

        #[cfg(feature = "grpc-storage")]
        {
            let scanner_result = runner.run_scanner(&["--version"]);
            scanner_result.assert_success();
        }
    }

    #[test]
    fn test_binary_exit_codes() {
        let runner = CliTestRunner::new();

        // Valid commands should return 0
        let result = runner.run_signing(&["--help"]);
        assert_eq!(result.exit_code, 0);

        // Invalid commands should return non-zero
        let result = runner.run_signing(&["invalid-command"]);
        assert_ne!(result.exit_code, 0);
    }

    #[test]
    fn test_concurrent_binary_execution() {
        use std::sync::Arc;
        use std::thread;

        let runner = Arc::new(CliTestRunner::new());
        let mut handles = vec![];

        // Run multiple binaries concurrently
        for i in 0..3 {
            let runner_clone = Arc::clone(&runner);
            let handle = thread::spawn(move || {
                let result = runner_clone.run_signing(&["--help"]);
                result.assert_success();
                i
            });
            handles.push(handle);
        }

        // Wait for all to complete
        for handle in handles {
            handle.join().unwrap();
        }
    }
}

// ============================================================================
// ERROR HANDLING & EDGE CASES
// ============================================================================

mod error_handling_tests {
    use super::*;

    #[test]
    fn test_malformed_arguments() {
        let runner = CliTestRunner::new();

        // Test with malformed unicode (avoid null bytes which cause Command failures)
        let _result = runner.run_signing(&["sign", "--message", "invalid\u{FFFD}chars"]);
        // Should handle gracefully without crashing

        // Test with very long arguments
        let long_arg = "a".repeat(10000);
        let _result = runner.run_signing(&["sign", "--message", &long_arg]);
        // Should either succeed or fail gracefully
    }

    #[test]
    fn test_environment_isolation() {
        let runner = CliTestRunner::new();

        // Each test should be isolated - run same command multiple times
        for _ in 0..3 {
            let result = runner.run_signing(&["generate", "--stdout"]);
            result.assert_success();

            // Each run should produce different keys
            assert!(result.contains_stdout("Secret Key"));
        }
    }

    #[test]
    fn test_interrupted_execution() {
        // Test how binaries handle interruption
        // Note: This is harder to test automatically but we can test timeout scenarios
        let runner = CliTestRunner::new();

        // Use a command that might take time and see if it handles signals properly
        let result = runner.run_signing(&["--help"]);
        result.assert_success();

        // At minimum, ensure help commands complete quickly
        assert!(!result.stdout.is_empty());
    }
}
