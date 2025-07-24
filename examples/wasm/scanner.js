#!/usr/bin/env node

/**
 * Tari WASM Scanner CLI
 * 
 * A Node.js CLI client for Tari WASM Scanner with seed phrase and view key support.
 * This CLI replicates the functionality of the native Rust scanner using WASM.
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Import WASM module
import {
    wasm_scan_with_seed_phrase,
    wasm_scan_with_view_key,
    wasm_validate_seed_phrase,
    wasm_validate_view_key,
    wasm_get_tip_height,
    WasmScanConfig,
    WasmOutputFormat
} from './pkg_node/lightweight_wallet_libs.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Package info
let packageInfo;
try {
    packageInfo = JSON.parse(readFileSync(join(__dirname, 'package.json'), 'utf8'));
} catch (error) {
    packageInfo = { version: 'unknown' };
}

/**
 * CLI Program setup
 */
const program = new Command();

program
    .name('tari-scanner')
    .description('Enhanced Tari Wallet Scanner (WASM)')
    .version(packageInfo.version || 'unknown')
    .usage('[options]');

// CLI Arguments matching scanner.rs exactly
program
    .option('-s, --seed-phrase <phrase>', 'Seed phrase for the wallet (uses memory-only storage)')
    .option('--view-key <key>', 'Private view key in hex format (64 characters). Uses memory-only storage. Not required when resuming from database')
    .option('-b, --base-url <url>', 'Base URL for Tari base node GRPC', 'http://127.0.0.1:8080')
    .option('--from-block <height>', 'Starting block height (defaults to wallet birthday or last scanned block)', parseInteger)
    .option('--to-block <height>', 'Ending block height (defaults to current tip)', parseInteger)
    .option('--blocks <heights>', 'Specific block heights to scan (comma-separated). If provided, overrides from-block and to-block', parseBlockList)
    .option('--batch-size <size>', 'Batch size for scanning', parseInteger, 10)
    .option('--progress-frequency <freq>', 'Update progress every N blocks', parseInteger, 10)
    .option('-q, --quiet', 'Quiet mode - only show essential information', false)
    .option('--format <format>', 'Output format: detailed, summary, json', 'summary');

/**
 * Parse integer from string with validation (matching scanner.rs style)
 */
function parseInteger(value) {
    const parsed = parseInt(value, 10);
    if (isNaN(parsed)) {
        throw new Error(`❌ Error: Invalid number: '${value}' - must be a valid integer`);
    }
    if (parsed < 0) {
        throw new Error(`❌ Error: Invalid number: '${value}' - must be >= 0`);
    }
    return parsed;
}

/**
 * Parse comma-separated block list (matching scanner.rs validation)
 */
function parseBlockList(value) {
    if (!value || value.trim().length === 0) {
        throw new Error('❌ Error: blocks list cannot be empty');
    }
    
    const blocks = value.split(',').map((block, index) => {
        const trimmed = block.trim();
        if (trimmed.length === 0) {
            throw new Error(`❌ Error: Empty block height at position ${index + 1}`);
        }
        
        try {
            return parseInteger(trimmed);
        } catch (error) {
            throw new Error(`❌ Error: Invalid block height '${trimmed}' at position ${index + 1}: ${error.message}`);
        }
    });
    
    return blocks;
}

/**
 * Display error message and exit (matching scanner.rs style)
 */
function showArgumentError(message) {
    console.error(chalk.red(`❌ Error: ${message}`));
    process.exit(1);
}

/**
 * Validate CLI arguments (matching scanner.rs validation exactly)
 */
function validateArgs(options) {
    const errors = [];

    // Check for mutual exclusion of seed phrase and view key (matching scanner.rs)
    if (options.seedPhrase && options.viewKey) {
        showArgumentError('Cannot specify both --seed-phrase and --view-key. Choose one.');
    }

    // Must provide either seed phrase or view key  
    if (!options.seedPhrase && !options.viewKey) {
        errors.push('❌ Error: No keys provided - provide --seed-phrase or --view-key, or use an existing wallet.');
    }

    // Validate seed phrase format
    if (options.seedPhrase) {
        if (options.seedPhrase.trim().length === 0) {
            errors.push('❌ Error: Seed phrase cannot be empty');
        } else if (!wasm_validate_seed_phrase(options.seedPhrase)) {
            errors.push('❌ Error: Invalid seed phrase format');
        }
    }

    // Validate view key format (matching scanner.rs exact requirements)
    if (options.viewKey) {
        if (options.viewKey.trim().length === 0) {
            errors.push('❌ Error: View key cannot be empty');
        } else if (options.viewKey.trim().length !== 64) {
            errors.push('❌ Error: View key must be exactly 64 hex characters (32 bytes)');
        } else if (!/^[0-9a-fA-F]{64}$/.test(options.viewKey.trim())) {
            errors.push('❌ Error: Invalid hex format for view key');
        } else if (!wasm_validate_view_key(options.viewKey)) {
            errors.push('❌ Error: Invalid view key format (must be 64 hex characters)');
        }
    }

    // Validate format option (matching scanner.rs options)
    const validFormats = ['detailed', 'summary', 'json'];
    if (!validFormats.includes(options.format)) {
        errors.push(`❌ Error: Invalid format: ${options.format}. Valid options: ${validFormats.join(', ')}`);
    }

    // Validate block range
    if (options.fromBlock !== undefined && options.toBlock !== undefined) {
        if (options.fromBlock < 0) {
            errors.push('❌ Error: from-block must be >= 0');
        }
        if (options.toBlock < 0) {
            errors.push('❌ Error: to-block must be >= 0');
        }
        if (options.fromBlock >= options.toBlock) {
            errors.push('❌ Error: from-block must be less than to-block');
        }
    }

    // Validate specific blocks
    if (options.blocks) {
        if (options.blocks.length === 0) {
            errors.push('❌ Error: blocks list cannot be empty');
        }
        for (const block of options.blocks) {
            if (block < 0) {
                errors.push(`❌ Error: block height ${block} must be >= 0`);
            }
        }
    }

    // Validate batch size
    if (options.batchSize <= 0) {
        errors.push('❌ Error: batch-size must be greater than 0');
    }

    if (options.batchSize > 1000) {
        console.warn(chalk.yellow(`⚠️  Warning: Large batch size (${options.batchSize}) may cause performance issues`));
    }

    // Validate progress frequency
    if (options.progressFrequency <= 0) {
        errors.push('❌ Error: progress-frequency must be greater than 0');
    }

    return errors;
}

/**
 * Create WASM scan configuration from CLI options
 */
function createScanConfig(options) {
    const config = new WasmScanConfig(options.baseUrl);
    
    // Set basic scan parameters using direct field access (convert to BigInt for u64)
    if (options.fromBlock !== undefined) config.from_block = BigInt(options.fromBlock);
    if (options.toBlock !== undefined) config.to_block = BigInt(options.toBlock);
    if (options.blocks) config.set_blocks(options.blocks.map(b => BigInt(b))); // Convert array elements to BigInt
    
    config.batch_size = BigInt(options.batchSize);
    config.progress_frequency = BigInt(options.progressFrequency);
    config.quiet = options.quiet;

    // Set output format using direct field access
    const wasmFormat = options.format === 'detailed' ? WasmOutputFormat.Detailed :
                      options.format === 'json' ? WasmOutputFormat.Json :
                      WasmOutputFormat.Summary;
    config.output_format = wasmFormat;

    return config;
}



/**
 * Display scan results
 */
function displayResults(results, options) {
    if (options.format === 'json') {
        console.log(JSON.stringify(results, null, 2));
        return;
    }

    const balance = (results.total_balance); // Convert to Tari
    const duration = results.duration_seconds.toFixed(2);
    const speed = results.average_blocks_per_second.toFixed(2);

    console.log('\n' + chalk.green('✓ Scan completed successfully!'));
    console.log(chalk.blue('═'.repeat(50)));
    
    if (options.format === 'detailed') {
        console.log(chalk.white(`Session ID: ${results.session_id}`));
        console.log(chalk.white(`Start Time: ${results.start_time}`));
        console.log(chalk.white(`End Time: ${results.end_time}`));
        console.log(chalk.white(`Configuration: ${results.config_summary || 'N/A'}`));
        console.log('');
    }

    console.log(chalk.white(`Blocks Scanned: ${results.blocks_scanned.toLocaleString()}`));
    console.log(chalk.white(`Final Height: ${results.final_height.toLocaleString()}`));
    console.log(chalk.white(`Outputs Found: ${results.outputs_found.toLocaleString()}`));
    console.log(chalk.white(`Total Balance: ${balance} T`));
    console.log(chalk.white(`Duration: ${duration}s`));
    console.log(chalk.white(`Average Speed: ${speed} blocks/s`));
    
    if (results.peak_memory_usage_mb) {
        console.log(chalk.white(`Peak Memory: ${results.peak_memory_usage_mb.toFixed(2)} MB`));
    }

    console.log(chalk.blue('═'.repeat(50)));
}

/**
 * Display error and exit
 */
function displayError(error, exitCode = 1) {
    console.error(chalk.red('✗ Error: ' + error.message));
    process.exit(exitCode);
}

/**
 * Cancellation state for graceful interruption
 */
let scanCancelled = false;
let currentScanProgress = null;
let partialResults = null;
let scanStartTime = null;
let currentScanOptions = null;

/**
 * Reset cancellation state for new scans
 */
function resetCancellationState() {
    scanCancelled = false;
    currentScanProgress = null;
    partialResults = null;
    scanStartTime = null;
    currentScanOptions = null;
}

/**
 * Create partial results from current progress data
 */
function createPartialResultsFromProgress() {
    if (!currentScanProgress || !scanStartTime) {
        return null;
    }
    
    const now = Date.now();
    const durationSeconds = (now - scanStartTime) / 1000;
    
    return {
        session_id: `interrupted-${Date.now()}`,
        start_time: new Date(scanStartTime).toISOString(),
        end_time: new Date(now).toISOString(),
        blocks_scanned: currentScanProgress.blocks_completed || 0,
        final_height: currentScanProgress.current_height || 0,
        outputs_found: currentScanProgress.outputs_found || 0,
        total_balance: currentScanProgress.current_balance || 0,
        duration_seconds: durationSeconds,
        average_blocks_per_second: currentScanProgress.blocks_per_second || 0,
        peak_memory_usage_mb: null, // Not available from progress
        config_summary: `Interrupted scan: ${currentScanProgress.blocks_completed || 0}/${currentScanProgress.total_blocks || '?'} blocks`
    };
}

/**
 * Handle scan interruption gracefully (matching scanner.rs behavior)
 */
function handleScanInterruption(options) {
    if (!options.quiet) {
        console.log(chalk.yellow('\n\n🛑 Scan interrupted by user (Ctrl+C)'));
        console.log(chalk.yellow('📊 Waiting for current batch to complete...\n'));
    }
    
    // Give a moment for the scan to notice the cancellation
    setTimeout(() => {
        // Try to use existing partial results, or create from progress data
        const resultsToDisplay = partialResults || createPartialResultsFromProgress();
        
        if (resultsToDisplay) {
            displayPartialResults(resultsToDisplay, options);
        } else {
            // No progress data available - scan was interrupted very early
            if (!options.quiet) {
                console.log(chalk.yellow('⚠️  Scan was interrupted before any blocks were processed.\n'));
                
                // Still provide resume command using original parameters
                console.log(chalk.yellow('🔄 To resume scanning from where you left off, use:'));
                
                const baseCommand = './scanner.js';
                let resumeCommand;
                
                if (options.seedPhrase) {
                    resumeCommand = `${baseCommand} --seed-phrase "${options.seedPhrase}"`;
                } else if (options.viewKey) {
                    resumeCommand = `${baseCommand} --view-key "${options.viewKey}"`;
                }
                
                // Add the original from-block or default
                if (options.fromBlock) {
                    resumeCommand += ` --from-block ${options.fromBlock}`;
                }
                
                // Add other options to resume command
                if (options.baseUrl !== 'http://127.0.0.1:8080') {
                    resumeCommand += ` --base-url "${options.baseUrl}"`;
                }
                if (options.toBlock) {
                    resumeCommand += ` --to-block ${options.toBlock}`;
                }
                if (options.batchSize !== 10) {
                    resumeCommand += ` --batch-size ${options.batchSize}`;
                }
                if (options.format !== 'summary') {
                    resumeCommand += ` --format ${options.format}`;
                }
                if (options.quiet) {
                    resumeCommand += ' --quiet';
                }
                
                console.log(chalk.gray(`   ${resumeCommand}`));
            }
            process.exit(130); // Standard exit code for SIGINT
        }
    }, 100);
}

/**
 * Display partial results when scan is interrupted (matching scanner.rs)
 */
function displayPartialResults(results, options) {
    if (!options.quiet) {
        console.log(chalk.yellow('⚠️  Scan was interrupted but collected partial data:\n'));
    }

    // Display partial results based on output format (same as complete results)
    displayResults(results, options);

    // Determine resume block from results or current progress
    const finalHeight = results.final_height || (currentScanProgress && currentScanProgress.current_height);
    
    if (!options.quiet && finalHeight) {
        console.log(chalk.yellow('\n🔄 To resume scanning from where you left off, use:'));
        
        // Generate resume command based on scan type
        const resumeBlock = finalHeight + 1;
        const baseCommand = './scanner.js';
        
        let resumeCommand;
        if (options.seedPhrase) {
            resumeCommand = `${baseCommand} --seed-phrase "${options.seedPhrase}" --from-block ${resumeBlock}`;
        } else if (options.viewKey) {
            resumeCommand = `${baseCommand} --view-key "${options.viewKey}" --from-block ${resumeBlock}`;
        }
        
        // Add other options to resume command
        if (options.baseUrl !== 'http://127.0.0.1:8080') {
            resumeCommand += ` --base-url "${options.baseUrl}"`;
        }
        if (options.toBlock) {
            resumeCommand += ` --to-block ${options.toBlock}`;
        }
        if (options.format !== 'summary') {
            resumeCommand += ` --format ${options.format}`;
        }
        if (options.quiet) {
            resumeCommand += ' --quiet';
        }
        
        console.log(chalk.gray(`   ${resumeCommand}`));
    }
    
    process.exit(130); // Standard exit code for SIGINT
}

/**
 * Enhanced progress callback with cancellation support
 */
function createProgressCallbackWithCancellation(options) {
    if (options.quiet) {
        return null; // No progress updates in quiet mode
    }

    return (progress) => {
        // Store current progress for potential partial results
        currentScanProgress = progress;
        
        // Check for cancellation
        if (scanCancelled) {
            return false; // Signal to WASM to stop scanning
        }
        
        const percentage = progress.percentage.toFixed(1);
        const current = progress.current_height;
        const total = progress.total_blocks;
        const completed = progress.blocks_completed;
        const found = progress.outputs_found;
        const balance = (progress.current_balance / 1000000).toFixed(6); // Convert to Tari
        const speed = progress.blocks_per_second.toFixed(2);
        
        let message = `${percentage}% - Block ${current} (${completed}/${total}) - Found ${found} outputs`;
        message += ` - Balance: ${balance} T - Speed: ${speed} blocks/s`;
        
        if (progress.estimated_remaining_seconds) {
            const remaining = Math.round(progress.estimated_remaining_seconds);
            message += ` - ETA: ${remaining}s`;
        }

        console.log(chalk.cyan(message));
        return true; // Continue scanning
    };
}

/**
 * Main scanner function with cancellation support
 */
async function runScan(options) {
    // Reset cancellation state for new scan
    resetCancellationState();
    
    // Store options and start time for interruption handling
    currentScanOptions = options;
    scanStartTime = Date.now();
    
    const spinner = ora('Initializing WASM module...').start();
    
    try {
        // WASM module is automatically initialized for Node.js target
        spinner.succeed('WASM module initialized');

        // Validate arguments
        const validationErrors = validateArgs(options);
        if (validationErrors.length > 0) {
            spinner.fail('Validation failed');
            validationErrors.forEach(error => console.error(error));
            process.exit(1);
        }

        // Create scan configuration
        const config = createScanConfig(options);
        
        // Create progress callback with cancellation support
        const progressCallback = createProgressCallbackWithCancellation(options);

        // Get tip height if needed
        if (!options.quiet) {
            spinner.start('Getting blockchain tip height...');
            try {
                const tipHeight = await wasm_get_tip_height(options.baseUrl);
                spinner.succeed(`Blockchain tip height: ${tipHeight.toLocaleString()}`);
            } catch (error) {
                spinner.warn(`Could not get tip height: ${error.message}`);
            }
        }

        // Start scanning
        spinner.start('Starting blockchain scan...');
        let results;

        try {
            if (options.seedPhrase) {
                results = await wasm_scan_with_seed_phrase(
                    options.seedPhrase,
                    null, // No passphrase support in CLI yet
                    config,
                    progressCallback
                );
            } else if (options.viewKey) {
                results = await wasm_scan_with_view_key(
                    options.viewKey,
                    config,
                    progressCallback
                );
            }

            // Store results in case we get interrupted later
            partialResults = results;

            spinner.succeed('Blockchain scan completed');

            // Display results
            displayResults(results, options);

        } catch (error) {
            // Check if this was a cancellation-related error
            if (scanCancelled) {
                spinner.fail('Scan interrupted');
                return; // Signal handler will take care of the rest
            }
            throw error; // Re-throw non-cancellation errors
        }

    } catch (error) {
        console.log(error);
        spinner.fail('Scan failed');
        displayError(error);
    }
}

/**
 * Main entry point
 */
async function main() {
    try {
        // Parse command line arguments
        program.parse();
        const options = program.opts();

        // Show help if no arguments provided (matching scanner.rs style)
        if (process.argv.length <= 2) {
            console.log(chalk.blue('🚀 Enhanced Tari Wallet Scanner (WASM)'));
            console.log(chalk.blue('======================================='));
            console.log();
            console.log(chalk.gray('Use --help for detailed usage information'));
            console.log();
            console.log(chalk.yellow('## Quick Examples:'));
            console.log();
            console.log(chalk.white('# Scan with wallet from birthday to tip using seed phrase (memory only)'));
            console.log(chalk.gray('./scanner.js --seed-phrase "your seed phrase here"'));
            console.log();
            console.log(chalk.white('# Scan using private view key (hex format, 64 characters, memory only)'));
            console.log(chalk.gray('./scanner.js --view-key "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab"'));
            console.log();
            console.log(chalk.white('# Scan specific range with view key (memory only)'));
            console.log(chalk.gray('./scanner.js --view-key "your_view_key_here" --from-block 34920 --to-block 34930'));
            console.log();
            console.log(chalk.white('# Scan specific blocks only (memory only)'));
            console.log(chalk.gray('./scanner.js --seed-phrase "your seed phrase" --blocks 1000,2000,5000,10000'));
            console.log();
            console.log(chalk.white('# Use custom base node URL (memory only)'));
            console.log(chalk.gray('./scanner.js --seed-phrase "your seed phrase" --base-url "http://192.168.1.100:8080"'));
            console.log();
            console.log(chalk.white('# Quiet mode with JSON output (script-friendly, memory only)'));
            console.log(chalk.gray('./scanner.js --view-key "your_view_key" --quiet --format json'));
            console.log();
            console.log(chalk.white('# Summary output with minimal progress updates (memory only)'));
            console.log(chalk.gray('./scanner.js --seed-phrase "your seed phrase" --format summary --progress-frequency 50'));
            process.exit(0);
        }

        // Run the scan
        await runScan(options);

    } catch (error) {
        if (error.code === 'commander.helpDisplayed') {
            process.exit(0);
        }
        displayError(error);
    }
}

/**
 * Handle process signals with graceful shutdown (matching scanner.rs behavior)
 */
process.on('SIGINT', () => {
    // Don't exit immediately - let the scan complete current batch
    if (!scanCancelled) {
        scanCancelled = true;
        if (currentScanOptions) {
            handleScanInterruption(currentScanOptions);
        } else {
            console.log(chalk.yellow('\n⚠ Scan interrupted by user'));
            process.exit(130);
        }
    }
});

process.on('SIGTERM', () => {
    if (!scanCancelled) {
        scanCancelled = true;
        console.log(chalk.yellow('\n⚠ Scan terminated by system'));
        process.exit(143);
    }
});

// Run the CLI
main().catch(error => {
    console.error(chalk.red('Fatal error:'), error);
    process.exit(1);
});
