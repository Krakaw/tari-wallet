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
import init, {
    wasm_scan_with_seed_phrase,
    wasm_scan_with_view_key,
    wasm_validate_seed_phrase,
    wasm_validate_view_key,
    wasm_get_tip_height,
    wasm_create_console_progress_callback,
    wasm_create_rate_limited_progress_callback,
    wasm_scan_with_memory_management,
    wasm_force_garbage_collection,
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
    .description('CLI client for Tari WASM Scanner with seed phrase and view key support')
    .version(packageInfo.version || 'unknown')
    .usage('[options]');

// CLI Arguments matching scanner.rs
program
    .option('-s, --seed-phrase <phrase>', 'Seed phrase for the wallet (uses memory-only storage)')
    .option('--view-key <key>', 'Private view key in hex format (64 characters). Uses memory-only storage')
    .option('-b, --base-url <url>', 'Base URL for Tari base node HTTP endpoint', 'http://127.0.0.1:18142')
    .option('--from-block <height>', 'Starting block height (defaults to wallet birthday or 0)', parseInteger)
    .option('--to-block <height>', 'Ending block height (defaults to current tip)', parseInteger)
    .option('--blocks <heights>', 'Specific block heights to scan (comma-separated). Overrides from-block and to-block', parseBlockList)
    .option('--batch-size <size>', 'Batch size for scanning', parseInteger, 10)
    .option('--progress-frequency <freq>', 'Update progress every N blocks', parseInteger, 10)
    .option('-q, --quiet', 'Quiet mode - only show essential information', false)
    .option('--format <format>', 'Output format: detailed, summary, json', 'summary')
    .option('--memory-limit <mb>', 'Memory limit in MB for result storage', parseInteger, 64)
    .option('--request-timeout <seconds>', 'Request timeout in seconds', parseInteger, 30)
    .option('--scan-stealth-addresses', 'Enable stealth address scanning', true)
    .option('--no-scan-stealth-addresses', 'Disable stealth address scanning')
    .option('--max-addresses-per-account <max>', 'Maximum addresses per account', parseInteger, 1000)
    .option('--scan-imported-keys', 'Enable imported key scanning', true)
    .option('--no-scan-imported-keys', 'Disable imported key scanning')
    .option('--rate-limit-progress <ms>', 'Rate limit progress updates (milliseconds)', parseInteger)
    .option('--force-gc', 'Force garbage collection after scan', false);

/**
 * Parse integer from string with validation
 */
function parseInteger(value) {
    const parsed = parseInt(value, 10);
    if (isNaN(parsed) || parsed < 0) {
        throw new Error(`Invalid number: ${value}`);
    }
    return parsed;
}

/**
 * Parse comma-separated block list
 */
function parseBlockList(value) {
    return value.split(',').map(block => {
        const parsed = parseInteger(block.trim());
        return parsed;
    });
}

/**
 * Validate CLI arguments
 */
function validateArgs(options) {
    const errors = [];

    // Must provide either seed phrase or view key
    if (!options.seedPhrase && !options.viewKey) {
        errors.push('Must provide either --seed-phrase or --view-key');
    }

    if (options.seedPhrase && options.viewKey) {
        errors.push('Cannot provide both --seed-phrase and --view-key');
    }

    // Validate seed phrase format
    if (options.seedPhrase && !wasm_validate_seed_phrase(options.seedPhrase)) {
        errors.push('Invalid seed phrase format');
    }

    // Validate view key format
    if (options.viewKey && !wasm_validate_view_key(options.viewKey)) {
        errors.push('Invalid view key format (must be 64 hex characters)');
    }

    // Validate format option
    const validFormats = ['detailed', 'summary', 'json'];
    if (!validFormats.includes(options.format)) {
        errors.push(`Invalid format: ${options.format}. Valid options: ${validFormats.join(', ')}`);
    }

    // Validate block range
    if (options.fromBlock !== undefined && options.toBlock !== undefined) {
        if (options.fromBlock >= options.toBlock) {
            errors.push('from-block must be less than to-block');
        }
    }

    // Validate batch size
    if (options.batchSize <= 0) {
        errors.push('batch-size must be greater than 0');
    }

    if (options.batchSize > 1000) {
        console.warn(chalk.yellow(`Warning: Large batch size (${options.batchSize}) may cause performance issues`));
    }

    return errors;
}

/**
 * Create WASM scan configuration from CLI options
 */
function createScanConfig(options) {
    const config = new WasmScanConfig(options.baseUrl);
    
    if (options.fromBlock !== undefined) config.set_from_block(options.fromBlock);
    if (options.toBlock !== undefined) config.set_to_block(options.toBlock);
    if (options.blocks) config.set_blocks(options.blocks);
    
    config.set_batch_size(options.batchSize);
    config.set_progress_frequency(options.progressFrequency);
    config.set_request_timeout_seconds(options.requestTimeout);
    config.set_scan_stealth_addresses(options.scanStealthAddresses);
    config.set_max_addresses_per_account(options.maxAddressesPerAccount);
    config.set_scan_imported_keys(options.scanImportedKeys);
    config.set_quiet(options.quiet);

    // Set output format
    const wasmFormat = options.format === 'detailed' ? WasmOutputFormat.Detailed :
                      options.format === 'json' ? WasmOutputFormat.Json :
                      WasmOutputFormat.Summary;
    config.set_output_format(wasmFormat);

    return config;
}

/**
 * Create progress callback based on options
 */
function createProgressCallback(options) {
    if (options.quiet) {
        return null; // No progress updates in quiet mode
    }

    // Create base progress callback
    const baseCallback = (progress) => {
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
    };

    // Apply rate limiting if specified
    if (options.rateLimitProgress) {
        return wasm_create_rate_limited_progress_callback(baseCallback, options.rateLimitProgress);
    }

    return baseCallback;
}

/**
 * Display scan results
 */
function displayResults(results, options) {
    if (options.format === 'json') {
        console.log(JSON.stringify(results, null, 2));
        return;
    }

    const balance = (results.total_balance / 1000000).toFixed(6); // Convert to Tari
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
 * Main scanner function
 */
async function runScan(options) {
    const spinner = ora('Initializing WASM module...').start();
    
    try {
        // Initialize WASM module
        await init();
        spinner.succeed('WASM module initialized');

        // Validate arguments
        const validationErrors = validateArgs(options);
        if (validationErrors.length > 0) {
            spinner.fail('Validation failed');
            validationErrors.forEach(error => console.error(chalk.red('✗ ' + error)));
            process.exit(1);
        }

        // Create scan configuration
        const config = createScanConfig(options);
        
        // Create progress callback
        const progressCallback = createProgressCallback(options);

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

        if (options.seedPhrase) {
            if (options.memoryLimit && options.memoryLimit < 256) {
                // Use memory-managed scanning for smaller limits
                const container = await wasm_scan_with_memory_management(
                    options.seedPhrase,
                    null, // No passphrase support in CLI yet
                    config,
                    options.memoryLimit,
                    progressCallback
                );
                results = container.get_results();
                container.dispose(); // Clean up
            } else {
                results = await wasm_scan_with_seed_phrase(
                    options.seedPhrase,
                    null, // No passphrase support in CLI yet
                    config,
                    progressCallback
                );
            }
        } else if (options.viewKey) {
            results = await wasm_scan_with_view_key(
                options.viewKey,
                config,
                progressCallback
            );
        }

        spinner.succeed('Blockchain scan completed');

        // Display results
        displayResults(results, options);

        // Force garbage collection if requested
        if (options.forceGc) {
            console.log(chalk.gray('Forcing garbage collection...'));
            wasm_force_garbage_collection();
        }

    } catch (error) {
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

        // Show help if no arguments provided
        if (process.argv.length <= 2) {
            console.log(chalk.blue('Tari WASM Scanner CLI'));
            console.log(chalk.gray('Use --help for usage information'));
            console.log();
            console.log(chalk.yellow('Quick examples:'));
            console.log(chalk.white('  # Scan with seed phrase'));
            console.log(chalk.gray('  ./scanner.js --seed-phrase "your seed phrase here"'));
            console.log();
            console.log(chalk.white('  # Scan with view key'));
            console.log(chalk.gray('  ./scanner.js --view-key "64char_hex_view_key"'));
            console.log();
            console.log(chalk.white('  # Scan specific block range'));
            console.log(chalk.gray('  ./scanner.js --view-key "key" --from-block 1000 --to-block 2000'));
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

// Handle process signals
process.on('SIGINT', () => {
    console.log(chalk.yellow('\n⚠ Scan interrupted by user'));
    console.log(chalk.gray('Cleaning up...'));
    wasm_force_garbage_collection();
    process.exit(130);
});

process.on('SIGTERM', () => {
    console.log(chalk.yellow('\n⚠ Scan terminated'));
    process.exit(143);
});

// Run the CLI
main().catch(error => {
    console.error(chalk.red('Fatal error:'), error);
    process.exit(1);
});
