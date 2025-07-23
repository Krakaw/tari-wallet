#!/usr/bin/env node

/**
 * Tari WASM Scanner - Node.js CLI Client
 * 
 * This CLI client uses the modern scanner engine and async wrapper functions
 * for robust blockchain scanning with JSON output.
 * 
 * Usage:
 *   node examples/wasm/scanner.js [options]
 * 
 * Options:
 *   --data <string>           View key or seed phrase (required)
 *   --base-url <url>          Base node URL (default: https://rpc.tari.com)
 *   --mode <mode>             Scan mode: 'range' or 'specific' (default: range)
 *   --start-height <number>   Start height for range mode (default: 0)
 *   --end-height <number>     End height for range mode (optional)
 *   --heights <numbers>       Comma-separated heights for specific mode
 *   --batch-size <number>     Batch size for processing (default: 50)
 *   --progress                Show progress updates
 *   --streaming               Use streaming scan for memory efficiency
 *   --health-check            Perform health check before scanning
 *   --memory-stats            Show memory statistics
 *   --max-retries <number>    Maximum retries for initialization (default: 3)
 *   --help                    Show help message
 * 
 * Examples:
 *   node scanner.js --data "your_hex_view_key" --start-height 1000 --end-height 2000
 *   node scanner.js --data "your 24 word seed phrase" --mode specific --heights "100,200,300"
 *   node scanner.js --data "key_or_phrase" --streaming --progress --batch-size 50
 * 
 * Output:
 *   All results are output as JSON to stdout for easy parsing by other tools.
 */

const fs = require('fs');
const path = require('path');

// Polyfills for Node.js to make WASM work with wasm-node feature
if (typeof global !== 'undefined' && !global.fetch) {
    // Set up global fetch for Node.js WASM target
    const fetch = require('node-fetch');
    
    // Set fetch as a global function that WASM can access
    global.fetch = fetch;
    
    // Also add Response and Request constructors
    global.Response = fetch.Response;
    global.Request = fetch.Request;
    global.Headers = fetch.Headers;
}

/**
 * CLI Scanner using the modern scanner engine
 */
class CLIScanner {
    constructor(options = {}) {
        this.options = {
            baseUrl: 'https://rpc.tari.com',
            batchSize: 50,
            maxRetries: 3,
            showProgress: true,
            useStreaming: false,
            ...options
        };
        
        this.wasm = null;
        this.scanner = null;
        this.results = {
            success: false,
            error: null,
            scanner_info: {},
            connection_status: {},
            scan_results: {},
            memory_stats: {},
            health_check: {},
            performance: {
                initialization_time_ms: 0,
                scan_time_ms: 0,
                total_time_ms: 0
            }
        };
        this.startTime = Date.now();
    }

    /**
     * Initialize WASM module and create scanner with modern scanner engine
     */
    async init() {
        const initStart = Date.now();
        
        try {
            const wasmPath = path.join(__dirname, 'pkg_node/lightweight_wallet_libs.js');
            
            if (!fs.existsSync(wasmPath)) {
                throw new Error(`WASM module not found. Build with: wasm-pack build --target nodejs --out-dir examples/wasm/pkg_node --features http,wasm-node`);
            }

            if (this.options.showProgress) {
                console.error(`Loading WASM from: ${wasmPath}`);
            }
            
            this.wasm = require(wasmPath);
            
            if (this.options.showProgress) {
                console.error(`WASM module loaded, initializing...`);
            }
            
            // For Node.js builds, we need to initialize the WASM module synchronously
            const wasmBinaryPath = path.join(__dirname, 'pkg_node/lightweight_wallet_libs_bg.wasm');
            const wasmBinary = fs.readFileSync(wasmBinaryPath);
            
            if (typeof this.wasm.initSync === 'function') {
                this.wasm.initSync(wasmBinary);
            } else if (typeof this.wasm.default === 'function') {
                await this.wasm.default(wasmBinary);
            }
            
            if (this.options.showProgress) {
                console.error(`WASM initialized, getting version...`);
            }
            
            this.results.scanner_info = {
                version: this.wasm.get_version(),
                wasm_loaded: true,
                features: 'http',
                timestamp: new Date().toISOString()
            };
            
            this.results.performance.initialization_time_ms = Date.now() - initStart;
            
            if (this.options.showProgress) {
                console.error(`WASM initialized successfully, version: ${this.results.scanner_info.version}`);
            }
            
        } catch (error) {
            console.error(`WASM initialization error:`, error);
            this.results.error = `Failed to initialize WASM: ${error.message}`;
            throw error;
        }
    }

    /**
     * Create and initialize scanner using modern async initialization
     */
    async createAndInitializeScanner(data) {
        try {
            if (!data) {
                throw new Error('Scanner data (view key or seed phrase) is required');
            }

            if (this.options.showProgress) {
                process.stderr.write(`Initializing scanner with ${this.options.maxRetries} max retries...\n`);
            }

            // Use the modern async initialization with retries
            this.scanner = await this.wasm.create_and_initialize_scanner_async(
                data,
                this.options.baseUrl,
                this.options.maxRetries
            );
            
            this.results.scanner_info.scanner_created = true;
            this.results.scanner_info.data_type = data.split(' ').length > 10 ? 'seed_phrase' : 'view_key';
            this.results.scanner_info.base_url = this.options.baseUrl;
            this.results.scanner_info.max_retries = this.options.maxRetries;
            
            if (this.options.showProgress) {
                process.stderr.write(`✅ Scanner initialized successfully\n`);
            }
            
        } catch (error) {
            console.error('Scanner initialization error:', error);
            this.results.error = `Failed to create and initialize scanner: ${error.message}`;
            this.results.scanner_info.initialization_failed = true;
            this.results.scanner_info.error = error.message;
            throw error;
        }
    }

    /**
     * Perform health check using modern health check function
     */
    async performHealthCheck() {
        try {
            const healthResult = await this.wasm.check_scanner_health(this.scanner);
            const health = JSON.parse(healthResult);
            
            this.results.health_check = health;
            this.results.connection_status = {
                connected: health.connectivity_ok || false,
                base_url: this.options.baseUrl,
                scanner_engine_initialized: health.scanner_engine_initialized,
                wallet_context_available: health.wallet_context_available,
                has_view_key: health.has_view_key,
                transaction_count: health.transaction_count
            };

            if (health.tip_info) {
                this.results.connection_status.chain_tip_height = health.tip_info.metadata?.best_block_height;
            }

            if (health.connectivity_error) {
                this.results.connection_status.error = health.connectivity_error;
            }
            
            return health.connectivity_ok !== false;
        } catch (error) {
            this.results.health_check = { error: error.message };
            this.results.connection_status = {
                connected: false,
                error: error.message
            };
            return false;
        }
    }

    /**
     * Get memory statistics using modern memory stats function
     */
    getMemoryStats() {
        try {
            const statsResult = this.wasm.get_scanner_memory_stats(this.scanner);
            const stats = JSON.parse(statsResult);
            
            this.results.memory_stats = stats;
            return stats;
        } catch (error) {
            this.results.memory_stats = { error: error.message };
            return null;
        }
    }

    /**
     * Scan blocks using range mode with modern scanner engine
     */
    async scanRange(startHeight, endHeight = null) {
        const scanStart = Date.now();
        
        try {
            let scanResult;
            
            if (this.options.useStreaming) {
                // Use streaming scan for memory efficiency
                scanResult = await this.streamingScan(startHeight, endHeight);
            } else {
                // Use memory-optimized scan
                scanResult = await this.memoryOptimizedScan(startHeight, endHeight);
            }

            this.results.scan_results = scanResult;
            this.results.performance.scan_time_ms = Date.now() - scanStart;
            return scanResult;
            
        } catch (error) {
            this.results.scan_results = {
                success: false,
                error: error.message,
                start_height: startHeight,
                end_height: endHeight
            };
            this.results.performance.scan_time_ms = Date.now() - scanStart;
            throw error;
        }
    }

    /**
     * Scan specific block heights using modern multiple ranges function
     */
    async scanSpecificHeights(heights) {
        const scanStart = Date.now();
        
        try {
            // Convert heights to scan ranges format
            const ranges = heights.map(height => ({ from_height: height, to_height: height }));
            const rangesJson = JSON.stringify(ranges);
            
            let progressCallback = null;
            if (this.options.showProgress) {
                progressCallback = (progressData) => {
                    const progress = JSON.parse(progressData);
                    process.stderr.write(`Progress: ${progress.overall_progress.toFixed(1)}% - Block ${progress.current_height} - ${progress.transactions_found} transactions\r`);
                };
            }

            const resultJson = await this.wasm.scan_multiple_ranges_async(
                this.scanner,
                rangesJson,
                this.options.batchSize,
                progressCallback
            );
            
            const result = JSON.parse(resultJson);
            this.results.scan_results = result;
            this.results.performance.scan_time_ms = Date.now() - scanStart;
            return result;
            
        } catch (error) {
            this.results.scan_results = {
                success: false,
                error: error.message,
                heights: heights
            };
            this.results.performance.scan_time_ms = Date.now() - scanStart;
            throw error;
        }
    }

    /**
     * Memory-optimized scan using modern async wrapper
     */
    async memoryOptimizedScan(startHeight, endHeight) {
        if (this.options.showProgress) {
            process.stderr.write(`Memory-optimized scan: blocks ${startHeight} to ${endHeight || 'tip'}...\n`);
        }

        // Use the modern memory management async function
        // Convert heights to BigInt for WASM u64 parameters
        const resultJson = await this.wasm.scan_with_memory_management_async(
            this.scanner,
            BigInt(startHeight),
            BigInt(endHeight || 0)
        );
        
        return JSON.parse(resultJson);
    }

    /**
     * Streaming scan using modern streaming function for memory efficiency
     */
    async streamingScan(startHeight, endHeight) {
        if (this.options.showProgress) {
            process.stderr.write(`Streaming scan: blocks ${startHeight} to ${endHeight || 'tip'}...\n`);
        }

        let progressCallback = null;
        if (this.options.showProgress) {
            progressCallback = (progressData) => {
                const progress = JSON.parse(progressData);
                process.stderr.write(`Progress: ${progress.percentage.toFixed(1)}% - Block ${progress.current_height} - ${progress.transactions_found} transactions - Memory: ${progress.memory_usage}\r`);
            };
        }

        // Use the modern streaming async function
        // Convert heights to BigInt for WASM u64 parameters
        const resultJson = await this.wasm.scan_blocks_streaming_async(
            this.scanner,
            BigInt(startHeight),
            BigInt(endHeight || 0),
            this.options.batchSize,
            progressCallback
        );
        
        return JSON.parse(resultJson);
    }

    /**
     * Optimize scanner memory using modern optimization function
     */
    optimizeMemory() {
        try {
            const optimizeResult = this.wasm.optimize_scanner_memory(this.scanner);
            const optimization = JSON.parse(optimizeResult);
            
            this.results.memory_optimization = optimization;
            return optimization;
        } catch (error) {
            this.results.memory_optimization = { error: error.message };
            return null;
        }
    }

    /**
     * Get final results
     */
    getResults() {
        this.results.success = !this.results.error;
        this.results.performance.total_time_ms = Date.now() - this.startTime;
        
        // Add summary statistics
        if (this.results.scan_results && this.results.scan_results.success) {
            this.results.summary = {
                blocks_processed: this.results.scan_results.blocks_processed,
                transactions_found: this.results.scan_results.transactions?.length || 0,
                total_outputs: this.results.scan_results.total_outputs,
                total_spent: this.results.scan_results.total_spent,
                current_balance_microtari: this.results.scan_results.current_balance,
                current_balance_tari: (this.results.scan_results.current_balance / 1000000).toFixed(6),
                total_value_microtari: this.results.scan_results.total_value,
                total_value_tari: (this.results.scan_results.total_value / 1000000).toFixed(6)
            };
        }
        
        return this.results;
    }
}

/**
 * Parse command line arguments
 */
function parseArgs() {
    const args = process.argv.slice(2);
    const options = {
        data: null,
        baseUrl: 'https://rpc.tari.com',
        mode: 'range',
        startHeight: 0,
        endHeight: null,
        heights: [],
        batchSize: 50,
        maxRetries: 3,
        showProgress: false,
        useStreaming: false,
        healthCheck: true, // Default to true for modern scanner
        memoryStats: false,
        help: false
    };

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        
        switch (arg) {
            case '--data':
                options.data = args[++i];
                break;
            case '--base-url':
                options.baseUrl = args[++i];
                break;
            case '--mode':
                options.mode = args[++i];
                break;
            case '--start-height':
                options.startHeight = parseInt(args[++i]);
                break;
            case '--end-height':
                options.endHeight = parseInt(args[++i]);
                break;
            case '--heights':
                options.heights = args[++i].split(',').map(h => parseInt(h.trim()));
                break;
            case '--batch-size':
                options.batchSize = parseInt(args[++i]);
                break;
            case '--max-retries':
                options.maxRetries = parseInt(args[++i]);
                break;
            case '--progress':
                options.showProgress = true;
                break;
            case '--streaming':
                options.useStreaming = true;
                break;
            case '--health-check':
                options.healthCheck = true;
                break;
            case '--memory-stats':
                options.memoryStats = true;
                break;
            case '--help':
                options.help = true;
                break;
            default:
                if (!arg.startsWith('--') && !options.data) {
                    options.data = arg; // Allow data as positional argument
                }
                break;
        }
    }

    return options;
}

/**
 * Show help message
 */
function showHelp() {
    console.log(`
Tari WASM Scanner - Node.js CLI Client (Modern Scanner Engine)

Usage:
  node scanner.js [options]

Options:
  --data <string>           View key or seed phrase (required)
  --base-url <url>          Base node URL (default: https://rpc.tari.com)
  --mode <mode>             Scan mode: 'range' or 'specific' (default: range)
  --start-height <number>   Start height for range mode (default: 0)
  --end-height <number>     End height for range mode (optional, defaults to tip)
  --heights <numbers>       Comma-separated heights for specific mode
  --batch-size <number>     Batch size for processing (default: 50)
  --max-retries <number>    Maximum retries for initialization (default: 3)
  --progress                Show progress updates to stderr
  --streaming               Use streaming scan for memory efficiency
  --health-check            Perform health check before scanning (default: true)
  --memory-stats            Include memory statistics in output
  --help                    Show this help message

Examples:
  # Range scan with progress
  node scanner.js --data "your_hex_view_key" --start-height 1000 --end-height 2000 --progress

  # Specific heights scan
  node scanner.js --data "your 24 word seed phrase" --mode specific --heights "100,200,300"

  # Streaming scan for large ranges
  node scanner.js --data "key_or_phrase" --streaming --progress --batch-size 25

  # Full scan with health check and memory stats
  node scanner.js --data "key_or_phrase" --health-check --memory-stats --start-height 0

Features:
  - Uses modern scanner engine with robust error handling
  - Automatic retry logic for network failures
  - Memory-optimized scanning for large ranges
  - Streaming support for minimal memory usage
  - Health checks for scanner and connectivity status
  - Comprehensive memory statistics and performance metrics

Output:
  All results are output as JSON to stdout.
  Progress messages (if enabled) are sent to stderr.
`);
}

/**
 * Main execution function
 */
async function main() {
    const options = parseArgs();

    if (options.help) {
        showHelp();
        return;
    }

    if (!options.data) {
        console.error('Error: --data parameter is required');
        showHelp();
        process.exit(1);
    }

    const scanner = new CLIScanner(options);

    try {
        // Initialize WASM module
        await scanner.init();

        // Create and initialize scanner with modern async initialization
        await scanner.createAndInitializeScanner(options.data);

        // Perform health check (always done with modern scanner)
        if (options.healthCheck) {
            const connected = await scanner.performHealthCheck();
            if (!connected) {
                throw new Error('Health check failed - scanner or connectivity issues detected');
            }
        }

        // Only proceed with scanning if we have a valid scanner
        if (!scanner.scanner) {
            throw new Error('Scanner not properly initialized');
        }

        // Perform scanning based on mode
        if (options.mode === 'specific') {
            if (options.heights.length === 0) {
                throw new Error('Heights must be specified for specific mode');
            }
            await scanner.scanSpecificHeights(options.heights);
        } else {
            await scanner.scanRange(options.startHeight, options.endHeight);
        }

        // Get memory stats if requested
        if (options.memoryStats) {
            scanner.getMemoryStats();
        }

        // Optimize memory for large scans
        if (options.useStreaming || (options.endHeight && (options.endHeight - options.startHeight) > 1000)) {
            scanner.optimizeMemory();
        }

        // Clear progress line if shown
        if (options.showProgress) {
            process.stderr.write('\n');
        }

        // Output final results as JSON
        const results = scanner.getResults();
        console.log(JSON.stringify(results, null, 2));

    } catch (error) {
        // Clear progress line if shown
        if (options.showProgress) {
            process.stderr.write('\n');
        }
        
        // Ensure error is properly set in results
        scanner.results.error = error.message;
        scanner.results.success = false;
        
        // Output error results as JSON
        const results = scanner.getResults();
        console.log(JSON.stringify(results, null, 2));
        process.exit(1);
    }
}

/**
 * Handle unhandled errors
 */
process.on('unhandledRejection', (error) => {
    console.error(JSON.stringify({
        success: false,
        error: `Unhandled promise rejection: ${error.message}`,
        timestamp: new Date().toISOString()
    }, null, 2));
    process.exit(1);
});

process.on('uncaughtException', (error) => {
    console.error(JSON.stringify({
        success: false,
        error: `Uncaught exception: ${error.message}`,
        timestamp: new Date().toISOString()
    }, null, 2));
    process.exit(1);
});

// Run if executed directly
if (require.main === module) {
    main();
}

// Export for use as a module
module.exports = {
    CLIScanner,
    parseArgs,
    showHelp
};
