#!/usr/bin/env node

/**
 * Enhanced Tari WASM Scanner - Demonstration of lib's enhanced scanning functionality
 * 
 * This example demonstrates how to use the Tari WASM scanner with the new enhanced
 * scanning functionality, including:
 * - Progress callbacks with real-time updates
 * - Cancellation support
 * - Memory-only storage (WASM-compatible)
 * - Comprehensive error handling
 * - Animated progress bars
 * 
 * Usage:
 *   node examples/wasm/enhanced_scanner.js [seed_phrase_or_view_key] [base_node_url]
 * 
 * Examples:
 *   # Using seed phrase (full wallet functionality)
 *   node examples/wasm/enhanced_scanner.js "your 24 word seed phrase here" 
 *   
 *   # Using view key (view-only access)
 *   node examples/wasm/enhanced_scanner.js "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab"
 *   
 *   # With custom base node URL
 *   node examples/wasm/enhanced_scanner.js "your seed phrase" "http://192.168.1.100:9000"
 * 
 * Requirements:
 *   - Build the WASM package first: npm run build-enhanced
 *   - Node.js 16+ for proper WASM support
 */

const path = require('path');

// Initialize the WASM module
let wasm;

/**
 * Initialize WASM module
 */
async function initWasm() {
    try {
        // Import the WASM module
        wasm = await import(path.resolve(__dirname, 'pkg', 'lightweight_wallet_libs.js'));
        // console.log(wasm)
        // await wasm.default(); // Initialize the WASM module
        console.log('🚀 WASM module initialized successfully');
        return true;
    } catch (error) {
        console.error('❌ Failed to initialize WASM module:', error.message);
        console.log('\n💡 Make sure to build the WASM package first:');
        console.log('   npm run build-enhanced');
        return false;
    }
}

/**
 * Enhanced progress display with animated progress bar
 */
class ProgressDisplay {
    constructor() {
        this.startTime = Date.now();
        this.lastUpdate = 0;
    }

    /**
     * Update progress display with animation
     */
    update(progress) {
        // Throttle updates to avoid console spam
        const now = Date.now();
        if (now - this.lastUpdate < 100) return; // Update max 10 times per second
        this.lastUpdate = now;

        const {
            current_block,
            total_blocks,
            blocks_processed,
            outputs_found,
            inputs_found,
            progress_percent,
            blocks_per_second,
            phase,
            elapsed_seconds,
            remaining_seconds
        } = progress;

        // Create animated progress bar
        const barWidth = 40;
        const filledWidth = Math.floor((progress_percent / 100) * barWidth);
        const bar = '█'.repeat(filledWidth) + '░'.repeat(barWidth - filledWidth);

        // Format time
        const formatTime = (seconds) => {
            if (!seconds || !isFinite(seconds)) return 'Unknown';
            const mins = Math.floor(seconds / 60);
            const secs = Math.floor(seconds % 60);
            return `${mins}:${secs.toString().padStart(2, '0')}`;
        };

        // Format numbers with commas
        const formatNumber = (num) => num.toLocaleString();

        // Build progress display
        const progressLine = `[${bar}] ${progress_percent.toFixed(1)}% ${phase}`;
        const statsLine = `Block ${formatNumber(current_block)} | ${blocks_per_second.toFixed(1)} blocks/s | Found: ${formatNumber(outputs_found)} outputs, ${formatNumber(inputs_found)} spent`;
        const timeLine = `Elapsed: ${formatTime(elapsed_seconds)} | Remaining: ${formatTime(remaining_seconds)} | ${formatNumber(blocks_processed)}/${formatNumber(total_blocks)} blocks`;

        // Clear previous lines and write new progress
        process.stdout.write('\r\x1b[K' + progressLine);
        process.stdout.write('\n\r\x1b[K' + statsLine);
        process.stdout.write('\n\r\x1b[K' + timeLine);
        process.stdout.write('\r\x1b[2A'); // Move cursor back up
    }

    /**
     * Complete the progress display
     */
    complete(result) {
        // Move cursor down and clear
        process.stdout.write('\r\x1b[3B\x1b[K');
        
        if (result.completed) {
            console.log('\n✅ Scan completed successfully!');
        } else if (result.interrupted) {
            console.log('\n⚠️ Scan was interrupted');
        } else {
            console.log('\n❌ Scan failed');
        }
    }
}

/**
 * Enhanced WASM scanner demonstration
 */
async function demonstrateEnhancedScanner(input, baseUrl = 'http://127.0.0.1:9000') {
    console.log('🔍 Enhanced Tari WASM Scanner Demo');
    console.log('=================================\n');

    try {
        // Detect input type (view key vs seed phrase)
        const isViewKey = /^[a-fA-F0-9]{64}$/.test(input.trim());
        const isSeedPhrase = input.trim().split(' ').length >= 12;

        if (!isViewKey && !isSeedPhrase) {
            throw new Error('Input must be either a 64-character hex view key or a seed phrase (12+ words)');
        }

        console.log(`🔑 Input type: ${isViewKey ? 'View Key (view-only)' : 'Seed Phrase (full wallet)'}`);
        console.log(`🌐 Base node URL: ${baseUrl}`);

        // Create enhanced scanner
        console.log('\n📦 Creating enhanced scanner...');
        const scanner = isViewKey 
            ? wasm.EnhancedWasmScanner.new_from_view_key(input.trim())
            : new wasm.EnhancedWasmScanner(input.trim());

        console.log('✅ Scanner created');

        // Initialize HTTP connection
        console.log('🌐 Initializing HTTP scanner...');
        await scanner.initialize_scanner(baseUrl);
        console.log('✅ HTTP scanner initialized');

        // Configure scan (scan last 100 blocks as demo)
        console.log('⚙️ Configuring scan parameters...');
        const currentBlock = 60000; // Demo: would normally get from base node
        const fromBlock = currentBlock - 100;
        const toBlock = currentBlock;
        const batchSize = 10;

        scanner.configure_scan(fromBlock, toBlock, batchSize);
        console.log(`✅ Configured to scan blocks ${fromBlock.toLocaleString()} to ${toBlock.toLocaleString()}`);

        // Create cancellation token
        scanner.create_cancellation_token();
        console.log('🛑 Cancellation token created (Press Ctrl+C to cancel)');

        // Setup progress display
        const progressDisplay = new ProgressDisplay();

        // Setup Ctrl+C cancellation
        process.on('SIGINT', () => {
            console.log('\n\n🛑 Cancelling scan...');
            scanner.cancel_scan();
        });

        // Define progress callback
        const progressCallback = (progress) => {
            progressDisplay.update(progress);
        };

        console.log('\n🚀 Starting enhanced scan...\n');

        // Perform the scan
        const result = await scanner.scan_wallet(progressCallback);

        // Complete progress display
        progressDisplay.complete(result);

        // Display results
        console.log('\n📊 SCAN RESULTS');
        console.log('===============');
        console.log(`Status: ${result.completed ? '✅ Completed' : result.interrupted ? '⚠️ Interrupted' : '❌ Failed'}`);
        
        if (result.error) {
            console.log(`Error: ${result.error}`);
        } else {
            console.log(`Duration: ${result.duration_seconds.toFixed(2)} seconds`);
            console.log(`Transactions found: ${result.transaction_count.toLocaleString()}`);
            console.log(`Total received: ${(result.total_received / 1_000_000).toFixed(6)} T`);
            console.log(`Total spent: ${(result.total_spent / 1_000_000).toFixed(6)} T`);
            console.log(`Current balance: ${(result.current_balance / 1_000_000).toFixed(6)} T`);
            console.log(`Unspent outputs: ${result.unspent_count.toLocaleString()}`);
            console.log(`Spent outputs: ${result.spent_count.toLocaleString()}`);
        }

        console.log('\n🎉 Demo completed!');

    } catch (error) {
        console.error('\n❌ Scanner error:', error.message);
        console.error('Stack trace:', error.stack);
    }
}

/**
 * Main function
 */
async function main() {
    // Parse command line arguments
    const args = process.argv.slice(2);
    
    if (args.length === 0) {
        console.log('Enhanced Tari WASM Scanner Demo');
        console.log('Usage: node enhanced_scanner.js [seed_phrase_or_view_key] [base_node_url]');
        console.log('\nExamples:');
        console.log('  node enhanced_scanner.js "your 24 word seed phrase here"');
        console.log('  node enhanced_scanner.js "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab"');
        console.log('  node enhanced_scanner.js "your seed phrase" "http://192.168.1.100:9000"');
        process.exit(1);
    }

    const input = args[0];
    const baseUrl = args[1] || 'http://127.0.0.1:9000';

    // Initialize WASM
    const wasmInitialized = await initWasm();
    if (!wasmInitialized) {
        process.exit(1);
    }

    // Run demonstration
    await demonstrateEnhancedScanner(input, baseUrl);
}

/**
 * Handle uncaught errors gracefully
 */
process.on('unhandledRejection', (reason, promise) => {
    console.error('\n❌ Unhandled promise rejection:', reason);
    process.exit(1);
});

process.on('uncaughtException', (error) => {
    console.error('\n❌ Uncaught exception:', error.message);
    process.exit(1);
});

// Run the demo
if (require.main === module) {
    main().catch(error => {
        console.error('\n❌ Demo failed:', error.message);
        process.exit(1);
    });
}

module.exports = { demonstrateEnhancedScanner, initWasm }; 