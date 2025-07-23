# Tari WASM Scanner CLI

A Node.js CLI client for the Tari WASM Scanner that uses the modern scanner engine with robust error handling, memory optimization, and comprehensive JSON output.

## Features

- **Modern Scanner Engine**: Uses the latest scanner engine with retry logic and robust error handling
- **Memory Optimization**: Supports streaming scans and memory management for large blockchain ranges
- **Health Checks**: Built-in connectivity and scanner health validation
- **Progress Reporting**: Real-time progress updates with detailed statistics
- **JSON Output**: All results are output as structured JSON for easy parsing
- **Multiple Scan Modes**: Range scanning and specific block height scanning
- **Performance Metrics**: Detailed timing and memory usage statistics

## Requirements

- Node.js 14.0.0 or higher
- WASM package built with `wasm-pack`

## Setup

1. Build the WASM package:
```bash
wasm-pack build --target web --out-dir examples/wasm/pkg --features http
```

2. Navigate to the examples/wasm directory:
```bash
cd examples/wasm
```

## Usage

### Basic Range Scan
```bash
node scanner.js --data "your_hex_view_key_or_seed_phrase" --start-height 1000 --end-height 2000
```

### Specific Heights Scan
```bash
node scanner.js --data "your_seed_phrase" --mode specific --heights "100,200,300,1000"
```

### Streaming Scan for Large Ranges
```bash
node scanner.js --data "your_key" --streaming --progress --start-height 0 --end-height 10000
```

### Health Check and Memory Statistics
```bash
node scanner.js --data "your_key" --health-check --memory-stats --start-height 1000
```

### With Progress Updates
```bash
node scanner.js --data "your_key" --progress --start-height 1000 --end-height 2000
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--data <string>` | View key (64 hex chars) or seed phrase (12-24 words) | **Required** |
| `--base-url <url>` | Base node URL | `https://rpc.tari.com` |
| `--mode <mode>` | Scan mode: `range` or `specific` | `range` |
| `--start-height <number>` | Start height for range mode | `0` |
| `--end-height <number>` | End height for range mode | Tip height |
| `--heights <numbers>` | Comma-separated heights for specific mode | - |
| `--batch-size <number>` | Batch size for processing | `50` |
| `--max-retries <number>` | Maximum retries for initialization | `3` |
| `--progress` | Show progress updates to stderr | `false` |
| `--streaming` | Use streaming scan for memory efficiency | `false` |
| `--health-check` | Perform health check before scanning | `true` |
| `--memory-stats` | Include memory statistics in output | `false` |
| `--help` | Show help message | - |

## Output Format

All results are output as JSON to stdout with the following structure:

```json
{
  "success": true,
  "error": null,
  "scanner_info": {
    "version": "0.2.0",
    "wasm_loaded": true,
    "features": "http",
    "scanner_created": true,
    "data_type": "view_key",
    "base_url": "https://rpc.tari.com",
    "max_retries": 3,
    "timestamp": "2024-01-01T12:00:00.000Z"
  },
  "connection_status": {
    "connected": true,
    "base_url": "https://rpc.tari.com",
    "scanner_engine_initialized": true,
    "wallet_context_available": true,
    "has_view_key": true,
    "transaction_count": 0,
    "chain_tip_height": 56484
  },
  "scan_results": {
    "total_outputs": 5,
    "total_spent": 0,
    "total_value": 5000000,
    "current_balance": 5000000,
    "blocks_processed": 1001,
    "transactions": [
      {
        "hash": "abc123...",
        "block_height": 1500,
        "value": 1000000,
        "direction": "inbound",
        "status": "MinedConfirmed",
        "is_spent": false,
        "payment_id": null
      }
    ],
    "success": true,
    "error": null
  },
  "health_check": {
    "scanner_engine_initialized": true,
    "wallet_context_available": true,
    "has_view_key": true,
    "transaction_count": 5,
    "connectivity_ok": true,
    "timestamp": 1640995200000
  },
  "memory_stats": {
    "transaction_count": 5,
    "estimated_transaction_memory_bytes": 2400,
    "wallet_summary": {
      "total_received": 5000000,
      "total_spent": 0,
      "current_balance": 5000000,
      "unspent_outputs": 5,
      "spent_outputs": 0
    },
    "transaction_types": {
      "inbound": 5,
      "outbound": 0,
      "unknown": 0
    },
    "memory_efficiency_tips": [
      "Use streaming scan functions for large ranges",
      "Yield frequently to allow garbage collection",
      "Process in smaller batches",
      "All transaction data is preserved for integrity"
    ]
  },
  "performance": {
    "initialization_time_ms": 150,
    "scan_time_ms": 2500,
    "total_time_ms": 2650
  },
  "summary": {
    "blocks_processed": 1001,
    "transactions_found": 5,
    "total_outputs": 5,
    "total_spent": 0,
    "current_balance_microtari": 5000000,
    "current_balance_tari": "5.000000",
    "total_value_microtari": 5000000,
    "total_value_tari": "5.000000"
  }
}
```

## Modern Scanner Engine Features

This CLI uses the latest scanner engine with the following improvements:

### Robust Initialization
- **Automatic Retry Logic**: Retries failed connections with exponential backoff
- **Health Validation**: Comprehensive health checks before scanning
- **Modern Async Patterns**: Uses async/await throughout for better error handling

### Memory Optimization
- **Streaming Processing**: Process large ranges without loading everything into memory
- **Automatic Memory Management**: Optimizes internal data structures without losing data
- **Transaction Integrity**: All transaction data is preserved (no arbitrary limits)
- **Garbage Collection Friendly**: Yields control to allow proper memory cleanup

### Enhanced Error Handling
- **Detailed Error Messages**: Comprehensive error information in JSON format
- **Graceful Degradation**: Continues operation when possible, fails safely when not
- **Progress Recovery**: Can resume from interruptions

### Performance Monitoring
- **Timing Metrics**: Detailed performance measurements
- **Memory Statistics**: Real-time memory usage tracking
- **Progress Reporting**: Live progress updates with transaction counts

## Examples

### Basic Wallet Scan
```bash
# Scan the last 1000 blocks for a view key
node scanner.js --data "1234567890abcdef..." --start-height 55000 --progress
```

### Large Range with Streaming
```bash
# Scan 10,000 blocks using streaming for memory efficiency
node scanner.js --data "your seed phrase here" --streaming --progress --start-height 40000 --end-height 50000
```

### Specific Block Analysis
```bash
# Check specific blocks for transactions
node scanner.js --data "your_key" --mode specific --heights "45000,45100,45200" --memory-stats
```

### Health Check Only
```bash
# Verify scanner and connectivity without scanning
node scanner.js --data "your_key" --health-check --end-height 0
```

## Error Handling

The CLI outputs structured JSON for both success and error cases:

```json
{
  "success": false,
  "error": "Health check failed - scanner or connectivity issues detected",
  "scanner_info": { ... },
  "connection_status": {
    "connected": false,
    "error": "Request failed: connect ECONNREFUSED 127.0.0.1:18142"
  },
  "performance": {
    "total_time_ms": 1500
  }
}
```

## Integration

The CLI can be easily integrated into scripts and other tools:

```bash
# Parse results with jq
node scanner.js --data "$KEY" --start-height 1000 | jq '.summary.current_balance_tari'

# Check for errors
if ! node scanner.js --data "$KEY" --start-height 1000 | jq -e '.success'; then
    echo "Scan failed"
    exit 1
fi

# Extract transaction count
TXNS=$(node scanner.js --data "$KEY" --start-height 1000 | jq '.summary.transactions_found')
echo "Found $TXNS transactions"
```

## Troubleshooting

### WASM Module Not Found
```
Error: WASM module not found. Build with: wasm-pack build --target web --out-dir examples/wasm/pkg --features http
```
**Solution**: Build the WASM package as shown in the setup instructions.

### Connection Failed
```json
{
  "connection_status": {
    "connected": false,
    "error": "Request failed: connect ECONNREFUSED"
  }
}
```
**Solution**: Check that the base node URL is correct and the node is running.

### Memory Issues
For very large scans, use the streaming option:
```bash
node scanner.js --data "$KEY" --streaming --batch-size 25 --start-height 0
```

## License

This tool is part of the Tari Wallet Libraries project and follows the same BSD-3-Clause license.
