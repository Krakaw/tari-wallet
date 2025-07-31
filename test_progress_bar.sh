#!/bin/bash

echo "Testing ASCII Progress Bar Display..."
echo "======================================"

echo "1. Testing with seed phrase and small block range:"
echo "   This should definitely show the progress bar if it's working"
echo ""

# Test with a known seed phrase and small range
cargo run --bin scanner --features grpc-storage -- \
  --seed-phrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art" \
  --from-block 0 \
  --to-block 10 \
  --base-url "http://127.0.0.1:18142"

echo ""
echo "If you didn't see a progress bar above, check:"
echo "1. Is tari_base_node running on port 18142?"
echo "2. Did you see any error messages?"
echo "3. Did the scan actually start?"
