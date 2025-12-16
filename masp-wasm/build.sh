#!/bin/bash
# Build MASP WASM module with optimizations
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/../webapp/public/wasm"

echo "[1/3] Building WASM with wasm-pack..."
wasm-pack build --target web --out-dir "$OUT_DIR"

echo "[2/3] Optimizing WASM with wasm-opt..."
if command -v wasm-opt &> /dev/null; then
    WASM_FILE="$OUT_DIR/masp_wasm_bg.wasm"
    ORIGINAL_SIZE=$(stat -f%z "$WASM_FILE" 2>/dev/null || stat -c%s "$WASM_FILE")

    wasm-opt -O3 --enable-bulk-memory "$WASM_FILE" -o "$WASM_FILE.opt"
    mv "$WASM_FILE.opt" "$WASM_FILE"

    OPTIMIZED_SIZE=$(stat -f%z "$WASM_FILE" 2>/dev/null || stat -c%s "$WASM_FILE")
    echo "   Original: $(echo "scale=1; $ORIGINAL_SIZE/1024" | bc)KB"
    echo "   Optimized: $(echo "scale=1; $OPTIMIZED_SIZE/1024" | bc)KB"
    echo "   Saved: $(echo "scale=1; ($ORIGINAL_SIZE-$OPTIMIZED_SIZE)/1024" | bc)KB"
else
    echo "   wasm-opt not found, skipping optimization"
    echo "   Install with: apt-get install binaryen"
fi

echo "[3/3] Done!"
echo "Output: $OUT_DIR"
