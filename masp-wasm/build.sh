#!/bin/bash
# Build MASP WASM module with optimizations
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/../webapp/public/wasm"

# Note: wasm-opt is disabled by default because it can cause "failed to grow table"
# errors at runtime with certain optimization levels. The Rust-level optimizations
# (opt-level=3, lto=fat) already provide good performance.
USE_WASM_OPT=${USE_WASM_OPT:-false}

echo "[1/2] Building WASM with wasm-pack..."
wasm-pack build --target web --out-dir "$OUT_DIR"

# Restore .gitignore that wasm-pack overwrites
cat > "$OUT_DIR/.gitignore" << 'EOF'
# Ignore wasm-pack generated files except what we need
*
!.gitignore
!masp_wasm.js
!masp_wasm.d.ts
!masp_wasm_bg.wasm
!masp_wasm_bg.wasm.d.ts
!prover-worker.js
EOF

if [ "$USE_WASM_OPT" = "true" ]; then
    echo "[2/2] Optimizing WASM with wasm-opt..."
    if command -v wasm-opt &> /dev/null; then
        WASM_FILE="$OUT_DIR/masp_wasm_bg.wasm"
        ORIGINAL_SIZE=$(stat -f%z "$WASM_FILE" 2>/dev/null || stat -c%s "$WASM_FILE")

        # Use conservative -O2 optimization (not -O3 which can cause issues)
        wasm-opt -O2 "$WASM_FILE" -o "$WASM_FILE.opt"
        mv "$WASM_FILE.opt" "$WASM_FILE"

        OPTIMIZED_SIZE=$(stat -f%z "$WASM_FILE" 2>/dev/null || stat -c%s "$WASM_FILE")
        echo "   Original: $(echo "scale=1; $ORIGINAL_SIZE/1024" | bc)KB"
        echo "   Optimized: $(echo "scale=1; $OPTIMIZED_SIZE/1024" | bc)KB"
        echo "   Saved: $(echo "scale=1; ($ORIGINAL_SIZE-$OPTIMIZED_SIZE)/1024" | bc)KB"
    else
        echo "   wasm-opt not found, skipping optimization"
        echo "   Install with: apt-get install binaryen"
    fi
else
    echo "[2/2] Skipping wasm-opt (disabled by default)"
    echo "   To enable: USE_WASM_OPT=true ./build.sh"
fi

echo ""
echo "Done! Output: $OUT_DIR"
FINAL_SIZE=$(stat -f%z "$OUT_DIR/masp_wasm_bg.wasm" 2>/dev/null || stat -c%s "$OUT_DIR/masp_wasm_bg.wasm")
echo "WASM size: $(echo "scale=1; $FINAL_SIZE/1024" | bc)KB"
