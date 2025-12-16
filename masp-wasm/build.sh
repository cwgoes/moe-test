#!/bin/bash
# Build MASP WASM module for both main thread and Web Worker
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/../webapp/public/wasm"
WORKER_OUT_DIR="$SCRIPT_DIR/../webapp/public/wasm-worker"

echo "=========================================="
echo "Building MASP WASM modules"
echo "=========================================="

echo ""
echo "[1/3] Building WASM for main thread (--target web)..."
wasm-pack build --target web --out-dir "$OUT_DIR"

# Restore .gitignore that wasm-pack overwrites
cat > "$OUT_DIR/.gitignore" << 'GITIGNORE'
# Ignore wasm-pack generated files except what we need
*
!.gitignore
!masp_wasm.js
!masp_wasm.d.ts
!masp_wasm_bg.wasm
!masp_wasm_bg.wasm.d.ts
!prover-worker.js
GITIGNORE

echo ""
echo "[2/3] Building WASM for Web Worker (--target no-modules)..."
wasm-pack build --target no-modules --out-dir "$WORKER_OUT_DIR"

# Restore .gitignore for worker directory
cat > "$WORKER_OUT_DIR/.gitignore" << 'GITIGNORE'
# Ignore wasm-pack generated files except what we need
*
!.gitignore
!masp_wasm.js
!masp_wasm_bg.wasm
GITIGNORE

echo ""
echo "[3/3] Build complete!"
echo ""
echo "Output directories:"
echo "  Main thread: $OUT_DIR"
echo "  Web Worker:  $WORKER_OUT_DIR"
echo ""

MAIN_SIZE=$(stat -f%z "$OUT_DIR/masp_wasm_bg.wasm" 2>/dev/null || stat -c%s "$OUT_DIR/masp_wasm_bg.wasm")
WORKER_SIZE=$(stat -f%z "$WORKER_OUT_DIR/masp_wasm_bg.wasm" 2>/dev/null || stat -c%s "$WORKER_OUT_DIR/masp_wasm_bg.wasm")

echo "WASM sizes:"
echo "  Main thread: $(echo "scale=1; $MAIN_SIZE/1024" | bc)KB"
echo "  Web Worker:  $(echo "scale=1; $WORKER_SIZE/1024" | bc)KB"
echo ""
echo "The Web Worker runs proof generation in a background thread,"
echo "keeping the UI responsive during the ~30 second proof computation."
