#!/usr/bin/env bash
# Build the aegis-vault Rust crate to wasm via wasm-pack and drop the output
# in packages/aegis-vault-web/pkg/. The pkg/ directory is gitignored — every
# consumer rebuilds from source via this script (or via the npm package's
# `npm run build:wasm` script which calls into here).
#
# Used by:
#   - Local dev: `bash scripts/build-wasm.sh`
#   - npm: `npm run build:wasm` from packages/aegis-vault-web/
#   - CI: same, before publishing the npm package

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v wasm-pack >/dev/null 2>&1; then
    echo "wasm-pack not found. Install via: cargo install wasm-pack" >&2
    exit 1
fi

OUT_DIR="packages/aegis-vault-web/pkg"

echo "Building aegis-vault → $OUT_DIR"
RUSTFLAGS="-C target-feature=+simd128" \
    wasm-pack build crates/aegis-vault \
    --release \
    --target web \
    --out-dir "../../$OUT_DIR"

echo "Done. Wasm size:"
du -h "$OUT_DIR/aegis_vault_bg.wasm"
