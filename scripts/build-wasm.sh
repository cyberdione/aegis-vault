#!/usr/bin/env bash
# Build the aegis-vault Rust crate to wasm via wasm-pack and drop the output
# in ./pkg/ at the repo root. The pkg/ directory is gitignored — every
# consumer rebuilds from source via this script (or, when consuming via git
# URL `github:cyberdione/aegis-vault#vX.Y.Z`, via the npm postinstall hook
# calling `npm run build:wasm`).
#
# Used by:
#   - Local dev: `bash scripts/build-wasm.sh`
#   - npm consumers: triggered via `npm run build:wasm` from the repo root
#   - CI: same, on every push / PR

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v wasm-pack >/dev/null 2>&1; then
    echo "wasm-pack not found. Install via: cargo install wasm-pack" >&2
    exit 1
fi

OUT_DIR="pkg"

echo "Building aegis-vault → $OUT_DIR"
RUSTFLAGS="-C target-feature=+simd128" \
    wasm-pack build crates/aegis-vault \
    --release \
    --target web \
    --out-dir "../../$OUT_DIR"

echo "Done. Wasm size:"
du -h "$OUT_DIR/aegis_vault_bg.wasm"
