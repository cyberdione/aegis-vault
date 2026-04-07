# aegis-vault

Encrypted browser identity vault — Rust crate.

This is the Rust workspace member of the [aegis-vault](https://github.com/cyberdione/aegis-vault) project. It compiles to WebAssembly via `wasm-pack` and is consumed by the [`@cyberdione/aegis-vault-web`](../../packages/aegis-vault-web) npm package.

See the [project README](../../README.md) and [THREATMODEL.md](../../THREATMODEL.md) for design rationale, threat model, and API documentation.

## Build

```bash
# From the repo root:
bash scripts/build-wasm.sh
# or
cargo build -p aegis-vault
```

## Test

```bash
cargo test -p aegis-vault
```

33 unit tests cover crypto round-trips, format encoding, identity derivation, page lifecycle, vault unlock, WebAuthn PRF combine, and purpose isolation.

## License

Apache-2.0. See [LICENSE](../../LICENSE) at the repo root.
