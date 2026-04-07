# @cyberdione/aegis-vault-web

> Encrypted browser identity vault — TypeScript bindings for the [aegis-vault](https://github.com/cyberdione/aegis-vault) Rust crate.

Wraps the wasm-bindgen `Vault` core with IndexedDB persistence, locked/persistent state tracking, BroadcastChannel cross-tab coherence, and React bindings.

## Install

```bash
npm install @cyberdione/aegis-vault-web
```

## Usage

```ts
import { vault } from '@cyberdione/aegis-vault-web';

if (!(await vault.exists())) {
  await vault.create('correct horse battery staple');
} else {
  await vault.unlock('correct horse battery staple');
}

const id = vault.identityOpen('hyprstream-rpc-envelope-v1');
const sig = id.sign(canonicalBytes);
```

### React

```tsx
import { VaultProvider, useVault, VaultModal } from '@cyberdione/aegis-vault-web/react';

function App() {
  return (
    <VaultProvider>
      <VaultModal />
      <YourApp />
    </VaultProvider>
  );
}
```

See the [project README](https://github.com/cyberdione/aegis-vault) for the full API, design rationale, and threat model.

## License

Apache-2.0
