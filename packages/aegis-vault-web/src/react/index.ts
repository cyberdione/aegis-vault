/**
 * React adapter for @cyberdione/aegis-vault-web.
 *
 * Headless only: ships a `VaultProvider` context and `useVault()` /
 * `useVaultState()` hooks. **No UI components.** React consumers build
 * their own modal using the hooks, or use `<aegis-vault-modal>` from
 * `@cyberdione/aegis-vault-web/widget` (which works inside JSX because
 * React understands custom elements as lowercase tags).
 *
 * React is not privileged in aegis-vault's architecture — the vanilla
 * core at `@cyberdione/aegis-vault-web` is the canonical entry point,
 * and this package is a thin (~80 LOC) convenience adapter for React
 * consumers. Future Vue / Svelte / Solid adapters would be peers of
 * this one, all built on the same vanilla `VaultClient` interface.
 */

export { VaultProvider, useVault, useVaultState } from './VaultProvider.js';
export type { VaultActions, VaultContextValue } from './VaultProvider.js';
