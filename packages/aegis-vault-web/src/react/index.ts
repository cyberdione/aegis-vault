/**
 * React bindings for @cyberdione/aegis-vault-web.
 *
 * This module exports a headless `VaultProvider` and `useVault()` hook so
 * consumers can wire the vault into their app's provider tree without
 * pulling in any UI library. For a reference UI implementation see
 * `VaultModal`, which is a minimal unstyled modal — consumers are expected
 * to either use it as a starting point or build their own UI on top of the
 * `useVault()` hook.
 *
 * Chakra-, Tailwind-, or shadcn-styled modals are out of scope for this
 * package. Cyberdione builds its Chakra modal in `src/vault/VaultModal.tsx`
 * using the hooks below.
 */

export { VaultProvider, useVault, useVaultState } from './VaultProvider.js';
export { VaultModal } from './VaultModal.js';
export type { VaultActions, VaultContextValue } from './VaultProvider.js';
