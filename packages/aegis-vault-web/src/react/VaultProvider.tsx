/**
 * Headless vault provider + hook.
 *
 * Wraps the singleton `vault` instance in a React context, exposes its
 * state via `useVaultState()`, and provides action wrappers (`create`,
 * `unlock`, `startEphemeral`, `lock`, `delete`) via `useVault()`.
 *
 * No UI is rendered here — children render unconditionally. Consumers
 * decide how to gate their app on `state.locked`. See `VaultModal.tsx`
 * for a reference implementation.
 */

import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { vault, type AegisVault, type VaultState } from '../index.js';

export interface VaultActions {
  create: (passphrase: string, prfOutput?: Uint8Array) => Promise<void>;
  unlock: (passphrase: string, prfOutput?: Uint8Array) => Promise<void>;
  startEphemeral: () => Promise<void>;
  lock: () => void;
  delete: () => Promise<void>;
  exists: () => Promise<boolean>;
}

export interface VaultContextValue {
  state: VaultState;
  actions: VaultActions;
  vault: AegisVault;
}

const VaultContext = createContext<VaultContextValue | null>(null);

interface VaultProviderProps {
  children: ReactNode;
  /**
   * Inject a custom vault instance. Defaults to the singleton exported
   * from `@cyberdione/aegis-vault-web`. Tests can pass a fresh instance.
   */
  instance?: AegisVault;
}

export function VaultProvider({ children, instance = vault }: VaultProviderProps) {
  const [state, setState] = useState<VaultState>(instance.state);

  useEffect(() => {
    return instance.subscribe(setState);
  }, [instance]);

  const actions = useMemo<VaultActions>(
    () => ({
      create: (pw, prf) => instance.create(pw, prf),
      unlock: (pw, prf) => instance.unlock(pw, prf),
      startEphemeral: () => instance.startEphemeral(),
      lock: () => instance.lock(),
      delete: () => instance.delete(),
      exists: () => instance.exists(),
    }),
    [instance],
  );

  const value = useMemo<VaultContextValue>(
    () => ({ state, actions, vault: instance }),
    [state, actions, instance],
  );

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}

/**
 * Access the full vault context. Throws if called outside `<VaultProvider>`.
 */
export function useVault(): VaultContextValue {
  const ctx = useContext(VaultContext);
  if (!ctx) {
    throw new Error('useVault must be used within a <VaultProvider>');
  }
  return ctx;
}

/**
 * Access just the vault state. Convenience for components that only care
 * about `locked` / `persistent` and don't need the actions.
 */
export function useVaultState(): VaultState {
  return useVault().state;
}
