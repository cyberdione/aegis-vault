/**
 * Headless React adapter.
 *
 * Thin React binding (~80 LOC) over the vanilla `VaultClient` interface.
 * Exposes the vault's state via a context provider + hooks; renders no UI.
 *
 * Consumers decide how to present the locked state — typically either by
 * using `<aegis-vault-modal />` from the vanilla widget subpackage, or by
 * building their own modal with `useVault()`.
 *
 * This adapter is one of several the library may ship. React is not
 * privileged in aegis-vault's architecture — the vanilla core is the
 * canonical entry point, and this file is a ~80 LOC convenience for React
 * consumers. Future Vue / Svelte / Solid adapters would live alongside
 * this one and consume the same `VaultClient` interface.
 */

import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { vault } from '../index.js';
import type { VaultClient, VaultState } from '../types.js';

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
  vault: VaultClient;
}

const VaultContext = createContext<VaultContextValue | null>(null);

interface VaultProviderProps {
  children: ReactNode;
  /**
   * Inject a custom `VaultClient` instance. Defaults to the singleton
   * exported from `@cyberdione/aegis-vault-web`. Tests and multi-vault
   * apps can pass their own instance.
   *
   * In Phase D (cross-origin iframe deployment), consumers pass an
   * `IframeHostVaultClient` instead of the default in-process singleton;
   * this provider and the `useVault()` hook both accept either one
   * without code changes.
   */
  instance?: VaultClient;
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
 *
 * All cross-boundary methods on `vault` are async — consumers must `await`
 * `pageGet`, `pageEntries`, `identityOpen`, `sign`, etc. This is the
 * forward-compatibility contract that keeps the React code valid when the
 * cross-origin iframe transport lands in Phase D.
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
