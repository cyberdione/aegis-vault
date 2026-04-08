/**
 * React example: build a custom modal with the headless hooks.
 *
 * Use this pattern when your app has a design system (Chakra, shadcn,
 * Tailwind, MUI) and you want the vault unlock UX to match. The
 * `useVault()` hook exposes state and action wrappers; you own the JSX.
 *
 * The example below uses plain HTML/CSS for clarity — replace the
 * elements with your UI library's components.
 *
 * For the easy path (no custom modal), see `react-with-widget.tsx`.
 *
 * NOTE: This file lives in `docs/examples/` and is NOT shipped in the npm
 * package. It's documentation-as-code: consumers copy-paste this into
 * their own repo and adapt to their design system.
 */

import { useEffect, useState } from 'react';
import { VaultProvider, useVault } from '@cyberdione/aegis-vault-web/react';
import type { IdentityHandleClient } from '@cyberdione/aegis-vault-web';

export function App() {
  return (
    <VaultProvider>
      <VaultGate>
        <AuthenticatedApp />
      </VaultGate>
    </VaultProvider>
  );
}

/**
 * Gate the rest of the app on vault unlock state. While locked, renders
 * the custom modal; while unlocked, renders the children.
 */
function VaultGate({ children }: { children: React.ReactNode }) {
  const { state } = useVault();
  if (state.locked) return <CustomVaultModal />;
  return <>{children}</>;
}

function CustomVaultModal() {
  const { actions } = useVault();
  const [view, setView] = useState<'home' | 'create' | 'unlock'>('create');
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    actions.exists().then((exists) => setView(exists ? 'unlock' : 'create'));
  }, [actions]);

  const doCreate = async () => {
    setError(null);
    if (passphrase.length < 8) return setError('Passphrase must be at least 8 characters');
    if (passphrase !== confirm) return setError('Passphrases do not match');
    setBusy(true);
    try {
      await actions.create(passphrase);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const doUnlock = async () => {
    setError(null);
    if (!passphrase) return setError('Enter your passphrase');
    setBusy(true);
    try {
      await actions.unlock(passphrase);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="vault-backdrop" role="dialog" aria-modal="true">
      <div className="vault-modal">
        <h2>My App — Vault</h2>

        {view === 'create' && (
          <>
            <p>Create a passphrase to secure your vault.</p>
            <input
              type="password"
              placeholder="Passphrase"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              disabled={busy}
            />
            <input
              type="password"
              placeholder="Confirm"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              disabled={busy}
            />
            <button onClick={doCreate} disabled={busy}>
              {busy ? 'Creating…' : 'Create vault'}
            </button>
          </>
        )}

        {view === 'unlock' && (
          <>
            <p>Unlock your vault to continue.</p>
            <input
              type="password"
              placeholder="Passphrase"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && doUnlock()}
              disabled={busy}
              autoFocus
            />
            <button onClick={doUnlock} disabled={busy}>
              {busy ? 'Unlocking…' : 'Unlock'}
            </button>
          </>
        )}

        <button className="secondary" onClick={() => actions.startEphemeral()} disabled={busy}>
          Continue without saving
        </button>

        {error && <div role="alert" className="error">{error}</div>}
      </div>
    </div>
  );
}

function AuthenticatedApp() {
  const { vault, actions } = useVault();
  const [pubkey, setPubkey] = useState<string>('—');

  useEffect(() => {
    let handle: IdentityHandleClient | null = null;
    (async () => {
      handle = await vault.identityOpen('example-app-v1');
      const hex = Array.from(handle.pubkey, (b) => b.toString(16).padStart(2, '0')).join('');
      setPubkey(hex);
    })();
    return () => {
      void handle?.close();
    };
  }, [vault]);

  return (
    <main>
      <h1>Authenticated</h1>
      <p>Pubkey: <code>{pubkey}</code></p>
      <button onClick={() => actions.lock()}>Lock</button>
    </main>
  );
}
