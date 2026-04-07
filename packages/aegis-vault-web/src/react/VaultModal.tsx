/**
 * Reference modal for vault create/unlock/ephemeral/delete.
 *
 * **Minimal unstyled implementation** — exists so consumers can use the
 * vault out of the box, but real apps should build their own using the
 * `useVault()` hook from `./VaultProvider`. Cyberdione's Chakra modal
 * lives in cyberdione's `src/vault/VaultModal.tsx` and uses `useVault()`
 * directly.
 *
 * No CSS framework dependency. Inline styles only. The button copy
 * deliberately says "Continue without saving" — never "Anonymous".
 */

import { useEffect, useState } from 'react';
import { useVault } from './VaultProvider.js';

export interface VaultModalProps {
  /** Hidden when `state.locked === false`. Override to keep it open. */
  forceOpen?: boolean;
  /** Hide the "Continue without saving" option (force passphrase). Default false. */
  hideEphemeral?: boolean;
}

export function VaultModal({ forceOpen, hideEphemeral }: VaultModalProps) {
  const { state, actions } = useVault();
  const [vaultExists, setVaultExists] = useState<boolean | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<'home' | 'create' | 'unlock'>('home');

  useEffect(() => {
    if (state.locked) {
      actions.exists().then(setVaultExists).catch(() => setVaultExists(false));
    }
  }, [state.locked, actions]);

  if (!forceOpen && !state.locked) {
    return null;
  }

  const reset = () => {
    setPassphrase('');
    setConfirm('');
    setError(null);
    setView('home');
  };

  const handleCreate = async () => {
    if (passphrase.length < 8) {
      setError('Passphrase must be at least 8 characters');
      return;
    }
    if (passphrase !== confirm) {
      setError('Passphrases do not match');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await actions.create(passphrase);
      reset();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const handleUnlock = async () => {
    if (!passphrase) {
      setError('Enter your passphrase');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await actions.unlock(passphrase);
      reset();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const handleEphemeral = async () => {
    setBusy(true);
    setError(null);
    try {
      await actions.startEphemeral();
      reset();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={backdropStyle} role="dialog" aria-modal="true" aria-label="Aegis Vault">
      <div style={modalStyle}>
        <h2 style={{ margin: 0, fontSize: 18, fontWeight: 600 }}>Aegis Vault</h2>

        {view === 'home' && (
          <>
            <p style={{ margin: '12px 0', fontSize: 14, color: '#666' }}>
              {vaultExists === null
                ? 'Checking for vault…'
                : vaultExists
                  ? 'A vault exists on this device. Unlock it with your passphrase.'
                  : 'No vault exists yet. Create one to persist your identity and credentials.'}
            </p>
            {vaultExists ? (
              <button style={primaryBtn} onClick={() => setView('unlock')} disabled={busy}>
                Unlock
              </button>
            ) : (
              <button style={primaryBtn} onClick={() => setView('create')} disabled={busy}>
                Create vault
              </button>
            )}
            {!hideEphemeral && (
              <button style={secondaryBtn} onClick={handleEphemeral} disabled={busy}>
                Continue without saving
              </button>
            )}
          </>
        )}

        {view === 'create' && (
          <>
            <p style={{ margin: '12px 0', fontSize: 13, color: '#666' }}>
              Choose a strong passphrase. If you forget it, your vault cannot be recovered.
            </p>
            <input
              style={inputStyle}
              type="password"
              placeholder="Passphrase"
              autoComplete="new-password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              disabled={busy}
            />
            <input
              style={inputStyle}
              type="password"
              placeholder="Confirm passphrase"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              disabled={busy}
            />
            <button style={primaryBtn} onClick={handleCreate} disabled={busy}>
              {busy ? 'Creating…' : 'Create'}
            </button>
            <button style={linkBtn} onClick={reset} disabled={busy}>
              Back
            </button>
          </>
        )}

        {view === 'unlock' && (
          <>
            <input
              style={inputStyle}
              type="password"
              placeholder="Passphrase"
              autoComplete="current-password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleUnlock();
              }}
              disabled={busy}
              autoFocus
            />
            <button style={primaryBtn} onClick={handleUnlock} disabled={busy}>
              {busy ? 'Unlocking…' : 'Unlock'}
            </button>
            <button style={linkBtn} onClick={reset} disabled={busy}>
              Back
            </button>
          </>
        )}

        {error && (
          <div role="alert" style={errorStyle}>
            {error}
          </div>
        )}
      </div>
    </div>
  );
}

// Inline styles — intentionally minimal. Override with your own UI library.
const backdropStyle: React.CSSProperties = {
  position: 'fixed',
  inset: 0,
  background: 'rgba(0,0,0,0.5)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  zIndex: 9999,
};
const modalStyle: React.CSSProperties = {
  background: '#fff',
  color: '#222',
  padding: 24,
  borderRadius: 8,
  minWidth: 320,
  maxWidth: 400,
  display: 'flex',
  flexDirection: 'column',
  gap: 8,
  boxShadow: '0 10px 40px rgba(0,0,0,0.3)',
};
const inputStyle: React.CSSProperties = {
  padding: '8px 12px',
  border: '1px solid #ccc',
  borderRadius: 4,
  fontSize: 14,
};
const primaryBtn: React.CSSProperties = {
  padding: '10px 16px',
  background: '#FF8B3E',
  color: '#fff',
  border: 'none',
  borderRadius: 4,
  fontSize: 14,
  fontWeight: 600,
  cursor: 'pointer',
  marginTop: 4,
};
const secondaryBtn: React.CSSProperties = {
  padding: '10px 16px',
  background: 'transparent',
  color: '#666',
  border: '1px solid #ccc',
  borderRadius: 4,
  fontSize: 14,
  cursor: 'pointer',
  marginTop: 4,
};
const linkBtn: React.CSSProperties = {
  padding: '6px',
  background: 'transparent',
  color: '#666',
  border: 'none',
  fontSize: 13,
  cursor: 'pointer',
  textDecoration: 'underline',
};
const errorStyle: React.CSSProperties = {
  padding: '8px 12px',
  background: '#fee',
  border: '1px solid #fcc',
  borderRadius: 4,
  fontSize: 13,
  color: '#900',
  marginTop: 4,
};
