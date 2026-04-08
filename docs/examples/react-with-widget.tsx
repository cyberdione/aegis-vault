/**
 * React example: use the vanilla widget from JSX.
 *
 * React understands custom elements as lowercase JSX tags, so you can drop
 * <aegis-vault-modal /> into your component tree and listen for its events
 * with standard React event handlers. This is the easy default for React
 * apps that don't need a design-system-integrated modal.
 *
 * For a custom Chakra / shadcn / Tailwind modal, see `react-custom.tsx`.
 *
 * NOTE: This file lives in `docs/examples/` and is NOT shipped in the npm
 * package. It's documentation-as-code: consumers can copy-paste this into
 * their own repo as a starting point.
 */

import { useEffect, useRef, useState } from 'react';
import '@cyberdione/aegis-vault-web/widget';
import { vault, type IdentityHandleClient } from '@cyberdione/aegis-vault-web';

// React doesn't know about our custom element's props/events by default.
// A minimal declaration lets TypeScript accept <aegis-vault-modal /> in JSX.
declare module 'react' {
  namespace JSX {
    interface IntrinsicElements {
      'aegis-vault-modal': React.DetailedHTMLProps<
        React.HTMLAttributes<HTMLElement> & {
          'hide-ephemeral'?: boolean;
          'force-open'?: boolean;
        },
        HTMLElement
      >;
    }
  }
}

export function App() {
  const modalRef = useRef<HTMLElement>(null);
  const [status, setStatus] = useState('initializing');
  const [pubkey, setPubkey] = useState<string>('—');

  useEffect(() => {
    const el = modalRef.current;
    if (!el) return;

    const onUnlocked = async (ev: Event) => {
      const detail = (ev as CustomEvent<{ persistent: boolean }>).detail;
      setStatus(detail.persistent ? 'unlocked (persistent)' : 'unlocked (ephemeral)');

      const id: IdentityHandleClient = await vault.identityOpen('example-app-v1');
      const hex = Array.from(id.pubkey, (b) => b.toString(16).padStart(2, '0')).join('');
      setPubkey(hex);
      await id.close();
    };

    const onLocked = () => setStatus('locked');

    el.addEventListener('aegis-vault-unlocked', onUnlocked);
    el.addEventListener('aegis-vault-locked', onLocked);

    return () => {
      el.removeEventListener('aegis-vault-unlocked', onUnlocked);
      el.removeEventListener('aegis-vault-locked', onLocked);
    };
  }, []);

  return (
    <>
      <aegis-vault-modal ref={modalRef as React.RefObject<HTMLElement>} />
      <main>
        <h1>React + Aegis Vault widget</h1>
        <p>State: {status}</p>
        <p>Pubkey: <code>{pubkey}</code></p>
        <button onClick={() => vault.lock()}>Lock</button>
      </main>
    </>
  );
}
