/**
 * `<aegis-vault-modal>` — a framework-agnostic Web Component for the
 * aegis-vault unlock flow.
 *
 * Renders the create / unlock / ephemeral flow using vanilla DOM inside
 * an open shadow root. Consumers drop `<aegis-vault-modal></aegis-vault-modal>`
 * into their markup and the widget wires itself to the singleton `vault`
 * from `@cyberdione/aegis-vault-web` by default.
 *
 * **Shadow DOM is for encapsulation, not security.** See `THREATMODEL.md`.
 * It isolates the widget's styles and markup from the host page, but does
 * not prevent same-origin JavaScript from observing or bypassing the widget.
 * The cross-origin iframe deployment (Phase D) is the architecture that
 * actually closes that attack class.
 *
 * ## Attributes
 *
 * - `hide-ephemeral`    — if present, hides the "Continue without saving" option
 * - `force-open`        — if present, keeps the modal visible even when unlocked
 *
 * ## Events
 *
 * Custom events bubble on the host element with `detail` payloads:
 * - `aegis-vault-unlocked`  `{ persistent: boolean }`
 * - `aegis-vault-locked`    `{}`
 * - `aegis-vault-created`   `{ persistent: true }`
 * - `aegis-vault-failed`    `{ error: string, phase: 'create' | 'unlock' | 'ephemeral' }`
 * - `aegis-vault-deleted`   `{}`
 *
 * ## Injecting a custom client
 *
 * By default the widget uses the `vault` singleton from the core module.
 * To use a different `VaultClient` (e.g. an iframe-host client in Phase D),
 * set the `client` JS property on the element:
 *
 *   const el = document.querySelector('aegis-vault-modal');
 *   el.client = myIframeHostVaultClient;
 */

import { vault as defaultVault } from '../index.js';
import type { VaultClient, VaultState } from '../types.js';
import { MODAL_STYLES } from './styles.js';
import {
  bindActions,
  homeView,
  validateCreatePassphrase,
  validateUnlockPassphrase,
  type View,
  type WidgetActions,
} from './state-machine.js';

export class AegisVaultModal extends HTMLElement {
  static observedAttributes = ['hide-ephemeral', 'force-open'] as const;

  private root: ShadowRoot;
  private _client: VaultClient = defaultVault;
  private actions: WidgetActions = bindActions(defaultVault);
  private unsubscribe?: () => void;
  private state: VaultState;
  private view: View = 'create';
  private vaultExists = false;
  private busy = false;
  private errorMessage: string | null = null;

  constructor() {
    super();
    this.root = this.attachShadow({ mode: 'open' });
    this.state = this._client.state;
  }

  /**
   * Inject a custom `VaultClient`. Use this in Phase D deployments where
   * the parent app creates an `IframeHostVaultClient` and wants the widget
   * to proxy through it instead of the in-process singleton.
   */
  set client(client: VaultClient) {
    if (this.unsubscribe) this.unsubscribe();
    this._client = client;
    this.actions = bindActions(client);
    this.state = client.state;
    if (this.isConnected) {
      this.subscribe();
      void this.refresh();
    }
  }

  get client(): VaultClient {
    return this._client;
  }

  connectedCallback(): void {
    this.role = 'dialog';
    this.setAttribute('aria-modal', 'true');
    this.setAttribute('aria-label', 'Aegis Vault');
    this.subscribe();
    void this.refresh();
  }

  disconnectedCallback(): void {
    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = undefined;
    }
  }

  attributeChangedCallback(): void {
    this.render();
  }

  private subscribe(): void {
    this.unsubscribe = this._client.subscribe((state) => {
      const wasLocked = this.state.locked;
      this.state = state;
      if (wasLocked && !state.locked) {
        this.dispatchEvent(
          new CustomEvent('aegis-vault-unlocked', {
            detail: { persistent: state.persistent },
            bubbles: true,
            composed: true,
          }),
        );
      } else if (!wasLocked && state.locked) {
        this.dispatchEvent(
          new CustomEvent('aegis-vault-locked', {
            detail: {},
            bubbles: true,
            composed: true,
          }),
        );
      }
      this.render();
    });
  }

  /**
   * Refresh `vaultExists`, pick the initial view, and render. Called on
   * connect and whenever the client is swapped.
   */
  private async refresh(): Promise<void> {
    try {
      this.vaultExists = await this.actions.exists();
    } catch {
      this.vaultExists = false;
    }
    this.view = homeView(this.vaultExists);
    this.render();
  }

  // ── Actions ───────────────────────────────────────────────────────────────

  private async doCreate(passphrase: string, confirm: string): Promise<void> {
    const err = validateCreatePassphrase(passphrase, confirm);
    if (err) {
      this.setError(err);
      return;
    }
    this.setBusy(true);
    try {
      await this.actions.create(passphrase);
      this.dispatchEvent(
        new CustomEvent('aegis-vault-created', {
          detail: { persistent: true },
          bubbles: true,
          composed: true,
        }),
      );
    } catch (e) {
      this.dispatchFailed('create', e);
    } finally {
      this.setBusy(false);
    }
  }

  private async doUnlock(passphrase: string): Promise<void> {
    const err = validateUnlockPassphrase(passphrase);
    if (err) {
      this.setError(err);
      return;
    }
    this.setBusy(true);
    try {
      await this.actions.unlock(passphrase);
    } catch (e) {
      this.dispatchFailed('unlock', e);
    } finally {
      this.setBusy(false);
    }
  }

  private async doEphemeral(): Promise<void> {
    this.setBusy(true);
    try {
      await this.actions.startEphemeral();
    } catch (e) {
      this.dispatchFailed('ephemeral', e);
    } finally {
      this.setBusy(false);
    }
  }

  private async doDelete(): Promise<void> {
    this.setBusy(true);
    try {
      await this.actions.delete();
      this.vaultExists = false;
      this.view = 'create';
      this.dispatchEvent(
        new CustomEvent('aegis-vault-deleted', {
          detail: {},
          bubbles: true,
          composed: true,
        }),
      );
    } catch (e) {
      this.dispatchFailed('unlock', e);
    } finally {
      this.setBusy(false);
    }
  }

  private dispatchFailed(phase: 'create' | 'unlock' | 'ephemeral', e: unknown): void {
    const msg = e instanceof Error ? e.message : String(e);
    this.setError(msg);
    this.dispatchEvent(
      new CustomEvent('aegis-vault-failed', {
        detail: { error: msg, phase },
        bubbles: true,
        composed: true,
      }),
    );
  }

  private setBusy(busy: boolean): void {
    this.busy = busy;
    this.render();
  }

  private setError(msg: string | null): void {
    this.errorMessage = msg;
    this.render();
  }

  // ── Rendering ─────────────────────────────────────────────────────────────

  private render(): void {
    if (!this.state.locked && !this.hasAttribute('force-open')) {
      this.root.innerHTML = '';
      this.hidden = true;
      return;
    }
    this.hidden = false;

    const hideEphemeral = this.hasAttribute('hide-ephemeral');

    this.root.innerHTML = `
      <style>${MODAL_STYLES}</style>
      <div class="backdrop">
        <div class="modal" part="modal">
          <h2>Aegis Vault</h2>
          ${this.renderBody(hideEphemeral)}
        </div>
      </div>
    `;

    this.wireEvents();
  }

  private renderBody(hideEphemeral: boolean): string {
    const err = this.errorMessage
      ? `<div class="error" role="alert">${escapeHtml(this.errorMessage)}</div>`
      : '';
    const ephemeralBtn = hideEphemeral
      ? ''
      : `<button type="button" class="secondary" data-action="ephemeral"${
          this.busy ? ' disabled' : ''
        }>Continue without saving</button>`;

    if (this.view === 'create') {
      return `
        <p>No vault on this device. Create one to persist your identity and credentials.</p>
        <p>Choose a strong passphrase. If you forget it, your vault cannot be recovered.</p>
        <form class="form" data-form="create">
          <input type="password" name="passphrase" placeholder="Passphrase"
                 autocomplete="new-password"${this.busy ? ' disabled' : ''}>
          <input type="password" name="confirm" placeholder="Confirm passphrase"
                 autocomplete="new-password"${this.busy ? ' disabled' : ''}>
          ${err}
          <button type="submit" class="primary"${this.busy ? ' disabled' : ''}>
            ${this.busy ? 'Creating…' : 'Create vault'}
          </button>
          ${ephemeralBtn}
        </form>
      `;
    }

    if (this.view === 'unlock') {
      return `
        <p>A vault exists on this device. Unlock it with your passphrase.</p>
        <form class="form" data-form="unlock">
          <input type="password" name="passphrase" placeholder="Passphrase"
                 autocomplete="current-password" autofocus${this.busy ? ' disabled' : ''}>
          ${err}
          <button type="submit" class="primary"${this.busy ? ' disabled' : ''}>
            ${this.busy ? 'Unlocking…' : 'Unlock'}
          </button>
          ${ephemeralBtn}
          <button type="button" class="link" data-action="delete"${this.busy ? ' disabled' : ''}>
            Delete vault
          </button>
        </form>
      `;
    }

    // 'home' is resolved in refresh(); this branch is unreachable but
    // keeps TypeScript's exhaustiveness checker happy.
    return '';
  }

  private wireEvents(): void {
    const form = this.root.querySelector('form');
    if (form) {
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        const formKind = (form as HTMLFormElement).dataset.form;
        const data = new FormData(form as HTMLFormElement);
        if (formKind === 'create') {
          void this.doCreate(
            String(data.get('passphrase') ?? ''),
            String(data.get('confirm') ?? ''),
          );
        } else if (formKind === 'unlock') {
          void this.doUnlock(String(data.get('passphrase') ?? ''));
        }
      });
    }

    this.root.querySelectorAll('button[data-action]').forEach((btn) => {
      const action = (btn as HTMLButtonElement).dataset.action;
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        if (action === 'ephemeral') void this.doEphemeral();
        else if (action === 'delete') void this.doDelete();
      });
    });
  }
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
