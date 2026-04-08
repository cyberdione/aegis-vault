/**
 * Widget entry point.
 *
 * Side-effect import: registering this module registers the
 * `<aegis-vault-modal>` custom element with the browser's `customElements`
 * registry. Consumers should import this module for its side effect and
 * then use the element in their HTML / JSX:
 *
 *   // Any framework, including vanilla:
 *   import '@cyberdione/aegis-vault-web/widget';
 *   <aegis-vault-modal></aegis-vault-modal>
 *
 *   // React understands custom elements as lowercase JSX tags:
 *   import '@cyberdione/aegis-vault-web/widget';
 *   <aegis-vault-modal />
 *
 * The registration is idempotent — importing the module twice does not
 * throw.
 */

import { AegisVaultModal } from './modal.js';

export { AegisVaultModal } from './modal.js';
export type { View, ValidationError, WidgetActions } from './state-machine.js';

/**
 * The element name we register. Consumers can refer to this constant if
 * they want to check registration status before using the element:
 *
 *   import { AEGIS_VAULT_MODAL_TAG } from '@cyberdione/aegis-vault-web/widget';
 *   if (customElements.get(AEGIS_VAULT_MODAL_TAG)) { ... }
 */
export const AEGIS_VAULT_MODAL_TAG = 'aegis-vault-modal';

if (typeof customElements !== 'undefined' && !customElements.get(AEGIS_VAULT_MODAL_TAG)) {
  customElements.define(AEGIS_VAULT_MODAL_TAG, AegisVaultModal);
}
