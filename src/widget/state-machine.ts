/**
 * View-switching + form-validation logic for the AegisVaultModal widget.
 *
 * Framework-free. Consumed by `modal.ts` which handles all DOM rendering.
 * Isolating the logic here keeps the DOM code purely about rendering and
 * makes the widget's behavior easier to unit-test.
 */

import type { VaultClient } from '../types.js';

/** Which view the modal is currently showing. */
export type View = 'home' | 'create' | 'unlock';

/** Validation result for form fields. `null` = valid, string = error message. */
export type ValidationError = string | null;

/** Minimum passphrase length accepted by the widget's built-in validation. */
export const MIN_PASSPHRASE_LENGTH = 8;

/**
 * Validate a passphrase for vault creation. Returns an error message if
 * invalid, or `null` if acceptable.
 *
 * v0.2 rules: length >= 8. v0.3 may integrate zxcvbn-style strength scoring
 * (matches Osh's vault). Kept minimal here to avoid a runtime dependency.
 */
export function validateCreatePassphrase(
  passphrase: string,
  confirm: string,
): ValidationError {
  if (!passphrase) return 'Enter a passphrase';
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    return `Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`;
  }
  if (passphrase !== confirm) return 'Passphrases do not match';
  return null;
}

/**
 * Validate a passphrase for vault unlock. Returns an error message if
 * the field is empty; does not check against the actual vault.
 */
export function validateUnlockPassphrase(passphrase: string): ValidationError {
  if (!passphrase) return 'Enter your passphrase';
  return null;
}

/**
 * Determine which view to show based on whether a persistent vault exists.
 *
 * - Vault exists in IDB → unlock view
 * - No vault → create view
 */
export function homeView(vaultExists: boolean): View {
  return vaultExists ? 'unlock' : 'create';
}

/**
 * Facade over vault lifecycle actions for the widget. Wraps the async
 * methods so the widget can subscribe to resolve/reject without caring
 * about which backend implements `VaultClient`.
 */
export interface WidgetActions {
  create(passphrase: string, prfOutput?: Uint8Array): Promise<void>;
  unlock(passphrase: string, prfOutput?: Uint8Array): Promise<void>;
  startEphemeral(): Promise<void>;
  delete(): Promise<void>;
  exists(): Promise<boolean>;
}

/** Build a `WidgetActions` binding from a `VaultClient` instance. */
export function bindActions(client: VaultClient): WidgetActions {
  return {
    create: (pw, prf) => client.create(pw, prf),
    unlock: (pw, prf) => client.unlock(pw, prf),
    startEphemeral: () => client.startEphemeral(),
    delete: () => client.delete(),
    exists: () => client.exists(),
  };
}
