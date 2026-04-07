/**
 * WebAuthn PRF enrollment and assertion helpers.
 *
 * The vault uses the WebAuthn PRF extension as an optional second factor
 * combined with the passphrase via HMAC inside the Rust crate. This module
 * handles the JS-land ceremony (credential creation, assertion) and returns
 * the 32-byte PRF output that gets passed to the wasm `Vault::createNew` /
 * `Vault::unlock` methods.
 *
 * The credential ID and prfSalt are stored in the page `prefs` (or in
 * localStorage by the consumer) so the same hardware token can be used to
 * unlock on subsequent visits. They are not secret — the secret is the PRF
 * output the authenticator computes from the salt.
 */

const RP_NAME = 'Aegis Vault';

/** Result of enrolling a WebAuthn credential with PRF. */
export interface PrfEnrollment {
  /** The credential ID. Persist this so future unlocks can target the same credential. */
  credentialId: Uint8Array;
  /** PRF salt — random 32 bytes generated at enroll time. Persist alongside credentialId. */
  prfSalt: Uint8Array;
  /** The 32-byte PRF output to pass into `Vault::createNew`. */
  prfOutput: Uint8Array;
}

/** Cred bundle to persist between sessions for re-assertion. */
export interface PrfCredentialBundle {
  credentialId: Uint8Array;
  prfSalt: Uint8Array;
}

/**
 * Enroll a new WebAuthn credential with the PRF extension.
 *
 * Caller is expected to be inside a user gesture (button click, etc) for
 * the WebAuthn API to permit the prompt. The returned `prfOutput` is the
 * 32 bytes that go into `Vault::createNew(passphrase, prfOutput)`.
 *
 * Throws if WebAuthn is unavailable, if the user cancels, or if the
 * authenticator does not support the PRF extension.
 */
export async function enrollWebAuthnPrf(): Promise<PrfEnrollment> {
  if (typeof navigator === 'undefined' || !navigator.credentials) {
    throw new Error('WebAuthn unavailable');
  }

  const prfSalt = crypto.getRandomValues(new Uint8Array(32));
  const prfSaltBuf = new ArrayBuffer(prfSalt.byteLength);
  new Uint8Array(prfSaltBuf).set(prfSalt);

  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: RP_NAME, id: location.hostname },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: 'aegis-vault',
        displayName: 'Aegis Vault Key',
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: {
        userVerification: 'discouraged',
        residentKey: 'discouraged',
      },
      extensions: { prf: { eval: { first: prfSaltBuf } } } as AuthenticationExtensionsClientInputs,
      timeout: 60_000,
    },
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error('WebAuthn credential creation returned null');
  }

  const extResults = credential.getClientExtensionResults() as AuthenticationExtensionsClientOutputs & {
    prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } };
  };

  if (!extResults.prf || !extResults.prf.enabled) {
    throw new Error('Authenticator does not support PRF extension');
  }

  let prfOutput: Uint8Array;
  if (extResults.prf.results?.first) {
    prfOutput = new Uint8Array(extResults.prf.results.first);
  } else {
    // Some authenticators only return PRF results on assertion, not creation.
    // Do an immediate assertion to fetch the PRF output.
    prfOutput = await assertWebAuthnPrf({
      credentialId: new Uint8Array(credential.rawId),
      prfSalt,
    });
  }

  return {
    credentialId: new Uint8Array(credential.rawId),
    prfSalt,
    prfOutput,
  };
}

/**
 * Re-assert a previously enrolled WebAuthn credential to retrieve the same
 * PRF output. Used during vault unlock when the user has WebAuthn enabled.
 */
export async function assertWebAuthnPrf(bundle: PrfCredentialBundle): Promise<Uint8Array> {
  if (typeof navigator === 'undefined' || !navigator.credentials) {
    throw new Error('WebAuthn unavailable');
  }
  // Copy into a fresh ArrayBuffer to avoid SharedArrayBuffer / view-offset
  // ambiguity in newer TS lib types.
  const credIdBuf = new ArrayBuffer(bundle.credentialId.byteLength);
  new Uint8Array(credIdBuf).set(bundle.credentialId);
  const prfSaltBuf = new ArrayBuffer(bundle.prfSalt.byteLength);
  new Uint8Array(prfSaltBuf).set(bundle.prfSalt);

  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [
        {
          type: 'public-key',
          id: credIdBuf,
          transports: ['usb', 'ble', 'nfc', 'internal'] as AuthenticatorTransport[],
        },
      ],
      extensions: { prf: { eval: { first: prfSaltBuf } } } as AuthenticationExtensionsClientInputs,
      userVerification: 'discouraged',
      timeout: 60_000,
    },
  })) as PublicKeyCredential | null;

  if (!assertion) {
    throw new Error('WebAuthn assertion returned null');
  }

  const extResults = assertion.getClientExtensionResults() as AuthenticationExtensionsClientOutputs & {
    prf?: { results?: { first?: ArrayBuffer } };
  };

  if (!extResults.prf?.results?.first) {
    throw new Error('PRF assertion produced no result');
  }
  return new Uint8Array(extResults.prf.results.first);
}
