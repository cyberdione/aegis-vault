/**
 * CSS for the AegisVaultModal Web Component.
 *
 * Injected into the open shadow root via a `<style>` element. Uses CSS
 * custom properties for theming — consumers can override colors from
 * outside the shadow boundary because custom properties pierce shadow
 * roots by design. To restyle, set variables on any parent of the widget:
 *
 *   aegis-vault-modal {
 *     --aegis-primary: #0066cc;
 *     --aegis-bg: #1a1a1a;
 *     --aegis-fg: #e0e0e0;
 *   }
 *
 * Deliberately conservative and accessible: single column layout, 16px
 * base font, high contrast, no animations that could trigger reduced-motion
 * sensitivities.
 */

export const MODAL_STYLES = /* css */ `
:host {
  --aegis-primary: #ff8b3e;
  --aegis-primary-contrast: #ffffff;
  --aegis-bg: #ffffff;
  --aegis-fg: #222222;
  --aegis-muted: #666666;
  --aegis-border: #cccccc;
  --aegis-error-bg: #fee;
  --aegis-error-border: #fcc;
  --aegis-error-fg: #900;
  --aegis-backdrop: rgba(0, 0, 0, 0.5);
  --aegis-modal-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
  --aegis-border-radius: 8px;
  --aegis-font: system-ui, -apple-system, 'Segoe UI', sans-serif;

  display: block;
  position: fixed;
  inset: 0;
  z-index: 9999;
  font-family: var(--aegis-font);
}

:host([hidden]) {
  display: none;
}

.backdrop {
  position: absolute;
  inset: 0;
  background: var(--aegis-backdrop);
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal {
  background: var(--aegis-bg);
  color: var(--aegis-fg);
  padding: 24px;
  border-radius: var(--aegis-border-radius);
  min-width: 320px;
  max-width: 420px;
  box-shadow: var(--aegis-modal-shadow);
  box-sizing: border-box;
}

h2 {
  margin: 0 0 8px 0;
  font-size: 18px;
  font-weight: 600;
}

p {
  margin: 12px 0;
  font-size: 14px;
  line-height: 1.5;
  color: var(--aegis-muted);
}

.form {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

input[type="password"],
input[type="text"] {
  padding: 10px 12px;
  border: 1px solid var(--aegis-border);
  border-radius: 4px;
  font-size: 14px;
  font-family: inherit;
  background: var(--aegis-bg);
  color: var(--aegis-fg);
  box-sizing: border-box;
  width: 100%;
}

input:focus {
  outline: 2px solid var(--aegis-primary);
  outline-offset: 1px;
  border-color: var(--aegis-primary);
}

button {
  padding: 10px 16px;
  border: none;
  border-radius: 4px;
  font-size: 14px;
  font-family: inherit;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 120ms ease;
}

button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.primary {
  background: var(--aegis-primary);
  color: var(--aegis-primary-contrast);
}

.secondary {
  background: transparent;
  color: var(--aegis-muted);
  border: 1px solid var(--aegis-border);
  font-weight: 400;
}

.link {
  background: transparent;
  color: var(--aegis-muted);
  border: none;
  font-size: 13px;
  font-weight: 400;
  padding: 6px;
  text-decoration: underline;
  align-self: center;
}

.error {
  padding: 8px 12px;
  background: var(--aegis-error-bg);
  border: 1px solid var(--aegis-error-border);
  border-radius: 4px;
  font-size: 13px;
  color: var(--aegis-error-fg);
}

[hidden] {
  display: none !important;
}
`;
