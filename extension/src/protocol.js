// Messages between the extension and the PlugPass helper app (Chrome native messaging).
// The helper app is registered under this name; see docs/spec.md.
export const HOST_NAME = "com.plugpass.host";

// The helper app refuses requests larger than this (host/src/NativeHost.cs, MaxRequestBytes).
export const MAX_MESSAGE_BYTES = 64 * 1024;

const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// A reply from the helper app must be a plain object with a known status, nothing else.
export function isValidHostReply(msg) {
  if (!isPlainObject(msg)) {
    return false;
  }
  if (msg.status === "ok") {
    return isPlainObject(msg.credential) && isPlainObject(msg.credential.response);
  }
  return msg.status === "error" && typeof msg.name === "string";
}

// A request from the content script: create/get with JSON-safe options of a sane size.
export function isValidPageRequest(msg) {
  if (!isPlainObject(msg) || (msg.type !== "create" && msg.type !== "get")) {
    return false;
  }
  if (!isPlainObject(msg.options)) {
    return false;
  }
  return JSON.stringify(msg.options).length < MAX_MESSAGE_BYTES - 1024;
}

// "Let the browser handle it": the page hook then calls the browser's own WebAuthn.
export function fallbackReply(message) {
  return { status: "error", name: "NotAllowedError", message, fallback: true };
}
