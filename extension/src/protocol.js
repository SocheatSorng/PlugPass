// Messages between the extension and the PlugPass helper app (Chrome native messaging).
// The helper app is registered under this name; see docs/spec.md.
export const HOST_NAME = "com.plugpass.host";

// Native messaging caps a host-to-extension message at 1 MB; requests stay far smaller.
export const MAX_MESSAGE_BYTES = 64 * 1024;

// A reply from the helper app must be a plain object with a known status, nothing else.
export function isValidHostReply(msg) {
  if (msg === null || typeof msg !== "object" || Array.isArray(msg)) {
    return false;
  }
  return msg.status === "ok" || msg.status === "error";
}
