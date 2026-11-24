// Converts WebAuthn options (with ArrayBuffers) to JSON-safe form (binary as base64url) so they can
// travel over extension messaging. Classic script, runs in the content script's isolated world,
// where its one global (PlugPassCodec) is invisible to the page.
// eslint-disable-next-line no-unused-vars
const PlugPassCodec = (() => {
  const MAX_DEPTH = 8;
  const tag = (v) => Object.prototype.toString.call(v);

  function bytesToB64Url(bytes) {
    let bin = "";
    for (const b of bytes) {
      bin += String.fromCharCode(b);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // Binary (ArrayBuffer / typed array / DataView) becomes base64url; functions and other objects
  // that aren't plain data are dropped. Works on values cloned from another realm.
  function toJsonSafe(value, depth = 0) {
    if (depth > MAX_DEPTH) {
      throw new TypeError("Options nested too deeply");
    }
    if (value === null || typeof value === "string" || typeof value === "boolean") {
      return value;
    }
    if (typeof value === "number") {
      return Number.isFinite(value) ? value : undefined;
    }
    if (tag(value) === "[object ArrayBuffer]") {
      return bytesToB64Url(new Uint8Array(value));
    }
    if (ArrayBuffer.isView(value)) {
      return bytesToB64Url(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
    }
    if (Array.isArray(value)) {
      return value.map((v) => toJsonSafe(v, depth + 1)).filter((v) => v !== undefined);
    }
    if (typeof value === "object" && tag(value) === "[object Object]") {
      const out = {};
      for (const [k, v] of Object.entries(value)) {
        const safe = toJsonSafe(v, depth + 1);
        if (safe !== undefined) {
          out[k] = safe; // eslint-disable-line security/detect-object-injection
        }
      }
      return out;
    }
    return undefined;
  }

  return { bytesToB64Url, toJsonSafe };
})();
