// Page-world hook: wraps navigator.credentials.create/get so security-key requests can be answered
// by PlugPass. Anything PlugPass can't serve (passkeys that must live on the device, PIN-verified
// requests, conditional autofill, or when the helper app is missing) goes to the browser as usual.
(() => {
  const creds = navigator.credentials;
  if (!creds || typeof window.PublicKeyCredential !== "function") {
    return;
  }
  const CHANNEL = "plugpass:v1";
  const origCreate = creds.create.bind(creds);
  const origGet = creds.get.bind(creds);
  const pending = new Map();
  let nextId = 1;

  window.addEventListener("message", (event) => {
    if (event.source !== window) {
      return;
    }
    const msg = event.data;
    if (!msg || msg.channel !== CHANNEL || msg.dir !== "reply" || !pending.has(msg.id)) {
      return;
    }
    const resolve = pending.get(msg.id);
    pending.delete(msg.id);
    resolve(msg.reply);
  });

  function ask(kind, publicKey) {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, resolve);
      try {
        window.postMessage(
          { channel: CHANNEL, dir: "request", id, kind, options: publicKey },
          window.location.origin,
        );
      } catch (err) {
        pending.delete(id); // options that can't be cloned: let the browser handle it
        reject(err);
      }
    });
  }

  // Why PlugPass can't serve this request ("" = it can). Shown in the console to help diagnose sites.
  function skipReason(kind, options) {
    const pk = options.publicKey;
    if (options.mediation === "conditional") {
      return "passkey autofill (conditional mediation)";
    }
    // Passkeys and PIN-verified requests are served by the drive (phase 2); with no drive plugged
    // in, the helper app hands them back silently.
    if (
      kind === "create" &&
      (pk.authenticatorSelection || {}).authenticatorAttachment === "platform"
    ) {
      return "site wants this device's own authenticator";
    }
    return "";
  }

  function note(kind, text) {
    console.info(`PlugPass: ${kind} handed to the browser: ${text}`);
  }

  function toBuffer(s) {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
    return Uint8Array.from(bin, (ch) => ch.charCodeAt(0)).buffer;
  }

  function define(obj, props) {
    for (const [name, value] of Object.entries(props)) {
      Object.defineProperty(obj, name, { value, enumerable: true });
    }
    return obj;
  }

  // Builds objects that behave like the browser's own PublicKeyCredential.
  function makeCredential(c) {
    const r = c.response;
    let response;
    if (r.attestationObject) {
      response = define(Object.create(window.AuthenticatorAttestationResponse.prototype), {
        clientDataJSON: toBuffer(r.clientDataJSON),
        attestationObject: toBuffer(r.attestationObject),
        getTransports: () => r.transports.slice(),
        getAuthenticatorData: () => toBuffer(r.authenticatorData),
        getPublicKey: () => toBuffer(r.publicKey),
        getPublicKeyAlgorithm: () => r.publicKeyAlgorithm,
      });
    } else {
      response = define(Object.create(window.AuthenticatorAssertionResponse.prototype), {
        clientDataJSON: toBuffer(r.clientDataJSON),
        authenticatorData: toBuffer(r.authenticatorData),
        signature: toBuffer(r.signature),
        userHandle: r.userHandle ? toBuffer(r.userHandle) : null,
      });
    }
    return define(Object.create(window.PublicKeyCredential.prototype), {
      id: c.id,
      rawId: toBuffer(c.rawId),
      type: "public-key",
      authenticatorAttachment: c.authenticatorAttachment,
      response,
      getClientExtensionResults: () => ({}),
      toJSON: () => JSON.parse(JSON.stringify(c)),
    });
  }

  async function handle(kind, options, original) {
    if (!options || !options.publicKey) {
      return original(options); // passwords, federated sign-in: not ours
    }
    const reason = skipReason(kind, options);
    if (reason) {
      note(kind, reason);
      return original(options);
    }
    if (options.signal && options.signal.aborted) {
      throw new DOMException("The operation was aborted.", "AbortError");
    }
    let reply;
    try {
      reply = await ask(kind, options.publicKey);
    } catch {
      note(kind, "request couldn't be passed to PlugPass");
      return original(options);
    }
    if (reply && reply.status === "ok" && reply.credential) {
      return makeCredential(reply.credential);
    }
    if (!reply || reply.fallback) {
      note(kind, String((reply && reply.message) || "no reply from PlugPass"));
      return original(options);
    }
    throw new DOMException(String(reply.message || "PlugPass refused"), String(reply.name));
  }

  creds.create = (options) => handle("create", options, origCreate);
  creds.get = (options) => handle("get", options, origGet);
})();
