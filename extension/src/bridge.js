// Isolated-world content script: relays requests between the page hook (inject.js, page world) and
// the service worker. The service worker adds the page's real origin from the browser, so nothing
// the page says about its origin is trusted.
/* global PlugPassCodec */
(() => {
  const CHANNEL = "plugpass:v1";
  const FALLBACK = { status: "error", name: "NotAllowedError", fallback: true };

  function reply(id, result) {
    window.postMessage(
      { channel: CHANNEL, dir: "reply", id, reply: result },
      window.location.origin,
    );
  }

  window.addEventListener("message", (event) => {
    if (event.source !== window || event.origin !== window.location.origin) {
      return;
    }
    const msg = event.data;
    if (!msg || msg.channel !== CHANNEL || msg.dir !== "request" || typeof msg.id !== "number") {
      return;
    }
    let options;
    try {
      options = PlugPassCodec.toJsonSafe(msg.options);
    } catch {
      reply(msg.id, FALLBACK);
      return;
    }
    chrome.runtime
      .sendMessage({ type: msg.kind, options })
      .then((result) => reply(msg.id, result || FALLBACK))
      .catch(() => reply(msg.id, FALLBACK));
  });
})();
