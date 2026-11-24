// PlugPass service worker. Later: receives WebAuthn requests from pages and forwards them to the
// helper app over native messaging. See docs/spec.md.
import { HOST_NAME } from "./protocol.js";

chrome.runtime.onInstalled.addListener(() => {
  console.info(`PlugPass installed; helper app: ${HOST_NAME}`);
});
