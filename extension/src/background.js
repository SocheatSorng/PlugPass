// PlugPass service worker: receives WebAuthn requests from the content script and forwards them to
// the helper app over native messaging, adding the page's origin as the browser reports it.
import { HOST_NAME, isValidHostReply, isValidPageRequest, fallbackReply } from "./protocol.js";

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only our own content scripts, in a tab's top frame, with a browser-supplied origin.
  if (sender.id !== chrome.runtime.id || !sender.tab || sender.frameId !== 0 || !sender.origin) {
    return false;
  }
  if (!isValidPageRequest(msg)) {
    sendResponse(fallbackReply("Unsupported request."));
    return false;
  }
  chrome.runtime
    .sendNativeMessage(HOST_NAME, { type: msg.type, origin: sender.origin, options: msg.options })
    .then((reply) =>
      sendResponse(isValidHostReply(reply) ? reply : fallbackReply("Unexpected reply.")),
    )
    .catch(() => sendResponse(fallbackReply("The PlugPass helper app is not installed.")));
  return true; // reply comes asynchronously
});
