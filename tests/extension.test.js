import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  HOST_NAME,
  isValidHostReply,
  isValidPageRequest,
  fallbackReply,
} from "../extension/src/protocol.js";

// Reads a repo file by a fixed relative path (no user input reaches the path).
function readRepo(relPath) {
  return readFileSync(new URL(relPath, import.meta.url), "utf8");
}
const readRepoJson = (relPath) => JSON.parse(readRepo(relPath));

const manifest = readRepoJson("../extension/manifest.json");
const EXTENSION_ID = "amppkfbnjicgeeakigkmafdllhknaigl";
const ALLOWED_PAGES = [
  "https://accounts.google.com/*",
  "https://myaccount.google.com/*",
  "https://webauthn.io/*",
];

test("manifest is MV3 and asks only for native messaging", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.permissions, ["nativeMessaging"]);
  assert.equal(manifest.host_permissions, undefined);
  assert.equal(manifest.optional_permissions, undefined);
  assert.equal(manifest.web_accessible_resources, undefined);
  assert.equal(manifest.externally_connectable, undefined);
});

test("content scripts run only on Google sign-in pages (and webauthn.io), top frame only", () => {
  assert.equal(manifest.content_scripts.length, 2);
  for (const cs of manifest.content_scripts) {
    assert.deepEqual(cs.matches, ALLOWED_PAGES);
    assert.equal(cs.all_frames, false);
    assert.equal(cs.run_at, "document_start");
  }
  const main = manifest.content_scripts.filter((cs) => cs.world === "MAIN");
  assert.equal(main.length, 1);
  assert.deepEqual(main[0].js, ["src/inject.js"]);
});

test("manifest key gives the fixed extension ID the helper app trusts", () => {
  const der = Buffer.from(manifest.key, "base64");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  const id = [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
  assert.equal(id, EXTENSION_ID);
  assert.match(readRepo("../tools/dev-register.ps1"), new RegExp(EXTENSION_ID));
});

test("extension and package versions match", () => {
  assert.equal(manifest.version, readRepoJson("../package.json").version);
});

test("helper app name is a valid native messaging name", () => {
  // Lowercase letters, digits, underscores and dots; no empty parts.
  assert.match(HOST_NAME, /^[a-z0-9_.]+$/);
  assert.ok(HOST_NAME.split(".").every((part) => part.length > 0));
});

test("only well-formed helper app replies are accepted", () => {
  assert.equal(isValidHostReply({ status: "ok", credential: { response: {} } }), true);
  assert.equal(isValidHostReply({ status: "error", name: "NotAllowedError" }), true);
  for (const bad of [
    null,
    undefined,
    "ok",
    1,
    [],
    {},
    { status: "maybe" },
    { status: "ok" },
    { status: "ok", credential: {} },
    { status: "error" },
  ]) {
    assert.equal(isValidHostReply(bad), false, JSON.stringify(bad));
  }
});

test("page requests: only create/get with plain, small options", () => {
  assert.equal(isValidPageRequest({ type: "create", options: {} }), true);
  assert.equal(isValidPageRequest({ type: "get", options: { challenge: "AA" } }), true);
  for (const bad of [
    null,
    { type: "delete", options: {} },
    { type: "get" },
    { type: "get", options: [] },
    { type: "get", options: { big: "x".repeat(70000) } },
  ]) {
    assert.equal(isValidPageRequest(bad), false, JSON.stringify(bad)?.slice(0, 60));
  }
});

test("fallback replies tell the page hook to use the browser's own security key", () => {
  const r = fallbackReply("why");
  assert.equal(r.fallback, true);
  assert.equal(isValidHostReply(r), true);
});
