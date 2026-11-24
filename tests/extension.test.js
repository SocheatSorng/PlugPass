import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { HOST_NAME, isValidHostReply } from "../extension/src/protocol.js";

// Reads a repo file by a fixed relative path (no user input reaches the path).
function readRepoJson(relPath) {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  return JSON.parse(readFileSync(new URL(relPath, import.meta.url), "utf8"));
}

const manifest = readRepoJson("../extension/manifest.json");

test("manifest is MV3 and asks only for native messaging", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.permissions, ["nativeMessaging"]);
  assert.equal(manifest.host_permissions, undefined);
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
  assert.equal(isValidHostReply({ status: "ok" }), true);
  assert.equal(isValidHostReply({ status: "error", message: "x" }), true);
  for (const bad of [null, undefined, "ok", 1, [], {}, { status: "maybe" }]) {
    assert.equal(isValidHostReply(bad), false, JSON.stringify(bad));
  }
});
