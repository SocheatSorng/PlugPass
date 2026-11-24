// The C++ sign-in tile, driven by credprov-harness.exe exactly as LogonUI would drive it, but signing
// nobody in. The C# test build enrols a FAKE password with a folder as the drive; the test variant of
// the tile reads that folder (PLUGPASS_KEY_DIR) and a throwaway HKCU key (PLUGPASS_TEST_REGKEY), never
// real drives or HKLM.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { testRegKey, signInValues, deleteRegKey } from "./winlib.js";

const bin = (p) => fileURLToPath(new URL(`../bin/${p}`, import.meta.url));
const exe = bin("test/PlugPass.exe");
const harness = bin("test/credprov-harness.exe");
const testDll = bin("test/PlugPassCredProv.dll");
const realDll = bin("PlugPassCredProv.dll");
const out = fileURLToPath(new URL("./out/credprov", import.meta.url));
const home = join(out, "home");
const drive = join(out, "drive");
const regKey = testRegKey();
const FAKE_PASSWORD = "fake-windows-pässword-1";
const E_NOTIMPL = "0x80004001";
const me = process.env.USERNAME;
const qualifiedMe = `${process.env.COMPUTERNAME}\\${me}`;

function enrol(root) {
  const r = spawnSync(exe, ["enrol-windows", root], {
    env: { ...process.env, PLUGPASS_HOME: home, PLUGPASS_TEST_REGKEY: regKey },
    input: `${FAKE_PASSWORD}\r\n`,
  });
  assert.equal(r.status, 0, r.stderr.toString());
}

function tile(scenario, { keyDir = drive, reg = regKey, dll = testDll, users, report } = {}) {
  const args = [dll, scenario, ...(users ? [users.join(",")] : [])];
  const r = spawnSync(harness, args, {
    env: {
      ...process.env,
      PLUGPASS_HOME: home,
      PLUGPASS_KEY_DIR: keyDir,
      PLUGPASS_TEST_REGKEY: reg,
      ...(report ? { PLUGPASS_HARNESS_REPORT: report } : {}),
    },
    timeout: 30000,
  });
  assert.equal(r.status, 0, r.stderr.toString());
  return Object.fromEntries(
    r.stdout
      .toString()
      .trim()
      .split(/\r?\n/)
      .map((line) => {
        const [key, ...rest] = line.split(" ");
        return [key, rest.join(" ")];
      }),
  );
}

before(() => {
  for (const f of [exe, harness, testDll, realDll]) assert.ok(existsSync(f), `build first: ${f}`);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(home, { recursive: true });
  mkdirSync(drive, { recursive: true });
  enrol(drive);
});
after(() => {
  rmSync(out, { recursive: true, force: true });
  deleteRegKey(regKey);
});

const expectedHash = createHash("sha256")
  .update(Buffer.from(FAKE_PASSWORD, "utf16le"))
  .digest("hex");

test("sign-in: drive present -> one tile, auto sign-in, the enrolled user and password", () => {
  const t = tile("logon", { report: "success" });
  assert.equal(t.scenario, "0x00000000");
  assert.equal(t.changed, "1", "the background check announced the drive");
  assert.equal(t.fields, "2");
  assert.equal(t.count, "1 auto 1");
  assert.equal(t.title, "PlugPass USB key");
  // 2 = credential finished; Negotiate is a small package number (usually 0)
  assert.match(t.serialize, /^0x00000000 response 2 package \d{1,2} clsid-ok 1$/);
  assert.equal(
    t.message,
    `2 domain ${process.env.COMPUTERNAME} user ${me} password-length ${FAKE_PASSWORD.length}`,
  ); // 2 = KerbInteractiveLogon
  assert.equal(t["password-sha256"], expectedHash, "C++ decrypts exactly what C# encrypted");
  assert.equal(t["after-report"], "count 1 auto 1", "a successful sign-in changes nothing");
});

test("unlock: offered only for the locked user", () => {
  const mine = tile("unlock", { users: [qualifiedMe], report: "success" });
  assert.equal(mine.count, "1 auto 1");
  assert.match(mine.message, /^7 /); // 7 = KerbWorkstationUnlockLogon
  const someoneElse = tile("unlock", { users: [`${process.env.COMPUTERNAME}\\someone-else`] });
  assert.equal(someoneElse.count, "0 auto 0", "another user's lock screen gets no tile");
});

test("everything except sign-in and unlock is refused (UAC, app password prompts)", () => {
  assert.equal(tile("credui").scenario, E_NOTIMPL);
  assert.equal(tile("credui", { dll: realDll }).scenario, E_NOTIMPL);
});

test("no drive, another PC, or a wrong key: no tile at all", () => {
  const empty = join(out, "empty-drive");
  mkdirSync(empty, { recursive: true });
  assert.equal(tile("logon", { keyDir: empty }).count, "0 auto 0");
  assert.equal(tile("logon", { reg: testRegKey() }).count, "0 auto 0", "another PC");
  const tampered = join(out, "tampered");
  mkdirSync(join(tampered, "PlugPass"), { recursive: true });
  const key = readFileSync(join(drive, "PlugPass", "windows.key"));
  key[40] ^= 1; // flip a bit of K
  writeFileSync(join(tampered, "PlugPass", "windows.key"), key);
  assert.equal(tile("logon", { keyDir: tampered }).count, "0 auto 0");
});

test("a rejected password is never retried, by any later sign-in screen, until re-enrolled", () => {
  const first = tile("logon"); // the harness reports STATUS_LOGON_FAILURE
  assert.equal(first.count, "1 auto 1");
  assert.equal(first["after-report"], "count 0 auto 0");
  assert.ok(
    signInValues(regKey).some((n) => n.endsWith(".rejected")),
    "rejection saved in the registry",
  );
  assert.equal(tile("logon").count, "0 auto 0", "a new sign-in screen doesn't retry it");
  enrol(drive); // e.g. after the password change: turn on again
  assert.equal(tile("logon", { report: "success" }).count, "1 auto 1");
  assert.equal(
    signInValues(regKey).some((n) => n.endsWith(".rejected")),
    false,
    "old rejection removed",
  );
});
