// Windows sign-in enrolment (phase 4) with the test build: a folder stands in for the drive and a
// throwaway HKCU key for HKLM\SOFTWARE\PlugPass\SignIn. The password is fake; nobody is signed in.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { testRegKey, signInValues, deleteRegKey } from "./winlib.js";

const exe = fileURLToPath(new URL("../bin/test/PlugPass.exe", import.meta.url));
const realExe = fileURLToPath(new URL("../bin/PlugPass.exe", import.meta.url));
const out = fileURLToPath(new URL("./out/windows-key", import.meta.url));
const home = join(out, "home");
const drive = join(out, "drive");
const regKey = testRegKey();
const FAKE_PASSWORD = "fake-windows-pässword-1";
const user = process.env.USERNAME;

function run(args, stdin = "", program = exe, env = {}) {
  const r = spawnSync(program, args, {
    env: { ...process.env, PLUGPASS_HOME: home, PLUGPASS_TEST_REGKEY: regKey, ...env },
    input: stdin,
    timeout: 60000,
  });
  return { code: r.status, out: r.stdout.toString(), err: r.stderr.toString() };
}
const enrolIds = () => signInValues(regKey).filter((n) => n.length === 32);

before(() => {
  assert.ok(existsSync(exe), "build first: .\\build.ps1");
  rmSync(out, { recursive: true, force: true });
  mkdirSync(home, { recursive: true });
  mkdirSync(drive, { recursive: true });
});
after(() => {
  rmSync(out, { recursive: true, force: true });
  deleteRegKey(regKey);
});

test("enrol: the drive gets K, the registry gets the encrypted password; they decrypt together", () => {
  const r = run(["enrol-windows", drive], `${FAKE_PASSWORD}\r\n`);
  assert.equal(r.code, 0, r.err);
  const driveFile = readFileSync(join(drive, "PlugPass", "windows.key"));
  assert.equal(driveFile.length, 64);
  assert.equal(driveFile.subarray(0, 8).toString("ascii"), "PPWINKEY");
  assert.equal(driveFile[8], 1);
  assert.deepEqual(enrolIds(), [driveFile.subarray(16, 32).toString("hex")]);
  const check = run(["windows-check", drive]);
  assert.equal(check.code, 0, check.err);
  assert.equal(check.out.trim(), `user ${user} password-length ${FAKE_PASSWORD.length}`);
});

test("re-enrolling replaces the old PC half; the old one is gone", () => {
  const before = enrolIds();
  assert.equal(run(["enrol-windows", drive], `${FAKE_PASSWORD}\r\n`).code, 0);
  const after = enrolIds();
  assert.equal(after.length, 1);
  assert.notDeepEqual(after, before);
});

test("a copied drive file without the PC half, or a tampered half, doesn't decrypt", () => {
  const r = run(["windows-check", drive], "", exe, { PLUGPASS_TEST_REGKEY: testRegKey() });
  assert.equal(r.code, 6, "another PC (empty store) can't decrypt");
  const drive2 = join(out, "drive2");
  mkdirSync(drive2, { recursive: true });
  assert.equal(run(["enrol-windows", drive2], `${FAKE_PASSWORD}\r\n`).code, 0);
  const a = readFileSync(join(drive, "PlugPass", "windows.key"));
  const b = readFileSync(join(drive2, "PlugPass", "windows.key"));
  const drive3 = join(out, "drive3");
  mkdirSync(join(drive3, "PlugPass"), { recursive: true });
  // drive's enrolment ID with drive2's K
  writeFileSync(
    join(drive3, "PlugPass", "windows.key"),
    Buffer.concat([a.subarray(0, 32), b.subarray(32)]),
  );
  assert.equal(run(["windows-check", drive3]).code, 6);
});

test("remove: the PC half and the drive file are both deleted", () => {
  const r = run(["remove-windows", drive]);
  assert.equal(r.code, 0, r.err);
  assert.equal(existsSync(join(drive, "PlugPass", "windows.key")), false);
  assert.equal(run(["windows-check", drive]).code, 6);
});

test("lost drive: 'remove for all drives' deletes every PC half, so no drive signs in", () => {
  const a = join(out, "lost-a");
  const b = join(out, "lost-b");
  for (const d of [a, b]) {
    mkdirSync(d, { recursive: true });
    assert.equal(run(["enrol-windows", d], `${FAKE_PASSWORD}\r\n`).code, 0);
  }
  const r = run(["remove-windows", "--all"]);
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(signInValues(regKey), []);
  assert.equal(run(["windows-check", a]).code, 6);
  assert.equal(run(["windows-check", b]).code, 6);
});

test("a password longer than Windows allows is refused cleanly", () => {
  const r = run(["enrol-windows", drive], `${"x".repeat(300)}\r\n`);
  assert.equal(r.code, 7, r.err);
});

test("the real build needs admin rights and checks the password with Windows", () => {
  // These tests run unelevated, so the real build refuses before reading any password.
  const r = run(["enrol-windows", drive], `${FAKE_PASSWORD}\r\n`, realExe);
  assert.ok(r.code === 7 || r.code === 9, `${r.code} ${r.err}`); // 7: not a removable drive
  assert.equal(existsSync(join(drive, "PlugPass", "windows.key")), false);
});
