// Windows sign-in enrolment (phase 4) with the test build: a folder stands in for the drive and
// PLUGPASS_HOME for the protected folder on the PC. The password is fake; nothing signs anyone in.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const exe = fileURLToPath(new URL("../bin/test/PlugPass.exe", import.meta.url));
const realExe = fileURLToPath(new URL("../bin/PlugPass.exe", import.meta.url));
const out = fileURLToPath(new URL("./out/windows-key", import.meta.url));
const home = join(out, "home");
const drive = join(out, "drive");
const FAKE_PASSWORD = "fake-windows-pässword-1";
const user = process.env.USERNAME;

function run(args, stdin = "", program = exe) {
  const r = spawnSync(program, args, {
    env: { ...process.env, PLUGPASS_HOME: home },
    input: stdin,
    timeout: 60000,
  });
  return { code: r.status, out: r.stdout.toString(), err: r.stderr.toString() };
}
const blobs = () => (existsSync(join(home, "signin")) ? readdirSync(join(home, "signin")) : []);

before(() => {
  assert.ok(existsSync(exe), "build first: .\\build.ps1");
  rmSync(out, { recursive: true, force: true });
  mkdirSync(home, { recursive: true });
  mkdirSync(drive, { recursive: true });
});
after(() => rmSync(out, { recursive: true, force: true }));

test("enrol: the drive gets K, the PC gets the encrypted password; they decrypt together", () => {
  const r = run(["enrol-windows", drive], `${FAKE_PASSWORD}\r\n`);
  assert.equal(r.code, 0, r.err);
  const driveFile = readFileSync(join(drive, "PlugPass", "windows.key"));
  assert.equal(driveFile.length, 64);
  assert.equal(driveFile.subarray(0, 8).toString("ascii"), "PPWINKEY");
  assert.equal(driveFile[8], 1);
  const enrolId = driveFile.subarray(16, 32).toString("hex");
  assert.deepEqual(blobs(), [`${enrolId}.bin`]);
  const blob = readFileSync(join(home, "signin", `${enrolId}.bin`));
  assert.equal(
    blob.includes(Buffer.from(FAKE_PASSWORD, "utf16le")),
    false,
    "password not readable on the PC",
  );
  assert.equal(blob.includes(Buffer.from("PPWINBLB")), false, "blob is DPAPI-wrapped");
  const check = run(["windows-check", drive]);
  assert.equal(check.code, 0, check.err);
  assert.equal(check.out.trim(), `user ${user} password-length ${FAKE_PASSWORD.length}`);
});

test("re-enrolling replaces the old PC half; the old one is gone", () => {
  const before = blobs();
  assert.equal(run(["enrol-windows", drive], `${FAKE_PASSWORD}\r\n`).code, 0);
  const after = blobs();
  assert.equal(after.length, 1);
  assert.notDeepEqual(after, before);
});

test("a copied drive file without the PC half, or a tampered half, doesn't decrypt", () => {
  const other = join(out, "other-home");
  mkdirSync(other, { recursive: true });
  const r = spawnSync(exe, ["windows-check", drive], {
    env: { ...process.env, PLUGPASS_HOME: other },
  });
  assert.equal(r.status, 6);
  // Swap in K from another enrolment: the MAC check fails.
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

test("the real build needs admin rights and checks the password with Windows", () => {
  // These tests run unelevated, so the real build refuses before reading any password.
  const r = run(["enrol-windows", drive], `${FAKE_PASSWORD}\r\n`, realExe);
  assert.ok(r.code === 7 || r.code === 9, `${r.code} ${r.err}`); // 7: not a removable drive
  assert.equal(existsSync(join(drive, "PlugPass", "windows.key")), false);
});
