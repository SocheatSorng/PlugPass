// Install / uninstall with the test build. PLUGPASS_HOME redirects the program folder, the Start menu
// and the "registry" (a JSON file), so the real registry, Start menu and Programs folder are untouched.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const exe = fileURLToPath(new URL("../bin/test/PlugPass.exe", import.meta.url));
const out = fileURLToPath(new URL("./out/installer", import.meta.url));
const home = join(out, "home");
const installDir = join(home, "Programs", "PlugPass");
const installedExe = join(installDir, "PlugPass.exe");
const EXT_ORIGIN = "chrome-extension://amppkfbnjicgeeakigkmafdllhknaigl/";
const version = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
).version;
const BROWSER_KEYS = [
  "Software\\Google\\Chrome\\NativeMessagingHosts\\com.plugpass.host",
  "Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.plugpass.host",
  "Software\\BraveSoftware\\Brave-Browser\\NativeMessagingHosts\\com.plugpass.host",
];
const UNINSTALL_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PlugPass";

function run(program, args, env = { PLUGPASS_HOME: home }) {
  const r = spawnSync(program, args, {
    env: { ...process.env, ...env },
    input: "",
    timeout: 60000,
  });
  return { code: r.status, out: r.stdout.toString(), err: r.stderr.toString() };
}
const registry = () => JSON.parse(readFileSync(join(home, "registry.json"), "utf8"));

before(() => {
  assert.ok(existsSync(exe), "build first: .\\build.ps1");
  rmSync(out, { recursive: true, force: true });
  mkdirSync(home, { recursive: true });
});
after(() => rmSync(out, { recursive: true, force: true }));

test("the test build refuses to install without PLUGPASS_HOME (never touches the real PC)", () => {
  const realDir = join(process.env.LOCALAPPDATA, "Programs", "PlugPass");
  const existedBefore = existsSync(realDir);
  const env = { ...process.env };
  delete env.PLUGPASS_HOME;
  const r = spawnSync(exe, ["install", "--quiet"], { env, input: "" });
  assert.equal(r.status, 6);
  assert.match(r.stderr.toString(), /PLUGPASS_HOME/);
  assert.equal(existsSync(realDir), existedBefore, "real program folder unchanged");
});

test("install: program files, browser registration, uninstall entry, Start menu shortcut", () => {
  const r = run(exe, ["install", "--quiet"]);
  assert.equal(r.code, 0, r.err);
  assert.ok(existsSync(installedExe));
  assert.ok(existsSync(join(installDir, "extension", "manifest.json")));
  assert.ok(existsSync(join(installDir, "extension", "src", "inject.js")));
  const manifestPath = join(installDir, "com.plugpass.host.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  assert.deepEqual(manifest, {
    name: "com.plugpass.host",
    description: "PlugPass helper app",
    path: installedExe,
    type: "stdio",
    allowed_origins: [EXT_ORIGIN],
  });
  const reg = registry();
  for (const key of BROWSER_KEYS) {
    assert.equal(reg[key][""], manifestPath, key);
  }
  const entry = reg[UNINSTALL_KEY];
  assert.equal(entry.DisplayName, "PlugPass");
  assert.equal(entry.DisplayVersion, version);
  assert.equal(entry.UninstallString, `"${installedExe}" uninstall`);
  assert.equal(entry.InstallLocation, installDir);
  assert.ok(existsSync(join(home, "StartMenu", "PlugPass.lnk")));
  assert.equal(run(installedExe, ["version"]).out.trim(), `PlugPass ${version}`);
});

test("installing again updates in place, even while the browser is using PlugPass", async () => {
  // A native host waiting for messages keeps its exe locked, as when Brave has PlugPass open.
  const busy = spawn(installedExe, [EXT_ORIGIN], { env: { ...process.env, PLUGPASS_HOME: home } });
  await sleep(500);
  try {
    const r = run(exe, ["install", "--quiet"]);
    assert.equal(r.code, 0, r.err);
    assert.equal(run(installedExe, ["version"]).code, 0);
    assert.equal(readdirSync(installDir).filter((f) => f.startsWith("PlugPass.old-")).length, 1);
  } finally {
    busy.stdin.end();
    await new Promise((resolve) => busy.on("exit", resolve));
  }
});

test("uninstall removes everything it added and keeps this PC's halves of drive keys", () => {
  const drive = join(out, "drive");
  mkdirSync(drive, { recursive: true });
  const created = spawnSync(exe, ["create-key", drive], {
    env: { ...process.env, PLUGPASS_HOME: home },
    input: "correct-horse-1\r\ncorrect-horse-1\r\n",
  });
  assert.equal(created.status, 0, created.stderr.toString());
  const r = run(exe, ["uninstall", "--quiet"]);
  assert.equal(r.code, 0, r.err);
  assert.equal(existsSync(installDir), false, "program folder removed (old copies too)");
  assert.equal(existsSync(join(home, "StartMenu", "PlugPass.lnk")), false);
  const reg = registry();
  for (const key of [...BROWSER_KEYS, UNINSTALL_KEY]) {
    assert.equal(reg[key], undefined, key);
  }
  assert.equal(readdirSync(join(home, "keys")).length, 1, "drive key's PC half kept");
  assert.match(run(exe, ["key-info", drive]).out, /this-pc/);
});

test("the installed copy can uninstall itself (as Settings > Apps does)", async () => {
  assert.equal(run(exe, ["install", "--quiet"]).code, 0);
  const r = run(installedExe, ["uninstall", "--quiet"]);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /removed in a few seconds/);
  for (let i = 0; i < 30 && existsSync(installDir); i++) await sleep(500);
  assert.equal(existsSync(installDir), false);
});

test("uninstalling when nothing is installed is harmless", () => {
  assert.equal(run(exe, ["uninstall", "--quiet"]).code, 0);
});
