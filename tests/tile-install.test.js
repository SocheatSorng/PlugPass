// Installing the Windows sign-in tile with the test build: PLUGPASS_HOME stands in for Program Files
// and a JSON file for HKLM, so the real sign-in screen is never touched.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const exe = fileURLToPath(new URL("../bin/test/PlugPass.exe", import.meta.url));
const realExe = fileURLToPath(new URL("../bin/PlugPass.exe", import.meta.url));
const out = fileURLToPath(new URL("./out/tile-install", import.meta.url));
const home = join(out, "home");
const CLSID = "{9170534E-8919-480A-A99A-4EF4979FE7A3}";
const PROVIDER_KEY = `SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\${CLSID}`;
const CLSID_KEY = `SOFTWARE\\Classes\\CLSID\\${CLSID}`;
const dll = join(home, "ProgramFiles", "PlugPass", "PlugPassCredProv.dll");

const run = (args, program = exe) => {
  const r = spawnSync(program, args, { env: { ...process.env, PLUGPASS_HOME: home }, input: "" });
  return { code: r.status, out: r.stdout.toString(), err: r.stderr.toString() };
};
const machine = () => JSON.parse(readFileSync(join(home, "registry-machine.json"), "utf8"));

before(() => {
  rmSync(out, { recursive: true, force: true });
  mkdirSync(home, { recursive: true });
});
after(() => rmSync(out, { recursive: true, force: true }));

test("install-tile: DLL in (fake) Program Files, registered as a credential provider", () => {
  const r = run(["install-tile"]);
  assert.equal(r.code, 0, r.err);
  assert.ok(existsSync(dll));
  assert.ok(
    existsSync(join(home, "ProgramFiles", "PlugPass", "PlugPass.exe")),
    "admin-owned copy of the app, elevated from then on",
  );
  const reg = machine();
  assert.equal(reg[PROVIDER_KEY][""], "PlugPass");
  assert.equal(reg[`${CLSID_KEY}\\InprocServer32`][""], dll);
  assert.equal(reg[`${CLSID_KEY}\\InprocServer32`].ThreadingModel, "Apartment");
});

test("install-tile again (update) works", () => {
  assert.equal(run(["install-tile"]).code, 0);
  assert.ok(existsSync(dll));
});

test("uninstall-tile: unregistered and files removed", () => {
  const r = run(["uninstall-tile"]);
  assert.equal(r.code, 0, r.err);
  const reg = machine();
  assert.equal(reg[PROVIDER_KEY], undefined);
  assert.equal(reg[`${CLSID_KEY}\\InprocServer32`], undefined);
  assert.equal(existsSync(join(home, "ProgramFiles", "PlugPass")), false);
});

test("the real build refuses without admin rights (tests never run elevated)", () => {
  const r = run(["install-tile"], realExe);
  assert.equal(r.code, 9, r.err);
  assert.equal(run(["windows-setup", "Q:", "nobody"], realExe).code === 0, false);
});
