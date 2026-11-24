// Helpers for the Windows sign-in tests: a throwaway registry key stands in for
// HKLM\SOFTWARE\PlugPass\SignIn (HKCU\Software\PlugPassTest\<random>\SignIn), removed afterwards.
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";

export function testRegKey() {
  return `t${randomBytes(6).toString("hex")}`;
}

// Value names in the throwaway sign-in key (enrolment IDs, "<id>.rejected").
export function signInValues(regKey) {
  const r = spawnSync("reg", ["query", `HKCU\\Software\\PlugPassTest\\${regKey}\\SignIn`]);
  if (r.status !== 0) return [];
  return r.stdout
    .toString()
    .split(/\r?\n/)
    .map((l) => l.trim().split(/\s+/))
    .filter((parts) => parts.length >= 2 && parts[1].startsWith("REG_"))
    .map((parts) => parts[0])
    .sort();
}

export function deleteRegKey(regKey) {
  spawnSync("reg", ["delete", `HKCU\\Software\\PlugPassTest\\${regKey}`, "/f"]);
  // Remove the parent too once no other test file is using it.
  const left = spawnSync("reg", ["query", "HKCU\\Software\\PlugPassTest"]);
  if (left.status === 0 && !left.stdout.toString().includes("PlugPassTest\\")) {
    spawnSync("reg", ["delete", "HKCU\\Software\\PlugPassTest", "/f"]);
  }
}
