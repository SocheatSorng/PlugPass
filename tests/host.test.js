// End-to-end tests of the helper app. Node runs bin\test\PlugPass.exe the way Chrome does (native
// messaging) and through its key commands, and checks every reply independently with Node's crypto.
// A folder under tests/out stands in for the USB drive (--key-dir, --no-drive-scan) and PLUGPASS_HOME
// holds this PC's half of the key, so real drives and real keys are never touched. PINs are fake.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, createPublicKey, verify, randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  rmSync,
  readFileSync,
  writeFileSync,
  readdirSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const exe = fileURLToPath(new URL("../bin/test/PlugPass.exe", import.meta.url));
const realExe = fileURLToPath(new URL("../bin/PlugPass.exe", import.meta.url));
const out = fileURLToPath(new URL("./out/node-host", import.meta.url));
const home = join(out, "home");
const drive = join(out, "drive");
const EXT = "chrome-extension://amppkfbnjicgeeakigkmafdllhknaigl/";
const PIN = "correct-horse-1";

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const fromB64u = (s) => Buffer.from(s, "base64url");
const sha256 = (data) => createHash("sha256").update(data).digest();
const keyPath = (root) => join(root, "PlugPass", "plugpass.ppkey");

// Runs a key command (create-key, change-pin, key-info, unlock-check); stdin lines are PINs.
function cli(args, lines = [], env = {}, program = exe) {
  const r = spawnSync(program, args, {
    input: lines.map((l) => `${l}\r\n`).join(""),
    env: { ...process.env, PLUGPASS_HOME: home, ...env },
    timeout: 60000,
  });
  return { code: r.status, out: r.stdout.toString(), err: r.stderr.toString() };
}

function newDrive(name, pin = PIN, env = {}) {
  const root = join(out, name);
  rmSync(root, { recursive: true, force: true });
  mkdirSync(root, { recursive: true });
  const r = cli(["create-key", root], [pin, pin], env);
  assert.equal(r.code, 0, r.err);
  return root;
}

before(() => {
  assert.ok(existsSync(exe), "build first: .\\build.ps1");
  rmSync(out, { recursive: true, force: true });
  mkdirSync(home, { recursive: true });
  newDrive("drive");
});
after(() => rmSync(out, { recursive: true, force: true }));

function frame(obj) {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32LE(body.length);
  return Buffer.concat([len, body]);
}

// Sends one request as Chrome would. Returns { reply, log: [pin:/choose:/tell: lines], code }.
function send(
  request,
  {
    decision = "--auto-approve",
    pins = [PIN],
    root = drive,
    extra = [],
    env = {},
    raw = null,
  } = {},
) {
  const args = [EXT, decision, "--no-drive-scan", ...(root ? ["--key-dir", root] : []), ...extra];
  const r = spawnSync(exe, args, {
    input: raw ?? frame(request),
    env: { ...process.env, PLUGPASS_HOME: home, PLUGPASS_TEST_PIN: pins.join("|"), ...env },
    timeout: 60000,
  });
  let reply = null;
  if (r.stdout.length >= 4) {
    reply = JSON.parse(r.stdout.subarray(4, 4 + r.stdout.readUInt32LE(0)).toString("utf8"));
  }
  const log = r.stderr
    .toString()
    .split(/\r?\n/)
    .filter((l) => /^(pin|choose|tell):/.test(l));
  return { reply, log, code: r.status };
}

// Minimal CBOR decoder: integers, byte/text strings, arrays, maps, true/false/null.
function decodeCbor(buf) {
  let pos = 0;
  function readLength(info) {
    if (info < 24) return info;
    const size = { 24: 1, 25: 2, 26: 4 }[info];
    assert.ok(size, `unsupported CBOR length ${info}`);
    const v = buf.readUIntBE(pos, size);
    pos += size;
    return v;
  }
  function item() {
    const first = buf[pos++];
    const major = first >> 5;
    const info = first & 31;
    if (major === 7) return { 20: false, 21: true, 22: null }[info];
    const n = readLength(info);
    switch (major) {
      case 0:
        return n;
      case 1:
        return -1 - n;
      case 2:
      case 3: {
        const s = buf.subarray(pos, pos + n);
        pos += n;
        return major === 2 ? Buffer.from(s) : s.toString("utf8");
      }
      case 4:
        return Array.from({ length: n }, item);
      case 5: {
        const m = new Map();
        for (let i = 0; i < n; i++) m.set(item(), item());
        return m;
      }
      default:
        throw new Error(`unsupported CBOR major type ${major}`);
    }
  }
  const value = item();
  return { value, rest: buf.subarray(pos) };
}

function createRequest(overrides = {}, user = "user-1234") {
  return {
    type: "create",
    origin: "https://webauthn.io",
    options: {
      rp: { id: "webauthn.io", name: "WebAuthn.io" },
      user: {
        id: b64u(Buffer.from(user)),
        name: `${user}@example.com`,
        displayName: `Name ${user}`,
      },
      challenge: b64u(randomBytes(32)),
      pubKeyCredParams: [
        { type: "public-key", alg: -8 },
        { type: "public-key", alg: -7 },
      ],
      authenticatorSelection: { userVerification: "discouraged", residentKey: "discouraged" },
      ...overrides,
    },
  };
}

function getRequest(credIds, overrides = {}, origin = "https://webauthn.io") {
  return {
    type: "get",
    origin,
    options: {
      rpId: "webauthn.io",
      challenge: b64u(randomBytes(32)),
      allowCredentials: credIds.map((id) => ({ type: "public-key", id })),
      userVerification: "preferred",
      ...overrides,
    },
  };
}

// Parses a registration reply the way a relying party would.
function parseCreate(reply) {
  assert.equal(reply.status, "ok", JSON.stringify(reply));
  const cred = reply.credential;
  const att = decodeCbor(fromB64u(cred.response.attestationObject)).value;
  const authData = att.get("authData");
  const credIdLen = authData.readUInt16BE(53);
  const credId = authData.subarray(55, 55 + credIdLen);
  const { value: cose, rest } = decodeCbor(authData.subarray(55 + credIdLen));
  const publicKey = createPublicKey({
    key: { kty: "EC", crv: "P-256", x: b64u(cose.get(-2)), y: b64u(cose.get(-3)) },
    format: "jwk",
  });
  return { cred, att, authData, credId, cose, rest, publicKey };
}

// Checks a sign-in reply: RP ID hash, flags, counter, signature. Returns the counter.
function checkAssertion(reply, req, publicKey) {
  assert.equal(reply.status, "ok", JSON.stringify(reply));
  const r = reply.credential.response;
  const authData = fromB64u(r.authenticatorData);
  const clientDataJSON = fromB64u(r.clientDataJSON);
  assert.deepEqual(authData.subarray(0, 32), sha256("webauthn.io"));
  assert.equal(authData[32], 0x05, "flags: user present + user verified (PIN)");
  assert.equal(authData.length, 37);
  const clientData = JSON.parse(clientDataJSON.toString("utf8"));
  assert.equal(clientData.type, "webauthn.get");
  assert.equal(clientData.challenge, req.options.challenge);
  assert.equal(clientData.origin, req.origin);
  const signed = Buffer.concat([authData, sha256(clientDataJSON)]);
  assert.ok(verify("sha256", signed, publicKey, fromB64u(r.signature)), "signature verifies");
  return authData.readUInt32BE(33);
}

let registered;
function register() {
  if (registered) return registered;
  const req = createRequest();
  const { reply, log } = send(req);
  registered = { req, log, ...parseCreate(reply) };
  return registered;
}

test("key file: the drive holds no readable secrets", () => {
  const bytes = readFileSync(keyPath(drive));
  assert.equal(bytes.subarray(0, 8).toString("ascii"), "PLUGPASS");
  assert.equal(bytes[8], 1, "format version");
  assert.equal(bytes.readInt32LE(12), 600000, "PBKDF2 iterations");
  for (const word of ["master", "passkeys", "counter"]) {
    assert.equal(bytes.includes(Buffer.from(word)), false, word);
  }
  const info = cli(["key-info", drive]);
  assert.match(info.out, /^key [0-9a-f]{32} tries-left 8 this-pc/);
});

test("create: asks for the PIN and returns a 'none' attestation with UV and a counter", () => {
  const { req, log, cred, att, authData, credId, cose, rest, publicKey } = register();
  assert.deepEqual(log, ["pin:create:webauthn.io:8"]);
  assert.equal(att.get("fmt"), "none");
  assert.equal(att.get("attStmt").size, 0);
  assert.deepEqual(authData.subarray(0, 32), sha256("webauthn.io"));
  assert.equal(authData[32], 0x45, "flags: user present + user verified + attested data");
  assert.ok(authData.readUInt32BE(33) >= 1, "signature counter started");
  assert.deepEqual(authData.subarray(37, 53), Buffer.alloc(16), "AAGUID");
  assert.equal(b64u(credId), cred.id);
  assert.equal(credId[0], 2, "credential ID version 2");
  assert.equal(rest.length, 0, "nothing after the COSE key");
  assert.equal(cose.get(3), -7, "alg ES256");
  assert.deepEqual(
    publicKey.export({ type: "spki", format: "der" }),
    fromB64u(cred.response.publicKey),
  );
  const clientData = JSON.parse(fromB64u(cred.response.clientDataJSON).toString("utf8"));
  assert.deepEqual(clientData, {
    type: "webauthn.create",
    challenge: req.options.challenge,
    origin: "https://webauthn.io",
    crossOrigin: false,
  });
});

test("get: signs with the drive's key; the counter goes up every time", () => {
  const { cred, publicKey } = register();
  let last = 0;
  for (let i = 0; i < 2; i++) {
    const req = getRequest([cred.id]);
    const { reply, log } = send(req);
    assert.deepEqual(log, ["pin:get:webauthn.io:8"]);
    const counter = checkAssertion(reply, req, publicKey);
    assert.ok(counter > last, `counter ${counter} > ${last}`);
    last = counter;
    assert.equal(fromB64u(reply.credential.response.userHandle).toString(), "user-1234");
  }
});

test("passkeys: stored on the drive and found without a credential list", () => {
  const req = createRequest(
    {
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      extensions: { credProps: true },
    },
    "passkey-user",
  );
  const created = send(req);
  const { cred, publicKey } = parseCreate(created.reply);
  assert.deepEqual(cred.clientExtensionResults, { credProps: { rk: true } });
  const getReq = getRequest([], { userVerification: "required" });
  const { reply, log } = send(getReq);
  checkAssertion(reply, getReq, publicKey);
  assert.equal(reply.credential.id, cred.id);
  assert.equal(fromB64u(reply.credential.response.userHandle).toString(), "passkey-user");
  assert.deepEqual(log, ["pin:get:webauthn.io:8"], "one account: no account picker");
  assert.match(cli(["unlock-check", drive], [PIN]).out, /^ok passkeys 1 /);
});

test("passkeys: several accounts on one site ask which one; re-registering replaces", () => {
  const root = newDrive("drive-accounts");
  const keys = {};
  for (const user of ["alice", "bob", "alice"]) {
    const req = createRequest({ authenticatorSelection: { residentKey: "required" } }, user);
    keys[user] = parseCreate(send(req, { root }).reply);
  }
  assert.match(
    cli(["unlock-check", root], [PIN]).out,
    /^ok passkeys 2 /,
    "alice replaced, not added",
  );
  const getReq = getRequest([]);
  const { reply, log } = send(getReq, { root, extra: ["--test-account", "1"] });
  assert.deepEqual(log, [
    "pin:get:webauthn.io:8",
    "choose:webauthn.io:Name bob (bob@example.com),Name alice (alice@example.com)",
  ]);
  checkAssertion(reply, getReq, keys.alice.publicKey);
  assert.equal(fromB64u(reply.credential.response.userHandle).toString(), "alice");
});

test("a wrong PIN asks again and counts down; the right PIN resets the count", () => {
  const { cred, publicKey } = register();
  const req = getRequest([cred.id]);
  const { reply, log } = send(req, { pins: ["wrong-pin-1", "wrong-pin-2", PIN] });
  assert.deepEqual(log, [
    "pin:get:webauthn.io:8",
    "pin:get:webauthn.io:7:Wrong PIN. 7 tries left before the key is erased.",
    "pin:get:webauthn.io:6:Wrong PIN. 6 tries left before the key is erased.",
  ]);
  checkAssertion(reply, req, publicKey);
  assert.match(cli(["key-info", drive]).out, /tries-left 8 /);
});

test("8 wrong PINs in a row erase the key: drive file and this PC's half", () => {
  const root = newDrive("drive-wipe");
  for (let i = 1; i <= 7; i++) {
    const r = cli(["unlock-check", root], [`wrong-pin-${i}`]);
    assert.equal(r.code, 3, r.err);
    assert.ok(r.err.includes(`${8 - i} tries left`), r.err);
  }
  assert.equal(existsSync(keyPath(root)), true);
  const r = cli(["unlock-check", root], ["wrong-pin-8"]);
  assert.equal(r.code, 4, r.err);
  assert.equal(existsSync(keyPath(root)), false, "drive file erased");
  assert.deepEqual(readdirSync(join(root, "PlugPass")), [], "nothing else left in PlugPass folder");
  assert.equal(cli(["key-info", root]).code, 6);
});

test("a drive claiming its tries are used up is locked, but nothing is erased on its word", () => {
  const root = newDrive("drive-claims-locked");
  const bytes = readFileSync(keyPath(root));
  bytes[9] = 8; // the wrong-PIN count isn't covered by the MAC, so anyone could set it
  writeFileSync(keyPath(root), bytes);
  const r = cli(["unlock-check", root], [PIN]);
  assert.equal(r.code, 8, r.err);
  assert.equal(existsSync(keyPath(root)), true, "drive file kept");
  assert.match(cli(["key-info", root]).out, /this-pc/, "this PC's half kept");
  const { reply, log } = send(getRequest([]), { root });
  assert.equal(reply.fallback, true);
  assert.match(log.at(-1), /^tell:This PlugPass drive is locked/);
});

test("each try is counted on the drive before the PIN is checked", () => {
  const root = newDrive("drive-readonly");
  chmodSync(keyPath(root), 0o444); // the count can't be saved, so the PIN must not be tested
  try {
    const r = cli(["unlock-check", root], [PIN]);
    assert.equal(r.code, 6, r.err);
    assert.equal(r.out.includes("ok"), false);
  } finally {
    chmodSync(keyPath(root), 0o666);
  }
  assert.equal(cli(["unlock-check", root], [PIN]).code, 0, "works again once writable");
});

test("parallel attempts can't share one try (one PlugPass at a time)", async () => {
  const root = newDrive("drive-parallel");
  const run = (pin) =>
    new Promise((resolve) => {
      const p = spawn(exe, ["unlock-check", root], {
        env: { ...process.env, PLUGPASS_HOME: home },
      });
      p.stdin.end(`${pin}\r\n`);
      p.on("exit", resolve);
    });
  const codes = await Promise.all([1, 2, 3, 4].map((i) => run(`wrong-pin-${i}`)));
  assert.deepEqual(codes, [3, 3, 3, 3]);
  assert.match(cli(["key-info", root]).out, /tries-left 4 /);
});

test("links on the drive are never followed", () => {
  const root = newDrive("drive-links");
  // A planted temp-file link pointing at a folder elsewhere: removed, and the target is untouched.
  const victim = join(out, "victim");
  mkdirSync(victim, { recursive: true });
  writeFileSync(join(victim, "keep.txt"), "important");
  const temp = `${keyPath(root)}.tmp`;
  assert.equal(spawnSync("cmd", ["/c", "mklink", "/J", temp, victim]).status, 0);
  assert.equal(cli(["unlock-check", root], ["wrong-pin-1"]).code, 3);
  assert.equal(readFileSync(join(victim, "keep.txt"), "utf8"), "important");
  assert.equal(existsSync(temp), false);
  // A PlugPass folder that is itself a link: refused.
  const linked = join(out, "drive-linked-folder");
  mkdirSync(linked, { recursive: true });
  assert.equal(
    spawnSync("cmd", ["/c", "mklink", "/J", join(linked, "PlugPass"), join(root, "PlugPass")])
      .status,
    0,
  );
  assert.equal(cli(["key-info", linked]).code, 6);
});

test("a key file asking for absurd PBKDF2 work is refused", () => {
  const root = newDrive("drive-iterations");
  const bytes = readFileSync(keyPath(root));
  bytes.writeInt32LE(100000000, 12);
  writeFileSync(keyPath(root), bytes);
  assert.equal(cli(["key-info", root]).code, 6);
});

test("only the PlugPass extension may start the helper as a native host", () => {
  const r = spawnSync(
    exe,
    ["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/", "--auto-approve"],
    {
      input: frame(createRequest()),
      env: { ...process.env, PLUGPASS_HOME: home },
    },
  );
  assert.equal(r.status, 2);
  assert.equal(r.stdout.length, 0);
});

test("wiping through the PIN window tells the person and lets the browser take over", () => {
  const root = newDrive("drive-wipe-host");
  const id = parseCreate(send(createRequest(), { root }).reply).cred.id;
  for (let i = 1; i <= 7; i++) cli(["unlock-check", root], [`wrong-${i}-pin`]); // 7 wrong in a row
  const { reply, log } = send(getRequest([id]), { root, pins: ["wrong-8-pin"] });
  assert.deepEqual(log[0], "pin:get:webauthn.io:1");
  assert.equal(reply.fallback, true);
  assert.match(log.at(-1), /^tell:Too many wrong PINs/);
  assert.equal(existsSync(keyPath(root)), false);
});

test("change-pin: the old PIN stops working, keys keep working with the new one", () => {
  const root = newDrive("drive-change");
  const { cred, publicKey } = parseCreate(send(createRequest(), { root }).reply);
  assert.equal(cli(["change-pin", root], ["wrong-pin-x", "new-pin-123", "new-pin-123"]).code, 3);
  assert.equal(cli(["change-pin", root], [PIN, "short", "short"]).code, 7);
  assert.equal(cli(["change-pin", root], [PIN, "new-pin-123", "other-pin-1"]).code, 7);
  assert.equal(cli(["change-pin", root], [PIN, "new-pin-123", "new-pin-123"]).code, 0);
  assert.equal(cli(["unlock-check", root], [PIN]).code, 3);
  const req = getRequest([cred.id]);
  checkAssertion(send(req, { root, pins: ["new-pin-123"] }).reply, req, publicKey);
});

test("create-key refuses weak PINs, mismatches and overwriting", () => {
  const root = join(out, "drive-rules");
  mkdirSync(root, { recursive: true });
  assert.equal(cli(["create-key", root], ["12345", "12345"]).code, 7, "too short");
  assert.equal(cli(["create-key", root], ["123456", "123457"]).code, 7, "mismatch");
  assert.equal(cli(["create-key", root], ["123456", "123456"]).code, 0, "6 digits is enough");
  assert.equal(cli(["create-key", root], ["abcdefg", "abcdefg"]).code, 7, "already has a key");
  assert.equal(cli(["create-key", join(out, "no-such-dir")], [PIN, PIN]).code, 7);
});

test("the real build only makes keys on removable drives", () => {
  const root = join(out, "drive-real");
  mkdirSync(root, { recursive: true });
  const r = cli(["create-key", root], [PIN, PIN], {}, realExe);
  assert.equal(r.code, 7);
  assert.match(r.err, /Not a removable drive/);
  assert.equal(existsSync(keyPath(root)), false);
});

test("no drive, a damaged drive or another PC's drive: silent hand-over to the browser", () => {
  const { cred } = register();
  // No drive plugged in.
  let r = send(getRequest([cred.id]), { root: null });
  assert.equal(r.reply.fallback, true);
  assert.match(r.reply.message, /No PlugPass drive/);
  assert.deepEqual(r.log, []);
  // A drive set up on another PC: this PC (another PLUGPASS_HOME) lacks its half of the key.
  const otherPc = join(out, "other-pc-home");
  mkdirSync(otherPc, { recursive: true });
  r = send(getRequest([cred.id]), { env: { PLUGPASS_HOME: otherPc } });
  assert.equal(r.reply.fallback, true);
  assert.match(r.reply.message, /another PC/);
  assert.deepEqual(r.log, []);
  // A damaged key file.
  const root = newDrive("drive-damaged");
  writeFileSync(keyPath(root), readFileSync(keyPath(root)).subarray(0, 50));
  r = send(createRequest(), { root });
  assert.equal(r.reply.fallback, true);
  assert.deepEqual(r.log, []);
});

test("another drive's credentials are ignored without asking for the PIN", () => {
  const other = newDrive("drive-other");
  const { cred } = parseCreate(send(createRequest(), { root: other }).reply);
  const { reply, log } = send(getRequest([cred.id]));
  assert.equal(reply.fallback, true);
  assert.deepEqual(log, []);
});

test("a credential is bound to its site: a webauthn.io key doesn't sign for google.com", () => {
  const { cred } = register();
  const req = getRequest([cred.id], { rpId: "google.com" }, "https://accounts.google.com");
  const { reply } = send(req);
  assert.equal(reply.status, "error");
  assert.equal(reply.fallback, true);
});

test("tampered credential IDs from this drive are refused", () => {
  const { credId } = register();
  const tampered = Buffer.from(credId);
  tampered[40] ^= 1;
  const { reply } = send(getRequest([b64u(tampered)]));
  assert.equal(reply.name, "NotAllowedError");
  assert.equal(reply.fallback, true);
});

test("create: a key already registered with the account gives InvalidStateError", () => {
  const { cred } = register();
  const { reply, log } = send(
    createRequest({ excludeCredentials: [{ type: "public-key", id: cred.id }] }),
  );
  assert.equal(reply.name, "InvalidStateError");
  assert.equal(reply.fallback, false);
  assert.equal(log.length, 1, "asked for the PIN first");
});

test("rejects pages whose origin doesn't match, and non-https pages, without asking", () => {
  const { cred } = register();
  for (const origin of [
    "https://evil.example",
    "https://webauthn.io.evil.example",
    "https://xwebauthn.io",
  ]) {
    const { reply, log } = send(getRequest([cred.id], {}, origin));
    assert.equal(reply.name, "SecurityError", origin);
    assert.deepEqual(log, []);
  }
  for (const origin of [
    "http://webauthn.io",
    "https://webauthn.io/path",
    "https://user@webauthn.io",
    "",
  ]) {
    const { reply, log } = send({ ...createRequest(), origin });
    assert.equal(reply.name, "SecurityError", origin);
    assert.deepEqual(log, []);
  }
  const { reply } = send({
    ...createRequest({ rp: { id: "example.com" } }),
    origin: "https://example.com",
  });
  assert.equal(reply.name, "NotSupportedError");
  assert.equal(reply.fallback, true);
});

test("Cancel rejects; 'Use another key' hands over to the browser", () => {
  const { cred } = register();
  let r = send(getRequest([cred.id]), { decision: "--auto-deny" });
  assert.equal(r.reply.fallback, false);
  r = send(getRequest([cred.id]), { decision: "--auto-fallback" });
  assert.equal(r.reply.fallback, true);
});

test("requests PlugPass can't serve, and invalid ones", () => {
  for (const req of [
    createRequest({ authenticatorSelection: { authenticatorAttachment: "platform" } }),
    createRequest({ pubKeyCredParams: [{ type: "public-key", alg: -257 }] }),
  ]) {
    const { reply, log } = send(req);
    assert.equal(reply.name, "NotSupportedError");
    assert.equal(reply.fallback, true);
    assert.deepEqual(log, []);
  }
  assert.equal(send(createRequest({ challenge: b64u(randomBytes(8)) })).reply.name, "TypeError");
  assert.equal(send(createRequest({ user: { id: "" } })).reply.name, "TypeError");
  assert.equal(
    send({ type: "delete", origin: "https://webauthn.io", options: {} }).reply.name,
    "NotSupportedError",
  );
  const lengthOnly = frame({ type: "get" }).subarray(0, 4); // says a body follows, but none does
  assert.equal(send(null, { raw: lengthOnly }).reply, null);
  const huge = Buffer.alloc(4);
  huge.writeUInt32LE(10 * 1024 * 1024);
  const r = send(null, { raw: huge });
  assert.equal(r.reply.status, "error");
  assert.equal(r.code, 1);
});
