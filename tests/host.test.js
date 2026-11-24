// End-to-end tests of the helper app as a native messaging host. Node starts bin\test\PlugPass.exe the
// way Chrome does, sends create/get requests and checks the replies independently with Node's crypto.
// The helper's data (spike master secret) goes to tests/out/node-host via PLUGPASS_HOME.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, createPublicKey, verify, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";

const exe = fileURLToPath(new URL("../bin/test/PlugPass.exe", import.meta.url));
const home = fileURLToPath(new URL("./out/node-host", import.meta.url));
const EXT = "chrome-extension://amppkfbnjicgeeakigkmafdllhknaigl/";

before(() => {
  assert.ok(existsSync(exe), "build first: .\\build.ps1");
  rmSync(home, { recursive: true, force: true });
  mkdirSync(home, { recursive: true });
});
after(() => rmSync(home, { recursive: true, force: true }));

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const fromB64u = (s) => Buffer.from(s, "base64url");
const sha256 = (data) => createHash("sha256").update(data).digest();

function frame(obj) {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32LE(body.length);
  return Buffer.concat([len, body]);
}

// Sends one request; returns { reply, consent: [lines logged by the scripted consent], code }.
function send(request, consent = "--auto-approve", rawInput = null) {
  const r = spawnSync(exe, [EXT, consent], {
    input: rawInput ?? frame(request),
    env: { ...process.env, PLUGPASS_HOME: home },
    timeout: 30000,
  });
  const out = r.stdout;
  let reply = null;
  if (out.length >= 4) {
    const len = out.readUInt32LE(0);
    reply = JSON.parse(out.subarray(4, 4 + len).toString("utf8"));
  }
  const consentLines = r.stderr
    .toString()
    .split(/\r?\n/)
    .filter((l) => l.startsWith("consent:"));
  return { reply, consent: consentLines, code: r.status };
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

function createRequest(overrides = {}) {
  return {
    type: "create",
    origin: "https://webauthn.io",
    options: {
      rp: { id: "webauthn.io", name: "WebAuthn.io" },
      user: { id: b64u(Buffer.from("user-1234")), name: "test", displayName: "Test" },
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

function getRequest(credId, overrides = {}, origin = "https://webauthn.io") {
  return {
    type: "get",
    origin,
    options: {
      rpId: "webauthn.io",
      challenge: b64u(randomBytes(32)),
      allowCredentials: [{ type: "public-key", id: credId }],
      userVerification: "discouraged",
      ...overrides,
    },
  };
}

// Registers once and parses everything a relying party would check.
let registered;
function register() {
  if (registered) return registered;
  const req = createRequest();
  const { reply, consent } = send(req);
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
  registered = { req, reply, consent, cred, att, authData, credId, cose, rest, publicKey };
  return registered;
}

test("create: returns a 'none' attestation a relying party accepts", () => {
  const { req, consent, cred, att, authData, credId, cose, rest, publicKey } = register();
  assert.deepEqual(consent, ["consent:create:webauthn.io"]);
  assert.equal(cred.type, "public-key");
  assert.equal(cred.id, cred.rawId);
  assert.equal(att.get("fmt"), "none");
  assert.equal(att.get("attStmt").size, 0);
  assert.deepEqual(authData.subarray(0, 32), sha256("webauthn.io"));
  assert.equal(authData[32], 0x41, "flags: user present + attested credential data");
  assert.equal(authData.readUInt32BE(33), 0, "sign counter");
  assert.deepEqual(authData.subarray(37, 53), Buffer.alloc(16), "AAGUID");
  assert.equal(b64u(credId), cred.id);
  assert.equal(rest.length, 0, "nothing after the COSE key");
  assert.equal(cose.get(1), 2, "kty EC2");
  assert.equal(cose.get(3), -7, "alg ES256");
  assert.equal(cose.get(-1), 1, "crv P-256");
  assert.equal(cred.response.publicKeyAlgorithm, -7);
  assert.deepEqual(
    publicKey.export({ type: "spki", format: "der" }),
    fromB64u(cred.response.publicKey),
    "getPublicKey() matches the COSE key",
  );
  assert.equal(cred.response.authenticatorData, b64u(authData));
  const clientData = JSON.parse(fromB64u(cred.response.clientDataJSON).toString("utf8"));
  assert.deepEqual(clientData, {
    type: "webauthn.create",
    challenge: req.options.challenge,
    origin: "https://webauthn.io",
    crossOrigin: false,
  });
});

test("get: signs with the registered key (verified with Node crypto)", () => {
  const { cred, publicKey } = register();
  for (let i = 0; i < 2; i++) {
    const req = getRequest(cred.id);
    const { reply, consent } = send(req);
    assert.equal(reply.status, "ok", JSON.stringify(reply));
    assert.deepEqual(consent, ["consent:get:webauthn.io"]);
    const r = reply.credential.response;
    const authData = fromB64u(r.authenticatorData);
    const clientDataJSON = fromB64u(r.clientDataJSON);
    assert.deepEqual(authData.subarray(0, 32), sha256("webauthn.io"));
    assert.equal(authData[32], 0x01, "flags: user present only");
    assert.equal(authData.length, 37);
    const clientData = JSON.parse(clientDataJSON.toString("utf8"));
    assert.equal(clientData.type, "webauthn.get");
    assert.equal(clientData.challenge, req.options.challenge);
    assert.equal(clientData.origin, "https://webauthn.io");
    const signed = Buffer.concat([authData, sha256(clientDataJSON)]);
    assert.ok(verify("sha256", signed, publicKey, fromB64u(r.signature)), "signature verifies");
    assert.equal(fromB64u(r.userHandle).toString(), "user-1234");
    assert.equal(reply.credential.id, cred.id);
  }
});

test("get: a subdomain page may use its parent domain as RP ID", () => {
  const { cred } = register();
  const { reply } = send(getRequest(cred.id, {}, "https://login.webauthn.io"));
  assert.equal(reply.status, "ok", JSON.stringify(reply));
});

test("rejects a page whose origin doesn't match the RP ID, without asking", () => {
  const { cred } = register();
  for (const origin of [
    "https://evil.example",
    "https://webauthn.io.evil.example",
    "https://xwebauthn.io",
  ]) {
    const { reply, consent } = send(getRequest(cred.id, {}, origin));
    assert.equal(reply.status, "error");
    assert.equal(reply.name, "SecurityError", origin);
    assert.equal(reply.fallback, false);
    assert.deepEqual(consent, []);
  }
});

test("rejects non-https and malformed origins", () => {
  for (const origin of [
    "http://webauthn.io",
    "https://webauthn.io/path",
    "https://user@webauthn.io",
    "chrome-extension://abc",
    "",
  ]) {
    const { reply, consent } = send({ ...createRequest(), origin });
    assert.equal(reply.name, "SecurityError", origin);
    assert.deepEqual(consent, []);
  }
});

test("sites outside the phase 1 allowlist go to the browser's own security key", () => {
  const req = createRequest({ rp: { id: "example.com", name: "Example" } });
  const { reply, consent } = send({ ...req, origin: "https://example.com" });
  assert.equal(reply.name, "NotSupportedError");
  assert.equal(reply.fallback, true);
  assert.deepEqual(consent, []);
});

test("a credential is bound to its site: a webauthn.io key doesn't sign for google.com", () => {
  const { cred } = register();
  const req = getRequest(cred.id, { rpId: "google.com" }, "https://accounts.google.com");
  const { reply, consent } = send(req);
  assert.equal(reply.status, "error");
  assert.equal(reply.fallback, true);
  assert.deepEqual(consent, []);
});

test("tampered or foreign credential IDs are ignored, without asking", () => {
  const { credId } = register();
  const tampered = Buffer.from(credId);
  tampered[20] ^= 1;
  for (const id of [b64u(tampered), b64u(randomBytes(120)), "not base64!", ""]) {
    const { reply, consent } = send(getRequest(id));
    assert.equal(reply.name, "NotAllowedError", id);
    assert.equal(reply.fallback, true);
    assert.deepEqual(consent, []);
  }
});

test("create: an already-registered key gives InvalidStateError (after asking)", () => {
  const { cred } = register();
  const { reply, consent } = send(
    createRequest({ excludeCredentials: [{ type: "public-key", id: cred.id }] }),
  );
  assert.equal(reply.name, "InvalidStateError");
  assert.equal(reply.fallback, false);
  assert.equal(consent.length, 1);
});

test("Cancel rejects; 'Use another key' hands over to the browser", () => {
  const { cred } = register();
  let r = send(getRequest(cred.id), "--auto-deny");
  assert.equal(r.reply.name, "NotAllowedError");
  assert.equal(r.reply.fallback, false);
  r = send(getRequest(cred.id), "--auto-fallback");
  assert.equal(r.reply.name, "NotAllowedError");
  assert.equal(r.reply.fallback, true);
  r = send(createRequest(), "--auto-deny");
  assert.equal(r.reply.fallback, false);
});

test("requests PlugPass can't honestly serve go to the browser", () => {
  const cases = [
    createRequest({ authenticatorSelection: { residentKey: "required" } }),
    createRequest({ authenticatorSelection: { requireResidentKey: true } }),
    createRequest({ authenticatorSelection: { userVerification: "required" } }),
    createRequest({ authenticatorSelection: { authenticatorAttachment: "platform" } }),
    createRequest({ pubKeyCredParams: [{ type: "public-key", alg: -257 }] }),
    getRequest("AAAA", { userVerification: "required" }),
    getRequest("AAAA", { allowCredentials: [] }),
  ];
  for (const req of cases) {
    const { reply, consent } = send(req);
    assert.equal(reply.name, "NotSupportedError", JSON.stringify(req.options));
    assert.equal(reply.fallback, true);
    assert.deepEqual(consent, []);
  }
});

test("invalid requests are refused", () => {
  let r = send(createRequest({ challenge: b64u(randomBytes(8)) }));
  assert.equal(r.reply.name, "TypeError");
  r = send(createRequest({ user: { id: "" } }));
  assert.equal(r.reply.name, "TypeError");
  r = send(createRequest({ user: { id: b64u(randomBytes(65)) } }));
  assert.equal(r.reply.name, "TypeError");
  r = send({ type: "delete", origin: "https://webauthn.io", options: {} });
  assert.equal(r.reply.name, "NotSupportedError");
  const lengthOnly = frame({ type: "get" }).subarray(0, 4); // says a body follows, but none does
  r = send(null, "--auto-approve", lengthOnly);
  assert.equal(r.reply, null, "truncated message: no reply");
});

test("oversized messages are refused before reading them", () => {
  const len = Buffer.alloc(4);
  len.writeUInt32LE(10 * 1024 * 1024);
  const r = send(null, "--auto-approve", len);
  assert.equal(r.reply.status, "error");
  assert.equal(r.code, 1);
});

test("several messages over one connection (connectNative) are all answered", () => {
  const { cred } = register();
  const input = Buffer.concat([frame(getRequest(cred.id)), frame(getRequest(cred.id))]);
  const r = spawnSync(exe, [EXT, "--auto-approve"], {
    input,
    env: { ...process.env, PLUGPASS_HOME: home },
  });
  const first = r.stdout.readUInt32LE(0);
  const second = r.stdout.readUInt32LE(4 + first);
  assert.equal(r.stdout.length, 8 + first + second);
});
