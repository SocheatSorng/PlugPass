// Runs the extension's classic content scripts (codec.js, inject.js) in a sandbox with a fake
// browser, to check what they forward to PlugPass, what they leave to the browser, and what the
// page gets back.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const source = (name) => readFileSync(new URL(`../extension/src/${name}`, import.meta.url), "utf8");

function loadCodec() {
  const ctx = vm.createContext({ btoa });
  vm.runInContext(`${source("codec.js")}\nthis.PlugPassCodec = PlugPassCodec;`, ctx);
  return ctx.PlugPassCodec;
}

// A fake page: records what inject.js posts and lets the test answer as the bridge would.
function loadInject(answer) {
  class PublicKeyCredential {}
  class AuthenticatorAttestationResponse {}
  class AuthenticatorAssertionResponse {}
  const listeners = [];
  const posted = [];
  const originalCalls = [];
  const win = {
    location: { origin: "https://webauthn.io" },
    PublicKeyCredential,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
    addEventListener: (type, fn) => listeners.push(fn),
    postMessage: (data) => {
      posted.push(data);
      const reply = answer(data);
      if (reply !== undefined) {
        setImmediate(() => {
          const event = {
            source: win,
            data: { channel: data.channel, dir: "reply", id: data.id, reply },
          };
          listeners.forEach((fn) => fn(event));
        });
      }
    },
  };
  const credentials = {
    create: async (o) => (originalCalls.push(["create", o]), "browser-create"),
    get: async (o) => (originalCalls.push(["get", o]), "browser-get"),
  };
  const logs = [];
  const ctx = vm.createContext({
    window: win,
    navigator: { credentials },
    atob,
    DOMException,
    console: { info: (m) => logs.push(m) },
  });
  vm.runInContext(source("inject.js"), ctx);
  return { credentials, posted, originalCalls, win, logs };
}

const createOptions = (sel = {}) => ({
  publicKey: {
    challenge: new Uint8Array(32),
    rp: { id: "webauthn.io", name: "x" },
    user: { id: new Uint8Array([1, 2]), name: "u", displayName: "U" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: sel,
  },
});
const getOptions = (extra = {}) => ({
  publicKey: {
    challenge: new Uint8Array(32),
    allowCredentials: [{ type: "public-key", id: new Uint8Array([9]) }],
    ...extra,
  },
});

const okCreate = {
  status: "ok",
  credential: {
    id: "AQID",
    rawId: "AQID",
    type: "public-key",
    authenticatorAttachment: "cross-platform",
    clientExtensionResults: {},
    response: {
      clientDataJSON: "e30",
      attestationObject: "oA",
      authenticatorData: "AA",
      publicKey: "BA",
      publicKeyAlgorithm: -7,
      transports: ["usb"],
    },
  },
};

test("codec: binary becomes base64url, junk is dropped", () => {
  const codec = loadCodec();
  const out = codec.toJsonSafe({
    challenge: new Uint8Array([251, 255, 0]).buffer,
    user: { id: new Uint8Array([1, 2, 3]) },
    view: new DataView(new Uint8Array([4, 5, 6, 7]).buffer, 1, 2),
    list: [{ id: new Uint16Array([0xffff]) }, () => 1],
    fn: () => 1,
    nan: Number.NaN,
    when: new Date(0),
    ok: true,
    n: -7,
  });
  assert.deepEqual(JSON.parse(JSON.stringify(out)), {
    challenge: "-_8A",
    user: { id: "AQID" },
    view: "BQY",
    list: [{ id: "__8" }],
    ok: true,
    n: -7,
  });
});

test("codec: refuses absurdly deep options", () => {
  const codec = loadCodec();
  let deep = {};
  for (let i = 0; i < 20; i++) deep = { deep };
  assert.throws(() => codec.toJsonSafe(deep), /deeply/);
});

test("inject: a security-key registration goes to PlugPass and returns a real-looking credential", async () => {
  const page = loadInject(() => okCreate);
  const cred = await page.credentials.create(createOptions({ userVerification: "discouraged" }));
  assert.equal(page.posted.length, 1);
  assert.equal(page.posted[0].kind, "create");
  assert.equal(page.originalCalls.length, 0);
  assert.ok(cred instanceof page.win.PublicKeyCredential);
  assert.ok(cred.response instanceof page.win.AuthenticatorAttestationResponse);
  assert.equal(cred.id, "AQID");
  assert.deepEqual(new Uint8Array(cred.rawId), new Uint8Array([1, 2, 3]));
  assert.equal(cred.response.getPublicKeyAlgorithm(), -7);
  assert.deepEqual(cred.response.getTransports(), ["usb"]);
  // Objects made inside the sandbox have the sandbox's prototypes, so compare their contents.
  assert.equal(JSON.stringify(cred.getClientExtensionResults()), "{}");
  assert.equal(cred.toJSON().id, "AQID");
});

test("inject: sign-in replies become assertion responses", async () => {
  const page = loadInject(() => ({
    status: "ok",
    credential: {
      ...okCreate.credential,
      response: {
        clientDataJSON: "e30",
        authenticatorData: "AA",
        signature: "MA",
        userHandle: null,
      },
    },
  }));
  const cred = await page.credentials.get(getOptions());
  assert.ok(cred.response instanceof page.win.AuthenticatorAssertionResponse);
  assert.equal(cred.response.userHandle, null);
  assert.equal(cred.response.signature.byteLength, 1);
});

test("inject: requests PlugPass can't serve go straight to the browser", async () => {
  const page = loadInject(() => okCreate);
  const cases = [
    ["create", createOptions({ residentKey: "required" })],
    ["create", createOptions({ requireResidentKey: true })],
    ["create", createOptions({ userVerification: "required" })],
    ["create", createOptions({ authenticatorAttachment: "platform" })],
    ["get", getOptions({ userVerification: "required" })],
    ["get", getOptions({ allowCredentials: [] })],
    ["get", { ...getOptions(), mediation: "conditional" }],
    ["get", { password: true }],
  ];
  for (const [kind, options] of cases) {
    const r = await (kind === "create"
      ? page.credentials.create(options)
      : page.credentials.get(options));
    assert.equal(r, `browser-${kind}`, JSON.stringify(options));
  }
  assert.equal(page.posted.length, 0);
  // Every WebAuthn case says why in the console (the password request isn't WebAuthn: silent).
  assert.equal(page.logs.length, cases.length - 1);
  assert.match(page.logs[0], /^PlugPass: create handed to the browser: .*residentKey: required/);
  assert.match(page.logs[2], /userVerification: required/);
  assert.match(page.logs[6], /conditional mediation/);
});

test("inject: a fallback reply hands the same request to the browser", async () => {
  const page = loadInject(() => ({
    status: "error",
    name: "NotAllowedError",
    message: "This account doesn't use this PlugPass key.",
    fallback: true,
  }));
  const options = getOptions();
  assert.equal(await page.credentials.get(options), "browser-get");
  assert.equal(page.originalCalls[0][1], options);
  assert.deepEqual(page.logs, [
    "PlugPass: get handed to the browser: This account doesn't use this PlugPass key.",
  ]);
});

test("inject: a refusal rejects with the named DOMException", async () => {
  const page = loadInject(() => ({
    status: "error",
    name: "NotAllowedError",
    message: "Cancelled.",
    fallback: false,
  }));
  await assert.rejects(page.credentials.get(getOptions()), (err) => {
    assert.equal(err.name, "NotAllowedError");
    assert.equal(err.message, "Cancelled.");
    return true;
  });
});

test("inject: an already-aborted signal rejects without asking PlugPass", async () => {
  const page = loadInject(() => okCreate);
  const options = { ...getOptions(), signal: { aborted: true } };
  await assert.rejects(page.credentials.get(options), { name: "AbortError" });
  assert.equal(page.posted.length, 0);
});
