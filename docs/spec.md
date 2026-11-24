# PlugPass spec

Status: draft, 2026-11-24. Intent: [docs/intent/usb-security-key.md](intent/usb-security-key.md).

## Objective

Turn a normal USB flash drive into a security key for:

1. **Google sign-in** in Chrome/Edge: drive + PIN (min 6 characters).
2. **Windows sign-in** for one local account on one PC: drive only, no typing.

The normal password always keeps working for both. Nothing PlugPass does may ever block it.

## Parts

| Part | Folder | Language | Does |
|---|---|---|---|
| Helper app | `host/` | C# 5, .NET Framework 4.8 (Windows' own csc) | Security-key logic, drive setup, PIN prompt, Chrome native messaging host |
| Browser extension | `extension/` | JavaScript, Manifest V3 | Answers Google's security-key requests by asking the helper app |
| Sign-in tile | `credprov/` (later) | C++ (COM DLL) | Windows credential provider: signs in when the drive is present |

### 1. Google: software security key

Windows 10 has no way for an app to register itself as a security key with the browser
(Windows 11 passkey-provider plugins don't exist here), and a flash drive can't speak the USB
security-key protocol. So the extension stands in:

- A content script in the page's own world, only on Google's sign-in and account pages, wraps
  `navigator.credentials.create/get`. When Google asks for a security key, it forwards the request
  (via an isolated content script and the service worker) to the helper app over native messaging.
- The helper app acts like a CTAP2 authenticator: it finds the PlugPass drive, asks for the PIN in
  its own window (never in the web page), and creates or signs with an ES256 (P-256) credential.
- **Keys:** the drive holds one random master secret in `PlugPass\plugpass.ppkey`, encrypted under
  the PIN (PBKDF2-SHA256 600k + AES-256-CBC + HMAC-SHA256, like VaultKeep's `PinBox`). Each site
  credential's private key is wrapped by that master secret inside the credential ID, so nothing
  per-site needs to be stored. A signature counter lives on the drive.
- Attestation: `none` (self). The origin and RP ID come from the browser (`sender.origin`), never
  from page-supplied data.
- PIN guessing: 8 wrong PINs in a row wipe the master secret on that drive (like a hardware key);
  the helper warns from attempt 5.

**Risk to test first (phase 1):** Google may reject an assertion that doesn't come from the browser's
real WebAuthn stack, or may want hardware attestation. Phase 1 proves the round trip on webauthn.io,
then on a Google account, before anything else is built.

### 2. Windows: sign-in tile (credential provider)

- Enrolment (in the helper app, after a Windows password check): asks for the Windows password once,
  creates a random 32-byte key **K** and writes it to the drive. The password is encrypted with K and
  then with machine-scope DPAPI, and stored on the PC in a folder only SYSTEM and Administrators can
  read. The drive alone is useless (the PC has the password blob); the PC alone is useless (the drive has K).
- At the sign-in screen, the tile looks for a drive with a K that decrypts this PC's blob. If found, it
  signs in automatically (auto-logon credential). If not, it shows nothing, and the normal password
  tile works as always.
- If the Windows password changes, sign-in with the stored one fails: the tile steps aside and the
  helper asks to re-enrol at the next sign-in.
- PlugPass never filters or hides Windows' own providers (no `ICredentialProviderFilter`). Safe Mode
  doesn't load third-party providers, so it is always a way back in.
- Needs a C++ compiler (Visual Studio Build Tools); not installed yet. Decide before phase 4.

## Phases

0. **Foundation** (done): repo, lint, tests, pre-commit, CI, security workflows, agent, CLAUDE.md.
1. **Spike: does Google accept it?** Minimal extension + helper with an in-memory test key. Register and
   sign in on webauthn.io, then on Google (owner's choice of account). Stop and report if Google refuses.
2. **Drive key + PIN:** key file format, PIN box, wrong-PIN counter, drive detection; full tests with a
   folder standing in for the drive (`--key-dir`, test build only).
3. **Google, finished:** setup window (prepare drive, set PIN), native host registration in HKCU,
   extension install steps, PIN dialog (designed with the UI designer agent).
4. **Windows sign-in tile:** enrolment, C++ credential provider, tested in a harness that calls it
   without registering it; registered on the real sign-in screen only with the owner's OK.
5. **Release:** installer/uninstaller, `/security-review`, README for users.

## Success criteria

- The drive is added as a security key in Google account settings, and signing in to Google with it works.
- Restarting the PC with the drive in reaches the desktop without typing. Without it, the password works.
- A copied drive does nothing on another PC, and a copied key file needs the PIN for Google.
- Lint, build and all tests pass on every change; CI is green.

## Boundaries

- **Always:** password fallback; tests use fake drives (`--key-dir`) and `PLUGPASS_HOME` under `tests/out/`.
- **Ask first:** registering the native host, loading the extension, registering the sign-in tile,
  touching the owner's real Google account, installing build tools.
- **Never:** store or log the Windows password, PIN or master secret in plain text; put secrets on a
  command line; weaken crypto parameters; ship the test build.
