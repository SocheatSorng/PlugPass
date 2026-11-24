# PlugPass

Turns a normal USB flash drive into a security key for Google sign-in (Chrome/Edge extension +
helper app, drive + PIN) and Windows sign-in (credential provider, drive only, local account).
Plan and phases: `docs/spec.md`. Agreed intent: `docs/intent/usb-security-key.md`.

## Commands

```powershell
npm ci           # once: lint tools
.\lint.ps1       # C# warnings as errors (/warn:4), ESLint + eslint-plugin-security, Prettier, text checks
.\build.ps1      # bin\PlugPass.exe (real), bin\test\PlugPass.exe (TESTHOOKS), bin\extension\
.\test.ps1       # node --test tests/ + tests\test_*.ps1 against the test build
```

After every code change: run lint, build and tests, and report the results.

## Layout

- `host/src/`: helper app (C# 5, built with Windows' own csc.exe, no SDK). Security-key logic, drive
  key file, PIN prompt, native messaging host.
- `extension/`: Chrome/Edge MV3 extension. `src/protocol.js` defines messages to the helper app.
- `credprov/` (phase 4): C++ credential provider for Windows sign-in. Needs VS Build Tools.
- `tests/`: `*.test.js` (node:test) and `test_*.ps1` (PowerShell, dot-source `TestLib.ps1`).
  Scratch data only under `tests/out/`.

## Rules

- **C# 5 only** (the Windows-bundled compiler): no `$""`, `?.`, `nameof`, expression-bodied members.
- **The password always works.** A missing, damaged or fake drive must never block Windows or Google
  sign-in by password. The credential provider never filters or hides Windows' own providers.
- Secrets (Windows password, PIN, master secret, key K) are never logged, written in plain text,
  put on a command line or in a URL. Don't weaken crypto parameters (PBKDF2-SHA256 600k minimum).
- Trust the browser, not the page: origin/RP ID come from `sender.origin`, never from page data.
  The PIN is typed in the helper app's own window, never in a web page.
- Keep the extension's permissions minimal (`tests/extension.test.js` checks the manifest).
- Never change a file format (key file, credential ID, enrolment blob) without a version number and
  keeping old versions readable.
- Never register the native host, load the extension, register the credential provider, or use the
  owner's real Google account or drives during development or tests without the owner's OK.
- Tests never touch real drives or keys: `PLUGPASS_HOME` (TestLib sets it) and `--key-dir <folder>` as a
  fake drive. Test-only behaviour lives behind `#if TESTHOOKS` and exists only in `bin\test\PlugPass.exe`.
  Never install or ship the test build.
- Run `/security-review` before a release and whenever crypto, PIN handling, the native host,
  the credential provider or enrolment changes.
- Write files as UTF-8 with the Write/Edit tools (PowerShell 5.1 `Set-Content` garbles non-ASCII;
  `.\lint.ps1` catches it).
- UI changes (PIN prompt, setup window): use the `winforms-ui-designer` agent (`.claude/agents/`).
