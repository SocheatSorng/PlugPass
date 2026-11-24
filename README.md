# PlugPass

Turn a normal USB flash drive into a security key:

- **Google sign-in** (Brave, Chrome and Edge): plug in the drive, type your PIN, done.
- **Windows sign-in** (local account, planned): plug in the drive and Windows signs you in.

Your normal password keeps working, with or without the drive.

> Status: Google sign-in works (drive + PIN, as a passkey or as a second step). Windows sign-in is
> planned. See [docs/spec.md](docs/spec.md).

## Install (users)

1. Unzip `PlugPass-<version>.zip` anywhere and double-click `PlugPass.exe`.
2. Click **Install**. PlugPass installs for your Windows account only (no administrator rights) into
   `%LOCALAPPDATA%\Programs\PlugPass` and registers itself with Brave, Chrome and Edge.
3. Add the extension (browsers only let the Web Store install extensions automatically):
   open `brave://extensions` (or `chrome://extensions`, `edge://extensions`), turn on
   **Developer mode**, click **Load unpacked** and choose `%LOCALAPPDATA%\Programs\PlugPass\extension`.
   The installer opens that folder for you.

## Use

1. **Set up a drive:** Start menu > **PlugPass**. Pick your USB flash drive, choose a PIN (6+
   characters; letters make it much stronger) and click **Set up drive**. Only a `PlugPass` folder
   is added; your other files stay as they are.
2. **Add it to Google:** Google Account > Security > **Passkeys and security keys** > **Create a
   passkey** > **Use another device**. Type your PIN in the PlugPass window and click **Add**.
   Google holds new keys for a few days unless you approve them with a passkey you already have.
3. **Sign in:** plug in the drive; when Google asks for your passkey or security key, PlugPass asks
   for your PIN.

Good to know:

- The drive works for Google only on the PC where you set it up (a copied drive is useless elsewhere).
- 8 wrong PINs in a row erase the key on the drive. Your password still works; set the drive up again
  and add it to Google again.
- Without the drive, PlugPass stays out of the way and your browser behaves as usual.
- **Uninstall:** if you turned on Windows sign-in, first open PlugPass → **Windows sign-in...** →
  **Turn off for all drives** (that removes the sign-in tile, which needs admin rights). Then
  Settings > Apps > PlugPass. Your drive keeps working for Google after a reinstall. Remove the
  extension from your browser too.

## Windows sign-in (local account)

PlugPass → **Windows sign-in...** (one admin prompt) → type your Windows password → **Turn on**. With the
drive plugged in, Windows signs you in and unlocks without typing; without it, your password works as
always. Needs a drive formatted as FAT32 or exFAT. Anyone holding the drive can sign in to this PC as
you, so keep it safe; lost it? **Turn off for all drives**. If the sign-in screen ever misbehaves, see
[docs/windows-signin-recovery.md](docs/windows-signin-recovery.md).

## How it works (short)

- A small **helper app** (`host/`, C#) holds the security-key logic and talks to the drive.
- A **browser extension** (`extension/`) passes Google's security-key requests to the helper app.
- A **Windows sign-in tile** (`credprov/`, later) unlocks your account when the drive is present.

A flash drive is not a hardware key: its files can be copied. PlugPass limits what a copy is worth:
Google needs the PIN, and the Windows sign-in only works on your own PC.

## Requirements

- Windows 10 or 11
- .NET Framework 4.8 (built into Windows)
- Node.js 22+ (only for linting and tests)
- Chrome or Edge 120+

## Develop

```powershell
npm ci           # once: lint tools (ESLint, Prettier)
.\lint.ps1       # C# warnings as errors, ESLint + security rules, Prettier, text checks
.\build.ps1      # bin\PlugPass.exe, bin\test\PlugPass.exe, bin\extension\, dist\PlugPass-<version>.zip
.\test.ps1       # JavaScript + PowerShell tests (fake drives only)
```

Security checks:

```powershell
npm audit                  # dependency vulnerabilities
pre-commit install         # gitleaks, private keys, large files, JSON/YAML, zizmor, lint on every commit
```

CI (`.github/workflows/`) runs lint, build and tests, plus gitleaks, ESLint security rules,
npm audit, zizmor and CodeQL.
