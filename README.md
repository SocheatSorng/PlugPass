# PlugPass

Turn a normal USB flash drive into a security key:

- **Google sign-in** (Chrome and Edge): plug in the drive, type your PIN, done.
- **Windows sign-in** (local account): plug in the drive and Windows signs you in.

Your normal password keeps working for both, with or without the drive.

> Status: early development. Nothing is usable yet. See [docs/spec.md](docs/spec.md) for the plan.

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
.\build.ps1      # bin\PlugPass.exe, bin\test\PlugPass.exe, bin\extension\
.\test.ps1       # JavaScript + PowerShell tests (fake drives only)
```

Security checks:

```powershell
npm audit                  # dependency vulnerabilities
pre-commit install         # gitleaks, private keys, large files, JSON/YAML, zizmor, lint on every commit
```

CI (`.github/workflows/`) runs lint, build and tests, plus gitleaks, ESLint security rules,
npm audit, zizmor and CodeQL.
