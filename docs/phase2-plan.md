# Phase 2 plan: the key moves onto the USB drive, behind a PIN, and becomes a passkey

Status: draft for the owner's OK, 2026-11-24. Builds on phase 1 (Google accepts PlugPass keys).

## What changes for the owner

- Google sign-in works only when the PlugPass USB drive is plugged in **and** the PIN is typed into
  PlugPass's own window. No drive: PlugPass stays silent and the browser behaves as usual.
- PlugPass can be a **passkey** for Google ("Use your passkey to confirm it's really you"), not only a
  second step after the password.
- A small **PlugPass setup** window prepares a drive (choose drive, set PIN) and can change the PIN.
- The phase 1 test key stops working (it was never on a drive). Remove it from the Google account and
  add the USB key instead, approved from the iPhone passkey to skip Google's 6-day delay.

## Design

**On the drive:** `<drive>:\PlugPass\plugpass.ppkey` (one file, a few KB).

| Part | Stored as |
|---|---|
| Header: format version, key ID, PIN salt, PBKDF2 iterations, wrong-PIN count | plain (needed before the PIN) |
| Master secret (32 bytes) + passkey list + signature counter | AES-256-CBC + HMAC-SHA256 under a key from PBKDF2-SHA256 (600k) of the PIN (decision 1 may add a PC secret) |

- **Passkeys stored on the drive** (discoverable credentials): the passkey list keeps site, account
  name and credential ID, so "sign in without typing a username" works. If an account has several,
  the PIN window lets you pick one.
- **PIN = user verification:** every operation asks for the PIN, so PlugPass reports "user verified"
  to sites (flag UV) and can serve the requests phase 1 had to hand to the browser.
- **Signature counter** increases with each sign-in (helps sites detect cloned keys).
- **Writes are safe:** the file is written to a temp name on the drive and renamed only when complete;
  a pulled-out drive mid-write keeps the old file.
- **Never blocks the password:** a missing, damaged or unreadable drive means "let the browser handle
  it", never an error that stops sign-in.
- Passkey autofill (conditional mediation) still goes to the browser, so PlugPass doesn't pop up on
  every Google page load.

**PIN window** (replaces the phase 1 consent window): site name, PIN box, tries left, buttons
*Sign in/Add*, *Use another key*, *Cancel*. Designed with the `winforms-ui-designer` agent.

## Decisions for the owner

1. **Bind the Google key to this PC too?**
   - *Recommended: yes.* The PIN key is derived from the PIN **and** a secret kept on this PC (DPAPI).
     A copied drive is useless elsewhere and its PIN can't be guessed offline without this PC.
     Cost: the drive works for Google only on this PC (other PCs were already out of scope).
   - *No:* drive + PIN works on any PC with PlugPass. A copied drive file with a 6-digit PIN could be
     cracked offline in days by someone with a fast computer.
2. **Too many wrong PINs?**
   - *Recommended: wipe after 8 wrong PINs in a row* (like a hardware key). The PlugPass file on the
     drive is erased; you re-create it and re-add the key to Google (the password still works).
   - *Pause only:* after 5 wrong PINs, wait longer each time. Never erases anything.
3. **PIN rules:** minimum 6 characters; digits or letters allowed (letters are much stronger).

## Build steps (each: code + tests, then lint/build/test, then commit)

1. **Key file format + PIN box** (`host/src/KeyFile.cs`): create, open with PIN, wrong-PIN count,
   wipe/pause, atomic write, version check. Tests with fake drives (`--key-dir`, test build only).
2. **Drive finding:** scan removable drives for `PlugPass\plugpass.ppkey`; `--no-drive-scan` in tests.
3. **Authenticator on the drive:** master from the key file instead of the phase 1 file; UV flag;
   signature counter; passkeys (discoverable credentials) for create and get; account picker.
   End-to-end Node tests extended (resident keys, UV, counter, no drive, damaged drive).
4. **Extension:** stop skipping "passkey" and "PIN required" requests (keep skipping autofill).
5. **PIN window + setup window** (`PlugPass setup`), UI checked with the designer agent.
6. **Remove the phase 1 test key file** support and `SpikeMaster.cs`; update README and manual test.
7. `/security-review` of crypto, PIN handling and file writes on the drive.

Manual test at the end: prepare a real USB drive, add it to Google as a passkey, approve it from the
iPhone, sign in with drive + PIN, and confirm nothing happens with the drive unplugged.
