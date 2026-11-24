# Phase 4 plan: Windows sign-in with the PlugPass drive

Status: draft for the owner's OK, 2026-11-24. Intent: drive plugged in at the sign-in screen, Windows
signs in the local account with no typing; no drive, the password works as always.

## How it works

- **Enrolment** (in the PlugPass setup window, once): you type your Windows password; PlugPass checks
  it with Windows, makes a random 32-byte key **K** and writes it to the drive
  (`PlugPass\windows.key`). The password is encrypted with K and then with Windows' machine-level
  protection (DPAPI, local machine), and stored in `%ProgramData%\PlugPass\` in a folder only
  SYSTEM and Administrators can read. Drive alone: useless (no password on it). PC alone: useless
  (no K). Needs admin rights once (UAC prompt), because it writes a protected system folder.
- **Sign-in tile** (credential provider, a COM DLL that Windows' sign-in screen loads): when the
  drive with a matching K is plugged in, the PlugPass tile signs in automatically. Otherwise it shows
  nothing and the normal password tile is used.
- **Password changed?** The stored password no longer works: the tile steps aside and the setup
  window asks you to enrol again.
- PlugPass never hides or filters Windows' own sign-in options.

## Safety plan (the sign-in screen is where a bug would hurt)

1. Build and test the tile in a **harness** that loads it like the sign-in screen does, but in a
   normal window with fake data. It is never registered on the real sign-in screen in this step.
2. Before the first real registration: a **system restore point**, and a written recovery recipe
   (Windows Recovery > Command Prompt > one `reg delete` line removes the tile).
3. Register with a single command you run yourself (admin), test sign-out/sign-in and the lock
   screen, and an equally simple unregister command.
4. The tile only reports itself for sign-in and unlock; it says "not for me" everywhere else (UAC
   prompts, "Windows Security" password boxes in apps), so it is never loaded there.

## Build steps

1. Toolchain (decision 1), then a minimal tile that shows up only in the harness.
2. Enrolment in the helper app + tests (fake drive, fake protected folder, no real password).
3. Tile: find drive, decrypt, hand Windows the sign-in (KERB_INTERACTIVE_UNLOCK_LOGON). Harness tests.
4. Setup window: "Use this drive to sign in to Windows" + re-enrol + remove.
5. Installer: register/unregister the tile (admin), uninstall removes it.
6. `/security-review`, then the real test with restore point and recovery recipe ready.

## Decisions for the owner

1. **Language of the sign-in tile.**
   - *Recommended: C++* (what Microsoft supports for sign-in tiles). Needs Visual Studio 2022 Build
     Tools with the C++ workload: free, about 3-6 GB, installed with winget, needs admin (UAC).
   - *C#* with the compiler already on this PC (no install). Works, but Microsoft doesn't support
     managed sign-in tiles, and it loads .NET into the sign-in screen: more ways to break.
2. **Also unlock the lock screen** (Win+L) with the drive? Recommended: yes.
3. **Safety net before the first real registration:** restore point + recovery recipe (recommended),
   optionally also a second administrator account as a backup way in.

## Result (2026-11-24)

Security review findings fixed (see commit "Fix security review findings for Windows sign-in"). Real
test by the owner on their PC with a FAT32 USB drive, safety net = a Windows restore point from
before the tile was turned on: sign-in and Win+L unlock with the drive work without typing; without
the drive the normal password screen appears; plugging the drive in at the lock screen unlocks.
