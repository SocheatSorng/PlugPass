# Phase 1 manual test: does Google accept PlugPass?

The automated tests prove the helper app produces valid security-key data. This manual test checks
the part only a real browser and a real site can answer.

In phase 1 the key is **not on a USB drive yet**: a temporary master secret lives in
`%LOCALAPPDATA%\PlugPass\spike-master.bin`, protected by your Windows account. Instead of a PIN you
click **Sign in / Add** in a PlugPass window. Phase 2 moves the key to the drive and adds the PIN.

## 1. Build and register (changes HKCU registry for your user only)

```powershell
.\build.ps1
.\tools\dev-register.ps1
```

## 2. Load the extension

1. Open `chrome://extensions` (or `edge://extensions`, `brave://extensions`), turn on **Developer mode**.
2. **Load unpacked** and choose `bin\extension`.
3. The ID must be `amppkfbnjicgeeakigkmafdllhknaigl`.

## 3. Test on webauthn.io

1. Go to https://webauthn.io, type any username.
2. Open **Advanced settings**: set *User Verification* to **Discouraged** and *Discoverable Credential*
   to **Discouraged**, attestation **None**.
3. **Register**: the PlugPass window asks "Add your PlugPass key to webauthn.io?". Click **Add**.
4. **Authenticate**: PlugPass asks "Sign in to webauthn.io with PlugPass?". Click **Sign in**.
   Expected: "You're logged in!".

## 4. Test on Google

1. Google Account > **Security** > **2-Step Verification** > **Security keys** > **Add security key**.
   (2-Step Verification must already be on with another method, so you can't be locked out.)
2. If Google offers a passkey instead, choose the security-key option. If PlugPass's window doesn't
   appear, Google is asking for something PlugPass can't do yet (PIN-verified or a passkey stored on
   the key): note what Google showed.
3. Click **Add** in PlugPass and give the key a name in Google.
4. Sign out, sign in again: when Google asks for your security key, PlugPass asks; click **Sign in**.

Report back: which steps worked, and the exact wording of any Google error.

## 5. Clean up when done

```powershell
.\tools\dev-register.ps1 -Unregister
```

Remove the extension in `chrome://extensions`, and remove the test key from your Google account
(Security > Security keys). The spike key only exists to test phase 1; phase 2 replaces it.
