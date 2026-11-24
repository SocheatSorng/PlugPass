# Intent: a normal USB flash drive that works like a security key

Confirmed with the owner on 2026-11-24.

- **Outcome:** turn an ordinary USB flash drive into a security key for two things: the owner's
  Google account and signing in to Windows.
- **User:** the owner, on one Windows 10 Pro PC with a **local** Windows account (no Microsoft
  account, no Azure AD / domain).
- **Windows sign-in:** a sign-in tile (credential provider). With the drive plugged in, sign-in
  happens with **no typing, no PIN**. The Windows password is stored encrypted on the drive and can
  only be decrypted on this PC (DPAPI), so a copied drive is useless elsewhere. Without the drive, or
  with a damaged one, the normal password works. The owner must never be locked out.
- **Google:** a Chrome/Edge extension plus a small helper app on the PC acts as a security key /
  passkey (WebAuthn). It needs the drive **and a PIN (minimum 6 characters)**.
- **Success:** the drive can be added as a security key in Google account settings and used to sign
  in; restarting the PC with the drive in reaches the desktop without typing.
- **Constraint:** a missing, wrong or damaged drive never blocks the password path. The sign-in tile
  is tested safely before it is ever registered on the real sign-in screen, and only with the owner's OK.
- **Early risk:** some Google flows may accept only hardware keys with attestation. Test this first.
- **Out of scope (for now):** Firefox, other websites beyond what works for free, other PCs,
  Microsoft/work accounts, a kernel/virtual USB driver that pretends to be a hardware key, changes to VaultKeep.
- **Accepted trade-off:** unlike a hardware key, the secret on a flash drive can be copied. The PIN
  (Google) and DPAPI binding to this PC (Windows) limit what a copy is worth.
