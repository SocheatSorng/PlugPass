// Reads a PlugPass Windows sign-in: the key K on a removable FAT32/exFAT drive (PlugPass\windows.key)
// and the encrypted password in HKLM\SOFTWARE\PlugPass\SignIn (DPAPI local machine). The format is
// defined in host/src/WindowsKey.cs; keep the two in step.
#pragma once

#include <windows.h>
#include <string>

// The drive half, kept in memory by the tile's background thread so LogonUI's own calls never touch
// the USB stick.
struct DriveKey
{
    BYTE id[16] = {};
    BYTE k[32] = {};

    void Clear() { SecureZeroMemory(this, sizeof(*this)); }
};

struct Enrolment
{
    std::wstring user;
    std::wstring password;  // wiped by Clear() and the destructor

    void Clear();
    ~Enrolment() { Clear(); }
};

// Background thread only (may block on a slow drive): the first ready removable FAT32/exFAT drive
// with a well-formed windows.key whose enrolment exists on this PC and isn't marked rejected.
bool ProbeDrive(DriveKey& key);

// Decrypts this PC's half with a drive key. Reads only the registry, never the drive.
bool Decrypt(const DriveKey& key, Enrolment& e);

// Windows rejected the stored password (e.g. it was changed): no sign-in screen retries it until the
// drive is enrolled again.
void MarkRejected(const BYTE id[16]);
