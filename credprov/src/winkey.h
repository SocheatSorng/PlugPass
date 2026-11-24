// Reads a PlugPass Windows sign-in: the key K on a removable drive (PlugPass\windows.key) and the
// encrypted password on this PC (%ProgramData%\PlugPass\signin\<id>.bin, DPAPI local machine).
// The format is defined in host/src/WindowsKey.cs; keep the two in step.
#pragma once

#include <windows.h>
#include <string>

struct Enrolment
{
    BYTE id[16] = {};
    std::wstring user;
    std::wstring password;  // wiped by Clear() and the destructor

    void Clear();
    ~Enrolment() { Clear(); }
};

// The enrolment ID of the first removable drive holding a well-formed windows.key, without decrypting
// anything (cheap: used to notice a drive being plugged in or pulled out). False when there is none.
bool FindEnrolledDrive(BYTE id[16]);

// Finds the drive and decrypts the PC half with it. False on any problem (no drive, no PC half,
// wrong key, damaged data); never throws.
bool LoadEnrolment(Enrolment& e);
