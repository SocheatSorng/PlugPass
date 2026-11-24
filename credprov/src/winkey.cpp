#include "winkey.h"

#include <bcrypt.h>
#include <shlobj.h>
#include <wincrypt.h>

#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace
{
const BYTE kDriveMagic[8] = {'P', 'P', 'W', 'I', 'N', 'K', 'E', 'Y'};
const BYTE kBlobMagic[8] = {'P', 'P', 'W', 'I', 'N', 'B', 'L', 'B'};
const BYTE kVersion = 1;
const char kEntropy[] = "PlugPass windows v1";
const size_t kDriveFileLength = 64;
const size_t kMaxBlob = 64 * 1024;

struct Wiper
{
    std::vector<BYTE>& v;
    ~Wiper()
    {
        if (!v.empty())
        {
            SecureZeroMemory(v.data(), v.size());
        }
    }
};

#ifdef PLUGPASS_TESTHOOKS
// Test build only: PLUGPASS_KEY_DIR stands in for the drive, PLUGPASS_HOME for %ProgramData%\PlugPass.
std::wstring Env(const wchar_t* name)
{
    wchar_t buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(name, buf, MAX_PATH);
    return (n > 0 && n < MAX_PATH) ? std::wstring(buf, n) : std::wstring();
}
#endif

bool IsLink(const std::wstring& path)
{
    DWORD a = GetFileAttributesW(path.c_str());
    return a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

// Reads a whole small file, refusing links. Empty on any problem.
std::vector<BYTE> ReadSmallFile(const std::wstring& path, size_t maxBytes)
{
    std::vector<BYTE> data;
    if (IsLink(path))
    {
        return data;
    }
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        return data;
    }
    LARGE_INTEGER size;
    if (GetFileSizeEx(h, &size) && size.QuadPart > 0 && static_cast<ULONGLONG>(size.QuadPart) <= maxBytes)
    {
        data.resize(static_cast<size_t>(size.QuadPart));
        DWORD read = 0;
        if (!ReadFile(h, data.data(), static_cast<DWORD>(data.size()), &read, nullptr) || read != data.size())
        {
            data.clear();
        }
    }
    CloseHandle(h);
    return data;
}

std::vector<std::wstring> CandidateRoots()
{
    std::vector<std::wstring> roots;
#ifdef PLUGPASS_TESTHOOKS
    std::wstring keyDir = Env(L"PLUGPASS_KEY_DIR");
    if (!keyDir.empty())
    {
        roots.push_back(keyDir + L"\\");
        return roots;
    }
#endif
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; i++)
    {
        if (mask & (1u << i))
        {
            wchar_t root[4] = {static_cast<wchar_t>(L'A' + i), L':', L'\\', 0};
            if (GetDriveTypeW(root) == DRIVE_REMOVABLE)
            {
                roots.push_back(root);
            }
        }
    }
    return roots;
}

bool ReadDriveKey(const std::wstring& root, std::vector<BYTE>& out)
{
    std::wstring folder = root + L"PlugPass";
    if (IsLink(folder))
    {
        return false;
    }
    out = ReadSmallFile(folder + L"\\windows.key", kDriveFileLength);
    if (out.size() != kDriveFileLength || memcmp(out.data(), kDriveMagic, 8) != 0 || out[8] != kVersion)
    {
        if (!out.empty())
        {
            SecureZeroMemory(out.data(), out.size());
        }
        out.clear();
        return false;
    }
    return true;
}

std::wstring SignInDir()
{
#ifdef PLUGPASS_TESTHOOKS
    std::wstring home = Env(L"PLUGPASS_HOME");
    if (!home.empty())
    {
        return home + L"\\signin";
    }
#endif
    PWSTR programData = nullptr;
    std::wstring dir;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &programData)))
    {
        dir = std::wstring(programData) + L"\\PlugPass\\signin";
    }
    CoTaskMemFree(programData);
    return dir;
}

std::wstring Hex(const BYTE* b, size_t n)
{
    static const wchar_t digits[] = L"0123456789abcdef";
    std::wstring s;
    for (size_t i = 0; i < n; i++)
    {
        s += digits[b[i] >> 4];
        s += digits[b[i] & 15];
    }
    return s;
}

bool HmacSha256(const BYTE* key, ULONG keyLen, const BYTE* data, ULONG dataLen, BYTE out[32])
{
    return BCRYPT_SUCCESS(BCryptHash(BCRYPT_HMAC_SHA256_ALG_HANDLE, const_cast<PUCHAR>(key), keyLen,
                                     const_cast<PUCHAR>(data), dataLen, out, 32));
}

bool Derive(const BYTE k[32], const char* label, BYTE out[32])
{
    return HmacSha256(k, 32, reinterpret_cast<const BYTE*>(label), static_cast<ULONG>(strlen(label)), out);
}

bool FixedTimeEquals(const BYTE* a, const BYTE* b, size_t n)
{
    BYTE diff = 0;
    for (size_t i = 0; i < n; i++)
    {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

bool AesCbcDecrypt(const BYTE key[32], const BYTE iv[16], const BYTE* ct, ULONG ctLen, std::vector<BYTE>& plain)
{
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(BCRYPT_AES_CBC_ALG_HANDLE, &hKey, nullptr, 0,
                                                   const_cast<PUCHAR>(key), 32, 0)))
    {
        return false;
    }
    BYTE ivCopy[16];
    memcpy(ivCopy, iv, 16);
    plain.resize(ctLen);
    ULONG written = 0;
    NTSTATUS st = BCryptDecrypt(hKey, const_cast<PUCHAR>(ct), ctLen, nullptr, ivCopy, 16, plain.data(),
                                static_cast<ULONG>(plain.size()), &written, BCRYPT_BLOCK_PADDING);
    BCryptDestroyKey(hKey);
    if (!BCRYPT_SUCCESS(st))
    {
        SecureZeroMemory(plain.data(), plain.size());
        plain.clear();
        return false;
    }
    plain.resize(written);
    return true;
}
}  // namespace

void Enrolment::Clear()
{
    if (!password.empty())
    {
        SecureZeroMemory(&password[0], password.size() * sizeof(wchar_t));
    }
    password.clear();
    user.clear();
    SecureZeroMemory(id, sizeof(id));
}

bool FindEnrolledDrive(BYTE id[16])
{
    for (const std::wstring& root : CandidateRoots())
    {
        std::vector<BYTE> key;
        Wiper w{key};
        if (ReadDriveKey(root, key))
        {
            memcpy(id, key.data() + 16, 16);
            return true;
        }
    }
    return false;
}

bool LoadEnrolment(Enrolment& e)
{
    e.Clear();
    std::wstring dir = SignInDir();
    if (dir.empty())
    {
        return false;
    }
    for (const std::wstring& root : CandidateRoots())
    {
        std::vector<BYTE> key;
        Wiper wk{key};
        if (!ReadDriveKey(root, key))
        {
            continue;
        }
        const BYTE* enrolId = key.data() + 16;
        const BYTE* k = key.data() + 32;

        std::vector<BYTE> wrapped = ReadSmallFile(dir + L"\\" + Hex(enrolId, 16) + L".bin", kMaxBlob);
        if (wrapped.empty())
        {
            continue;
        }
        DATA_BLOB in = {static_cast<DWORD>(wrapped.size()), wrapped.data()};
        DATA_BLOB entropy = {static_cast<DWORD>(sizeof(kEntropy) - 1),
                             reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy))};
        DATA_BLOB out = {};
        if (!CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        {
            continue;
        }
        std::vector<BYTE> blob(out.pbData, out.pbData + out.cbData);
        Wiper wb{blob};
        SecureZeroMemory(out.pbData, out.cbData);
        LocalFree(out.pbData);

        // magic(8) version(1) reserved(7) id(16) iv(16) ciphertext(n*16) mac(32)
        if (blob.size() < 48 + 16 + 32 || (blob.size() - 48 - 32) % 16 != 0 ||
            memcmp(blob.data(), kBlobMagic, 8) != 0 || blob[8] != kVersion ||
            !FixedTimeEquals(blob.data() + 16, enrolId, 16))
        {
            continue;
        }
        BYTE macKey[32], encKey[32], mac[32];
        size_t macAt = blob.size() - 32;
        bool macOk = Derive(k, "PlugPass windows mac v1", macKey) &&
                     HmacSha256(macKey, 32, blob.data(), static_cast<ULONG>(macAt), mac) &&
                     FixedTimeEquals(mac, blob.data() + macAt, 32);
        SecureZeroMemory(macKey, sizeof(macKey));
        if (!macOk || !Derive(k, "PlugPass windows enc v1", encKey))
        {
            continue;
        }
        std::vector<BYTE> plain;
        Wiper wp{plain};
        bool decrypted = AesCbcDecrypt(encKey, blob.data() + 32, blob.data() + 48,
                                       static_cast<ULONG>(macAt - 48), plain);
        SecureZeroMemory(encKey, sizeof(encKey));
        if (!decrypted || plain.size() < 4)
        {
            continue;
        }
        size_t userLen = plain[0] | (plain[1] << 8);
        size_t passAt = 2 + userLen * 2;
        if (userLen == 0 || passAt + 2 > plain.size())
        {
            continue;
        }
        size_t passLen = plain[passAt] | (plain[passAt + 1] << 8);
        if (passAt + 2 + passLen * 2 != plain.size())
        {
            continue;
        }
        e.user.assign(reinterpret_cast<const wchar_t*>(plain.data() + 2), userLen);
        e.password.assign(reinterpret_cast<const wchar_t*>(plain.data() + passAt + 2), passLen);
        memcpy(e.id, enrolId, 16);
        return true;
    }
    return false;
}
