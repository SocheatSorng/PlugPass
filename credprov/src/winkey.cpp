#include "winkey.h"

#include <bcrypt.h>
#include <wincrypt.h>

#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace
{
const BYTE kDriveMagic[8] = {'P', 'P', 'W', 'I', 'N', 'K', 'E', 'Y'};
const BYTE kBlobMagic[8] = {'P', 'P', 'W', 'I', 'N', 'B', 'L', 'B'};
const BYTE kVersion = 1;
const char kEntropy[] = "PlugPass windows v1";
const size_t kDriveFileLength = 64;
const DWORD kMaxBlob = 64 * 1024;

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
// Test build only: PLUGPASS_KEY_DIR stands in for the drive, PLUGPASS_TEST_REGKEY for the HKLM key.
std::wstring Env(const wchar_t* name)
{
    wchar_t buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(name, buf, MAX_PATH);
    return (n > 0 && n < MAX_PATH) ? std::wstring(buf, n) : std::wstring();
}
#endif

// The sign-in key: HKLM\SOFTWARE\PlugPass\SignIn (only SYSTEM and Administrators can read it).
HKEY OpenStore(REGSAM access)
{
    HKEY root = HKEY_LOCAL_MACHINE;
    std::wstring path = L"SOFTWARE\\PlugPass\\SignIn";
#ifdef PLUGPASS_TESTHOOKS
    std::wstring test = Env(L"PLUGPASS_TEST_REGKEY");
    if (!test.empty())
    {
        root = HKEY_CURRENT_USER;
        path = L"Software\\PlugPassTest\\" + test + L"\\SignIn";
    }
#endif
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, path.c_str(), 0, access | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
    {
        return nullptr;
    }
    return key;
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

// The DPAPI-wrapped blob for an enrolment, or empty. Also empty when the enrolment is marked rejected.
std::vector<BYTE> ReadBlob(const BYTE id[16])
{
    std::vector<BYTE> data;
    HKEY key = OpenStore(KEY_QUERY_VALUE);
    if (!key)
    {
        return data;
    }
    std::wstring name = Hex(id, 16);
    DWORD rejected = 0, size = sizeof(rejected);
    if (RegGetValueW(key, nullptr, (name + L".rejected").c_str(), RRF_RT_REG_DWORD, nullptr, &rejected, &size) !=
            ERROR_SUCCESS ||
        rejected == 0)
    {
        size = 0;
        if (RegGetValueW(key, nullptr, name.c_str(), RRF_RT_REG_BINARY, nullptr, nullptr, &size) == ERROR_SUCCESS &&
            size > 0 && size <= kMaxBlob)
        {
            data.resize(size);
            if (RegGetValueW(key, nullptr, name.c_str(), RRF_RT_REG_BINARY, nullptr, data.data(), &size) !=
                ERROR_SUCCESS)
            {
                data.clear();
            }
            else
            {
                data.resize(size);
            }
        }
    }
    RegCloseKey(key);
    return data;
}

// Only drives that can't hold links (FAT32/exFAT), and only when the media is ready.
bool UsableDrive(const std::wstring& root)
{
#ifdef PLUGPASS_TESTHOOKS
    if (!Env(L"PLUGPASS_KEY_DIR").empty())
    {
        return true;  // tests use a folder on NTFS as the drive
    }
#endif
    DWORD flags = 0;
    if (!GetVolumeInformationW(root.c_str(), nullptr, 0, nullptr, nullptr, &flags, nullptr, 0))
    {
        return false;  // not ready / no media
    }
    return (flags & FILE_SUPPORTS_REPARSE_POINTS) == 0;
}

bool ReadDriveKey(const std::wstring& root, DriveKey& key)
{
    std::wstring path = root + L"PlugPass\\windows.key";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    BYTE buf[kDriveFileLength + 1];
    DWORD read = 0;
    BOOL ok = ReadFile(h, buf, sizeof(buf), &read, nullptr);
    CloseHandle(h);
    bool valid = ok && read == kDriveFileLength && memcmp(buf, kDriveMagic, 8) == 0 && buf[8] == kVersion;
    if (valid)
    {
        memcpy(key.id, buf + 16, 16);
        memcpy(key.k, buf + 32, 32);
    }
    SecureZeroMemory(buf, sizeof(buf));
    return valid;
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
}  // namespace

void Enrolment::Clear()
{
    if (!password.empty())
    {
        SecureZeroMemory(&password[0], password.size() * sizeof(wchar_t));
    }
    password.clear();
    user.clear();
}

bool ProbeDrive(DriveKey& key)
{
    for (const std::wstring& root : CandidateRoots())
    {
        DriveKey candidate;
        if (UsableDrive(root) && ReadDriveKey(root, candidate))
        {
            std::vector<BYTE> blob = ReadBlob(candidate.id);
            Wiper w{blob};
            if (!blob.empty())
            {
                key = candidate;
                candidate.Clear();
                return true;
            }
        }
        candidate.Clear();
    }
    return false;
}

bool Decrypt(const DriveKey& key, Enrolment& e)
{
    e.Clear();
    std::vector<BYTE> wrapped = ReadBlob(key.id);
    Wiper ww{wrapped};
    if (wrapped.empty())
    {
        return false;
    }
    DATA_BLOB in = {static_cast<DWORD>(wrapped.size()), wrapped.data()};
    DATA_BLOB entropy = {static_cast<DWORD>(sizeof(kEntropy) - 1), reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy))};
    DATA_BLOB out = {};
    if (!CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
    {
        return false;
    }
    std::vector<BYTE> blob(out.pbData, out.pbData + out.cbData);
    Wiper wb{blob};
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);

    // magic(8) version(1) reserved(7) id(16) iv(16) ciphertext(n*16) mac(32)
    if (blob.size() < 48 + 16 + 32 || (blob.size() - 48 - 32) % 16 != 0 || memcmp(blob.data(), kBlobMagic, 8) != 0 ||
        blob[8] != kVersion || !FixedTimeEquals(blob.data() + 16, key.id, 16))
    {
        return false;
    }
    BYTE macKey[32], encKey[32], mac[32];
    size_t macAt = blob.size() - 32;
    bool macOk = Derive(key.k, "PlugPass windows mac v1", macKey) &&
                 HmacSha256(macKey, 32, blob.data(), static_cast<ULONG>(macAt), mac) &&
                 FixedTimeEquals(mac, blob.data() + macAt, 32);
    SecureZeroMemory(macKey, sizeof(macKey));
    if (!macOk || !Derive(key.k, "PlugPass windows enc v1", encKey))
    {
        return false;
    }
    std::vector<BYTE> plain;
    Wiper wp{plain};
    bool decrypted = AesCbcDecrypt(encKey, blob.data() + 32, blob.data() + 48, static_cast<ULONG>(macAt - 48), plain);
    SecureZeroMemory(encKey, sizeof(encKey));
    if (!decrypted || plain.size() < 4)
    {
        return false;
    }
    size_t userLen = plain[0] | (plain[1] << 8);
    size_t passAt = 2 + userLen * 2;
    if (userLen == 0 || passAt + 2 > plain.size())
    {
        return false;
    }
    size_t passLen = plain[passAt] | (plain[passAt + 1] << 8);
    if (passAt + 2 + passLen * 2 != plain.size())
    {
        return false;
    }
    e.user.assign(reinterpret_cast<const wchar_t*>(plain.data() + 2), userLen);
    e.password.assign(reinterpret_cast<const wchar_t*>(plain.data() + passAt + 2), passLen);
    return true;
}

void MarkRejected(const BYTE id[16])
{
    HKEY key = OpenStore(KEY_SET_VALUE);
    if (key)
    {
        DWORD one = 1;
        RegSetValueExW(key, (Hex(id, 16) + L".rejected").c_str(), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&one),
                       sizeof(one));
        RegCloseKey(key);
    }
}
