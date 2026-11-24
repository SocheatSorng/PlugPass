// Test harness: loads the sign-in tile DLL the way LogonUI does (DllGetClassObject -> ICredentialProvider,
// SetUsageScenario, SetUserArray, Advise, wait for CredentialsChanged, GetCredentialCount...) and walks
// the sign-in steps WITHOUT signing anyone in. It never prints a password: only its length, plus (only
// with PLUGPASS_HOME set, i.e. test data) a SHA-256 of the fake test password so tests can compare.
//
//   credprov-harness.exe <dll> logon|unlock|credui [user1,user2,...]
//   (with a user list: the tile is told those are the users Windows is asking about, as on unlock)
//   Set PLUGPASS_HARNESS_REPORT=success to report a successful sign-in instead of a rejected one.
// Output: one "key value" line per step.

#include <windows.h>
#include <bcrypt.h>
#include <credentialprovider.h>
#include <initguid.h>
#include <ntsecapi.h>
#include <propkey.h>
#include <shlwapi.h>

#include <atomic>
#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shlwapi.lib")

static const CLSID CLSID_PlugPassProvider = {
    0x9170534e, 0x8919, 0x480a, {0xa9, 0x9a, 0x4e, 0xf4, 0x97, 0x9f, 0xe7, 0xa3}};

// Signals an event when the tile says its credentials changed (as LogonUI would re-ask).
class Events : public ICredentialProviderEvents
{
public:
    HANDLE changed = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override { return --refs_; }  // stack-owned
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderEvents)
        {
            *ppv = this;
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP CredentialsChanged(UINT_PTR) override
    {
        SetEvent(changed);
        return S_OK;
    }

private:
    std::atomic<long> refs_{1};
};

class User : public ICredentialProviderUser
{
public:
    explicit User(const std::wstring& name) : name_(name) {}
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override
    {
        long r = --refs_;
        if (r == 0)
        {
            delete this;
        }
        return r;
    }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderUser)
        {
            *ppv = this;
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP GetSid(LPWSTR* sid) override
    {
        *sid = nullptr;
        return E_NOTIMPL;
    }
    IFACEMETHODIMP GetProviderID(GUID* id) override
    {
        *id = GUID_NULL;
        return E_NOTIMPL;
    }
    IFACEMETHODIMP GetStringValue(REFPROPERTYKEY key, LPWSTR* value) override
    {
        *value = nullptr;
        return key == PKEY_Identity_QualifiedUserName ? SHStrDupW(name_.c_str(), value) : E_NOTIMPL;
    }
    IFACEMETHODIMP GetValue(REFPROPERTYKEY, PROPVARIANT*) override { return E_NOTIMPL; }

private:
    std::wstring name_;
    std::atomic<long> refs_{1};
};

class UserArray : public ICredentialProviderUserArray
{
public:
    std::vector<std::wstring> names;
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override { return --refs_; }  // stack-owned
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderUserArray)
        {
            *ppv = this;
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP SetProviderFilter(REFGUID) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetAccountOptions(CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS* o) override
    {
        *o = CPAO_NONE;
        return S_OK;
    }
    IFACEMETHODIMP GetCount(DWORD* count) override
    {
        *count = static_cast<DWORD>(names.size());
        return S_OK;
    }
    IFACEMETHODIMP GetAt(DWORD i, ICredentialProviderUser** user) override
    {
        if (i >= names.size())
        {
            return E_INVALIDARG;
        }
        *user = new User(names[i]);
        return S_OK;
    }

private:
    std::atomic<long> refs_{1};
};

static std::wstring FromOffset(const BYTE* base, ULONG size, const UNICODE_STRING& us)
{
    ULONG_PTR offset = reinterpret_cast<ULONG_PTR>(us.Buffer);
    if (offset + us.Length > size)
    {
        return L"<out of range>";
    }
    return std::wstring(reinterpret_cast<const wchar_t*>(base + offset), us.Length / sizeof(wchar_t));
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3 || argc > 4)
    {
        fwprintf(stderr, L"usage: credprov-harness <dll> logon|unlock|credui [user1,user2]\n");
        return 2;
    }
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus = wcscmp(argv[2], L"logon") == 0    ? CPUS_LOGON
                                              : wcscmp(argv[2], L"unlock") == 0 ? CPUS_UNLOCK_WORKSTATION
                                                                                 : CPUS_CREDUI;
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    HMODULE dll = LoadLibraryW(argv[1]);
    if (!dll)
    {
        wprintf(L"load failed %lu\n", GetLastError());
        return 1;
    }
    typedef HRESULT(STDAPICALLTYPE * GetClassObject)(REFCLSID, REFIID, void**);
    GetClassObject getClassObject = reinterpret_cast<GetClassObject>(GetProcAddress(dll, "DllGetClassObject"));
    IClassFactory* factory = nullptr;
    ICredentialProvider* provider = nullptr;
    if (!getClassObject ||
        FAILED(getClassObject(CLSID_PlugPassProvider, IID_IClassFactory, reinterpret_cast<void**>(&factory))) ||
        FAILED(factory->CreateInstance(nullptr, IID_ICredentialProvider, reinterpret_cast<void**>(&provider))))
    {
        wprintf(L"create failed\n");
        return 1;
    }
    factory->Release();

    HRESULT hr = provider->SetUsageScenario(cpus, 0);
    wprintf(L"scenario 0x%08lx\n", static_cast<unsigned long>(hr));
    if (FAILED(hr))
    {
        provider->Release();
        return 0;
    }
    UserArray users;
    if (argc == 4)
    {
        std::wstring list = argv[3];
        size_t start = 0;
        while (start <= list.size())
        {
            size_t comma = list.find(L',', start);
            if (comma == std::wstring::npos)
            {
                comma = list.size();
            }
            users.names.push_back(list.substr(start, comma - start));
            start = comma + 1;
        }
        ICredentialProviderSetUserArray* setUsers = nullptr;
        if (SUCCEEDED(provider->QueryInterface(IID_ICredentialProviderSetUserArray, reinterpret_cast<void**>(&setUsers))))
        {
            setUsers->SetUserArray(&users);
            setUsers->Release();
        }
    }
    Events events;
    provider->Advise(&events, 42);
    DWORD changed = WaitForSingleObject(events.changed, 5000);
    wprintf(L"changed %d\n", changed == WAIT_OBJECT_0);
    DWORD fields = 0;
    provider->GetFieldDescriptorCount(&fields);
    wprintf(L"fields %lu\n", fields);
    DWORD count = 0, def = 0;
    BOOL autoLogon = FALSE;
    provider->GetCredentialCount(&count, &def, &autoLogon);
    wprintf(L"count %lu auto %d\n", count, autoLogon);
    if (count == 1)
    {
        ICredentialProviderCredential* cred = nullptr;
        provider->GetCredentialAt(0, &cred);
        PWSTR title = nullptr;
        cred->GetStringValue(0, &title);
        wprintf(L"title %ls\n", title ? title : L"");
        CoTaskMemFree(title);
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE resp;
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cs;
        PWSTR status = nullptr;
        CREDENTIAL_PROVIDER_STATUS_ICON icon;
        hr = cred->GetSerialization(&resp, &cs, &status, &icon);
        // "Negotiate" is usually authentication package 0, so print it rather than test for non-zero.
        wprintf(L"serialize 0x%08lx response %d package %lu clsid-ok %d\n", static_cast<unsigned long>(hr), resp,
                cs.ulAuthenticationPackage, IsEqualCLSID(cs.clsidCredentialProvider, CLSID_PlugPassProvider));
        CoTaskMemFree(status);
        if (resp == CPGSR_RETURN_CREDENTIAL_FINISHED && cs.rgbSerialization)
        {
            const KERB_INTERACTIVE_UNLOCK_LOGON* k =
                reinterpret_cast<const KERB_INTERACTIVE_UNLOCK_LOGON*>(cs.rgbSerialization);
            std::wstring domain = FromOffset(cs.rgbSerialization, cs.cbSerialization, k->Logon.LogonDomainName);
            std::wstring user = FromOffset(cs.rgbSerialization, cs.cbSerialization, k->Logon.UserName);
            std::wstring pass = FromOffset(cs.rgbSerialization, cs.cbSerialization, k->Logon.Password);
            wprintf(L"message %d domain %ls user %ls password-length %zu\n", k->Logon.MessageType, domain.c_str(),
                    user.c_str(), pass.size());
            wchar_t home[8];
            if (GetEnvironmentVariableW(L"PLUGPASS_HOME", home, 8) > 0)
            {
                BYTE digest[32];
                BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, reinterpret_cast<PUCHAR>(&pass[0]),
                           static_cast<ULONG>(pass.size() * sizeof(wchar_t)), digest, 32);
                wprintf(L"password-sha256 ");
                for (BYTE b : digest)
                {
                    wprintf(L"%02x", b);
                }
                wprintf(L"\n");
            }
            SecureZeroMemory(&pass[0], pass.size() * sizeof(wchar_t));
            SecureZeroMemory(cs.rgbSerialization, cs.cbSerialization);
            CoTaskMemFree(cs.rgbSerialization);
            wchar_t report[16] = {};
            GetEnvironmentVariableW(L"PLUGPASS_HARNESS_REPORT", report, 16);
            NTSTATUS result = wcscmp(report, L"success") == 0 ? 0 : static_cast<NTSTATUS>(0xC000006DL);
            PWSTR text = nullptr;
            cred->ReportResult(result, 0, &text, &icon);
            CoTaskMemFree(text);
            provider->GetCredentialCount(&count, &def, &autoLogon);
            wprintf(L"after-report count %lu auto %d\n", count, autoLogon);
        }
        cred->Release();
    }
    provider->UnAdvise();
    provider->Release();
    CloseHandle(events.changed);
    CoUninitialize();
    return 0;
}
