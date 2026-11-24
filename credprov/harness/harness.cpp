// Test harness: loads the sign-in tile DLL the way LogonUI does (DllGetClassObject -> ICredentialProvider)
// and walks the sign-in steps WITHOUT signing anyone in. It never prints a password: only its length,
// plus (test DLL with PLUGPASS_HOME set only) a SHA-256 of the fake test password so tests can compare.
//
//   credprov-harness.exe <dll> logon|unlock|credui
// Output: one "key value" line per step.

#include <windows.h>
#include <bcrypt.h>
#include <credentialprovider.h>
#include <ntsecapi.h>

#include <cstdio>
#include <string>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "bcrypt.lib")

static const CLSID CLSID_PlugPassProvider = {
    0x9170534e, 0x8919, 0x480a, {0xa9, 0x9a, 0x4e, 0xf4, 0x97, 0x9f, 0xe7, 0xa3}};

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
    if (argc != 3)
    {
        fwprintf(stderr, L"usage: credprov-harness <dll> logon|unlock|credui\n");
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
            // Pretend Windows rejected it: the tile must step aside until the drive is replugged.
            PWSTR text = nullptr;
            cred->ReportResult(static_cast<NTSTATUS>(0xC000006DL) /* STATUS_LOGON_FAILURE */, 0, &text, &icon);
            CoTaskMemFree(text);
            provider->GetCredentialCount(&count, &def, &autoLogon);
            wprintf(L"after-failure count %lu auto %d\n", count, autoLogon);
        }
        cred->Release();
    }
    provider->Release();
    CoUninitialize();
    return 0;
}
