// PlugPass sign-in tile (Windows credential provider).
//
// Shows one tile, and signs in automatically, only while a removable drive with a PlugPass Windows
// sign-in is plugged in and its key decrypts this PC's half. Otherwise it reports zero tiles, so
// Windows' own password tile is used as always. It serves sign-in and unlock only; every other use
// (UAC, credential prompts in apps, password change) gets E_NOTIMPL. Never filters other providers.
// If Windows rejects the password it handed over (e.g. the password was changed), it stops offering
// that drive until the drive is unplugged, so it can't loop.
//
// Everything here must fail closed and quietly: no exceptions escape, any problem means "no tile".

#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <shlwapi.h>

#include <atomic>
#include <new>
#include <string>

#include "winkey.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// {9170534E-8919-480A-A99A-4EF4979FE7A3}
extern "C" const CLSID CLSID_PlugPassProvider = {
    0x9170534e, 0x8919, 0x480a, {0xa9, 0x9a, 0x4e, 0xf4, 0x97, 0x9f, 0xe7, 0xa3}};

std::atomic<long> g_dllRefs(0);

namespace
{
enum FieldId
{
    FIELD_TITLE = 0,
    FIELD_STATUS,
    FIELD_COUNT
};

const wchar_t kTitle[] = L"PlugPass USB key";
const wchar_t kReady[] = L"Signing in with your PlugPass drive...";
const wchar_t kFailed[] =
    L"PlugPass couldn't sign you in. Use your password. If you changed it, set up the drive for Windows again in PlugPass.";

// Drives Windows rejected in this sign-in session (by enrolment ID). Cleared when the drive is removed.
CRITICAL_SECTION g_lock;
BYTE g_failedId[16];
bool g_hasFailed = false;
INIT_ONCE g_initOnce = INIT_ONCE_STATIC_INIT;

BOOL CALLBACK InitLock(PINIT_ONCE, PVOID, PVOID*)
{
    InitializeCriticalSection(&g_lock);
    return TRUE;
}

void EnsureLock()
{
    InitOnceExecuteOnce(&g_initOnce, InitLock, nullptr, nullptr);
}

bool IsFailed(const BYTE id[16])
{
    EnsureLock();
    EnterCriticalSection(&g_lock);
    bool failed = g_hasFailed && memcmp(g_failedId, id, 16) == 0;
    LeaveCriticalSection(&g_lock);
    return failed;
}

void MarkFailed(const BYTE id[16])
{
    EnsureLock();
    EnterCriticalSection(&g_lock);
    memcpy(g_failedId, id, 16);
    g_hasFailed = true;
    LeaveCriticalSection(&g_lock);
}

void ForgetFailureUnless(const BYTE id[16], bool present)
{
    EnsureLock();
    EnterCriticalSection(&g_lock);
    if (g_hasFailed && (!present || memcmp(g_failedId, id, 16) != 0))
    {
        g_hasFailed = false;
    }
    LeaveCriticalSection(&g_lock);
}

HRESULT DupString(const wchar_t* s, PWSTR* out)
{
    return SHStrDupW(s, out);
}

// Packs KERB_INTERACTIVE_UNLOCK_LOGON with string buffers stored as offsets from the start, as LSA
// expects for serialized credentials.
HRESULT PackLogon(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, const std::wstring& domain, const std::wstring& user,
                  const std::wstring& password, BYTE** out, ULONG* outSize)
{
    const size_t maxChars = 0x7FFF;
    if (domain.size() > maxChars || user.size() > maxChars || password.size() > maxChars)
    {
        return E_INVALIDARG;
    }
    USHORT cbDomain = static_cast<USHORT>(domain.size() * sizeof(wchar_t));
    USHORT cbUser = static_cast<USHORT>(user.size() * sizeof(wchar_t));
    USHORT cbPass = static_cast<USHORT>(password.size() * sizeof(wchar_t));
    ULONG cb = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + cbDomain + cbUser + cbPass;
    BYTE* buf = static_cast<BYTE*>(CoTaskMemAlloc(cb));
    if (!buf)
    {
        return E_OUTOFMEMORY;
    }
    ZeroMemory(buf, cb);
    KERB_INTERACTIVE_UNLOCK_LOGON* p = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(buf);
    p->Logon.MessageType = (cpus == CPUS_UNLOCK_WORKSTATION) ? KerbWorkstationUnlockLogon : KerbInteractiveLogon;
    BYTE* cur = buf + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);
    auto put = [&](UNICODE_STRING& us, const std::wstring& s, USHORT cbs) {
        us.Length = cbs;
        us.MaximumLength = cbs;
        us.Buffer = reinterpret_cast<PWSTR>(cur - buf);
        if (cbs)
        {
            memcpy(cur, s.data(), cbs);
        }
        cur += cbs;
    };
    put(p->Logon.LogonDomainName, domain, cbDomain);
    put(p->Logon.UserName, user, cbUser);
    put(p->Logon.Password, password, cbPass);
    *out = buf;
    *outSize = cb;
    return S_OK;
}

HRESULT NegotiatePackage(ULONG* package)
{
    HANDLE lsa = nullptr;
    if (LsaConnectUntrusted(&lsa) != STATUS_SUCCESS)
    {
        return E_FAIL;
    }
    char name[] = "Negotiate";
    LSA_STRING ls;
    ls.Buffer = name;
    ls.Length = static_cast<USHORT>(strlen(name));
    ls.MaximumLength = static_cast<USHORT>(ls.Length + 1);
    NTSTATUS st = LsaLookupAuthenticationPackage(lsa, &ls, package);
    LsaDeregisterLogonProcess(lsa);
    return st == STATUS_SUCCESS ? S_OK : E_FAIL;
}

std::wstring ComputerName()
{
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD n = ARRAYSIZE(name);
    return GetComputerNameW(name, &n) ? std::wstring(name, n) : std::wstring(L".");
}

class Credential : public ICredentialProviderCredential
{
public:
    explicit Credential(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus) : refs_(1), cpus_(cpus), events_(nullptr)
    {
        g_dllRefs++;
    }

    // IUnknown
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
        if (!ppv)
        {
            return E_POINTER;
        }
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential)
        {
            *ppv = static_cast<ICredentialProviderCredential*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* events) override
    {
        if (events_)
        {
            events_->Release();
        }
        events_ = events;
        if (events_)
        {
            events_->AddRef();
        }
        return S_OK;
    }
    IFACEMETHODIMP UnAdvise() override
    {
        if (events_)
        {
            events_->Release();
            events_ = nullptr;
        }
        return S_OK;
    }
    IFACEMETHODIMP SetSelected(BOOL* autoLogon) override
    {
        if (!autoLogon)
        {
            return E_POINTER;
        }
        *autoLogon = TRUE;  // nothing to type: selecting the tile signs in
        return S_OK;
    }
    IFACEMETHODIMP SetDeselected() override { return S_OK; }
    IFACEMETHODIMP GetFieldState(DWORD field, CREDENTIAL_PROVIDER_FIELD_STATE* state,
                                 CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive) override
    {
        if (field >= FIELD_COUNT || !state || !interactive)
        {
            return E_INVALIDARG;
        }
        *state = CPFS_DISPLAY_IN_BOTH;
        *interactive = CPFIS_NONE;
        return S_OK;
    }
    IFACEMETHODIMP GetStringValue(DWORD field, PWSTR* value) override
    {
        if (!value)
        {
            return E_POINTER;
        }
        *value = nullptr;
        if (field == FIELD_TITLE)
        {
            return DupString(kTitle, value);
        }
        if (field == FIELD_STATUS)
        {
            return DupString(kReady, value);
        }
        return E_INVALIDARG;
    }
    IFACEMETHODIMP GetBitmapValue(DWORD, HBITMAP* bmp) override
    {
        if (bmp)
        {
            *bmp = nullptr;
        }
        return E_NOTIMPL;
    }
    IFACEMETHODIMP GetCheckboxValue(DWORD, BOOL*, PWSTR*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetSubmitButtonValue(DWORD, DWORD*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueCount(DWORD, DWORD*, DWORD*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueAt(DWORD, DWORD, PWSTR*) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetStringValue(DWORD, PCWSTR) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetCheckboxValue(DWORD, BOOL) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD, DWORD) override { return E_NOTIMPL; }
    IFACEMETHODIMP CommandLinkClicked(DWORD) override { return E_NOTIMPL; }

    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* cs, PWSTR* statusText,
                                    CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override
    {
        if (!response || !cs)
        {
            return E_POINTER;
        }
        *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        ZeroMemory(cs, sizeof(*cs));
        if (statusText)
        {
            *statusText = nullptr;
        }
        if (statusIcon)
        {
            *statusIcon = CPSI_NONE;
        }
        try
        {
            // Decrypt fresh, so the password lives in memory only for this call.
            Enrolment e;
            if (!LoadEnrolment(e) || IsFailed(e.id))
            {
                if (statusText)
                {
                    DupString(kFailed, statusText);
                }
                if (statusIcon)
                {
                    *statusIcon = CPSI_WARNING;
                }
                *response = CPGSR_NO_CREDENTIAL_FINISHED;
                return S_OK;
            }
            memcpy(lastId_, e.id, 16);
            ULONG package = 0;
            HRESULT hr = NegotiatePackage(&package);
            BYTE* buf = nullptr;
            ULONG cb = 0;
            if (SUCCEEDED(hr))
            {
                hr = PackLogon(cpus_, ComputerName(), e.user, e.password, &buf, &cb);
            }
            if (FAILED(hr))
            {
                return hr;
            }
            cs->ulAuthenticationPackage = package;
            cs->clsidCredentialProvider = CLSID_PlugPassProvider;
            cs->cbSerialization = cb;
            cs->rgbSerialization = buf;  // owned (and freed) by LogonUI
            *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
            return S_OK;
        }
        catch (...)
        {
            return E_FAIL;
        }
    }

    IFACEMETHODIMP ReportResult(NTSTATUS status, NTSTATUS, PWSTR* statusText,
                                CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override
    {
        if (statusText)
        {
            *statusText = nullptr;
        }
        if (statusIcon)
        {
            *statusIcon = CPSI_NONE;
        }
        if (status < 0)  // !NT_SUCCESS: stop offering this drive until it is replugged
        {
            MarkFailed(lastId_);
            if (statusText)
            {
                DupString(kFailed, statusText);
            }
            if (statusIcon)
            {
                *statusIcon = CPSI_ERROR;
            }
        }
        return S_OK;
    }

private:
    ~Credential()
    {
        UnAdvise();
        g_dllRefs--;
    }

    std::atomic<long> refs_;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus_;
    ICredentialProviderCredentialEvents* events_;
    BYTE lastId_[16] = {};
};

class Provider : public ICredentialProvider
{
public:
    Provider()
        : refs_(1), cpus_(CPUS_INVALID), events_(nullptr), context_(0), thread_(nullptr), stop_(nullptr),
          credential_(nullptr), present_(false)
    {
        g_dllRefs++;
        EnsureLock();
        InitializeCriticalSection(&stateLock_);
    }

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
        if (!ppv)
        {
            return E_POINTER;
        }
        if (riid == IID_IUnknown || riid == IID_ICredentialProvider)
        {
            *ppv = static_cast<ICredentialProvider*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD) override
    {
        if (cpus != CPUS_LOGON && cpus != CPUS_UNLOCK_WORKSTATION)
        {
            return E_NOTIMPL;  // UAC, CredUI, password change: not ours
        }
        cpus_ = cpus;
        return S_OK;
    }
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override
    {
        return E_NOTIMPL;
    }

    IFACEMETHODIMP Advise(ICredentialProviderEvents* events, UINT_PTR context) override
    {
        StopWatcher();
        EnterCriticalSection(&stateLock_);
        if (events_)
        {
            events_->Release();
        }
        events_ = events;
        if (events_)
        {
            events_->AddRef();
        }
        context_ = context;
        present_ = FindEnrolledDrive(presentId_);
        LeaveCriticalSection(&stateLock_);
        stop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (stop_)
        {
            AddRef();  // the watcher holds a reference until it exits
            thread_ = CreateThread(nullptr, 0, WatchThunk, this, 0, nullptr);
            if (!thread_)
            {
                Release();
            }
        }
        return S_OK;
    }
    IFACEMETHODIMP UnAdvise() override
    {
        StopWatcher();
        EnterCriticalSection(&stateLock_);
        if (events_)
        {
            events_->Release();
            events_ = nullptr;
        }
        LeaveCriticalSection(&stateLock_);
        return S_OK;
    }

    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* count) override
    {
        if (!count)
        {
            return E_POINTER;
        }
        *count = FIELD_COUNT;
        return S_OK;
    }
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** out) override
    {
        if (!out)
        {
            return E_POINTER;
        }
        *out = nullptr;
        if (index >= FIELD_COUNT)
        {
            return E_INVALIDARG;
        }
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* d =
            static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(*d)));
        if (!d)
        {
            return E_OUTOFMEMORY;
        }
        ZeroMemory(d, sizeof(*d));
        d->dwFieldID = index;
        d->cpft = index == FIELD_TITLE ? CPFT_LARGE_TEXT : CPFT_SMALL_TEXT;
        HRESULT hr = DupString(index == FIELD_TITLE ? L"PlugPass" : L"Status", &d->pszLabel);
        if (FAILED(hr))
        {
            CoTaskMemFree(d);
            return hr;
        }
        *out = d;
        return S_OK;
    }

    IFACEMETHODIMP GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogonWithDefault) override
    {
        if (!count || !defaultIndex || !autoLogonWithDefault)
        {
            return E_POINTER;
        }
        *count = 0;
        *defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *autoLogonWithDefault = FALSE;
        try
        {
            Enrolment e;
            if (LoadEnrolment(e) && !IsFailed(e.id))
            {
                *count = 1;
                *defaultIndex = 0;
                *autoLogonWithDefault = TRUE;  // drive in: sign in with no typing
            }
        }
        catch (...)
        {
            *count = 0;
        }
        return S_OK;
    }

    IFACEMETHODIMP GetCredentialAt(DWORD index, ICredentialProviderCredential** out) override
    {
        if (!out)
        {
            return E_POINTER;
        }
        *out = nullptr;
        if (index != 0)
        {
            return E_INVALIDARG;
        }
        if (!credential_)
        {
            credential_ = new (std::nothrow) Credential(cpus_);
            if (!credential_)
            {
                return E_OUTOFMEMORY;
            }
        }
        return credential_->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(out));
    }

private:
    ~Provider()
    {
        StopWatcher();
        if (events_)
        {
            events_->Release();
        }
        if (credential_)
        {
            credential_->Release();
        }
        DeleteCriticalSection(&stateLock_);
        g_dllRefs--;
    }

    void StopWatcher()
    {
        if (thread_)
        {
            SetEvent(stop_);
            WaitForSingleObject(thread_, 5000);
            CloseHandle(thread_);
            thread_ = nullptr;
        }
        if (stop_)
        {
            CloseHandle(stop_);
            stop_ = nullptr;
        }
    }

    static DWORD WINAPI WatchThunk(LPVOID self)
    {
        Provider* p = static_cast<Provider*>(self);
        p->Watch();
        p->Release();
        return 0;
    }

    // Polls for the drive being plugged in or pulled out and tells LogonUI to ask again.
    void Watch()
    {
        while (WaitForSingleObject(stop_, 1500) == WAIT_TIMEOUT)
        {
            BYTE id[16] = {};
            bool present = FindEnrolledDrive(id);
            ForgetFailureUnless(id, present);
            EnterCriticalSection(&stateLock_);
            bool changed = present != present_ || (present && memcmp(id, presentId_, 16) != 0);
            present_ = present;
            memcpy(presentId_, id, 16);
            ICredentialProviderEvents* events = events_;
            UINT_PTR context = context_;
            if (changed && events)
            {
                events->AddRef();
            }
            LeaveCriticalSection(&stateLock_);
            if (changed && events)
            {
                events->CredentialsChanged(context);
                events->Release();
            }
        }
    }

    std::atomic<long> refs_;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus_;
    ICredentialProviderEvents* events_;
    UINT_PTR context_;
    HANDLE thread_;
    HANDLE stop_;
    Credential* credential_;
    CRITICAL_SECTION stateLock_;
    bool present_;
    BYTE presentId_[16] = {};
};

class ClassFactory : public IClassFactory
{
public:
    ClassFactory() : refs_(1) { g_dllRefs++; }
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
        if (!ppv)
        {
            return E_POINTER;
        }
        if (riid == IID_IUnknown || riid == IID_IClassFactory)
        {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override
    {
        if (!ppv)
        {
            return E_POINTER;
        }
        *ppv = nullptr;
        if (outer)
        {
            return CLASS_E_NOAGGREGATION;
        }
        Provider* p = new (std::nothrow) Provider();
        if (!p)
        {
            return E_OUTOFMEMORY;
        }
        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }
    IFACEMETHODIMP LockServer(BOOL lock) override
    {
        if (lock)
        {
            g_dllRefs++;
        }
        else
        {
            g_dllRefs--;
        }
        return S_OK;
    }

private:
    ~ClassFactory() { g_dllRefs--; }
    std::atomic<long> refs_;
};
}  // namespace

STDAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void** ppv)
{
    if (!ppv)
    {
        return E_POINTER;
    }
    *ppv = nullptr;
    if (clsid != CLSID_PlugPassProvider)
    {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    ClassFactory* f = new (std::nothrow) ClassFactory();
    if (!f)
    {
        return E_OUTOFMEMORY;
    }
    HRESULT hr = f->QueryInterface(riid, ppv);
    f->Release();
    return hr;
}

STDAPI DllCanUnloadNow()
{
    return g_dllRefs == 0 ? S_OK : S_FALSE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}
