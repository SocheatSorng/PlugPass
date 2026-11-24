// PlugPass sign-in tile (Windows credential provider).
//
// Shows one tile, and signs in automatically, only while a removable FAT32/exFAT drive with a PlugPass
// Windows sign-in is plugged in, its key decrypts this PC's half, and the enrolled user is one Windows
// is asking about (on the lock screen: the locked user). Otherwise zero tiles, so Windows' own password
// tile is used as always. Serves sign-in and unlock only (E_NOTIMPL for UAC, CredUI, password change).
// Never filters other providers.
//
// All drive access happens on a background thread; LogonUI's calls only read the cached result, so a
// slow or failing USB stick can't freeze the sign-in screen. When Windows rejects the stored password
// (changed password, account locked...) the enrolment is marked rejected in the registry, so no sign-in
// screen retries it (no lockout from repeated tries) until the drive is enrolled again.
//
// Everything here must fail closed and quietly: no exception escapes, any problem means "no tile".

#include <windows.h>
#include <initguid.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <propkey.h>
#include <shlwapi.h>

#include <atomic>
#include <new>
#include <string>
#include <vector>

#include "winkey.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

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
    L"PlugPass couldn't sign you in. Use your password. If you changed it, turn on Windows sign-in for the drive again in PlugPass.";

// Results that mean "this stored password will never work": stop using it everywhere.
bool IsPasswordProblem(NTSTATUS st)
{
    const NTSTATUS codes[] = {
        static_cast<NTSTATUS>(0xC000006DL),  // STATUS_LOGON_FAILURE
        static_cast<NTSTATUS>(0xC000006AL),  // STATUS_WRONG_PASSWORD
        static_cast<NTSTATUS>(0xC0000234L),  // STATUS_ACCOUNT_LOCKED_OUT
        static_cast<NTSTATUS>(0xC0000071L),  // STATUS_PASSWORD_EXPIRED
        static_cast<NTSTATUS>(0xC0000224L),  // STATUS_PASSWORD_MUST_CHANGE
        static_cast<NTSTATUS>(0xC0000072L),  // STATUS_ACCOUNT_DISABLED
    };
    for (NTSTATUS c : codes)
    {
        if (st == c)
        {
            return true;
        }
    }
    return false;
}

HRESULT DupString(const wchar_t* s, PWSTR* out)
{
    return SHStrDupW(s, out);
}

std::wstring ComputerName()
{
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD n = ARRAYSIZE(name);
    return GetComputerNameW(name, &n) ? std::wstring(name, n) : std::wstring(L".");
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

// What the background thread found. Guarded by the provider's lock.
struct DriveState
{
    bool ready = false;  // a drive is in, and its key decrypts this PC's half
    DriveKey key;
    std::wstring user;  // enrolled user (no password kept)
};

class Provider;

class Credential : public ICredentialProviderCredential
{
public:
    Credential(Provider* provider, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus);

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

    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents*) override { return S_OK; }
    IFACEMETHODIMP UnAdvise() override { return S_OK; }
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
                                    CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;
    IFACEMETHODIMP ReportResult(NTSTATUS status, NTSTATUS, PWSTR* statusText,
                                CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;

    void Detach() { provider_ = nullptr; }

private:
    ~Credential();

    std::atomic<long> refs_;
    Provider* provider_;  // not AddRef'd (would be a cycle); the provider detaches us when it goes
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus_;
    BYTE lastId_[16] = {};
};

struct WatchArgs
{
    Provider* provider;  // AddRef'd for the thread
    HANDLE stop;         // the thread's own handle to the stop event
    HMODULE module;      // keeps the DLL loaded until the thread exits
};

class Provider : public ICredentialProvider, public ICredentialProviderSetUserArray
{
public:
    Provider()
        : refs_(1), cpus_(CPUS_INVALID), events_(nullptr), context_(0), thread_(nullptr), stop_(nullptr),
          credential_(nullptr), haveUsers_(false), suppressed_(false)
    {
        g_dllRefs++;
        InitializeCriticalSection(&lock_);
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
        }
        else if (riid == IID_ICredentialProviderSetUserArray)
        {
            *ppv = static_cast<ICredentialProviderSetUserArray*>(this);
        }
        else
        {
            *ppv = nullptr;
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }

    // ICredentialProviderSetUserArray: the users Windows is asking about (on unlock: the locked user).
    IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray* users) override
    {
        try
        {
            std::vector<std::wstring> names;
            DWORD count = 0;
            if (users && SUCCEEDED(users->GetCount(&count)))
            {
                for (DWORD i = 0; i < count; i++)
                {
                    ICredentialProviderUser* u = nullptr;
                    if (FAILED(users->GetAt(i, &u)) || !u)
                    {
                        continue;
                    }
                    PWSTR name = nullptr;
                    if (SUCCEEDED(u->GetStringValue(PKEY_Identity_QualifiedUserName, &name)) && name)
                    {
                        names.push_back(name);
                        CoTaskMemFree(name);
                    }
                    u->Release();
                }
            }
            EnterCriticalSection(&lock_);
            users_.swap(names);
            haveUsers_ = users != nullptr;
            LeaveCriticalSection(&lock_);
        }
        catch (...)
        {
        }
        return S_OK;
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
        try
        {
            StopWatcher();
            EnterCriticalSection(&lock_);
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
            LeaveCriticalSection(&lock_);
            StartWatcher();
        }
        catch (...)
        {
        }
        return S_OK;
    }
    IFACEMETHODIMP UnAdvise() override
    {
        StopWatcher();
        EnterCriticalSection(&lock_);
        if (events_)
        {
            events_->Release();
            events_ = nullptr;
        }
        LeaveCriticalSection(&lock_);
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

    // Reads only the cache the background thread keeps: never touches the drive.
    IFACEMETHODIMP GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogonWithDefault) override
    {
        if (!count || !defaultIndex || !autoLogonWithDefault)
        {
            return E_POINTER;
        }
        *count = 0;
        *defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *autoLogonWithDefault = FALSE;
        EnterCriticalSection(&lock_);
        bool offer = state_.ready && !suppressed_ && UserWanted();
        LeaveCriticalSection(&lock_);
        if (offer)
        {
            *count = 1;
            *defaultIndex = 0;
            *autoLogonWithDefault = TRUE;  // drive in: sign in with no typing
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
            credential_ = new (std::nothrow) Credential(this, cpus_);
            if (!credential_)
            {
                return E_OUTOFMEMORY;
            }
        }
        return credential_->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(out));
    }

    // For the credential: a copy of the cached drive key (false if no drive is ready).
    bool CurrentKey(DriveKey& key)
    {
        EnterCriticalSection(&lock_);
        bool ok = state_.ready && !suppressed_ && UserWanted();
        if (ok)
        {
            key = state_.key;
        }
        LeaveCriticalSection(&lock_);
        return ok;
    }

    // Windows rejected the password: never again for a password problem (persisted), and not again
    // in this sign-in screen for anything else, until the drive changes.
    void Rejected(const BYTE id[16], NTSTATUS status)
    {
        if (IsPasswordProblem(status))
        {
            MarkRejected(id);
        }
        EnterCriticalSection(&lock_);
        suppressed_ = true;
        LeaveCriticalSection(&lock_);
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
            credential_->Detach();
            credential_->Release();
        }
        state_.key.Clear();
        DeleteCriticalSection(&lock_);
        g_dllRefs--;
    }

    // Caller holds lock_. Without a user list (older Windows) any enrolled user is fine.
    bool UserWanted() const
    {
        if (!haveUsers_)
        {
            return true;
        }
        std::wstring qualified = ComputerName() + L"\\" + state_.user;
        for (const std::wstring& u : users_)
        {
            if (_wcsicmp(u.c_str(), qualified.c_str()) == 0 || _wcsicmp(u.c_str(), state_.user.c_str()) == 0)
            {
                return true;
            }
        }
        return false;
    }

    void StartWatcher()
    {
        HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stop)
        {
            return;
        }
        WatchArgs* args = new (std::nothrow) WatchArgs();
        HANDLE threadStop = nullptr;
        HMODULE module = nullptr;
        if (!args ||
            !DuplicateHandle(GetCurrentProcess(), stop, GetCurrentProcess(), &threadStop, 0, FALSE,
                             DUPLICATE_SAME_ACCESS) ||
            !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(&WatchThunk),
                                &module))
        {
            if (threadStop)
            {
                CloseHandle(threadStop);
            }
            delete args;
            CloseHandle(stop);
            return;
        }
        args->provider = this;
        args->stop = threadStop;
        args->module = module;
        AddRef();
        HANDLE thread = CreateThread(nullptr, 0, WatchThunk, args, 0, nullptr);
        if (!thread)
        {
            Release();
            CloseHandle(threadStop);
            FreeLibrary(module);
            delete args;
            CloseHandle(stop);
            return;
        }
        stop_ = stop;
        thread_ = thread;
    }

    void StopWatcher()
    {
        if (thread_)
        {
            SetEvent(stop_);
            // On timeout the thread keeps its own event handle, provider reference and DLL reference,
            // so letting go of ours here is safe.
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

    static DWORD WINAPI WatchThunk(LPVOID param)
    {
        WatchArgs* args = static_cast<WatchArgs*>(param);
        HMODULE module = args->module;
        try
        {
            DWORD oldMode = 0;
            SetThreadErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX, &oldMode);
            args->provider->Watch(args->stop);
        }
        catch (...)
        {
        }
        args->provider->Release();
        CloseHandle(args->stop);
        delete args;
        FreeLibraryAndExitThread(module, 0);
    }

    // Looks for the drive now and every 1.5 s; tells LogonUI to ask again when anything changed.
    void Watch(HANDLE stop)
    {
        DWORD wait = 0;
        while (WaitForSingleObject(stop, wait) == WAIT_TIMEOUT)
        {
            wait = 1500;
            try
            {
                DriveState found;
                if (ProbeDrive(found.key))
                {
                    Enrolment e;
                    if (Decrypt(found.key, e))
                    {
                        found.ready = true;
                        found.user = e.user;
                    }
                }
                if (!found.ready)
                {
                    found.key.Clear();
                }
                EnterCriticalSection(&lock_);
                bool changed = found.ready != state_.ready ||
                               (found.ready && (memcmp(found.key.id, state_.key.id, 16) != 0 ||
                                                found.user != state_.user));
                if (changed)
                {
                    state_.key.Clear();
                    state_ = found;
                    suppressed_ = false;  // a different drive (or none): start fresh
                }
                ICredentialProviderEvents* events = changed ? events_ : nullptr;
                UINT_PTR context = context_;
                if (events)
                {
                    events->AddRef();
                }
                LeaveCriticalSection(&lock_);
                found.key.Clear();
                if (events)
                {
                    events->CredentialsChanged(context);
                    events->Release();
                }
            }
            catch (...)
            {
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
    CRITICAL_SECTION lock_;
    DriveState state_;
    std::vector<std::wstring> users_;
    bool haveUsers_;
    bool suppressed_;
};

Credential::Credential(Provider* provider, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus)
    : refs_(1), provider_(provider), cpus_(cpus)
{
    g_dllRefs++;
}

Credential::~Credential()
{
    g_dllRefs--;
}

HRESULT Credential::GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
                                     CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* cs, PWSTR* statusText,
                                     CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon)
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
        // Decrypt from the cached drive key and the registry, so the password lives only for this call.
        DriveKey key;
        Enrolment e;
        bool ok = provider_ && provider_->CurrentKey(key) && Decrypt(key, e);
        memcpy(lastId_, key.id, 16);
        key.Clear();
        if (!ok)
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

HRESULT Credential::ReportResult(NTSTATUS status, NTSTATUS, PWSTR* statusText, CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon)
{
    if (statusText)
    {
        *statusText = nullptr;
    }
    if (statusIcon)
    {
        *statusIcon = CPSI_NONE;
    }
    if (status < 0)  // !NT_SUCCESS
    {
        try
        {
            if (provider_)
            {
                provider_->Rejected(lastId_, status);
            }
        }
        catch (...)
        {
        }
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
