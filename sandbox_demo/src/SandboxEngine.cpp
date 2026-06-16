// ============================================================
//  SandboxEngine.cpp
//
//  Core implementation.  Read the inline comments — they
//  explain exactly which Sandboxie technique each block maps to.
// ============================================================
#include "SandboxEngine.h"
#include <psapi.h>
#include <sstream>
#include <filesystem>
#include <cassert>
#include <algorithm>
#include <fstream>

namespace fs = std::filesystem;

static bool isChromiumFamilyPath(std::wstring path)
{
    std::transform(path.begin(), path.end(), path.begin(), ::towlower);
    return path.find(L"chrome") != std::wstring::npos ||
        path.find(L"msedge") != std::wstring::npos ||
        path.find(L"brave") != std::wstring::npos;
}

static std::string utf8FromWide(const std::wstring& text)
{
    if (text.empty()) return {};

    int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
        static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};

    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
        static_cast<int>(text.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

static std::string jsonEscape(const std::string& text)
{
    std::string out;
    out.reserve(text.size());
    for (char ch : text) {
        switch (ch) {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:   out += ch; break;
        }
    }
    return out;
}

static DWORD makeSandboxPathWritable(const std::wstring& path)
{
    PSECURITY_DESCRIPTOR sd = nullptr;
    DWORD flags = DACL_SECURITY_INFORMATION;

#ifdef LABEL_SECURITY_INFORMATION
    flags |= LABEL_SECURITY_INFORMATION;
#endif

    /*
     * This is a demo sandbox root, not a host-protected directory.  Chrome may
     * use restricted/low-integrity workers for download writes, so the sandbox
     * tree must be writable by normal users and carry a low integrity label.
     */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)(A;OICI;FA;;;WD)"
        L"S:(ML;OICI;NW;;;LW)",
        SDDL_REVISION_1,
        &sd,
        nullptr)) {
        return GetLastError();
    }

    BOOL ok = SetFileSecurityW(path.c_str(), flags, sd);
    DWORD err = ok ? ERROR_SUCCESS : GetLastError();
    LocalFree(sd);
    return err;
}

// ------------------------------------------------------------
//  Constructor / Destructor
// ------------------------------------------------------------
SandboxEngine::SandboxEngine(LogCallback log)
    : m_log(std::move(log))
{
    // Ensure NT API is loaded once
    auto& api = getNtApi();
    (void)api;
}

SandboxEngine::~SandboxEngine() = default;

// ------------------------------------------------------------
//  Public: launch()
//  Orchestrates the four isolation steps.
// ------------------------------------------------------------
SandboxedProcess SandboxEngine::launch(const SandboxConfig& cfg)
{
    SandboxedProcess result;
    result.boxName = cfg.boxName;

    log(L"[SandboxEngine] === Launching box: " + cfg.boxName + L" ===");

    // STEP 1 — Object Namespace Virtualization
    //   Create \Sessions\<n>\BaseNamedObjects\Sandbox\<boxName>\
    //   This mirrors what SbieDrv does in kernel:
    //   any named object the child creates via CreateMutex,
    //   CreateNamedPipe, CreateFileMapping etc. will be looked
    //   up relative to this directory when we pass it as the
    //   root in OBJECT_ATTRIBUTES (or via the boundary descriptor
    //   + private namespace APIs).
    result.hNamespaceDir = createPrivateNamespace(cfg.boxName);
    if (!result.hNamespaceDir) {
        log(L"[!] Failed to create private namespace for " + cfg.boxName);
        // Non-fatal for the demo — continue without NS isolation
    }
    else {
        log(L"[+] Private NT namespace created: \\Sandbox\\" + cfg.boxName);
    }

    // STEP 2 — Job Object Containment
    //   Sandboxie wraps every sandboxed process tree in a Job.
    //   - All children automatically join the same job.
    //   - JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: whole tree dies
    //     when our handle is closed (prevents orphaned processes).
    //   - JOB_OBJECT_UILIMIT_*: blocks hooking the global message
    //     queue, accessing the desktop, etc.
    result.hJob = createJobObject(cfg);
    if (!result.hJob) {
        log(L"[!] Failed to create Job Object — aborting.");
        return result;
    }
    log(L"[+] Job Object created (kill-on-close=" +
        std::wstring(cfg.killOnClose ? L"yes" : L"no") + L")");

    // STEP 3 — Filesystem Root Preparation
    //   Sandboxie redirects every NtCreateFile call in kernel.
    //   We approximate this at the user-mode launch level:
    //   prepare a per-box folder and pass it to the child via
    //   environment variable / command-line flag so the child
    //   writes there instead of the real FS.
    result.fsRoot = prepareFsRoot(cfg.fsRootBase, cfg.boxName);
    log(L"[+] FS root: " + result.fsRoot);

    // STEP 4 — Spawn process suspended → assign to Job.
    //   We MUST assign to the job before the first thread runs,
    //   otherwise child processes spawned immediately on start
    //   can escape the job boundary.
    if (!spawnInJob(cfg, result.hJob, result.hNamespaceDir, result)) {
        log(L"[!] Failed to spawn process.");
        CloseHandle(result.hJob);
        if (result.hNamespaceDir) CloseHandle(result.hNamespaceDir);
        return result;
    }

    result.valid = true;
    log(L"[+] Process " + std::to_wstring(result.pid) +
        L" created suspended inside sandbox box \"" + cfg.boxName + L"\"");
    return result;
}

// ------------------------------------------------------------
//  Public: release()
// ------------------------------------------------------------
void SandboxEngine::release(SandboxedProcess& sp)
{
    if (!sp.valid) return;

    // Terminate via Job — kills all children atomically
    if (sp.hJob) {
        TerminateJobObject(sp.hJob, 0);
        CloseHandle(sp.hJob);
        sp.hJob = nullptr;
    }
    if (sp.hProcess) { CloseHandle(sp.hProcess); sp.hProcess = nullptr; }
    if (sp.hThread) { CloseHandle(sp.hThread);  sp.hThread = nullptr; }

    // Release the private namespace handle.
    // Must use ClosePrivateNamespace (not CloseHandle/NtClose) for
    // handles returned by CreatePrivateNamespaceW/OpenPrivateNamespaceW.
    if (sp.hNamespaceDir) {
        ClosePrivateNamespace(sp.hNamespaceDir, 0);
        sp.hNamespaceDir = nullptr;
    }
    sp.valid = false;
    sp.suspended = false;
    log(L"[SandboxEngine] Released box: " + sp.boxName);
}

bool SandboxEngine::resume(SandboxedProcess& sp)
{
    if (!sp.valid || !sp.hThread) return false;
    if (!sp.suspended) return true;

    DWORD rc = ResumeThread(sp.hThread);
    if (rc == static_cast<DWORD>(-1)) {
        log(L"[!] ResumeThread failed: " + std::to_wstring(GetLastError()));
        return false;
    }

    sp.suspended = false;
    log(L"[+] PID " + std::to_wstring(sp.pid) + L" resumed.");
    return true;
}

// ------------------------------------------------------------
//  Public: isAlive()
// ------------------------------------------------------------
bool SandboxEngine::isAlive(DWORD pid)
{
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!h) return false;
    DWORD rc = WaitForSingleObject(h, 0);
    CloseHandle(h);
    return rc == WAIT_TIMEOUT;  // WAIT_TIMEOUT → still running
}

bool SandboxEngine::isAlive(const SandboxedProcess& sp)
{
    if (!sp.valid) return false;

    if (sp.hJob) {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION bai{};
        if (QueryInformationJobObject(sp.hJob,
            JobObjectBasicAccountingInformation,
            &bai, sizeof(bai), nullptr)) {
            return bai.ActiveProcesses > 0;
        }
    }

    return isAlive(sp.pid);
}

// ------------------------------------------------------------
//  Private: createPrivateNamespace()
//
//  TECHNIQUE 1 — Object Manager Namespace Virtualization
//
//  Sandboxie's SbieDrv.sys hooks NtOpenDirectoryObject and
//  NtCreateDirectoryObject at the SSDT level and rewrites the
//  path from \BaseNamedObjects\<name> to
//  \BaseNamedObjects\Sandbox\<box>\<name>.
//
//  In user mode (no kernel driver) we use the documented
//  Private Namespace APIs (Vista+) which achieve the same
//  effect for named objects created by processes that call
//  CreatePrivateNamespace / OpenPrivateNamespace:
//
//    CreateBoundaryDescriptor  → opaque token identifying the box
//    AddSIDToBoundaryDescriptor → only THIS user's processes can join
//    CreatePrivateNamespace     → creates the NT directory object
//
//  Processes that use the returned HANDLE as their namespace
//  root will find/create named objects in isolation.
//
//  For child processes that don't call these APIs themselves
//  (like Chrome), a full implementation would inject a shim DLL
//  (just like SbieApi_NtMonitor does) that intercepts Win32
//  named-object creation and prepends the box prefix.
//  For this demo we show the namespace creation side.
// ------------------------------------------------------------
HANDLE SandboxEngine::createPrivateNamespace(const std::wstring& boxName)
{
    // Build boundary descriptor
    HANDLE hBd = CreateBoundaryDescriptorW(boxName.c_str(), 0);
    if (!hBd) {
        log(L"[!] CreateBoundaryDescriptor failed: " +
            std::to_wstring(GetLastError()));
        return nullptr;
    }

    // Get the current user's real SID from the process token.
    // WinCreatorOwnerSid is a placeholder and cannot be used here —
    // AddSIDToBoundaryDescriptor requires a real account SID.
    BYTE   sidBuf[SECURITY_MAX_SID_SIZE] = {};
    PSID   pSid = reinterpret_cast<PSID>(sidBuf);
    bool   sidOk = false;

    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BYTE   tuBuf[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE] = {};
        DWORD  needed = 0;
        if (GetTokenInformation(hToken, TokenUser, tuBuf, sizeof(tuBuf), &needed)) {
            auto* tu = reinterpret_cast<TOKEN_USER*>(tuBuf);
            DWORD sidLen = GetLengthSid(tu->User.Sid);
            if (sidLen <= SECURITY_MAX_SID_SIZE) {
                CopySid(SECURITY_MAX_SID_SIZE, pSid, tu->User.Sid);
                sidOk = true;
            }
        }
        CloseHandle(hToken);
    }

    if (!sidOk) {
        // Fallback: LocalSystem / Administrators SID
        DWORD sidLen = SECURITY_MAX_SID_SIZE;
        if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, pSid, &sidLen)) {
            sidLen = SECURITY_MAX_SID_SIZE;
            CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, pSid, &sidLen);
        }
    }

    if (!AddSIDToBoundaryDescriptor(&hBd, pSid)) {
        log(L"[!] AddSIDToBoundaryDescriptor failed: " +
            std::to_wstring(GetLastError()));
        DeleteBoundaryDescriptor(hBd);
        return nullptr;
    }

    // NULL DACL = anyone who knows the name and has matching SID can open
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    SECURITY_DESCRIPTOR sd{};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);
    sa.lpSecurityDescriptor = &sd;

    HANDLE hNs = CreatePrivateNamespaceW(&sa, hBd, boxName.c_str());
    if (!hNs) {
        DWORD err = GetLastError();
        if (err == ERROR_ALREADY_EXISTS) {
            log(L"[~] Private namespace '" + boxName + L"' already exists, opening.");
            hNs = OpenPrivateNamespaceW(hBd, boxName.c_str());
        }
        if (!hNs) {
            log(L"[!] CreatePrivateNamespace failed: " + std::to_wstring(err) +
                L" (ensure app runs as Administrator)");
            DeleteBoundaryDescriptor(hBd);
            return nullptr;
        }
    }

    DeleteBoundaryDescriptor(hBd);
    return hNs;
}

// ------------------------------------------------------------
//  Private: createJobObject()
//
//  TECHNIQUE 2 — Job Object Containment
//
//  Sandboxie places every sandboxed process + its descendants
//  into a named Job Object.  Key limits we apply:
//
//  JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
//    → When our HANDLE closes (app exits or calls release()),
//      Windows terminates every process in the job.
//      Prevents orphaned processes escaping the sandbox.
//
//  JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
//    → Exceptions don't pop WER dialogs from a sandboxed proc.
//
//  JOB_OBJECT_UILIMIT_HANDLES
//    → Sandboxed processes cannot use USER handles (HWND, etc.)
//      belonging to processes outside the job.
//
//  JOB_OBJECT_UILIMIT_GLOBALATOMS
//    → Cannot read/write the global atom table (DDE isolation).
//
//  JOB_OBJECT_UILIMIT_EXITWINDOWS
//    → Cannot call ExitWindowsEx() to reboot/logoff the host.
//
//  JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
//    → Cannot call SystemParametersInfo to change system settings.
// ------------------------------------------------------------
HANDLE SandboxEngine::createJobObject(const SandboxConfig& cfg)
{
    std::wstring jobName = L"SandboxDemo_" + cfg.boxName;
    HANDLE hJob = CreateJobObjectW(nullptr, jobName.c_str());
    if (!hJob) {
        log(L"[!] CreateJobObject failed: " +
            std::to_wstring(GetLastError()));
        return nullptr;
    }

    // -- Basic limits --
    JOBOBJECT_BASIC_LIMIT_INFORMATION bli{};
    if (cfg.killOnClose)
        bli.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    bli.LimitFlags |= JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli{};
    eli.BasicLimitInformation = bli;

    if (!SetInformationJobObject(hJob,
        JobObjectExtendedLimitInformation,
        &eli, sizeof(eli))) {
        log(L"[!] SetInformationJobObject (limits) failed: " +
            std::to_wstring(GetLastError()));
    }

    // -- UI restrictions (mirrors Sandboxie's UIPI enforcement) --
    if (cfg.restrictUI) {
        JOBOBJECT_BASIC_UI_RESTRICTIONS uir{};
        uir.UIRestrictionsClass =
            JOB_OBJECT_UILIMIT_HANDLES |   // no cross-job USER handles
            JOB_OBJECT_UILIMIT_GLOBALATOMS |   // no global atom table
            JOB_OBJECT_UILIMIT_EXITWINDOWS |   // no ExitWindowsEx
            JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;   // no SystemParametersInfo

        if (!SetInformationJobObject(hJob,
            JobObjectBasicUIRestrictions,
            &uir, sizeof(uir))) {
            log(L"[!] SetInformationJobObject (UI) failed: " +
                std::to_wstring(GetLastError()));
        }
    }

    return hJob;
}

// ------------------------------------------------------------
//  Private: spawnInJob()
//
//  TECHNIQUE 3 partial + the critical "assign before resume" trick
//
//  Pattern:
//    1. CreateProcess(..., CREATE_SUSPENDED, ...)
//    2. AssignProcessToJobObject(hJob, hProcess)
//    3. ResumeThread(hThread)
//
//  If you ResumeThread BEFORE AssignProcessToJobObject, the
//  process may spawn children that miss the job assignment.
//  Sandboxie's driver assigns at NtCreateProcess time (kernel);
//  we approximate this in user mode using CREATE_SUSPENDED.
//
//  FS Redirection approximation:
//    We inject SANDBOX_ROOT env var and (for Chrome) append
//    --user-data-dir=<fsRoot> so Chrome writes to the sandbox
//    folder.  A real implementation (like Sandboxie) hooks
//    NtCreateFile in kernel and rewrites every path on the fly.
// ------------------------------------------------------------
bool SandboxEngine::spawnInJob(const SandboxConfig& cfg,
    HANDLE hJob,
    HANDLE /*hNsDir*/,
    SandboxedProcess& out)
{
    // Build environment block with SANDBOX_ROOT injected
    // (demonstrates the FS redirection intent)
    std::wstring envBlock;
    {
        // Copy current environment
        LPWCH curEnv = GetEnvironmentStringsW();
        if (curEnv) {
            for (LPWCH p = curEnv; *p; ) {
                std::wstring entry(p);
                // Never inherit stale sandbox identity into a new launch.
                if (entry.find(L"SANDBOX_ROOT=") != 0 &&
                    entry.find(L"SANDBOX_BOX=") != 0 &&
                    entry.find(L"SANDBOX_BORDER_ACTIVE=") != 0)
                    envBlock += entry + L'\0';
                p += entry.size() + 1;
            }
            FreeEnvironmentStringsW(curEnv);
        }
        // Inject sandbox variables
        envBlock += L"SANDBOX_ROOT=" + out.fsRoot + L'\0';
        envBlock += L"SANDBOX_BOX=" + cfg.boxName + L'\0';
        if (!cfg.borderDllPath.empty())
            envBlock += L"SANDBOX_BORDER_ACTIVE=1\0";
        envBlock += L'\0';  // double-null terminator
    }

    // Build command line
    std::wstring cmdLine = L"\"" + cfg.executablePath + L"\"";
    if (!cfg.commandLine.empty())
        cmdLine += L" " + cfg.commandLine;

    // Keep Chromium profile data under the driver's sandbox root.  If this
    // points at out.fsRoot\Profile, the minifilter redirects it again into a
    // nested path and Chrome exits during early profile initialization.
    if (isChromiumFamilyPath(cfg.executablePath)) {
        cmdLine += L" --user-data-dir=\"" + out.fsRoot + L"\\drive\\Profile\"";
        cmdLine += L" --no-first-run";
        cmdLine += L" --disable-background-networking";
        cmdLine += L" --no-sandbox";
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    DWORD flags = CREATE_SUSPENDED           // Must be suspended first!
        | CREATE_NEW_CONSOLE
        | CREATE_UNICODE_ENVIRONMENT;// envBlock is wide chars

    BOOL ok = CreateProcessW(
        cfg.executablePath.c_str(),
        cmdLine.data(),
        nullptr,              // process SA
        nullptr,              // thread SA
        FALSE,                // inherit handles = no
        flags,
        envBlock.data(),      // our modified environment
        nullptr,              // current directory (inherit)
        &si,
        &pi
    );

    if (!ok) {
        log(L"[!] CreateProcess failed: " +
            std::to_wstring(GetLastError()) +
            L"  cmd=" + cmdLine);
        return false;
    }

    // *** ASSIGN TO JOB BEFORE RESUMING ***
    // The caller registers the PID with the driver before resume, so
    // children created by Chrome inherit sandbox membership immediately.
    if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
        DWORD err = GetLastError();
        log(L"[!] AssignProcessToJobObject failed: " +
            std::to_wstring(err));
        // ERROR_ACCESS_DENIED (5) usually means the process is
        // already in a job (e.g., launched from a job-constrained
        // parent like VS debugger).  In that case we continue
        // anyway — nested jobs are supported on Win8+.
        if (err != ERROR_ACCESS_DENIED) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
    }
    else {
        log(L"[+] Process assigned to Job Object before first instruction");
    }

    out.pid = pi.dwProcessId;
    out.hProcess = pi.hProcess;
    out.hThread = pi.hThread;
    out.suspended = true;
    return true;
}

// ------------------------------------------------------------
//  Private: prepareFsRoot()
//  Creates the per-box directory tree.
// ------------------------------------------------------------
std::wstring SandboxEngine::prepareFsRoot(const std::wstring& base,
    const std::wstring& boxName)
{
    std::wstring root = base + L"\\" + boxName;
    std::error_code ec;
    fs::create_directories(fs::path(root), ec);
    fs::create_directories(fs::path(root + L"\\drive\\C"), ec);
    fs::create_directories(fs::path(root + L"\\drive\\Downloads"), ec);
    fs::create_directories(fs::path(root + L"\\drive\\Profile"), ec);
    fs::create_directories(fs::path(root + L"\\drive\\Profile\\Default"), ec);
    fs::create_directories(fs::path(root + L"\\RegHive"), ec);
    fs::create_directories(fs::path(root + L"\\Profile"), ec);

    for (const auto& dir : {
        root,
        root + L"\\drive",
        root + L"\\drive\\C",
        root + L"\\drive\\Downloads",
        root + L"\\drive\\Profile",
        root + L"\\drive\\Profile\\Default",
        root + L"\\RegHive",
        root + L"\\Profile"
    }) {
        DWORD aclErr = makeSandboxPathWritable(dir);
        if (aclErr != ERROR_SUCCESS) {
            log(L"[!] Failed to relax sandbox ACL for " + dir +
                L": " + std::to_wstring(aclErr));
        }
    }

    {
        fs::path prefsPath(root + L"\\drive\\Profile\\Default\\Preferences");
        std::ofstream prefs(prefsPath, std::ios::binary | std::ios::trunc);
        if (prefs) {
            std::string downloads = jsonEscape(
                utf8FromWide(root + L"\\drive\\Downloads"));
            prefs
                << "{"
                << "\"download\":{"
                << "\"default_directory\":\"" << downloads << "\","
                << "\"directory_upgrade\":true,"
                << "\"prompt_for_download\":false"
                << "},"
                << "\"safebrowsing\":{\"enabled\":false}"
                << "}";
        }
    }

    return root;
}

// ------------------------------------------------------------
//  Public: describeJob()
//  Returns a human-readable summary of job object limits.
// ------------------------------------------------------------
std::wstring SandboxEngine::describeJob(HANDLE hJob)
{
    if (!hJob) return L"(no job)";

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli{};
    if (!QueryInformationJobObject(hJob,
        JobObjectExtendedLimitInformation,
        &eli, sizeof(eli), nullptr))
        return L"(query failed)";

    std::wostringstream ss;
    ss << L"Flags=0x" << std::hex << eli.BasicLimitInformation.LimitFlags;
    if (eli.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        ss << L" KillOnClose";
    if (eli.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION)
        ss << L" DieOnException";

    JOBOBJECT_BASIC_UI_RESTRICTIONS uir{};
    if (QueryInformationJobObject(hJob, JobObjectBasicUIRestrictions,
        &uir, sizeof(uir), nullptr)) {
        if (uir.UIRestrictionsClass & JOB_OBJECT_UILIMIT_HANDLES)
            ss << L" NoHandleLeak";
        if (uir.UIRestrictionsClass & JOB_OBJECT_UILIMIT_GLOBALATOMS)
            ss << L" NoGlobalAtoms";
        if (uir.UIRestrictionsClass & JOB_OBJECT_UILIMIT_EXITWINDOWS)
            ss << L" NoExitWindows";
    }
    return ss.str();
}

// ------------------------------------------------------------
void SandboxEngine::log(const std::wstring& msg)
{
    if (m_log) m_log(msg);
}

