#pragma once
// ============================================================
//  SandboxEngine.h
//  (unchanged except: injectWhileSuspended() added)
// ============================================================
#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include "NtDefs.h"

struct SandboxedProcess {
    DWORD  pid          = 0;
    HANDLE hProcess     = nullptr;
    HANDLE hThread      = nullptr;
    HANDLE hJob         = nullptr;
    HANDLE hNamespaceDir= nullptr;
    std::wstring boxName;
    std::wstring fsRoot;
    std::vector<DWORD> driverPids;
    bool   valid        = false;
    bool   suspended    = false;
};

struct SandboxConfig {
    std::wstring boxName;
    std::wstring executablePath;
    std::wstring commandLine;
    std::wstring fsRootBase;
    std::wstring borderDllPath;   // path to injected shell broker; empty = skip
    bool restrictUI     = true;
    bool killOnClose    = true;
    bool inheritConsole = false;
};

using LogCallback = std::function<void(const std::wstring&)>;

class SandboxEngine {
public:
    explicit SandboxEngine(LogCallback log = nullptr);
    ~SandboxEngine();

    SandboxedProcess launch(const SandboxConfig& cfg);
    void release(SandboxedProcess& sp);
    bool resume(SandboxedProcess& sp);

    // Inject a DLL into a SUSPENDED process using thread-context hijack.
    // Must be called BEFORE resume() while the process is still suspended.
    // Works even when the Job has JOB_OBJECT_UILIMIT_HANDLES, because the
    // process has not yet started and the UI restrictions are not enforced
    // on memory operations against a suspended, not-yet-scheduled thread.
    //
    // hProcess / hThread: from SandboxedProcess (PROCESS_ALL_ACCESS from CreateProcess)
    // dllPath:            full Win32 path to the DLL
    bool injectWhileSuspended(const SandboxedProcess& sp,
                               const std::wstring& dllPath);

    static bool isAlive(DWORD pid);
    static bool isAlive(const SandboxedProcess& sp);
    static std::wstring describeJob(HANDLE hJob);

private:
    LogCallback m_log;

    HANDLE createPrivateNamespace(const std::wstring& boxName);
    HANDLE createJobObject(const SandboxConfig& cfg);
    bool   spawnInJob(const SandboxConfig& cfg,
                      HANDLE hJob,
                      HANDLE hNsDir,
                      SandboxedProcess& out);
    std::wstring prepareFsRoot(const std::wstring& base,
                                const std::wstring& boxName);
    void log(const std::wstring& msg);
};
