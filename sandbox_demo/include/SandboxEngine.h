#pragma once
// ============================================================
//  SandboxEngine.h
//  Sandboxed process creation and Detours payload injection.
// ============================================================
#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include "NtDefs.h"

#ifndef SANDBOX_LOG_CALLBACK_DEFINED
#define SANDBOX_LOG_CALLBACK_DEFINED
using LogCallback = std::function<void(const std::wstring&)>;
#endif

struct SandboxedProcess {
    DWORD  pid          = 0;
    HANDLE hProcess     = nullptr;
    HANDLE hThread      = nullptr;
    HANDLE hJob         = nullptr;
    HANDLE hNamespaceDir= nullptr;
    std::wstring boxName;
    std::wstring fsRoot;
    std::vector<DWORD> driverPids;
    bool   wfpEnabled   = false;
    bool   driverRegistered = false;
    ULONG  wfpVnicIp    = 0;
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
    bool isolateClipboard = true;
    bool killOnClose    = true;
    bool inheritConsole = false;
};

class SandboxEngine {
public:
    explicit SandboxEngine(LogCallback log = nullptr);
    ~SandboxEngine();

    SandboxedProcess launch(const SandboxConfig& cfg);
    SandboxedProcess createBoxSession(const SandboxConfig& cfg,
                                      const std::wstring& fsRoot);
    SandboxedProcess launchInExistingBox(const SandboxConfig& cfg,
                                         HANDLE existingJob,
                                         const std::wstring& fsRoot);
    void release(SandboxedProcess& sp);
    bool resume(SandboxedProcess& sp);

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
    std::wstring prepareFsRootAt(const std::wstring& root);
    void log(const std::wstring& msg);
};
