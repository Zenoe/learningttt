#pragma once
// ============================================================
//  SandboxEngine.h
//  (unchanged except: injectWhileSuspended() added)
// ============================================================
#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include "NtDefs.h"
#include "VaultManager.h"

#ifndef SANDBOX_LOG_CALLBACK_DEFINED
#define SANDBOX_LOG_CALLBACK_DEFINED
using LogCallback = std::function<void(const std::wstring&)>;
#endif

struct DerivedKeys {
    std::array<uint8_t, 32> masterKey{};
    std::array<uint8_t, 32> hmacKey{};
};

struct SandboxedProcess {
    DWORD  pid          = 0;
    HANDLE hProcess     = nullptr;
    HANDLE hThread      = nullptr;
    HANDLE hJob         = nullptr;
    HANDLE hNamespaceDir= nullptr;
    std::wstring boxName;
    std::wstring fsRoot;
    std::wstring vaultFilePath;
    std::wstring vaultMountPoint;
    std::wstring mountPointNt;
    std::array<uint8_t, 32> masterKey{};
    std::array<uint8_t, 32> hmacKey{};
    std::vector<DWORD> driverPids;
    bool   wfpEnabled   = false;
    ULONG  wfpVnicIp    = 0;
    bool   vaultMounted  = false;
    bool   cryptoKeysValid = false;
    bool   valid        = false;
    bool   suspended    = false;
};

struct SandboxConfig {
    std::wstring boxName;
    std::wstring executablePath;
    std::wstring commandLine;
    std::wstring fsRootBase;
    bool useVault = true;
    std::wstring vaultDir = L"C:\\SandboxBoxes";
    std::wstring mountDir = L"C:\\SandboxMounts";
    uint64_t vaultSizeMB = 512;
    std::wstring passphrase;
    std::wstring borderDllPath;   // path to injected shell broker; empty = skip
    bool restrictUI     = true;
    bool killOnClose    = true;
    bool inheritConsole = false;
};

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
    static DerivedKeys deriveKeys(const std::wstring& boxName,
                                  const std::vector<uint8_t>& salt,
                                  const std::wstring& passphrase);

private:
    LogCallback m_log;
    VaultManager m_vault;

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
