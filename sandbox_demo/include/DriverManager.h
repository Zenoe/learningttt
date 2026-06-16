#pragma once
// ============================================================
//  DriverManager.h
//
//  Handles the full lifecycle of SandboxFlt.sys from user mode:
//    1. Install   — copy .sys + call SCM to register service
//    2. Load      — StartService / fltMC load
//    3. Open      — CreateFile(\\.\SandboxFlt)
//    4. IOCTL     — add/remove boxes and PIDs, query stats
//    5. Unload    — StopService
//    6. Uninstall — delete service registration
//
//  Requires elevation (Administrator).
// ============================================================
#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsvc.h>
#include <string>
#include <functional>

// Pull in the shared IPC header (same file the driver uses)
#include "../driver/include/SandboxIpc.h"

using LogFn = std::function<void(const std::wstring&)>;

class DriverManager {
public:
    explicit DriverManager(LogFn log = nullptr);
    ~DriverManager();

    // ---- Lifecycle ----------------------------------------

    // Install the driver service (copies .sys to system32\drivers,
    // registers via SCM).  sysPath = full path to SandboxFlt.sys.
    bool install(const std::wstring& sysPath);

    // Load (start) the driver — must be installed first.
    bool load();

    // Open the control device so IOCTLs can be sent.
    bool open();

    // Stop and optionally uninstall the service.
    bool unload(bool uninstall = false);

    bool isLoaded()  const { return m_hDevice != INVALID_HANDLE_VALUE; }
    bool isInstalled() const;

    // ---- IOCTL wrappers -----------------------------------

    // Register a sandbox box with the driver.
    // sandboxRootRelative: path relative to volume root,
    //   e.g. L"\\SandboxDemo\\Box0\\drive"
    // realRoot: volume-relative path to intercept,
    //   e.g. L"\\" (entire volume) or L"\\Users\\"
    bool addBox(const std::wstring& boxName,
                const std::wstring& sandboxRootRelative,
                const std::wstring& realRoot = L"\\");

    bool removeBox(const std::wstring& boxName);

    // Tell the driver which PID belongs to which box.
    // Call this AFTER the process is created (spawnInJob).
    bool addProcess(DWORD pid, const std::wstring& boxName);
    bool removeProcess(DWORD pid);

    // Query live statistics from the driver.
    bool queryStats(SANDBOX_STATS& out);
    bool queryProcesses(SANDBOX_PROCESS_LIST& out);

    // Update write policy for a box.
    bool setPolicy(const std::wstring& boxName,
                   SANDBOX_WRITE_POLICY policy,
                   bool redirectReads = true,
                   bool hideHostFiles = false);

    // ---- Helpers ------------------------------------------
    static std::wstring defaultSysPath();   // exe dir + SandboxFlt.sys
    static bool isElevated();

private:
    LogFn   m_log;
    HANDLE  m_hDevice = INVALID_HANDLE_VALUE;

    bool sendIoctl(DWORD code,
                   void* inBuf,  DWORD inLen,
                   void* outBuf, DWORD outLen,
                   DWORD* bytesReturned = nullptr);

    void log(const std::wstring& msg);

    static constexpr const wchar_t* kServiceName = L"SandboxFlt";
    static constexpr const wchar_t* kDriverPath  =
        L"\\SystemRoot\\System32\\drivers\\SandboxFlt.sys";
};
