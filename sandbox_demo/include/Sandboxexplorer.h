// ============================================================
//  SandboxExplorer.h
//
//  Integrates with the existing SandboxEngine + DriverManager
//  to provide Sandboxie-style "Show in folder" support:
//
//  PROBLEM:
//    Chrome's "Show in folder" calls SHOpenFolderAndSelectItems
//    with the REAL download path (e.g. C:\Users\foo\Downloads).
//    This opens an *unsandboxed* Explorer that sees only the real
//    filesystem — none of the files Chrome wrote to the sandbox
//    virtual root (C:\SandboxDemo\Box00\drive\Users\foo\Downloads).
//
//  SANDBOXIE'S APPROACH:
//    1. Inject SbieDll.dll into every sandboxed process.
//    2. SbieDll hooks SHOpenFolderAndSelectItems + ShellExecuteW.
//    3. When Chrome triggers "Show in folder", SbieDll intercepts
//       it, suppresses the real call, and asks SbieCtrl (the user-
//       mode service) to launch a sandboxed Explorer instead.
//    4. The sandboxed Explorer is in the same box → the minifilter
//       redirects its file I/O, so it sees the merged view
//       (host files + sandbox overlay = Notepad save-dialog style).
//  OUR IMPLEMENTATION:
//    - SandboxBorder.dll  = injected Show-in-folder shell hook
//    - SandboxExplorer    = this class; runs a named-pipe server
//      and handles open-folder requests from the DLL.
//    - The DLL is injected while each root process is suspended.
//
//  INTEGRATION POINTS in MainWindow.cpp:
//    // After m_engine.launch() succeeds:
//    m_engine.injectWhileSuspended(sp, explorerDllPath);
//    // Start pipe server once (e.g. in constructor):
//    m_explorer.startPipeServer(m_driver, m_engine, cfg);
// ============================================================
#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <functional>

#include "SandboxEngine.h"
#include "DriverManager.h"
#include "../SandboxBorder/SandboxBorder.h"

// Callback type for logging (same signature as the rest of the codebase)
using ExplorerLogFn = std::function<void(const std::wstring&)>;

// ============================================================
class SandboxExplorer {
public:
    explicit SandboxExplorer(ExplorerLogFn log = nullptr);
    ~SandboxExplorer();

    // ---- Named-pipe server ------------------------------------

    // Start the background thread that listens for open-folder requests
    // from injected DLLs.  Safe to call multiple times (idempotent).
    //
    // engine + driver: used to launch the sandboxed Explorer on demand
    // fsRootBase:      e.g. L"C:\\SandboxDemo"  (same as cfg.fsRootBase)
    void startPipeServer(DriverManager& driver,
                         SandboxEngine&  engine,
                         const std::wstring& fsRootBase);

    void stopPipeServer();

    // ---- Sandboxed Explorer launch ----------------------------

    // Launch explorer.exe /select,"<virtualPath>" inside the box.
    // Called by the pipe server when it receives an openFolder request.
    //
    // boxName:      the box the request came from
    // realPath:     the real path Chrome passed to SHOpenFolderAndSelectItems
    // sandboxRoot:  full Win32 root of the box (e.g. C:\SandboxDemo\Box00)
    bool openFolderInSandbox(DriverManager&      driver,
                             SandboxEngine&       engine,
                             const std::wstring&  boxName,
                             const std::wstring&  realPath,
                             const std::wstring&  fsRootBase);

    // Default DLL path: same directory as the host EXE
    static std::wstring defaultDllPath();

private:
    ExplorerLogFn   m_log;
    std::thread     m_pipeThread;
    std::atomic_bool m_running{ false };

    // Pipe server loop body (runs on m_pipeThread)
    void pipeServerLoop(DriverManager*    driver,
                        SandboxEngine*    engine,
                        std::wstring      fsRootBase);

    // Map a real Win32 path to the sandbox overlay path.
    // e.g. "C:\Users\foo\Downloads" → "C:\SandboxDemo\Box00\drive\Users\foo\Downloads"
    static std::wstring realToVirtual(const std::wstring& realPath,
                                      const std::wstring& boxRoot);

    // Minimal JSON field extractor (avoids a JSON library dependency)
    static std::string  jsonGetField(const std::string& json,
                                     const std::string& key);

    void log(const std::wstring& msg) { if (m_log) m_log(msg); }
};
