// ============================================================
//  SandboxExplorer.cpp
// ============================================================
#include "SandboxExplorer.h"
#include <filesystem>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cwchar>
#include "StringUtil.h"
namespace fs = std::filesystem;

// ============================================================
SandboxExplorer::SandboxExplorer(ExplorerLogFn log)
    : m_log(std::move(log))
{}

SandboxExplorer::~SandboxExplorer()
{
    stopPipeServer();
}

// ============================================================
//  Named-pipe server
//
//  One pipe instance per connection (ConnectNamedPipe → read →
//  dispatch → disconnect loop).  The pipe name is fixed to the
//  box name, matching what the DLL writes to.
//
//  We use a single shared pipe name for all boxes:
//      \\.\pipe\SandboxFlt_Broker
//  and let the JSON payload carry the box name.  This avoids
//  creating one pipe per box and keeps the server simple.
// ============================================================
static constexpr wchar_t kPipeName[] =
    L"\\\\.\\pipe\\SandboxFlt_Broker";

void SandboxExplorer::startPipeServer(DriverManager& driver,
                                       SandboxEngine&  engine,
                                       const std::wstring& fsRootBase)
{
    if (m_running.exchange(true)) return;  // already running

    // Capture raw pointers.  driver and engine are MainWindow members whose
    // lifetime exceeds this thread — MainWindow::~MainWindow calls
    // stopPipeServer() (which joins the thread) before destroying m_driver
    // and m_engine, so these pointers are always valid while the thread runs.
    DriverManager* pDriver = &driver;
    SandboxEngine* pEngine = &engine;
    m_pipeThread = std::thread([this, pDriver, pEngine, fsRootBase]() {
        pipeServerLoop(pDriver, pEngine, fsRootBase);
    });
    log(L"[Explorer] Pipe server started: " + std::wstring(kPipeName));
}

void SandboxExplorer::stopPipeServer()
{
    if (!m_running.exchange(false)) return;

    // Wake up a blocked ConnectNamedPipe by opening + closing a dummy client
    HANDLE hDummy = CreateFileW(kPipeName, GENERIC_WRITE, 0,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDummy != INVALID_HANDLE_VALUE) CloseHandle(hDummy);

    if (m_pipeThread.joinable()) m_pipeThread.join();
    log(L"[Explorer] Pipe server stopped.");
}

void SandboxExplorer::pipeServerLoop(DriverManager* driver,
                                      SandboxEngine*  engine,
                                      std::wstring    fsRootBase)
{
    log(L"[Explorer] Pipe worker entered. fsRoot=" + fsRootBase);

    while (m_running.load()) {
        // Create a new named pipe instance for each connection
        HANDLE hPipe = CreateNamedPipeW(
            kPipeName,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0, 4096, 0, nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            log(L"[Explorer] CreateNamedPipe failed: " +
                std::to_wstring(GetLastError()));
            Sleep(1000);
            continue;
        }

        log(L"[Explorer] Pipe instance ready; waiting for client...");

        // Block until a client connects
        BOOL connected = ConnectNamedPipe(hPipe, nullptr);
        DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();
        if (!connected && connectError != ERROR_PIPE_CONNECTED) {
            log(L"[Explorer] ConnectNamedPipe failed: " +
                std::to_wstring(connectError));
            CloseHandle(hPipe);
            continue;
        }

        log(L"[Explorer] Pipe client connected.");

        if (!m_running.load()) {
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            break;
        }

        // Read one message (up to 4 KB)
        char buf[4096] = {};
        DWORD read = 0;
        BOOL readOk = ReadFile(hPipe, buf, sizeof(buf) - 1, &read, nullptr);
        if (readOk && read > 0) {
            buf[read] = '\0';
            std::string json(buf);
            log(L"[Explorer] Pipe message received: " +
                std::to_wstring(read) + L" bytes.");

            // Parse: {"cmd":"openFolder","box":"Box00","root":"C:\\SandboxMounts\\Box00","path":"C:\\..."}
            std::string cmd  = jsonGetField(json, "cmd");
            std::string box  = jsonGetField(json, "box");
            std::string root = jsonGetField(json, "root");
            std::string path = jsonGetField(json, "path");

            if (cmd == "openFolder" && !box.empty() && !path.empty()) {
                // Convert UTF-8 fields to wide strings
                std::wstring wBox  = StringUtil::utf8ToWide(box);
                std::wstring wRoot = StringUtil::utf8ToWide(root);
                std::wstring wPath = StringUtil::utf8ToWide(path);

                log(L"[Explorer] openFolder request: box=" + wBox +
                    L" root=" + wRoot + L" path=" + wPath);

                openFolderInSandbox(*driver, *engine, wBox, wPath,
                    wRoot, fsRootBase);
            }
            else {
                log(L"[Explorer] Ignored malformed/unknown pipe message: cmd=" +
                    StringUtil::utf8ToWide(cmd) + L" box=" +
                    StringUtil::utf8ToWide(box) + L" path=" +
                    StringUtil::utf8ToWide(path));
            }
        }
        else {
            DWORD readError = readOk ? ERROR_SUCCESS : GetLastError();
            log(L"[Explorer] Pipe read returned no message. bytes=" +
                std::to_wstring(read) + L" error=" +
                std::to_wstring(readError));
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    log(L"[Explorer] Pipe worker exited.");
}

// ============================================================
//  openFolderInSandbox
//
//  Maps the real Chrome download path to the sandbox virtual
//  path, then launches:
//
//    explorer.exe /select,"<virtualPath>\<selectedFile>"
//
//  inside the same box so the minifilter gives it the merged
//  (host + sandbox overlay) directory view — exactly like the
//  Notepad save dialog already works.
//
//  The Explorer instance is:
//    - Assigned to the box's Job Object (via SandboxEngine::launch)
//    - Its PID is registered with the driver (addProcess)
//    - SandboxBorder.dll is injected for Show-in-folder interception
//
//  After injection, Explorer opens at the virtual path.  The
//  PostDirectoryControl hook in SandboxFlt_Filter.c merges
//  host entries + sandbox entries, so the user sees everything.
// ============================================================
bool SandboxExplorer::openFolderInSandbox(DriverManager&      driver,
                                           SandboxEngine&       engine,
                                           const std::wstring&  boxName,
                                           const std::wstring&  realPath,
                                           const std::wstring&  sandboxRoot,
                                           const std::wstring&  fsRootBase)
{
    // 1. Compute sandbox root for this box
    //    e.g. C:\SandboxMounts\Box00 in vault mode, or C:\SandboxDemo\Box00
    std::wstring boxRoot = sandboxRoot.empty()
        ? fsRootBase + L"\\" + boxName
        : sandboxRoot;

    // 2. Map real path → virtual path
    //    C:\Users\foo\Downloads →
    //    C:\SandboxDemo\Box00\drive\Users\foo\Downloads
    std::wstring virtualPath = realToVirtual(realPath, boxRoot);
    log(L"[Explorer] Virtual path: " + virtualPath);

    // 3. Ensure the virtual directory exists (may not if Chrome hasn't
    //    written anything there yet — in that case we open the sandbox
    //    root's drive folder so the user at least sees something)
    DWORD attr = GetFileAttributesW(virtualPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        fs::path parent = fs::path(virtualPath).parent_path();
        DWORD parentAttr = parent.empty()
            ? INVALID_FILE_ATTRIBUTES
            : GetFileAttributesW(parent.c_str());
        if (parentAttr != INVALID_FILE_ATTRIBUTES &&
            (parentAttr & FILE_ATTRIBUTE_DIRECTORY)) {
            virtualPath = parent.wstring();
            attr = parentAttr;
            log(L"[Explorer] Virtual path not found; falling back to parent " +
                virtualPath);
        }
        else {
            virtualPath = boxRoot + L"\\drive";
            attr = GetFileAttributesW(virtualPath.c_str());
            log(L"[Explorer] Virtual path not found; falling back to " +
                virtualPath);
        }
    }

    // 4. Launch explorer.exe /select,"<virtualPath>" sandboxed
    //    We use SandboxEngine::launch which:
    //      a) Creates a Job Object (KillOnClose=false so Explorer lives independently)
    //      b) Creates the private namespace
    //      c) Spawns explorer.exe suspended
    //    Then we register the PID with the driver and resume.
    wchar_t explorerPath[MAX_PATH] = {};
    GetWindowsDirectoryW(explorerPath, MAX_PATH);
    wcscat_s(explorerPath, L"\\explorer.exe");

    SandboxConfig cfg;
    cfg.boxName        = boxName;
    cfg.executablePath = explorerPath;
    cfg.commandLine    = (attr != INVALID_FILE_ATTRIBUTES &&
                          (attr & FILE_ATTRIBUTE_DIRECTORY))
        ? L"/separate,\"" + virtualPath + L"\""
        : L"/separate,/select,\"" + virtualPath + L"\"";
    cfg.fsRootBase     = fsRootBase;
    cfg.borderDllPath  = defaultDllPath();
    cfg.restrictUI     = false;   // Explorer needs full UI access
    cfg.killOnClose    = false;   // Don't kill Explorer when we close

    SandboxedProcess sp = engine.launch(cfg);
    if (!sp.valid) {
        log(L"[Explorer] Failed to launch sandboxed Explorer.");
        return false;
    }

    // 5. Register with driver (so its file I/O is redirected)
    if (driver.isLoaded()) {
        // Box should already exist; addProcess is idempotent on collision
        bool pidOk = driver.addProcess(sp.pid, boxName);
        if (!pidOk) {
            log(L"[Explorer] Warning: addProcess failed for Explorer PID " +
                std::to_wstring(sp.pid) + L" — it will still run but without FS redirect");
        }
    }

    // 6. SandboxEngine uses DetourCreateProcessWithDllExW when
    //    borderDllPath is set, so no suspended-thread hijack is needed here.
    {
        if (!cfg.borderDllPath.empty()) {
            log(L"[Explorer] Shell broker injected by Detours for Explorer PID " +
                std::to_wstring(sp.pid));
        } else {
            log(L"[Explorer] SandboxBorder.dll not found — Show in folder broker unavailable.");
        }
    }

    // 7. Resume the process (stub runs LoadLibraryW then jumps to real entry)
    if (!engine.resume(sp)) {
        log(L"[Explorer] Failed to resume Explorer.");
        engine.release(sp);
        return false;
    }

    log(L"[Explorer] Sandboxed Explorer PID " +
        std::to_wstring(sp.pid) + L" running at: " + virtualPath);
    return true;
}

// ============================================================
//  realToVirtual
//
//  Maps a real Win32 path to the sandbox's drive overlay.
//
//  Real:     C:\Users\foo\Downloads\file.zip
//  BoxRoot:  C:\SandboxDemo\Box00
//  Virtual:  C:\SandboxDemo\Box00\drive\Users\foo\Downloads\file.zip
//
//  The mapping strips the drive letter + colon, prepends the
//  box root and the "\drive" overlay folder.  This mirrors
//  how SandboxEngine::prepareFsRoot lays out the directory tree.
// ============================================================
std::wstring SandboxExplorer::realToVirtual(const std::wstring& realPath,
                                             const std::wstring& boxRoot)
{
    // Normalise slashes
    std::wstring norm = realPath;
    std::replace(norm.begin(), norm.end(), L'/', L'\\');

    std::wstring normalizedRoot = boxRoot;
    std::replace(normalizedRoot.begin(), normalizedRoot.end(), L'/', L'\\');
    while (!normalizedRoot.empty() &&
           normalizedRoot.back() == L'\\')
        normalizedRoot.pop_back();

    if (!normalizedRoot.empty()) {
        if (_wcsicmp(norm.c_str(), normalizedRoot.c_str()) == 0)
            return norm;
        if (norm.size() > normalizedRoot.size() &&
            norm[normalizedRoot.size()] == L'\\' &&
            _wcsnicmp(norm.c_str(), normalizedRoot.c_str(),
                normalizedRoot.size()) == 0) {
            return norm;
        }
    }

    // Strip drive letter (e.g. "C:")
    std::wstring rel = norm;
    if (rel.size() >= 2 && rel[1] == L':')
        rel = rel.substr(2);  // → \Users\foo\Downloads

    // Ensure leading backslash
    if (rel.empty() || rel[0] != L'\\')
        rel = L'\\' + rel;

    return boxRoot + L"\\drive" + rel;
}

// ============================================================
//  jsonGetField  —  minimal JSON string field extractor
//  Returns raw UTF-8 value. Caller converts to wide as needed.
//  Handles simple flat JSON: {"key":"value","key2":"val2"}
//  Supports \\-escaped backslashes (path values).
// ============================================================
std::string SandboxExplorer::jsonGetField(const std::string& json,
                                           const std::string& key)
{
    std::string search = "\"" + key + "\":\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return {};
    pos += search.size();

    std::string val;
    bool escaped = false;
    for (size_t i = pos; i < json.size(); ++i) {
        char c = json[i];
        if (escaped) {
            if      (c == '\\') val += '\\';
            else if (c == '"')  val += '"';
            else if (c == 'n')  val += '\n';
            else if (c == 't')  val += '\t';
            else                val += c;
            escaped = false;
        } else if (c == '\\') {
            escaped = true;
        } else if (c == '"') {
            break;
        } else {
            val += c;
        }
    }
    return val;   // raw UTF-8; caller converts to wide as needed
}

// Helper: UTF-8 std::string -> std::wstring
static std::wstring utf8ToWide(const std::string& s)
{
    if (s.empty()) return {};
    int wLen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (wLen <= 0) return {};
    std::wstring w(wLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), wLen);
    // MultiByteToWideChar with -1 includes the null terminator in the count
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

// ============================================================
//  defaultDllPath — SandboxBorder.dll next to the host EXE
// ============================================================
std::wstring SandboxExplorer::defaultDllPath()
{
    wchar_t exeBuf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exeBuf, MAX_PATH);
    fs::path p(exeBuf);
    fs::path dll = p.parent_path() / L"SandboxBorder.dll";
    if (fs::exists(dll))
        return dll.wstring();
    return {};
}
