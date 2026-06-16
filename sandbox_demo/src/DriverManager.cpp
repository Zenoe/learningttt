// ============================================================
//  DriverManager.cpp
// ============================================================
#include "DriverManager.h"
#include <filesystem>
#include <sstream>
#include <cassert>

namespace fs = std::filesystem;

// ------------------------------------------------------------
DriverManager::DriverManager(LogFn log) : m_log(std::move(log)) {}

DriverManager::~DriverManager()
{
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
    }
}

// ============================================================
//  install()
//  Copies the .sys binary to System32\drivers and creates a
//  SERVICE_KERNEL_DRIVER / FILE_SYSTEM_DRIVER service entry
//  via SCM.  This is equivalent to what the .INF does, but
//  done programmatically so the Qt app can do it in one click.
// ============================================================
bool DriverManager::install(const std::wstring& sysPath)
{
    if (!isElevated()) {
        log(L"[Driver] install() requires Administrator privileges.");
        return false;
    }

    // 1. Copy .sys to %SystemRoot%\System32\drivers
    wchar_t winDir[MAX_PATH] = {};
    GetWindowsDirectoryW(winDir, MAX_PATH);
    std::wstring destPath = std::wstring(winDir) +
        L"\\System32\\drivers\\SandboxFlt.sys";

    if (!CopyFileW(sysPath.c_str(), destPath.c_str(), FALSE)) {
        DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND) {
            // If already exists (re-install), overwrite
            if (!CopyFileW(sysPath.c_str(), destPath.c_str(), FALSE)) {
                log(L"[Driver] CopyFile failed: " + std::to_wstring(GetLastError()));
                return false;
            }
        }
        else {
            log(L"[Driver] Source .sys not found: " + sysPath);
            return false;
        }
    }
    log(L"[Driver] Copied to " + destPath);

    // 2. Open SCM
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        log(L"[Driver] OpenSCManager failed: " + std::to_wstring(GetLastError()));
        return false;
    }

    // 3. Create (or open) the service
    SC_HANDLE hSvc = CreateServiceW(
        hScm,
        kServiceName,                       // service name
        L"SandboxFlt Filesystem Filter",    // display name
        SERVICE_ALL_ACCESS,
        SERVICE_FILE_SYSTEM_DRIVER,         // type — minifilter
        SERVICE_DEMAND_START,               // start type
        SERVICE_ERROR_NORMAL,
        kDriverPath,                        // binary path in kernel format
        L"FSFilter Activity Monitor",       // load order group (minifilters)
        nullptr, nullptr, nullptr, nullptr);

    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            log(L"[Driver] Service already registered — OK.");
            hSvc = OpenServiceW(hScm, kServiceName, SERVICE_ALL_ACCESS);
        }
        else {
            log(L"[Driver] CreateService failed: " + std::to_wstring(err));
            CloseServiceHandle(hScm);
            return false;
        }
    }
    else {
        log(L"[Driver] Service registered successfully.");
    }

    // 4. Set the Altitude registry value (required for minifilters)
    //    HKLM\SYSTEM\CurrentControlSet\Services\SandboxFlt\Instances
    {
        HKEY hKey = nullptr;
        std::wstring regPath =
            L"SYSTEM\\CurrentControlSet\\Services\\SandboxFlt\\Instances";
        RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(),
            0, nullptr, REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
            nullptr, &hKey, nullptr);
        if (hKey) {
            const wchar_t* defInst = L"SandboxFlt Instance";
            RegSetValueExW(hKey, L"DefaultInstance", 0, REG_SZ,
                (BYTE*)defInst,
                (DWORD)((wcslen(defInst) + 1) * sizeof(wchar_t)));
            RegCloseKey(hKey);
        }
        std::wstring instPath = regPath + L"\\SandboxFlt Instance";
        RegCreateKeyExW(HKEY_LOCAL_MACHINE, instPath.c_str(),
            0, nullptr, REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE, nullptr, &hKey, nullptr);
        if (hKey) {
            const wchar_t* alt = L"370030";
            RegSetValueExW(hKey, L"Altitude", 0, REG_SZ,
                (BYTE*)alt,
                (DWORD)((wcslen(alt) + 1) * sizeof(wchar_t)));
            DWORD flags = 0;
            RegSetValueExW(hKey, L"Flags", 0, REG_DWORD,
                (BYTE*)&flags, sizeof(flags));
            RegCloseKey(hKey);
        }
    }
    log(L"[Driver] Altitude registry set to 370030.");

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return true;
}

// ============================================================
//  load() — StartService to load the kernel driver
// ============================================================
bool DriverManager::load()
{
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        log(L"[Driver] OpenSCManager failed: " + std::to_wstring(GetLastError()));
        return false;
    }

    SC_HANDLE hSvc = OpenServiceW(hScm, kServiceName, SERVICE_ALL_ACCESS);
    if (!hSvc) {
        log(L"[Driver] OpenService failed: " + std::to_wstring(GetLastError()));
        CloseServiceHandle(hScm);
        return false;
    }

    BOOL ok = StartServiceW(hSvc, 0, nullptr);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            log(L"[Driver] Driver already running — OK.");
            ok = TRUE;
        }
        else {
            log(L"[Driver] StartService failed: " + std::to_wstring(err));
        }
    }
    else {
        log(L"[Driver] Driver loaded (StartService succeeded).");
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return ok == TRUE;
}

// ============================================================
//  open() — open the control device for IOCTL
// ============================================================
bool DriverManager::open()
{
    m_hDevice = CreateFileW(
        SANDBOX_WIN32_DEVICE,
        GENERIC_READ | GENERIC_WRITE,
        0,              // no sharing
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (m_hDevice == INVALID_HANDLE_VALUE) {
        log(L"[Driver] CreateFile(" + std::wstring(SANDBOX_WIN32_DEVICE) +
            L") failed: " + std::to_wstring(GetLastError()));
        return false;
    }
    log(L"[Driver] Control device opened.");
    return true;
}

// ============================================================
//  unload() — stop (and optionally uninstall) the driver
// ============================================================
bool DriverManager::unload(bool doUninstall)
{
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
    }

    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hScm) return false;

    SC_HANDLE hSvc = OpenServiceW(hScm, kServiceName, SERVICE_ALL_ACCESS);
    if (!hSvc) {
        CloseServiceHandle(hScm);
        return false;
    }

    SERVICE_STATUS ss{};
    ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
    Sleep(500);  // give the driver a moment to unload
    log(L"[Driver] Stop signal sent.");

    if (doUninstall) {
        DeleteService(hSvc);
        log(L"[Driver] Service deleted.");
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return true;
}

// ============================================================
//  isInstalled()
// ============================================================
bool DriverManager::isInstalled() const
{
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) return false;
    SC_HANDLE hSvc = OpenServiceW(hScm, kServiceName, SERVICE_QUERY_STATUS);
    bool exists = (hSvc != nullptr);
    if (hSvc) CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return exists;
}

// ============================================================
//  addBox()
// ============================================================
bool DriverManager::addBox(const std::wstring& boxName,
    const std::wstring& sandboxRootRelative,
    const std::wstring& realRoot)
{
    SANDBOX_BOX_INFO info{};
    wcsncpy_s(info.BoxName, boxName.c_str(), SANDBOX_MAX_BOX - 1);
    wcsncpy_s(info.SandboxRootNt, sandboxRootRelative.c_str(), SANDBOX_MAX_PATH - 1);
    wcsncpy_s(info.RealRootNt, realRoot.c_str(), SANDBOX_MAX_PATH - 1);

    bool ok = sendIoctl(IOCTL_SANDBOX_ADD_BOX, &info, sizeof(info),
        nullptr, 0);
    if (!ok && GetLastError() == ERROR_ALREADY_EXISTS) {
        log(L"[Driver] addBox '" + boxName + L"' already exists; reusing it.");
        ok = true;
    }

    if (ok) log(L"[Driver] addBox '" + boxName + L"'  root=" + sandboxRootRelative);
    else    log(L"[Driver] addBox failed for '" + boxName + L"'");
    return ok;
}

bool DriverManager::removeBox(const std::wstring& boxName)
{
    SANDBOX_BOX_INFO info{};
    wcsncpy_s(info.BoxName, boxName.c_str(), SANDBOX_MAX_BOX - 1);
    bool ok = sendIoctl(IOCTL_SANDBOX_REMOVE_BOX, &info, sizeof(info),
        nullptr, 0);
    if (ok) log(L"[Driver] removeBox '" + boxName + L"'");
    // NOT_FOUND (1168) is expected if addBox failed — don't log as error
    return ok;
}

bool DriverManager::addProcess(DWORD pid, const std::wstring& boxName)
{
    SANDBOX_PROCESS_INFO info{};
    info.ProcessId = pid;
    wcsncpy_s(info.BoxName, boxName.c_str(), SANDBOX_MAX_BOX - 1);
    bool ok = sendIoctl(IOCTL_SANDBOX_ADD_PROCESS, &info, sizeof(info),
        nullptr, 0);
    if (!ok && GetLastError() == ERROR_ALREADY_EXISTS)
        ok = true;

    if (ok) log(L"[Driver] addProcess PID=" + std::to_wstring(pid) +
        L" → box='" + boxName + L"'");
    else    log(L"[Driver] addProcess failed PID=" + std::to_wstring(pid));
    return ok;
}

bool DriverManager::removeProcess(DWORD pid)
{
    SANDBOX_PROCESS_INFO info{};
    info.ProcessId = pid;
    bool ok = sendIoctl(IOCTL_SANDBOX_REMOVE_PROCESS, &info, sizeof(info),
        nullptr, 0);
    if (ok) log(L"[Driver] removeProcess PID=" + std::to_wstring(pid));
    // NOT_FOUND (1168) expected if addProcess was never called — don't log as error
    return ok;
}

bool DriverManager::queryStats(SANDBOX_STATS& out)
{
    DWORD bytes = 0;
    return sendIoctl(IOCTL_SANDBOX_QUERY_STATS,
        nullptr, 0,
        &out, sizeof(out),
        &bytes) && bytes >= sizeof(SANDBOX_STATS);
}

bool DriverManager::queryProcesses(SANDBOX_PROCESS_LIST& out)
{
    DWORD bytes = 0;
    return sendIoctl(IOCTL_SANDBOX_QUERY_PROCESSES,
        nullptr, 0,
        &out, sizeof(out),
        &bytes) && bytes >= sizeof(SANDBOX_PROCESS_LIST);
}

bool DriverManager::setPolicy(const std::wstring& boxName,
    SANDBOX_WRITE_POLICY policy,
    bool redirectReads,
    bool hideHostFiles)
{
    SANDBOX_POLICY_INFO info{};
    wcsncpy_s(info.BoxName, boxName.c_str(), SANDBOX_MAX_BOX - 1);
    info.WritePolicy = (ULONG)policy;
    info.RedirectReads = redirectReads ? 1UL : 0UL;
    info.HideHostFiles = hideHostFiles ? 1UL : 0UL;
    bool ok = sendIoctl(IOCTL_SANDBOX_SET_POLICY, &info, sizeof(info),
        nullptr, 0);
    if (ok) log(L"[Driver] setPolicy box='" + boxName + L"' policy=" +
        std::to_wstring((int)policy));
    return ok;
}

// ============================================================
//  sendIoctl() — thin wrapper around DeviceIoControl
// ============================================================
bool DriverManager::sendIoctl(DWORD code,
    void* inBuf, DWORD inLen,
    void* outBuf, DWORD outLen,
    DWORD* bytesReturned)
{
    if (m_hDevice == INVALID_HANDLE_VALUE) {
        log(L"[Driver] sendIoctl: device not open.");
        return false;
    }
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(m_hDevice, code,
        inBuf, inLen,
        outBuf, outLen,
        &bytes, nullptr);
    if (bytesReturned) *bytesReturned = bytes;
    if (!ok) {
        DWORD err = GetLastError();
        // Suppress ERROR_NOT_FOUND (1168) on remove operations — expected
        // when addBox/addProcess was never called (e.g. driver addBox failed).
        bool isRemove = (code == IOCTL_SANDBOX_REMOVE_BOX ||
            code == IOCTL_SANDBOX_REMOVE_PROCESS);
        bool isExistingBox = (code == IOCTL_SANDBOX_ADD_BOX &&
            err == ERROR_ALREADY_EXISTS);
        bool isExistingPid = (code == IOCTL_SANDBOX_ADD_PROCESS &&
            err == ERROR_ALREADY_EXISTS);
        if (!(isRemove && err == ERROR_NOT_FOUND) && !isExistingBox) {
            if (isExistingPid)
                return ok == TRUE;
            log(L"[Driver] DeviceIoControl 0x" +
                [code] { std::wostringstream s; s << std::hex << code; return s.str(); }() +
                L" failed: " + std::to_wstring(err));
        }
    }
    return ok == TRUE;
}

// ============================================================
//  Helpers
// ============================================================
std::wstring DriverManager::defaultSysPath()
{
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    fs::path p(buf);
    return (p.parent_path() / L"SandboxFlt.sys").wstring();
}

bool DriverManager::isElevated()
{
    BOOL elevated = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te{};
        DWORD len = 0;
        if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &len))
            elevated = te.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated == TRUE;
}

void DriverManager::log(const std::wstring& msg)
{
    if (m_log) m_log(msg);
}
