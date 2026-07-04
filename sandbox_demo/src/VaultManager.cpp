#include "VaultManager.h"
#include <virtdisk.h>
#include <cstdlib>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <vector>

#pragma comment(lib, "virtdisk.lib")

namespace fs = std::filesystem;

static constexpr GUID kVirtualStorageVendorMicrosoft = {
    0xEC984AEC,
    0xA0F9,
    0x47E9,
    { 0x90, 0x1F, 0x71, 0x41, 0x5A, 0x66, 0x34, 0x5B }
};

static std::wstring trimTrailingSlash(std::wstring path)
{
    while (path.size() > 3 && (path.back() == L'\\' || path.back() == L'/'))
        path.pop_back();
    return path;
}

static std::wstring withTrailingSlash(std::wstring path)
{
    if (!path.empty() && path.back() != L'\\' && path.back() != L'/')
        path.push_back(L'\\');
    return path;
}

static std::wstring quoteDiskpartPath(const std::wstring& path)
{
    std::wstring out;
    out.reserve(path.size() + 2);
    out.push_back(L'"');
    out += path;
    out.push_back(L'"');
    return out;
}

static std::wstring wideFromAcp(const std::string& text)
{
    if (text.empty())
        return {};

    int needed = MultiByteToWideChar(CP_ACP, 0, text.data(),
                                     static_cast<int>(text.size()),
                                     nullptr, 0);
    if (needed <= 0)
        return {};

    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_ACP, 0, text.data(),
                        static_cast<int>(text.size()),
                        out.data(), needed);
    return out;
}

static std::wstring sanitizeDiskLabel(std::wstring label)
{
    static const wchar_t* invalid = L"\\/:*?\"<>|.,;+=[]";
    for (wchar_t& ch : label) {
        if (wcschr(invalid, ch))
            ch = L'_';
    }
    if (label.empty())
        label = L"SandboxBox";
    if (label.size() > 32)
        label.resize(32);
    return label;
}

VaultManager::VaultManager(LogCallback log)
    : m_log(std::move(log))
{
}

VaultManager::~VaultManager()
{
    unmountAll();
}

std::wstring VaultManager::defaultBaseDir()
{
    return L"C:\\SandboxBoxes";
}

std::optional<VaultBoxMount> VaultManager::mountBox(
    const std::wstring& baseDir,
    const std::wstring& boxName)
{
    if (boxName.empty()) {
        log(L"[Vault] mountBox requires a box name.");
        return std::nullopt;
    }

    auto existing = m_mounted.find(boxName);
    if (existing != m_mounted.end())
        return existing->second.info;

    const fs::path base = trimTrailingSlash(
        baseDir.empty() ? defaultBaseDir() : baseDir);
    const fs::path vaultPath = base / (boxName + L".vault");
    const fs::path mountPoint = base / L".mounts" / boxName;

    std::error_code ec;
    fs::create_directories(base, ec);
    fs::create_directories(mountPoint, ec);
    if (ec) {
        log(L"[Vault] Failed to create vault directories: " +
            std::to_wstring(ec.value()));
        return std::nullopt;
    }

    const bool freshVault = !fs::exists(vaultPath, ec);
    if (freshVault && !createVaultFile(vaultPath.wstring()))
        return std::nullopt;

    HANDLE handle = nullptr;
    if (!openAndAttach(vaultPath.wstring(), handle))
        return std::nullopt;

    if (!prepareMountedVolume(handle,
                              mountPoint.wstring(),
                              boxName,
                              freshVault)) {
        DetachVirtualDisk(handle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
        CloseHandle(handle);
        return std::nullopt;
    }

    std::wstring ntVolume = queryMountedVolumeDevice(mountPoint.wstring());
    if (ntVolume.empty()) {
        log(L"[Vault] Could not resolve mounted VHD volume device path.");
        DetachVirtualDisk(handle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
        CloseHandle(handle);
        return std::nullopt;
    }

    VaultBoxMount info;
    info.boxName = boxName;
    info.vaultPath = vaultPath.wstring();
    info.mountPoint = mountPoint.wstring();
    info.driverRootNt = ntVolume + L"\\drive";

    MountedVault mounted;
    mounted.info = info;
    mounted.handle = handle;
    m_mounted.emplace(boxName, std::move(mounted));

    log(L"[Vault] Mounted " + info.vaultPath + L" -> " +
        info.mountPoint + L"  driverRoot=" + info.driverRootNt);
    return info;
}

bool VaultManager::unmountBox(const std::wstring& boxName)
{
    auto it = m_mounted.find(boxName);
    if (it == m_mounted.end())
        return true;

    const std::wstring vaultPath = it->second.info.vaultPath;
    const std::wstring mountPoint = it->second.info.mountPoint;
    bool ok = true;

    if (it->second.handle) {
        DWORD err = DetachVirtualDisk(it->second.handle,
                                      DETACH_VIRTUAL_DISK_FLAG_NONE,
                                      0);
        if (err != ERROR_SUCCESS) {
            log(L"[Vault] DetachVirtualDisk failed for " + vaultPath +
                L": " + std::to_wstring(err));
            ok = false;
        }
        CloseHandle(it->second.handle);
        it->second.handle = nullptr;
    }

    std::error_code ec;
    fs::remove(mountPoint, ec);
    m_mounted.erase(it);

    if (ok)
        log(L"[Vault] Unmounted and locked " + vaultPath);
    return ok;
}

void VaultManager::unmountAll()
{
    std::vector<std::wstring> boxes;
    boxes.reserve(m_mounted.size());
    for (const auto& pair : m_mounted)
        boxes.push_back(pair.first);
    for (const auto& box : boxes)
        unmountBox(box);
}

bool VaultManager::isMounted(const std::wstring& boxName) const
{
    return m_mounted.find(boxName) != m_mounted.end();
}

std::wstring VaultManager::mountPoint(const std::wstring& boxName) const
{
    auto it = m_mounted.find(boxName);
    return it == m_mounted.end() ? std::wstring() : it->second.info.mountPoint;
}

std::wstring VaultManager::driverRootNt(const std::wstring& boxName) const
{
    auto it = m_mounted.find(boxName);
    return it == m_mounted.end() ? std::wstring() : it->second.info.driverRootNt;
}

bool VaultManager::createVaultFile(const std::wstring& vaultPath)
{
    VIRTUAL_STORAGE_TYPE storage{};
    storage.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
    storage.VendorId = kVirtualStorageVendorMicrosoft;

    CREATE_VIRTUAL_DISK_PARAMETERS params{};
    params.Version = CREATE_VIRTUAL_DISK_VERSION_2;
    params.Version2.MaximumSize = 2ull * 1024ull * 1024ull * 1024ull;

    HANDLE handle = nullptr;
    DWORD err = CreateVirtualDisk(&storage,
                                  vaultPath.c_str(),
                                  VIRTUAL_DISK_ACCESS_NONE,
                                  nullptr,
                                  CREATE_VIRTUAL_DISK_FLAG_NONE,
                                  0,
                                  &params,
                                  nullptr,
                                  &handle);
    if (err != ERROR_SUCCESS) {
        log(L"[Vault] CreateVirtualDisk failed for " + vaultPath +
            L": " + std::to_wstring(err));
        return false;
    }

    CloseHandle(handle);
    log(L"[Vault] Created VHDX vault: " + vaultPath);
    return true;
}

bool VaultManager::openAndAttach(const std::wstring& vaultPath, HANDLE& handle)
{
    handle = nullptr;

    VIRTUAL_STORAGE_TYPE storage{};
    storage.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
    storage.VendorId = kVirtualStorageVendorMicrosoft;

    OPEN_VIRTUAL_DISK_PARAMETERS openParams{};
    openParams.Version = OPEN_VIRTUAL_DISK_VERSION_1;
    openParams.Version1.RWDepth = OPEN_VIRTUAL_DISK_RW_DEPTH_DEFAULT;

    DWORD err = OpenVirtualDisk(&storage,
                                vaultPath.c_str(),
                                VIRTUAL_DISK_ACCESS_ATTACH_RW |
                                    VIRTUAL_DISK_ACCESS_DETACH |
                                    VIRTUAL_DISK_ACCESS_GET_INFO,
                                OPEN_VIRTUAL_DISK_FLAG_NONE,
                                &openParams,
                                &handle);
    if (err != ERROR_SUCCESS) {
        log(L"[Vault] OpenVirtualDisk failed for " + vaultPath +
            L": " + std::to_wstring(err));
        return false;
    }

    ATTACH_VIRTUAL_DISK_PARAMETERS attachParams{};
    attachParams.Version = ATTACH_VIRTUAL_DISK_VERSION_1;

    err = AttachVirtualDisk(handle,
                            nullptr,
                            ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER,
                            0,
                            &attachParams,
                            nullptr);
    if (err != ERROR_SUCCESS && err != ERROR_ALREADY_EXISTS) {
        log(L"[Vault] AttachVirtualDisk failed for " + vaultPath +
            L": " + std::to_wstring(err));
        CloseHandle(handle);
        handle = nullptr;
        return false;
    }

    return true;
}

bool VaultManager::getAttachedDiskNumber(HANDLE handle, ULONG& diskNumber)
{
    diskNumber = 0;

    ULONG chars = 0;
    DWORD err = GetVirtualDiskPhysicalPath(handle, &chars, nullptr);
    if (err != ERROR_INSUFFICIENT_BUFFER || chars == 0) {
        log(L"[Vault] GetVirtualDiskPhysicalPath(size) failed: " +
            std::to_wstring(err));
        return false;
    }

    std::wstring physicalPath(chars, L'\0');
    err = GetVirtualDiskPhysicalPath(handle, &chars, physicalPath.data());
    if (err != ERROR_SUCCESS) {
        log(L"[Vault] GetVirtualDiskPhysicalPath failed: " +
            std::to_wstring(err));
        return false;
    }
    while (!physicalPath.empty() && physicalPath.back() == L'\0')
        physicalPath.pop_back();

    static const wchar_t prefix[] = L"\\\\.\\PhysicalDrive";
    if (physicalPath.rfind(prefix, 0) != 0) {
        log(L"[Vault] Unexpected VHD physical path: " + physicalPath);
        return false;
    }

    wchar_t* end = nullptr;
    unsigned long parsed = wcstoul(physicalPath.c_str() + wcslen(prefix),
                                   &end,
                                   10);
    if (!end || *end != L'\0') {
        log(L"[Vault] Could not parse VHD disk number: " + physicalPath);
        return false;
    }

    diskNumber = static_cast<ULONG>(parsed);
    log(L"[Vault] Attached as " + physicalPath);
    return true;
}

bool VaultManager::prepareMountedVolume(HANDLE handle,
                                        const std::wstring& mountPoint,
                                        const std::wstring& boxName,
                                        bool freshVault)
{
    ULONG diskNumber = 0;
    if (!getAttachedDiskNumber(handle, diskNumber))
        return false;

    auto buildScript = [&](bool initialize) {
        std::wstring script;
        script += L"select disk " + std::to_wstring(diskNumber) + L"\r\n";
        script += L"attributes disk clear readonly noerr\r\n";
        script += L"online disk noerr\r\n";
        if (initialize) {
            script += L"create partition primary\r\n";
            script += L"format fs=ntfs quick label=" +
                      quoteDiskpartPath(sanitizeDiskLabel(boxName)) + L"\r\n";
        }
        else {
            script += L"select partition 1\r\n";
        }
        script += L"assign mount=" +
                  quoteDiskpartPath(trimTrailingSlash(mountPoint)) + L"\r\n";
        script += L"exit\r\n";
        return script;
    };

    bool ok = runDiskpartScript(buildScript(freshVault));
    if (!ok && !freshVault) {
        log(L"[Vault] Existing vault did not mount; trying one-time partition initialization.");
        ok = runDiskpartScript(buildScript(true));
    }

    return ok;
}

bool VaultManager::runDiskpartScript(const std::wstring& script)
{
    wchar_t tempDir[MAX_PATH]{};
    wchar_t tempFile[MAX_PATH]{};
    wchar_t tempOutput[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH, tempDir) ||
        !GetTempFileNameW(tempDir, L"sbv", 0, tempFile) ||
        !GetTempFileNameW(tempDir, L"sbo", 0, tempOutput)) {
        log(L"[Vault] Could not create a temporary diskpart script.");
        return false;
    }

    {
        std::wofstream out(tempFile, std::ios::binary | std::ios::trunc);
        if (!out) {
            DeleteFileW(tempFile);
            DeleteFileW(tempOutput);
            log(L"[Vault] Could not write diskpart script.");
            return false;
        }
        out << script;
    }

    std::wstring command = L"\"";
    wchar_t systemDir[MAX_PATH]{};
    if (GetSystemDirectoryW(systemDir, MAX_PATH))
        command += std::wstring(systemDir) + L"\\diskpart.exe";
    else
        command += L"diskpart.exe";
    command += L"\" /s \"" + std::wstring(tempFile) + L"\"";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE outFile = CreateFileW(tempOutput,
                                 GENERIC_WRITE,
                                 FILE_SHARE_READ,
                                 &sa,
                                 CREATE_ALWAYS,
                                 FILE_ATTRIBUTE_TEMPORARY,
                                 nullptr);
    HANDLE nullIn = CreateFileW(L"NUL",
                                GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                &sa,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,
                                nullptr);
    si.hStdOutput = outFile != INVALID_HANDLE_VALUE ? outFile : GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = si.hStdOutput;
    si.hStdInput = nullIn != INVALID_HANDLE_VALUE ? nullIn : GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(nullptr,
                             command.data(),
                             nullptr,
                             nullptr,
                             TRUE,
                             CREATE_NO_WINDOW,
                             nullptr,
                             nullptr,
                             &si,
                             &pi);
    if (!ok) {
        DWORD err = GetLastError();
        if (outFile != INVALID_HANDLE_VALUE)
            CloseHandle(outFile);
        if (nullIn != INVALID_HANDLE_VALUE)
            CloseHandle(nullIn);
        DeleteFileW(tempFile);
        DeleteFileW(tempOutput);
        log(L"[Vault] Failed to start diskpart: " + std::to_wstring(err));
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (outFile != INVALID_HANDLE_VALUE)
        CloseHandle(outFile);
    if (nullIn != INVALID_HANDLE_VALUE)
        CloseHandle(nullIn);
    DeleteFileW(tempFile);

    if (exitCode != 0) {
        log(L"[Vault] diskpart failed with exit code " +
            std::to_wstring(exitCode));
        std::ifstream diskpartOutput(tempOutput, std::ios::binary);
        if (diskpartOutput) {
            std::string text((std::istreambuf_iterator<char>(diskpartOutput)),
                             std::istreambuf_iterator<char>());
            std::wstring output = wideFromAcp(text);
            if (!output.empty())
                log(L"[Vault][diskpart] " + output);
        }
        DeleteFileW(tempOutput);
        return false;
    }
    DeleteFileW(tempOutput);
    return true;
}

std::wstring VaultManager::queryMountedVolumeDevice(
    const std::wstring& mountPoint)
{
    wchar_t volumeName[MAX_PATH]{};
    std::wstring mount = withTrailingSlash(mountPoint);
    if (!GetVolumeNameForVolumeMountPointW(mount.c_str(),
                                           volumeName,
                                           MAX_PATH)) {
        log(L"[Vault] GetVolumeNameForVolumeMountPoint failed: " +
            std::to_wstring(GetLastError()));
        return {};
    }

    std::wstring dosName = volumeName;
    if (dosName.rfind(L"\\\\?\\", 0) == 0)
        dosName.erase(0, 4);
    if (!dosName.empty() && dosName.back() == L'\\')
        dosName.pop_back();

    wchar_t target[1024]{};
    DWORD chars = QueryDosDeviceW(dosName.c_str(), target, 1024);
    if (chars == 0) {
        log(L"[Vault] QueryDosDevice failed for " + dosName +
            L": " + std::to_wstring(GetLastError()));
        return {};
    }

    return target;
}

void VaultManager::log(const std::wstring& msg)
{
    if (m_log)
        m_log(msg);
}
