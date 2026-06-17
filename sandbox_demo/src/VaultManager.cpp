#include "VaultManager.h"

#include <bcrypt.h>
#include <virtdisk.h>
#include <winioctl.h>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

static constexpr uint64_t kMiB = 1024ull * 1024ull;

static const GUID kVaultSaltMetadataGuid = {
    0x8e1781d1, 0x8f67, 0x4988,
    { 0x9a, 0x3c, 0x73, 0xce, 0x5f, 0x7a, 0x6c, 0x11 }
};

static const GUID kVirtualStorageVendorMicrosoft = {
    0xec984aec, 0xa0f9, 0x47e9,
    { 0x90, 0x1f, 0x71, 0x41, 0x5a, 0x66, 0x34, 0x5b }
};

static bool vaultFileExistsNonEmpty(const std::wstring& path)
{
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data))
        return false;
    if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        return false;

    ULARGE_INTEGER size{};
    size.HighPart = data.nFileSizeHigh;
    size.LowPart = data.nFileSizeLow;
    return size.QuadPart != 0;
}

static std::wstring withTrailingBackslash(std::wstring path)
{
    if (!path.empty() && path.back() != L'\\' && path.back() != L'/')
        path.push_back(L'\\');
    return path;
}

static bool prepareMountPointDirectory(const std::wstring& mountPoint,
                                       LogCallback log)
{
    std::error_code ec;
    fs::path mountPath(mountPoint);
    fs::path parent = mountPath.parent_path();
    if (!parent.empty()) {
        fs::create_directories(parent, ec);
        if (ec) {
            if (log) {
                log(L"[Vault] cannot create mount parent " +
                    parent.wstring() + L": " + std::to_wstring(ec.value()));
            }
            return false;
        }
    }

    DWORD attrs = GetFileAttributesW(mountPoint.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            if (log)
                log(L"[Vault] mount point path exists but is not a directory.");
            return false;
        }

        if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
            std::wstring volumeMountPoint = withTrailingBackslash(mountPoint);
            if (DeleteVolumeMountPointW(volumeMountPoint.c_str())) {
                if (log)
                    log(L"[Vault] removed stale mount point " + mountPoint);
            }
            else {
                DWORD err = GetLastError();
                if (err != ERROR_INVALID_PARAMETER &&
                    err != ERROR_PATH_NOT_FOUND &&
                    err != ERROR_FILE_NOT_FOUND) {
                    if (log) {
                        log(L"[Vault] DeleteVolumeMountPoint failed for " +
                            mountPoint + L": " + std::to_wstring(err));
                    }
                    return false;
                }
            }
        }
    }

    fs::create_directories(mountPath, ec);
    if (ec) {
        if (log) {
            log(L"[Vault] cannot create mount point " + mountPoint +
                L": " + std::to_wstring(ec.value()));
        }
        return false;
    }

    return true;
}

static HANDLE openVolumeForExtents(const std::wstring& volumeName)
{
    std::wstring openName = volumeName;
    if (!openName.empty() &&
        (openName.back() == L'\\' || openName.back() == L'/')) {
        openName.pop_back();
    }

    return CreateFileW(openName.c_str(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
}

static bool volumeBelongsToDisk(const std::wstring& volumeName,
                                unsigned long diskNumber)
{
    HANDLE volume = openVolumeForExtents(volumeName);
    if (volume == INVALID_HANDLE_VALUE)
        return false;

    std::vector<BYTE> buffer(sizeof(VOLUME_DISK_EXTENTS) +
        sizeof(DISK_EXTENT) * 15);
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(volume,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        nullptr,
        0,
        buffer.data(),
        static_cast<DWORD>(buffer.size()),
        &bytesReturned,
        nullptr);
    CloseHandle(volume);

    if (!ok)
        return false;

    auto* extents = reinterpret_cast<VOLUME_DISK_EXTENTS*>(buffer.data());
    for (DWORD i = 0; i < extents->NumberOfDiskExtents; ++i) {
        if (extents->Extents[i].DiskNumber == diskNumber)
            return true;
    }

    return false;
}

static bool findVolumeForDisk(unsigned long diskNumber,
                              std::wstring& outVolumeName,
                              LogCallback log)
{
    wchar_t volumeName[MAX_PATH]{};
    HANDLE find = FindFirstVolumeW(volumeName, ARRAYSIZE(volumeName));
    if (find == INVALID_HANDLE_VALUE) {
        if (log) {
            log(L"[Vault] FindFirstVolume failed: " +
                std::to_wstring(GetLastError()));
        }
        return false;
    }

    bool found = false;
    do {
        std::wstring candidate(volumeName);
        if (volumeBelongsToDisk(candidate, diskNumber)) {
            outVolumeName = candidate;
            found = true;
            break;
        }
    } while (FindNextVolumeW(find, volumeName, ARRAYSIZE(volumeName)));

    DWORD err = GetLastError();
    FindVolumeClose(find);

    if (!found && err != ERROR_NO_MORE_FILES && log) {
        log(L"[Vault] FindNextVolume failed: " + std::to_wstring(err));
    }

    return found;
}

VaultManager::~VaultManager()
{
    for (auto& item : m_attachedVaults) {
        if (item.second && item.second != INVALID_HANDLE_VALUE) {
            DetachVirtualDisk(item.second, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
            CloseHandle(item.second);
        }
    }
    m_attachedVaults.clear();
}

std::wstring VaultManager::createAndMount(const VaultConfig& cfg, LogCallback log)
{
    if (vaultFileExistsNonEmpty(cfg.vaultFilePath)) {
        return mount(cfg, log);
    }

    if (!createVhdx(cfg, log))
        return {};

    std::wstring physicalDrive;
    if (!attachVhdx(cfg.vaultFilePath, physicalDrive, log))
        return {};

    if (!formatAttachedDisk(physicalDrive, cfg.mountPoint, log)) {
        detachVhdx(cfg.vaultFilePath, log);
        return {};
    }

    logLine(log, L"[Vault] created and mounted at " + cfg.mountPoint);
    return cfg.mountPoint;
}

std::wstring VaultManager::mount(const VaultConfig& cfg, LogCallback log)
{
    std::wstring physicalDrive;
    if (!attachVhdx(cfg.vaultFilePath, physicalDrive, log))
        return {};

    if (!assignMountPoint(physicalDrive, cfg.mountPoint, log)) {
        detachVhdx(cfg.vaultFilePath, log);
        return {};
    }

    logLine(log, L"[Vault] mounted at " + cfg.mountPoint);
    return cfg.mountPoint;
}

bool VaultManager::unmount(const std::wstring& vaultFilePath, LogCallback log)
{
    return detachVhdx(vaultFilePath, log);
}

bool VaultManager::isMounted(const std::wstring& vaultFilePath) const
{
    return m_attachedVaults.find(normalizePath(vaultFilePath)) != m_attachedVaults.end();
}

bool VaultManager::loadOrCreateSalt(const std::wstring& vaultFilePath,
                                    std::array<uint8_t, 32>& salt,
                                    LogCallback log)
{
    std::error_code ec;
    fs::path vaultPath(vaultFilePath);
    if (fs::exists(vaultPath, ec) && fs::file_size(vaultPath, ec) == 0) {
        fs::remove(vaultPath, ec);
        logLine(log, L"[Vault] removed empty stale vault file.");
    }

    if (vaultFileExistsNonEmpty(vaultFilePath)) {
        DWORD metadataErr = ERROR_SUCCESS;
        if (readSaltMetadata(vaultFilePath, salt, log, &metadataErr))
            return true;

        if (metadataErr != ERROR_NOT_FOUND &&
            metadataErr != ERROR_FILE_NOT_FOUND) {
            logLine(log, L"[Vault] refusing to overwrite existing vault salt.");
            return false;
        }

        logLine(log, L"[Vault] existing vault has no salt metadata; creating one.");
    }

    NTSTATUS status = BCryptGenRandom(nullptr,
        salt.data(),
        static_cast<ULONG>(salt.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0) {
        logLine(log, L"[Vault] BCryptGenRandom failed while creating salt.");
        return false;
    }

    if (vaultFileExistsNonEmpty(vaultFilePath)) {
        VIRTUAL_STORAGE_TYPE storageType{};
        storageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
        storageType.VendorId = kVirtualStorageVendorMicrosoft;

        OPEN_VIRTUAL_DISK_PARAMETERS openParams{};
        openParams.Version = OPEN_VIRTUAL_DISK_VERSION_1;

        HANDLE handle = INVALID_HANDLE_VALUE;
        DWORD err = OpenVirtualDisk(
            &storageType,
            vaultFilePath.c_str(),
            VIRTUAL_DISK_ACCESS_GET_INFO | VIRTUAL_DISK_ACCESS_METAOPS,
            OPEN_VIRTUAL_DISK_FLAG_NONE,
            &openParams,
            &handle);
        if (err != ERROR_SUCCESS) {
            logLine(log, L"[Vault] OpenVirtualDisk(meta) failed: " +
                std::to_wstring(err));
            return false;
        }

        bool ok = writeSaltMetadata(handle, salt, log);
        CloseHandle(handle);
        return ok;
    }

    return true;
}

bool VaultManager::createVhdx(const VaultConfig& cfg, LogCallback log)
{
    std::error_code ec;
    fs::path vaultPath(cfg.vaultFilePath);
    if (vaultPath.has_parent_path()) {
        fs::create_directories(vaultPath.parent_path(), ec);
        if (ec) {
            logLine(log, L"[Vault] cannot create vault directory " +
                vaultPath.parent_path().wstring() + L": " +
                std::to_wstring(ec.value()));
            return false;
        }
    }

    if (vaultFileExistsNonEmpty(cfg.vaultFilePath)) {
        logLine(log, L"[Vault] using existing vault file " + cfg.vaultFilePath);
        return true;
    }
    if (fs::exists(vaultPath, ec)) {
        SetFileAttributesW(vaultPath.wstring().c_str(), FILE_ATTRIBUTE_NORMAL);
        fs::remove(vaultPath, ec);
        if (ec || fs::exists(vaultPath)) {
            logLine(log, L"[Vault] cannot remove stale vault file " +
                vaultPath.wstring() + L": " + std::to_wstring(ec.value()));
            return false;
        }
    }

    fs::path createPath = vaultPath;
    createPath += L".vhdx";
    SetFileAttributesW(createPath.wstring().c_str(), FILE_ATTRIBUTE_NORMAL);
    fs::remove(createPath, ec);
    if (ec || fs::exists(createPath)) {
        logLine(log, L"[Vault] cannot remove stale temporary VHDX " +
            createPath.wstring() + L": " + std::to_wstring(ec.value()));
        return false;
    }
    std::wstring createPathText = createPath.wstring();

    VIRTUAL_STORAGE_TYPE storageType{};
    storageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
    storageType.VendorId = kVirtualStorageVendorMicrosoft;

    CREATE_VIRTUAL_DISK_PARAMETERS params{};
    params.Version = CREATE_VIRTUAL_DISK_VERSION_1;
    params.Version1.MaximumSize = cfg.sizeMB * kMiB;
    params.Version1.BlockSizeInBytes = CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_BLOCK_SIZE;
    params.Version1.SectorSizeInBytes = CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_SECTOR_SIZE;

    HANDLE handle = INVALID_HANDLE_VALUE;
    DWORD err = CreateVirtualDisk(
        &storageType,
        createPathText.c_str(),
        VIRTUAL_DISK_ACCESS_CREATE,
        nullptr,
        CREATE_VIRTUAL_DISK_FLAG_NONE,
        0,
        &params,
        nullptr,
        &handle);

    if (err != ERROR_SUCCESS) {
        logLine(log, L"[Vault] CreateVirtualDisk failed for " +
            createPathText + L": " + std::to_wstring(err));
        if (err == ERROR_ACCESS_DENIED) {
            logLine(log, L"[Vault] access denied: run SandboxDemo as Administrator "
                L"and ensure the vault directory is writable.");
        }
        fs::remove(createPath, ec);
        return false;
    }

    CloseHandle(handle);

    fs::rename(createPath, vaultPath, ec);
    if (ec) {
        logLine(log, L"[Vault] rename temporary VHDX failed: " +
            std::to_wstring(ec.value()));
        fs::remove(createPath, ec);
        return false;
    }

    OPEN_VIRTUAL_DISK_PARAMETERS openParams{};
    openParams.Version = OPEN_VIRTUAL_DISK_VERSION_1;
    err = OpenVirtualDisk(
        &storageType,
        cfg.vaultFilePath.c_str(),
        VIRTUAL_DISK_ACCESS_METAOPS,
        OPEN_VIRTUAL_DISK_FLAG_NONE,
        &openParams,
        &handle);
    if (err != ERROR_SUCCESS) {
        logLine(log, L"[Vault] OpenVirtualDisk(meta after create) failed: " +
            std::to_wstring(err));
        DeleteFileW(cfg.vaultFilePath.c_str());
        return false;
    }

    if (!writeSaltMetadata(handle, cfg.salt, log)) {
        CloseHandle(handle);
        DeleteFileW(cfg.vaultFilePath.c_str());
        return false;
    }

    CloseHandle(handle);
    logLine(log, L"[Vault] VHDX vault created: " + cfg.vaultFilePath);
    return true;
}

bool VaultManager::readSaltMetadata(const std::wstring& vaultFilePath,
                                    std::array<uint8_t, 32>& salt,
                                    LogCallback log,
                                    DWORD* outError) const
{
    if (outError)
        *outError = ERROR_SUCCESS;

    VIRTUAL_STORAGE_TYPE storageType{};
    storageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
    storageType.VendorId = kVirtualStorageVendorMicrosoft;

    OPEN_VIRTUAL_DISK_PARAMETERS openParams{};
    openParams.Version = OPEN_VIRTUAL_DISK_VERSION_1;

    HANDLE handle = INVALID_HANDLE_VALUE;
    DWORD err = OpenVirtualDisk(
        &storageType,
        vaultFilePath.c_str(),
        VIRTUAL_DISK_ACCESS_GET_INFO | VIRTUAL_DISK_ACCESS_METAOPS,
        OPEN_VIRTUAL_DISK_FLAG_NONE,
        &openParams,
        &handle);
    if (err != ERROR_SUCCESS) {
        if (outError)
            *outError = err;
        logLine(log, L"[Vault] OpenVirtualDisk(meta read) failed: " +
            std::to_wstring(err));
        return false;
    }

    ULONG metadataSize = static_cast<ULONG>(salt.size());
    err = GetVirtualDiskMetadata(handle,
        &kVaultSaltMetadataGuid,
        &metadataSize,
        salt.data());
    CloseHandle(handle);

    if (err != ERROR_SUCCESS || metadataSize != salt.size()) {
        if (outError)
            *outError = err;
        logLine(log, L"[Vault] GetVirtualDiskMetadata(salt) failed: " +
            std::to_wstring(err));
        return false;
    }

    logLine(log, L"[Vault] loaded salt from VHDX metadata.");
    return true;
}

bool VaultManager::writeSaltMetadata(HANDLE virtualDisk,
                                     const std::array<uint8_t, 32>& salt,
                                     LogCallback log) const
{
    DWORD err = SetVirtualDiskMetadata(virtualDisk,
        &kVaultSaltMetadataGuid,
        static_cast<ULONG>(salt.size()),
        salt.data());
    if (err != ERROR_SUCCESS) {
        logLine(log, L"[Vault] SetVirtualDiskMetadata(salt) failed: " +
            std::to_wstring(err));
        return false;
    }

    logLine(log, L"[Vault] stored salt in VHDX metadata.");
    return true;
}

bool VaultManager::attachVhdx(const std::wstring& vaultFilePath,
                              std::wstring& outPhysicalDrive,
                              LogCallback log)
{
    const std::wstring key = normalizePath(vaultFilePath);
    auto existing = m_attachedVaults.find(key);
    if (existing != m_attachedVaults.end()) {
        ULONG len = 0;
        DWORD err = GetVirtualDiskPhysicalPath(existing->second, &len, nullptr);
        if (err == ERROR_INSUFFICIENT_BUFFER && len > 1) {
            std::wstring path(len, L'\0');
            err = GetVirtualDiskPhysicalPath(existing->second, &len, path.data());
            if (err == ERROR_SUCCESS) {
                path.resize(wcsnlen(path.c_str(), path.size()));
                outPhysicalDrive = path;
                return true;
            }
        }
        return true;
    }

    VIRTUAL_STORAGE_TYPE storageType{};
    storageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
    storageType.VendorId = kVirtualStorageVendorMicrosoft;

    OPEN_VIRTUAL_DISK_PARAMETERS openParams{};
    openParams.Version = OPEN_VIRTUAL_DISK_VERSION_1;

    HANDLE handle = INVALID_HANDLE_VALUE;
    DWORD err = OpenVirtualDisk(
        &storageType,
        vaultFilePath.c_str(),
        VIRTUAL_DISK_ACCESS_ALL,
        OPEN_VIRTUAL_DISK_FLAG_NONE,
        &openParams,
        &handle);
    if (err != ERROR_SUCCESS) {
        logLine(log, L"[Vault] OpenVirtualDisk failed: " + std::to_wstring(err));
        return false;
    }

    ATTACH_VIRTUAL_DISK_PARAMETERS attachParams{};
    attachParams.Version = ATTACH_VIRTUAL_DISK_VERSION_1;

    err = AttachVirtualDisk(
        handle,
        nullptr,
        ATTACH_VIRTUAL_DISK_FLAG_NONE,
        0,
        &attachParams,
        nullptr);
    if (err != ERROR_SUCCESS && err != ERROR_SHARING_VIOLATION) {
        logLine(log, L"[Vault] AttachVirtualDisk failed: " + std::to_wstring(err));
        CloseHandle(handle);
        return false;
    }

    ULONG len = 0;
    for (int i = 0; i < 40; ++i) {
        err = GetVirtualDiskPhysicalPath(handle, &len, nullptr);
        if (err == ERROR_INSUFFICIENT_BUFFER && len > 1) {
            std::wstring path(len, L'\0');
            err = GetVirtualDiskPhysicalPath(handle, &len, path.data());
            if (err == ERROR_SUCCESS) {
                path.resize(wcsnlen(path.c_str(), path.size()));
                outPhysicalDrive = path;
                m_attachedVaults[key] = handle;
                logLine(log, L"[Vault] attached as " + outPhysicalDrive);
                return true;
            }
        }
        Sleep(100);
    }

    logLine(log, L"[Vault] attached but physical path was not ready.");
    DetachVirtualDisk(handle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
    CloseHandle(handle);
    return false;
}

bool VaultManager::detachVhdx(const std::wstring& vaultFilePath, LogCallback log)
{
    const std::wstring key = normalizePath(vaultFilePath);
    auto it = m_attachedVaults.find(key);
    if (it == m_attachedVaults.end())
        return true;

    DWORD err = DetachVirtualDisk(it->second, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
    CloseHandle(it->second);
    m_attachedVaults.erase(it);

    if (err != ERROR_SUCCESS) {
        logLine(log, L"[Vault] DetachVirtualDisk failed: " + std::to_wstring(err));
        return false;
    }

    logLine(log, L"[Vault] unmounted " + vaultFilePath);
    return true;
}

bool VaultManager::formatAttachedDisk(const std::wstring& physicalDrive,
                                      const std::wstring& mountPoint,
                                      LogCallback log)
{
    unsigned long diskNumber = 0;
    if (!parsePhysicalDriveNumber(physicalDrive, diskNumber)) {
        logLine(log, L"[Vault] cannot parse physical drive path: " + physicalDrive);
        return false;
    }

    if (!prepareMountPointDirectory(mountPoint, log))
        return false;

    std::wostringstream script;
    script << L"select disk " << diskNumber << L"\r\n"
           << L"online disk noerr\r\n"
           << L"attributes disk clear readonly noerr\r\n"
           << L"convert gpt noerr\r\n"
           << L"create partition primary\r\n"
           << L"format fs=ntfs quick label=\"SandboxVault\"\r\n";

    if (!runDiskPart(script.str(), log))
        return false;

    return assignMountPoint(physicalDrive, mountPoint, log);
}

bool VaultManager::assignMountPoint(const std::wstring& physicalDrive,
                                    const std::wstring& mountPoint,
                                    LogCallback log)
{
    unsigned long diskNumber = 0;
    if (!parsePhysicalDriveNumber(physicalDrive, diskNumber)) {
        logLine(log, L"[Vault] cannot parse physical drive path: " + physicalDrive);
        return false;
    }

    if (!prepareMountPointDirectory(mountPoint, log))
        return false;

    std::wstring volumeName;
    for (int i = 0; i < 50; ++i) {
        if (findVolumeForDisk(diskNumber, volumeName, log))
            break;
        Sleep(100);
    }
    if (volumeName.empty()) {
        logLine(log, L"[Vault] cannot find volume for " + physicalDrive);
        return false;
    }

    std::wstring mountPointName = withTrailingBackslash(mountPoint);
    if (!SetVolumeMountPointW(mountPointName.c_str(), volumeName.c_str())) {
        DWORD err = GetLastError();
        logLine(log, L"[Vault] SetVolumeMountPoint failed: " +
            std::to_wstring(err) + L" volume=" + volumeName +
            L" mount=" + mountPointName);
        return false;
    }

    logLine(log, L"[Vault] assigned mount point " + mountPointName +
        L" -> " + volumeName);
    return true;
}

std::wstring VaultManager::normalizePath(const std::wstring& path)
{
    wchar_t full[MAX_PATH]{};
    if (_wfullpath(full, path.c_str(), MAX_PATH) == nullptr)
        return path;

    std::wstring normalized(full);
    for (auto& ch : normalized)
        ch = static_cast<wchar_t>(towlower(ch));
    return normalized;
}

bool VaultManager::runDiskPart(const std::wstring& script, LogCallback log)
{
    wchar_t tempDir[MAX_PATH]{};
    wchar_t tempFile[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH, tempDir) ||
        !GetTempFileNameW(tempDir, L"sbox", 0, tempFile)) {
        logLine(log, L"[Vault] cannot create diskpart script file.");
        return false;
    }

    {
        std::wofstream out(tempFile, std::ios::binary | std::ios::trunc);
        if (!out) {
            DeleteFileW(tempFile);
            logLine(log, L"[Vault] cannot write diskpart script.");
            return false;
        }
        out << script;
    }

    std::wstring cmd = L"diskpart.exe /s \"" + std::wstring(tempFile) + L"\"";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessW(
        nullptr,
        cmd.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi);

    if (!ok) {
        DWORD err = GetLastError();
        DeleteFileW(tempFile);
        logLine(log, L"[Vault] diskpart launch failed: " + std::to_wstring(err));
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DeleteFileW(tempFile);

    if (exitCode != 0) {
        logLine(log, L"[Vault] diskpart failed: exit " + std::to_wstring(exitCode));
        return false;
    }

    return true;
}

bool VaultManager::parsePhysicalDriveNumber(const std::wstring& physicalDrive,
                                            unsigned long& outDiskNumber)
{
    static const std::wstring prefix = L"\\\\.\\PhysicalDrive";
    if (physicalDrive.size() <= prefix.size())
        return false;

    std::wstring lower = physicalDrive;
    for (auto& ch : lower)
        ch = static_cast<wchar_t>(towlower(ch));

    std::wstring lowerPrefix = prefix;
    for (auto& ch : lowerPrefix)
        ch = static_cast<wchar_t>(towlower(ch));

    if (lower.rfind(lowerPrefix, 0) != 0)
        return false;

    wchar_t* end = nullptr;
    unsigned long value = wcstoul(physicalDrive.c_str() + prefix.size(), &end, 10);
    if (!end || *end != L'\0')
        return false;

    outDiskNumber = value;
    return true;
}

void VaultManager::logLine(LogCallback log, const std::wstring& msg)
{
    if (log)
        log(msg);
}
