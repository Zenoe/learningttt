#include "VaultManager.h"

#include <bcrypt.h>
#include <virtdisk.h>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <sstream>

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
    std::error_code ec;
    if (fs::exists(fs::path(cfg.vaultFilePath), ec) &&
        fs::file_size(fs::path(cfg.vaultFilePath), ec) > 0) {
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

    if (fs::exists(vaultPath, ec)) {
        if (readSaltMetadata(vaultFilePath, salt, log))
            return true;
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

    if (fs::exists(vaultPath, ec)) {
        VIRTUAL_STORAGE_TYPE storageType{};
        storageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
        storageType.VendorId = kVirtualStorageVendorMicrosoft;

        OPEN_VIRTUAL_DISK_PARAMETERS openParams{};
        openParams.Version = OPEN_VIRTUAL_DISK_VERSION_1;

        HANDLE handle = INVALID_HANDLE_VALUE;
        DWORD err = OpenVirtualDisk(
            &storageType,
            vaultFilePath.c_str(),
            VIRTUAL_DISK_ACCESS_METAOPS,
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

    if (fs::exists(vaultPath, ec) && fs::file_size(vaultPath, ec) > 0) {
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
                                    LogCallback log) const
{
    VIRTUAL_STORAGE_TYPE storageType{};
    storageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
    storageType.VendorId = kVirtualStorageVendorMicrosoft;

    OPEN_VIRTUAL_DISK_PARAMETERS openParams{};
    openParams.Version = OPEN_VIRTUAL_DISK_VERSION_1;

    HANDLE handle = INVALID_HANDLE_VALUE;
    DWORD err = OpenVirtualDisk(
        &storageType,
        vaultFilePath.c_str(),
        VIRTUAL_DISK_ACCESS_METAOPS,
        OPEN_VIRTUAL_DISK_FLAG_NONE,
        &openParams,
        &handle);
    if (err != ERROR_SUCCESS) {
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

    std::error_code ec;
    fs::create_directories(fs::path(mountPoint), ec);

    std::wostringstream script;
    script << L"select disk " << diskNumber << L"\r\n"
           << L"online disk noerr\r\n"
           << L"attributes disk clear readonly noerr\r\n"
           << L"convert gpt noerr\r\n"
           << L"create partition primary\r\n"
           << L"format fs=ntfs quick label=\"SandboxVault\"\r\n"
           << L"assign mount=\"" << mountPoint << L"\"\r\n";

    return runDiskPart(script.str(), log);
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

    std::error_code ec;
    fs::create_directories(fs::path(mountPoint), ec);

    std::wostringstream script;
    script << L"select disk " << diskNumber << L"\r\n"
           << L"online disk noerr\r\n"
           << L"select partition 1\r\n"
           << L"assign mount=\"" << mountPoint << L"\"\r\n";

    return runDiskPart(script.str(), log);
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
