#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>

#ifndef SANDBOX_LOG_CALLBACK_DEFINED
#define SANDBOX_LOG_CALLBACK_DEFINED
using LogCallback = std::function<void(const std::wstring&)>;
#endif

class VaultManager {
public:
    struct VaultConfig {
        std::wstring vaultFilePath;
        std::wstring mountPoint;
        uint64_t     sizeMB = 512;
        std::array<uint8_t, 32> salt{};
        std::array<uint8_t, 32> masterKey{};
        std::array<uint8_t, 32> hmacKey{};
    };

    VaultManager() = default;
    ~VaultManager();

    std::wstring createAndMount(const VaultConfig& cfg, LogCallback log);
    std::wstring mount(const VaultConfig& cfg, LogCallback log);
    bool unmount(const std::wstring& vaultFilePath, LogCallback log);
    bool isMounted(const std::wstring& vaultFilePath) const;
    bool loadOrCreateSalt(const std::wstring& vaultFilePath,
                          std::array<uint8_t, 32>& salt,
                          LogCallback log);

private:
    bool createVhdx(const VaultConfig& cfg, LogCallback log);
    bool readSaltMetadata(const std::wstring& vaultFilePath,
                          std::array<uint8_t, 32>& salt,
                          LogCallback log,
                          DWORD* outError = nullptr) const;
    bool writeSaltMetadata(HANDLE virtualDisk,
                           const std::array<uint8_t, 32>& salt,
                           LogCallback log) const;
    bool attachVhdx(const std::wstring& vaultFilePath,
                    std::wstring& outPhysicalDrive,
                    LogCallback log);
    bool detachVhdx(const std::wstring& vaultFilePath, LogCallback log);
    bool formatAttachedDisk(const std::wstring& physicalDrive,
                            const std::wstring& mountPoint,
                            LogCallback log);
    bool assignMountPoint(const std::wstring& physicalDrive,
                          const std::wstring& mountPoint,
                          LogCallback log);

    static std::wstring normalizePath(const std::wstring& path);
    static bool runDiskPart(const std::wstring& script, LogCallback log);
    static bool parsePhysicalDriveNumber(const std::wstring& physicalDrive,
                                         unsigned long& outDiskNumber);
    static void logLine(LogCallback log, const std::wstring& msg);

    std::unordered_map<std::wstring, HANDLE> m_attachedVaults;
};
