#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>

#ifndef SANDBOX_LOG_CALLBACK_DEFINED
#define SANDBOX_LOG_CALLBACK_DEFINED
using LogCallback = std::function<void(const std::wstring&)>;
#endif

struct VaultBoxMount {
    std::wstring boxName;
    std::wstring vaultPath;
    std::wstring mountPoint;
    std::wstring driverRootNt;
};

class VaultManager {
public:
    explicit VaultManager(LogCallback log = nullptr);
    ~VaultManager();

    std::optional<VaultBoxMount> mountBox(const std::wstring& baseDir,
                                          const std::wstring& boxName);
    bool unmountBox(const std::wstring& boxName);
    void unmountAll();

    bool isMounted(const std::wstring& boxName) const;
    std::wstring mountPoint(const std::wstring& boxName) const;
    std::wstring driverRootNt(const std::wstring& boxName) const;

    static std::wstring defaultBaseDir();

private:
    struct MountedVault {
        VaultBoxMount info;
        HANDLE handle = nullptr;
    };

    LogCallback m_log;
    std::unordered_map<std::wstring, MountedVault> m_mounted;

    bool createVaultFile(const std::wstring& vaultPath);
    bool openAndAttach(const std::wstring& vaultPath, HANDLE& handle);
    bool runDiskpartScript(const std::wstring& script);
    bool getAttachedDiskNumber(HANDLE handle, ULONG& diskNumber);
    bool prepareMountedVolume(HANDLE handle,
                              const std::wstring& mountPoint,
                              const std::wstring& boxName,
                              bool freshVault);
    std::wstring queryMountedVolumeDevice(const std::wstring& mountPoint);
    void log(const std::wstring& msg);
};
