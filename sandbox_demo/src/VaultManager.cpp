#include "VaultManager.h"

#include <bcrypt.h>
#include <wincrypt.h>
#include <wbemidl.h>
#include <virtdisk.h>
#include <winioctl.h>
#include <combaseapi.h>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <utility>
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

namespace {

class ComScope {
public:
    ComScope()
    {
        m_result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        m_uninitialize = SUCCEEDED(m_result);
        if (m_result == RPC_E_CHANGED_MODE)
            m_result = S_OK;
    }

    ~ComScope()
    {
        if (m_uninitialize)
            CoUninitialize();
    }

    HRESULT result() const { return m_result; }

private:
    HRESULT m_result = E_FAIL;
    bool m_uninitialize = false;
};

static bool sameVolumeName(std::wstring left, std::wstring right)
{
    while (!left.empty() && (left.back() == L'\\' || left.back() == L'/'))
        left.pop_back();
    while (!right.empty() && (right.back() == L'\\' || right.back() == L'/'))
        right.pop_back();
    return _wcsicmp(left.c_str(), right.c_str()) == 0;
}

static ULONG variantToUlong(const VARIANT& value)
{
    if (value.vt == VT_UI4) return value.ulVal;
    if (value.vt == VT_I4) return static_cast<ULONG>(value.lVal);
    if (value.vt == VT_UI2) return value.uiVal;
    if (value.vt == VT_I2) return static_cast<ULONG>(value.iVal);
    return ULONG_MAX;
}

class BitLockerWmi {
public:
    ~BitLockerWmi()
    {
        if (m_services) m_services->Release();
        if (m_locator) m_locator->Release();
    }

    bool connect(LogCallback log)
    {
        if (FAILED(m_com.result())) {
            logError(log, L"CoInitializeEx", m_com.result());
            return false;
        }

        HRESULT hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
            RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr, EOAC_NONE, nullptr);
        if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
            logError(log, L"CoInitializeSecurity", hr);
            return false;
        }

        hr = CoCreateInstance(CLSID_WbemLocator, nullptr,
            CLSCTX_INPROC_SERVER, IID_IWbemLocator,
            reinterpret_cast<void**>(&m_locator));
        if (FAILED(hr)) {
            logError(log, L"CoCreateInstance(IWbemLocator)", hr);
            return false;
        }

        BSTR ns = SysAllocString(
            L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption");
        if (!ns)
            return false;
        hr = m_locator->ConnectServer(ns, nullptr, nullptr, nullptr,
            0, nullptr, nullptr, &m_services);
        SysFreeString(ns);
        if (FAILED(hr)) {
            logError(log, L"ConnectServer(BitLocker)", hr);
            return false;
        }

        hr = CoSetProxyBlanket(m_services, RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
        if (FAILED(hr)) {
            logError(log, L"CoSetProxyBlanket", hr);
            return false;
        }
        return true;
    }

    bool findVolume(const std::wstring& volumeName,
                    std::wstring& objectPath,
                    LogCallback log)
    {
        BSTR language = SysAllocString(L"WQL");
        BSTR query = SysAllocString(L"SELECT * FROM Win32_EncryptableVolume");
        if (!language || !query) {
            if (language) SysFreeString(language);
            if (query) SysFreeString(query);
            return false;
        }

        IEnumWbemClassObject* enumerator = nullptr;
        HRESULT hr = m_services->ExecQuery(language, query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr, &enumerator);
        SysFreeString(language);
        SysFreeString(query);
        if (FAILED(hr)) {
            logError(log, L"ExecQuery(Win32_EncryptableVolume)", hr);
            return false;
        }

        bool found = false;
        for (;;) {
            IWbemClassObject* item = nullptr;
            ULONG returned = 0;
            hr = enumerator->Next(5000, 1, &item, &returned);
            if (FAILED(hr) || returned == 0)
                break;

            VARIANT device{};
            VariantInit(&device);
            if (SUCCEEDED(item->Get(L"DeviceID", 0, &device, nullptr, nullptr)) &&
                device.vt == VT_BSTR && device.bstrVal &&
                sameVolumeName(device.bstrVal, volumeName)) {
                VARIANT path{};
                VariantInit(&path);
                if (SUCCEEDED(item->Get(L"__PATH", 0, &path, nullptr, nullptr)) &&
                    path.vt == VT_BSTR && path.bstrVal) {
                    objectPath.assign(path.bstrVal, SysStringLen(path.bstrVal));
                    found = true;
                }
                VariantClear(&path);
            }
            VariantClear(&device);
            item->Release();
            if (found)
                break;
        }
        enumerator->Release();

        if (!found && log)
            log(L"[BitLocker] volume is not exposed by the WMI provider.");
        return found;
    }

    bool invoke(const std::wstring& objectPath,
                const wchar_t* method,
                const std::vector<std::pair<std::wstring, VARIANT>>& inputs,
                IWbemClassObject** output,
                ULONG& returnValue,
                LogCallback log)
    {
        IWbemClassObject* klass = nullptr;
        IWbemClassObject* inDefinition = nullptr;
        IWbemClassObject* inInstance = nullptr;
        IWbemClassObject* outInstance = nullptr;
        BSTR className = SysAllocString(L"Win32_EncryptableVolume");
        BSTR methodName = SysAllocString(method);
        BSTR path = SysAllocStringLen(objectPath.data(),
            static_cast<UINT>(objectPath.size()));
        if (!className || !methodName || !path)
            goto Cleanup;

        {
            HRESULT hr = m_services->GetObject(className, 0, nullptr,
                &klass, nullptr);
            if (FAILED(hr)) {
                logError(log, L"GetObject(Win32_EncryptableVolume)", hr);
                goto Cleanup;
            }
            hr = klass->GetMethod(methodName, 0, &inDefinition, nullptr);
            if (FAILED(hr)) {
                logError(log, std::wstring(L"GetMethod(") + method + L")", hr);
                goto Cleanup;
            }
            if (inDefinition) {
                hr = inDefinition->SpawnInstance(0, &inInstance);
                if (FAILED(hr)) {
                    logError(log, L"SpawnInstance", hr);
                    goto Cleanup;
                }
                for (const auto& input : inputs) {
                    hr = inInstance->Put(input.first.c_str(), 0,
                        const_cast<VARIANT*>(&input.second), 0);
                    if (FAILED(hr)) {
                        logError(log, std::wstring(L"Put(") + input.first + L")", hr);
                        goto Cleanup;
                    }
                }
            }

            hr = m_services->ExecMethod(path, methodName, 0, nullptr,
                inInstance, &outInstance, nullptr);
            if (FAILED(hr)) {
                logError(log, std::wstring(L"ExecMethod(") + method + L")", hr);
                goto Cleanup;
            }
        }

        {
            VARIANT result{};
            VariantInit(&result);
            HRESULT hr = outInstance->Get(L"ReturnValue", 0, &result,
                nullptr, nullptr);
            if (FAILED(hr)) {
                VariantClear(&result);
                goto Cleanup;
            }
            returnValue = variantToUlong(result);
            VariantClear(&result);
        }

        if (output) {
            *output = outInstance;
            outInstance = nullptr;
        }
        if (outInstance) outInstance->Release();
        if (inInstance) inInstance->Release();
        if (inDefinition) inDefinition->Release();
        if (klass) klass->Release();
        SysFreeString(path);
        SysFreeString(methodName);
        SysFreeString(className);
        return true;

    Cleanup:
        if (outInstance) outInstance->Release();
        if (inInstance) inInstance->Release();
        if (inDefinition) inDefinition->Release();
        if (klass) klass->Release();
        if (path) SysFreeString(path);
        if (methodName) SysFreeString(methodName);
        if (className) SysFreeString(className);
        return false;
    }

private:
    static void logError(LogCallback log, const std::wstring& operation,
                         HRESULT hr)
    {
        if (log) {
            std::wostringstream line;
            line << L"[BitLocker] " << operation << L" failed: 0x"
                 << std::hex << std::uppercase << static_cast<ULONG>(hr);
            log(line.str());
        }
    }

    ComScope m_com;
    IWbemLocator* m_locator = nullptr;
    IWbemServices* m_services = nullptr;
};

static VARIANT makeStringVariant(const std::wstring& value)
{
    VARIANT result{};
    VariantInit(&result);
    result.vt = VT_BSTR;
    result.bstrVal = SysAllocStringLen(value.data(),
        static_cast<UINT>(value.size()));
    return result;
}

static VARIANT makeUlongVariant(ULONG value)
{
    VARIANT result{};
    VariantInit(&result);
    // The BitLocker WMI provider declares these as CIM uint32, but older
    // Win10 providers require the Automation representation VT_I4.
    result.vt = VT_I4;
    result.lVal = static_cast<LONG>(value);
    return result;
}

static VARIANT makeBoolVariant(bool value)
{
    VARIANT result{};
    VariantInit(&result);
    result.vt = VT_BOOL;
    result.boolVal = value ? VARIANT_TRUE : VARIANT_FALSE;
    return result;
}

static void clearInputs(std::vector<std::pair<std::wstring, VARIANT>>& inputs)
{
    for (auto& input : inputs)
        VariantClear(&input.second);
    inputs.clear();
}

static bool getOutputUlong(IWbemClassObject* output, const wchar_t* name,
                           ULONG& value)
{
    VARIANT item{};
    VariantInit(&item);
    HRESULT hr = output->Get(name, 0, &item, nullptr, nullptr);
    if (SUCCEEDED(hr))
        value = variantToUlong(item);
    VariantClear(&item);
    return SUCCEEDED(hr) && value != ULONG_MAX;
}

static bool getOutputString(IWbemClassObject* output, const wchar_t* name,
                            std::wstring& value)
{
    VARIANT item{};
    VariantInit(&item);
    HRESULT hr = output->Get(name, 0, &item, nullptr, nullptr);
    if (SUCCEEDED(hr) && item.vt == VT_BSTR && item.bstrVal)
        value.assign(item.bstrVal, SysStringLen(item.bstrVal));
    else
        hr = E_FAIL;
    VariantClear(&item);
    return SUCCEEDED(hr);
}

} // namespace

static const GUID kVaultBitLockerMetadataGuid = {
    0xb74ec186, 0x0638, 0x4c39,
    { 0x8d, 0x1a, 0x5c, 0x68, 0xc5, 0xeb, 0x45, 0x71 }
};

struct VaultBitLockerMetadata {
    ULONG magic;
    ULONG version;
};

static constexpr ULONG kVaultBitLockerMagic = 0x4b4c4253; // "SBLK"
static constexpr ULONG kVaultBitLockerVersion = 1;

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

static bool sha256PathName(const std::wstring& text, std::wstring& hex)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD resultSize = 0;
    std::vector<UCHAR> object;
    UCHAR digest[32]{};

    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm,
        BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0)
        return false;
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize),
        &resultSize, 0);
    if (status >= 0) {
        object.resize(objectSize);
        status = BCryptCreateHash(algorithm, &hash, object.data(),
            objectSize, nullptr, 0, 0);
    }
    if (status >= 0) {
        status = BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(text.data())),
            static_cast<ULONG>(text.size() * sizeof(wchar_t)), 0);
    }
    if (status >= 0)
        status = BCryptFinishHash(hash, digest, sizeof(digest), 0);
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    SecureZeroMemory(object.data(), object.size());
    if (status < 0) {
        SecureZeroMemory(digest, sizeof(digest));
        return false;
    }

    static const wchar_t chars[] = L"0123456789abcdef";
    hex.clear();
    hex.reserve(sizeof(digest) * 2);
    for (UCHAR value : digest) {
        hex.push_back(chars[value >> 4]);
        hex.push_back(chars[value & 0x0f]);
    }
    SecureZeroMemory(digest, sizeof(digest));
    return true;
}

static std::wstring bytesToHex(const UCHAR* bytes, size_t length)
{
    static const wchar_t chars[] = L"0123456789abcdef";
    std::wstring result;
    result.reserve(length * 2);
    for (size_t i = 0; i < length; ++i) {
        result.push_back(chars[bytes[i] >> 4]);
        result.push_back(chars[bytes[i] & 0x0f]);
    }
    return result;
}

static bool generateBitLockerRecoveryPassword(std::wstring& password)
{
    USHORT values[8]{};
    NTSTATUS status = BCryptGenRandom(nullptr,
        reinterpret_cast<PUCHAR>(values), sizeof(values),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0)
        return false;

    std::wostringstream text;
    text << std::setfill(L'0');
    for (size_t i = 0; i < ARRAYSIZE(values); ++i) {
        if (i != 0)
            text << L'-';
        // Each BitLocker recovery-password block is a 16-bit value encoded
        // as a six-digit decimal number divisible by 11.
        text << std::setw(6) << (static_cast<ULONG>(values[i]) * 11u);
    }
    SecureZeroMemory(values, sizeof(values));
    password = text.str();
    return true;
}

static void logBitLockerCode(LogCallback log, const wchar_t* operation,
                             ULONG code)
{
    if (!log)
        return;
    std::wostringstream line;
    line << L"[BitLocker] " << operation << L" failed: 0x"
         << std::hex << std::uppercase << code;
    log(line.str());
}

VaultManager::~VaultManager()
{
    for (auto& item : m_attachedVaults) {
        if (item.second.handle && item.second.handle != INVALID_HANDLE_VALUE) {
            if (!item.second.mountPoint.empty()) {
                std::wstring mount = withTrailingBackslash(
                    item.second.mountPoint);
                DeleteVolumeMountPointW(mount.c_str());
            }
            lockBitLocker(item.second.volumeName, nullptr);
            DetachVirtualDisk(item.second.handle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
            CloseHandle(item.second.handle);
        }
    }
    m_attachedVaults.clear();
    m_saltCache.clear();
    for (auto& item : m_pendingRecoveryPasswords) {
        SecureZeroMemory(item.second.data(),
            item.second.size() * sizeof(wchar_t));
    }
    m_pendingRecoveryPasswords.clear();
}

std::wstring VaultManager::createAndMount(const VaultConfig& cfg, LogCallback log)
{
    if (vaultFileExistsNonEmpty(cfg.vaultFilePath)) {
        return mount(cfg, log);
    }

    if (!createVhdx(cfg, log))
        return {};

    auto removeIncompleteVault = [&]() {
        if (detachVhdx(cfg.vaultFilePath, log)) {
            if (!DeleteFileW(cfg.vaultFilePath.c_str())) {
                DWORD err = GetLastError();
                if (err != ERROR_FILE_NOT_FOUND) {
                    logLine(log, L"[Vault] failed to remove incomplete vault: " +
                        std::to_wstring(err));
                }
            }
        }
    };

    std::wstring physicalDrive;
    if (!attachVhdx(cfg.vaultFilePath, physicalDrive, log)) {
        removeIncompleteVault();
        return {};
    }

    if (!formatAttachedDisk(physicalDrive, cfg.mountPoint, log)) {
        removeIncompleteVault();
        return {};
    }

    unsigned long diskNumber = 0;
    std::wstring volumeName;
    if (!parsePhysicalDriveNumber(physicalDrive, diskNumber)) {
        removeIncompleteVault();
        return {};
    }
    for (int i = 0; i < 50 && volumeName.empty(); ++i) {
        findVolumeForDisk(diskNumber, volumeName, log);
        if (volumeName.empty()) Sleep(100);
    }
    if (volumeName.empty()) {
        removeIncompleteVault();
        return {};
    }

    std::wstring bitLockerPassphrase;
    std::wstring recoveryPassword;
    if (!resolveBitLockerPassphrase(cfg, true, bitLockerPassphrase, log) ||
        !enableBitLocker(volumeName, bitLockerPassphrase, true,
            recoveryPassword, log)) {
        SecureZeroMemory(bitLockerPassphrase.data(),
            bitLockerPassphrase.size() * sizeof(wchar_t));
        removeIncompleteVault();
        return {};
    }
    SecureZeroMemory(bitLockerPassphrase.data(),
        bitLockerPassphrase.size() * sizeof(wchar_t));

    const std::wstring key = normalizePath(cfg.vaultFilePath);
    auto attached = m_attachedVaults.find(key);
    if (attached == m_attachedVaults.end() ||
        !writeBitLockerMetadata(attached->second.handle, log)) {
        SecureZeroMemory(recoveryPassword.data(),
            recoveryPassword.size() * sizeof(wchar_t));
        removeIncompleteVault();
        return {};
    }

    if (!assignMountPoint(physicalDrive, cfg.mountPoint, log)) {
        SecureZeroMemory(recoveryPassword.data(),
            recoveryPassword.size() * sizeof(wchar_t));
        removeIncompleteVault();
        return {};
    }

    {
        auto existing = m_attachedVaults.find(key);
        if (existing != m_attachedVaults.end()) {
            existing->second.mountPoint = cfg.mountPoint;
            existing->second.volumeName = volumeName;
        }
    }

    m_pendingRecoveryPasswords[key] = std::move(recoveryPassword);

    logLine(log, L"[Vault] created and mounted at " + cfg.mountPoint);
    return cfg.mountPoint;
}

std::wstring VaultManager::mount(const VaultConfig& cfg, LogCallback log)
{
    const std::wstring key = normalizePath(cfg.vaultFilePath);
    auto existing = m_attachedVaults.find(key);
    if (existing != m_attachedVaults.end()) {
        wchar_t mountedVolume[MAX_PATH]{};
        std::wstring currentMount = withTrailingBackslash(
            existing->second.mountPoint.empty()
                ? cfg.mountPoint
                : existing->second.mountPoint);
        if (!GetVolumeNameForVolumeMountPointW(currentMount.c_str(),
            mountedVolume, ARRAYSIZE(mountedVolume))) {
            std::wstring bitLockerPassphrase;
            bool restored = resolveBitLockerPassphrase(cfg, false,
                bitLockerPassphrase, log) &&
                unlockBitLocker(existing->second.volumeName,
                    bitLockerPassphrase, log) &&
                assignMountPoint(existing->second.physicalDrive,
                    cfg.mountPoint, log);
            SecureZeroMemory(bitLockerPassphrase.data(),
                bitLockerPassphrase.size() * sizeof(wchar_t));
            if (!restored)
                return {};
            existing->second.mountPoint = cfg.mountPoint;
        }
        existing->second.refCount++;
        if (existing->second.mountPoint.empty())
            existing->second.mountPoint = cfg.mountPoint;
        logLine(log, L"[Vault] reused mounted vault " + cfg.vaultFilePath +
            L" refs=" + std::to_wstring(existing->second.refCount));
        return existing->second.mountPoint.empty()
            ? cfg.mountPoint
            : existing->second.mountPoint;
    }

    if (!readBitLockerMetadata(cfg.vaultFilePath, log))
        return {};

    std::wstring physicalDrive;
    if (!attachVhdx(cfg.vaultFilePath, physicalDrive, log))
        return {};

    unsigned long diskNumber = 0;
    std::wstring volumeName;
    if (!parsePhysicalDriveNumber(physicalDrive, diskNumber)) {
        detachVhdx(cfg.vaultFilePath, log);
        return {};
    }
    for (int i = 0; i < 50 && volumeName.empty(); ++i) {
        findVolumeForDisk(diskNumber, volumeName, log);
        if (volumeName.empty()) Sleep(100);
    }

    std::wstring bitLockerPassphrase;
    bool unlocked = !volumeName.empty() &&
        resolveBitLockerPassphrase(cfg, false, bitLockerPassphrase, log) &&
        unlockBitLocker(volumeName, bitLockerPassphrase, log);
    SecureZeroMemory(bitLockerPassphrase.data(),
        bitLockerPassphrase.size() * sizeof(wchar_t));
    if (!unlocked || !assignMountPoint(physicalDrive, cfg.mountPoint, log)) {
        detachVhdx(cfg.vaultFilePath, log);
        return {};
    }

    existing = m_attachedVaults.find(key);
    if (existing != m_attachedVaults.end()) {
        existing->second.mountPoint = cfg.mountPoint;
        existing->second.volumeName = volumeName;
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
    const std::wstring key = normalizePath(vaultFilePath);
    auto cached = m_saltCache.find(key);
    if (cached != m_saltCache.end()) {
        salt = cached->second;
        logLine(log, L"[Vault] loaded salt from memory cache.");
        return true;
    }

    fs::path vaultPath(vaultFilePath);
    if (fs::exists(vaultPath, ec) && fs::file_size(vaultPath, ec) == 0) {
        fs::remove(vaultPath, ec);
        logLine(log, L"[Vault] removed empty stale vault file.");
    }

    if (vaultFileExistsNonEmpty(vaultFilePath)) {
        DWORD metadataErr = ERROR_SUCCESS;
        if (readSaltMetadata(vaultFilePath, salt, log, &metadataErr)) {
            m_saltCache[key] = salt;
            return true;
        }

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
        if (ok)
            m_saltCache[key] = salt;
        return ok;
    }

    m_saltCache[key] = salt;
    return true;
}

std::wstring VaultManager::takePendingRecoveryPassword(
    const std::wstring& vaultFilePath)
{
    const std::wstring key = normalizePath(vaultFilePath);
    auto it = m_pendingRecoveryPasswords.find(key);
    if (it == m_pendingRecoveryPasswords.end())
        return {};
    std::wstring result = std::move(it->second);
    m_pendingRecoveryPasswords.erase(it);
    return result;
}

bool VaultManager::resolveBitLockerPassphrase(const VaultConfig& cfg,
                                              bool createAutomaticSecret,
                                              std::wstring& passphrase,
                                              LogCallback log) const
{
    UCHAR secret[32]{};

    if (!cfg.passphrase.empty()) {
        std::wstring material = L"SandboxDemo BitLocker:" +
            cfg.boxName + L":" + cfg.passphrase;
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm,
            BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status >= 0) {
            status = BCryptDeriveKeyPBKDF2(algorithm,
                reinterpret_cast<PUCHAR>(material.data()),
                static_cast<ULONG>(material.size() * sizeof(wchar_t)),
                const_cast<PUCHAR>(cfg.salt.data()),
                static_cast<ULONG>(cfg.salt.size()),
                150000, secret, sizeof(secret), 0);
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }
        SecureZeroMemory(material.data(), material.size() * sizeof(wchar_t));
        if (status < 0) {
            logLine(log, L"[BitLocker] PBKDF2 key derivation failed.");
            return false;
        }
        passphrase = bytesToHex(secret, sizeof(secret));
        SecureZeroMemory(secret, sizeof(secret));
        return true;
    }

    wchar_t localAppData[MAX_PATH]{};
    DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData,
        ARRAYSIZE(localAppData));
    if (length == 0 || length >= ARRAYSIZE(localAppData)) {
        logLine(log, L"[BitLocker] LOCALAPPDATA is unavailable for key storage.");
        return false;
    }

    std::wstring keyName;
    if (!sha256PathName(normalizePath(cfg.vaultFilePath), keyName)) {
        logLine(log, L"[BitLocker] failed to derive automatic key filename.");
        return false;
    }
    fs::path keyDirectory = fs::path(localAppData) /
        L"SandboxDemo" / L"BitLockerKeys";
    fs::path keyPath = keyDirectory / (keyName + L".dpapi");
    std::vector<BYTE> protectedBytes;

    std::ifstream input(keyPath, std::ios::binary | std::ios::ate);
    if (input) {
        std::streamsize size = input.tellg();
        if (size <= 0 || size > 4096) {
            logLine(log, L"[BitLocker] automatic key file is invalid.");
            return false;
        }
        protectedBytes.resize(static_cast<size_t>(size));
        input.seekg(0, std::ios::beg);
        if (!input.read(reinterpret_cast<char*>(protectedBytes.data()), size)) {
            SecureZeroMemory(protectedBytes.data(), protectedBytes.size());
            return false;
        }

        static const BYTE entropyBytes[] =
            "SandboxDemo BitLocker automatic key v1";
        DATA_BLOB encrypted{};
        encrypted.pbData = protectedBytes.data();
        encrypted.cbData = static_cast<DWORD>(protectedBytes.size());
        DATA_BLOB entropy{};
        entropy.pbData = const_cast<BYTE*>(entropyBytes);
        entropy.cbData = sizeof(entropyBytes);
        DATA_BLOB clear{};
        BOOL ok = CryptUnprotectData(&encrypted, nullptr, &entropy,
            nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &clear);
        SecureZeroMemory(protectedBytes.data(), protectedBytes.size());
        if (!ok || clear.cbData != sizeof(secret)) {
            if (clear.pbData) {
                SecureZeroMemory(clear.pbData, clear.cbData);
                LocalFree(clear.pbData);
            }
            logLine(log, L"[BitLocker] DPAPI could not unlock the automatic key.");
            return false;
        }
        memcpy(secret, clear.pbData, sizeof(secret));
        SecureZeroMemory(clear.pbData, clear.cbData);
        LocalFree(clear.pbData);
    }
    else {
        if (!createAutomaticSecret) {
            logLine(log, L"[BitLocker] automatic key is missing; use the recovery password.");
            return false;
        }

        NTSTATUS status = BCryptGenRandom(nullptr, secret, sizeof(secret),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0)
            return false;

        static const BYTE entropyBytes[] =
            "SandboxDemo BitLocker automatic key v1";
        DATA_BLOB clear{};
        clear.pbData = secret;
        clear.cbData = sizeof(secret);
        DATA_BLOB entropy{};
        entropy.pbData = const_cast<BYTE*>(entropyBytes);
        entropy.cbData = sizeof(entropyBytes);
        DATA_BLOB encrypted{};
        if (!CryptProtectData(&clear, L"SandboxDemo BitLocker key",
            &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN,
            &encrypted)) {
            SecureZeroMemory(secret, sizeof(secret));
            return false;
        }

        std::error_code ec;
        fs::create_directories(keyDirectory, ec);
        fs::path temporary = keyPath;
        temporary += L".tmp";
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        bool written = output && output.write(
            reinterpret_cast<const char*>(encrypted.pbData),
            encrypted.cbData).good();
        output.close();
        SecureZeroMemory(encrypted.pbData, encrypted.cbData);
        LocalFree(encrypted.pbData);
        if (!written || !MoveFileExW(temporary.c_str(), keyPath.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DeleteFileW(temporary.c_str());
            SecureZeroMemory(secret, sizeof(secret));
            logLine(log, L"[BitLocker] failed to persist the DPAPI key.");
            return false;
        }
        logLine(log, L"[BitLocker] created a DPAPI-protected automatic key.");
    }

    passphrase = bytesToHex(secret, sizeof(secret));
    SecureZeroMemory(secret, sizeof(secret));
    return true;
}

bool VaultManager::enableBitLocker(const std::wstring& volumeName,
                                   const std::wstring& passphrase,
                                   bool usedSpaceOnly,
                                   std::wstring& recoveryPassword,
                                   LogCallback log) const
{
    BitLockerWmi wmi;
    std::wstring objectPath;
    if (!wmi.connect(log) || !wmi.findVolume(volumeName, objectPath, log))
        return false;

    ULONG code = ULONG_MAX;
    ULONG conversionStatus = ULONG_MAX;
    IWbemClassObject* output = nullptr;
    if (!wmi.invoke(objectPath, L"GetConversionStatus", {}, &output,
        code, log) || code != ERROR_SUCCESS ||
        !getOutputUlong(output, L"ConversionStatus", conversionStatus)) {
        if (output) output->Release();
        if (code != ERROR_SUCCESS) logBitLockerCode(log, L"GetConversionStatus", code);
        return false;
    }
    output->Release();

    if (conversionStatus != 0) {
        logLine(log, L"[BitLocker] volume protection already exists.");
        return unlockBitLocker(volumeName, passphrase, log);
    }

    std::vector<std::pair<std::wstring, VARIANT>> inputs;
    inputs.emplace_back(L"FriendlyName",
        makeStringVariant(L"SandboxDemo automatic protector"));
    inputs.emplace_back(L"PassPhrase", makeStringVariant(passphrase));
    output = nullptr;
    bool invoked = wmi.invoke(objectPath, L"ProtectKeyWithPassPhrase",
        inputs, &output, code, log);
    clearInputs(inputs);
    if (!invoked || code != ERROR_SUCCESS) {
        if (output) output->Release();
        logBitLockerCode(log, L"ProtectKeyWithPassPhrase", code);
        return false;
    }
    output->Release();

    if (!generateBitLockerRecoveryPassword(recoveryPassword)) {
        logLine(log, L"[BitLocker] failed to generate a recovery password.");
        return false;
    }

    inputs.emplace_back(L"FriendlyName",
        makeStringVariant(L"SandboxDemo recovery password"));
    inputs.emplace_back(L"NumericalPassword",
        makeStringVariant(recoveryPassword));
    output = nullptr;
    invoked = wmi.invoke(objectPath, L"ProtectKeyWithNumericalPassword",
        inputs, &output, code, log);
    clearInputs(inputs);
    std::wstring recoveryProtector;
    if (!invoked || code != ERROR_SUCCESS ||
        !getOutputString(output, L"VolumeKeyProtectorID", recoveryProtector)) {
        if (output) output->Release();
        logBitLockerCode(log, L"ProtectKeyWithNumericalPassword", code);
        SecureZeroMemory(recoveryPassword.data(),
            recoveryPassword.size() * sizeof(wchar_t));
        recoveryPassword.clear();
        return false;
    }
    output->Release();

    inputs.emplace_back(L"VolumeKeyProtectorID",
        makeStringVariant(recoveryProtector));
    output = nullptr;
    invoked = wmi.invoke(objectPath, L"GetKeyProtectorNumericalPassword",
        inputs, &output, code, log);
    clearInputs(inputs);
    std::wstring confirmedRecoveryPassword;
    if (!invoked || code != ERROR_SUCCESS ||
        !getOutputString(output, L"NumericalPassword",
            confirmedRecoveryPassword)) {
        if (output) output->Release();
        logBitLockerCode(log, L"GetKeyProtectorNumericalPassword", code);
        SecureZeroMemory(recoveryPassword.data(),
            recoveryPassword.size() * sizeof(wchar_t));
        recoveryPassword.clear();
        return false;
    }
    output->Release();
    SecureZeroMemory(recoveryPassword.data(),
        recoveryPassword.size() * sizeof(wchar_t));
    recoveryPassword = std::move(confirmedRecoveryPassword);

    inputs.emplace_back(L"EncryptionMethod", makeUlongVariant(7));
    inputs.emplace_back(L"EncryptionFlags",
        makeUlongVariant(usedSpaceOnly ? 1u : 0u));
    invoked = wmi.invoke(objectPath, L"Encrypt", inputs, nullptr, code, log);
    clearInputs(inputs);
    if (!invoked || code != ERROR_SUCCESS) {
        if (invoked)
            logBitLockerCode(log, L"Encrypt(XTS-AES-256)", code);
        SecureZeroMemory(recoveryPassword.data(),
            recoveryPassword.size() * sizeof(wchar_t));
        recoveryPassword.clear();
        return false;
    }

    if (!unlockBitLocker(volumeName, passphrase, log)) {
        SecureZeroMemory(recoveryPassword.data(),
            recoveryPassword.size() * sizeof(wchar_t));
        recoveryPassword.clear();
        return false;
    }

    logLine(log, L"[BitLocker] XTS-AES-256 protection enabled.");
    return true;
}

bool VaultManager::unlockBitLocker(const std::wstring& volumeName,
                                   const std::wstring& passphrase,
                                   LogCallback log) const
{
    BitLockerWmi wmi;
    std::wstring objectPath;
    if (!wmi.connect(log) || !wmi.findVolume(volumeName, objectPath, log))
        return false;

    ULONG code = ULONG_MAX;
    ULONG lockStatus = ULONG_MAX;
    IWbemClassObject* output = nullptr;
    if (!wmi.invoke(objectPath, L"GetLockStatus", {}, &output, code, log) ||
        code != ERROR_SUCCESS ||
        !getOutputUlong(output, L"LockStatus", lockStatus)) {
        if (output) output->Release();
        logBitLockerCode(log, L"GetLockStatus", code);
        return false;
    }
    output->Release();

    std::vector<std::pair<std::wstring, VARIANT>> inputs;
    if (lockStatus != 0) {
        inputs.emplace_back(L"PassPhrase", makeStringVariant(passphrase));
        bool invoked = wmi.invoke(objectPath, L"UnlockWithPassPhrase",
            inputs, nullptr, code, log);
        clearInputs(inputs);
        if (!invoked || code != ERROR_SUCCESS) {
            logBitLockerCode(log, L"UnlockWithPassPhrase", code);
            return false;
        }
        logLine(log, L"[BitLocker] volume unlocked.");
    }

    ULONG conversionStatus = ULONG_MAX;
    output = nullptr;
    if (!wmi.invoke(objectPath, L"GetConversionStatus", {}, &output,
        code, log) || code != ERROR_SUCCESS ||
        !getOutputUlong(output, L"ConversionStatus", conversionStatus)) {
        if (output) output->Release();
        logBitLockerCode(log, L"GetConversionStatus", code);
        return false;
    }
    output->Release();

    if (conversionStatus == 4) {
        if (!wmi.invoke(objectPath, L"ResumeConversion", {}, nullptr,
            code, log) || code != ERROR_SUCCESS) {
            logBitLockerCode(log, L"ResumeConversion", code);
            return false;
        }
        conversionStatus = 2;
    }
    if (conversionStatus != 1 && conversionStatus != 2) {
        logLine(log, L"[BitLocker] volume is not in an encrypted state.");
        return false;
    }

    ULONG protectionStatus = ULONG_MAX;
    output = nullptr;
    if (!wmi.invoke(objectPath, L"GetProtectionStatus", {}, &output,
        code, log) || code != ERROR_SUCCESS ||
        !getOutputUlong(output, L"ProtectionStatus", protectionStatus)) {
        if (output) output->Release();
        logBitLockerCode(log, L"GetProtectionStatus", code);
        return false;
    }
    output->Release();
    if (protectionStatus != 1) {
        // Win10 reports ProtectionStatus=Unprotected while initial
        // encryption is still converting the volume, even though the
        // passphrase and recovery protectors were added successfully.
        if (conversionStatus == 2) {
            logLine(log, L"[BitLocker] encryption is in progress; key "
                L"protectors are configured.");
            return true;
        }
        logLine(log, L"[BitLocker] key protectors are not enabled.");
        return false;
    }
    return true;
}

bool VaultManager::lockBitLocker(const std::wstring& volumeName,
                                 LogCallback log) const
{
    if (volumeName.empty())
        return true;
    BitLockerWmi wmi;
    std::wstring objectPath;
    if (!wmi.connect(log) || !wmi.findVolume(volumeName, objectPath, log))
        return false;

    ULONG code = ULONG_MAX;
    std::vector<std::pair<std::wstring, VARIANT>> inputs;
    inputs.emplace_back(L"ForceDismount", makeBoolVariant(false));
    bool invoked = wmi.invoke(objectPath, L"Lock", inputs, nullptr, code, log);
    clearInputs(inputs);
    if (!invoked || code != ERROR_SUCCESS) {
        logBitLockerCode(log, L"Lock", code);
        return false;
    }
    logLine(log, L"[BitLocker] volume locked.");
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

bool VaultManager::readBitLockerMetadata(const std::wstring& vaultFilePath,
                                         LogCallback log) const
{
    VIRTUAL_STORAGE_TYPE storageType{};
    storageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
    storageType.VendorId = kVirtualStorageVendorMicrosoft;
    OPEN_VIRTUAL_DISK_PARAMETERS openParams{};
    openParams.Version = OPEN_VIRTUAL_DISK_VERSION_1;

    HANDLE handle = INVALID_HANDLE_VALUE;
    DWORD err = OpenVirtualDisk(&storageType, vaultFilePath.c_str(),
        VIRTUAL_DISK_ACCESS_GET_INFO | VIRTUAL_DISK_ACCESS_METAOPS,
        OPEN_VIRTUAL_DISK_FLAG_NONE, &openParams, &handle);
    if (err != ERROR_SUCCESS)
        return false;

    VaultBitLockerMetadata metadata{};
    ULONG size = sizeof(metadata);
    err = GetVirtualDiskMetadata(handle, &kVaultBitLockerMetadataGuid,
        &size, &metadata);
    CloseHandle(handle);
    bool valid = err == ERROR_SUCCESS && size == sizeof(metadata) &&
        metadata.magic == kVaultBitLockerMagic &&
        metadata.version == kVaultBitLockerVersion;
    if (!valid) {
        logLine(log, L"[BitLocker] legacy vault detected; refusing in-place "
            L"encryption. Export it with the old crypto driver, then create "
            L"a new BitLocker vault.");
    }
    return valid;
}

bool VaultManager::writeBitLockerMetadata(HANDLE virtualDisk,
                                          LogCallback log) const
{
    VaultBitLockerMetadata metadata{};
    metadata.magic = kVaultBitLockerMagic;
    metadata.version = kVaultBitLockerVersion;
    DWORD err = SetVirtualDiskMetadata(virtualDisk,
        &kVaultBitLockerMetadataGuid, sizeof(metadata), &metadata);
    if (err != ERROR_SUCCESS) {
        logLine(log, L"[BitLocker] failed to commit vault format marker: " +
            std::to_wstring(err));
        return false;
    }
    return true;
}

bool VaultManager::attachVhdx(const std::wstring& vaultFilePath,
                              std::wstring& outPhysicalDrive,
                              LogCallback log)
{
    const std::wstring key = normalizePath(vaultFilePath);
    auto existing = m_attachedVaults.find(key);
    if (existing != m_attachedVaults.end()) {
        existing->second.refCount++;
        outPhysicalDrive = existing->second.physicalDrive;
        logLine(log, L"[Vault] reused attached vault " + vaultFilePath +
            L" refs=" + std::to_wstring(existing->second.refCount));
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
                AttachedVault attached;
                attached.handle = handle;
                attached.refCount = 1;
                attached.physicalDrive = path;
                m_attachedVaults[key] = attached;
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

    if (it->second.refCount > 1) {
        it->second.refCount--;
        logLine(log, L"[Vault] kept mounted " + vaultFilePath +
            L" refs=" + std::to_wstring(it->second.refCount));
        return true;
    }

    if (!it->second.mountPoint.empty()) {
        std::wstring mount = withTrailingBackslash(it->second.mountPoint);
        if (!DeleteVolumeMountPointW(mount.c_str())) {
            DWORD mountErr = GetLastError();
            if (mountErr != ERROR_FILE_NOT_FOUND &&
                mountErr != ERROR_PATH_NOT_FOUND &&
                mountErr != ERROR_INVALID_PARAMETER) {
                logLine(log, L"[Vault] DeleteVolumeMountPoint failed: " +
                    std::to_wstring(mountErr));
                return false;
            }
        }
    }

    if (!it->second.volumeName.empty() &&
        !lockBitLocker(it->second.volumeName, log)) {
        logLine(log, L"[Vault] volume still has open handles; detach deferred.");
        return false;
    }

    DWORD err = DetachVirtualDisk(it->second.handle,
        DETACH_VIRTUAL_DISK_FLAG_NONE, 0);

    if (err != ERROR_SUCCESS) {
        logLine(log, L"[Vault] DetachVirtualDisk failed: " + std::to_wstring(err));
        return false;
    }

    CloseHandle(it->second.handle);
    m_attachedVaults.erase(it);

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

    return true;
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
