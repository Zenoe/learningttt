#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <string>
#include <functional>

using WfpLogFn = std::function<void(const std::wstring&)>;

class WfpManager {
public:
    explicit WfpManager(WfpLogFn log = nullptr);
    ~WfpManager();

    bool open();
    void close();
    bool isOpen() const { return m_hDevice != INVALID_HANDLE_VALUE; }

    bool addRootProcess(DWORD pid, const std::wstring& boxName, ULONG vnicIp);
    bool removeProcessTree(DWORD rootPid);
    bool clear();

    static bool parseIpv4(const std::wstring& text, ULONG& outHostOrder);
    static std::wstring formatIpv4(ULONG hostOrder);

private:
    struct ProcessInput {
        ULONG ProcessId;
        ULONG VnicIp;
        WCHAR BoxName[64];
    };

    bool sendIoctl(DWORD code, void* inBuf, DWORD inLen,
                   bool missingIsOk = false);
    void log(const std::wstring& msg);

    WfpLogFn m_log;
    HANDLE m_hDevice = INVALID_HANDLE_VALUE;
};
