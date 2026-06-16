#include "WfpManager.h"
#include <cwchar>
#include <sstream>
#include <utility>

namespace {
constexpr wchar_t kDeviceName[] = L"\\\\.\\WfpRedirect";
constexpr DWORD kIoctlBase = 0x8000;
constexpr DWORD kIoctlAddProcess =
    CTL_CODE(FILE_DEVICE_UNKNOWN, kIoctlBase + 1, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD kIoctlRemoveProcess =
    CTL_CODE(FILE_DEVICE_UNKNOWN, kIoctlBase + 2, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD kIoctlClear =
    CTL_CODE(FILE_DEVICE_UNKNOWN, kIoctlBase + 3, METHOD_BUFFERED, FILE_ANY_ACCESS);
}

WfpManager::WfpManager(WfpLogFn log)
    : m_log(std::move(log))
{}

WfpManager::~WfpManager()
{
    close();
}

bool WfpManager::open()
{
    if (isOpen())
        return true;

    m_hDevice = CreateFileW(kDeviceName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (m_hDevice == INVALID_HANDLE_VALUE) {
        log(L"[WFP] CreateFile(\\\\.\\WfpRedirect) failed: " +
            std::to_wstring(GetLastError()));
        return false;
    }

    log(L"[WFP] Control device opened.");
    return true;
}

void WfpManager::close()
{
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
    }
}

bool WfpManager::addRootProcess(DWORD pid,
                                const std::wstring& boxName,
                                ULONG vnicIp)
{
    if (pid == 0 || vnicIp == 0)
        return false;
    if (!open())
        return false;

    ProcessInput input{};
    input.ProcessId = pid;
    input.VnicIp = vnicIp;
    wcsncpy_s(input.BoxName, boxName.c_str(), _TRUNCATE);

    bool ok = sendIoctl(kIoctlAddProcess, &input, sizeof(input));
    if (ok) {
        log(L"[WFP] Root PID " + std::to_wstring(pid) +
            L" -> vNIC " + formatIpv4(vnicIp) +
            L" box='" + boxName + L"'");
    }
    return ok;
}

bool WfpManager::removeProcessTree(DWORD rootPid)
{
    if (rootPid == 0)
        return true;
    if (!isOpen())
        return true;

    ULONG pid = rootPid;
    bool ok = sendIoctl(kIoctlRemoveProcess, &pid, sizeof(pid), true);
    if (ok)
        log(L"[WFP] Removed PID tree root=" + std::to_wstring(rootPid));
    return ok;
}

bool WfpManager::clear()
{
    if (!isOpen())
        return true;
    return sendIoctl(kIoctlClear, nullptr, 0, true);
}

bool WfpManager::sendIoctl(DWORD code, void* inBuf, DWORD inLen,
                           bool missingIsOk)
{
    if (!isOpen()) {
        log(L"[WFP] Device not open.");
        return false;
    }

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(m_hDevice, code,
        inBuf, inLen,
        nullptr, 0,
        &bytes, nullptr);

    if (!ok) {
        DWORD err = GetLastError();
        if (missingIsOk &&
            (err == ERROR_NOT_FOUND ||
             err == ERROR_FILE_NOT_FOUND ||
             err == ERROR_PATH_NOT_FOUND)) {
            return true;
        }

        std::wostringstream s;
        s << L"[WFP] DeviceIoControl 0x" << std::hex << code
          << L" failed: " << std::dec << err;
        log(s.str());
    }
    return ok == TRUE;
}

bool WfpManager::parseIpv4(const std::wstring& text, ULONG& outHostOrder)
{
    ULONG parts[4]{};
    const wchar_t* p = text.c_str();
    wchar_t* end = nullptr;

    for (int i = 0; i < 4; ++i) {
        if (*p == L'\0')
            return false;
        unsigned long value = wcstoul(p, &end, 10);
        if (end == p || value > 255)
            return false;
        parts[i] = static_cast<ULONG>(value);
        if (i < 3) {
            if (*end != L'.')
                return false;
            p = end + 1;
        }
        else if (*end != L'\0') {
            return false;
        }
    }

    outHostOrder = (parts[0] << 24) | (parts[1] << 16) |
                   (parts[2] << 8) | parts[3];
    return outHostOrder != 0;
}

std::wstring WfpManager::formatIpv4(ULONG hostOrder)
{
    wchar_t buf[16]{};
    swprintf_s(buf, L"%u.%u.%u.%u",
        (hostOrder >> 24) & 0xFF,
        (hostOrder >> 16) & 0xFF,
        (hostOrder >> 8) & 0xFF,
        hostOrder & 0xFF);
    return buf;
}

void WfpManager::log(const std::wstring& msg)
{
    if (m_log)
        m_log(msg);
}
