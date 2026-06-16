///////////////////////////////////////////////////////////////////////////////
//
// SandboxFlt WFP control test tool
//
// Usage:
//   RevDrvCtl set <PID> <vnic_ip> [box_name]
//       Enable SandboxFlt's WFP source-IP forcing for an already tracked
//       sandbox root PID. Child PIDs inherit the policy in sandboxflt.sys.
//
//   RevDrvCtl unset <PID> [box_name]
//       Disable WFP source-IP forcing for the PID tree rooted at <PID>.
//
//   RevDrvCtl clear <PID> [box_name]
//       Alias for unset.
//
//   RevDrvCtl list
//       Query SandboxFlt's tracked process table and show WFP state.
//
// Examples:
//   RevDrvCtl set 1234 10.8.0.4
//   RevDrvCtl set 1234 10.8.0.4 Box00
//   RevDrvCtl unset 1234
//   RevDrvCtl clear 1234
//   RevDrvCtl list
//
// Notes:
//   The PID must already be registered with SandboxFlt through
//   IOCTL_SANDBOX_ADD_PROCESS, normally by sandbox_demo.
//
///////////////////////////////////////////////////////////////////////////////

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>

#define SANDBOX_WIN32_DEVICE "\\\\.\\SandboxFlt"
#define SANDBOX_IOCTL_BASE 0x8000
#define SANDBOX_MAX_BOX 64
#define SANDBOX_MAX_TRACKED_PIDS 256

#define IOCTL_SANDBOX_QUERY_PROCESSES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, SANDBOX_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SANDBOX_SET_WFP_POLICY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, SANDBOX_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _SANDBOX_PROCESS_ENTRY {
    ULONG ProcessId;
    ULONG ParentProcessId;
    ULONG RootProcessId;
    ULONG WfpEnabled;
    ULONG WfpVnicIp;
    ULONG WfpNetworkSeen;
    ULONG _pad;
    WCHAR BoxName[SANDBOX_MAX_BOX];
} SANDBOX_PROCESS_ENTRY;

typedef struct _SANDBOX_PROCESS_LIST {
    ULONG Count;
    ULONG _pad;
    SANDBOX_PROCESS_ENTRY Entries[SANDBOX_MAX_TRACKED_PIDS];
} SANDBOX_PROCESS_LIST;

typedef struct _SANDBOX_WFP_POLICY_INFO {
    WCHAR BoxName[SANDBOX_MAX_BOX];
    ULONG ProcessId;
    ULONG Enabled;
    ULONG VnicIp;
    ULONG _pad;
} SANDBOX_WFP_POLICY_INFO;

static void
PrintUsage(void)
{
    printf("Usage:\n"
        "  RevDrvCtl set <PID> <vnic_ip> [box_name]\n"
        "  RevDrvCtl unset <PID> [box_name]\n"
        "  RevDrvCtl clear <PID> [box_name]\n"
        "  RevDrvCtl list\n");
}

static BOOL
ParseIpv4(const char* text, ULONG* outHostOrder)
{
    ULONG parts[4] = { 0 };
    const char* p = text;
    char* end = NULL;

    if (!text || !outHostOrder)
        return FALSE;

    for (int i = 0; i < 4; ++i) {
        unsigned long value;

        if (*p == '\0')
            return FALSE;

        value = strtoul(p, &end, 10);
        if (end == p || value > 255)
            return FALSE;

        parts[i] = (ULONG)value;
        if (i < 3) {
            if (*end != '.')
                return FALSE;
            p = end + 1;
        }
        else if (*end != '\0') {
            return FALSE;
        }
    }

    *outHostOrder = (parts[0] << 24) | (parts[1] << 16) |
        (parts[2] << 8) | parts[3];
    return *outHostOrder != 0;
}

static const char*
FmtIp(ULONG hostOrder)
{
    static char buf[16];
    (void)sprintf_s(buf, sizeof(buf), "%u.%u.%u.%u",
        (hostOrder >> 24) & 0xFF,
        (hostOrder >> 16) & 0xFF,
        (hostOrder >> 8) & 0xFF,
        hostOrder & 0xFF);
    return buf;
}

static BOOL
CopyArgToWideBox(const char* src, WCHAR* dst, DWORD dstCount)
{
    int written;

    if (!dst || dstCount == 0)
        return FALSE;

    dst[0] = L'\0';
    if (!src || src[0] == '\0')
        return TRUE;

    written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        src, -1, dst, (int)dstCount);
    if (written == 0) {
        written = MultiByteToWideChar(CP_ACP, 0,
            src, -1, dst, (int)dstCount);
    }
    if (written == 0) {
        dst[0] = L'\0';
        return FALSE;
    }

    dst[dstCount - 1] = L'\0';
    return TRUE;
}

static void
WideBoxToUtf8(const WCHAR* src, char* dst, DWORD dstCount)
{
    int written;

    if (!dst || dstCount == 0)
        return;

    dst[0] = '\0';
    if (!src || src[0] == L'\0')
        return;

    written = WideCharToMultiByte(CP_UTF8, 0,
        src, -1, dst, (int)dstCount, NULL, NULL);
    if (written == 0) {
        written = WideCharToMultiByte(CP_ACP, 0,
            src, -1, dst, (int)dstCount, NULL, NULL);
    }
    if (written == 0)
        dst[0] = '\0';
    else
        dst[dstCount - 1] = '\0';
}

static BOOL
SendIoctl(
    HANDLE hDevice,
    DWORD code,
    PVOID inBuf,
    DWORD inLen,
    PVOID outBuf,
    DWORD outLen,
    DWORD* bytesReturned)
{
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(hDevice, code,
        inBuf, inLen,
        outBuf, outLen,
        &bytes, NULL);

    if (bytesReturned)
        *bytesReturned = bytes;
    return ok;
}

static int
SetWfpPolicy(HANDLE hDevice, int argc, char* argv[], BOOL enabled)
{
    SANDBOX_WFP_POLICY_INFO info;
    ULONG pid;
    ULONG vnicIp;

    if (enabled) {
        if (argc < 4) {
            fprintf(stderr, "Usage: RevDrvCtl set <PID> <vnic_ip> [box_name]\n");
            return 1;
        }
    }
    else {
        if (argc < 3) {
            fprintf(stderr, "Usage: RevDrvCtl unset <PID> [box_name]\n");
            return 1;
        }
    }

    pid = (ULONG)strtoul(argv[2], NULL, 10);
    if (pid == 0) {
        fprintf(stderr, "[!] Invalid PID: %s\n", argv[2]);
        return 1;
    }

    vnicIp = 0;
    if (enabled && !ParseIpv4(argv[3], &vnicIp)) {
        fprintf(stderr, "[!] Invalid vNIC IP: %s\n", argv[3]);
        return 1;
    }

    ZeroMemory(&info, sizeof(info));
    info.ProcessId = pid;
    info.Enabled = enabled ? 1UL : 0UL;
    info.VnicIp = enabled ? vnicIp : 0UL;

    if (!CopyArgToWideBox(enabled ? (argc >= 5 ? argv[4] : NULL)
        : (argc >= 4 ? argv[3] : NULL),
        info.BoxName, SANDBOX_MAX_BOX)) {
        fprintf(stderr, "[!] Invalid box name encoding.\n");
        return 1;
    }

    if (!SendIoctl(hDevice, IOCTL_SANDBOX_SET_WFP_POLICY,
        &info, sizeof(info), NULL, 0, NULL)) {
        DWORD err = GetLastError();
        fprintf(stderr, "[!] IOCTL_SANDBOX_SET_WFP_POLICY failed: %lu\n", err);
        if (err == ERROR_NOT_FOUND) {
            fprintf(stderr,
                "    PID is not tracked by SandboxFlt, or box_name does not match.\n"
                "    Start the process through sandbox_demo first.\n");
        }
        return 1;
    }

    if (enabled) {
        printf("[+] SandboxFlt WFP enabled: root PID %lu -> vNIC %s\n",
            pid, FmtIp(vnicIp));
    }
    else {
        printf("[+] SandboxFlt WFP disabled for root PID %lu\n", pid);
    }
    return 0;
}

static int
ListProcesses(HANDLE hDevice)
{
    SANDBOX_PROCESS_LIST list;
    DWORD bytes = 0;

    ZeroMemory(&list, sizeof(list));
    if (!SendIoctl(hDevice, IOCTL_SANDBOX_QUERY_PROCESSES,
        NULL, 0, &list, sizeof(list), &bytes)) {
        fprintf(stderr, "[!] IOCTL_SANDBOX_QUERY_PROCESSES failed: %lu\n",
            GetLastError());
        return 1;
    }

    printf("Tracked PIDs: %lu\n", list.Count);
    printf("%-8s %-8s %-8s %-6s %-15s %-6s %s\n",
        "PID", "Parent", "Root", "WFP", "vNIC", "Seen", "Box");

    for (ULONG i = 0; i < list.Count && i < SANDBOX_MAX_TRACKED_PIDS; ++i) {
        const SANDBOX_PROCESS_ENTRY* e = &list.Entries[i];
        char boxName[SANDBOX_MAX_BOX * 4] = { 0 };
        WideBoxToUtf8(e->BoxName, boxName, sizeof(boxName));

        printf("%-8lu %-8lu %-8lu %-6s %-15s %-6s %s\n",
            e->ProcessId,
            e->ParentProcessId,
            e->RootProcessId,
            e->WfpEnabled ? "on" : "off",
            e->WfpEnabled ? FmtIp(e->WfpVnicIp) : "-",
            e->WfpNetworkSeen ? "yes" : "no",
            boxName);
    }

    return 0;
}

int main(int argc, char* argv[])
{
    HANDLE hDevice;
    int exitCode;

    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    hDevice = CreateFileA(
        SANDBOX_WIN32_DEVICE,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        fprintf(stderr,
            "[!] Cannot open %s (error %lu)\n"
            "    Is sandboxflt.sys loaded? Try loading SandboxFlt first.\n",
            SANDBOX_WIN32_DEVICE,
            GetLastError());
        return 1;
    }

    if (_stricmp(argv[1], "set") == 0) {
        exitCode = SetWfpPolicy(hDevice, argc, argv, TRUE);
    }
    else if (_stricmp(argv[1], "unset") == 0 ||
        _stricmp(argv[1], "clear") == 0) {
        exitCode = SetWfpPolicy(hDevice, argc, argv, FALSE);
    }
    else if (_stricmp(argv[1], "list") == 0 ||
        _stricmp(argv[1], "query") == 0) {
        exitCode = ListProcesses(hDevice);
    }
    else {
        fprintf(stderr, "[!] Unknown command: %s\n", argv[1]);
        PrintUsage();
        exitCode = 1;
    }

    CloseHandle(hDevice);
    return exitCode;
}
