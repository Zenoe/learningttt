///////////////////////////////////////////////////////////////////////////////
//
// wfpredir_ctrl.c  —  User-mode control tool
//
// Usage:
//   wfpredir_ctrl set <PID> <dest_ip>
//       Add <PID> as a source-IP-forcing root and bind its process tree to
//       <dest_ip> when sockets bind to INADDR_ANY.
//       Non-target PIDs that explicitly bind to <dest_ip> are reset to
//       INADDR_ANY by the driver.
//
//   wfpredir_ctrl unset <PID>
//       Remove <PID> and its inherited children from source-IP forcing.
//
//   wfpredir_ctrl clear
//       Disable all redirection.
//
// Example:
//   wfpredir_ctrl set 1234 10.8.0.2
//   wfpredir_ctrl unset 1234
//
///////////////////////////////////////////////////////////////////////////////

// Must come before any Windows headers
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winioctl.h>   // ← 新增：提供 FILE_DEVICE_UNKNOWN、CTL_CODE 等
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Link with Winsock

#pragma comment(lib, "ws2_32.lib")

// ---------------------------------------------------------------
// Replicate the shared IOCTL definitions here so that the control
// tool can be compiled without the WDK headers.
// ---------------------------------------------------------------
#define WFPREDIR_IOCTL_BASE   0x8000

#define IOCTL_WFPREDIR_ADD_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WFPREDIR_REMOVE_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WFPREDIR_CLEAR \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define WFPREDIR_MAX_BOX 64

typedef struct _WFPREDIR_PROCESS_INPUT
{
    ULONG ProcessId;
    ULONG VnicIp;
    WCHAR BoxName[WFPREDIR_MAX_BOX];
} WFPREDIR_PROCESS_INPUT;

// ---------------------------------------------------------------
// Parse "a.b.c.d" → ULONG host byte order
// ---------------------------------------------------------------
static BOOL
ParseIpv4(const char* str, ULONG* outHostOrder)
{
    struct in_addr addr = { 0 };
    // inet_pton returns 1 on success; result is in network byte order
    if (inet_pton(AF_INET, str, &addr) != 1)
        return FALSE;
    // Convert to host byte order
    *outHostOrder = ntohl(addr.s_addr);
    return TRUE;
}

// ---------------------------------------------------------------
// Format a host-byte-order IPv4 address into a static buffer.
// Not thread-safe, but fine for a single-threaded CLI tool.
// ---------------------------------------------------------------
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

// ---------------------------------------------------------------
// SendIoctl  – thin wrapper around DeviceIoControl
// ---------------------------------------------------------------
static BOOL
SendIoctl(
    HANDLE hDevice,
    DWORD  code,
    PVOID  inBuf,
    DWORD  inLen
)
{
    DWORD bytesReturned = 0;
    return DeviceIoControl(hDevice, code, inBuf, inLen,
        NULL, 0, &bytesReturned, NULL);
}

// ---------------------------------------------------------------
// main
// ---------------------------------------------------------------
int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("Usage:\n"
            "  wfpredir_ctrl set <PID> <dest_ip>\n"
            "  wfpredir_ctrl unset <PID>\n"
            "  wfpredir_ctrl clear\n");
        return 1;
    }

    // Initialise Winsock (needed for inet_pton / ntohl)
    WSADATA wsa = { 0 };
    WSAStartup(MAKEWORD(2, 2), &wsa);

    // Open the driver device
    HANDLE hDevice = CreateFileA(
        "\\\\.\\WfpRedirect",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr,
            "[!] Cannot open \\\\.\\WfpRedirect  (error %lu)\n"
            "    Is the driver loaded?  Run: sc start WfpRedirect\n",
            GetLastError());
        WSACleanup();
        return 1;
    }

    int exitCode = 0;

    if (_stricmp(argv[1], "set") == 0)
    {
        // ------------------------------------------------------------
        // "set <PID> <dest_ip>"
        // ------------------------------------------------------------
        if (argc < 4)
        {
            fprintf(stderr, "Usage: wfpredir_ctrl set <PID> <dest_ip>\n");
            exitCode = 1;
            goto Cleanup;
        }

        ULONG pid = (ULONG)strtoul(argv[2], NULL, 10);
        ULONG destIp = 0;

        if (!ParseIpv4(argv[3], &destIp))
        {
            fprintf(stderr, "[!] Invalid IP address: %s\n", argv[3]);
            exitCode = 1;
            goto Cleanup;
        }

        WFPREDIR_PROCESS_INPUT input = { 0 };
        input.ProcessId = pid;
        input.VnicIp = destIp;
        wcscpy_s(input.BoxName, WFPREDIR_MAX_BOX, L"(cli)");

        // ---- Add the root PID and source IP atomically ----
        if (!SendIoctl(hDevice, IOCTL_WFPREDIR_ADD_PROCESS, &input, sizeof(input)))
        {
            fprintf(stderr, "[!] IOCTL_WFPREDIR_ADD_PROCESS failed: %lu\n",
                GetLastError());
            exitCode = 1;
            goto Cleanup;
        }
        printf("[+] Forcing PID %lu source IP to %s\n"
            "    Non-target PIDs binding to %s will be reset to 0.0.0.0\n"
            "    Watch DebugView for per-connection logs.\n",
            pid, argv[3], argv[3]);
    }
    else if (_stricmp(argv[1], "unset") == 0)
    {
        // ------------------------------------------------------------
        // "unset <PID>"
        // ------------------------------------------------------------
        if (argc < 3)
        {
            fprintf(stderr, "Usage: wfpredir_ctrl unset <PID>\n");
            exitCode = 1;
            goto Cleanup;
        }

        ULONG pid = (ULONG)strtoul(argv[2], NULL, 10);
        if (pid == 0)
        {
            fprintf(stderr, "[!] Invalid PID: %s\n", argv[2]);
            exitCode = 1;
            goto Cleanup;
        }

        if (!SendIoctl(hDevice, IOCTL_WFPREDIR_REMOVE_PROCESS, &pid, sizeof(pid)))
        {
            DWORD err = GetLastError();
            if (err == ERROR_NOT_FOUND)
            {
                printf("[+] PID %lu was not registered.\n", pid);
            }
            else
            {
                fprintf(stderr, "[!] IOCTL_WFPREDIR_REMOVE_PROCESS failed: %lu\n", err);
                exitCode = 1;
                goto Cleanup;
            }
        }
        else
        {
            printf("[+] Removed source-IP forcing for PID tree root %lu.\n", pid);
        }
    }
    else if (_stricmp(argv[1], "clear") == 0)
    {
        // ------------------------------------------------------------
        // "clear"
        // ------------------------------------------------------------
        if (!SendIoctl(hDevice, IOCTL_WFPREDIR_CLEAR, NULL, 0))
        {
            fprintf(stderr, "[!] IOCTL_WFPREDIR_CLEAR failed: %lu\n",
                GetLastError());
            exitCode = 1;
            goto Cleanup;
        }
        printf("[+] Redirection cleared.\n");
    }
    else
    {
        fprintf(stderr, "[!] Unknown command: %s\n", argv[1]);
        exitCode = 1;
    }

Cleanup:
    CloseHandle(hDevice);
    WSACleanup();
    return exitCode;
}
