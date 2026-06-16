///////////////////////////////////////////////////////////////////////////////
//
// wfpredir_ctrl.c  —  User-mode control tool
//
// Usage:
//   wfpredir_ctrl set <PID> <dest_ip>
//       Start redirecting <PID> to <dest_ip>.
//       The real default-route IP (lowest-metric route) is resolved
//       automatically from the IP routing table and sent to the driver
//       as the "defaultIp" so the kernel can safely re-bind any
//       non-matching PID that accidentally grabs <dest_ip>.
//
//   wfpredir_ctrl clear
//       Disable all redirection.
//
// Example:
//   wfpredir_ctrl set 1234 10.8.0.2
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
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef MAXULONG
#define MAXULONG  ((ULONG)(~0UL))   // 0xFFFFFFFF
#endif

// Link with Ip Helper and Winsock

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// ---------------------------------------------------------------
// Replicate the shared IOCTL definitions here so that the control
// tool can be compiled without the WDK headers.
// ---------------------------------------------------------------
#define WFPREDIR_IOCTL_BASE   0x8000

#define IOCTL_WFPREDIR_SET_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WFPREDIR_IP_PAIR \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WFPREDIR_CLEAR \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Must match kernel-side definition exactly (pragma pack(push,1))
#pragma pack(push, 1)
typedef struct _WFPREDIR_IP_PAIR_INPUT
{
    ULONG DestIp;      // VPN / tunnel IP    (host byte order)
    ULONG DefaultIp;   // Real default NIC IP (host byte order)
} WFPREDIR_IP_PAIR_INPUT;
#pragma pack(pop)

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
// GetDefaultRouteNextHopIp
//
// Enumerates all IPv4 unicast routes and returns the next-hop
// (gateway) IP of the route with:
//   - destination prefix 0.0.0.0/0  (default route)
//   - lowest metric
//
// Falls back to the interface address itself if the gateway is
// 0.0.0.0 (on-link route).
//
// Returns TRUE and sets *outHostOrder on success.
// Returns FALSE on failure and prints the Win32 error.
// ---------------------------------------------------------------
static BOOL
GetDefaultRouteNextHopIp(ULONG* outHostOrder)
{
    // We call GetIpForwardTable2 which requires Vista+.
    // Dynamically load so the binary doesn't hard-fail on XP (rare concern
    // for a driver tool, but keeps linking clean).
    typedef DWORD(WINAPI* PFN_GetIpForwardTable2)(ADDRESS_FAMILY, PMIB_IPFORWARD_TABLE2*);
    typedef VOID(WINAPI* PFN_FreeMibTable)(PVOID);

    HMODULE hIphlp = GetModuleHandleA("iphlpapi.dll");
    if (!hIphlp) hIphlp = LoadLibraryA("iphlpapi.dll");
    if (!hIphlp)
    {
        fprintf(stderr, "[!] Cannot load iphlpapi.dll\n");
        return FALSE;
    }

    PFN_GetIpForwardTable2 pfnGet =
        (PFN_GetIpForwardTable2)GetProcAddress(hIphlp, "GetIpForwardTable2");
    PFN_FreeMibTable       pfnFree =
        (PFN_FreeMibTable)GetProcAddress(hIphlp, "FreeMibTable");

    if (!pfnGet || !pfnFree)
    {
        fprintf(stderr, "[!] GetIpForwardTable2 not available (Vista+ required)\n");
        return FALSE;
    }

    PMIB_IPFORWARD_TABLE2 table = NULL;
    DWORD err = pfnGet(AF_INET, &table);
    if (err != NO_ERROR)
    {
        fprintf(stderr, "[!] GetIpForwardTable2 failed: %lu\n", err);
        return FALSE;
    }

    ULONG  bestMetric = MAXULONG;
    ULONG  bestNextHop = 0;
    BOOL   found = FALSE;

    for (ULONG i = 0; i < table->NumEntries; i++)
    {
        MIB_IPFORWARD_ROW2* row = &table->Table[i];

        // We want only 0.0.0.0/0 (default route)
        if (row->DestinationPrefix.PrefixLength != 0)
            continue;
        if (row->DestinationPrefix.Prefix.si_family != AF_INET)
            continue;
        if (row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr != 0)
            continue;

        ULONG metric = row->Metric;

        if (!found || metric < bestMetric)
        {
            bestMetric = metric;
            // NextHop 0.0.0.0 means "on-link"; use interface address instead
            ULONG nhNet = row->NextHop.Ipv4.sin_addr.s_addr; // network byte order
            if (nhNet != 0)
            {
                bestNextHop = ntohl(nhNet); // convert to host byte order
            }
            else
            {
                // Resolve the on-link interface address
                MIB_IFROW ifRow = { 0 };
                ifRow.dwIndex = row->InterfaceIndex;
                if (GetIfEntry(&ifRow) == NO_ERROR)
                {
                    // GetIfEntry doesn't give us the IP; use GetAdaptersAddresses
                    IP_ADAPTER_ADDRESSES  hint = { 0 };
                    ULONG                 bufSz = 0;
                    GetAdaptersAddresses(AF_INET,
                        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                        GAA_FLAG_SKIP_DNS_SERVER,
                        NULL, &hint, &bufSz);

                    PIP_ADAPTER_ADDRESSES pAdapters = (PIP_ADAPTER_ADDRESSES)malloc(bufSz);
                    if (pAdapters)
                    {
                        if (GetAdaptersAddresses(AF_INET,
                            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                            GAA_FLAG_SKIP_DNS_SERVER,
                            NULL, pAdapters, &bufSz) == NO_ERROR)
                        {
                            for (PIP_ADAPTER_ADDRESSES a = pAdapters; a; a = a->Next)
                            {
                                if (a->IfIndex != row->InterfaceIndex)
                                    continue;
                                for (PIP_ADAPTER_UNICAST_ADDRESS u = a->FirstUnicastAddress;
                                    u; u = u->Next)
                                {
                                    SOCKADDR_IN* sa =
                                        (SOCKADDR_IN*)u->Address.lpSockaddr;
                                    if (sa->sin_family == AF_INET)
                                    {
                                        bestNextHop = ntohl(sa->sin_addr.s_addr);
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                        free(pAdapters);
                    }
                }
            }
            found = TRUE;
        }
    }

    pfnFree(table);

    if (!found || bestNextHop == 0)
    {
        fprintf(stderr, "[!] No usable default route found in the routing table.\n");
        return FALSE;
    }

    *outHostOrder = bestNextHop;
    return TRUE;
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

        // Resolve the real default-route IP automatically
        ULONG defaultIp = 0;
        if (!GetDefaultRouteNextHopIp(&defaultIp))
        {
            fprintf(stderr,
                "[!] Could not determine default-route IP.\n"
                "    Redirection would leave non-target PIDs unable to\n"
                "    bind to %s.  Aborting.\n", argv[3]);
            exitCode = 1;
            goto Cleanup;
        }

        printf("[*] Default-route IP resolved to: %s\n", FmtIp(defaultIp));

        // Safety: if both IPs are the same the redirect is a no-op
        if (destIp == defaultIp)
        {
            fprintf(stderr,
                "[!] dest_ip (%s) and default-route IP (%s) are identical.\n"
                "    Nothing to redirect.\n",
                FmtIp(destIp), FmtIp(defaultIp));
            exitCode = 1;
            goto Cleanup;
        }

        // ---- Send IOCTL_WFPREDIR_IP_PAIR (both IPs in one shot) ----
        WFPREDIR_IP_PAIR_INPUT pair = { destIp, defaultIp };

        if (!SendIoctl(hDevice, IOCTL_WFPREDIR_IP_PAIR, &pair, sizeof(pair)))
        {
            fprintf(stderr, "[!] IOCTL_WFPREDIR_IP_PAIR failed: %lu\n",
                GetLastError());
            exitCode = 1;
            goto Cleanup;
        }
        printf("[+] IP pair set:  dest=%s  default=%s\n",
            FmtIp(destIp), FmtIp(defaultIp));

        // ---- Activate by setting the target PID ----
        if (!SendIoctl(hDevice, IOCTL_WFPREDIR_SET_PID, &pid, sizeof(pid)))
        {
            fprintf(stderr, "[!] IOCTL_WFPREDIR_SET_PID failed: %lu\n",
                GetLastError());
            exitCode = 1;
            goto Cleanup;
        }
        printf("[+] Redirecting PID %lu  -->  %s\n"
            "    Non-target PIDs binding to %s will be re-bound to %s\n"
            "    Watch DebugView for per-connection logs.\n",
            pid, argv[3], argv[3], FmtIp(defaultIp));
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