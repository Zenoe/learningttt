#pragma once

//
// WFP Redirect Driver
// Redirects all TCP/UDP connections from a target PID to a specified IP.
// Non-matching PIDs that bind to the destination IP are transparently
// re-bound to the real default-gateway IP.
//
// Include order is critical for WDK 10.0.26100+
//

#define NDIS_SUPPORT_NDIS6  1
#define NDIS60              1

#include <ntddk.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <wsk.h>

// ---------------------------------------------------------------
// Device names
// ---------------------------------------------------------------
#define WFPREDIR_DEVICE_NAME    L"\\Device\\WfpRedirect"
#define WFPREDIR_SYMLINK_NAME   L"\\DosDevices\\WfpRedirect"

// ---------------------------------------------------------------
// IOCTLs
// ---------------------------------------------------------------
#define WFPREDIR_IOCTL_BASE     0x8000

//
// IOCTL_WFPREDIR_SET_PID
//   Input:  ULONG pid
//   Effect: Begin redirecting all traffic from <pid> to g_DestIp.
//
#define IOCTL_WFPREDIR_SET_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// IOCTL_WFPREDIR_IP_PAIR
//   Input:  WFPREDIR_IP_PAIR_INPUT { destIp, defaultIp }  (host byte order)
//   Effect: Sets both the VPN tunnel IP and the real default-route IP.
//           Non-matching PIDs that accidentally bind to destIp are
//           transparently re-bound to defaultIp instead.
//
#define IOCTL_WFPREDIR_IP_PAIR \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// IOCTL_WFPREDIR_CLEAR
//   Input:  none
//   Effect: Disable all redirection; zero all globals.
//
#define IOCTL_WFPREDIR_CLEAR \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------
// Shared structures (kernel + user mode)
// ---------------------------------------------------------------
#pragma pack(push, 1)
typedef struct _WFPREDIR_IP_PAIR_INPUT
{
    ULONG DestIp;       // VPN / tunnel IP    (host byte order, e.g. 0x0A080002)
    ULONG DefaultIp;    // Real default-route IP (host byte order, e.g. 0xC0A80101)
} WFPREDIR_IP_PAIR_INPUT, *PWFPREDIR_IP_PAIR_INPUT;
#pragma pack(pop)

// ---------------------------------------------------------------
// Global state  (set by IOCTL, read by callouts)
// ---------------------------------------------------------------
#ifdef _KERNEL_MODE_   // only expose storage in kernel compilation units
extern volatile LONG   g_TargetPid;   // 0  = disabled
extern volatile ULONG  g_DestIp;      // VPN IP,         host byte order
extern volatile ULONG  g_DefaultIp;   // Real default IP, host byte order
extern volatile USHORT g_DestPort;    // 0  = keep original port, host byte order
#endif

// ---------------------------------------------------------------
// GUIDs
// ---------------------------------------------------------------

// Connect-redirect callout  {D1E2F3A4-B5C6-7890-DEFA-123456789ABC}
// {A87CF59B-A1D0-4B20-BBCD-5940FD2AB5A9}
DEFINE_GUID(WFPREDIR_CONNECT_CALLOUT_GUID,
0xa87cf59b, 0xa1d0, 0x4b20, 0xbb, 0xcd, 0x59, 0x40, 0xfd, 0x2a, 0xb5, 0xa9);

// {0B83F405-5CCB-48B8-89B2-827692B39E3A}
DEFINE_GUID(WFPREDIR_BIND_CALLOUT_GUID,
0xb83f405, 0x5ccb, 0x48b8, 0x89, 0xb2, 0x82, 0x76, 0x92, 0xb3, 0x9e, 0x3a);
// {F7FA76DA-234C-4163-BC33-F0A36A70F34C}
DEFINE_GUID(WFPREDIR_SUBLAYER_GUID,
0xf7fa76da, 0x234c, 0x4163, 0xbc, 0x33, 0xf0, 0xa3, 0x6a, 0x70, 0xf3, 0x4c);
// {1E778837-C335-4EFA-9D7F-C8CF916AB4D8}
DEFINE_GUID(WFPREDIR_CONNECT_FILTER_GUID,
0x1e778837, 0xc335, 0x4efa, 0x9d, 0x7f, 0xc8, 0xcf, 0x91, 0x6a, 0xb4, 0xd8);
// {4FA08970-D2A6-4C92-ABEA-0F3D7AA78D3A}
DEFINE_GUID(WFPREDIR_BIND_FILTER_GUID,
0x4fa08970, 0xd2a6, 0x4c92, 0xab, 0xea, 0xf, 0x3d, 0x7a, 0xa7, 0x8d, 0x3a);

// ---------------------------------------------------------------
// Prototypes
// ---------------------------------------------------------------
DRIVER_INITIALIZE  DriverEntry;
DRIVER_UNLOAD      WfpRedirUnload;

NTSTATUS WfpRedirRegister(_In_ PDEVICE_OBJECT DeviceObject);
VOID     WfpRedirUnregister(VOID);

VOID ConnectRedirectClassify(
    _In_        const FWPS_INCOMING_VALUES0*          inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID*                                 layerData,
    _In_opt_    const VOID*                           classifyContext,
    _In_        const FWPS_FILTER1*                   filter,
    _In_        UINT64                                flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0*                   classifyOut);

VOID BindRedirectClassify(
    _In_        const FWPS_INCOMING_VALUES0*          inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID*                                 layerData,
    _In_opt_    const VOID*                           classifyContext,
    _In_        const FWPS_FILTER1*                   filter,
    _In_        UINT64                                flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0*                   classifyOut);

NTSTATUS CommonNotify(
    _In_    FWPS_CALLOUT_NOTIFY_TYPE  notifyType,
    _In_    const GUID*               filterKey,
    _Inout_ FWPS_FILTER1*             filter);
