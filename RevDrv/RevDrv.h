#pragma once

//
// WFP source-IP forcing driver.
// Forces target-PID sockets that bind to INADDR_ANY to bind to a specified
// local vNIC IP instead. Non-target PIDs that explicitly bind to that vNIC IP
// are transparently re-bound to INADDR_ANY so the normal route/interface
// selection logic can run.
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
//   Effect: Begin source-IP forcing for <pid> using g_DestIp.
//
#define IOCTL_WFPREDIR_SET_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// IOCTL_WFPREDIR_SET_DEST_IP
//   Input: ULONG destIp  (host byte order)
//   Effect: Sets the local vNIC/tunnel IP used for source-IP forcing.
//
#define IOCTL_WFPREDIR_SET_DEST_IP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// IOCTL_WFPREDIR_CLEAR
//   Input:  none
//   Effect: Disable all redirection; zero all globals.
//
#define IOCTL_WFPREDIR_CLEAR \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------
// Global state  (set by IOCTL, read by callouts)
// ---------------------------------------------------------------
#ifdef _KERNEL_MODE_   // only expose storage in kernel compilation units
extern volatile LONG   g_TargetPid;   // 0  = disabled
extern volatile ULONG  g_DestIp;      // VPN IP,         host byte order
#endif

// ---------------------------------------------------------------
// GUIDs
// ---------------------------------------------------------------

// {0B83F405-5CCB-48B8-89B2-827692B39E3A}
DEFINE_GUID(WFPREDIR_BIND_CALLOUT_GUID,
0xb83f405, 0x5ccb, 0x48b8, 0x89, 0xb2, 0x82, 0x76, 0x92, 0xb3, 0x9e, 0x3a);
// {F7FA76DA-234C-4163-BC33-F0A36A70F34C}
DEFINE_GUID(WFPREDIR_SUBLAYER_GUID,
0xf7fa76da, 0x234c, 0x4163, 0xbc, 0x33, 0xf0, 0xa3, 0x6a, 0x70, 0xf3, 0x4c);
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
