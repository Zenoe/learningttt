#pragma once

//
// WFP source-IP forcing driver.
// Root PIDs are registered from user mode with a local vNIC IP. Child PIDs are
// inherited in kernel through process-create notifications. At bind time, only
// tracked PIDs that actually perform network I/O are rewritten.
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
// IOCTL_WFPREDIR_ADD_PROCESS
//   Input:  WFPREDIR_PROCESS_INPUT
//   Effect: Add/update a root PID and its per-tree vNIC source IP.
//
#define IOCTL_WFPREDIR_ADD_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// IOCTL_WFPREDIR_REMOVE_PROCESS
//   Input:  ULONG rootPid
//   Effect: Remove the root PID and all inherited children from the table.
//
#define IOCTL_WFPREDIR_REMOVE_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// IOCTL_WFPREDIR_CLEAR
//   Input:  none
//   Effect: Disable all redirection; clear the PID table.
//
#define IOCTL_WFPREDIR_CLEAR \
    CTL_CODE(FILE_DEVICE_UNKNOWN, WFPREDIR_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------
// Shared structures
// ---------------------------------------------------------------
#define WFPREDIR_MAX_BOX 64
#define WFPREDIR_MAX_TRACKED_PIDS 4096

typedef struct _WFPREDIR_PROCESS_INPUT
{
    ULONG ProcessId;
    ULONG VnicIp;  // host byte order, e.g. 0x0A080004 for 10.8.0.4
    WCHAR BoxName[WFPREDIR_MAX_BOX];
} WFPREDIR_PROCESS_INPUT, *PWFPREDIR_PROCESS_INPUT;

typedef struct _WFPREDIR_PID_ENTRY
{
    ULONG ProcessId;
    ULONG ParentProcessId;
    ULONG RootProcessId;
    ULONG VnicIp;
    ULONG NetworkSeen;
    WCHAR BoxName[WFPREDIR_MAX_BOX];
} WFPREDIR_PID_ENTRY, *PWFPREDIR_PID_ENTRY;

// ---------------------------------------------------------------
// PID table API
// ---------------------------------------------------------------
#ifdef _KERNEL_MODE_   // only expose storage in kernel compilation units
NTSTATUS WfpPidTableInitialize(VOID);
VOID     WfpPidTableClear(VOID);
NTSTATUS WfpPidAddRoot(_In_ const WFPREDIR_PROCESS_INPUT* Input);
NTSTATUS WfpPidRemoveTree(_In_ ULONG RootPid);
BOOLEAN  WfpPidFindAndMarkNetwork(_In_ ULONG Pid, _Out_ WFPREDIR_PID_ENTRY* Entry);
BOOLEAN  WfpPidIsProtectedVnicIp(_In_ ULONG VnicIp);
VOID     WfpRedirProcessNotify(
    _Inout_  PEPROCESS Process,
    _In_     HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
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
