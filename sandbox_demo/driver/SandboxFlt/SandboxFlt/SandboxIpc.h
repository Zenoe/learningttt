#pragma once
// ============================================================
//  SandboxIpc.h  —  Shared between SandboxFlt.sys and Qt app
//
//  ALL structures in this file must be identical in both
//  kernel and user mode compilation units.
//  Use only fixed-width types; no pointers.
// ============================================================
#ifdef _KERNEL_MODE
    // 内核模式驱动编译时
#include <ntddk.h>
#else
#include <winioctl.h>
#endif

//
// Device name the driver exposes to user mode
//
#define SANDBOX_DEVICE_NAME     L"\\Device\\SandboxFlt"
#define SANDBOX_DOS_DEVICE_NAME L"\\DosDevices\\SandboxFlt"
#define SANDBOX_WIN32_DEVICE    L"\\\\.\\SandboxFlt"

//
// Maximum lengths (in WCHARs, excluding null terminator)
//
#define SANDBOX_MAX_PATH   512
#define SANDBOX_MAX_BOX    64
#define SANDBOX_MAX_RULES  32
#define SANDBOX_MAX_TRACKED_PIDS 256

// ============================================================
//  IOCTL codes
//  Method = METHOD_BUFFERED for simplicity
// ============================================================
#define SANDBOX_IOCTL_BASE          0x8000

#define IOCTL_SANDBOX_ADD_BOX       CTL_CODE(FILE_DEVICE_UNKNOWN, \
    SANDBOX_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SANDBOX_REMOVE_BOX    CTL_CODE(FILE_DEVICE_UNKNOWN, \
    SANDBOX_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SANDBOX_ADD_PROCESS   CTL_CODE(FILE_DEVICE_UNKNOWN, \
    SANDBOX_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SANDBOX_REMOVE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, \
    SANDBOX_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SANDBOX_QUERY_STATS   CTL_CODE(FILE_DEVICE_UNKNOWN, \
    SANDBOX_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SANDBOX_SET_POLICY    CTL_CODE(FILE_DEVICE_UNKNOWN, \
    SANDBOX_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SANDBOX_QUERY_PROCESSES CTL_CODE(FILE_DEVICE_UNKNOWN, \
    SANDBOX_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================
//  Structures
// ============================================================

//
// One sandbox "box" descriptor.
// Tells the driver: any PID in this box → redirect writes
// from RealRootNt to SandboxRootNt.
//
// NOTE: No #pragma pack — all fields are WCHAR arrays or ULONG,
// naturally 2- or 4-byte aligned. Packing would misalign kernel
// structs (ERESOURCE, LIST_ENTRY) that include this header.

typedef struct _SANDBOX_BOX_INFO {
    WCHAR  BoxName[SANDBOX_MAX_BOX];           // e.g. L"Box0"
    WCHAR  SandboxRootNt[SANDBOX_MAX_PATH];    // volume-relative e.g. L"\\SandboxDemo\\Box0\\drive"
    WCHAR  RealRootNt[SANDBOX_MAX_PATH];       // volume-relative e.g. L"\\"
} SANDBOX_BOX_INFO, * PSANDBOX_BOX_INFO;

//
// Register / unregister a PID with a named box
//
typedef struct _SANDBOX_PROCESS_INFO {
    WCHAR  BoxName[SANDBOX_MAX_BOX];
    ULONG  ProcessId;
    ULONG  _pad;                               // explicit pad: keep 8-byte aligned
} SANDBOX_PROCESS_INFO, * PSANDBOX_PROCESS_INFO;

//
// Runtime statistics the driver maintains
//
typedef struct _SANDBOX_STATS {
    ULONG  TotalBoxes;
    ULONG  TotalTrackedPids;
    ULONG  TotalRedirects;
    ULONG  TotalBlocked;
    ULONG  TotalPassThrough;
    ULONG  _pad;
    WCHAR  LastRedirectedPath[SANDBOX_MAX_PATH];
} SANDBOX_STATS, * PSANDBOX_STATS;

//
// Driver-side process tree snapshot. Root launcher PIDs are registered by
// user mode; child PIDs are inherited through process-create notifications.
//
typedef struct _SANDBOX_PROCESS_ENTRY {
    ULONG  ProcessId;
    ULONG  ParentProcessId;
    ULONG  RootProcessId;
    WCHAR  BoxName[SANDBOX_MAX_BOX];
} SANDBOX_PROCESS_ENTRY, * PSANDBOX_PROCESS_ENTRY;

typedef struct _SANDBOX_PROCESS_LIST {
    ULONG                 Count;
    ULONG                 _pad;
    SANDBOX_PROCESS_ENTRY Entries[SANDBOX_MAX_TRACKED_PIDS];
} SANDBOX_PROCESS_LIST, * PSANDBOX_PROCESS_LIST;

//
// Per-box write policy
//
typedef enum _SANDBOX_WRITE_POLICY {
    SandboxPolicy_Redirect = 0,
    SandboxPolicy_Block = 1,
    SandboxPolicy_PassThrough = 2
} SANDBOX_WRITE_POLICY;

typedef struct _SANDBOX_POLICY_INFO {
    WCHAR                BoxName[SANDBOX_MAX_BOX];
    ULONG                WritePolicy;          // use ULONG not enum for cross-compile safety
    ULONG                RedirectReads;
    ULONG                HideHostFiles;
} SANDBOX_POLICY_INFO, * PSANDBOX_POLICY_INFO;
