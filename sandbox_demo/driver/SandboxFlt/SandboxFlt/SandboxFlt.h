#pragma once
// ============================================================
//  SandboxFlt.h  -  Kernel-internal definitions
//  NOT included from user mode code.
// ============================================================
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "SandboxIpc.h"

// ============================================================
//  Pool tag  ('SbFl' reversed = 'lFbS')
// ============================================================
#define SANDBOX_POOL_TAG  'lFbS'

// ============================================================
//  ERESOURCE helper macros
//  ExAcquireResourceXxxLite requires:
//    - IRQL <= APC_LEVEL
//    - APCs disabled (KeEnterCriticalRegion)
//  Always pair ACQUIRE/RELEASE with ENTER/LEAVE.
// ============================================================
#define SbAcquireExclusive(res) \
    KeEnterCriticalRegion(); \
    ExAcquireResourceExclusiveLite((res), TRUE)

#define SbAcquireShared(res) \
    KeEnterCriticalRegion(); \
    ExAcquireResourceSharedLite((res), TRUE)

#define SbRelease(res) \
    ExReleaseResourceLite((res)); \
    KeLeaveCriticalRegion()

// ============================================================
//  Per-box runtime entry (kernel heap)
// ============================================================
typedef struct _BOX_ENTRY {
    LIST_ENTRY      ListEntry;
    UNICODE_STRING  BoxName;
    UNICODE_STRING  SandboxRootNt;
    UNICODE_STRING  RealRootNt;
    SANDBOX_WRITE_POLICY WritePolicy;
    BOOLEAN         RedirectReads;
    BOOLEAN         HideHostFiles;
    ULONG           CacheGeneration;
    WCHAR           BoxNameBuf[SANDBOX_MAX_BOX];
    WCHAR           SandboxRootBuf[SANDBOX_MAX_PATH];
    WCHAR           RealRootBuf[SANDBOX_MAX_PATH];
} BOX_ENTRY, * PBOX_ENTRY;

// ============================================================
//  Per-PID tracking entry (kernel heap)
// ============================================================
typedef struct _PID_ENTRY {
    LIST_ENTRY  ListEntry;
    HANDLE      ProcessId;
    HANDLE      ParentProcessId;
    HANDLE      RootProcessId;
    PBOX_ENTRY  Box;
} PID_ENTRY, * PPID_ENTRY;

typedef struct _DIR_MERGE_CONTEXT {
    PFILE_OBJECT SandboxFileObject;
    HANDLE       SandboxHandle;
    BOOLEAN      SandboxStarted;
    BOOLEAN      SandboxDone;
} DIR_MERGE_CONTEXT, * PDIR_MERGE_CONTEXT;

// ============================================================
//  Global driver context
// ============================================================
typedef struct _SANDBOX_GLOBALS {
    PFLT_FILTER     FilterHandle;
    PDEVICE_OBJECT  ControlDevice;
    PDRIVER_OBJECT  DriverObject;

    LIST_ENTRY      BoxList;
    ERESOURCE       BoxLock;

    LIST_ENTRY      PidList;
    ERESOURCE       PidLock;

    volatile LONG   TotalRedirects;
    volatile LONG   TotalBlocked;
    volatile LONG   TotalPassThrough;

    WCHAR           LastRedirectedPath[SANDBOX_MAX_PATH];
    KSPIN_LOCK      LastRedirectedPathLock;   // guards LastRedirectedPath
    BOOLEAN         ProcessNotifyRegistered;
} SANDBOX_GLOBALS, * PSANDBOX_GLOBALS;

extern SANDBOX_GLOBALS g_Sandbox;

// ============================================================
//  C-compatible const pointer helpers
//  PCUNICODE_STRING is already defined in WDK headers as
//  "const UNICODE_STRING *" but SAL annotations on packed
//  struct pointers can confuse the C front-end in some WDK
//  versions.  Use explicit spellings in every prototype.
// ============================================================
#ifndef _CONST_UNICODE_STRING_DEFINED
#define _CONST_UNICODE_STRING_DEFINED
typedef const UNICODE_STRING* PC_UNICODE_STRING;
#endif

// ============================================================
//  Function prototypes
// ============================================================

// Entry / cleanup
DRIVER_INITIALIZE DriverEntry;
NTSTATUS SandboxFlt_Unload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags);

// Filter callbacks
FLT_PREOP_CALLBACK_STATUS
SandboxFlt_PreCreate(
    _Inout_  PFLT_CALLBACK_DATA              Data,
    _In_     PCFLT_RELATED_OBJECTS           FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext);

FLT_POSTOP_CALLBACK_STATUS
SandboxFlt_PostCreate(
    _Inout_  PFLT_CALLBACK_DATA              Data,
    _In_     PCFLT_RELATED_OBJECTS           FltObjects,
    _In_opt_ PVOID                           CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS        Flags);

FLT_PREOP_CALLBACK_STATUS
SandboxFlt_PreDirectoryControl(
    _Inout_  PFLT_CALLBACK_DATA              Data,
    _In_     PCFLT_RELATED_OBJECTS           FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext);

FLT_POSTOP_CALLBACK_STATUS
SandboxFlt_PostDirectoryControl(
    _Inout_  PFLT_CALLBACK_DATA              Data,
    _In_     PCFLT_RELATED_OBJECTS           FltObjects,
    _In_opt_ PVOID                           CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS        Flags);

VOID
SandboxFlt_DirMergeContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType);

// NtQueryAttributesFile fast-path — force slow path for sandboxed PIDs
FLT_PREOP_CALLBACK_STATUS
SandboxFlt_PreNetworkQueryOpen(
    _Inout_  PFLT_CALLBACK_DATA              Data,
    _In_     PCFLT_RELATED_OBJECTS           FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext);

// IOCTL dispatch
NTSTATUS SandboxFlt_DispatchCreate(
    _In_ PDEVICE_OBJECT DevObj,
    _In_ PIRP           Irp);

NTSTATUS SandboxFlt_DispatchClose(
    _In_ PDEVICE_OBJECT DevObj,
    _In_ PIRP           Irp);

NTSTATUS SandboxFlt_DispatchIoctl(
    _In_ PDEVICE_OBJECT DevObj,
    _In_ PIRP           Irp);

// Box management
//   Use struct pointer directly (avoids SAL/packed-typedef issue)
NTSTATUS Box_Add(
    _In_ struct _SANDBOX_BOX_INFO* Info);

NTSTATUS Box_Remove(
    _In_ PCWSTR BoxName);

PBOX_ENTRY Box_Find(
    _In_ PC_UNICODE_STRING BoxName);   /* caller holds BoxLock shared */

// PID management
NTSTATUS Pid_Add(
    _In_ ULONG  Pid,
    _In_ PCWSTR BoxName);

NTSTATUS Pid_Remove(
    _In_ ULONG Pid);

PPID_ENTRY Pid_Find(
    _In_ HANDLE Pid);                  /* caller holds PidLock shared */

NTSTATUS Pid_AddInherited(
    _In_ ULONG      Pid,
    _In_ ULONG      ParentPid,
    _In_ ULONG      RootPid,
    _In_ PBOX_ENTRY Box);

VOID SandboxFlt_ProcessNotify(
    _Inout_  PEPROCESS             Process,
    _In_     HANDLE                ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

ULONG Pid_CopyProcessList(
    _Out_writes_(MaxEntries) PSANDBOX_PROCESS_ENTRY Entries,
    _In_ ULONG MaxEntries);

// Path helpers
BOOLEAN Path_StartsWith(
    _In_ PC_UNICODE_STRING Full,
    _In_ PC_UNICODE_STRING Prefix);

NTSTATUS Path_BuildRedirect(
    _In_  PC_UNICODE_STRING  OriginalPath,
    _In_  PBOX_ENTRY         Box,
    _Out_ PUNICODE_STRING    RedirectedPath
  );

NTSTATUS Path_BuildRedirectRelative(
    _In_  PC_UNICODE_STRING  OriginalPath,
    _In_  PBOX_ENTRY         Box,
    _Out_ PUNICODE_STRING    RedirectedPath);

// PID bitmap — maintained by BoxMgr (Tier 1)
VOID PidBitmap_OnAdd(_In_ ULONG Pid);
VOID PidBitmap_OnRemove(_In_ ULONG Pid);

// Per-process hash table — set/clear by BoxMgr (Tier 2)
NTSTATUS Filter_SetProcContext(_In_ ULONG Pid, _In_ PBOX_ENTRY Box);
VOID     Filter_ClearProcContext(_In_ ULONG Pid);
PBOX_ENTRY Filter_GetProcContext(_In_ ULONG Pid);

// Global active-box counter (Tier 0)
extern volatile LONG g_AnyBoxActive;

// Context registration table for FLT_REGISTRATION (empty, no FLT contexts used)
const FLT_CONTEXT_REGISTRATION* Filter_GetContextReg(VOID);
