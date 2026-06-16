// ============================================================
//  SandboxFlt_Main.c  —  DriverEntry, filter registration,
//                         IOCTL control device, unload
//
//  Compile with WDK (not MSVC alone).
//  Build via the companion sources/dirs or CMakeLists.txt
//  that invokes the WDK toolchain.
// ============================================================
#include "SandboxFlt.h"

// ============================================================
//  Global instance
// ============================================================
SANDBOX_GLOBALS g_Sandbox = { 0 };

// ============================================================
//  Filter registration table
//
//  We register for IRP_MJ_CREATE and directory queries.
//  Pre-create: inspect the target path; if the initiating PID
//              is sandboxed, rewrite the file name to the box root.
//  Directory query post-op: host entries are returned first, then
//              matching sandbox entries are overlaid at host EOF.
// ============================================================
static const FLT_OPERATION_REGISTRATION c_Callbacks[] = {
    {
        IRP_MJ_CREATE,
        FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
        SandboxFlt_PreCreate,
        SandboxFlt_PostCreate
    },
    {
        IRP_MJ_DIRECTORY_CONTROL,
        0,
        SandboxFlt_PreDirectoryControl,
        SandboxFlt_PostDirectoryControl
    },
    {
        // NtQueryAttributesFile / NtQueryFullAttributesFile fast path.
        // Returning FLT_PREOP_DISALLOW_FASTIO forces fallback to slow
        // IRP_MJ_CREATE which our PreCreate intercepts and redirects.
        // Required so notepad's post-save file-existence check hits
        // the sandbox copy rather than the real (empty) path.
        IRP_MJ_NETWORK_QUERY_OPEN,
        0,
        SandboxFlt_PreNetworkQueryOpen,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};

static FLT_REGISTRATION c_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,                      /* ContextRegistration: filled in DriverEntry */
    c_Callbacks,
    SandboxFlt_Unload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

// ============================================================
//  DriverEntry
// ============================================================
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS          status;
    UNICODE_STRING    devName, symLink;
    PDEVICE_OBJECT    ctrlDev = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[SandboxFlt] DriverEntry\n");

    g_Sandbox.DriverObject = DriverObject;
    InitializeListHead(&g_Sandbox.BoxList);
    InitializeListHead(&g_Sandbox.PidList);

    // Initialize ERESOURCE locks
    status = ExInitializeResourceLite(&g_Sandbox.BoxLock);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SandboxFlt] ExInitializeResourceLite(BoxLock) failed: %08x\n", status);
        return status;
    }
    status = ExInitializeResourceLite(&g_Sandbox.PidLock);
    if (!NT_SUCCESS(status)) {
        ExDeleteResourceLite(&g_Sandbox.BoxLock);
        DbgPrint("[SandboxFlt] ExInitializeResourceLite(PidLock) failed: %08x\n", status);
        return status;
    }

    // --------------------------------------------------------
    //  1. Create control device object for IOCTL from user mode
    //     This is NOT a filter instance — it's a plain device
    //     the Qt app opens with CreateFile(SANDBOX_WIN32_DEVICE)
    // --------------------------------------------------------
    RtlInitUnicodeString(&devName, SANDBOX_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        0,                          // no device extension needed
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &ctrlDev);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SandboxFlt] IoCreateDevice failed: %08x\n", status);
        goto Cleanup;
    }
    ctrlDev->Flags |= DO_BUFFERED_IO;
    ctrlDev->Flags &= ~DO_DEVICE_INITIALIZING;
    g_Sandbox.ControlDevice = ctrlDev;

    // Symbolic link so user mode can open \\.\SandboxFlt
    RtlInitUnicodeString(&symLink, SANDBOX_DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SandboxFlt] IoCreateSymbolicLink failed: %08x\n", status);
        goto Cleanup;
    }

    // Set dispatch routines on our control device
    DriverObject->MajorFunction[IRP_MJ_CREATE] = SandboxFlt_DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SandboxFlt_DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SandboxFlt_DispatchIoctl;

    // --------------------------------------------------------
    //  2. Register the minifilter
    //     Wire up the instance context registration (for the
    //     per-volume box-count that enables Layer 1 fast path).
    // --------------------------------------------------------
    c_FilterRegistration.ContextRegistration = Filter_GetContextReg();

    status = FltRegisterFilter(DriverObject,
        &c_FilterRegistration,
        &g_Sandbox.FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SandboxFlt] FltRegisterFilter failed: %08x\n", status);
        goto Cleanup;
    }

    status = FltStartFiltering(g_Sandbox.FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SandboxFlt] FltStartFiltering failed: %08x\n", status);
        FltUnregisterFilter(g_Sandbox.FilterHandle);
        g_Sandbox.FilterHandle = NULL;
        goto Cleanup;
    }

    status = PsSetCreateProcessNotifyRoutineEx(SandboxFlt_ProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SandboxFlt] PsSetCreateProcessNotifyRoutineEx failed: %08x\n", status);
        FltUnregisterFilter(g_Sandbox.FilterHandle);
        g_Sandbox.FilterHandle = NULL;
        goto Cleanup;
    }
    g_Sandbox.ProcessNotifyRegistered = TRUE;

    DbgPrint("[SandboxFlt] Loaded and filtering. Device: %S\n",
        SANDBOX_DEVICE_NAME);
    return STATUS_SUCCESS;

Cleanup:
    if (g_Sandbox.ProcessNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(SandboxFlt_ProcessNotify, TRUE);
        g_Sandbox.ProcessNotifyRegistered = FALSE;
    }
    if (g_Sandbox.ControlDevice) {
        RtlInitUnicodeString(&symLink, SANDBOX_DOS_DEVICE_NAME);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_Sandbox.ControlDevice);
        g_Sandbox.ControlDevice = NULL;
    }
    ExDeleteResourceLite(&g_Sandbox.PidLock);
    ExDeleteResourceLite(&g_Sandbox.BoxLock);
    return status;
}

// ============================================================
//  Unload  — called by FltMgr when the filter is detached
// ============================================================
NTSTATUS
SandboxFlt_Unload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNICODE_STRING symLink;
    PLIST_ENTRY    entry;

    UNREFERENCED_PARAMETER(Flags);
    DbgPrint("[SandboxFlt] Unloading\n");

    if (g_Sandbox.ProcessNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(SandboxFlt_ProcessNotify, TRUE);
        g_Sandbox.ProcessNotifyRegistered = FALSE;
    }

    // Stop accepting new requests
    if (g_Sandbox.FilterHandle) {
        FltUnregisterFilter(g_Sandbox.FilterHandle);
        g_Sandbox.FilterHandle = NULL;
    }

    // Remove symbolic link + control device
    RtlInitUnicodeString(&symLink, SANDBOX_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&symLink);
    if (g_Sandbox.ControlDevice) {
        IoDeleteDevice(g_Sandbox.ControlDevice);
        g_Sandbox.ControlDevice = NULL;
    }

    // Prevent any new PreCreate callbacks from doing work while we clean up
    InterlockedExchange(&g_AnyBoxActive, 0);

    // Free all PID entries
    SbAcquireExclusive(&g_Sandbox.PidLock);
    while (!IsListEmpty(&g_Sandbox.PidList)) {
        entry = RemoveHeadList(&g_Sandbox.PidList);
        ExFreePoolWithTag(CONTAINING_RECORD(entry, PID_ENTRY, ListEntry),
            SANDBOX_POOL_TAG);
    }
    SbRelease(&g_Sandbox.PidLock);

    // Free all box entries
    SbAcquireExclusive(&g_Sandbox.BoxLock);
    while (!IsListEmpty(&g_Sandbox.BoxList)) {
        entry = RemoveHeadList(&g_Sandbox.BoxList);
        ExFreePoolWithTag(CONTAINING_RECORD(entry, BOX_ENTRY, ListEntry),
            SANDBOX_POOL_TAG);
    }
    SbRelease(&g_Sandbox.BoxLock);

    ExDeleteResourceLite(&g_Sandbox.PidLock);
    ExDeleteResourceLite(&g_Sandbox.BoxLock);

    DbgPrint("[SandboxFlt] Unloaded. Redirects=%d\n",
        g_Sandbox.TotalRedirects);
    return STATUS_SUCCESS;
}

// ============================================================
//  IOCTL dispatch — open / close / DeviceIoControl
// ============================================================
NTSTATUS
SandboxFlt_DispatchCreate(
    _In_ PDEVICE_OBJECT DevObj,
    _In_ PIRP           Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
SandboxFlt_DispatchClose(
    _In_ PDEVICE_OBJECT DevObj,
    _In_ PIRP           Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
SandboxFlt_DispatchIoctl(
    _In_ PDEVICE_OBJECT DevObj,
    _In_ PIRP           Irp)
{
    /* All locals declared at top for C89 compliance */
    PIO_STACK_LOCATION    stack;
    ULONG                 code;
    PVOID                 buf;
    ULONG                 inLen;
    ULONG                 outLen;
    NTSTATUS              status;
    ULONG_PTR             info;
    PSANDBOX_PROCESS_INFO procInfo;
    PSANDBOX_STATS        st;
    PSANDBOX_PROCESS_LIST procList;
    PSANDBOX_POLICY_INFO  polInfo;
    UNICODE_STRING        boxName;
    PBOX_ENTRY            box;
    PLIST_ENTRY           e;

    stack = IoGetCurrentIrpStackLocation(Irp);
    code = stack->Parameters.DeviceIoControl.IoControlCode;
    buf = Irp->AssociatedIrp.SystemBuffer;
    inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    status = STATUS_INVALID_DEVICE_REQUEST;
    info = 0;

    UNREFERENCED_PARAMETER(DevObj);

    switch (code) {

    case IOCTL_SANDBOX_ADD_BOX:
        if (inLen >= sizeof(SANDBOX_BOX_INFO))
            status = Box_Add((struct _SANDBOX_BOX_INFO*)buf);
        else
            status = STATUS_BUFFER_TOO_SMALL;
        break;

    case IOCTL_SANDBOX_REMOVE_BOX:
        if (inLen >= sizeof(SANDBOX_BOX_INFO))
            status = Box_Remove(((struct _SANDBOX_BOX_INFO*)buf)->BoxName);
        else
            status = STATUS_BUFFER_TOO_SMALL;
        break;

    case IOCTL_SANDBOX_ADD_PROCESS:
        if (inLen >= sizeof(SANDBOX_PROCESS_INFO)) {
            procInfo = (PSANDBOX_PROCESS_INFO)buf;
            status = Pid_Add(procInfo->ProcessId, procInfo->BoxName);
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_SANDBOX_REMOVE_PROCESS:
        if (inLen >= sizeof(SANDBOX_PROCESS_INFO)) {
            procInfo = (PSANDBOX_PROCESS_INFO)buf;
            status = Pid_Remove(procInfo->ProcessId);
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_SANDBOX_QUERY_STATS:
        if (outLen >= sizeof(SANDBOX_STATS)) {
            st = (PSANDBOX_STATS)buf;
            RtlZeroMemory(st, sizeof(*st));

            SbAcquireShared(&g_Sandbox.BoxLock);
            for (e = g_Sandbox.BoxList.Flink;
                e != &g_Sandbox.BoxList; e = e->Flink)
                st->TotalBoxes++;
            SbRelease(&g_Sandbox.BoxLock);

            SbAcquireShared(&g_Sandbox.PidLock);
            for (e = g_Sandbox.PidList.Flink;
                e != &g_Sandbox.PidList; e = e->Flink)
                st->TotalTrackedPids++;
            SbRelease(&g_Sandbox.PidLock);

            st->TotalRedirects = (ULONG)g_Sandbox.TotalRedirects;
            st->TotalBlocked = (ULONG)g_Sandbox.TotalBlocked;
            st->TotalPassThrough = (ULONG)g_Sandbox.TotalPassThrough;
            RtlCopyMemory(st->LastRedirectedPath,
                g_Sandbox.LastRedirectedPath,
                sizeof(st->LastRedirectedPath));
            info = sizeof(SANDBOX_STATS);
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_SANDBOX_QUERY_PROCESSES:
        if (outLen >= sizeof(SANDBOX_PROCESS_LIST)) {
            procList = (PSANDBOX_PROCESS_LIST)buf;
            RtlZeroMemory(procList, sizeof(*procList));
            procList->Count = Pid_CopyProcessList(
                procList->Entries,
                SANDBOX_MAX_TRACKED_PIDS);
            info = sizeof(SANDBOX_PROCESS_LIST);
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_SANDBOX_SET_POLICY:
        if (inLen >= sizeof(SANDBOX_POLICY_INFO)) {
            polInfo = (PSANDBOX_POLICY_INFO)buf;
            RtlInitUnicodeString(&boxName, polInfo->BoxName);
            SbAcquireExclusive(&g_Sandbox.BoxLock);
            box = Box_Find(&boxName);
            if (box) {
                box->WritePolicy = (SANDBOX_WRITE_POLICY)polInfo->WritePolicy;
                box->RedirectReads = (BOOLEAN)(polInfo->RedirectReads != 0);
                box->HideHostFiles = (BOOLEAN)(polInfo->HideHostFiles != 0);
                status = STATUS_SUCCESS;
            }
            else {
                status = STATUS_NOT_FOUND;
            }
            SbRelease(&g_Sandbox.BoxLock);
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
