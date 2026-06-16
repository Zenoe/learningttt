///////////////////////////////////////////////////////////////////////////////
//
// driver.c  -  DriverEntry, IRP dispatch, unload
//
// Handles device creation and the three IOCTLs:
//   IOCTL_WFPREDIR_ADD_PROCESS    - add root PID + vNIC IP
//   IOCTL_WFPREDIR_REMOVE_PROCESS - remove root PID tree
//   IOCTL_WFPREDIR_CLEAR          - clear the PID table
//
///////////////////////////////////////////////////////////////////////////////

#define _KERNEL_MODE_
#include "RevDrv.h"

static PDEVICE_OBJECT  g_DeviceObject = NULL;
static UNICODE_STRING  g_DeviceName;
static UNICODE_STRING  g_SymlinkName;
static BOOLEAN         g_ProcessNotifyRegistered = FALSE;

// ---------------------------------------------------------------
// IRP_MJ_CREATE / IRP_MJ_CLOSE
// ---------------------------------------------------------------
static NTSTATUS
DispatchCreateClose(
    _In_    PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------
// IRP_MJ_DEVICE_CONTROL
// ---------------------------------------------------------------
static NTSTATUS
DispatchIoControl(
    _In_    PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack    = IoGetCurrentIrpStackLocation(Irp);
    ULONG              ioctl    = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID              buffer   = Irp->AssociatedIrp.SystemBuffer;
    ULONG              inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS           status   = STATUS_SUCCESS;

    switch (ioctl)
    {
    // ----------------------------------------------------------------
    // IOCTL_WFPREDIR_ADD_PROCESS  -  input: WFPREDIR_PROCESS_INPUT
    // ----------------------------------------------------------------
    case IOCTL_WFPREDIR_ADD_PROCESS:
    {
        if (inputLen < sizeof(WFPREDIR_PROCESS_INPUT) || buffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = WfpPidAddRoot((const WFPREDIR_PROCESS_INPUT*)buffer);
        break;
    }

    // ----------------------------------------------------------------
    // IOCTL_WFPREDIR_REMOVE_PROCESS  -  input: ULONG rootPid
    // ----------------------------------------------------------------
    case IOCTL_WFPREDIR_REMOVE_PROCESS:
    {
        if (inputLen < sizeof(ULONG) || buffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = WfpPidRemoveTree(*(ULONG*)buffer);
        break;
    }

    // ----------------------------------------------------------------
    // IOCTL_WFPREDIR_CLEAR  -  disable everything
    // ----------------------------------------------------------------
    case IOCTL_WFPREDIR_CLEAR:
        WfpPidTableClear();
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
            "[WfpRedir] PID table cleared.\n");
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ---------------------------------------------------------------
// DriverUnload
// ---------------------------------------------------------------
VOID
WfpRedirUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
        "[WfpRedir] Unloading...\n");

    if (g_ProcessNotifyRegistered)
    {
        PsSetCreateProcessNotifyRoutineEx(WfpRedirProcessNotify, TRUE);
        g_ProcessNotifyRegistered = FALSE;
    }

    WfpRedirUnregister();
    WfpPidTableClear();
    IoDeleteSymbolicLink(&g_SymlinkName);

    if (g_DeviceObject)
    {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
        "[WfpRedir] Unloaded.\n");
}

// ---------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
        "[WfpRedir] DriverEntry.\n");

    WfpPidTableInitialize();

    RtlInitUnicodeString(&g_DeviceName, WFPREDIR_DEVICE_NAME);
    RtlInitUnicodeString(&g_SymlinkName, WFPREDIR_SYMLINK_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject);

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[WfpRedir] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymlinkName, &g_DeviceName);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[WfpRedir] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;
    DriverObject->DriverUnload                          = WfpRedirUnload;

    status = WfpRedirRegister(g_DeviceObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[WfpRedir] WfpRedirRegister failed: 0x%08X\n", status);
        WfpRedirUnregister();
        IoDeleteSymbolicLink(&g_SymlinkName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    status = PsSetCreateProcessNotifyRoutineEx(WfpRedirProcessNotify, FALSE);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[WfpRedir] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
        WfpRedirUnregister();
        IoDeleteSymbolicLink(&g_SymlinkName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        WfpPidTableClear();
        return status;
    }
    g_ProcessNotifyRegistered = TRUE;

    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
        "[WfpRedir] Ready. Add root PIDs to enable source-IP forcing.\n");
    return STATUS_SUCCESS;
}
