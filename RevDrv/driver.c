///////////////////////////////////////////////////////////////////////////////
//
// driver.c  —  DriverEntry, IRP dispatch, unload
//
// Handles device creation and the three IOCTLs:
//   IOCTL_WFPREDIR_SET_PID    – set target PID
//   IOCTL_WFPREDIR_IP_PAIR    – set (destIp, defaultIp) atomically
//   IOCTL_WFPREDIR_CLEAR      – disable all redirection
//
///////////////////////////////////////////////////////////////////////////////

#define _KERNEL_MODE_
#include "RevDrv.h"

static PDEVICE_OBJECT  g_DeviceObject = NULL;
static UNICODE_STRING  g_DeviceName;
static UNICODE_STRING  g_SymlinkName;

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
    // IOCTL_WFPREDIR_SET_PID  –  input: ULONG pid
    // ----------------------------------------------------------------
    case IOCTL_WFPREDIR_SET_PID:
    {
        if (inputLen < sizeof(ULONG) || buffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        ULONG pid = *(ULONG*)buffer;
        InterlockedExchange(&g_TargetPid, (LONG)pid);
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
            "[WfpRedir] Target PID set to: %lu\n", pid);
        break;
    }

    // ----------------------------------------------------------------
    // IOCTL_WFPREDIR_IP_PAIR  –  input: WFPREDIR_IP_PAIR_INPUT
    //
    //  DestIp    = the VPN / tunnel IP to redirect the target PID to
    //  DefaultIp = the real default-route IP used to re-bind any
    //              non-matching PID that tries to bind to DestIp
    // ----------------------------------------------------------------
    case IOCTL_WFPREDIR_IP_PAIR:
    {
        if (inputLen < sizeof(WFPREDIR_IP_PAIR_INPUT) || buffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        WFPREDIR_IP_PAIR_INPUT pair = *(WFPREDIR_IP_PAIR_INPUT*)buffer;

        InterlockedExchange((volatile LONG*)&g_DestIp,    (LONG)pair.DestIp);
        InterlockedExchange((volatile LONG*)&g_DefaultIp, (LONG)pair.DefaultIp);

        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
            "[WfpRedir] DestIp    = %d.%d.%d.%d\n",
            (pair.DestIp    >> 24) & 0xFF, (pair.DestIp    >> 16) & 0xFF,
            (pair.DestIp    >>  8) & 0xFF,  pair.DestIp           & 0xFF);
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
            "[WfpRedir] DefaultIp = %d.%d.%d.%d\n",
            (pair.DefaultIp >> 24) & 0xFF, (pair.DefaultIp >> 16) & 0xFF,
            (pair.DefaultIp >>  8) & 0xFF,  pair.DefaultIp         & 0xFF);
        break;
    }

    // ----------------------------------------------------------------
    // IOCTL_WFPREDIR_CLEAR  –  disable everything
    // ----------------------------------------------------------------
    case IOCTL_WFPREDIR_CLEAR:
        InterlockedExchange(&g_TargetPid,              0);
        InterlockedExchange((volatile LONG*)&g_DestIp,    0);
        InterlockedExchange((volatile LONG*)&g_DefaultIp, 0);
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
            "[WfpRedir] Redirection disabled.\n");
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

    WfpRedirUnregister();
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

    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
        "[WfpRedir] Ready. Send IOCTL_WFPREDIR_SET_PID to begin.\n");
    return STATUS_SUCCESS;
}
