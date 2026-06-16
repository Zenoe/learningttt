///////////////////////////////////////////////////////////////////////////////
//
// callout.c  -  Bind-redirect source-IP forcing callout
//
//   - Target-PID sockets that bind to INADDR_ANY (0.0.0.0) are re-bound
//     to the configured vNIC IP so the OS routes their packets through it.
//   - Non-target PIDs that explicitly bind to a protected vNIC IP are re-bound to
//     INADDR_ANY so normal route/interface selection is restored.
//
///////////////////////////////////////////////////////////////////////////////

#include <initguid.h>
#define _KERNEL_MODE_
#include "RevDrv.h"

// ---------------------------------------------------------------
// WFP const-correctness adapter
//
// The WFP classify callback receives classifyContext as
// "const VOID*" (_In_opt_) because the callout must not store or
// alias the pointer past the classify call.  However the WFP API
// function FwpsAcquireClassifyHandle0 predates SAL and declares its
// first parameter as plain "void*", causing C4090 when the const
// pointer is passed directly.
//
// CLASSIFY_CONTEXT_TO_HANDLE() is the single place where the
// const is intentionally discarded.  The cast is safe because:
//   1. We never write through the pointer.
//   2. The WFP kernel itself allocated the object; it merely omitted
//      const in the Acquire prototype for historical reasons.
//   3. A compile-time assertion confirms the pointer width matches.
//
// Using a named macro (rather than a raw cast at each call site)
// makes every intentional const-discard searchable and auditable.
// ---------------------------------------------------------------
C_ASSERT(sizeof(void*) == sizeof(const void*));  // always true; guards future ABI surprises

#define CLASSIFY_CONTEXT_TO_HANDLE(ctx) \
    ((void*)(ULONG_PTR)(ctx))           // ULONG_PTR round-trip preserves the address
// without triggering C4090 or pointer-truncation

// ---------------------------------------------------------------
// Fixed PID table.
// No per-process heap allocation is used, so cleanup cannot leak memory.
// ---------------------------------------------------------------
static KSPIN_LOCK g_PidLock;
static WFPREDIR_PID_ENTRY g_PidTable[WFPREDIR_MAX_TRACKED_PIDS];
static volatile LONG g_PidCount = 0;

static LONG
PidFindIndexLocked(_In_ ULONG Pid)
{
    ULONG i;

    if (Pid == 0)
        return -1;

    for (i = 0; i < WFPREDIR_MAX_TRACKED_PIDS; ++i) {
        if (g_PidTable[i].ProcessId == Pid)
            return (LONG)i;
    }
    return -1;
}

static LONG
PidFindFreeIndexLocked(VOID)
{
    ULONG i;

    for (i = 0; i < WFPREDIR_MAX_TRACKED_PIDS; ++i) {
        if (g_PidTable[i].ProcessId == 0)
            return (LONG)i;
    }
    return -1;
}

static VOID
PidCopyBoxName(
    _Out_writes_(WFPREDIR_MAX_BOX) WCHAR* Dest,
    _In_reads_(WFPREDIR_MAX_BOX) const WCHAR* Source)
{
    ULONG i;

    for (i = 0; i < WFPREDIR_MAX_BOX - 1; ++i) {
        Dest[i] = Source[i];
        if (Source[i] == L'\0')
            return;
    }
    Dest[WFPREDIR_MAX_BOX - 1] = L'\0';
}

static NTSTATUS
PidAddLocked(
    _In_ ULONG Pid,
    _In_ ULONG ParentPid,
    _In_ ULONG RootPid,
    _In_ ULONG VnicIp,
    _In_reads_(WFPREDIR_MAX_BOX) const WCHAR* BoxName)
{
    LONG idx;

    if (Pid == 0 || VnicIp == 0)
        return STATUS_INVALID_PARAMETER;

    if (RootPid == 0)
        RootPid = Pid;

    idx = PidFindIndexLocked(Pid);
    if (idx < 0)
        idx = PidFindFreeIndexLocked();
    if (idx < 0)
        return STATUS_INSUFFICIENT_RESOURCES;

    if (g_PidTable[idx].ProcessId == 0)
        InterlockedIncrement(&g_PidCount);

    g_PidTable[idx].ProcessId = Pid;
    g_PidTable[idx].ParentProcessId = ParentPid;
    g_PidTable[idx].RootProcessId = RootPid;
    g_PidTable[idx].VnicIp = VnicIp;
    g_PidTable[idx].NetworkSeen = 0;
    PidCopyBoxName(g_PidTable[idx].BoxName, BoxName);
    return STATUS_SUCCESS;
}

static BOOLEAN
PidFindCopy(_In_ ULONG Pid, _Out_ WFPREDIR_PID_ENTRY* Entry)
{
    KIRQL oldIrql;
    LONG idx;
    BOOLEAN found;

    if (!Entry)
        return FALSE;

    found = FALSE;
    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    idx = PidFindIndexLocked(Pid);
    if (idx >= 0) {
        *Entry = g_PidTable[idx];
        found = TRUE;
    }
    KeReleaseSpinLock(&g_PidLock, oldIrql);
    return found;
}

static VOID
PidRemoveOne(_In_ ULONG Pid)
{
    KIRQL oldIrql;
    LONG idx;

    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    idx = PidFindIndexLocked(Pid);
    if (idx >= 0) {
        RtlZeroMemory(&g_PidTable[idx], sizeof(g_PidTable[idx]));
        InterlockedDecrement(&g_PidCount);
    }
    KeReleaseSpinLock(&g_PidLock, oldIrql);
}

NTSTATUS
WfpPidTableInitialize(VOID)
{
    KeInitializeSpinLock(&g_PidLock);
    RtlZeroMemory(g_PidTable, sizeof(g_PidTable));
    InterlockedExchange(&g_PidCount, 0);
    return STATUS_SUCCESS;
}

VOID
WfpPidTableClear(VOID)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    RtlZeroMemory(g_PidTable, sizeof(g_PidTable));
    InterlockedExchange(&g_PidCount, 0);
    KeReleaseSpinLock(&g_PidLock, oldIrql);
}

NTSTATUS
WfpPidAddRoot(_In_ const WFPREDIR_PROCESS_INPUT* Input)
{
    KIRQL oldIrql;
    NTSTATUS status;

    if (!Input || Input->ProcessId == 0 || Input->VnicIp == 0)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    status = PidAddLocked(Input->ProcessId, 0, Input->ProcessId,
        Input->VnicIp, Input->BoxName);
    KeReleaseSpinLock(&g_PidLock, oldIrql);

    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
            "[WfpRedir] AddRoot PID=%lu vNIC=%u.%u.%u.%u\n",
            Input->ProcessId,
            (Input->VnicIp >> 24) & 0xFF, (Input->VnicIp >> 16) & 0xFF,
            (Input->VnicIp >> 8) & 0xFF, Input->VnicIp & 0xFF);
    }
    return status;
}

NTSTATUS
WfpPidRemoveTree(_In_ ULONG RootPid)
{
    KIRQL oldIrql;
    ULONG i;
    ULONG removed;

    if (RootPid == 0)
        return STATUS_INVALID_PARAMETER;

    removed = 0;
    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    for (i = 0; i < WFPREDIR_MAX_TRACKED_PIDS; ++i) {
        if (g_PidTable[i].ProcessId != 0 &&
            (g_PidTable[i].RootProcessId == RootPid ||
             g_PidTable[i].ProcessId == RootPid)) {
            RtlZeroMemory(&g_PidTable[i], sizeof(g_PidTable[i]));
            ++removed;
        }
    }
    if (removed != 0)
        InterlockedExchangeAdd(&g_PidCount, -(LONG)removed);
    KeReleaseSpinLock(&g_PidLock, oldIrql);

    if (removed == 0)
        return STATUS_NOT_FOUND;

    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
        "[WfpRedir] RemoveTree root=%lu removed=%lu\n", RootPid, removed);
    return STATUS_SUCCESS;
}

BOOLEAN
WfpPidFindAndMarkNetwork(_In_ ULONG Pid, _Out_ WFPREDIR_PID_ENTRY* Entry)
{
    KIRQL oldIrql;
    LONG idx;
    BOOLEAN found;

    if (!Entry)
        return FALSE;

    found = FALSE;
    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    idx = PidFindIndexLocked(Pid);
    if (idx >= 0) {
        g_PidTable[idx].NetworkSeen = 1;
        *Entry = g_PidTable[idx];
        found = TRUE;
    }
    KeReleaseSpinLock(&g_PidLock, oldIrql);
    return found;
}

BOOLEAN
WfpPidIsProtectedVnicIp(_In_ ULONG VnicIp)
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN found;

    if (VnicIp == 0 ||
        InterlockedCompareExchange(&g_PidCount, 0, 0) == 0)
        return FALSE;

    found = FALSE;
    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    for (i = 0; i < WFPREDIR_MAX_TRACKED_PIDS; ++i) {
        if (g_PidTable[i].ProcessId != 0 && g_PidTable[i].VnicIp == VnicIp) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_PidLock, oldIrql);
    return found;
}

static NTSTATUS
PidAddInherited(_In_ ULONG Pid, _In_ const WFPREDIR_PID_ENTRY* Parent)
{
    KIRQL oldIrql;
    NTSTATUS status;

    if (!Parent || Pid == 0 || Parent->VnicIp == 0)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    status = PidAddLocked(Pid, Parent->ProcessId, Parent->RootProcessId,
        Parent->VnicIp, Parent->BoxName);
    KeReleaseSpinLock(&g_PidLock, oldIrql);
    return status;
}

VOID
WfpRedirProcessNotify(
    _Inout_  PEPROCESS Process,
    _In_     HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    ULONG pid;

    UNREFERENCED_PARAMETER(Process);

    pid = HandleToULong(ProcessId);
    if (CreateInfo) {
        WFPREDIR_PID_ENTRY parent;
        ULONG parentPid;

        parentPid = HandleToULong(CreateInfo->ParentProcessId);
        if (PidFindCopy(parentPid, &parent)) {
            NTSTATUS status = PidAddInherited(pid, &parent);
            if (NT_SUCCESS(status)) {
                DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
                    "[WfpRedir] Inherit PID=%lu parent=%lu root=%lu\n",
                    pid, parentPid, parent.RootProcessId);
            }
        }
    }
    else {
        PidRemoveOne(pid);
    }
}

// ---------------------------------------------------------------
// Byte-swap helpers (avoid pulling in <winsock2.h> in kernel mode)
// ---------------------------------------------------------------
static FORCEINLINE ULONG
HostToNetLong(ULONG x)
{
    return RtlUlongByteSwap(x);
}

static FORCEINLINE ULONG
NetToHostLong(ULONG x)
{
    return RtlUlongByteSwap(x);
}

///////////////////////////////////////////////////////////////////////////////
//
// BindRedirectClassify
//
// Layer: FWPM_LAYER_ALE_BIND_REDIRECT_V4
//
// Two distinct behaviours based on PID match:
//
//  A) Tracked PID:
//     The socket is binding to INADDR_ANY (0.0.0.0). Re-bind to the
//     per-process-tree vNIC IP
//     so the OS selects the vNIC as the source interface.
//
//  B) Non-matching PID:
//     The socket is explicitly binding to a protected vNIC IP. This
//     is either a race condition, an accident, or a malicious attempt to
//     grab the tunnel address. Re-bind to INADDR_ANY so the normal route and
//     source address selection rules apply.
//
///////////////////////////////////////////////////////////////////////////////
VOID
BindRedirectClassify(
    _In_        const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_    const VOID* classifyContext,
    _In_        const FWPS_FILTER1* filter,
    _In_        UINT64                                flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0* classifyOut
)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(flowContext);

    WFPREDIR_PID_ENTRY entry;
    BOOLEAN tracked;

    // ---- Guard: must have write rights and a classify context ----
    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
        return;

    if (classifyContext == NULL || layerData == NULL)
    {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Default: permit
    classifyOut->actionType = FWP_ACTION_PERMIT;

    // ---- PID metadata must be present ----
    if (!(inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID))
        return;

    ULONG callerPid = (ULONG)inMetaValues->processId;

    // Determine the current bind address (network byte order).
    // layerData is _Inout_opt_ VOID* but we only read here; cast through
    // const to make the read-only intent explicit and avoid aliasing concerns.
    const FWPS_BIND_REQUEST0* peek = (const FWPS_BIND_REQUEST0*)layerData;
    const SOCKADDR_IN* peekAddr = (const SOCKADDR_IN*)&peek->localAddressAndPort;
    ULONG               bindIpNet = peekAddr->sin_addr.s_addr;          // NBO
    ULONG               bindIpHst = NetToHostLong(bindIpNet);           // HBO

    tracked = WfpPidFindAndMarkNetwork(callerPid, &entry);

    // ---------------------------------------------------------------
    // Path A - tracked PID: force bind to its configured vNIC IP.
    // Only act when the socket is binding to INADDR_ANY (0.0.0.0);
    // if it already has a specific address, leave it alone.
    // ---------------------------------------------------------------
    if (tracked && entry.VnicIp != 0)
    {
        if (bindIpHst != 0)
        {
            // Socket is explicitly binding to a specific IP;
            // respect the caller's choice and only permit.
            DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
                "[WfpRedir][Bind] PID %lu (tracked): already bound to "
                "%u.%u.%u.%u, leaving unchanged.\n",
                callerPid,
                (bindIpHst >> 24) & 0xFF, (bindIpHst >> 16) & 0xFF,
                (bindIpHst >> 8) & 0xFF, bindIpHst & 0xFF);
            return;
        }

        // Acquire classify handle and writable pointer
        UINT64 classifyHandle = 0;
        NTSTATUS status = FwpsAcquireClassifyHandle0(
            CLASSIFY_CONTEXT_TO_HANDLE(classifyContext), 0, &classifyHandle);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
                "[WfpRedir][Bind] AcquireClassifyHandle failed: 0x%08X\n", status);
            return;
        }

        FWPS_BIND_REQUEST0* req = NULL;
        status = FwpsAcquireWritableLayerDataPointer0(
            classifyHandle,
            filter->filterId,
            0,
            (PVOID*)&req,
            classifyOut);

        if (!NT_SUCCESS(status) || req == NULL)
        {
            DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
                "[WfpRedir][Bind] AcquireWritableLayerDataPointer failed: 0x%08X\n", status);
            classifyOut->actionType = FWP_ACTION_PERMIT;
            FwpsReleaseClassifyHandle0(classifyHandle);
            return;
        }

        SOCKADDR_IN* local = (SOCKADDR_IN*)&req->localAddressAndPort;
        local->sin_addr.s_addr = HostToNetLong(entry.VnicIp);

        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
            "[WfpRedir][Bind] PID %lu (tracked): 0.0.0.0  -->  "
            "%u.%u.%u.%u (vNIC)\n",
            callerPid,
            (entry.VnicIp >> 24) & 0xFF, (entry.VnicIp >> 16) & 0xFF,
            (entry.VnicIp >> 8) & 0xFF, entry.VnicIp & 0xFF);

        FwpsApplyModifiedLayerData0(classifyHandle, (PVOID)req, 0);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        FwpsReleaseClassifyHandle0(classifyHandle);
        return;
    }

    // ---------------------------------------------------------------
    // Path B - non-target PID that is trying to bind a protected vNIC IP:
    // reset to INADDR_ANY so normal routing/source selection applies.
    // ---------------------------------------------------------------
    if (!tracked && WfpPidIsProtectedVnicIp(bindIpHst))
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
            "[WfpRedir][Bind] PID %lu (non-target): tried to bind "
            "%u.%u.%u.%u (vNIC IP)  -->  resetting to 0.0.0.0\n",
            callerPid,
            (bindIpHst >> 24) & 0xFF, (bindIpHst >> 16) & 0xFF,
            (bindIpHst >> 8) & 0xFF, bindIpHst & 0xFF);

        UINT64 classifyHandle = 0;
        NTSTATUS status = FwpsAcquireClassifyHandle0(
            CLASSIFY_CONTEXT_TO_HANDLE(classifyContext), 0, &classifyHandle);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
                "[WfpRedir][Bind] AcquireClassifyHandle (non-target) "
                "failed: 0x%08X\n", status);
            classifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }

        FWPS_BIND_REQUEST0* req = NULL;
        status = FwpsAcquireWritableLayerDataPointer0(
            classifyHandle,
            filter->filterId,
            0,
            (PVOID*)&req,
            classifyOut);

        if (!NT_SUCCESS(status) || req == NULL)
        {
            DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
                "[WfpRedir][Bind] AcquireWritableLayerDataPointer "
                "(non-target) failed: 0x%08X\n", status);
            classifyOut->actionType = FWP_ACTION_PERMIT;
            FwpsReleaseClassifyHandle0(classifyHandle);
            return;
        }

        SOCKADDR_IN* local = (SOCKADDR_IN*)&req->localAddressAndPort;
        local->sin_addr.s_addr = 0; // INADDR_ANY

        FwpsApplyModifiedLayerData0(classifyHandle, (PVOID)req, 0);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        FwpsReleaseClassifyHandle0(classifyHandle);
        return;
    }

    // All other traffic: permit without modification
}

///////////////////////////////////////////////////////////////////////////////
// CommonNotify  - required stub for FWPS_CALLOUT1
///////////////////////////////////////////////////////////////////////////////
NTSTATUS
CommonNotify(
    _In_    FWPS_CALLOUT_NOTIFY_TYPE  notifyType,
    _In_    const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}
