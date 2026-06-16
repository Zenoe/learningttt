///////////////////////////////////////////////////////////////////////////////
//
// callout.c  —  Connect-redirect and Bind-redirect callout functions
//
// Fix 1 (Connect):
//   Target-PID traffic is redirected to g_DestIp (the VPN/tunnel IP).
//
// Fix 2 (Bind):
//   • Target-PID sockets that bind to INADDR_ANY (0.0.0.0) are re-bound
//     to g_DestIp so the OS routes their packets through the VPN NIC.
//   • Non-matching PIDs that explicitly bind to g_DestIp are re-bound
//     to g_DefaultIp (the real default-route NIC IP) so they are never
//     blocked and never accidentally tunnel through the VPN.
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
// Global state  (written from IOCTL dispatch, read from callouts)
// All accesses use Interlocked* for coherence across processors.
// ---------------------------------------------------------------
volatile LONG   g_TargetPid = 0;   // 0  = disabled
volatile ULONG  g_DestIp = 0;   // VPN / tunnel IP   (host byte order)
volatile ULONG  g_DefaultIp = 0;   // Real default-route IP (host byte order)
volatile USHORT g_DestPort = 0;   // 0  = keep original port

// ---------------------------------------------------------------
// Byte-swap helpers (avoid pulling in <winsock2.h> in kernel mode)
// ---------------------------------------------------------------
static FORCEINLINE ULONG
HostToNetLong(ULONG x)
{
    return RtlUlongByteSwap(x);
}

static FORCEINLINE USHORT
HostToNetShort(USHORT x)
{
    return RtlUshortByteSwap(x);
}

static FORCEINLINE ULONG
NetToHostLong(ULONG x)
{
    return RtlUlongByteSwap(x);
}

///////////////////////////////////////////////////////////////////////////////
//
// ConnectRedirectClassify
//
// Layer: FWPM_LAYER_ALE_CONNECT_REDIRECT_V4
//
// For every outbound TCP/UDP connect attempt: if the initiating PID matches
// g_TargetPid, rewrite the remote (destination) address to g_DestIp and,
// if g_DestPort != 0, rewrite the destination port too.
//
// The function follows the four-step WFP redirect protocol:
//   1. FwpsAcquireClassifyHandle0
//   2. FwpsAcquireWritableLayerDataPointer0  (writes classifyOut internally)
//   3. mutate writableRequest
//   4. FwpsApplyModifiedLayerData0 + FwpsReleaseClassifyHandle0
//
///////////////////////////////////////////////////////////////////////////////
VOID
ConnectRedirectClassify(
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

    // Snapshot globals once to keep decisions consistent within this call
    ULONG  targetPid = (ULONG)InterlockedCompareExchange(&g_TargetPid, 0, 0);
    ULONG  destIp = (ULONG)InterlockedCompareExchange((volatile LONG*)&g_DestIp, 0, 0);
    USHORT destPort = g_DestPort;   // USHORT reads are naturally atomic on x86/x64

    // ---- Guard: must have write rights and a classify context ----
    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
        return;

    if (classifyContext == NULL || layerData == NULL)
    {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Default: permit unconditionally
    classifyOut->actionType = FWP_ACTION_PERMIT;

    // ---- Quick bail-out when redirection is disabled ----
    if (targetPid == 0 || destIp == 0)
        return;

    // ---- PID metadata must be present ----
    if (!(inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID))
        return;

    // ---- PID filter ----
    if (inMetaValues->processId != (UINT64)targetPid)
        return;

    // ---- Detect re-authorisation of an already-redirected flow ----
    // layerData is _Inout_opt_ VOID*; we only read localRedirectHandle here.
    {
        const FWPS_CONNECT_REQUEST0* initial = (const FWPS_CONNECT_REQUEST0*)layerData;
        if (initial->localRedirectHandle != NULL)
        {
            // Already redirected by us; permit without mutation
            classifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }
    }

    // ---- Acquire a classify handle ----
    UINT64 classifyHandle = 0;
    NTSTATUS status = FwpsAcquireClassifyHandle0(
        CLASSIFY_CONTEXT_TO_HANDLE(classifyContext), 0, &classifyHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[WfpRedir][Connect] FwpsAcquireClassifyHandle0 failed: 0x%08X\n", status);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // ---- Acquire the writable connect-request ----
    FWPS_CONNECT_REQUEST0* req = NULL;
    status = FwpsAcquireWritableLayerDataPointer0(
        classifyHandle,
        filter->filterId,
        0,
        (PVOID*)&req,
        classifyOut);

    if (!NT_SUCCESS(status) || req == NULL)
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[WfpRedir][Connect] FwpsAcquireWritableLayerDataPointer0 "
            "failed: 0x%08X\n", status);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        FwpsReleaseClassifyHandle0(classifyHandle);
        return;
    }

    SOCKADDR_IN* remote = (SOCKADDR_IN*)&req->remoteAddressAndPort;

    // Log the original destination before we overwrite it
    ULONG  origIp = NetToHostLong(remote->sin_addr.s_addr);
    USHORT origPort = RtlUshortByteSwap(remote->sin_port);

    // ---- Rewrite remote IP ----
    remote->sin_addr.s_addr = HostToNetLong(destIp);

    // ---- Rewrite remote port (only if configured) ----
    if (destPort != 0)
        remote->sin_port = HostToNetShort(destPort);

    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
        "[WfpRedir][Connect] PID %lu: %u.%u.%u.%u:%u  -->  %u.%u.%u.%u:%u\n",
        targetPid,
        (origIp >> 24) & 0xFF, (origIp >> 16) & 0xFF,
        (origIp >> 8) & 0xFF, origIp & 0xFF,
        origPort,
        (destIp >> 24) & 0xFF, (destIp >> 16) & 0xFF,
        (destIp >> 8) & 0xFF, destIp & 0xFF,
        (destPort != 0) ? destPort : origPort);

    // ---- Commit the mutation ----
    FwpsApplyModifiedLayerData0(classifyHandle, (PVOID)req, 0);

    classifyOut->actionType = FWP_ACTION_PERMIT;
    // Clear write-right so lower-weight filters cannot undo our change
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

    FwpsReleaseClassifyHandle0(classifyHandle);
}

///////////////////////////////////////////////////////////////////////////////
//
// BindRedirectClassify
//
// Layer: FWPM_LAYER_ALE_BIND_REDIRECT_V4
//
// Two distinct behaviours based on PID match:
//
//  A) Matching PID (g_TargetPid):
//     The socket is binding to INADDR_ANY (0.0.0.0).  Re-bind to g_DestIp
//     so the OS selects the VPN NIC as the source interface, ensuring
//     outbound packets egress through the tunnel.
//
//  B) Non-matching PID:
//     The socket is explicitly binding to g_DestIp (our VPN IP).  This
//     is either a race condition, an accident, or a malicious attempt to
//     grab the tunnel address.  Re-bind to g_DefaultIp (the real default-
//     route NIC IP) so the socket works correctly without going through
//     the tunnel and without being dropped.
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

    // Snapshot globals
    ULONG targetPid = (ULONG)InterlockedCompareExchange(&g_TargetPid, 0, 0);
    ULONG destIp = (ULONG)InterlockedCompareExchange((volatile LONG*)&g_DestIp, 0, 0);
    ULONG defaultIp = (ULONG)InterlockedCompareExchange((volatile LONG*)&g_DefaultIp, 0, 0);

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

    // ---------------------------------------------------------------
    // Path A – matching PID: force bind to g_DestIp (VPN IP)
    // Only act when the socket is binding to INADDR_ANY (0.0.0.0);
    // if it already has a specific address, leave it alone.
    // ---------------------------------------------------------------
    if (callerPid == targetPid && targetPid != 0 && destIp != 0)
    {
        if (bindIpHst != 0)
        {
            // Socket is explicitly binding to a specific IP;
            // respect the caller's choice and only permit.
            DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
                "[WfpRedir][Bind] PID %lu (target): already bound to "
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
        local->sin_addr.s_addr = HostToNetLong(destIp);

        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
            "[WfpRedir][Bind] PID %lu (target): 0.0.0.0  -->  "
            "%u.%u.%u.%u (VPN)\n",
            callerPid,
            (destIp >> 24) & 0xFF, (destIp >> 16) & 0xFF,
            (destIp >> 8) & 0xFF, destIp & 0xFF);

        FwpsApplyModifiedLayerData0(classifyHandle, (PVOID)req, 0);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        FwpsReleaseClassifyHandle0(classifyHandle);
        return;
    }

    // ---------------------------------------------------------------
    // Path B – non-matching PID that is trying to bind to g_DestIp:
    // redirect to g_DefaultIp so it uses the real default NIC.
    // ---------------------------------------------------------------
    if (destIp != 0 &&
        defaultIp != 0 &&
        bindIpHst == destIp)    // caller is targeting our VPN IP
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
            "[WfpRedir][Bind] PID %lu (non-target): tried to bind "
            "%u.%u.%u.%u (VPN IP)  -->  redirecting to "
            "%u.%u.%u.%u (default)\n",
            callerPid,
            (destIp >> 24) & 0xFF, (destIp >> 16) & 0xFF,
            (destIp >> 8) & 0xFF, destIp & 0xFF,
            (defaultIp >> 24) & 0xFF, (defaultIp >> 16) & 0xFF,
            (defaultIp >> 8) & 0xFF, defaultIp & 0xFF);

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
        local->sin_addr.s_addr = HostToNetLong(defaultIp);

        FwpsApplyModifiedLayerData0(classifyHandle, (PVOID)req, 0);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        FwpsReleaseClassifyHandle0(classifyHandle);
        return;
    }

    // All other traffic: permit without modification
}

///////////////////////////////////////////////////////////////////////////////
// CommonNotify  – required stub for FWPS_CALLOUT1
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