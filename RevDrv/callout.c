///////////////////////////////////////////////////////////////////////////////
//
// callout.c  -  Bind-redirect source-IP forcing callout
//
//   - Target-PID sockets that bind to INADDR_ANY (0.0.0.0) are re-bound
//     to g_DestIp so the OS routes their packets through the vNIC.
//   - Non-target PIDs that explicitly bind to g_DestIp are re-bound to
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
// Global state  (written from IOCTL dispatch, read from callouts)
// All accesses use Interlocked* for coherence across processors.
// ---------------------------------------------------------------
volatile LONG   g_TargetPid = 0;   // 0  = disabled
volatile ULONG  g_DestIp = 0;   // VPN / tunnel IP   (host byte order)

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
//  A) Matching PID (g_TargetPid):
//     The socket is binding to INADDR_ANY (0.0.0.0).  Re-bind to g_DestIp
//     so the OS selects the VPN NIC as the source interface, ensuring
//     outbound packets egress through the tunnel.
//
//  B) Non-matching PID:
//     The socket is explicitly binding to g_DestIp (our vNIC IP).  This
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

    // Snapshot globals
    ULONG targetPid = (ULONG)InterlockedCompareExchange(&g_TargetPid, 0, 0);
    ULONG destIp = (ULONG)InterlockedCompareExchange((volatile LONG*)&g_DestIp, 0, 0);

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
    // Path A - matching PID: force bind to g_DestIp (VPN IP)
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
    // Path B - non-target PID that is trying to bind to g_DestIp:
    // reset to INADDR_ANY so normal routing/source selection applies.
    // ---------------------------------------------------------------
    if (destIp != 0 &&
        bindIpHst == destIp)    // caller is targeting our VPN IP
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
            "[WfpRedir][Bind] PID %lu (non-target): tried to bind "
            "%u.%u.%u.%u (vNIC IP)  -->  resetting to 0.0.0.0\n",
            callerPid,
            (destIp >> 24) & 0xFF, (destIp >> 16) & 0xFF,
            (destIp >> 8) & 0xFF, destIp & 0xFF);

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
