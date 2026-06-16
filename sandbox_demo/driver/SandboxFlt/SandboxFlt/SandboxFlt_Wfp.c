// ============================================================
//  SandboxFlt_Wfp.c  -  WFP bind-redirect source-IP forcing
//
//  This is part of SandboxFlt.sys. User mode enables it per sandbox root
//  PID through IOCTL_SANDBOX_SET_WFP_POLICY. Child PIDs inherit the policy
//  through the existing process notification path in SandboxFlt_BoxMgr.c.
// ============================================================
#define NDIS_SUPPORT_NDIS6 1
#define NDIS60 1
#include "SandboxFlt.h"
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <wsk.h>

static const GUID SANDBOX_WFP_BIND_CALLOUT_GUID =
{ 0x1f10c545, 0x4b42, 0x4b1a, { 0xb5, 0x0f, 0x67, 0x7f, 0x51, 0xd7, 0x31, 0x21 } };

static const GUID SANDBOX_WFP_SUBLAYER_GUID =
{ 0x3ad8c75a, 0x1ad0, 0x4c91, { 0x91, 0x5f, 0x57, 0x2d, 0xa1, 0x0f, 0x77, 0x42 } };

static const GUID SANDBOX_WFP_BIND_FILTER_GUID =
{ 0xd4a62d42, 0x08ec, 0x4ef1, { 0x86, 0x7a, 0x71, 0x17, 0xb6, 0xf0, 0x44, 0x9a } };

static HANDLE  g_WfpEngineHandle = NULL;
static UINT32  g_WfpBindCalloutId = 0;
static BOOLEAN g_WfpBindCalloutRegistered = FALSE;
static BOOLEAN g_WfpSubLayerAdded = FALSE;
static BOOLEAN g_WfpBindMgmtAdded = FALSE;
static BOOLEAN g_WfpBindFilterAdded = FALSE;

static FORCEINLINE ULONG
HostToNetLong(_In_ ULONG x)
{
    return RtlUlongByteSwap(x);
}

static FORCEINLINE ULONG
NetToHostLong(_In_ ULONG x)
{
    return RtlUlongByteSwap(x);
}

static BOOLEAN
SandboxWfp_FindPidPolicy(
    _In_ ULONG Pid,
    _Out_ ULONG* VnicIp)
{
    PPID_ENTRY pe;
    BOOLEAN found;

    if (!VnicIp)
        return FALSE;
    *VnicIp = 0;

    found = FALSE;
    SbAcquireExclusive(&g_Sandbox.PidLock);
    pe = Pid_Find(ULongToHandle(Pid));
    if (pe && pe->WfpEnabled && pe->WfpVnicIp != 0) {
        pe->WfpNetworkSeen = 1;
        *VnicIp = pe->WfpVnicIp;
        found = TRUE;
    }
    SbRelease(&g_Sandbox.PidLock);
    return found;
}

static BOOLEAN
SandboxWfp_IsProtectedVnicIp(_In_ ULONG VnicIp)
{
    PLIST_ENTRY entry;
    PPID_ENTRY pe;
    BOOLEAN found;

    if (VnicIp == 0)
        return FALSE;

    found = FALSE;
    SbAcquireShared(&g_Sandbox.PidLock);
    for (entry = g_Sandbox.PidList.Flink;
        entry != &g_Sandbox.PidList;
        entry = entry->Flink)
    {
        pe = CONTAINING_RECORD(entry, PID_ENTRY, ListEntry);
        if (pe->WfpEnabled && pe->WfpVnicIp == VnicIp) {
            found = TRUE;
            break;
        }
    }
    SbRelease(&g_Sandbox.PidLock);
    return found;
}

NTSTATUS
SandboxWfp_SetProcessPolicy(_In_ const SANDBOX_WFP_POLICY_INFO* Info)
{
    WCHAR boxBuf[SANDBOX_MAX_BOX];
    UNICODE_STRING boxName;
    PPID_ENTRY rootEntry;
    PLIST_ENTRY entry;
    ULONG rootPid;
    ULONG changed;
    BOOLEAN enabled;

    if (!Info || Info->ProcessId == 0)
        return STATUS_INVALID_PARAMETER;

    enabled = (BOOLEAN)(Info->Enabled != 0);
    if (enabled && Info->VnicIp == 0)
        return STATUS_INVALID_PARAMETER;

    RtlCopyMemory(boxBuf, Info->BoxName, sizeof(boxBuf));
    boxBuf[SANDBOX_MAX_BOX - 1] = L'\0';
    RtlInitUnicodeString(&boxName, boxBuf);

    changed = 0;
    rootPid = Info->ProcessId;

    SbAcquireExclusive(&g_Sandbox.PidLock);

    rootEntry = Pid_Find(ULongToHandle(Info->ProcessId));
    if (!rootEntry) {
        if (enabled) {
            SbRelease(&g_Sandbox.PidLock);
            return STATUS_NOT_FOUND;
        }
        rootPid = Info->ProcessId;
    }
    else {
        if (boxName.Length != 0 &&
            (!rootEntry->Box ||
             !RtlEqualUnicodeString(&rootEntry->Box->BoxName, &boxName, TRUE))) {
            SbRelease(&g_Sandbox.PidLock);
            return STATUS_NOT_FOUND;
        }

        if (rootEntry->RootProcessId)
            rootPid = HandleToULong(rootEntry->RootProcessId);
    }

    for (entry = g_Sandbox.PidList.Flink;
        entry != &g_Sandbox.PidList;
        entry = entry->Flink)
    {
        PPID_ENTRY pe;
        ULONG pePid;
        ULONG peRoot;

        pe = CONTAINING_RECORD(entry, PID_ENTRY, ListEntry);
        pePid = HandleToULong(pe->ProcessId);
        peRoot = pe->RootProcessId ? HandleToULong(pe->RootProcessId) : pePid;

        if (pePid == rootPid || peRoot == rootPid) {
            pe->WfpEnabled = enabled;
            pe->WfpVnicIp = enabled ? Info->VnicIp : 0;
            pe->WfpNetworkSeen = 0;
            changed++;
        }
    }

    SbRelease(&g_Sandbox.PidLock);

    if (changed == 0)
        return enabled ? STATUS_NOT_FOUND : STATUS_SUCCESS;

    DbgPrint("[SandboxFlt][WFP] root=%lu enabled=%lu vNIC=%u.%u.%u.%u changed=%lu\n",
        rootPid,
        enabled ? 1UL : 0UL,
        (Info->VnicIp >> 24) & 0xFF,
        (Info->VnicIp >> 16) & 0xFF,
        (Info->VnicIp >> 8) & 0xFF,
        Info->VnicIp & 0xFF,
        changed);
    return STATUS_SUCCESS;
}

static VOID
SandboxWfp_BindClassify(
    _In_        const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_    const VOID* classifyContext,
    _In_        const FWPS_FILTER1* filter,
    _In_        UINT64 flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0* classifyOut)
{
    const FWPS_BIND_REQUEST0* peek;
    const SOCKADDR_IN* peekAddr;
    ULONG callerPid;
    ULONG bindIpNet;
    ULONG bindIpHst;
    ULONG vnicIp;
    BOOLEAN tracked;
    UINT64 classifyHandle;
    NTSTATUS status;
    FWPS_BIND_REQUEST0* req;
    SOCKADDR_IN* local;

    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(flowContext);

    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
        return;

    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (!classifyContext || !layerData)
        return;

    if (!(inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID))
        return;

    callerPid = (ULONG)inMetaValues->processId;
    peek = (const FWPS_BIND_REQUEST0*)layerData;
    peekAddr = (const SOCKADDR_IN*)&peek->localAddressAndPort;
    bindIpNet = peekAddr->sin_addr.s_addr;
    bindIpHst = NetToHostLong(bindIpNet);

    tracked = SandboxWfp_FindPidPolicy(callerPid, &vnicIp);

    if (tracked && vnicIp != 0) {
        if (bindIpHst != 0)
            return;

        classifyHandle = 0;
        status = FwpsAcquireClassifyHandle0(
            (PVOID)classifyContext, 0, &classifyHandle);
        if (!NT_SUCCESS(status))
            return;

        req = NULL;
        status = FwpsAcquireWritableLayerDataPointer0(
            classifyHandle,
            filter->filterId,
            0,
            (PVOID*)&req,
            classifyOut);

        if (!NT_SUCCESS(status) || req == NULL) {
            FwpsReleaseClassifyHandle0(classifyHandle);
            return;
        }

        local = (SOCKADDR_IN*)&req->localAddressAndPort;
        local->sin_addr.s_addr = HostToNetLong(vnicIp);

        FwpsApplyModifiedLayerData0(classifyHandle, (PVOID)req, 0);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        FwpsReleaseClassifyHandle0(classifyHandle);
        return;
    }

    if (!tracked && SandboxWfp_IsProtectedVnicIp(bindIpHst)) {
        classifyHandle = 0;
        status = FwpsAcquireClassifyHandle0(
            (PVOID)classifyContext, 0, &classifyHandle);
        if (!NT_SUCCESS(status))
            return;

        req = NULL;
        status = FwpsAcquireWritableLayerDataPointer0(
            classifyHandle,
            filter->filterId,
            0,
            (PVOID*)&req,
            classifyOut);

        if (!NT_SUCCESS(status) || req == NULL) {
            FwpsReleaseClassifyHandle0(classifyHandle);
            return;
        }

        local = (SOCKADDR_IN*)&req->localAddressAndPort;
        local->sin_addr.s_addr = 0;

        FwpsApplyModifiedLayerData0(classifyHandle, (PVOID)req, 0);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        FwpsReleaseClassifyHandle0(classifyHandle);
    }
}

static NTSTATUS
SandboxWfp_CommonNotify(
    _In_    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_    const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static NTSTATUS
SandboxWfp_RegisterKernelCallout(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ UINT32* CalloutId)
{
    FWPS_CALLOUT1 callout;

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = SANDBOX_WFP_BIND_CALLOUT_GUID;
    callout.classifyFn = SandboxWfp_BindClassify;
    callout.notifyFn = SandboxWfp_CommonNotify;

    return FwpsCalloutRegister1(DeviceObject, &callout, CalloutId);
}

static NTSTATUS
SandboxWfp_AddManagementCallout(VOID)
{
    FWPM_CALLOUT0 callout;
    NTSTATUS status;

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = SANDBOX_WFP_BIND_CALLOUT_GUID;
    callout.displayData.name = L"SandboxFlt WFP Bind Callout";
    callout.applicableLayer = FWPM_LAYER_ALE_BIND_REDIRECT_V4;

    status = FwpmCalloutAdd0(g_WfpEngineHandle, &callout, NULL, NULL);
    if (status == STATUS_OBJECT_NAME_COLLISION)
        status = STATUS_SUCCESS;
    return status;
}

static NTSTATUS
SandboxWfp_AddBindFilter(VOID)
{
    FWPM_FILTER0 filter;
    UINT64 filterId;

    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = SANDBOX_WFP_BIND_FILTER_GUID;
    filter.displayData.name = L"SandboxFlt WFP Bind Filter";
    filter.layerKey = FWPM_LAYER_ALE_BIND_REDIRECT_V4;
    filter.subLayerKey = SANDBOX_WFP_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 0;
    filter.filterCondition = NULL;
    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = SANDBOX_WFP_BIND_CALLOUT_GUID;

    filterId = 0;
    return FwpmFilterAdd0(g_WfpEngineHandle, &filter, NULL, &filterId);
}

NTSTATUS
SandboxWfp_Register(_In_ PDEVICE_OBJECT DeviceObject)
{
    FWPM_SESSION0 session;
    FWPM_SUBLAYER0 subLayer;
    NTSTATUS status;

    RtlZeroMemory(&session, sizeof(session));
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL,
        &session, &g_WfpEngineHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SandboxFlt][WFP] FwpmEngineOpen0 failed: %08x\n", status);
        return status;
    }

    status = SandboxWfp_RegisterKernelCallout(DeviceObject,
        &g_WfpBindCalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SandboxFlt][WFP] FwpsCalloutRegister1 failed: %08x\n", status);
        SandboxWfp_Unregister();
        return status;
    }
    g_WfpBindCalloutRegistered = TRUE;

    status = FwpmTransactionBegin0(g_WfpEngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        SandboxWfp_Unregister();
        return status;
    }

    RtlZeroMemory(&subLayer, sizeof(subLayer));
    subLayer.subLayerKey = SANDBOX_WFP_SUBLAYER_GUID;
    subLayer.displayData.name = L"SandboxFlt WFP Sublayer";
    subLayer.weight = 0x8000;

    status = FwpmSubLayerAdd0(g_WfpEngineHandle, &subLayer, NULL);
    if (status == STATUS_OBJECT_NAME_COLLISION)
        status = STATUS_SUCCESS;
    if (!NT_SUCCESS(status)) {
        FwpmTransactionAbort0(g_WfpEngineHandle);
        SandboxWfp_Unregister();
        return status;
    }
    g_WfpSubLayerAdded = TRUE;

    status = SandboxWfp_AddManagementCallout();
    if (!NT_SUCCESS(status)) {
        FwpmTransactionAbort0(g_WfpEngineHandle);
        SandboxWfp_Unregister();
        return status;
    }
    g_WfpBindMgmtAdded = TRUE;

    status = SandboxWfp_AddBindFilter();
    if (!NT_SUCCESS(status)) {
        FwpmTransactionAbort0(g_WfpEngineHandle);
        SandboxWfp_Unregister();
        return status;
    }
    g_WfpBindFilterAdded = TRUE;

    status = FwpmTransactionCommit0(g_WfpEngineHandle);
    if (!NT_SUCCESS(status)) {
        SandboxWfp_Unregister();
        return status;
    }

    DbgPrint("[SandboxFlt][WFP] Registered bind source-IP forcing\n");
    return STATUS_SUCCESS;
}

VOID
SandboxWfp_Unregister(VOID)
{
    if (g_WfpEngineHandle) {
        if (g_WfpBindFilterAdded) {
            FwpmFilterDeleteByKey0(g_WfpEngineHandle,
                &SANDBOX_WFP_BIND_FILTER_GUID);
            g_WfpBindFilterAdded = FALSE;
        }
        if (g_WfpBindMgmtAdded) {
            FwpmCalloutDeleteByKey0(g_WfpEngineHandle,
                &SANDBOX_WFP_BIND_CALLOUT_GUID);
            g_WfpBindMgmtAdded = FALSE;
        }
        if (g_WfpSubLayerAdded) {
            FwpmSubLayerDeleteByKey0(g_WfpEngineHandle,
                &SANDBOX_WFP_SUBLAYER_GUID);
            g_WfpSubLayerAdded = FALSE;
        }

        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
    }

    if (g_WfpBindCalloutRegistered) {
        FwpsCalloutUnregisterById0(g_WfpBindCalloutId);
        g_WfpBindCalloutRegistered = FALSE;
        g_WfpBindCalloutId = 0;
    }
}
