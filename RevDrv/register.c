///////////////////////////////////////////////////////////////////////////////
//
// register.c  —  Register / unregister WFP callouts, sublayer, filters
//
// We register at two layers:
//   FWPM_LAYER_ALE_CONNECT_REDIRECT_V4  – rewrite the remote address
//   FWPM_LAYER_ALE_BIND_REDIRECT_V4     – rewrite the local bind address
//
// Both callouts share a single sublayer.  The unregister path is
// idempotent: each object is deleted independently so a partial
// initialisation failure does not leave the system in an inconsistent state.
//
///////////////////////////////////////////////////////////////////////////////

#define _KERNEL_MODE_
#include "RevDrv.h"

static HANDLE  g_EngineHandle       = NULL;
static UINT32  g_ConnectCalloutId   = 0;
static UINT32  g_BindCalloutId      = 0;
static BOOLEAN g_ConnectCalloutReg  = FALSE;
static BOOLEAN g_BindCalloutReg     = FALSE;
static BOOLEAN g_SubLayerAdded      = FALSE;
static BOOLEAN g_ConnectMgmtAdded   = FALSE;
static BOOLEAN g_BindMgmtAdded      = FALSE;
static BOOLEAN g_ConnectFilterAdded = FALSE;
static BOOLEAN g_BindFilterAdded    = FALSE;

// ---------------------------------------------------------------
// Helper – register one FWPS kernel callout
// ---------------------------------------------------------------
static NTSTATUS
RegisterKernelCallout(
    _In_  PDEVICE_OBJECT              DeviceObject,
    _In_  const GUID*                 calloutKey,
    _In_  FWPS_CALLOUT_CLASSIFY_FN1   classifyFn,
    _Out_ UINT32*                     calloutId
)
{
    FWPS_CALLOUT1 c = { 0 };
    c.calloutKey   = *calloutKey;
    c.classifyFn   = classifyFn;
    c.notifyFn     = CommonNotify;
    c.flowDeleteFn = NULL;

    return FwpsCalloutRegister1(DeviceObject, &c, calloutId);
}

// ---------------------------------------------------------------
// Helper – add one FWPM management callout (inside a transaction)
// ---------------------------------------------------------------
static NTSTATUS
AddManagementCallout(
    _In_ HANDLE      engineHandle,
    _In_ const GUID* calloutKey,
    _In_ const GUID* layerKey,
    _In_ PCWSTR      name
)
{
    FWPM_CALLOUT0 mc = { 0 };
    mc.calloutKey          = *calloutKey;
    mc.displayData.name    = (PWSTR)name;
    mc.applicableLayer     = *layerKey;

    NTSTATUS status = FwpmCalloutAdd0(engineHandle, &mc, NULL, NULL);
    if (status == STATUS_OBJECT_NAME_COLLISION)
        status = STATUS_SUCCESS;
    return status;
}

// ---------------------------------------------------------------
// Helper – add one FWPM filter (inside a transaction)
// ---------------------------------------------------------------
static NTSTATUS
AddFilter(
    _In_ HANDLE      engineHandle,
    _In_ const GUID* filterKey,
    _In_ const GUID* layerKey,
    _In_ const GUID* calloutKey,
    _In_ PCWSTR      name
)
{
    FWPM_FILTER0 f = { 0 };
    f.filterKey              = *filterKey;
    f.displayData.name       = (PWSTR)name;
    f.layerKey               = *layerKey;
    f.subLayerKey            = WFPREDIR_SUBLAYER_GUID;
    f.weight.type            = FWP_EMPTY;
    f.numFilterConditions    = 0;
    f.filterCondition        = NULL;
    f.action.type            = FWP_ACTION_CALLOUT_UNKNOWN;
    f.action.calloutKey      = *calloutKey;

    UINT64 filterId = 0;
    return FwpmFilterAdd0(engineHandle, &f, NULL, &filterId);
}

// ---------------------------------------------------------------
// WfpRedirRegister
// ---------------------------------------------------------------
NTSTATUS
WfpRedirRegister(_In_ PDEVICE_OBJECT DeviceObject)
{
    NTSTATUS status;

    // ------------------------------------------------------------------
    // 1. Open the WFP engine (non-dynamic so objects survive a crash)
    // ------------------------------------------------------------------
    FWPM_SESSION0 session = { 0 };
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[WfpRedir] FwpmEngineOpen0 failed: 0x%08X\n", status);
        return status;
    }

    // ------------------------------------------------------------------
    // 2. Register FWPS (kernel) callouts – must happen outside any txn
    // ------------------------------------------------------------------
    /* status = RegisterKernelCallout( */
    /*     DeviceObject, */
    /*     &WFPREDIR_CONNECT_CALLOUT_GUID, */
    /*     ConnectRedirectClassify, */
    /*     &g_ConnectCalloutId); */
    /* if (!NT_SUCCESS(status)) */
    /* { */
    /*     DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, */
    /*         "[WfpRedir] Connect callout register failed: 0x%08X\n", status); */
    /*     WfpRedirUnregister(); */
    /*     return status; */
    /* } */
    /* g_ConnectCalloutReg = TRUE; */

    status = RegisterKernelCallout(
        DeviceObject,
        &WFPREDIR_BIND_CALLOUT_GUID,
        BindRedirectClassify,
        &g_BindCalloutId);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[WfpRedir] Bind callout register failed: 0x%08X\n", status);
        WfpRedirUnregister();
        return status;
    }
    g_BindCalloutReg = TRUE;

    // ------------------------------------------------------------------
    // 3. Add FWPM management objects inside a single transaction
    // ------------------------------------------------------------------
    status = FwpmTransactionBegin0(g_EngineHandle, 0);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[WfpRedir] FwpmTransactionBegin0 failed: 0x%08X\n", status);
        WfpRedirUnregister();
        return status;
    }

    // 3a. Sublayer
    {
        FWPM_SUBLAYER0 sl = { 0 };
        sl.subLayerKey        = WFPREDIR_SUBLAYER_GUID;
        sl.displayData.name   = L"WfpRedirect Sublayer";
        sl.weight             = 0x8000;

        status = FwpmSubLayerAdd0(g_EngineHandle, &sl, NULL);
        if (status == STATUS_OBJECT_NAME_COLLISION)
            status = STATUS_SUCCESS;

        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
                "[WfpRedir] FwpmSubLayerAdd0 failed: 0x%08X\n", status);
            FwpmTransactionAbort0(g_EngineHandle);
            WfpRedirUnregister();
            return status;
        }
        g_SubLayerAdded = TRUE;
    }

    // 3b. Connect-redirect management callout
    /* status = AddManagementCallout( */
    /*     g_EngineHandle, */
    /*     &WFPREDIR_CONNECT_CALLOUT_GUID, */
    /*     &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, */
    /*     L"WfpRedirect Connect Callout"); */
    /* if (!NT_SUCCESS(status)) */
    /* { */
    /*     DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, */
    /*         "[WfpRedir] AddManagementCallout (connect) failed: 0x%08X\n", status); */
    /*     FwpmTransactionAbort0(g_EngineHandle); */
    /*     WfpRedirUnregister(); */
    /*     return status; */
    /* } */
    /* g_ConnectMgmtAdded = TRUE; */

    /* // 3c. Connect-redirect filter */
    /* status = AddFilter( */
    /*     g_EngineHandle, */
    /*     &WFPREDIR_CONNECT_FILTER_GUID, */
    /*     &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, */
    /*     &WFPREDIR_CONNECT_CALLOUT_GUID, */
    /*     L"WfpRedirect Connect Filter"); */
    /* if (!NT_SUCCESS(status)) */
    /* { */
    /*     DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, */
    /*         "[WfpRedir] AddFilter (connect) failed: 0x%08X\n", status); */
    /*     FwpmTransactionAbort0(g_EngineHandle); */
    /*     WfpRedirUnregister(); */
    /*     return status; */
    /* } */
    /* g_ConnectFilterAdded = TRUE; */

    // 3d. Bind-redirect management callout
    status = AddManagementCallout(
        g_EngineHandle,
        &WFPREDIR_BIND_CALLOUT_GUID,
        &FWPM_LAYER_ALE_BIND_REDIRECT_V4,
        L"WfpRedirect Bind Callout");
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[WfpRedir] AddManagementCallout (bind) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(g_EngineHandle);
        WfpRedirUnregister();
        return status;
    }
    g_BindMgmtAdded = TRUE;

    // 3e. Bind-redirect filter
    status = AddFilter(
        g_EngineHandle,
        &WFPREDIR_BIND_FILTER_GUID,
        &FWPM_LAYER_ALE_BIND_REDIRECT_V4,
        &WFPREDIR_BIND_CALLOUT_GUID,
        L"WfpRedirect Bind Filter");
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[WfpRedir] AddFilter (bind) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(g_EngineHandle);
        WfpRedirUnregister();
        return status;
    }
    g_BindFilterAdded = TRUE;

    // ------------------------------------------------------------------
    // 4. Commit
    // ------------------------------------------------------------------
    status = FwpmTransactionCommit0(g_EngineHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[WfpRedir] FwpmTransactionCommit0 failed: 0x%08X\n", status);
        WfpRedirUnregister();
        return status;
    }

    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
        "[WfpRedir] Registered successfully. "
        "Connect + Bind redirect layers active.\n");
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------
// WfpRedirUnregister  (idempotent)
// ---------------------------------------------------------------
VOID
WfpRedirUnregister(VOID)
{
    if (g_EngineHandle)
    {
        // Delete FWPM objects in reverse dependency order:
        //   filters → callouts → sublayer
        if (g_ConnectFilterAdded)
        {
            FwpmFilterDeleteByKey0(g_EngineHandle, &WFPREDIR_CONNECT_FILTER_GUID);
            g_ConnectFilterAdded = FALSE;
        }
        if (g_BindFilterAdded)
        {
            FwpmFilterDeleteByKey0(g_EngineHandle, &WFPREDIR_BIND_FILTER_GUID);
            g_BindFilterAdded = FALSE;
        }
        if (g_ConnectMgmtAdded)
        {
            FwpmCalloutDeleteByKey0(g_EngineHandle, &WFPREDIR_CONNECT_CALLOUT_GUID);
            g_ConnectMgmtAdded = FALSE;
        }
        if (g_BindMgmtAdded)
        {
            FwpmCalloutDeleteByKey0(g_EngineHandle, &WFPREDIR_BIND_CALLOUT_GUID);
            g_BindMgmtAdded = FALSE;
        }
        if (g_SubLayerAdded)
        {
            FwpmSubLayerDeleteByKey0(g_EngineHandle, &WFPREDIR_SUBLAYER_GUID);
            g_SubLayerAdded = FALSE;
        }

        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
    }

    // Unregister FWPS (kernel) callouts after closing the engine
    if (g_ConnectCalloutReg)
    {
        FwpsCalloutUnregisterById0(g_ConnectCalloutId);
        g_ConnectCalloutReg = FALSE;
    }
    if (g_BindCalloutReg)
    {
        FwpsCalloutUnregisterById0(g_BindCalloutId);
        g_BindCalloutReg = FALSE;
    }

    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
        "[WfpRedir] Unregistered.\n");
}
