// ============================================================
//  SandboxFlt_BoxMgr.c  -  Box and PID list management
// ============================================================
#include "SandboxFlt.h"

static volatile LONG g_BoxGeneration = 0;

// ============================================================
//  Box_Find  - caller must hold BoxLock (via SbAcquireXxx)
// ============================================================
PBOX_ENTRY
Box_Find(_In_ PC_UNICODE_STRING BoxName)
{
    PLIST_ENTRY entry;
    PBOX_ENTRY  box;
    for (entry = g_Sandbox.BoxList.Flink;
        entry != &g_Sandbox.BoxList;
        entry = entry->Flink)
    {
        box = CONTAINING_RECORD(entry, BOX_ENTRY, ListEntry);
        if (RtlEqualUnicodeString(&box->BoxName, (PUNICODE_STRING)BoxName, TRUE))
            return box;
    }
    return NULL;
}

// ============================================================
//  Box_Add
// ============================================================
NTSTATUS
Box_Add(_In_ struct _SANDBOX_BOX_INFO* Info)
{
    PBOX_ENTRY     box;
    UNICODE_STRING name;
    ULONG          nameLen;
    ULONG          rootLen;
    ULONG          realLen;

    nameLen = (ULONG)wcsnlen(Info->BoxName, SANDBOX_MAX_BOX);
    rootLen = (ULONG)wcsnlen(Info->SandboxRootNt, SANDBOX_MAX_PATH);
    realLen = (ULONG)wcsnlen(Info->RealRootNt, SANDBOX_MAX_PATH);

    if (nameLen == 0 || nameLen >= SANDBOX_MAX_BOX)
        return STATUS_INVALID_PARAMETER;

    RtlInitUnicodeString(&name, Info->BoxName);

    SbAcquireExclusive(&g_Sandbox.BoxLock);
    if (Box_Find(&name)) {
        SbRelease(&g_Sandbox.BoxLock);
        DbgPrint("[SandboxFlt] Box_Add: %S already exists\n", Info->BoxName);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    box = (PBOX_ENTRY)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(BOX_ENTRY), SANDBOX_POOL_TAG);
    if (!box) {
        SbRelease(&g_Sandbox.BoxLock);
        DbgPrint("[SandboxFlt] Box_Add: alloc failed sizeof=%llu\n",
            (ULONG64)sizeof(BOX_ENTRY));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(box, sizeof(*box));

    RtlCopyMemory(box->BoxNameBuf, Info->BoxName, (nameLen + 1) * sizeof(WCHAR));
    RtlCopyMemory(box->SandboxRootBuf, Info->SandboxRootNt, (rootLen + 1) * sizeof(WCHAR));
    RtlCopyMemory(box->RealRootBuf, Info->RealRootNt, (realLen + 1) * sizeof(WCHAR));

    RtlInitUnicodeString(&box->BoxName, box->BoxNameBuf);
    RtlInitUnicodeString(&box->SandboxRootNt, box->SandboxRootBuf);
    RtlInitUnicodeString(&box->RealRootNt, box->RealRootBuf);

    box->WritePolicy = SandboxPolicy_Redirect;
    box->RedirectReads = TRUE;   /* must be TRUE: app reads back its own writes */
    box->HideHostFiles = FALSE;
    box->CacheGeneration = (ULONG)InterlockedIncrement(&g_BoxGeneration);
    if (box->CacheGeneration == 0)
        box->CacheGeneration = (ULONG)InterlockedIncrement(&g_BoxGeneration);

    InsertTailList(&g_Sandbox.BoxList, &box->ListEntry);
    SbRelease(&g_Sandbox.BoxLock);

    InterlockedIncrement(&g_AnyBoxActive);   /* Tier 0: mark system active */
    DbgPrint("[SandboxFlt] Box_Add OK: '%S'  root='%S'\n",
        Info->BoxName, Info->SandboxRootNt);
    return STATUS_SUCCESS;
}

// ============================================================
//  Box_Remove
// ============================================================
NTSTATUS
Box_Remove(_In_ PCWSTR BoxName)
{
    UNICODE_STRING name;
    PBOX_ENTRY     box;
    PLIST_ENTRY    entry;
    PPID_ENTRY     pe;

    RtlInitUnicodeString(&name, BoxName);

    SbAcquireExclusive(&g_Sandbox.BoxLock);
    box = Box_Find(&name);
    if (!box) {
        SbRelease(&g_Sandbox.BoxLock);
        return STATUS_NOT_FOUND;
    }

    SbAcquireShared(&g_Sandbox.PidLock);
    for (entry = g_Sandbox.PidList.Flink;
        entry != &g_Sandbox.PidList;
        entry = entry->Flink)
    {
        pe = CONTAINING_RECORD(entry, PID_ENTRY, ListEntry);
        if (pe->Box == box) {
            SbRelease(&g_Sandbox.PidLock);
            SbRelease(&g_Sandbox.BoxLock);
            return STATUS_DEVICE_BUSY;
        }
    }
    SbRelease(&g_Sandbox.PidLock);

    RemoveEntryList(&box->ListEntry);
    SbRelease(&g_Sandbox.BoxLock);

    ExFreePoolWithTag(box, SANDBOX_POOL_TAG);
    InterlockedDecrement(&g_AnyBoxActive);   /* Tier 0 */
    DbgPrint("[SandboxFlt] Box_Remove: '%S'\n", BoxName);
    return STATUS_SUCCESS;
}

// ============================================================
//  Pid_Find  - caller must hold PidLock (via SbAcquireXxx)
// ============================================================
PPID_ENTRY
Pid_Find(_In_ HANDLE Pid)
{
    PLIST_ENTRY entry;
    PPID_ENTRY  pe;
    for (entry = g_Sandbox.PidList.Flink;
        entry != &g_Sandbox.PidList;
        entry = entry->Flink)
    {
        pe = CONTAINING_RECORD(entry, PID_ENTRY, ListEntry);
        if (pe->ProcessId == Pid)
            return pe;
    }
    return NULL;
}

static NTSTATUS
Pid_AddWithBox(
    _In_ ULONG Pid,
    _In_ ULONG ParentPid,
    _In_ ULONG RootPid,
    _In_ PBOX_ENTRY Box)
{
    PPID_ENTRY pe;

    if (!Box) return STATUS_INVALID_PARAMETER;
    if (RootPid == 0) RootPid = Pid;

    pe = (PPID_ENTRY)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(PID_ENTRY), SANDBOX_POOL_TAG);
    if (!pe) return STATUS_INSUFFICIENT_RESOURCES;

    pe->ProcessId = ULongToHandle(Pid);
    pe->ParentProcessId = ULongToHandle(ParentPid);
    pe->RootProcessId = ULongToHandle(RootPid);
    pe->Box = Box;

    SbAcquireExclusive(&g_Sandbox.PidLock);
    if (Pid_Find(pe->ProcessId)) {
        SbRelease(&g_Sandbox.PidLock);
        ExFreePoolWithTag(pe, SANDBOX_POOL_TAG);
        return STATUS_OBJECT_NAME_COLLISION;
    }
    InsertTailList(&g_Sandbox.PidList, &pe->ListEntry);
    SbRelease(&g_Sandbox.PidLock);

    if (!NT_SUCCESS(Filter_SetProcContext(Pid, Box))) {
        PidBitmap_OnRemove(Pid);
        SbAcquireExclusive(&g_Sandbox.PidLock);
        if (Pid_Find(pe->ProcessId)) {
            RemoveEntryList(&pe->ListEntry);
        }
        SbRelease(&g_Sandbox.PidLock);
        ExFreePoolWithTag(pe, SANDBOX_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PidBitmap_OnAdd(Pid);
    return STATUS_SUCCESS;
}

// ============================================================
//  Pid_Add
// ============================================================
NTSTATUS
Pid_Add(_In_ ULONG Pid, _In_ PCWSTR BoxName)
{
    UNICODE_STRING boxName;
    PBOX_ENTRY     box;
    NTSTATUS       status;

    RtlInitUnicodeString(&boxName, BoxName);

    SbAcquireShared(&g_Sandbox.BoxLock);
    box = Box_Find(&boxName);
    SbRelease(&g_Sandbox.BoxLock);

    if (!box) {
        DbgPrint("[SandboxFlt] Pid_Add: box '%S' not found\n", BoxName);
        return STATUS_NOT_FOUND;
    }

    status = Pid_AddWithBox(Pid, 0, Pid, box);
    if (!NT_SUCCESS(status))
        return status;

    DbgPrint("[SandboxFlt] Pid_Add: PID %lu -> box '%S'\n", Pid, BoxName);
    return STATUS_SUCCESS;
}

NTSTATUS
Pid_AddInherited(
    _In_ ULONG Pid,
    _In_ ULONG ParentPid,
    _In_ ULONG RootPid,
    _In_ PBOX_ENTRY Box)
{
    NTSTATUS status;

    status = Pid_AddWithBox(Pid, ParentPid, RootPid, Box);
    if (NT_SUCCESS(status)) {
        DbgPrint("[SandboxFlt] Pid_AddInherited: PID %lu parent=%lu root=%lu -> box '%wZ'\n",
            Pid, ParentPid, RootPid, &Box->BoxName);
    }
    return status;
}

VOID
SandboxFlt_ProcessNotify(
    _Inout_  PEPROCESS             Process,
    _In_ HANDLE  ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    ULONG pid;
    ULONG parentPid;
    ULONG rootPid;
    PBOX_ENTRY parentBox;
    PPID_ENTRY parentEntry;

    pid = HandleToULong(ProcessId);

    if (CreateInfo) {
        parentPid = HandleToULong(CreateInfo->ParentProcessId);
        parentBox = Filter_GetProcContext(parentPid);
        if (parentBox) {
            rootPid = parentPid;
            SbAcquireShared(&g_Sandbox.PidLock);
            parentEntry = Pid_Find(ULongToHandle(parentPid));
            if (parentEntry && parentEntry->RootProcessId)
                rootPid = HandleToULong(parentEntry->RootProcessId);
            SbRelease(&g_Sandbox.PidLock);

            (VOID)Pid_AddInherited(pid, parentPid, rootPid, parentBox);
        }
    }
    else {
        if (Filter_GetProcContext(pid))
            (VOID)Pid_Remove(pid);
    }

    UNREFERENCED_PARAMETER(Process);
}

ULONG
Pid_CopyProcessList(
    _Out_writes_(MaxEntries) PSANDBOX_PROCESS_ENTRY Entries,
    _In_ ULONG MaxEntries)
{
    PLIST_ENTRY entry;
    PPID_ENTRY  pe;
    ULONG       count;
    ULONG       copyBytes;

    if (!Entries || MaxEntries == 0)
        return 0;

    count = 0;
    SbAcquireShared(&g_Sandbox.PidLock);
    for (entry = g_Sandbox.PidList.Flink;
        entry != &g_Sandbox.PidList && count < MaxEntries;
        entry = entry->Flink)
    {
        pe = CONTAINING_RECORD(entry, PID_ENTRY, ListEntry);
        RtlZeroMemory(&Entries[count], sizeof(Entries[count]));
        Entries[count].ProcessId = HandleToULong(pe->ProcessId);
        Entries[count].ParentProcessId = HandleToULong(pe->ParentProcessId);
        Entries[count].RootProcessId = HandleToULong(pe->RootProcessId);
        if (pe->Box) {
            copyBytes = pe->Box->BoxName.Length;
            if (copyBytes > (SANDBOX_MAX_BOX - 1) * sizeof(WCHAR))
                copyBytes = (SANDBOX_MAX_BOX - 1) * sizeof(WCHAR);
            RtlCopyMemory(Entries[count].BoxName,
                pe->Box->BoxName.Buffer,
                copyBytes);
            Entries[count].BoxName[copyBytes / sizeof(WCHAR)] = L'\0';
        }
        count++;
    }
    SbRelease(&g_Sandbox.PidLock);
    return count;
}

// ============================================================
//  Pid_Remove
// ============================================================
NTSTATUS
Pid_Remove(_In_ ULONG Pid)
{
    HANDLE     h = ULongToHandle(Pid);
    PPID_ENTRY pe;

    SbAcquireExclusive(&g_Sandbox.PidLock);
    pe = Pid_Find(h);
    if (!pe) {
        SbRelease(&g_Sandbox.PidLock);
        return STATUS_NOT_FOUND;
    }
    RemoveEntryList(&pe->ListEntry);
    SbRelease(&g_Sandbox.PidLock);

    PidBitmap_OnRemove(HandleToULong(h));  /* Tier 1: clear bitmap */
    Filter_ClearProcContext(HandleToULong(h)); /* Tier 2: remove FLT context */
    ExFreePoolWithTag(pe, SANDBOX_POOL_TAG);
    DbgPrint("[SandboxFlt] Pid_Remove: PID %lu\n", Pid);
    return STATUS_SUCCESS;
}
