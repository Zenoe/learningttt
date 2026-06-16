// ============================================================
//  SandboxFlt_Filter.c  -  IRP_MJ_CREATE pre/post callbacks
//
//  PERFORMANCE ARCHITECTURE  v3  (based on Sandboxie source study)
//  ============================================================
//
//  Root cause of freeze:
//  The minifilter sees ALL IRP_MJ_CREATE from ALL processes on
//  ALL volumes. Chrome opens ~10,000-50,000 files/second during
//  startup. Even a 1-microsecond per-IRP cost = 10-50ms/sec of
//  pure filter overhead on a single core — enough to starve the
//  system when multiplied across Chrome's many processes and the
//  rest of the OS.
//
//  Previous attempts failed because:
//  - FltGetInstanceContext() has internal FltMgr spinlocks.
//    Called on every IRP it serializes all file I/O.
//  - Even the PID bitmap test runs on EVERY IRP from EVERY
//    process — Chrome has 20+ processes each doing thousands
//    of opens/sec.
//  - FltGetFileNameInformation(NORMALIZED) triggers recursive
//    directory opens — an IRP storm.
//
//  SOLUTION — three-tier design learned from Sandboxie:
//
//  TIER 0 (PreCreate entry, ~2 cycles):
//    Check a single global LONG g_AnyBoxActive.
//    If zero → return immediately. Zero overhead when no
//    sandboxed process is running.  Uses no locks, no function
//    calls, just one InterlockedCompareExchange-free read.
//
//  TIER 1 (PID bitmap, ~5 cycles, lock-free):
//    2048-ULONG bitmap covering all Windows PIDs.
//    Read with a single memory access. Non-sandboxed PIDs
//    (the vast majority) exit here.  No FltMgr calls at all.
//
//  TIER 2 (CUSTOM LOCK-FREE HASH MAP, ~5 cycles):
//    Replaces non-existent FLT_PROCESS_CONTEXT. Since Filter Manager 
//    doesn't natively support process context, we implement a cache-friendly,
//    lock-free fixed hash table. Each bucket fits in a single Cache Line.
//    No list walk, no locks, zero FltMgr calls on the hot path.
//
//  TIER 3 (path redirect, only for sandboxed PIDs):
//    Use FLT_FILE_NAME_OPENED (not NORMALIZED) to avoid the
//    recursive directory open storm.
//    Skip FltGetFileNameInformation entirely if TargetFileObject
//    ->FileName is empty (open-by-ID) or if it's a paging file.
//
// ============================================================

// ============================================================
//  SandboxFlt_Filter.c  -  IRP_MJ_CREATE pre/post callbacks  v4
//
//  v4 fixes: Chrome exits immediately (code 21) because:
//
//  BUG 1 — Double-redirect:
//    Our SandboxRootNt is e.g. \SandboxDemo\Box02\drive.
//    When Chrome writes a file, we rewrite the path to
//    \Device\HDD\SandboxDemo\Box02\drive\Users\...
//    But FltMgr then calls PreCreate AGAIN for that redirected
//    open (because it comes back through the filter stack).
//    We intercept it again and produce:
//    \Device\HDD\SandboxDemo\Box02\drive\SandboxDemo\Box02\drive\...
//    → STATUS_OBJECT_PATH_NOT_FOUND → Chrome dies.
//    FIX: skip any path that already starts with SandboxRootNt.
//
//  BUG 2 — Missing parent directories:
//    Chrome tries to write C:\Users\foo\AppData\Local\Google\...
//    We redirect to C:\SandboxDemo\Box02\drive\Users\foo\AppData\...
//    But that directory tree doesn't exist in the sandbox yet.
//    NTFS returns STATUS_OBJECT_PATH_NOT_FOUND.
//    FIX: Before applying IoReplaceFileObjectName, call
//    Path_EnsureParentDir() which creates the directory chain
//    inside the sandbox using FILE_OPEN_IF + FILE_DIRECTORY_FILE.
//
//  BUG 3 — System path contamination:
//    We intercept Chrome's reads/writes to \Windows\System32\,
//    \Program Files\Google\Chrome\ (its own exe and DLLs).
//    These must always come from the real FS.
//    FIX: exclude paths starting with \Windows\, \Program Files\,
//    and the sandbox root itself (BUG 1 above).
// ============================================================
// ============================================================
//  SandboxFlt_Filter.c  -  IRP_MJ_CREATE pre/post callbacks  v4
//
//  v4 fixes: Chrome exits immediately (code 21) because:
//
//  BUG 1 — Double-redirect:
//    Our SandboxRootNt is e.g. \SandboxDemo\Box02\drive.
//    When Chrome writes a file, we rewrite the path to
//    \Device\HDD\SandboxDemo\Box02\drive\Users\...
//    But FltMgr then calls PreCreate AGAIN for that redirected
//    open (because it comes back through the filter stack).
//    We intercept it again and produce:
//    \Device\HDD\SandboxDemo\Box02\drive\SandboxDemo\Box02\drive\...
//    → STATUS_OBJECT_PATH_NOT_FOUND → Chrome dies.
//    FIX: skip any path that already starts with SandboxRootNt.
//
//  BUG 2 — Missing parent directories:
//    Chrome tries to write C:\Users\foo\AppData\Local\Google\...
//    We redirect to C:\SandboxDemo\Box02\drive\Users\foo\AppData\...
//    But that directory tree doesn't exist in the sandbox yet.
//    NTFS returns STATUS_OBJECT_PATH_NOT_FOUND.
//    FIX: Before applying IoReplaceFileObjectName, call
//    Path_EnsureParentDir() which creates the directory chain
//    inside the sandbox using FILE_OPEN_IF + FILE_DIRECTORY_FILE.
//
//  BUG 3 — System path contamination:
//    We intercept Chrome's reads/writes to \Windows\System32\,
//    \Program Files\Google\Chrome\ (its own exe and DLLs).
//    These must always come from the real FS.
//    FIX: exclude paths starting with \Windows\, \Program Files\,
//    and the sandbox root itself (BUG 1 above).
// ============================================================
// ============================================================
//  SandboxFlt_Filter.c  -  IRP_MJ_CREATE pre/post callbacks  v4
//
//  v4 fixes: Chrome exits immediately (code 21) because:
//
//  BUG 1 — Double-redirect:
//    Our SandboxRootNt is e.g. \SandboxDemo\Box02\drive.
//    When Chrome writes a file, we rewrite the path to
//    \Device\HDD\SandboxDemo\Box02\drive\Users\...
//    But FltMgr then calls PreCreate AGAIN for that redirected
//    open (because it comes back through the filter stack).
//    We intercept it again and produce:
//    \Device\HDD\SandboxDemo\Box02\drive\SandboxDemo\Box02\drive\...
//    → STATUS_OBJECT_PATH_NOT_FOUND → Chrome dies.
//    FIX: skip any path that already starts with SandboxRootNt.
//
//  BUG 2 — Missing parent directories:
//    Chrome tries to write C:\Users\foo\AppData\Local\Google\...
//    We redirect to C:\SandboxDemo\Box02\drive\Users\foo\AppData\...
//    But that directory tree doesn't exist in the sandbox yet.
//    NTFS returns STATUS_OBJECT_PATH_NOT_FOUND.
//    FIX: Before applying IoReplaceFileObjectName, call
//    Path_EnsureParentDir() which creates the directory chain
//    inside the sandbox using FILE_OPEN_IF + FILE_DIRECTORY_FILE.
//
//  BUG 3 — System path contamination:
//    We intercept Chrome's reads/writes to \Windows\System32\,
//    \Program Files\Google\Chrome\ (its own exe and DLLs).
//    These must always come from the real FS.
//    FIX: exclude paths starting with \Windows\, \Program Files\,
//    and the sandbox root itself (BUG 1 above).
// ============================================================
#include "SandboxFlt.h"
#include <wdm.h>

// ============================================================
//  TIER 0 — global active-box counter
// ============================================================
volatile LONG g_AnyBoxActive = 0;

// ============================================================
//  TIER 1 — PID bitmap (lock-free)
// ============================================================
#define PID_BITMAP_ULONGS 2048
static volatile LONG g_PidBitmap[PID_BITMAP_ULONGS];

VOID PidBitmap_OnAdd(ULONG Pid)
{
    ULONG idx = (Pid / 4) / 32;
    ULONG bit = (Pid / 4) % 32;
    if (idx < PID_BITMAP_ULONGS)
        InterlockedOr(&g_PidBitmap[idx], (LONG)(1UL << bit));
}

VOID PidBitmap_OnRemove(ULONG Pid)
{
    ULONG idx = (Pid / 4) / 32;
    ULONG bit = (Pid / 4) % 32;
    if (idx < PID_BITMAP_ULONGS)
        InterlockedAnd(&g_PidBitmap[idx], (LONG)~(1UL << bit));
}

static BOOLEAN PidBitmap_Test(ULONG Pid)
{
    ULONG idx = (Pid / 4) / 32;
    ULONG bit = (Pid / 4) % 32;
    if (idx >= PID_BITMAP_ULONGS) return FALSE;
    return (BOOLEAN)(((g_PidBitmap[idx] >> bit) & 1) != 0);
}

// ============================================================
//  TIER 2 — Custom lock-free process hash table
// ============================================================
#define TIER2_HASH_SIZE        256
#define TIER2_HASH_MASK        (TIER2_HASH_SIZE - 1)
#define TIER2_SLOTS_PER_BUCKET 4

typedef struct _TIER2_ENTRY {
    volatile LONG Pid;
    PBOX_ENTRY    Box;
} TIER2_ENTRY;

typedef struct _TIER2_BUCKET {
    TIER2_ENTRY Slots[TIER2_SLOTS_PER_BUCKET];
} TIER2_BUCKET;

static TIER2_BUCKET g_ProcessTable[TIER2_HASH_SIZE];

/*
 * Hot-path caches.  A sandboxed browser can issue tens of thousands of
 * creates during startup; issuing a nested FltCreateFile for each read is
 * enough to make the box look like a system freeze.  These caches let reads
 * redirect only after this driver has already redirected a write to the same
 * original path, and avoid re-creating known parent directory chains.
 */
#define WRITE_PATH_CACHE_SIZE 4096
#define DIR_PATH_CACHE_SIZE   8192
#define CACHE_EMPTY_KEY       0

static volatile LONG g_WritePathCache[WRITE_PATH_CACHE_SIZE];
static volatile LONG g_DirPathCache[DIR_PATH_CACHE_SIZE];

static const FLT_CONTEXT_REGISTRATION c_ContextReg[] = {
    {
        FLT_STREAMHANDLE_CONTEXT,
        0,
        SandboxFlt_DirMergeContextCleanup,
        sizeof(DIR_MERGE_CONTEXT),
        SANDBOX_POOL_TAG
    },
    { FLT_CONTEXT_END }
};

const FLT_CONTEXT_REGISTRATION* Filter_GetContextReg(VOID)
{
    return c_ContextReg;
}

NTSTATUS Filter_SetProcContext(ULONG Pid, PBOX_ENTRY Box)
{
    ULONG bucketIdx = (Pid >> 2) & TIER2_HASH_MASK;
    ULONG i;
    for (i = 0; i < TIER2_SLOTS_PER_BUCKET; i++) {
        if (g_ProcessTable[bucketIdx].Slots[i].Pid == (LONG)Pid) {
            g_ProcessTable[bucketIdx].Slots[i].Box = Box;
            return STATUS_SUCCESS;
        }
    }
    for (i = 0; i < TIER2_SLOTS_PER_BUCKET; i++) {
        if (InterlockedCompareExchange(
            &g_ProcessTable[bucketIdx].Slots[i].Pid, (LONG)Pid, 0) == 0) {
            g_ProcessTable[bucketIdx].Slots[i].Box = Box;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_INSUFFICIENT_RESOURCES;
}

VOID Filter_ClearProcContext(ULONG Pid)
{
    ULONG bucketIdx = (Pid >> 2) & TIER2_HASH_MASK;
    ULONG i;
    for (i = 0; i < TIER2_SLOTS_PER_BUCKET; i++) {
        if (g_ProcessTable[bucketIdx].Slots[i].Pid == (LONG)Pid) {
            g_ProcessTable[bucketIdx].Slots[i].Box = NULL;
            InterlockedExchange(&g_ProcessTable[bucketIdx].Slots[i].Pid, 0);
            return;
        }
    }
}

PBOX_ENTRY Filter_GetProcContext(ULONG Pid)
{
    ULONG bucketIdx = (Pid >> 2) & TIER2_HASH_MASK;
    ULONG i;
    for (i = 0; i < TIER2_SLOTS_PER_BUCKET; i++) {
        if (g_ProcessTable[bucketIdx].Slots[i].Pid == (LONG)Pid)
            return g_ProcessTable[bucketIdx].Slots[i].Box;
    }
    return NULL;
}

// ============================================================
//  Path helpers
// ============================================================
static WCHAR Hash_Upcase(WCHAR ch)
{
    if (ch >= L'a' && ch <= L'z')
        return (WCHAR)(ch - (L'a' - L'A'));
    return ch;
}

static ULONG Hash_Unicode(_In_ PC_UNICODE_STRING Text, _In_ ULONG Seed)
{
    ULONG hash = Seed;
    USHORT i;
    USHORT charCount = Text->Length / sizeof(WCHAR);

    for (i = 0; i < charCount; i++) {
        hash ^= (ULONG)Hash_Upcase(Text->Buffer[i]);
        hash *= 16777619u;
    }

    if (hash == CACHE_EMPTY_KEY)
        hash = 2166136261u;
    return hash;
}

// 这两个数字是 FNV-1a 哈希算法 中定义的两个核心常量：
//2166136261u → 偏移基值（offset basis）
//16777619u → FNV 素数（FNV prime）
// generate a hash key for searching the cache for a file path
// 为文件路径生成一个用于缓存查找的哈希键值
static ULONG Path_WriteCacheKey(
    _In_ PC_UNICODE_STRING OriginalPath,
    _In_ PBOX_ENTRY Box)
{
    ULONG hash;

    hash = Hash_Unicode((PC_UNICODE_STRING)&Box->BoxName, 2166136261u);
    hash ^= Box->CacheGeneration;
    hash *= 16777619u;
    hash ^= 0x9e3779b9u;
    hash = Hash_Unicode(OriginalPath, hash);
    if (hash == CACHE_EMPTY_KEY)
        hash = 2166136261u;
    return hash;
}

static ULONG Path_ParentCacheKey(_In_ PC_UNICODE_STRING Path)
{
    UNICODE_STRING parent;
    USHORT i;
    USHORT charCount;

    charCount = Path->Length / sizeof(WCHAR);
    if (charCount == 0)
        return CACHE_EMPTY_KEY;

    for (i = charCount; i > 0; i--) {
        if (Path->Buffer[i - 1] == L'\\') {
            if (i <= 1)
                return CACHE_EMPTY_KEY;
            parent.Buffer = Path->Buffer;
            parent.Length = (USHORT)((i - 1) * sizeof(WCHAR));
            parent.MaximumLength = parent.Length;
            return Hash_Unicode((PC_UNICODE_STRING)&parent, 2166136261u);
        }
    }

    return CACHE_EMPTY_KEY;
}

// check the existence of a key in a fixed-size hash cache table o(1)
static BOOLEAN Cache_Contains(
    _In_reads_(Size) volatile LONG* Cache,
    _In_ ULONG Size,
    _In_ ULONG Key)
{
    ULONG idx;

    if (Key == CACHE_EMPTY_KEY)
        return FALSE;

	// Key & (Size - 1) is equivalent to Key % Size, but cheaper if Size is a power of 2 (which it is).
    idx = Key & (Size - 1);
    return (BOOLEAN)(Cache[idx] == (LONG)Key);
}

static VOID Cache_Add(
    _Inout_updates_(Size) volatile LONG* Cache,
    _In_ ULONG Size,
    _In_ ULONG Key)
{
    ULONG idx;

    if (Key == CACHE_EMPTY_KEY)
        return;

    idx = Key & (Size - 1);
    InterlockedExchange(&Cache[idx], (LONG)Key);
}

BOOLEAN
Path_StartsWith(_In_ PC_UNICODE_STRING Full, _In_ PC_UNICODE_STRING Prefix)
{
    UNICODE_STRING sub;
    if (Prefix->Length == 0) return TRUE;
    if (Full->Length < Prefix->Length) return FALSE;
    sub.Buffer = Full->Buffer;
    sub.Length = Prefix->Length;
    sub.MaximumLength = Prefix->Length;
    return (RtlCompareUnicodeString(&sub, (PUNICODE_STRING)Prefix, TRUE) == 0);
}

// ============================================================
//  Path_GetVolumeEnd
//  Returns index of the 3rd backslash in an NT path, e.g.:
//    \Device\HarddiskVolume3\Users\foo  → index 22
//  Returns 0 if fewer than 3 backslashes found.
// ============================================================
static USHORT Path_GetVolumeEnd(_In_ PC_UNICODE_STRING Path)
{
    USHORT i, slashCount = 0;
    USHORT charCount = Path->Length / sizeof(WCHAR);
    for (i = 0; i < charCount; i++) {
        if (Path->Buffer[i] == L'\\') {
            slashCount++;
            if (slashCount == 3) return i;
        }
    }
    return 0;
}

// ============================================================
//  Path_IsExcluded
//  Returns TRUE if this path must NEVER be redirected:
//    1. Already inside the sandbox root (double-redirect guard)
//    2. Under \Windows\ (system DLLs, fonts, etc.)
//    3. Under \Program Files\ or \Program Files (x86)\
//
//  'RelPath' is the volume-relative portion: \Users\foo\...
//  'SandboxRoot' is the box's root: \SandboxDemo\Box02\drive
// ============================================================
static BOOLEAN Path_IsExcluded(
    _In_ PC_UNICODE_STRING RelPath,
    _In_ PC_UNICODE_STRING SandboxRoot)
{
    /* Static exclusion prefixes (volume-relative, lowercase) */
    static const WCHAR kWindows[] = L"\\windows\\";
    static const WCHAR kProgFiles[] = L"\\program files\\";
    static const WCHAR kProgFiles86[] = L"\\program files (x86)\\";

    UNICODE_STRING excl;
    UNICODE_STRING sub;

    /* 1. Double-redirect guard: path starts with sandbox root */
    if (Path_StartsWith(RelPath, SandboxRoot))
        return TRUE;

    /* 2. \Windows\ */
    RtlInitUnicodeString(&excl, kWindows);
    sub.Buffer = RelPath->Buffer;
    sub.Length = excl.Length;
    sub.MaximumLength = excl.Length;
    if (RelPath->Length >= excl.Length &&
        RtlCompareUnicodeString(&sub, &excl, TRUE) == 0)
        return TRUE;

    /* 3. \Program Files\ */
    RtlInitUnicodeString(&excl, kProgFiles);
    sub.Length = sub.MaximumLength = excl.Length;
    if (RelPath->Length >= excl.Length &&
        RtlCompareUnicodeString(&sub, &excl, TRUE) == 0)
        return TRUE;

    /* 4. \Program Files (x86)\ */
    RtlInitUnicodeString(&excl, kProgFiles86);
    sub.Length = sub.MaximumLength = excl.Length;
    if (RelPath->Length >= excl.Length &&
        RtlCompareUnicodeString(&sub, &excl, TRUE) == 0)
        return TRUE;

    return FALSE;
}

// ============================================================
//  Path_EnsureParentDir
//
//  Creates the directory chain for a sandbox path STARTING
//  from the sandbox root — not from the volume prefix.
//  e.g. for \Device\HDD\SandboxDemo\Box\drive\Users\foo\bar.txt
//  and SandboxRoot = \SandboxDemo\Box\drive
//  we only create:
//    \Device\HDD\SandboxDemo\Box\drive\Users\
//    \Device\HDD\SandboxDemo\Box\drive\Users\foo\
//
//  The sandbox root itself (\Device\HDD\SandboxDemo\Box\drive)
//  is created by prepareFsRoot() in user mode before launch.
//
//  Buffer is pool-allocated (not stack) — kernel stack is limited
//  and we're already deep in the filter callback chain.
// ============================================================
static BOOLEAN Path_EnsureParentDir(
    _In_ PFLT_INSTANCE     Instance,
    _In_ PC_UNICODE_STRING SandboxFilePath,
    _In_ PC_UNICODE_STRING SandboxRootNt)   /* volume-relative root */
{
    PWCHAR          pathBuf;
    USHORT          charCount;
    USHORT          i;
    USHORT          volumeEnd;
    USHORT          rootRelEnd;  /* index where subdirs begin */
    UNICODE_STRING  dirPath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK   iosb;
    HANDLE            h;
    NTSTATUS          st;

    charCount = SandboxFilePath->Length / sizeof(WCHAR);

    /* Pool-allocate the working buffer — never use large stack arrays
     * inside a minifilter callback (kernel stack ~12KB, already deep). */
    pathBuf = (PWCHAR)ExAllocatePoolWithTag(
        NonPagedPool,
        (charCount + 1) * sizeof(WCHAR),
        SANDBOX_POOL_TAG);
    if (!pathBuf) return FALSE;

    RtlCopyMemory(pathBuf, SandboxFilePath->Buffer,
        SandboxFilePath->Length);
    pathBuf[charCount] = L'\0';

    /* Find end of volume device prefix (\Device\HarddiskVolumeN)
     * = index of the 3rd backslash */
    volumeEnd = 0;
    {
        USHORT slashCount = 0;
        for (i = 0; i < charCount; i++) {
            if (pathBuf[i] == L'\\') {
                slashCount++;
                if (slashCount == 3) { volumeEnd = i; break; }
            }
        }
    }
    if (volumeEnd == 0) {
        ExFreePoolWithTag(pathBuf, SANDBOX_POOL_TAG);
        return FALSE;
    }

    /* Find where the subdirectories begin — skip the sandbox root itself
     * (e.g. \SandboxDemo\Box\drive) since that was created in user mode.
     * rootRelEnd = volumeEnd + length-of-SandboxRootNt-in-chars */
    rootRelEnd = volumeEnd + (SandboxRootNt->Length / sizeof(WCHAR));
    if (rootRelEnd >= charCount) {
        ExFreePoolWithTag(pathBuf, SANDBOX_POOL_TAG);
        return TRUE;
    }

    /* Walk from rootRelEnd+1, creating each new directory component */
    for (i = rootRelEnd + 1; i <= charCount; i++) {
        if (i == charCount || pathBuf[i] == L'\\') {
            if (i == charCount) break; /* file itself — don't create */

            pathBuf[i] = L'\0';

            dirPath.Buffer = pathBuf;
            dirPath.Length = (USHORT)(i * sizeof(WCHAR));
            dirPath.MaximumLength = dirPath.Length + sizeof(WCHAR);

            InitializeObjectAttributes(&oa, &dirPath,
                OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

            st = FltCreateFile(
                g_Sandbox.FilterHandle,
                Instance,
                &h,
                FILE_LIST_DIRECTORY | SYNCHRONIZE,
                &oa, &iosb, NULL,
                FILE_ATTRIBUTE_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN_IF,
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                NULL, 0,
                IO_IGNORE_SHARE_ACCESS_CHECK);
            if (NT_SUCCESS(st)) {
                FltClose(h);
            }
            else if (st != STATUS_OBJECT_NAME_COLLISION &&
                st != STATUS_OBJECT_NAME_EXISTS) {
                pathBuf[i] = L'\\';
                ExFreePoolWithTag(pathBuf, SANDBOX_POOL_TAG);
                return FALSE;
            }

            pathBuf[i] = L'\\';
        }
    }

    ExFreePoolWithTag(pathBuf, SANDBOX_POOL_TAG);
    return TRUE;
}

NTSTATUS
Path_BuildRedirect(
    _In_  PC_UNICODE_STRING  OriginalPath,
    _In_  PBOX_ENTRY         Box,
    _Out_ PUNICODE_STRING    RedirectedPath)
{
    USHORT i, slashCount, volumeEnd, charCount, totalChars, off;
    PWCHAR p, buf;
    UNICODE_STRING volumePrefix, relPath;

    slashCount = 0; volumeEnd = 0;
    p = OriginalPath->Buffer;
    charCount = OriginalPath->Length / sizeof(WCHAR);

    for (i = 0; i < charCount; i++) {
        if (p[i] == L'\\') {
            slashCount++;
            if (slashCount == 3) { volumeEnd = i; break; }
        }
    }
    if (slashCount < 3) return STATUS_INVALID_PARAMETER;

    volumePrefix.Buffer = OriginalPath->Buffer;
    volumePrefix.Length = volumePrefix.MaximumLength =
        (USHORT)(volumeEnd * sizeof(WCHAR));
    relPath.Buffer = OriginalPath->Buffer + volumeEnd;
    relPath.Length = relPath.MaximumLength =
        OriginalPath->Length - volumePrefix.Length;

    totalChars = (USHORT)((volumePrefix.Length + Box->SandboxRootNt.Length +
        relPath.Length) / sizeof(WCHAR) + 1);

    buf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool,
        totalChars * sizeof(WCHAR), SANDBOX_POOL_TAG);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    off = 0;
    RtlCopyMemory(buf + off, volumePrefix.Buffer, volumePrefix.Length);
    off += volumePrefix.Length / sizeof(WCHAR);
    RtlCopyMemory(buf + off, Box->SandboxRootNt.Buffer, Box->SandboxRootNt.Length);
    off += Box->SandboxRootNt.Length / sizeof(WCHAR);
    RtlCopyMemory(buf + off, relPath.Buffer, relPath.Length);
    off += relPath.Length / sizeof(WCHAR);
    buf[off] = L'\0';

    RedirectedPath->Buffer = buf;
    RedirectedPath->Length = (USHORT)(off * sizeof(WCHAR));
    RedirectedPath->MaximumLength = (USHORT)(totalChars * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

NTSTATUS
Path_BuildRedirectRelative(
    _In_  PC_UNICODE_STRING  OriginalPath,
    _In_  PBOX_ENTRY         Box,
    _Out_ PUNICODE_STRING    RedirectedPath)
{
    USHORT i, slashCount, volumeEnd, charCount, totalChars, off;
    PWCHAR p, buf;
    UNICODE_STRING relPath;

    slashCount = 0;
    volumeEnd = 0;
    p = OriginalPath->Buffer;
    charCount = OriginalPath->Length / sizeof(WCHAR);

    for (i = 0; i < charCount; i++) {
        if (p[i] == L'\\') {
            slashCount++;
            if (slashCount == 3) { volumeEnd = i; break; }
        }
    }
    if (slashCount < 3) return STATUS_INVALID_PARAMETER;

    relPath.Buffer = OriginalPath->Buffer + volumeEnd;
    relPath.Length = relPath.MaximumLength =
        OriginalPath->Length - (USHORT)(volumeEnd * sizeof(WCHAR));

    totalChars = (USHORT)((Box->SandboxRootNt.Length +
        relPath.Length) / sizeof(WCHAR) + 1);

    buf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool,
        totalChars * sizeof(WCHAR), SANDBOX_POOL_TAG);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    off = 0;
    RtlCopyMemory(buf + off, Box->SandboxRootNt.Buffer, Box->SandboxRootNt.Length);
    off += Box->SandboxRootNt.Length / sizeof(WCHAR);
    RtlCopyMemory(buf + off, relPath.Buffer, relPath.Length);
    off += relPath.Length / sizeof(WCHAR);
    buf[off] = L'\0';

    RedirectedPath->Buffer = buf;
    RedirectedPath->Length = (USHORT)(off * sizeof(WCHAR));
    RedirectedPath->MaximumLength = (USHORT)(totalChars * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

static BOOLEAN IsWriteIntent(_In_ PFLT_CALLBACK_DATA Data)
{
    ACCESS_MASK access = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    ULONG       disp = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
    if (access & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES |
        FILE_WRITE_EA | GENERIC_WRITE | DELETE)) return TRUE;
    if (disp == FILE_CREATE || disp == FILE_SUPERSEDE ||
        disp == FILE_OVERWRITE || disp == FILE_OVERWRITE_IF) return TRUE;
    return FALSE;
}

// ============================================================
//  SandboxFlt_PreCreate  —  THE HOT PATH
// ============================================================
FLT_PREOP_CALLBACK_STATUS
SandboxFlt_PreCreate(
    _Inout_ PFLT_CALLBACK_DATA             Data,
    _In_    PCFLT_RELATED_OBJECTS          FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext)
{
    PBOX_ENTRY                 box;
    PFLT_FILE_NAME_INFORMATION nameInfo;
    BOOLEAN                    isWrite;
    BOOLEAN                    doRedirect;
    UNICODE_STRING             fullPath;
    UNICODE_STRING             fileObjectPath;
    UNICODE_STRING             relPath;
    NTSTATUS                   status;
    USHORT                     copyLen;
    USHORT                     volumeEnd;
    ULONG                      pid;
    ULONG                      writeKey;
    ULONG                      parentKey;
    KIRQL                      oldIrql;      // BUG D FIX: needed for spinlock
    *CompletionContext = NULL;

    // Initialize path buffers to NULL so cleanup is safe on all exit paths.
    fullPath.Buffer = NULL;
    fileObjectPath.Buffer = NULL;

    /* ---- TIER 0 ---- */
    if (g_AnyBoxActive == 0)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) ||
        FlagOn(Data->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* ---- TIER 1 ---- */
    pid = HandleToULong(PsGetCurrentProcessId());
    if (!PidBitmap_Test(pid))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* ---- TIER 2: hash table lookup ---- */
    box = NULL;
    {
        ULONG bucketIdx = (pid >> 2) & TIER2_HASH_MASK;
        ULONG i;
        for (i = 0; i < TIER2_SLOTS_PER_BUCKET; i++) {
            if (g_ProcessTable[bucketIdx].Slots[i].Pid == (LONG)pid) {
                box = g_ProcessTable[bucketIdx].Slots[i].Box;
                break;
            }
        }
    }
    if (!box) {
        PidBitmap_OnRemove(pid);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* ---- TIER 3: policy checks ---- */
    isWrite = IsWriteIntent(Data);

    if (!isWrite && !box->RedirectReads) {
        InterlockedIncrement(&g_Sandbox.TotalPassThrough);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (box->WritePolicy == SandboxPolicy_Block && isWrite) {
        InterlockedIncrement(&g_Sandbox.TotalBlocked);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    if (box->WritePolicy == SandboxPolicy_PassThrough) {
        InterlockedIncrement(&g_Sandbox.TotalPassThrough);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Skip open-by-ID and empty filenames */
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!Data->Iopb->TargetFileObject ||
        Data->Iopb->TargetFileObject->FileName.Length == 0)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* ---- Get file name (OPENED, not NORMALIZED) ---- */
    nameInfo = NULL;
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* ---- BUG 1+3 FIX: exclusion check ----
     * Extract the volume-relative portion of the path and check
     * whether it should be excluded from redirection.
     *
     * nameInfo->Name is the full NT path:
     *   \Device\HarddiskVolume3\Users\foo\bar.txt
     * volumeEnd is the index of the 3rd backslash (22 in example).
     * relPath starts at that backslash: \Users\foo\bar.txt
     *
     * We check:
     *   a) relPath starts with SandboxRootNt → already redirected
     *      (double-redirect guard — fixes BUG 1)
     *   b) relPath starts with \Windows\, \Program Files\ etc.
     *      (system exclusion — fixes BUG 3)
     */
    volumeEnd = Path_GetVolumeEnd((PC_UNICODE_STRING)&nameInfo->Name);
    if (volumeEnd == 0) {
        /* Couldn't parse volume prefix — pass through safely */
        FltReleaseFileNameInformation(nameInfo);
        InterlockedIncrement(&g_Sandbox.TotalPassThrough);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    relPath.Buffer = nameInfo->Name.Buffer + volumeEnd;
    relPath.Length = nameInfo->Name.Length - (USHORT)(volumeEnd * sizeof(WCHAR));
    relPath.MaximumLength = relPath.Length;

    if (Path_IsExcluded((PC_UNICODE_STRING)&relPath,
        (PC_UNICODE_STRING)&box->SandboxRootNt)) {
        FltReleaseFileNameInformation(nameInfo);
        InterlockedIncrement(&g_Sandbox.TotalPassThrough);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* ---- Decide redirect ---- */
    writeKey = Path_WriteCacheKey((PC_UNICODE_STRING)&nameInfo->Name, box);
    doRedirect = isWrite;
    if (!doRedirect && box->RedirectReads) {
        doRedirect = Cache_Contains(g_WritePathCache,
            WRITE_PATH_CACHE_SIZE, writeKey);
    }

    if (!doRedirect) {
        FltReleaseFileNameInformation(nameInfo);
        InterlockedIncrement(&g_Sandbox.TotalPassThrough);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* ---- Build redirect paths ----
     * FltCreateFile needs a full NT path.  IoReplaceFileObjectName needs
     * the name format the file system expects after the volume was already
     * selected, which is volume-relative for ordinary creates.
     */
    // fullPath: "\Device\HarddiskVolume4\SandboxDemo\Box00\drive\Users\admin"
    status = Path_BuildRedirect(&nameInfo->Name, box, &fullPath);
    if (NT_SUCCESS(status)) {
        //fileObjectPath: ""\SandboxDemo\Box00\drive\Users\admin""
        status = Path_BuildRedirectRelative(&nameInfo->Name, box,
            &fileObjectPath);
    }
    FltReleaseFileNameInformation(nameInfo);

    if (!NT_SUCCESS(status)) {
        // BUG B FIX: if Path_BuildRedirect succeeded but
        // Path_BuildRedirectRelative failed, fullPath.Buffer is already
        // allocated and must be freed here before returning.
        if (fullPath.Buffer)
            ExFreePoolWithTag(fullPath.Buffer, SANDBOX_POOL_TAG);
        InterlockedIncrement(&g_Sandbox.TotalPassThrough);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* ---- BUG 2 FIX: ensure parent directories exist in sandbox ----
     * Before rewriting the filename, create the entire parent directory
     * chain inside the sandbox. Without this, NTFS returns
     * STATUS_OBJECT_PATH_NOT_FOUND and Chrome crashes.
     */
    if (isWrite) {
        parentKey = Path_ParentCacheKey((PC_UNICODE_STRING)&fullPath);
        if (!Cache_Contains(g_DirPathCache, DIR_PATH_CACHE_SIZE, parentKey)) {
            if (Path_EnsureParentDir(FltObjects->Instance,
                (PC_UNICODE_STRING)&fullPath,
                (PC_UNICODE_STRING)&box->SandboxRootNt)) {
                Cache_Add(g_DirPathCache, DIR_PATH_CACHE_SIZE, parentKey);
            }
        }
    }

    /* ---- Apply the redirect ---- */
    // RelatedFileObject 通常用于表示相对于某个目录的文件
    // 设为 NULL 确保路径替换时不会产生相对路径解析问题 避免内核混淆"这个文件相对于什么"
    Data->Iopb->TargetFileObject->RelatedFileObject = NULL;
    status = IoReplaceFileObjectName(Data->Iopb->TargetFileObject,
        fileObjectPath.Buffer, fileObjectPath.Length);
    if (NT_SUCCESS(status)) {
		// 告诉FltMgr已经修改了 Data 中的内容,ensures that the changes are used when the I/O operation is performed.
        FltSetCallbackDataDirty(Data);
        InterlockedIncrement(&g_Sandbox.TotalRedirects);
		// Cache the last redirected path for debugging purposes.  We truncate to fit the buffer, but that's fine since it's only for diagnostics and not used in any logic.
        // BUG D FIX: LastRedirectedPath is a shared global written from any
        // arbitrary thread.  Protect the copy + NUL-termination with the
        // dedicated spinlock to prevent a data race on SMP systems.
        // (This field is diagnostic-only, so a spinlock is sufficient and
        // keeps the fast path cheap.)
        copyLen = min(fullPath.Length,
            (SANDBOX_MAX_PATH - 1) * sizeof(WCHAR));
        KeAcquireSpinLock(&g_Sandbox.LastRedirectedPathLock, &oldIrql);
        RtlCopyMemory(g_Sandbox.LastRedirectedPath,
            fullPath.Buffer, copyLen);
        g_Sandbox.LastRedirectedPath[copyLen / sizeof(WCHAR)] = L'\0';
        KeReleaseSpinLock(&g_Sandbox.LastRedirectedPathLock, oldIrql);
        if (isWrite)
			// Cache the write-intent path for redirecting future reads without needing to parse the full path again.
            Cache_Add(g_WritePathCache, WRITE_PATH_CACHE_SIZE, writeKey);
        DbgPrint("[SandboxFlt] PID=%lu REDIR -> %wZ\n", pid, &fullPath);
    }
    else {
        InterlockedIncrement(&g_Sandbox.TotalPassThrough);
        DbgPrint("[SandboxFlt] IoReplaceFileObjectName failed: %08x\n", status);
		if (fileObjectPath.Buffer)
			ExFreePoolWithTag(fileObjectPath.Buffer, SANDBOX_POOL_TAG);
    }

	// BUG B FIX: fullPath.Buffer is always caller-owned regardless of
    // IoReplaceFileObjectName's outcome.  Free it unconditionally here,
	// after all uses (DbgPrint above) are complete.
    if (fullPath.Buffer)
        ExFreePoolWithTag(fullPath.Buffer, SANDBOX_POOL_TAG);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
SandboxFlt_PostCreate(
    _Inout_ PFLT_CALLBACK_DATA       Data,
    _In_    PCFLT_RELATED_OBJECTS    FltObjects,
    _In_opt_ PVOID                   CompletionContext,
    _In_    FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

VOID
SandboxFlt_DirMergeContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType)
{
    PDIR_MERGE_CONTEXT ctx;

    UNREFERENCED_PARAMETER(ContextType);

    ctx = (PDIR_MERGE_CONTEXT)Context;
    if (ctx->SandboxHandle) {
        FltClose(ctx->SandboxHandle);
        ctx->SandboxHandle = NULL;
    }
    if (ctx->SandboxFileObject) {
        ObDereferenceObject(ctx->SandboxFileObject);
        ctx->SandboxFileObject = NULL;
    }
}

static PBOX_ENTRY
Filter_GetCurrentBox(VOID)
{
    ULONG pid;

    if (g_AnyBoxActive == 0)
        return NULL;

    pid = HandleToULong(PsGetCurrentProcessId());
    if (!PidBitmap_Test(pid))
        return NULL;

    return Filter_GetProcContext(pid);
}

FLT_PREOP_CALLBACK_STATUS
SandboxFlt_PreDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA             Data,
    _In_    PCFLT_RELATED_OBJECTS          FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext)
{
    PBOX_ENTRY box;
    PDIR_MERGE_CONTEXT ctx;
    PFLT_CONTEXT rawCtx;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    box = Filter_GetCurrentBox();
    if (!box || !box->RedirectReads)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (FlagOn(Data->Iopb->OperationFlags, SL_RESTART_SCAN)) {
        rawCtx = NULL;
        status = FltGetStreamHandleContext(FltObjects->Instance,
            FltObjects->FileObject,
            &rawCtx);
        if (NT_SUCCESS(status)) {
            ctx = (PDIR_MERGE_CONTEXT)rawCtx;
            ctx->SandboxStarted = FALSE;
            ctx->SandboxDone = FALSE;
            FltReleaseContext(ctx);
        }
    }

    /*
     * Directory query buffers are commonly user buffers.  Lock them in pre-op
     * so post-op can safely replace STATUS_NO_MORE_FILES with sandbox entries.
    FltLockUserBuffer is used to lock the user application's memory buffer into physical memory (RAM) and create a safe mapping for the kernel to access.
     */
    status = FltLockUserBuffer(Data);
    if (!NT_SUCCESS(status))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    *CompletionContext = box;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static PVOID
DirQuery_GetSystemBuffer(_In_ PFLT_CALLBACK_DATA Data)
{
    PMDL mdl;

    mdl = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress;
    if (mdl)
        return MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);

    return Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
}

// FltObjects Standard mini-filter callback object containing Instance, FileObject, Volume
/*
Path_BuildRedirect()
        ↓
   sandboxPath (UNICODE_STRING)
        ↓
   InitializeObjectAttributes()
        ↓
   FltCreateFileEx() 
        ↓
   ctx->SandboxFileObject  +  ctx->SandboxHandle
        ↓
   FltSetStreamHandleContext()  → attached to original FileObject
        ↓
   Cleanup: ExFreePoolWithTag(sandboxPath.Buffer)
*/
NTSTATUS
DirMerge_OpenSandboxDirectory(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PBOX_ENTRY Box,
    _Outptr_ PDIR_MERGE_CONTEXT* OutCtx)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PDIR_MERGE_CONTEXT ctx = NULL;
    PFLT_CONTEXT rawCtx = NULL;
    UNICODE_STRING sandboxPath = { 0 };
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    BOOLEAN pathAllocated = FALSE;

    *OutCtx = NULL;

    // 1. Get file name information
    status = FltGetFileNameInformationUnsafe(FltObjects->FileObject,
        FltObjects->Instance,
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status))
        return status;

    status = FltParseFileNameInformation(nameInfo);
    if (NT_SUCCESS(status)) {
        status = Path_BuildRedirect((PC_UNICODE_STRING)&nameInfo->Name,
            Box, &sandboxPath);
        if (NT_SUCCESS(status)) {
            pathAllocated = TRUE;
        }
    }
    FltReleaseFileNameInformation(nameInfo);

    if (!NT_SUCCESS(status))
        return status;

    // 2. Allocate Minifilter Context
    status = FltAllocateContext(g_Sandbox.FilterHandle,
        FLT_STREAMHANDLE_CONTEXT,
        sizeof(DIR_MERGE_CONTEXT),
        NonPagedPool,
        &rawCtx);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    ctx = (PDIR_MERGE_CONTEXT)rawCtx;
    RtlZeroMemory(ctx, sizeof(*ctx));

    // 3. Initialize attributes and open the sandbox directory
    InitializeObjectAttributes(&oa, &sandboxPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // open sandbox directory by kernel privilege, retrieving the handle
    status = FltCreateFileEx(g_Sandbox.FilterHandle,
        FltObjects->Instance,
        &ctx->SandboxHandle,
        &ctx->SandboxFileObject,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK);

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // 4. Set the stream handle context
    // PDIR_MERGE_CONTEXT (ctx) stores persistent information:
    //      HANDLE         SandboxHandle;      // Handle to sandbox directory
    //		PFILE_OBJECT   SandboxFileObject;  // FileObject of sandbox directory
    // Only the opened handles are kept — not the path string.
    // 将自定义数据结构与文件对象关联
    status = FltSetStreamHandleContext(FltObjects->Instance,
        FltObjects->FileObject,   // original directory
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        ctx,
        NULL);

    // Handle race condition where another thread set it first
    // 多线程并发设置同一个 FileObject 上下文 
    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        // Close handles opened for the local duplicate context
        FltClose(ctx->SandboxHandle);
        ObDereferenceObject(ctx->SandboxFileObject);

        // Release our allocation reference
        FltReleaseContext(ctx);
        ctx = NULL;

        // Retrieve the existing context (adds 1 to ref count)
        status = FltGetStreamHandleContext(FltObjects->Instance,
            FltObjects->FileObject,
            &rawCtx);
        if (NT_SUCCESS(status)) {
            *OutCtx = (PDIR_MERGE_CONTEXT)rawCtx;
        }
        goto Cleanup;
    }

    if (!NT_SUCCESS(status)) {
        // If setting context failed for any other reason, clean up the handles
        FltClose(ctx->SandboxHandle);
        ObDereferenceObject(ctx->SandboxFileObject);
        goto Cleanup;
    }

    // Success path for newly created context
    *OutCtx = ctx;
    status = STATUS_SUCCESS;

Cleanup:
    // Always free the allocated path buffer
    if (pathAllocated) {
        ExFreePoolWithTag(sandboxPath.Buffer, SANDBOX_POOL_TAG);
    }

    // If we encountered an error and ctx was allocated but not set, release it
    if (!NT_SUCCESS(status) && ctx != NULL) {
        FltReleaseContext(ctx);
    }

    return status;
}

FLT_POSTOP_CALLBACK_STATUS
SandboxFlt_PostDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA       Data,
    _In_    PCFLT_RELATED_OBJECTS    FltObjects,
    _In_opt_ PVOID                   CompletionContext,
    _In_    FLT_POST_OPERATION_FLAGS Flags)
{
    PBOX_ENTRY box;
    PDIR_MERGE_CONTEXT ctx;
    PFLT_CONTEXT rawCtx;
    PVOID buffer;
    ULONG length;
    ULONG bytesReturned;
    BOOLEAN restartScan;
    BOOLEAN returnSingleEntry;
    NTSTATUS status;

	// todo, completioncontext need clean or not? if the context is stored in stream handle context, it will be automatically released by the framework when the handle is closed,
    // so we don't need to manually free it here. However, if we allocated any additional resources in the context that are not automatically managed by the framework,
    // we would need to ensure they are properly cleaned up in the context cleanup callback (SandboxFlt_DirMergeContextCleanup in this case). Since we're using FltAllocateContext and FltSetStreamHandleContext,
    // the framework will take care of releasing the context when it's no longer needed, so we don't have to worry about manual cleanup in this post-op callback.
    //if (BooleanFlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
    //    // 2. Safely clean up any context passed from Pre-Op
    //    if (CompletionContext != NULL) {
    //        // Assuming CompletionContext was allocated via ExAllocatePool / FltAllocatePool
    //        ExFreePoolWithTag(CompletionContext, MY_POOL_TAG);
    //    }
    //    // 3. Must return finished processing immediately
    //    return FLT_POSTOP_FINISHED_PROCESSING;
    //}

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
        return FLT_POSTOP_FINISHED_PROCESSING;

    /*
     * Let the real directory enumerate normally.  Only when the host side is
     * exhausted do we continue enumeration from the sandbox overlay directory.
     */
    if (Data->IoStatus.Status != STATUS_NO_MORE_FILES &&
        Data->IoStatus.Status != STATUS_NO_SUCH_FILE)
        return FLT_POSTOP_FINISHED_PROCESSING;

    box = (PBOX_ENTRY)CompletionContext;
    if (!box)
        return FLT_POSTOP_FINISHED_PROCESSING;

    // return a safe kernel-mode virtual address to the output buffer that will contain the directory listing results (FILE_DIRECTORY_INFORMATION, FILE_BOTH_DIR_INFORMATION, etc.).
    buffer = DirQuery_GetSystemBuffer(Data);
    length = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;
    if (!buffer || length == 0)
        return FLT_POSTOP_FINISHED_PROCESSING;

    ctx = NULL;
    rawCtx = NULL;
    status = FltGetStreamHandleContext(FltObjects->Instance,
        FltObjects->FileObject,
        &rawCtx);
    if (NT_SUCCESS(status))
        ctx = (PDIR_MERGE_CONTEXT)rawCtx;
    if (!NT_SUCCESS(status)) {
        // opens a handle (SandboxHandle) and a FileObject (SandboxFileObject) to the sandbox directory.
        // after FltCreateFileEx in this fun, ctx->SandboxHandle and ctx->SandboxFileObject now represent the opened sandbox directory.
        status = DirMerge_OpenSandboxDirectory(FltObjects, box, &ctx);
    }
    if (!NT_SUCCESS(status) || !ctx)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (ctx->SandboxDone) {
        FltReleaseContext(ctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    restartScan = (BOOLEAN)(FlagOn(Data->Iopb->OperationFlags, SL_RESTART_SCAN) ||
        !ctx->SandboxStarted);
    returnSingleEntry = (BOOLEAN)FlagOn(Data->Iopb->OperationFlags,
        SL_RETURN_SINGLE_ENTRY);

    bytesReturned = 0;
    status = FltQueryDirectoryFile(FltObjects->Instance,
        ctx->SandboxFileObject,  // ← Uses the opened sandbox FileObject(in DirMerge_OpenSandboxDirectory)
        buffer,
        length,
        Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass,
        returnSingleEntry,
        Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileName,
        restartScan,
        &bytesReturned);

    ctx->SandboxStarted = TRUE;
    if (status == STATUS_NO_MORE_FILES || status == STATUS_NO_SUCH_FILE)
        ctx->SandboxDone = TRUE;

    if (NT_SUCCESS(status)) {
        Data->IoStatus.Status = STATUS_SUCCESS;
        Data->IoStatus.Information = bytesReturned;
    }

    FltReleaseContext(ctx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================
//  SandboxFlt_PreNetworkQueryOpen
//
//  NtQueryAttributesFile and NtQueryFullAttributesFile use a
//  FAST PATH called "Network Query Open" that bypasses the
//  normal IRP_MJ_CREATE flow and goes straight to the FS
//  driver. It is exposed to minifilters as IRP_MJ_NETWORK_QUERY_OPEN.
//
//  This is what notepad calls after saving to check the file
//  exists. Without intercepting it, the query hits the REAL
//  path (where the file doesn't exist) -> "path not found".
//
//  Strategy: if the sandboxed PID queries a path and a sandbox
//  copy exists, rewrite the query to point at the sandbox copy.
//  We do this by closing the fast-path and re-issuing it as
//  a normal IRP_MJ_CREATE, then filling in the attributes
//  from the sandbox file.
//
//  Simpler approach used here: return STATUS_FLT_DISALLOW_FAST_IO
//  which forces Windows to fall back to the slow path (full
//  IRP_MJ_CREATE), which our PreCreate DOES intercept.
//  Cost: one extra round-trip for attribute queries from
//  sandboxed processes. This is rare compared to file I/O.
// ============================================================
FLT_PREOP_CALLBACK_STATUS
SandboxFlt_PreNetworkQueryOpen(
    _Inout_ PFLT_CALLBACK_DATA             Data,
    _In_    PCFLT_RELATED_OBJECTS          FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext)
{
    ULONG pid;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    /* Tier 0: fast exit if no sandboxed process active */
    if (g_AnyBoxActive == 0)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    pid = HandleToULong(PsGetCurrentProcessId());
    if (!PidBitmap_Test(pid))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Verify this PID is actually in our table */
    {
        ULONG bucketIdx = (pid >> 2) & TIER2_HASH_MASK;
        ULONG i;
        BOOLEAN found = FALSE;
        for (i = 0; i < TIER2_SLOTS_PER_BUCKET; i++) {
            if (g_ProcessTable[bucketIdx].Slots[i].Pid == (LONG)pid) {
                found = TRUE;
                break;
            }
        }
        if (!found) {
            PidBitmap_OnRemove(pid);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    /* Force fallback to slow path (full IRP_MJ_CREATE).
     * Our PreCreate will then intercept it and redirect to sandbox.
     * This is the correct documented way to handle this in a minifilter. */
    UNREFERENCED_PARAMETER(Data);
    return FLT_PREOP_DISALLOW_FASTIO;
}
