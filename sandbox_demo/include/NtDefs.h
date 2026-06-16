#pragma once
// ============================================================
//  NtDefs.h
//  Undocumented / semi-documented NT kernel structures needed
//  to manipulate the Object Manager namespace directly.
//
//  Technique borrowed from Sandboxie's SbieDrv / SbieAPI:
//    - RtlInitUnicodeString  → build kernel string
//    - NtCreateDirectoryObject → carve a private namespace dir
//    - NtOpenDirectoryObject  → open existing namespace dir
//    - RtlCreateBoundaryDescriptor / RtlAddSIDToBoundaryDescriptor
//      → create a private namespace boundary (Vista+)
//    - CreatePrivateNamespace / OpenPrivateNamespace (kernel32)
//      → user-mode wrappers for the above
// ============================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>   // UNICODE_STRING, OBJECT_ATTRIBUTES
#include <ntstatus.h>
#include <sddl.h>
#include <aclapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Advapi32.lib")

// ---- NT status & access masks not in every SDK header -------
#ifndef STATUS_SUCCESS
#  define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#define DIRECTORY_QUERY                 0x0001
#define DIRECTORY_TRAVERSE              0x0002
#define DIRECTORY_CREATE_OBJECT         0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY   0x0008
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

// ---- InitializeObjectAttributes helper ----------------------
#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p,n,a,r,s) \
{                                              \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);   \
    (p)->RootDirectory = r;                    \
    (p)->Attributes = a;                       \
    (p)->ObjectName = n;                       \
    (p)->SecurityDescriptor = s;               \
    (p)->SecurityQualityOfService = NULL;      \
}
#endif

// ---- Function pointer types for dynamic loading --------------
using PFN_RtlInitUnicodeString = VOID(NTAPI*)(
    PUNICODE_STRING DestinationString,
    PCWSTR          SourceString);

using PFN_NtCreateDirectoryObject = NTSTATUS(NTAPI*)(
    PHANDLE            DirectoryHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

using PFN_NtOpenDirectoryObject = NTSTATUS(NTAPI*)(
    PHANDLE            DirectoryHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

using PFN_NtClose = NTSTATUS(NTAPI*)(HANDLE Handle);

// ---- Dynamically resolve ntdll exports ----------------------
struct NtApi {
    PFN_RtlInitUnicodeString    RtlInitUnicodeString    = nullptr;
    PFN_NtCreateDirectoryObject NtCreateDirectoryObject = nullptr;
    PFN_NtOpenDirectoryObject   NtOpenDirectoryObject   = nullptr;
    PFN_NtClose                 NtClose                 = nullptr;

    bool load() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;

#define LOAD(fn) fn = reinterpret_cast<PFN_##fn>(GetProcAddress(ntdll, #fn)); \
                 if (!fn) return false;
        LOAD(RtlInitUnicodeString)
        LOAD(NtCreateDirectoryObject)
        LOAD(NtOpenDirectoryObject)
        LOAD(NtClose)
#undef LOAD
        return true;
    }
};

inline NtApi& getNtApi() {
    static NtApi api;
    static bool loaded = api.load();
    return api;
}
