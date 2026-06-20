#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

// Creates a Detours-injected process. When the host is elevated, the process
// is created with the interactive user's medium-integrity token so Chromium
// does not de-elevate by relaunching itself and lose the injected DLL.
BOOL DetourCreateProcessWithDllForInteractiveUser(
    LPCWSTR applicationName,
    LPWSTR commandLine,
    LPSECURITY_ATTRIBUTES processAttributes,
    LPSECURITY_ATTRIBUTES threadAttributes,
    BOOL inheritHandles,
    DWORD creationFlags,
    LPVOID environment,
    LPCWSTR currentDirectory,
    LPSTARTUPINFOW startupInfo,
    LPPROCESS_INFORMATION processInformation,
    LPCSTR dllName,
    bool* usedInteractiveToken = nullptr);
