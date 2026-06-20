#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#if __has_include(<detours/detours.h>)
#include <detours/detours.h>
#elif __has_include(<detours.h>)
#include <detours.h>
#else
#error Microsoft Detours headers are required to build HookDll
#endif

#include "HookLogger.h"
#include "Hooks.h"

namespace {

DWORD WINAPI initializeHooks(LPVOID)
{
    hooklog::write(L"[lifecycle] HookDll initialization thread started");
    const bool installed = hooks::install();
    hooklog::write(L"[lifecycle] HookDll initialization complete installed=%d",
                   installed ? 1 : 0);
    return installed ? ERROR_SUCCESS : ERROR_FUNCTION_FAILED;
}

} // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    if (DetourIsHelperProcess())
        return TRUE;

    if (reason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();
        DisableThreadLibraryCalls(instance);
        if (HANDLE thread = CreateThread(nullptr, 0, initializeHooks,
                                         nullptr, 0, nullptr)) {
            CloseHandle(thread);
        }
    } else if (reason == DLL_PROCESS_DETACH && reserved == nullptr) {
        hooks::remove();
    }
    return TRUE;
}
