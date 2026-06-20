#include "DetourProcessLauncher.h"

#if __has_include(<detours/detours.h>)
#include <detours/detours.h>
#elif __has_include(<detours.h>)
#include <detours.h>
#else
#error Microsoft Detours headers are required to build SandboxDemo
#endif

namespace {

thread_local HANDLE g_interactiveToken = nullptr;

bool tokenIsElevated(HANDLE token)
{
    TOKEN_ELEVATION elevation{};
    DWORD bytes = 0;
    return GetTokenInformation(token, TokenElevation, &elevation,
                               sizeof(elevation), &bytes) &&
           elevation.TokenIsElevated != FALSE;
}

HANDLE duplicatePrimaryToken(HANDLE token)
{
    HANDLE primary = nullptr;
    if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, nullptr,
                          SecurityImpersonation, TokenPrimary, &primary)) {
        return nullptr;
    }
    return primary;
}

HANDLE linkedMediumToken()
{
    HANDLE processToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE,
                          &processToken)) {
        return nullptr;
    }

    HANDLE result = nullptr;
    if (tokenIsElevated(processToken)) {
        TOKEN_LINKED_TOKEN linked{};
        DWORD bytes = 0;
        if (GetTokenInformation(processToken, TokenLinkedToken, &linked,
                                sizeof(linked), &bytes)) {
            result = duplicatePrimaryToken(linked.LinkedToken);
            CloseHandle(linked.LinkedToken);
        }
    }
    CloseHandle(processToken);
    return result;
}

HANDLE shellPrimaryToken()
{
    const HWND shellWindow = GetShellWindow();
    if (!shellWindow)
        return nullptr;

    DWORD processId = 0;
    GetWindowThreadProcessId(shellWindow, &processId);
    if (!processId)
        return nullptr;

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                 FALSE, processId);
    if (!process)
        return nullptr;

    HANDLE token = nullptr;
    HANDLE result = nullptr;
    if (OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE |
                         TOKEN_ASSIGN_PRIMARY, &token)) {
        if (!tokenIsElevated(token))
            result = duplicatePrimaryToken(token);
        CloseHandle(token);
    }
    CloseHandle(process);
    return result;
}

HANDLE interactiveMediumToken()
{
    HANDLE token = linkedMediumToken();
    if (!token)
        token = shellPrimaryToken();
    return token;
}

BOOL WINAPI createProcessWithInteractiveToken(
    LPCWSTR applicationName,
    LPWSTR commandLine,
    LPSECURITY_ATTRIBUTES processAttributes,
    LPSECURITY_ATTRIBUTES threadAttributes,
    BOOL inheritHandles,
    DWORD creationFlags,
    LPVOID environment,
    LPCWSTR currentDirectory,
    LPSTARTUPINFOW startupInfo,
    LPPROCESS_INFORMATION processInformation)
{
    if (!g_interactiveToken) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    BOOL result = CreateProcessAsUserW(
        g_interactiveToken, applicationName, commandLine,
        processAttributes, threadAttributes, inheritHandles, creationFlags,
        environment, currentDirectory, startupInfo, processInformation);
    if (!result && GetLastError() == ERROR_PRIVILEGE_NOT_HELD &&
        !inheritHandles && !processAttributes && !threadAttributes) {
        result = CreateProcessWithTokenW(
            g_interactiveToken, LOGON_WITH_PROFILE, applicationName,
            commandLine, creationFlags, environment, currentDirectory,
            startupInfo, processInformation);
    }
    return result;
}

} // namespace

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
    bool* usedInteractiveToken)
{
    if (usedInteractiveToken)
        *usedInteractiveToken = false;

    HANDLE currentToken = nullptr;
    bool elevated = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &currentToken)) {
        elevated = tokenIsElevated(currentToken);
        CloseHandle(currentToken);
    }

    HANDLE interactiveToken = elevated ? interactiveMediumToken() : nullptr;
    if (elevated && !interactiveToken) {
        SetLastError(ERROR_NO_TOKEN);
        return FALSE;
    }

    g_interactiveToken = interactiveToken;
    const BOOL result = DetourCreateProcessWithDllExW(
        applicationName, commandLine, processAttributes, threadAttributes,
        inheritHandles, creationFlags, environment, currentDirectory,
        startupInfo, processInformation, dllName,
        interactiveToken ? createProcessWithInteractiveToken : nullptr);
    const DWORD error = GetLastError();
    g_interactiveToken = nullptr;

    if (usedInteractiveToken)
        *usedInteractiveToken = interactiveToken != nullptr;
    if (interactiveToken)
        CloseHandle(interactiveToken);
    SetLastError(error);
    return result;
}
