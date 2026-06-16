// ============================================================
//  SandboxBorder.cpp  —  Injected shell-broker payload
//
//  Window borders and title prefixes are owned by the Qt host. This DLL
//  only redirects "Show in folder" requests to the host broker so Explorer
//  can be launched inside the same sandbox box.
// ============================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SANDBOXBORDER_EXPORTS
#include "SandboxBorder.h"
#include <shlobj.h>
#include <shellapi.h>
#include <string>
#include <cstdio>

#pragma comment(lib, "Shell32.lib")

static wchar_t g_BoxName[64] = {};
static constexpr wchar_t g_PipeName[] = SANDBOX_PIPE_NAME;

using PFN_SHOpenFolderAndSelectItems = HRESULT(WINAPI*)(
    PCIDLIST_ABSOLUTE, UINT, PCUITEMID_CHILD_ARRAY, DWORD);
using PFN_ShellExecuteW = HINSTANCE(WINAPI*)(
    HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);

static PFN_SHOpenFolderAndSelectItems g_origSHOpen = nullptr;
static PFN_ShellExecuteW g_origShellExecuteW = nullptr;

static void NotifyHostOpenFolder(const wchar_t* realPath)
{
    HANDLE hPipe = CreateFileW(g_PipeName, GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE)
        return;

    char boxUtf8[64] = {};
    char pathUtf8[MAX_PATH * 2] = {};
    WideCharToMultiByte(CP_UTF8, 0, g_BoxName, -1,
        boxUtf8, sizeof(boxUtf8), nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, realPath, -1,
        pathUtf8, sizeof(pathUtf8), nullptr, nullptr);

    std::string escapedPath;
    for (char ch : std::string(pathUtf8))
        escapedPath += ch == '\\' ? "\\\\" : std::string(1, ch);

    char message[1024];
    int length = _snprintf_s(message, sizeof(message), _TRUNCATE,
        "{\"cmd\":\"openFolder\",\"box\":\"%s\",\"path\":\"%s\"}\n",
        boxUtf8, escapedPath.c_str());

    DWORD written = 0;
    WriteFile(hPipe, message, static_cast<DWORD>(length), &written, nullptr);
    CloseHandle(hPipe);
}

static bool PatchIAT(HMODULE module, const char* dll, const char* function,
    PROC replacement, PROC* original)
{
    if (!module)
        return false;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<BYTE*>(module) + dos->e_lfanew);
    auto& importDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress)
        return false;

    auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        reinterpret_cast<BYTE*>(module) + importDir.VirtualAddress);
    for (; descriptor->Name; ++descriptor) {
        auto* importedDll = reinterpret_cast<char*>(
            reinterpret_cast<BYTE*>(module) + descriptor->Name);
        if (_stricmp(importedDll, dll) != 0)
            continue;

        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            reinterpret_cast<BYTE*>(module) + descriptor->FirstThunk);
        auto* originalThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            reinterpret_cast<BYTE*>(module) + descriptor->OriginalFirstThunk);

        for (; originalThunk->u1.AddressOfData; ++thunk, ++originalThunk) {
            if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal))
                continue;

            auto* import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                reinterpret_cast<BYTE*>(module) +
                originalThunk->u1.AddressOfData);
            if (_stricmp(reinterpret_cast<char*>(import->Name), function) != 0)
                continue;

            DWORD oldProtection = 0;
            if (!VirtualProtect(&thunk->u1.Function, sizeof(PROC),
                PAGE_READWRITE, &oldProtection)) {
                return false;
            }
            if (original)
                *original = reinterpret_cast<PROC>(thunk->u1.Function);
            thunk->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
            VirtualProtect(&thunk->u1.Function, sizeof(PROC),
                oldProtection, &oldProtection);
            return true;
        }
    }
    return false;
}

static HRESULT WINAPI Hook_SHOpenFolderAndSelectItems(
    PCIDLIST_ABSOLUTE pidl, UINT count,
    PCUITEMID_CHILD_ARRAY children, DWORD flags)
{
    wchar_t path[MAX_PATH] = {};
    if (SHGetPathFromIDListW(pidl, path)) {
        NotifyHostOpenFolder(path);
        return S_OK;
    }
    return g_origSHOpen
        ? g_origSHOpen(pidl, count, children, flags)
        : E_FAIL;
}

static HINSTANCE WINAPI Hook_ShellExecuteW(
    HWND window, LPCWSTR operation, LPCWSTR file, LPCWSTR parameters,
    LPCWSTR directory, INT showCommand)
{
    bool isOpen = !operation || !_wcsicmp(operation, L"open") ||
        !_wcsicmp(operation, L"explore");
    if (isOpen && file) {
        DWORD attributes = GetFileAttributesW(file);
        if (attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            NotifyHostOpenFolder(file);
            return reinterpret_cast<HINSTANCE>(static_cast<INT_PTR>(42));
        }
    }

    return g_origShellExecuteW
        ? g_origShellExecuteW(window, operation, file, parameters,
            directory, showCommand)
        : reinterpret_cast<HINSTANCE>(static_cast<INT_PTR>(2));
}

extern "C" SBAPI BOOL WINAPI SandboxBorder_Init(void)
{
    GetEnvironmentVariableW(SANDBOX_BORDER_BOX_ENV,
        g_BoxName, ARRAYSIZE(g_BoxName));
    if (g_BoxName[0] == L'\0')
        return FALSE;

    HMODULE executable = GetModuleHandleW(nullptr);
    HMODULE shell = GetModuleHandleW(L"shell32.dll");
    PatchIAT(executable, "shell32.dll", "SHOpenFolderAndSelectItems",
        reinterpret_cast<PROC>(Hook_SHOpenFolderAndSelectItems),
        reinterpret_cast<PROC*>(&g_origSHOpen));
    PatchIAT(executable, "shell32.dll", "ShellExecuteW",
        reinterpret_cast<PROC>(Hook_ShellExecuteW),
        reinterpret_cast<PROC*>(&g_origShellExecuteW));

    if (!g_origSHOpen && shell) {
        g_origSHOpen = reinterpret_cast<PFN_SHOpenFolderAndSelectItems>(
            GetProcAddress(shell, "SHOpenFolderAndSelectItems"));
    }
    if (!g_origShellExecuteW && shell) {
        g_origShellExecuteW = reinterpret_cast<PFN_ShellExecuteW>(
            GetProcAddress(shell, "ShellExecuteW"));
    }
    return TRUE;
}

extern "C" SBAPI BOOL WINAPI SandboxBorder_Uninit(void)
{
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(instance);
    return TRUE;
}
