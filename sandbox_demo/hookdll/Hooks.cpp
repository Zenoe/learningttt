#include "Hooks.h"

#include "HookIpcProtocol.h"
#include "HookLogger.h"
#include "PipeClient.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#if __has_include(<detours/detours.h>)
#include <detours/detours.h>
#elif __has_include(<detours.h>)
#include <detours.h>
#else
#error Microsoft Detours headers are required to build HookDll
#endif

#include <cwctype>
#include <string>
#include <vector>

namespace {

using SHOpenFn = HRESULT (WINAPI*)(PCIDLIST_ABSOLUTE, UINT,
                                   PCUITEMID_CHILD_ARRAY, DWORD);
using ShellExecuteWFn = HINSTANCE (WINAPI*)(HWND, LPCWSTR, LPCWSTR,
                                             LPCWSTR, LPCWSTR, INT);
using ShellExecuteExWFn = BOOL (WINAPI*)(SHELLEXECUTEINFOW*);
using CreateProcessWFn = BOOL (WINAPI*)(LPCWSTR, LPWSTR,
                                         LPSECURITY_ATTRIBUTES,
                                         LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                                         LPVOID, LPCWSTR, LPSTARTUPINFOW,
                                         LPPROCESS_INFORMATION);
using OpenClipboardFn = BOOL (WINAPI*)(HWND);
using CloseClipboardFn = BOOL (WINAPI*)();
using EmptyClipboardFn = BOOL (WINAPI*)();
using SetClipboardDataFn = HANDLE (WINAPI*)(UINT, HANDLE);
using GetClipboardDataFn = HANDLE (WINAPI*)(UINT);
using IsClipboardFormatAvailableFn = BOOL (WINAPI*)(UINT);
using CountClipboardFormatsFn = int (WINAPI*)();
using EnumClipboardFormatsFn = UINT (WINAPI*)(UINT);
using GetPriorityClipboardFormatFn = int (WINAPI*)(UINT*, int);

SHOpenFn g_originalSHOpen = nullptr;
ShellExecuteWFn g_originalShellExecuteW = nullptr;
ShellExecuteExWFn g_originalShellExecuteExW = nullptr;
CreateProcessWFn g_originalCreateProcessW = nullptr;
OpenClipboardFn g_originalOpenClipboard = nullptr;
CloseClipboardFn g_originalCloseClipboard = nullptr;
EmptyClipboardFn g_originalEmptyClipboard = nullptr;
SetClipboardDataFn g_originalSetClipboardData = nullptr;
GetClipboardDataFn g_originalGetClipboardData = nullptr;
IsClipboardFormatAvailableFn g_originalIsClipboardFormatAvailable = nullptr;
CountClipboardFormatsFn g_originalCountClipboardFormats = nullptr;
EnumClipboardFormatsFn g_originalEnumClipboardFormats = nullptr;
GetPriorityClipboardFormatFn g_originalGetPriorityClipboardFormat = nullptr;
bool g_installed = false;
std::wstring g_downloadsLower;
std::vector<HGLOBAL> g_localClipboardHandles;

thread_local int g_hookDepth = 0;
thread_local bool g_showMessageSent = false;
thread_local bool g_clipboardOpen = false;

struct HookScope {
    HookScope()
    {
        if (g_hookDepth == 0)
            g_showMessageSent = false;
        ++g_hookDepth;
    }
    ~HookScope() { --g_hookDepth; }
};

const wchar_t* safe(LPCWSTR value)
{
    return value ? value : L"<null>";
}

std::wstring lower(std::wstring value)
{
    for (wchar_t& ch : value)
        ch = static_cast<wchar_t>(towlower(ch));
    return value;
}

std::wstring normalizedDirectory(std::wstring path)
{
    while (!path.empty() && (path.back() == L'\\' || path.back() == L'/'))
        path.pop_back();
    return lower(std::move(path));
}

bool contains(const std::wstring& text, const wchar_t* value)
{
    return text.find(value) != std::wstring::npos;
}

bool explorerRevealCommand(LPCWSTR application, LPCWSTR commandLine,
                           std::wstring& selectedPath)
{
    const std::wstring app = application ? application : L"";
    const std::wstring cmd = commandLine ? commandLine : L"";
    const std::wstring appLower = lower(app);
    const std::wstring cmdLower = lower(cmd);

    const bool explorer = contains(appLower, L"explorer.exe") ||
                          contains(cmdLower, L"explorer.exe") ||
                          contains(appLower, L"\\explorer") ||
                          (app.empty() && cmdLower.rfind(L"explorer", 0) == 0);
    if (!explorer)
        return false;

    std::size_t position = cmdLower.find(L"/select,");
    std::size_t prefixLength = 8;
    if (position == std::wstring::npos) {
        position = cmdLower.find(L"/n,");
        prefixLength = 3;
    }
    if (position == std::wstring::npos)
        return false;

    std::wstring rest = cmd.substr(position + prefixLength);
    const std::size_t first = rest.find_first_not_of(L" \t");
    if (first == std::wstring::npos)
        return false;
    rest.erase(0, first);

    if (!rest.empty() && rest.front() == L'\"') {
        rest.erase(0, 1);
        const std::size_t quote = rest.find(L'\"');
        if (quote != std::wstring::npos)
            rest.resize(quote);
    } else {
        const std::size_t last = rest.find_last_not_of(L" \t");
        if (last != std::wstring::npos)
            rest.resize(last + 1);
    }

    selectedPath = rest;
    return !selectedPath.empty();
}

bool downloadsFolderOpen(LPCWSTR verb, LPCWSTR file, std::wstring& path)
{
    if (g_downloadsLower.empty() || !file)
        return false;

    const std::wstring verbLower = verb ? lower(verb) : L"";
    if (!verbLower.empty() && verbLower != L"open" && verbLower != L"explore")
        return false;
    if (normalizedDirectory(file) != g_downloadsLower)
        return false;

    path = file;
    return true;
}

std::wstring pidlPath(PCIDLIST_ABSOLUTE folder, UINT itemCount,
                      PCUITEMID_CHILD_ARRAY items)
{
    wchar_t path[32768]{};
    if (itemCount > 0 && items && items[0]) {
        PIDLIST_ABSOLUTE full = ILCombine(folder, items[0]);
        if (full) {
            const bool ok = SHGetPathFromIDListEx(full, path, _countof(path), 0) != FALSE;
            ILFree(full);
            if (ok)
                return path;
        }
    }

    if (folder && SHGetPathFromIDListEx(folder, path, _countof(path), 0))
        return path;
    return {};
}

bool signalShowInFolder(const std::wstring& path)
{
    if (g_showMessageSent)
        return true;

    const std::wstring target = path.empty() ? g_downloadsLower : path;
    // Chrome is normally the foreground process at this point.  Permit the
    // IPC receiver to activate the custom explorer in response to this user
    // action; otherwise Windows may leave it behind the SandboxDemo window.
    AllowSetForegroundWindow(ASFW_ANY);
    const bool sent = !target.empty() && pipeclient::sendShowInFolder(target);
    g_showMessageSent = sent;
    hooklog::write(L"[ipc] ShowInFolder sent=%d path=%s", sent ? 1 : 0,
                   target.empty() ? L"<unknown>" : target.c_str());
    return sent;
}

bool textClipboardFormat(UINT format)
{
    return format == CF_UNICODETEXT || format == CF_TEXT;
}

std::wstring wideFromClipboardHandle(UINT format, HANDLE data)
{
    if (!data)
        return {};

    void* locked = GlobalLock(data);
    if (!locked)
        return {};

    std::wstring result;
    if (format == CF_UNICODETEXT) {
        const wchar_t* text = static_cast<const wchar_t*>(locked);
        if (text)
            result = text;
    } else if (format == CF_TEXT) {
        const char* text = static_cast<const char*>(locked);
        if (text) {
            const int needed = MultiByteToWideChar(CP_ACP, 0, text, -1,
                                                   nullptr, 0);
            if (needed > 0) {
                result.resize(static_cast<std::size_t>(needed - 1));
                MultiByteToWideChar(CP_ACP, 0, text, -1,
                                    result.data(), needed);
            }
        }
    }

    GlobalUnlock(data);
    return result;
}

HANDLE clipboardHandleFromWide(UINT format, const std::wstring& text)
{
    if (format == CF_UNICODETEXT) {
        const SIZE_T bytes = (text.size() + 1) * sizeof(wchar_t);
        HGLOBAL handle = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if (!handle)
            return nullptr;
        void* locked = GlobalLock(handle);
        if (!locked) {
            GlobalFree(handle);
            return nullptr;
        }
        memcpy(locked, text.c_str(), bytes);
        GlobalUnlock(handle);
        g_localClipboardHandles.push_back(handle);
        return handle;
    }

    if (format == CF_TEXT) {
        const int needed = WideCharToMultiByte(CP_ACP, 0, text.c_str(), -1,
                                               nullptr, 0, nullptr, nullptr);
        if (needed <= 0)
            return nullptr;
        HGLOBAL handle = GlobalAlloc(GMEM_MOVEABLE, needed);
        if (!handle)
            return nullptr;
        void* locked = GlobalLock(handle);
        if (!locked) {
            GlobalFree(handle);
            return nullptr;
        }
        WideCharToMultiByte(CP_ACP, 0, text.c_str(), -1,
                            static_cast<char*>(locked), needed,
                            nullptr, nullptr);
        GlobalUnlock(handle);
        g_localClipboardHandles.push_back(handle);
        return handle;
    }

    return nullptr;
}

BOOL WINAPI hookedOpenClipboard(HWND)
{
    HookScope scope;
    g_clipboardOpen = true;
    hooklog::write(L"[clipboard] OpenClipboard -> TRUE (box-local)");
    return TRUE;
}

BOOL WINAPI hookedCloseClipboard()
{
    HookScope scope;
    g_clipboardOpen = false;
    hooklog::write(L"[clipboard] CloseClipboard -> TRUE (box-local)");
    return TRUE;
}

BOOL WINAPI hookedEmptyClipboard()
{
    HookScope scope;
    const bool ok = pipeclient::setClipboardText(L"");
    hooklog::write(L"[clipboard] EmptyClipboard -> %d (box-local)",
                   ok ? 1 : 0);
    return ok ? TRUE : FALSE;
}

HANDLE WINAPI hookedSetClipboardData(UINT format, HANDLE data)
{
    HookScope scope;
    if (!textClipboardFormat(format)) {
        hooklog::write(L"[clipboard] SetClipboardData(format=%u) blocked", format);
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;
    }

    const std::wstring text = wideFromClipboardHandle(format, data);
    const bool ok = pipeclient::setClipboardText(text);
    hooklog::write(L"[clipboard] SetClipboardData(format=%u, chars=%llu) -> %d",
                   format,
                   static_cast<unsigned long long>(text.size()),
                   ok ? 1 : 0);
    if (!ok) {
        SetLastError(ERROR_PIPE_NOT_CONNECTED);
        return nullptr;
    }
    return data;
}

HANDLE WINAPI hookedGetClipboardData(UINT format)
{
    HookScope scope;
    if (!textClipboardFormat(format)) {
        hooklog::write(L"[clipboard] GetClipboardData(format=%u) blocked", format);
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;
    }

    std::wstring text;
    if (!pipeclient::getClipboardText(text)) {
        SetLastError(ERROR_PIPE_NOT_CONNECTED);
        return nullptr;
    }

    HANDLE handle = clipboardHandleFromWide(format, text);
    hooklog::write(L"[clipboard] GetClipboardData(format=%u, chars=%llu) -> 0x%p",
                   format,
                   static_cast<unsigned long long>(text.size()),
                   handle);
    if (!handle)
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return handle;
}

BOOL WINAPI hookedIsClipboardFormatAvailable(UINT format)
{
    HookScope scope;
    const BOOL available =
        textClipboardFormat(format) && pipeclient::hasClipboardText()
            ? TRUE
            : FALSE;
    hooklog::write(L"[clipboard] IsClipboardFormatAvailable(%u) -> %d",
                   format, available);
    return available;
}

int WINAPI hookedCountClipboardFormats()
{
    HookScope scope;
    const int count = pipeclient::hasClipboardText() ? 2 : 0;
    hooklog::write(L"[clipboard] CountClipboardFormats -> %d", count);
    return count;
}

UINT WINAPI hookedEnumClipboardFormats(UINT format)
{
    HookScope scope;
    if (!pipeclient::hasClipboardText())
        return 0;
    if (format == 0)
        return CF_UNICODETEXT;
    if (format == CF_UNICODETEXT)
        return CF_TEXT;
    return 0;
}

int WINAPI hookedGetPriorityClipboardFormat(UINT* formats, int count)
{
    HookScope scope;
    if (!formats || count <= 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }
    if (!pipeclient::hasClipboardText())
        return 0;
    for (int i = 0; i < count; ++i) {
        if (textClipboardFormat(formats[i]))
            return static_cast<int>(formats[i]);
    }
    return 0;
}

HRESULT WINAPI hookedSHOpenFolderAndSelectItems(
    PCIDLIST_ABSOLUTE folder, UINT itemCount,
    PCUITEMID_CHILD_ARRAY items, DWORD flags)
{
    HookScope scope;
    const std::wstring path = pidlPath(folder, itemCount, items);
    hooklog::write(L"[call] SHOpenFolderAndSelectItems(cidl=%u, flags=0x%08lX) path=%s",
                   itemCount, flags, path.empty() ? L"<unknown>" : path.c_str());
    signalShowInFolder(path);
    hooklog::write(L"[return] SHOpenFolderAndSelectItems -> S_OK (real Explorer suppressed)");
    return S_OK;
}

HINSTANCE WINAPI hookedShellExecuteW(HWND window, LPCWSTR verb, LPCWSTR file,
                                     LPCWSTR parameters, LPCWSTR directory,
                                     INT showCommand)
{
    HookScope scope;
    hooklog::write(L"[call] ShellExecuteW(verb=%s, file=%s, params=%s)",
                   safe(verb), safe(file), safe(parameters));

    std::wstring target;
    if (explorerRevealCommand(file, parameters, target) ||
        downloadsFolderOpen(verb, file, target)) {
        signalShowInFolder(target);
        hooklog::write(L"[return] ShellExecuteW -> success (real Explorer suppressed)");
        return reinterpret_cast<HINSTANCE>(42);
    }

    const HINSTANCE result = g_originalShellExecuteW(
        window, verb, file, parameters, directory, showCommand);
    hooklog::write(L"[return] ShellExecuteW -> 0x%p (passed through)", result);
    return result;
}

BOOL WINAPI hookedShellExecuteExW(SHELLEXECUTEINFOW* executeInfo)
{
    HookScope scope;
    hooklog::write(L"[call] ShellExecuteExW(file=%s, verb=%s, params=%s)",
                   executeInfo ? safe(executeInfo->lpFile) : L"<null struct>",
                   executeInfo ? safe(executeInfo->lpVerb) : L"<null struct>",
                   executeInfo ? safe(executeInfo->lpParameters) : L"<null struct>");

    if (executeInfo) {
        std::wstring target;
        if (explorerRevealCommand(executeInfo->lpFile,
                                  executeInfo->lpParameters, target) ||
            downloadsFolderOpen(executeInfo->lpVerb,
                                executeInfo->lpFile, target)) {
            signalShowInFolder(target);
            executeInfo->hInstApp = reinterpret_cast<HINSTANCE>(42);
            hooklog::write(L"[return] ShellExecuteExW -> TRUE (real Explorer suppressed)");
            return TRUE;
        }
    }

    const BOOL result = g_originalShellExecuteExW(executeInfo);
    hooklog::write(L"[return] ShellExecuteExW -> %d (passed through)", result);
    return result;
}

BOOL WINAPI hookedCreateProcessW(
    LPCWSTR application, LPWSTR commandLine,
    LPSECURITY_ATTRIBUTES processAttributes,
    LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles,
    DWORD creationFlags, LPVOID environment, LPCWSTR currentDirectory,
    LPSTARTUPINFOW startupInfo, LPPROCESS_INFORMATION processInfo)
{
    HookScope scope;
    hooklog::write(L"[call] CreateProcessW(app=%s, cmd=%s, flags=0x%08lX)",
                   safe(application), safe(commandLine), creationFlags);

    std::wstring target;
    if (explorerRevealCommand(application, commandLine, target)) {
        signalShowInFolder(target);

        wchar_t systemDirectory[MAX_PATH]{};
        GetSystemDirectoryW(systemDirectory, _countof(systemDirectory));
        std::wstring commandPath = std::wstring(systemDirectory) + L"\\cmd.exe";
        wchar_t noOpCommand[] = L"cmd.exe /d /c exit";
        const BOOL result = g_originalCreateProcessW(
            commandPath.c_str(), noOpCommand, processAttributes, threadAttributes,
            FALSE, creationFlags | CREATE_NO_WINDOW, environment,
            currentDirectory, startupInfo, processInfo);
        const DWORD error = GetLastError();
        hooklog::write(L"[return] CreateProcessW explorer request -> %d; no-op process used",
                       result);
        SetLastError(error);
        return result;
    }

    const BOOL result = g_originalCreateProcessW(
        application, commandLine, processAttributes, threadAttributes,
        inheritHandles, creationFlags, environment, currentDirectory,
        startupInfo, processInfo);
    const DWORD error = GetLastError();
    hooklog::write(L"[return] CreateProcessW -> %d gle=%lu (passed through)",
                   result, result ? ERROR_SUCCESS : error);
    SetLastError(error);
    return result;
}

template <typename Function>
bool resolve(const wchar_t* moduleName, const char* functionName,
             Function& original, const wchar_t* label)
{
    HMODULE module = GetModuleHandleW(moduleName);
    if (!module)
        module = LoadLibraryW(moduleName);
    original = module
        ? reinterpret_cast<Function>(GetProcAddress(module, functionName))
        : nullptr;
    hooklog::write(L"[setup] resolve %s -> 0x%p", label,
                   reinterpret_cast<void*>(original));
    return original != nullptr;
}

template <typename Function>
bool attach(Function& original, Function detour, const wchar_t* label)
{
    if (!original)
        return false;
    const LONG result = DetourAttach(reinterpret_cast<PVOID*>(&original),
                                     reinterpret_cast<PVOID>(detour));
    hooklog::write(L"[setup] DetourAttach(%s) -> %ld", label, result);
    return result == NO_ERROR;
}

template <typename Function>
void detach(Function& original, Function detour, const wchar_t* label)
{
    if (!original)
        return;
    const LONG result = DetourDetach(reinterpret_cast<PVOID*>(&original),
                                     reinterpret_cast<PVOID>(detour));
    hooklog::write(L"[setup] DetourDetach(%s) -> %ld", label, result);
}

} // namespace

namespace hooks {

bool install()
{
    hooklog::write(L"[lifecycle] hooks::install begin");
    wchar_t downloads[hookipc::kMaxText]{};
    if (GetEnvironmentVariableW(L"SANDBOX_DOWNLOADS", downloads,
                                _countof(downloads)) > 0) {
        g_downloadsLower = normalizedDirectory(downloads);
    }
    hooklog::write(L"[setup] downloads=%s",
                   g_downloadsLower.empty() ? L"<unset>" : g_downloadsLower.c_str());

    if (!resolve(L"shell32.dll", "SHOpenFolderAndSelectItems",
                 g_originalSHOpen, L"SHOpenFolderAndSelectItems")) {
        hooklog::write(L"[lifecycle] hooks::install failed: primary export missing");
        return false;
    }
    resolve(L"shell32.dll", "ShellExecuteW", g_originalShellExecuteW,
            L"ShellExecuteW");
    resolve(L"shell32.dll", "ShellExecuteExW", g_originalShellExecuteExW,
            L"ShellExecuteExW");
    resolve(L"kernel32.dll", "CreateProcessW", g_originalCreateProcessW,
            L"CreateProcessW");
    resolve(L"user32.dll", "OpenClipboard", g_originalOpenClipboard,
            L"OpenClipboard");
    resolve(L"user32.dll", "CloseClipboard", g_originalCloseClipboard,
            L"CloseClipboard");
    resolve(L"user32.dll", "EmptyClipboard", g_originalEmptyClipboard,
            L"EmptyClipboard");
    resolve(L"user32.dll", "SetClipboardData", g_originalSetClipboardData,
            L"SetClipboardData");
    resolve(L"user32.dll", "GetClipboardData", g_originalGetClipboardData,
            L"GetClipboardData");
    resolve(L"user32.dll", "IsClipboardFormatAvailable",
            g_originalIsClipboardFormatAvailable,
            L"IsClipboardFormatAvailable");
    resolve(L"user32.dll", "CountClipboardFormats",
            g_originalCountClipboardFormats,
            L"CountClipboardFormats");
    resolve(L"user32.dll", "EnumClipboardFormats",
            g_originalEnumClipboardFormats,
            L"EnumClipboardFormats");
    resolve(L"user32.dll", "GetPriorityClipboardFormat",
            g_originalGetPriorityClipboardFormat,
            L"GetPriorityClipboardFormat");

    LONG result = DetourTransactionBegin();
    hooklog::write(L"[setup] DetourTransactionBegin -> %ld", result);
    if (result != NO_ERROR)
        return false;
    DetourUpdateThread(GetCurrentThread());

    const bool primary = attach(g_originalSHOpen,
                                hookedSHOpenFolderAndSelectItems,
                                L"SHOpenFolderAndSelectItems");
    attach(g_originalShellExecuteW, hookedShellExecuteW, L"ShellExecuteW");
    attach(g_originalShellExecuteExW, hookedShellExecuteExW, L"ShellExecuteExW");
    attach(g_originalCreateProcessW, hookedCreateProcessW, L"CreateProcessW");
    attach(g_originalOpenClipboard, hookedOpenClipboard, L"OpenClipboard");
    attach(g_originalCloseClipboard, hookedCloseClipboard, L"CloseClipboard");
    attach(g_originalEmptyClipboard, hookedEmptyClipboard, L"EmptyClipboard");
    attach(g_originalSetClipboardData, hookedSetClipboardData, L"SetClipboardData");
    attach(g_originalGetClipboardData, hookedGetClipboardData, L"GetClipboardData");
    attach(g_originalIsClipboardFormatAvailable,
           hookedIsClipboardFormatAvailable,
           L"IsClipboardFormatAvailable");
    attach(g_originalCountClipboardFormats,
           hookedCountClipboardFormats,
           L"CountClipboardFormats");
    attach(g_originalEnumClipboardFormats,
           hookedEnumClipboardFormats,
           L"EnumClipboardFormats");
    attach(g_originalGetPriorityClipboardFormat,
           hookedGetPriorityClipboardFormat,
           L"GetPriorityClipboardFormat");

    result = DetourTransactionCommit();
    hooklog::write(L"[setup] DetourTransactionCommit -> %ld", result);
    g_installed = primary && result == NO_ERROR;
    hooklog::write(L"[lifecycle] hooks::install end installed=%d",
                   g_installed ? 1 : 0);
    return g_installed;
}

void remove()
{
    hooklog::write(L"[lifecycle] hooks::remove begin installed=%d",
                   g_installed ? 1 : 0);
    if (!g_installed)
        return;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    detach(g_originalSHOpen, hookedSHOpenFolderAndSelectItems,
           L"SHOpenFolderAndSelectItems");
    detach(g_originalShellExecuteW, hookedShellExecuteW, L"ShellExecuteW");
    detach(g_originalShellExecuteExW, hookedShellExecuteExW, L"ShellExecuteExW");
    detach(g_originalCreateProcessW, hookedCreateProcessW, L"CreateProcessW");
    detach(g_originalOpenClipboard, hookedOpenClipboard, L"OpenClipboard");
    detach(g_originalCloseClipboard, hookedCloseClipboard, L"CloseClipboard");
    detach(g_originalEmptyClipboard, hookedEmptyClipboard, L"EmptyClipboard");
    detach(g_originalSetClipboardData, hookedSetClipboardData, L"SetClipboardData");
    detach(g_originalGetClipboardData, hookedGetClipboardData, L"GetClipboardData");
    detach(g_originalIsClipboardFormatAvailable,
           hookedIsClipboardFormatAvailable,
           L"IsClipboardFormatAvailable");
    detach(g_originalCountClipboardFormats,
           hookedCountClipboardFormats,
           L"CountClipboardFormats");
    detach(g_originalEnumClipboardFormats,
           hookedEnumClipboardFormats,
           L"EnumClipboardFormats");
    detach(g_originalGetPriorityClipboardFormat,
           hookedGetPriorityClipboardFormat,
           L"GetPriorityClipboardFormat");
    const LONG result = DetourTransactionCommit();
    g_installed = false;
    hooklog::write(L"[lifecycle] hooks::remove end commit=%ld", result);

    for (HGLOBAL handle : g_localClipboardHandles)
        GlobalFree(handle);
    g_localClipboardHandles.clear();
}

} // namespace hooks
