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
#include <ole2.h>
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
#include <cstring>
#include <mutex>
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
using GetPriorityClipboardFormatFn = int (WINAPI*)(UINT*, int);
using CountClipboardFormatsFn = int (WINAPI*)();
using EnumClipboardFormatsFn = UINT (WINAPI*)(UINT);
using OleSetClipboardFn = HRESULT (WINAPI*)(IDataObject*);

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
GetPriorityClipboardFormatFn g_originalGetPriorityClipboardFormat = nullptr;
CountClipboardFormatsFn g_originalCountClipboardFormats = nullptr;
EnumClipboardFormatsFn g_originalEnumClipboardFormats = nullptr;
OleSetClipboardFn g_originalOleSetClipboard = nullptr;
bool g_installed = false;
std::wstring g_downloadsLower;
std::wstring g_boxName;
std::wstring g_hookDllPath;
bool g_clipboardVirtualization = false;
std::mutex g_fakeClipboardHandlesMutex;
std::vector<HGLOBAL> g_fakeClipboardHandles;

thread_local int g_hookDepth = 0;
thread_local bool g_showMessageSent = false;

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

std::wstring environmentString(const wchar_t* name)
{
    wchar_t buffer[hookipc::kMaxText]{};
    const DWORD count = GetEnvironmentVariableW(name, buffer, _countof(buffer));
    if (count == 0 || count >= _countof(buffer))
        return {};
    return buffer;
}

bool textClipboardFormat(UINT format)
{
    return format == CF_UNICODETEXT || format == CF_TEXT;
}

std::wstring textFromClipboardHandle(HANDLE data, UINT format)
{
    if (!data || !textClipboardFormat(format))
        return {};

    const SIZE_T size = GlobalSize(data);
    void* locked = GlobalLock(data);
    if (!locked)
        return {};

    std::wstring result;
    if (format == CF_UNICODETEXT) {
        const wchar_t* text = static_cast<const wchar_t*>(locked);
        const std::size_t maxChars = size / sizeof(wchar_t);
        std::size_t length = 0;
        while (length < maxChars && text[length] != L'\0')
            ++length;
        result.assign(text, text + length);
    } else {
        const char* text = static_cast<const char*>(locked);
        std::size_t maxChars = size;
        std::size_t length = 0;
        while (length < maxChars && text[length] != '\0')
            ++length;
        if (length > 0) {
            const int needed = MultiByteToWideChar(
                CP_ACP, 0, text, static_cast<int>(length), nullptr, 0);
            if (needed > 0) {
                result.resize(static_cast<std::size_t>(needed));
                MultiByteToWideChar(CP_ACP, 0, text, static_cast<int>(length),
                                    result.data(), needed);
            }
        }
    }

    GlobalUnlock(data);
    return result;
}

bool textFromDataObject(IDataObject* dataObject, std::wstring& text)
{
    text.clear();
    if (!dataObject)
        return false;

    const UINT formats[] = { CF_UNICODETEXT, CF_TEXT };
    for (UINT format : formats) {
        FORMATETC formatEtc{};
        formatEtc.cfFormat = static_cast<CLIPFORMAT>(format);
        formatEtc.dwAspect = DVASPECT_CONTENT;
        formatEtc.lindex = -1;
        formatEtc.tymed = TYMED_HGLOBAL;

        STGMEDIUM medium{};
        const HRESULT hr = dataObject->GetData(&formatEtc, &medium);
        if (FAILED(hr))
            continue;
        if (medium.tymed != TYMED_HGLOBAL || !medium.hGlobal) {
            ReleaseStgMedium(&medium);
            continue;
        }

        text = textFromClipboardHandle(medium.hGlobal, format);
        ReleaseStgMedium(&medium);
        return true;
    }

    return false;
}

HGLOBAL allocateClipboardText(const std::wstring& text, UINT format)
{
    HGLOBAL memory = nullptr;
    if (format == CF_UNICODETEXT) {
        const SIZE_T bytes = (text.size() + 1) * sizeof(wchar_t);
        memory = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes);
        if (!memory)
            return nullptr;
        void* locked = GlobalLock(memory);
        if (!locked) {
            GlobalFree(memory);
            return nullptr;
        }
        memcpy(locked, text.c_str(), bytes);
        GlobalUnlock(memory);
    } else if (format == CF_TEXT) {
        const int needed = WideCharToMultiByte(
            CP_ACP, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (needed <= 0)
            return nullptr;
        memory = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT,
                             static_cast<SIZE_T>(needed));
        if (!memory)
            return nullptr;
        void* locked = GlobalLock(memory);
        if (!locked) {
            GlobalFree(memory);
            return nullptr;
        }
        WideCharToMultiByte(CP_ACP, 0, text.c_str(), -1,
                            static_cast<char*>(locked), needed, nullptr,
                            nullptr);
        GlobalUnlock(memory);
    }

    if (memory) {
        std::lock_guard<std::mutex> lock(g_fakeClipboardHandlesMutex);
        g_fakeClipboardHandles.push_back(memory);
    }
    return memory;
}

bool getPrivateClipboardText(std::wstring& text, bool& hasText)
{
    hasText = false;
    text.clear();
    return g_clipboardVirtualization &&
           pipeclient::getClipboardText(g_boxName, text, hasText);
}

bool hasPrivateClipboardText(bool& hasText)
{
    hasText = false;
    return g_clipboardVirtualization &&
           pipeclient::hasClipboardText(g_boxName, hasText);
}

bool systemClipboardHasTextFormat(UINT format)
{
    if (!textClipboardFormat(format))
        return false;

    bool hasText = false;
    return pipeclient::hasSystemClipboardText(g_boxName, hasText) && hasText;
}

int systemTextClipboardFormatCount()
{
    int count = 0;
    if (systemClipboardHasTextFormat(CF_UNICODETEXT))
        ++count;
    if (systemClipboardHasTextFormat(CF_TEXT))
        ++count;
    return count;
}

UINT nextSystemTextClipboardFormat(UINT format)
{
    if (format == 0) {
        if (systemClipboardHasTextFormat(CF_UNICODETEXT))
            return CF_UNICODETEXT;
        if (systemClipboardHasTextFormat(CF_TEXT))
            return CF_TEXT;
        return 0;
    }

    if (format == CF_UNICODETEXT &&
        systemClipboardHasTextFormat(CF_TEXT)) {
        return CF_TEXT;
    }

    return 0;
}

HGLOBAL getSystemClipboardText(UINT format)
{
    if (!textClipboardFormat(format))
        return nullptr;

    std::wstring text;
    bool hasText = false;
    if (!pipeclient::getSystemClipboardText(g_boxName, text, hasText) ||
        !hasText) {
        return nullptr;
    }

    return allocateClipboardText(text, format);
}

void freeFakeClipboardHandles()
{
    std::lock_guard<std::mutex> lock(g_fakeClipboardHandlesMutex);
    for (HGLOBAL handle : g_fakeClipboardHandles)
        GlobalFree(handle);
    g_fakeClipboardHandles.clear();
}

bool injectHookDllIntoProcess(HANDLE process)
{
    if (!process || g_hookDllPath.empty())
        return false;

    const SIZE_T bytes = (g_hookDllPath.size() + 1) * sizeof(wchar_t);
    void* remotePath = VirtualAllocEx(process, nullptr, bytes,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_READWRITE);
    if (!remotePath)
        return false;

    bool ok = false;
    if (WriteProcessMemory(process, remotePath, g_hookDllPath.c_str(), bytes,
                           nullptr)) {
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        auto* loadLibraryW = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(kernel32, "LoadLibraryW"));
        HANDLE thread = loadLibraryW
            ? CreateRemoteThread(process, nullptr, 0, loadLibraryW, remotePath,
                                 0, nullptr)
            : nullptr;
        if (thread) {
            WaitForSingleObject(thread, 5000);
            DWORD exitCode = 0;
            ok = GetExitCodeThread(thread, &exitCode) && exitCode != 0;
            CloseHandle(thread);
        }
    }

    VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
    return ok;
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

bool shouldSkipChildHookInjection(LPCWSTR application, LPCWSTR commandLine)
{
    const std::wstring appLower = lower(application ? application : L"");
    const std::wstring cmdLower = lower(commandLine ? commandLine : L"");

    if (contains(appLower, L"\\ai.exe") ||
        appLower == L"ai.exe" ||
        contains(cmdLower, L"\\ai.exe") ||
        cmdLower.rfind(L"ai.exe", 0) == 0) {
        return true;
    }

    return false;
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

    const bool skipChildHook = shouldSkipChildHookInjection(application,
                                                           commandLine);
    const bool propagateHook = g_clipboardVirtualization &&
                               !g_hookDllPath.empty() &&
                               !skipChildHook;
    const bool callerSuspended = (creationFlags & CREATE_SUSPENDED) != 0;
    const DWORD adjustedFlags = propagateHook
        ? (creationFlags | CREATE_SUSPENDED)
        : creationFlags;

    const BOOL result = g_originalCreateProcessW(
        application, commandLine, processAttributes, threadAttributes,
        inheritHandles, adjustedFlags, environment, currentDirectory,
        startupInfo, processInfo);
    const DWORD error = GetLastError();

    if (result && propagateHook && processInfo && processInfo->hProcess) {
        const bool injected = injectHookDllIntoProcess(processInfo->hProcess);
        hooklog::write(L"[child] HookDll injection pid=%lu -> %d",
                       processInfo->dwProcessId, injected ? 1 : 0);
        if (!callerSuspended && processInfo->hThread)
            ResumeThread(processInfo->hThread);
    } else if (result && skipChildHook && processInfo) {
        hooklog::write(L"[child] HookDll injection skipped pid=%lu app=%s cmd=%s",
                       processInfo->dwProcessId,
                       safe(application),
                       safe(commandLine));
    }

    hooklog::write(L"[return] CreateProcessW -> %d gle=%lu (passed through)",
                   result, result ? ERROR_SUCCESS : error);
    SetLastError(error);
    return result;
}

BOOL WINAPI hookedOpenClipboard(HWND)
{
    if (!g_clipboardVirtualization)
        return g_originalOpenClipboard ? g_originalOpenClipboard(nullptr) : FALSE;

    hooklog::write(L"[clipboard] OpenClipboard virtual box=%s",
                   g_boxName.c_str());
    return TRUE;
}

BOOL WINAPI hookedCloseClipboard()
{
    if (!g_clipboardVirtualization)
        return g_originalCloseClipboard ? g_originalCloseClipboard() : FALSE;
    return TRUE;
}

BOOL WINAPI hookedEmptyClipboard()
{
    if (!g_clipboardVirtualization)
        return g_originalEmptyClipboard ? g_originalEmptyClipboard() : FALSE;

    const bool ok = pipeclient::clearClipboard(g_boxName);
    hooklog::write(L"[clipboard] EmptyClipboard private -> %d", ok ? 1 : 0);
    return ok ? TRUE : FALSE;
}

HANDLE WINAPI hookedSetClipboardData(UINT format, HANDLE data)
{
    if (!g_clipboardVirtualization)
        return g_originalSetClipboardData
            ? g_originalSetClipboardData(format, data)
            : nullptr;

    if (!textClipboardFormat(format)) {
        hooklog::write(L"[clipboard] SetClipboardData format=%u suppressed",
                       format);
        return data;
    }

    if (!data) {
        hooklog::write(L"[clipboard] SetClipboardData format=%u delayed rendering suppressed",
                       format);
        return data;
    }

    const std::wstring text = textFromClipboardHandle(data, format);
    const bool ok = pipeclient::setClipboardText(g_boxName, text);
    hooklog::write(L"[clipboard] SetClipboardData format=%u chars=%zu -> %d",
                   format, text.size(), ok ? 1 : 0);
    return ok ? data : nullptr;
}

HANDLE WINAPI hookedGetClipboardData(UINT format)
{
    if (!g_clipboardVirtualization)
        return g_originalGetClipboardData
            ? g_originalGetClipboardData(format)
            : nullptr;

    if (!textClipboardFormat(format))
        return nullptr;

    std::wstring text;
    bool hasText = false;
    if (getPrivateClipboardText(text, hasText) && hasText) {
        hooklog::write(L"[clipboard] GetClipboardData format=%u private chars=%zu",
                       format, text.size());
        return allocateClipboardText(text, format);
    }

    hooklog::write(L"[clipboard] GetClipboardData format=%u fallback system",
                   format);
    return getSystemClipboardText(format);
}

BOOL WINAPI hookedIsClipboardFormatAvailable(UINT format)
{
    if (!g_clipboardVirtualization)
        return g_originalIsClipboardFormatAvailable
            ? g_originalIsClipboardFormatAvailable(format)
            : FALSE;

    if (!textClipboardFormat(format))
        return FALSE;

    bool hasText = false;
    if (hasPrivateClipboardText(hasText) && hasText)
        return TRUE;
    return systemClipboardHasTextFormat(format) ? TRUE : FALSE;
}

int WINAPI hookedGetPriorityClipboardFormat(UINT* priorityList, int count)
{
    if (!g_clipboardVirtualization)
        return g_originalGetPriorityClipboardFormat
            ? g_originalGetPriorityClipboardFormat(priorityList, count)
            : 0;

    bool hasText = false;
    if (hasPrivateClipboardText(hasText) && hasText) {
        for (int i = 0; i < count; ++i) {
            if (textClipboardFormat(priorityList[i]))
                return static_cast<int>(priorityList[i]);
        }
        return -1;
    }

    for (int i = 0; i < count; ++i) {
        if (systemClipboardHasTextFormat(priorityList[i]))
            return static_cast<int>(priorityList[i]);
    }
    return -1;
}

int WINAPI hookedCountClipboardFormats()
{
    if (!g_clipboardVirtualization)
        return g_originalCountClipboardFormats
            ? g_originalCountClipboardFormats()
            : 0;

    bool hasText = false;
    if (hasPrivateClipboardText(hasText) && hasText)
        return 2;
    return systemTextClipboardFormatCount();
}

UINT WINAPI hookedEnumClipboardFormats(UINT format)
{
    if (!g_clipboardVirtualization)
        return g_originalEnumClipboardFormats
            ? g_originalEnumClipboardFormats(format)
            : 0;

    bool hasText = false;
    if (hasPrivateClipboardText(hasText) && hasText) {
        if (format == 0)
            return CF_UNICODETEXT;
        if (format == CF_UNICODETEXT)
            return CF_TEXT;
        return 0;
    }

    return nextSystemTextClipboardFormat(format);
}

HRESULT WINAPI hookedOleSetClipboard(IDataObject* dataObject)
{
    if (!g_clipboardVirtualization)
        return g_originalOleSetClipboard
            ? g_originalOleSetClipboard(dataObject)
            : E_FAIL;

    if (!dataObject) {
        const bool ok = pipeclient::clearClipboard(g_boxName);
        hooklog::write(L"[clipboard] OleSetClipboard(NULL) clear -> %d",
                       ok ? 1 : 0);
        return ok ? S_OK : E_FAIL;
    }

    std::wstring text;
    const bool hasText = textFromDataObject(dataObject, text);
    if (!hasText) {
        hooklog::write(L"[clipboard] OleSetClipboard suppressed: no text format");
        return S_OK;
    }

    const bool ok = pipeclient::setClipboardText(g_boxName, text);
    hooklog::write(L"[clipboard] OleSetClipboard text chars=%zu -> %d",
                   text.size(), ok ? 1 : 0);
    return ok ? S_OK : E_FAIL;
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
    g_boxName = environmentString(L"SANDBOX_BOX");
    g_hookDllPath = environmentString(L"SANDBOX_HOOK_DLL");
    if (g_hookDllPath.empty()) {
        wchar_t modulePath[MAX_PATH]{};
        HMODULE module = nullptr;
        if (GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(&install), &module) &&
            GetModuleFileNameW(module, modulePath, _countof(modulePath)) > 0) {
            g_hookDllPath = modulePath;
        }
    }
    g_clipboardVirtualization = !g_boxName.empty();
    hooklog::write(L"[setup] box=%s clipboardVirtualization=%d",
                   g_boxName.empty() ? L"<none>" : g_boxName.c_str(),
                   g_clipboardVirtualization ? 1 : 0);
    hooklog::write(L"[setup] hookDllPath=%s",
                   g_hookDllPath.empty() ? L"<unset>" : g_hookDllPath.c_str());

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
    resolve(L"user32.dll", "GetPriorityClipboardFormat",
            g_originalGetPriorityClipboardFormat,
            L"GetPriorityClipboardFormat");
    resolve(L"user32.dll", "CountClipboardFormats",
            g_originalCountClipboardFormats,
            L"CountClipboardFormats");
    resolve(L"user32.dll", "EnumClipboardFormats",
            g_originalEnumClipboardFormats,
            L"EnumClipboardFormats");
    resolve(L"ole32.dll", "OleSetClipboard", g_originalOleSetClipboard,
            L"OleSetClipboard");

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
    attach(g_originalIsClipboardFormatAvailable, hookedIsClipboardFormatAvailable,
           L"IsClipboardFormatAvailable");
    attach(g_originalGetPriorityClipboardFormat, hookedGetPriorityClipboardFormat,
           L"GetPriorityClipboardFormat");
    attach(g_originalCountClipboardFormats, hookedCountClipboardFormats,
           L"CountClipboardFormats");
    attach(g_originalEnumClipboardFormats, hookedEnumClipboardFormats,
           L"EnumClipboardFormats");
    attach(g_originalOleSetClipboard, hookedOleSetClipboard,
           L"OleSetClipboard");

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
    detach(g_originalIsClipboardFormatAvailable, hookedIsClipboardFormatAvailable,
           L"IsClipboardFormatAvailable");
    detach(g_originalGetPriorityClipboardFormat, hookedGetPriorityClipboardFormat,
           L"GetPriorityClipboardFormat");
    detach(g_originalCountClipboardFormats, hookedCountClipboardFormats,
           L"CountClipboardFormats");
    detach(g_originalEnumClipboardFormats, hookedEnumClipboardFormats,
           L"EnumClipboardFormats");
    detach(g_originalOleSetClipboard, hookedOleSetClipboard,
           L"OleSetClipboard");
    const LONG result = DetourTransactionCommit();
    g_installed = false;
    freeFakeClipboardHandles();
    hooklog::write(L"[lifecycle] hooks::remove end commit=%ld", result);
}

} // namespace hooks
