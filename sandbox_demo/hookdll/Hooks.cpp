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
#include <algorithm>
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
using CreateFileWFn = HANDLE (WINAPI*)(LPCWSTR, DWORD, DWORD,
                                        LPSECURITY_ATTRIBUTES, DWORD, DWORD,
                                        HANDLE);
using CreateMutexWFn = HANDLE (WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);
using CreateMutexExWFn = HANDLE (WINAPI*)(LPSECURITY_ATTRIBUTES, LPCWSTR,
                                           DWORD, DWORD);
using OpenMutexWFn = HANDLE (WINAPI*)(DWORD, BOOL, LPCWSTR);
using CreateEventWFn = HANDLE (WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, BOOL,
                                         LPCWSTR);
using CreateEventExWFn = HANDLE (WINAPI*)(LPSECURITY_ATTRIBUTES, LPCWSTR,
                                           DWORD, DWORD);
using OpenEventWFn = HANDLE (WINAPI*)(DWORD, BOOL, LPCWSTR);
using CreateSemaphoreWFn = HANDLE (WINAPI*)(LPSECURITY_ATTRIBUTES, LONG, LONG,
                                             LPCWSTR);
using CreateSemaphoreExWFn = HANDLE (WINAPI*)(LPSECURITY_ATTRIBUTES, LONG, LONG,
                                               LPCWSTR, DWORD, DWORD);
using OpenSemaphoreWFn = HANDLE (WINAPI*)(DWORD, BOOL, LPCWSTR);
using CreateFileMappingWFn = HANDLE (WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES,
                                               DWORD, DWORD, DWORD, LPCWSTR);
using OpenFileMappingWFn = HANDLE (WINAPI*)(DWORD, BOOL, LPCWSTR);
using GetTempPathWFn = DWORD (WINAPI*)(DWORD, LPWSTR);
using GetTempPath2WFn = DWORD (WINAPI*)(DWORD, LPWSTR);
using RegCreateKeyExWFn = LSTATUS (WINAPI*)(HKEY, LPCWSTR, DWORD, LPWSTR,
                                             DWORD, REGSAM,
                                             LPSECURITY_ATTRIBUTES, PHKEY,
                                             LPDWORD);
using RegOpenKeyExWFn = LSTATUS (WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
using RegisterClassWFn = ATOM (WINAPI*)(const WNDCLASSW*);
using RegisterClassExWFn = ATOM (WINAPI*)(const WNDCLASSEXW*);
using UnregisterClassWFn = BOOL (WINAPI*)(LPCWSTR, HINSTANCE);
using CreateWindowExWFn = HWND (WINAPI*)(DWORD, LPCWSTR, LPCWSTR, DWORD, int,
                                          int, int, int, HWND, HMENU,
                                          HINSTANCE, LPVOID);
using FindWindowWFn = HWND (WINAPI*)(LPCWSTR, LPCWSTR);
using FindWindowExWFn = HWND (WINAPI*)(HWND, HWND, LPCWSTR, LPCWSTR);
using GetClassInfoWFn = BOOL (WINAPI*)(HINSTANCE, LPCWSTR, LPWNDCLASSW);
using GetClassInfoExWFn = BOOL (WINAPI*)(HINSTANCE, LPCWSTR, LPWNDCLASSEXW);
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
CreateFileWFn g_originalCreateFileW = nullptr;
CreateMutexWFn g_originalCreateMutexW = nullptr;
CreateMutexExWFn g_originalCreateMutexExW = nullptr;
OpenMutexWFn g_originalOpenMutexW = nullptr;
CreateEventWFn g_originalCreateEventW = nullptr;
CreateEventExWFn g_originalCreateEventExW = nullptr;
OpenEventWFn g_originalOpenEventW = nullptr;
CreateSemaphoreWFn g_originalCreateSemaphoreW = nullptr;
CreateSemaphoreExWFn g_originalCreateSemaphoreExW = nullptr;
OpenSemaphoreWFn g_originalOpenSemaphoreW = nullptr;
CreateFileMappingWFn g_originalCreateFileMappingW = nullptr;
OpenFileMappingWFn g_originalOpenFileMappingW = nullptr;
GetTempPathWFn g_originalGetTempPathW = nullptr;
GetTempPath2WFn g_originalGetTempPath2W = nullptr;
RegCreateKeyExWFn g_originalRegCreateKeyExW = nullptr;
RegOpenKeyExWFn g_originalRegOpenKeyExW = nullptr;
RegisterClassWFn g_originalRegisterClassW = nullptr;
RegisterClassExWFn g_originalRegisterClassExW = nullptr;
UnregisterClassWFn g_originalUnregisterClassW = nullptr;
CreateWindowExWFn g_originalCreateWindowExW = nullptr;
FindWindowWFn g_originalFindWindowW = nullptr;
FindWindowExWFn g_originalFindWindowExW = nullptr;
GetClassInfoWFn g_originalGetClassInfoW = nullptr;
GetClassInfoExWFn g_originalGetClassInfoExW = nullptr;
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
std::wstring g_boxRoot;
std::wstring g_hookDllPath;
std::wstring g_programDir;
std::wstring g_hookProfile;
std::vector<std::wstring> g_objectMarkers;
std::vector<std::wstring> g_filePathMarkers;
std::vector<std::wstring> g_registryRoots;
std::vector<std::wstring> g_windowMarkers;
bool g_clipboardVirtualization = false;
bool g_shellBrokerHooks = false;
bool g_childHookPropagation = false;
bool g_redirectAllObjects = false;
bool g_verboseIsolationLogging = false;
bool g_enableObjectHooks = false;
bool g_enableFileHooks = false;
bool g_enableRegistryHooks = false;
bool g_enableWindowHooks = false;
bool g_hideWindowLookup = false;
bool g_isolateRegistryReads = false;
bool g_rewriteWindowClasses = false;
std::mutex g_fakeClipboardHandlesMutex;
std::vector<HGLOBAL> g_fakeClipboardHandles;

thread_local int g_hookDepth = 0;
thread_local bool g_showMessageSent = false;
thread_local int g_isolationDepth = 0;

struct HookScope {
    HookScope()
    {
        if (g_hookDepth == 0)
            g_showMessageSent = false;
        ++g_hookDepth;
    }
    ~HookScope() { --g_hookDepth; }
};

struct IsolationScope {
    IsolationScope() { ++g_isolationDepth; }
    ~IsolationScope() { --g_isolationDepth; }
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

bool envFlag(const wchar_t* name)
{
    const std::wstring value = environmentString(name);
    return value == L"1" || _wcsicmp(value.c_str(), L"true") == 0 ||
           _wcsicmp(value.c_str(), L"yes") == 0;
}

bool startsWithI(const std::wstring& value, const std::wstring& prefix)
{
    return value.size() >= prefix.size() &&
           _wcsnicmp(value.c_str(), prefix.c_str(), prefix.size()) == 0;
}

bool hasBoundary(const std::wstring& value, size_t prefixLength)
{
    return value.size() == prefixLength || value[prefixLength] == L'\\' ||
           value[prefixLength] == L'/';
}

std::wstring joinPath(const std::wstring& left, const std::wstring& right)
{
    if (left.empty())
        return right;
    if (right.empty())
        return left;
    if (left.back() == L'\\' || left.back() == L'/')
        return left + right;
    return left + L"\\" + right;
}

std::wstring sanitizeName(const std::wstring& value)
{
    std::wstring result;
    result.reserve(value.size());
    for (wchar_t ch : value) {
        if ((ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') ||
            (ch >= L'0' && ch <= L'9') || ch == L'_' || ch == L'-' ||
            ch == L'.') {
            result.push_back(ch);
        } else {
            result.push_back(L'_');
        }
    }
    return result.empty() ? L"Box" : result;
}

void addUniqueMarker(std::vector<std::wstring>* markers, std::wstring marker)
{
    marker = lower(std::move(marker));
    if (marker.empty())
        return;
    if (std::find(markers->begin(), markers->end(), marker) == markers->end())
        markers->push_back(std::move(marker));
}

void addDelimitedMarkers(std::vector<std::wstring>* markers,
                         const std::wstring& value)
{
    size_t start = 0;
    while (start <= value.size()) {
        const size_t end = value.find_first_of(L";,", start);
        addUniqueMarker(markers, value.substr(
            start, end == std::wstring::npos ? std::wstring::npos :
                                               end - start));
        if (end == std::wstring::npos)
            break;
        start = end + 1;
    }
}

bool containsAnyMarker(const std::wstring& value,
                       const std::vector<std::wstring>& markers)
{
    const std::wstring lowered = lower(value);
    for (const std::wstring& marker : markers) {
        if (!marker.empty() && lowered.find(marker) != std::wstring::npos)
            return true;
    }
    return false;
}

void createDirectoryTree(const std::wstring& dir)
{
    if (dir.empty())
        return;

    std::wstring normalized = dir;
    std::replace(normalized.begin(), normalized.end(), L'/', L'\\');

    size_t pos = 0;
    if (normalized.rfind(L"\\\\", 0) == 0) {
        pos = normalized.find(L'\\', 2);
        if (pos != std::wstring::npos)
            pos = normalized.find(L'\\', pos + 1);
    } else if (normalized.size() >= 3 && normalized[1] == L':' &&
               normalized[2] == L'\\') {
        pos = 3;
    }

    while (pos != std::wstring::npos) {
        pos = normalized.find(L'\\', pos + 1);
        const std::wstring part = pos == std::wstring::npos
            ? normalized
            : normalized.substr(0, pos);
        if (!part.empty())
            CreateDirectoryW(part.c_str(), nullptr);
    }
}

void createParentDirectory(const std::wstring& path)
{
    const size_t slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos)
        createDirectoryTree(path.substr(0, slash));
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

std::wstring redirectUnder(const wchar_t* category, const std::wstring& relative)
{
    std::wstring trimmed = relative;
    while (!trimmed.empty() &&
           (trimmed.front() == L'\\' || trimmed.front() == L'/')) {
        trimmed.erase(trimmed.begin());
    }
    return joinPath(joinPath(g_boxRoot, L"Redirected"),
                    joinPath(category, trimmed));
}

std::wstring rewriteObjectName(LPCWSTR original)
{
    if (!original || !*original || g_boxName.empty())
        return {};

    std::wstring name(original);
    if (startsWithI(name, L"Local\\Iso_"))
        return {};

    std::wstring rest = name;
    if (startsWithI(rest, L"Global\\"))
        rest.erase(0, 7);
    else if (startsWithI(rest, L"Local\\"))
        rest.erase(0, 6);

    if (!g_redirectAllObjects && !containsAnyMarker(rest, g_objectMarkers))
        return {};

    return L"Local\\Iso_" + sanitizeName(g_boxName) + L"_" +
           sanitizeName(rest);
}

std::wstring rewritePipeName(const std::wstring& path)
{
    constexpr wchar_t pipePrefix[] = L"\\\\.\\pipe\\";
    if (!startsWithI(path, pipePrefix))
        return {};
    if (startsWithI(path, hookipc::kPipeName))
        return {};

    const std::wstring rest = path.substr(wcslen(pipePrefix));
    if (!g_redirectAllObjects && !containsAnyMarker(rest, g_objectMarkers))
        return {};

    return std::wstring(pipePrefix) + L"Iso_" + sanitizeName(g_boxName) +
           L"_" + sanitizeName(rest);
}

std::wstring rewriteMarkedUserDataPath(const std::wstring& path)
{
    if (g_filePathMarkers.empty() ||
        !containsAnyMarker(path, g_filePathMarkers)) {
        return {};
    }
    if (!g_programDir.empty() && startsWithI(path, g_programDir) &&
        hasBoundary(path, g_programDir.size())) {
        return {};
    }

    struct Rule {
        std::wstring prefix;
        const wchar_t* category;
    };
    const Rule rules[] = {
        {environmentString(L"SANDBOX_HOST_APPDATA"), L"HostRoaming"},
        {environmentString(L"SANDBOX_HOST_LOCALAPPDATA"), L"HostLocal"},
        {environmentString(L"SANDBOX_HOST_DOCUMENTS"), L"HostDocuments"},
        {environmentString(L"SANDBOX_HOST_USERPROFILE"), L"HostProfile"},
    };

    for (const Rule& rule : rules) {
        if (!rule.prefix.empty() && startsWithI(path, rule.prefix) &&
            hasBoundary(path, rule.prefix.size())) {
            return redirectUnder(rule.category, path.substr(rule.prefix.size()));
        }
    }
    return {};
}

std::wstring rewriteFilePath(LPCWSTR original)
{
    if (!original || !*original || g_boxRoot.empty())
        return {};

    const std::wstring path(original);
    const std::wstring pipe = rewritePipeName(path);
    if (!pipe.empty())
        return pipe;

    struct Rule {
        std::wstring prefix;
        const wchar_t* category;
    };
    const std::wstring appData = environmentString(L"APPDATA");
    const std::wstring localAppData = environmentString(L"LOCALAPPDATA");
    const std::wstring temp = environmentString(L"TEMP");
    const std::wstring tmp = environmentString(L"TMP");
    const Rule rules[] = {
        {joinPath(appData, L"Microsoft\\Office"), L"Roaming"},
        {joinPath(appData, L"Microsoft\\PowerPoint"), L"Roaming"},
        {joinPath(localAppData, L"Microsoft\\Office"), L"Local"},
        {joinPath(localAppData, L"Microsoft\\PowerPoint"), L"Local"},
        {temp, L"Temp"},
        {tmp, L"Temp"},
    };

    for (const Rule& rule : rules) {
        if (!rule.prefix.empty() && startsWithI(path, rule.prefix) &&
            hasBoundary(path, rule.prefix.size())) {
            return redirectUnder(rule.category, path.substr(rule.prefix.size()));
        }
    }

    return rewriteMarkedUserDataPath(path);
}

DWORD copyPathToCaller(const std::wstring& path, DWORD bufferLength,
                       LPWSTR buffer)
{
    std::wstring withSlash = path;
    if (!withSlash.empty() && withSlash.back() != L'\\' &&
        withSlash.back() != L'/') {
        withSlash.push_back(L'\\');
    }

    const DWORD required = static_cast<DWORD>(withSlash.size());
    if (bufferLength == 0 || !buffer || bufferLength <= required)
        return required + 1;

    wcscpy_s(buffer, bufferLength, withSlash.c_str());
    return required;
}

bool isRedirectedRegistryPath(HKEY root, LPCWSTR subKey)
{
    if (root != HKEY_CURRENT_USER || !subKey || g_boxName.empty())
        return false;

    const std::wstring path(subKey);
    for (const std::wstring& registryRoot : g_registryRoots) {
        if (startsWithI(path, registryRoot) &&
            hasBoundary(path, registryRoot.size())) {
            return true;
        }
    }
    return false;
}

std::wstring rewriteRegistryPath(LPCWSTR subKey)
{
    return L"Software\\SandboxDemo\\Boxes\\" + sanitizeName(g_boxName) +
           L"\\Registry\\" + std::wstring(subKey);
}

bool wantsRegistryWrite(REGSAM samDesired)
{
    constexpr REGSAM writeBits = KEY_SET_VALUE | KEY_CREATE_SUB_KEY |
        KEY_WRITE | KEY_ALL_ACCESS | DELETE | WRITE_DAC | WRITE_OWNER;
    return (samDesired & writeBits) != 0;
}

std::wstring rewriteWindowClassName(LPCWSTR original)
{
    if (!g_rewriteWindowClasses || !original || IS_INTRESOURCE(original) ||
        !*original || g_boxName.empty()) {
        return {};
    }

    std::wstring name(original);
    if (startsWithI(name, L"Iso_"))
        return {};
    if (!containsAnyMarker(name, g_windowMarkers))
        return {};

    return L"Iso_" + sanitizeName(g_boxName) + L"_" + sanitizeName(name);
}

bool windowLookupMatchesMarker(LPCWSTR className, LPCWSTR windowName)
{
    if (!g_hideWindowLookup)
        return false;
    if (className && !IS_INTRESOURCE(className) &&
        containsAnyMarker(className, g_windowMarkers)) {
        return true;
    }
    if (windowName && containsAnyMarker(windowName, g_windowMarkers))
        return true;
    return false;
}

HANDLE WINAPI hookedCreateFileW(LPCWSTR fileName, DWORD desiredAccess,
                                DWORD shareMode,
                                LPSECURITY_ATTRIBUTES securityAttributes,
                                DWORD creationDisposition,
                                DWORD flagsAndAttributes,
                                HANDLE templateFile)
{
    if (g_isolationDepth > 0) {
        return g_originalCreateFileW(fileName, desiredAccess, shareMode,
                                     securityAttributes, creationDisposition,
                                     flagsAndAttributes, templateFile);
    }
    IsolationScope isolationScope;
    const std::wstring rewritten = rewriteFilePath(fileName);
    if (!rewritten.empty()) {
        createParentDirectory(rewritten);
        if (g_verboseIsolationLogging) {
            hooklog::write(L"[isolation] CreateFileW redirected %s -> %s",
                           safe(fileName), rewritten.c_str());
        }
        return g_originalCreateFileW(
            rewritten.c_str(), desiredAccess, shareMode, securityAttributes,
            creationDisposition, flagsAndAttributes, templateFile);
    }
    return g_originalCreateFileW(fileName, desiredAccess, shareMode,
                                 securityAttributes, creationDisposition,
                                 flagsAndAttributes, templateFile);
}

HANDLE WINAPI hookedCreateMutexW(LPSECURITY_ATTRIBUTES attributes,
                                 BOOL initialOwner, LPCWSTR name)
{
    if (g_isolationDepth > 0)
        return g_originalCreateMutexW(attributes, initialOwner, name);
    IsolationScope isolationScope;
    const std::wstring redirected = rewriteObjectName(name);
    return g_originalCreateMutexW(attributes, initialOwner,
                                  redirected.empty() ? name :
                                                       redirected.c_str());
}

HANDLE WINAPI hookedCreateMutexExW(LPSECURITY_ATTRIBUTES attributes,
                                   LPCWSTR name, DWORD flags,
                                   DWORD desiredAccess)
{
    if (g_isolationDepth > 0)
        return g_originalCreateMutexExW(attributes, name, flags, desiredAccess);
    IsolationScope isolationScope;
    const std::wstring redirected = rewriteObjectName(name);
    return g_originalCreateMutexExW(attributes,
                                    redirected.empty() ? name :
                                                         redirected.c_str(),
                                    flags, desiredAccess);
}

HANDLE WINAPI hookedOpenMutexW(DWORD desiredAccess, BOOL inheritHandle,
                               LPCWSTR name)
{
    if (g_isolationDepth > 0)
        return g_originalOpenMutexW(desiredAccess, inheritHandle, name);
    IsolationScope isolationScope;
    const std::wstring redirected = rewriteObjectName(name);
    return g_originalOpenMutexW(desiredAccess, inheritHandle,
                                redirected.empty() ? name : redirected.c_str());
}

HANDLE WINAPI hookedCreateEventW(LPSECURITY_ATTRIBUTES attributes,
                                 BOOL manualReset, BOOL initialState,
                                 LPCWSTR name)
{
    if (g_isolationDepth > 0)
        return g_originalCreateEventW(attributes, manualReset, initialState,
                                      name);
    IsolationScope isolationScope;
    const std::wstring redirected = rewriteObjectName(name);
    return g_originalCreateEventW(attributes, manualReset, initialState,
                                  redirected.empty() ? name :
                                                       redirected.c_str());
}

HANDLE WINAPI hookedCreateEventExW(LPSECURITY_ATTRIBUTES attributes,
                                   LPCWSTR name, DWORD flags,
                                   DWORD desiredAccess)
{
    if (g_isolationDepth > 0)
        return g_originalCreateEventExW(attributes, name, flags,
                                        desiredAccess);
    IsolationScope isolationScope;
    const std::wstring redirected = rewriteObjectName(name);
    return g_originalCreateEventExW(attributes,
                                    redirected.empty() ? name :
                                                         redirected.c_str(),
                                    flags, desiredAccess);
}

HANDLE WINAPI hookedOpenEventW(DWORD desiredAccess, BOOL inheritHandle,
                               LPCWSTR name)
{
    if (g_isolationDepth > 0)
        return g_originalOpenEventW(desiredAccess, inheritHandle, name);
    IsolationScope isolationScope;
    const std::wstring redirected = rewriteObjectName(name);
    return g_originalOpenEventW(desiredAccess, inheritHandle,
                                redirected.empty() ? name : redirected.c_str());
}

HANDLE WINAPI hookedCreateSemaphoreW(LPSECURITY_ATTRIBUTES attributes,
                                     LONG initialCount, LONG maximumCount,
                                     LPCWSTR name)
{
    if (g_isolationDepth > 0)
        return g_originalCreateSemaphoreW(attributes, initialCount,
                                          maximumCount, name);
    IsolationScope isolationScope;
    const std::wstring redirected = rewriteObjectName(name);
    return g_originalCreateSemaphoreW(
        attributes, initialCount, maximumCount,
        redirected.empty() ? name : redirected.c_str());
}

HANDLE WINAPI hookedCreateSemaphoreExW(LPSECURITY_ATTRIBUTES attributes,
                                       LONG initialCount, LONG maximumCount,
                                       LPCWSTR name, DWORD flags,
                                       DWORD desiredAccess)
{
    if (g_isolationDepth > 0)
        return g_originalCreateSemaphoreExW(
            attributes, initialCount, maximumCount, name, flags, desiredAccess);
    IsolationScope isolationScope;
    const std::wstring redirected = rewriteObjectName(name);
    return g_originalCreateSemaphoreExW(
        attributes, initialCount, maximumCount,
        redirected.empty() ? name : redirected.c_str(), flags, desiredAccess);
}

HANDLE WINAPI hookedOpenSemaphoreW(DWORD desiredAccess, BOOL inheritHandle,
                                   LPCWSTR name)
{
    if (g_isolationDepth > 0)
        return g_originalOpenSemaphoreW(desiredAccess, inheritHandle, name);
    IsolationScope isolationScope;
    const std::wstring redirected = rewriteObjectName(name);
    return g_originalOpenSemaphoreW(desiredAccess, inheritHandle,
                                    redirected.empty() ? name :
                                                         redirected.c_str());
}

HANDLE WINAPI hookedCreateFileMappingW(HANDLE file,
                                       LPSECURITY_ATTRIBUTES attributes,
                                       DWORD protect, DWORD maximumSizeHigh,
                                       DWORD maximumSizeLow, LPCWSTR name)
{
    if (g_isolationDepth > 0)
        return g_originalCreateFileMappingW(
            file, attributes, protect, maximumSizeHigh, maximumSizeLow, name);
    IsolationScope isolationScope;
    const std::wstring redirected = rewriteObjectName(name);
    return g_originalCreateFileMappingW(
        file, attributes, protect, maximumSizeHigh, maximumSizeLow,
        redirected.empty() ? name : redirected.c_str());
}

HANDLE WINAPI hookedOpenFileMappingW(DWORD desiredAccess, BOOL inheritHandle,
                                     LPCWSTR name)
{
    if (g_isolationDepth > 0)
        return g_originalOpenFileMappingW(desiredAccess, inheritHandle, name);
    IsolationScope isolationScope;
    const std::wstring redirected = rewriteObjectName(name);
    return g_originalOpenFileMappingW(desiredAccess, inheritHandle,
                                      redirected.empty() ? name :
                                                           redirected.c_str());
}

DWORD WINAPI hookedGetTempPathW(DWORD bufferLength, LPWSTR buffer)
{
    if (g_boxRoot.empty())
        return g_originalGetTempPathW(bufferLength, buffer);

    const std::wstring temp = joinPath(joinPath(g_boxRoot, L"Redirected"),
                                       L"Temp");
    createDirectoryTree(temp);
    return copyPathToCaller(temp, bufferLength, buffer);
}

DWORD WINAPI hookedGetTempPath2W(DWORD bufferLength, LPWSTR buffer)
{
    if (g_boxRoot.empty())
        return g_originalGetTempPath2W
            ? g_originalGetTempPath2W(bufferLength, buffer)
            : g_originalGetTempPathW(bufferLength, buffer);

    const std::wstring temp = joinPath(joinPath(g_boxRoot, L"Redirected"),
                                       L"Temp");
    createDirectoryTree(temp);
    return copyPathToCaller(temp, bufferLength, buffer);
}

LSTATUS WINAPI hookedRegCreateKeyExW(HKEY key, LPCWSTR subKey, DWORD reserved,
                                     LPWSTR className, DWORD options,
                                     REGSAM samDesired,
                                     LPSECURITY_ATTRIBUTES securityAttributes,
                                     PHKEY result, LPDWORD disposition)
{
    if (isRedirectedRegistryPath(key, subKey)) {
        const std::wstring rewritten = rewriteRegistryPath(subKey);
        return g_originalRegCreateKeyExW(
            HKEY_CURRENT_USER, rewritten.c_str(), reserved, className, options,
            samDesired, securityAttributes, result, disposition);
    }
    return g_originalRegCreateKeyExW(key, subKey, reserved, className, options,
                                     samDesired, securityAttributes, result,
                                     disposition);
}

LSTATUS WINAPI hookedRegOpenKeyExW(HKEY key, LPCWSTR subKey, DWORD options,
                                   REGSAM samDesired, PHKEY result)
{
    if (isRedirectedRegistryPath(key, subKey) &&
        (wantsRegistryWrite(samDesired) || g_isolateRegistryReads)) {
        const std::wstring rewritten = rewriteRegistryPath(subKey);
        if (wantsRegistryWrite(samDesired)) {
            DWORD disposition = 0;
            return g_originalRegCreateKeyExW(
                HKEY_CURRENT_USER, rewritten.c_str(), 0, nullptr,
                REG_OPTION_NON_VOLATILE, samDesired, nullptr, result,
                &disposition);
        }
        return g_originalRegOpenKeyExW(HKEY_CURRENT_USER, rewritten.c_str(),
                                       options, samDesired, result);
    }
    return g_originalRegOpenKeyExW(key, subKey, options, samDesired, result);
}

ATOM WINAPI hookedRegisterClassW(const WNDCLASSW* windowClass)
{
    if (!windowClass)
        return g_originalRegisterClassW(windowClass);
    const std::wstring rewritten =
        rewriteWindowClassName(windowClass->lpszClassName);
    if (rewritten.empty())
        return g_originalRegisterClassW(windowClass);

    WNDCLASSW copy = *windowClass;
    copy.lpszClassName = rewritten.c_str();
    return g_originalRegisterClassW(&copy);
}

ATOM WINAPI hookedRegisterClassExW(const WNDCLASSEXW* windowClass)
{
    if (!windowClass)
        return g_originalRegisterClassExW(windowClass);
    const std::wstring rewritten =
        rewriteWindowClassName(windowClass->lpszClassName);
    if (rewritten.empty())
        return g_originalRegisterClassExW(windowClass);

    WNDCLASSEXW copy = *windowClass;
    copy.lpszClassName = rewritten.c_str();
    return g_originalRegisterClassExW(&copy);
}

BOOL WINAPI hookedUnregisterClassW(LPCWSTR className, HINSTANCE instance)
{
    const std::wstring rewritten = rewriteWindowClassName(className);
    return g_originalUnregisterClassW(
        rewritten.empty() ? className : rewritten.c_str(), instance);
}

HWND WINAPI hookedCreateWindowExW(DWORD exStyle, LPCWSTR className,
                                  LPCWSTR windowName, DWORD style, int x,
                                  int y, int width, int height, HWND parent,
                                  HMENU menu, HINSTANCE instance, LPVOID param)
{
    const std::wstring rewritten = rewriteWindowClassName(className);
    return g_originalCreateWindowExW(
        exStyle, rewritten.empty() ? className : rewritten.c_str(), windowName,
        style, x, y, width, height, parent, menu, instance, param);
}

HWND WINAPI hookedFindWindowW(LPCWSTR className, LPCWSTR windowName)
{
    const std::wstring rewritten = rewriteWindowClassName(className);
    if (!rewritten.empty())
        return g_originalFindWindowW(rewritten.c_str(), windowName);
    if (windowLookupMatchesMarker(className, windowName))
        return nullptr;
    return g_originalFindWindowW(className, windowName);
}

HWND WINAPI hookedFindWindowExW(HWND parent, HWND childAfter,
                                LPCWSTR className, LPCWSTR windowName)
{
    const std::wstring rewritten = rewriteWindowClassName(className);
    if (!rewritten.empty())
        return g_originalFindWindowExW(parent, childAfter, rewritten.c_str(),
                                       windowName);
    if (windowLookupMatchesMarker(className, windowName))
        return nullptr;
    return g_originalFindWindowExW(parent, childAfter, className, windowName);
}

BOOL WINAPI hookedGetClassInfoW(HINSTANCE instance, LPCWSTR className,
                                LPWNDCLASSW windowClass)
{
    const std::wstring rewritten = rewriteWindowClassName(className);
    return g_originalGetClassInfoW(
        instance, rewritten.empty() ? className : rewritten.c_str(),
        windowClass);
}

BOOL WINAPI hookedGetClassInfoExW(HINSTANCE instance, LPCWSTR className,
                                  LPWNDCLASSEXW windowClass)
{
    const std::wstring rewritten = rewriteWindowClassName(className);
    return g_originalGetClassInfoExW(
        instance, rewritten.empty() ? className : rewritten.c_str(),
        windowClass);
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
    const bool propagateHook = g_childHookPropagation &&
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

void configureIsolationProfile()
{
    addDelimitedMarkers(&g_objectMarkers,
                        environmentString(L"SANDBOX_OBJECT_MARKERS"));
    addDelimitedMarkers(&g_filePathMarkers,
                        environmentString(L"SANDBOX_FILE_PATH_MARKERS"));
    addDelimitedMarkers(&g_windowMarkers,
                        environmentString(L"SANDBOX_WINDOW_CLASS_MARKERS"));
    addDelimitedMarkers(&g_registryRoots,
                        environmentString(L"SANDBOX_REGISTRY_ROOTS"));

    g_hookProfile = lower(environmentString(L"SANDBOX_HOOK_PROFILE"));
    if (g_hookProfile == L"wps") {
        for (const wchar_t* marker :
             {L"wps", L"kingsoft", L"kso", L"ksolaunch", L"office6",
              L"\x91d1\x5c71"}) {
            addUniqueMarker(&g_objectMarkers, marker);
        }
    }

    if (g_hookProfile == L"word") {
        for (const wchar_t* marker :
             {L"word", L"winword", L"office", L"mso", L"dde"}) {
            addUniqueMarker(&g_objectMarkers, marker);
            addUniqueMarker(&g_windowMarkers, marker);
        }
        addUniqueMarker(&g_registryRoots, L"Software\\Microsoft\\Office");
    }

    if (g_hookProfile == L"powerpoint" || g_hookProfile == L"ppt") {
        for (const wchar_t* marker :
             {L"powerp", L"powerpoint", L"office", L"mso", L"ppt", L"dde"}) {
            addUniqueMarker(&g_objectMarkers, marker);
            addUniqueMarker(&g_windowMarkers, marker);
        }
        addUniqueMarker(&g_registryRoots, L"Software\\Microsoft\\Office");
        addUniqueMarker(&g_registryRoots, L"Software\\Microsoft\\PowerPoint");
    }

    if (g_hookProfile == L"foxmail") {
        for (const wchar_t* marker : {L"foxmail", L"foxmail7"}) {
            addUniqueMarker(&g_objectMarkers, marker);
            addUniqueMarker(&g_filePathMarkers, marker);
            addUniqueMarker(&g_windowMarkers, marker);
        }
        addUniqueMarker(&g_registryRoots, L"Software\\Foxmail7");
    }
}

} // namespace

namespace hooks {

bool install()
{
    hooklog::write(L"[lifecycle] hooks::install begin");
    g_boxName = environmentString(L"SANDBOX_BOX");
    g_boxRoot = environmentString(L"SANDBOX_ROOT");
    g_hookDllPath = environmentString(L"SANDBOX_HOOK_DLL");
    g_programDir = environmentString(L"SANDBOX_PROGRAM_DIR");
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
    g_shellBrokerHooks = envFlag(L"SANDBOX_ENABLE_SHELL_BROKER");
    g_clipboardVirtualization = envFlag(L"SANDBOX_ENABLE_CLIPBOARD_HOOK") &&
                                !g_boxName.empty();
    configureIsolationProfile();
    g_childHookPropagation = envFlag(L"SANDBOX_ENABLE_CHILD_HOOK") &&
                             !g_boxName.empty() && g_hookProfile != L"wps";
    g_enableObjectHooks = envFlag(L"SANDBOX_ENABLE_OBJECT_HOOK");
    g_enableFileHooks = envFlag(L"SANDBOX_ENABLE_FILE_HOOK");
    g_enableRegistryHooks = envFlag(L"SANDBOX_ENABLE_REGISTRY_HOOK");
    g_enableWindowHooks = envFlag(L"SANDBOX_ENABLE_WINDOW_HOOK");
    g_hideWindowLookup = envFlag(L"SANDBOX_HIDE_WINDOW_LOOKUP");
    g_isolateRegistryReads = envFlag(L"SANDBOX_REGISTRY_READ_ISOLATED");
    g_rewriteWindowClasses = envFlag(L"SANDBOX_REWRITE_WINDOW_CLASS");
    g_redirectAllObjects = envFlag(L"SANDBOX_REDIRECT_ALL_OBJECTS") &&
                           g_hookProfile != L"wps";
    g_verboseIsolationLogging = envFlag(L"SANDBOX_VERBOSE_ISOLATION_LOG");

    hooklog::write(L"[setup] box=%s root=%s shellBroker=%d clipboard=%d "
                   L"child=%d iso(object=%d file=%d registry=%d window=%d)",
                   g_boxName.empty() ? L"<none>" : g_boxName.c_str(),
                   g_boxRoot.empty() ? L"<none>" : g_boxRoot.c_str(),
                   g_shellBrokerHooks ? 1 : 0,
                   g_clipboardVirtualization ? 1 : 0,
                   g_childHookPropagation ? 1 : 0,
                   g_enableObjectHooks ? 1 : 0,
                   g_enableFileHooks ? 1 : 0,
                   g_enableRegistryHooks ? 1 : 0,
                   g_enableWindowHooks ? 1 : 0);
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
    resolve(L"kernel32.dll", "CreateFileW", g_originalCreateFileW,
            L"CreateFileW");
    resolve(L"kernel32.dll", "CreateMutexW", g_originalCreateMutexW,
            L"CreateMutexW");
    resolve(L"kernel32.dll", "CreateMutexExW", g_originalCreateMutexExW,
            L"CreateMutexExW");
    resolve(L"kernel32.dll", "OpenMutexW", g_originalOpenMutexW,
            L"OpenMutexW");
    resolve(L"kernel32.dll", "CreateEventW", g_originalCreateEventW,
            L"CreateEventW");
    resolve(L"kernel32.dll", "CreateEventExW", g_originalCreateEventExW,
            L"CreateEventExW");
    resolve(L"kernel32.dll", "OpenEventW", g_originalOpenEventW,
            L"OpenEventW");
    resolve(L"kernel32.dll", "CreateSemaphoreW", g_originalCreateSemaphoreW,
            L"CreateSemaphoreW");
    resolve(L"kernel32.dll", "CreateSemaphoreExW",
            g_originalCreateSemaphoreExW, L"CreateSemaphoreExW");
    resolve(L"kernel32.dll", "OpenSemaphoreW", g_originalOpenSemaphoreW,
            L"OpenSemaphoreW");
    resolve(L"kernel32.dll", "CreateFileMappingW",
            g_originalCreateFileMappingW, L"CreateFileMappingW");
    resolve(L"kernel32.dll", "OpenFileMappingW",
            g_originalOpenFileMappingW, L"OpenFileMappingW");
    resolve(L"kernel32.dll", "GetTempPathW", g_originalGetTempPathW,
            L"GetTempPathW");
    resolve(L"kernel32.dll", "GetTempPath2W", g_originalGetTempPath2W,
            L"GetTempPath2W");
    resolve(L"advapi32.dll", "RegCreateKeyExW", g_originalRegCreateKeyExW,
            L"RegCreateKeyExW");
    resolve(L"advapi32.dll", "RegOpenKeyExW", g_originalRegOpenKeyExW,
            L"RegOpenKeyExW");
    resolve(L"user32.dll", "RegisterClassW", g_originalRegisterClassW,
            L"RegisterClassW");
    resolve(L"user32.dll", "RegisterClassExW", g_originalRegisterClassExW,
            L"RegisterClassExW");
    resolve(L"user32.dll", "UnregisterClassW", g_originalUnregisterClassW,
            L"UnregisterClassW");
    resolve(L"user32.dll", "CreateWindowExW", g_originalCreateWindowExW,
            L"CreateWindowExW");
    resolve(L"user32.dll", "FindWindowW", g_originalFindWindowW,
            L"FindWindowW");
    resolve(L"user32.dll", "FindWindowExW", g_originalFindWindowExW,
            L"FindWindowExW");
    resolve(L"user32.dll", "GetClassInfoW", g_originalGetClassInfoW,
            L"GetClassInfoW");
    resolve(L"user32.dll", "GetClassInfoExW", g_originalGetClassInfoExW,
            L"GetClassInfoExW");
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

    if (g_shellBrokerHooks) {
        attach(g_originalSHOpen, hookedSHOpenFolderAndSelectItems,
               L"SHOpenFolderAndSelectItems");
        attach(g_originalShellExecuteW, hookedShellExecuteW, L"ShellExecuteW");
        attach(g_originalShellExecuteExW, hookedShellExecuteExW,
               L"ShellExecuteExW");
    }
    attach(g_originalCreateProcessW, hookedCreateProcessW, L"CreateProcessW");
    if (g_enableFileHooks) {
        attach(g_originalCreateFileW, hookedCreateFileW, L"CreateFileW");
        attach(g_originalGetTempPathW, hookedGetTempPathW, L"GetTempPathW");
        attach(g_originalGetTempPath2W, hookedGetTempPath2W, L"GetTempPath2W");
    }
    if (g_enableObjectHooks) {
        attach(g_originalCreateMutexW, hookedCreateMutexW, L"CreateMutexW");
        attach(g_originalCreateMutexExW, hookedCreateMutexExW,
               L"CreateMutexExW");
        attach(g_originalOpenMutexW, hookedOpenMutexW, L"OpenMutexW");
        attach(g_originalCreateEventW, hookedCreateEventW, L"CreateEventW");
        attach(g_originalCreateEventExW, hookedCreateEventExW,
               L"CreateEventExW");
        attach(g_originalOpenEventW, hookedOpenEventW, L"OpenEventW");
        attach(g_originalCreateSemaphoreW, hookedCreateSemaphoreW,
               L"CreateSemaphoreW");
        attach(g_originalCreateSemaphoreExW, hookedCreateSemaphoreExW,
               L"CreateSemaphoreExW");
        attach(g_originalOpenSemaphoreW, hookedOpenSemaphoreW,
               L"OpenSemaphoreW");
        attach(g_originalCreateFileMappingW, hookedCreateFileMappingW,
               L"CreateFileMappingW");
        attach(g_originalOpenFileMappingW, hookedOpenFileMappingW,
               L"OpenFileMappingW");
    }
    if (g_enableRegistryHooks) {
        attach(g_originalRegCreateKeyExW, hookedRegCreateKeyExW,
               L"RegCreateKeyExW");
        attach(g_originalRegOpenKeyExW, hookedRegOpenKeyExW, L"RegOpenKeyExW");
    }
    if (g_enableWindowHooks) {
        attach(g_originalRegisterClassW, hookedRegisterClassW,
               L"RegisterClassW");
        attach(g_originalRegisterClassExW, hookedRegisterClassExW,
               L"RegisterClassExW");
        attach(g_originalUnregisterClassW, hookedUnregisterClassW,
               L"UnregisterClassW");
        attach(g_originalCreateWindowExW, hookedCreateWindowExW,
               L"CreateWindowExW");
        attach(g_originalFindWindowW, hookedFindWindowW, L"FindWindowW");
        attach(g_originalFindWindowExW, hookedFindWindowExW, L"FindWindowExW");
        attach(g_originalGetClassInfoW, hookedGetClassInfoW, L"GetClassInfoW");
        attach(g_originalGetClassInfoExW, hookedGetClassInfoExW,
               L"GetClassInfoExW");
    }
    if (g_clipboardVirtualization) {
        attach(g_originalOpenClipboard, hookedOpenClipboard, L"OpenClipboard");
        attach(g_originalCloseClipboard, hookedCloseClipboard, L"CloseClipboard");
        attach(g_originalEmptyClipboard, hookedEmptyClipboard, L"EmptyClipboard");
        attach(g_originalSetClipboardData, hookedSetClipboardData,
               L"SetClipboardData");
        attach(g_originalGetClipboardData, hookedGetClipboardData,
               L"GetClipboardData");
        attach(g_originalIsClipboardFormatAvailable,
               hookedIsClipboardFormatAvailable,
               L"IsClipboardFormatAvailable");
        attach(g_originalGetPriorityClipboardFormat,
               hookedGetPriorityClipboardFormat,
               L"GetPriorityClipboardFormat");
        attach(g_originalCountClipboardFormats, hookedCountClipboardFormats,
               L"CountClipboardFormats");
        attach(g_originalEnumClipboardFormats, hookedEnumClipboardFormats,
               L"EnumClipboardFormats");
        attach(g_originalOleSetClipboard, hookedOleSetClipboard,
               L"OleSetClipboard");
    }

    result = DetourTransactionCommit();
    hooklog::write(L"[setup] DetourTransactionCommit -> %ld", result);
    g_installed = result == NO_ERROR;
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
    if (g_shellBrokerHooks) {
        detach(g_originalSHOpen, hookedSHOpenFolderAndSelectItems,
               L"SHOpenFolderAndSelectItems");
        detach(g_originalShellExecuteW, hookedShellExecuteW, L"ShellExecuteW");
        detach(g_originalShellExecuteExW, hookedShellExecuteExW,
               L"ShellExecuteExW");
    }
    detach(g_originalCreateProcessW, hookedCreateProcessW, L"CreateProcessW");
    if (g_enableFileHooks) {
        detach(g_originalCreateFileW, hookedCreateFileW, L"CreateFileW");
        detach(g_originalGetTempPathW, hookedGetTempPathW, L"GetTempPathW");
        detach(g_originalGetTempPath2W, hookedGetTempPath2W, L"GetTempPath2W");
    }
    if (g_enableObjectHooks) {
        detach(g_originalCreateMutexW, hookedCreateMutexW, L"CreateMutexW");
        detach(g_originalCreateMutexExW, hookedCreateMutexExW,
               L"CreateMutexExW");
        detach(g_originalOpenMutexW, hookedOpenMutexW, L"OpenMutexW");
        detach(g_originalCreateEventW, hookedCreateEventW, L"CreateEventW");
        detach(g_originalCreateEventExW, hookedCreateEventExW,
               L"CreateEventExW");
        detach(g_originalOpenEventW, hookedOpenEventW, L"OpenEventW");
        detach(g_originalCreateSemaphoreW, hookedCreateSemaphoreW,
               L"CreateSemaphoreW");
        detach(g_originalCreateSemaphoreExW, hookedCreateSemaphoreExW,
               L"CreateSemaphoreExW");
        detach(g_originalOpenSemaphoreW, hookedOpenSemaphoreW,
               L"OpenSemaphoreW");
        detach(g_originalCreateFileMappingW, hookedCreateFileMappingW,
               L"CreateFileMappingW");
        detach(g_originalOpenFileMappingW, hookedOpenFileMappingW,
               L"OpenFileMappingW");
    }
    if (g_enableRegistryHooks) {
        detach(g_originalRegCreateKeyExW, hookedRegCreateKeyExW,
               L"RegCreateKeyExW");
        detach(g_originalRegOpenKeyExW, hookedRegOpenKeyExW,
               L"RegOpenKeyExW");
    }
    if (g_enableWindowHooks) {
        detach(g_originalRegisterClassW, hookedRegisterClassW,
               L"RegisterClassW");
        detach(g_originalRegisterClassExW, hookedRegisterClassExW,
               L"RegisterClassExW");
        detach(g_originalUnregisterClassW, hookedUnregisterClassW,
               L"UnregisterClassW");
        detach(g_originalCreateWindowExW, hookedCreateWindowExW,
               L"CreateWindowExW");
        detach(g_originalFindWindowW, hookedFindWindowW, L"FindWindowW");
        detach(g_originalFindWindowExW, hookedFindWindowExW, L"FindWindowExW");
        detach(g_originalGetClassInfoW, hookedGetClassInfoW, L"GetClassInfoW");
        detach(g_originalGetClassInfoExW, hookedGetClassInfoExW,
               L"GetClassInfoExW");
    }
    if (g_clipboardVirtualization) {
        detach(g_originalOpenClipboard, hookedOpenClipboard, L"OpenClipboard");
        detach(g_originalCloseClipboard, hookedCloseClipboard, L"CloseClipboard");
        detach(g_originalEmptyClipboard, hookedEmptyClipboard, L"EmptyClipboard");
        detach(g_originalSetClipboardData, hookedSetClipboardData,
               L"SetClipboardData");
        detach(g_originalGetClipboardData, hookedGetClipboardData,
               L"GetClipboardData");
        detach(g_originalIsClipboardFormatAvailable,
               hookedIsClipboardFormatAvailable,
               L"IsClipboardFormatAvailable");
        detach(g_originalGetPriorityClipboardFormat,
               hookedGetPriorityClipboardFormat,
               L"GetPriorityClipboardFormat");
        detach(g_originalCountClipboardFormats, hookedCountClipboardFormats,
               L"CountClipboardFormats");
        detach(g_originalEnumClipboardFormats, hookedEnumClipboardFormats,
               L"EnumClipboardFormats");
        detach(g_originalOleSetClipboard, hookedOleSetClipboard,
               L"OleSetClipboard");
    }
    const LONG result = DetourTransactionCommit();
    g_installed = false;
    freeFakeClipboardHandles();
    hooklog::write(L"[lifecycle] hooks::remove end commit=%ld", result);
}

} // namespace hooks
