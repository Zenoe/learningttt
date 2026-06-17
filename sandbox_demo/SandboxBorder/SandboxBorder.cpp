// ============================================================
//  SandboxBorder.cpp  —  injected shell broker payload
//
//  Detours-based Chrome "Show in folder" interception.  This follows the
//  successful otherDemo hook shape:
//    - primary: shell32!SHOpenFolderAndSelectItems
//    - nets:    shell32!ShellExecuteW / ShellExecuteExW
//    - net:     kernel32!CreateProcessW for explorer.exe /select,...
//
//  Matching calls are suppressed and forwarded to the Qt broker over the
//  existing JSON named pipe.
// ============================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SANDBOXBORDER_EXPORTS
#include "SandboxBorder.h"

#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#include <string>
#include <cstdio>
#include <cstdarg>
#include <algorithm>
#include <cwctype>

#if __has_include(<detours/detours.h>)
#include <detours/detours.h>
#elif __has_include(<detours.h>)
#include <detours.h>
#else
#error Microsoft Detours headers are required to build SandboxBorder.dll
#endif

#pragma comment(lib, "Shell32.lib")

namespace {

static wchar_t g_BoxName[64] = {};
static wchar_t g_SandboxRoot[MAX_PATH] = {};
static constexpr wchar_t g_PipeName[] = SANDBOX_PIPE_NAME;

using PFN_SHOpenFolderAndSelectItems = HRESULT(WINAPI*)(
    PCIDLIST_ABSOLUTE, UINT, PCUITEMID_CHILD_ARRAY, DWORD);
using PFN_ShellExecuteW = HINSTANCE(WINAPI*)(
    HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
using PFN_ShellExecuteExW = BOOL(WINAPI*)(SHELLEXECUTEINFOW*);
using PFN_CreateProcessW = BOOL(WINAPI*)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static PFN_SHOpenFolderAndSelectItems g_origSHOpen = nullptr;
static PFN_ShellExecuteW g_origShellExecuteW = nullptr;
static PFN_ShellExecuteExW g_origShellExecuteExW = nullptr;
static PFN_CreateProcessW g_origCreateProcessW = nullptr;
static bool g_HooksInstalled = false;

thread_local int g_HookDepth = 0;
thread_local bool g_SentThisAction = false;

struct SendScope {
    SendScope()
    {
        if (g_HookDepth == 0)
            g_SentThisAction = false;
        ++g_HookDepth;
    }

    ~SendScope()
    {
        --g_HookDepth;
    }
};

static void LogLine(const wchar_t* fmt, ...)
{
    wchar_t dir[MAX_PATH] = {};
    DWORD n = GetTempPathW(MAX_PATH, dir);
    if (n == 0 || n >= MAX_PATH)
        return;

    wchar_t path[MAX_PATH] = {};
    _snwprintf_s(path, MAX_PATH, _TRUNCATE,
        L"%sSandboxBorder.log", dir);

    FILE* file = nullptr;
    if (_wfopen_s(&file, path, L"a, ccs=UTF-8") != 0 || !file)
        return;

    SYSTEMTIME st{};
    GetLocalTime(&st);
    fwprintf(file, L"[%02u:%02u:%02u.%03u pid=%lu tid=%lu] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        GetCurrentProcessId(), GetCurrentThreadId());

    va_list args;
    va_start(args, fmt);
    vfwprintf(file, fmt, args);
    va_end(args);

    fputwc(L'\n', file);
    fclose(file);
}

static std::wstring ToLower(std::wstring text)
{
    for (auto& ch : text)
        ch = static_cast<wchar_t>(towlower(ch));
    return text;
}

static bool Contains(const std::wstring& haystack, const wchar_t* needle)
{
    return haystack.find(needle) != std::wstring::npos;
}

static std::wstring Trim(std::wstring text)
{
    while (!text.empty() && iswspace(text.front()))
        text.erase(text.begin());
    while (!text.empty() && iswspace(text.back()))
        text.pop_back();
    if (text.size() >= 2 && text.front() == L'"' && text.back() == L'"')
        text = text.substr(1, text.size() - 2);
    return text;
}

static std::wstring NormalizeDir(std::wstring path)
{
    std::replace(path.begin(), path.end(), L'/', L'\\');
    while (!path.empty() && path.back() == L'\\')
        path.pop_back();
    return ToLower(std::move(path));
}

static bool IsExplorerReveal(LPCWSTR app, LPCWSTR cmdline, std::wstring& outPath)
{
    const std::wstring appText = app ? app : L"";
    const std::wstring cmdText = cmdline ? cmdline : L"";
    const std::wstring appLower = ToLower(appText);
    const std::wstring cmdLower = ToLower(cmdText);

    const bool isExplorer =
        Contains(appLower, L"explorer.exe") ||
        Contains(cmdLower, L"explorer.exe") ||
        Contains(appLower, L"\\explorer") ||
        (appText.empty() && cmdLower.rfind(L"explorer", 0) == 0);
    if (!isExplorer)
        return false;

    size_t pos = cmdLower.find(L"/select,");
    size_t advance = 8;
    if (pos == std::wstring::npos) {
        pos = cmdLower.find(L"/n,");
        advance = 3;
    }
    if (pos == std::wstring::npos)
        return false;

    std::wstring rest = cmdText.substr(pos + advance);
    rest = Trim(std::move(rest));
    if (rest.empty())
        return false;

    if (rest.front() == L'"') {
        rest.erase(0, 1);
        size_t quote = rest.find(L'"');
        if (quote != std::wstring::npos)
            rest = rest.substr(0, quote);
    }
    else {
        size_t end = rest.find_last_not_of(L" \t");
        if (end != std::wstring::npos)
            rest = rest.substr(0, end + 1);
    }

    outPath = rest;
    return !outPath.empty();
}

static bool IsSandboxDownloadsFolderOpen(
    LPCWSTR verb,
    LPCWSTR file,
    std::wstring& outPath)
{
    if (!file || g_SandboxRoot[0] == L'\0')
        return false;

    const std::wstring verbText = verb ? ToLower(verb) : L"";
    if (!(verbText.empty() || verbText == L"open" || verbText == L"explore"))
        return false;

    std::wstring downloads = std::wstring(g_SandboxRoot) + L"\\drive\\Downloads";
    if (NormalizeDir(file) != NormalizeDir(downloads))
        return false;

    DWORD attr = GetFileAttributesW(file);
    if (attr == INVALID_FILE_ATTRIBUTES ||
        !(attr & FILE_ATTRIBUTE_DIRECTORY))
        return false;

    outPath = file;
    return true;
}

static std::wstring PidlToPath(
    PCIDLIST_ABSOLUTE folder,
    UINT count,
    PCUITEMID_CHILD_ARRAY children)
{
    std::wstring path;

    if (count >= 1 && children && children[0]) {
        PIDLIST_ABSOLUTE full = ILCombine(folder, children[0]);
        if (full) {
            wchar_t buffer[MAX_PATH] = {};
            if (SHGetPathFromIDListW(full, buffer))
                path = buffer;
            ILFree(full);
        }
    }

    if (path.empty() && folder) {
        wchar_t buffer[MAX_PATH] = {};
        if (SHGetPathFromIDListW(folder, buffer))
            path = buffer;
    }

    return path;
}

static std::string Utf8FromWide(const wchar_t* text)
{
    if (!text || text[0] == L'\0')
        return {};

    int needed = WideCharToMultiByte(CP_UTF8, 0, text, -1,
        nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return {};

    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1,
        out.data(), needed, nullptr, nullptr);
    if (!out.empty() && out.back() == '\0')
        out.pop_back();
    return out;
}

static std::string JsonEscape(const std::string& text)
{
    std::string escaped;
    escaped.reserve(text.size());
    for (char ch : text) {
        if (ch == '\\')
            escaped += "\\\\";
        else if (ch == '"')
            escaped += "\\\"";
        else
            escaped += ch;
    }
    return escaped;
}

static bool NotifyHostOpenFolder(const std::wstring& realPath)
{
    if (realPath.empty() || g_BoxName[0] == L'\0')
        return false;

    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 3 && pipe == INVALID_HANDLE_VALUE; ++attempt) {
        pipe = CreateFileW(g_PipeName, GENERIC_WRITE, 0,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe != INVALID_HANDLE_VALUE)
            break;

        DWORD gle = GetLastError();
        LogLine(L"[pipe] connect attempt %d failed gle=%lu", attempt, gle);
        WaitNamedPipeW(g_PipeName, 1000);
    }

    if (pipe == INVALID_HANDLE_VALUE) {
        LogLine(L"[pipe] unreachable path=%s", realPath.c_str());
        return false;
    }

    std::string box = JsonEscape(Utf8FromWide(g_BoxName));
    std::string root = JsonEscape(Utf8FromWide(g_SandboxRoot));
    std::string path = JsonEscape(Utf8FromWide(realPath.c_str()));

    char message[4096] = {};
    int length = _snprintf_s(message, sizeof(message), _TRUNCATE,
        "{\"cmd\":\"openFolder\",\"box\":\"%s\",\"root\":\"%s\",\"path\":\"%s\"}\n",
        box.c_str(), root.c_str(), path.c_str());
    if (length <= 0) {
        CloseHandle(pipe);
        LogLine(L"[pipe] message format failed path=%s", realPath.c_str());
        return false;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(pipe, message, static_cast<DWORD>(length),
        &written, nullptr);
    CloseHandle(pipe);

    LogLine(L"[pipe] write ok=%d written=%lu/%d path=%s",
        ok, written, length, realPath.c_str());
    return ok && written == static_cast<DWORD>(length);
}

static void SignalOnce(const std::wstring& path)
{
    if (g_SentThisAction)
        return;
    if (NotifyHostOpenFolder(path))
        g_SentThisAction = true;
}

static HRESULT WINAPI Hook_SHOpenFolderAndSelectItems(
    PCIDLIST_ABSOLUTE folder,
    UINT count,
    PCUITEMID_CHILD_ARRAY children,
    DWORD flags)
{
    SendScope scope;
    const std::wstring path = PidlToPath(folder, count, children);
    LogLine(L"[hook] SHOpenFolderAndSelectItems path=%s",
        path.empty() ? L"<unknown>" : path.c_str());

    if (!path.empty()) {
        SignalOnce(path);
        if (g_SentThisAction)
            return S_OK;
    }

    return g_origSHOpen
        ? g_origSHOpen(folder, count, children, flags)
        : E_FAIL;
}

static HINSTANCE WINAPI Hook_ShellExecuteW(
    HWND window,
    LPCWSTR verb,
    LPCWSTR file,
    LPCWSTR parameters,
    LPCWSTR directory,
    INT showCommand)
{
    SendScope scope;
    std::wstring target;
    if (IsExplorerReveal(file, parameters, target) ||
        IsSandboxDownloadsFolderOpen(verb, file, target)) {
        LogLine(L"[hook] ShellExecuteW reveal -> %s", target.c_str());
        SignalOnce(target);
        if (g_SentThisAction)
            return reinterpret_cast<HINSTANCE>(static_cast<INT_PTR>(42));
    }

    return g_origShellExecuteW
        ? g_origShellExecuteW(window, verb, file, parameters,
            directory, showCommand)
        : reinterpret_cast<HINSTANCE>(static_cast<INT_PTR>(2));
}

static BOOL WINAPI Hook_ShellExecuteExW(SHELLEXECUTEINFOW* execInfo)
{
    SendScope scope;
    if (execInfo) {
        std::wstring target;
        if (IsExplorerReveal(execInfo->lpFile, execInfo->lpParameters, target) ||
            IsSandboxDownloadsFolderOpen(execInfo->lpVerb,
                execInfo->lpFile, target)) {
            LogLine(L"[hook] ShellExecuteExW reveal -> %s", target.c_str());
            SignalOnce(target);
            if (g_SentThisAction) {
                execInfo->hInstApp =
                    reinterpret_cast<HINSTANCE>(static_cast<INT_PTR>(42));
                return TRUE;
            }
        }
    }

    return g_origShellExecuteExW
        ? g_origShellExecuteExW(execInfo)
        : FALSE;
}

static BOOL WINAPI Hook_CreateProcessW(
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
    SendScope scope;
    std::wstring target;
    if (IsExplorerReveal(applicationName, commandLine, target)) {
        LogLine(L"[hook] CreateProcessW explorer reveal -> %s", target.c_str());
        SignalOnce(target);
        if (g_SentThisAction) {
            wchar_t noop[] = L"cmd.exe /c exit";
            return g_origCreateProcessW
                ? g_origCreateProcessW(nullptr, noop, processAttributes,
                    threadAttributes, FALSE, creationFlags | CREATE_NO_WINDOW,
                    environment, currentDirectory, startupInfo,
                    processInformation)
                : FALSE;
        }
    }

    return g_origCreateProcessW
        ? g_origCreateProcessW(applicationName, commandLine,
            processAttributes, threadAttributes, inheritHandles,
            creationFlags, environment, currentDirectory, startupInfo,
            processInformation)
        : FALSE;
}

template <typename Fn>
static bool ResolveOne(const wchar_t* moduleName,
    const char* functionName,
    Fn& original,
    const wchar_t* label)
{
    HMODULE module = GetModuleHandleW(moduleName);
    if (!module)
        module = LoadLibraryW(moduleName);
    if (!module) {
        LogLine(L"[hook] LoadLibraryW %s failed gle=%lu",
            moduleName, GetLastError());
        return false;
    }

    original = reinterpret_cast<Fn>(GetProcAddress(module, functionName));
    if (!original) {
        LogLine(L"[hook] GetProcAddress %s!%S failed gle=%lu",
            moduleName, functionName, GetLastError());
        return false;
    }

    LogLine(L"[hook] resolved %s", label);
    return true;
}

template <typename Fn>
static bool AttachOne(Fn& original, Fn detour, const wchar_t* label)
{
    if (!original)
        return false;

    LONG rc = DetourAttach(reinterpret_cast<PVOID*>(&original),
        reinterpret_cast<PVOID>(detour));
    LogLine(L"[hook] DetourAttach %s = %ld", label, rc);
    return rc == NO_ERROR;
}

template <typename Fn>
static void DetachOne(Fn& original, Fn detour, const wchar_t* label)
{
    if (!original)
        return;

    LONG rc = DetourDetach(reinterpret_cast<PVOID*>(&original),
        reinterpret_cast<PVOID>(detour));
    LogLine(L"[hook] DetourDetach %s = %ld", label, rc);
}

static bool LoadSandboxIdentity()
{
    GetEnvironmentVariableW(SANDBOX_BORDER_BOX_ENV,
        g_BoxName, ARRAYSIZE(g_BoxName));
    GetEnvironmentVariableW(L"SANDBOX_ROOT",
        g_SandboxRoot, ARRAYSIZE(g_SandboxRoot));

    LogLine(L"[hook] identity box=%s root=%s",
        g_BoxName[0] ? g_BoxName : L"<empty>",
        g_SandboxRoot[0] ? g_SandboxRoot : L"<empty>");
    return g_BoxName[0] != L'\0';
}

static bool InstallDetours()
{
    if (g_HooksInstalled)
        return true;
    if (!LoadSandboxIdentity())
        return false;

    if (!ResolveOne(L"shell32.dll", "SHOpenFolderAndSelectItems",
        g_origSHOpen, L"SHOpenFolderAndSelectItems")) {
        return false;
    }

    ResolveOne(L"shell32.dll", "ShellExecuteW",
        g_origShellExecuteW, L"ShellExecuteW");
    ResolveOne(L"shell32.dll", "ShellExecuteExW",
        g_origShellExecuteExW, L"ShellExecuteExW");
    ResolveOne(L"kernel32.dll", "CreateProcessW",
        g_origCreateProcessW, L"CreateProcessW");

    LONG rc = DetourTransactionBegin();
    if (rc != NO_ERROR) {
        LogLine(L"[hook] DetourTransactionBegin = %ld", rc);
        return false;
    }
    DetourUpdateThread(GetCurrentThread());

    bool primary = AttachOne(g_origSHOpen, Hook_SHOpenFolderAndSelectItems,
        L"SHOpenFolderAndSelectItems");
    AttachOne(g_origShellExecuteW, Hook_ShellExecuteW, L"ShellExecuteW");
    AttachOne(g_origShellExecuteExW, Hook_ShellExecuteExW, L"ShellExecuteExW");
    AttachOne(g_origCreateProcessW, Hook_CreateProcessW, L"CreateProcessW");

    rc = DetourTransactionCommit();
    LogLine(L"[hook] DetourTransactionCommit = %ld", rc);
    if (rc != NO_ERROR)
        return false;

    g_HooksInstalled = true;

    HMODULE shell = GetModuleHandleW(L"shell32.dll");
    if (shell) {
        const auto* code = reinterpret_cast<const BYTE*>(
            GetProcAddress(shell, "SHOpenFolderAndSelectItems"));
        if (code) {
            LogLine(L"[hook] SHOpen entry byte after enable = 0x%02X",
                code[0]);
        }
    }

    LogLine(L"[hook] Install done primary=%d", primary);
    return primary;
}

static void RemoveDetours()
{
    if (!g_HooksInstalled)
        return;

    if (DetourTransactionBegin() != NO_ERROR)
        return;
    DetourUpdateThread(GetCurrentThread());
    DetachOne(g_origSHOpen, Hook_SHOpenFolderAndSelectItems,
        L"SHOpenFolderAndSelectItems");
    DetachOne(g_origShellExecuteW, Hook_ShellExecuteW, L"ShellExecuteW");
    DetachOne(g_origShellExecuteExW, Hook_ShellExecuteExW, L"ShellExecuteExW");
    DetachOne(g_origCreateProcessW, Hook_CreateProcessW, L"CreateProcessW");
    LONG rc = DetourTransactionCommit();
    LogLine(L"[hook] Detour detach commit = %ld", rc);
    if (rc == NO_ERROR)
        g_HooksInstalled = false;
}

static DWORD WINAPI InitThreadProc(LPVOID)
{
    LogLine(L"[dll] init thread; installing hooks");
    InstallDetours();
    return 0;
}

} // namespace

extern "C" SBAPI BOOL WINAPI SandboxBorder_Init(void)
{
    return InstallDetours() ? TRUE : FALSE;
}

extern "C" SBAPI BOOL WINAPI SandboxBorder_Uninit(void)
{
    RemoveDetours();
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(reserved);

    if (DetourIsHelperProcess())
        return TRUE;

    if (reason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();
        DisableThreadLibraryCalls(instance);

        HANDLE thread = CreateThread(nullptr, 0, InitThreadProc,
            nullptr, 0, nullptr);
        if (thread)
            CloseHandle(thread);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        RemoveDetours();
    }

    return TRUE;
}
