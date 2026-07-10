#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>

#include <cwchar>

namespace {

int failureCode(DWORD code)
{
    return static_cast<int>(code == ERROR_SUCCESS ? ERROR_FUNCTION_FAILED :
                                                   code);
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR commandLine, int)
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(commandLine, &argc);
    if (!argv || argc < 2) {
        if (argv)
            LocalFree(argv);
        return ERROR_BAD_ARGUMENTS;
    }

    const DWORD pid = wcstoul(argv[0], nullptr, 10);
    const wchar_t* dllPath = argv[1];
    if (pid == 0 || !dllPath || !*dllPath) {
        LocalFree(argv);
        return ERROR_BAD_ARGUMENTS;
    }

    HANDLE process = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!process) {
        const DWORD error = GetLastError();
        LocalFree(argv);
        return failureCode(error);
    }

    const SIZE_T bytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    void* remotePath = VirtualAllocEx(process, nullptr, bytes,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_READWRITE);
    if (!remotePath) {
        const DWORD error = GetLastError();
        CloseHandle(process);
        LocalFree(argv);
        return failureCode(error);
    }

    DWORD result = ERROR_SUCCESS;
    if (!WriteProcessMemory(process, remotePath, dllPath, bytes, nullptr)) {
        result = GetLastError();
    } else {
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        auto* loadLibraryW = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(kernel32, "LoadLibraryW"));
        HANDLE thread = loadLibraryW
            ? CreateRemoteThread(process, nullptr, 0, loadLibraryW, remotePath,
                                 0, nullptr)
            : nullptr;
        if (!thread) {
            result = GetLastError();
        } else {
            WaitForSingleObject(thread, 10000);
            DWORD exitCode = 0;
            if (!GetExitCodeThread(thread, &exitCode) || exitCode == 0)
                result = exitCode == 0 ? ERROR_DLL_INIT_FAILED : GetLastError();
            CloseHandle(thread);
        }
    }

    VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
    CloseHandle(process);
    LocalFree(argv);
    return result == ERROR_SUCCESS ? ERROR_SUCCESS : failureCode(result);
}
