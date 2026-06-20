#include "HookLogger.h"

#include "HookIpcProtocol.h"
#include "PipeClient.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdarg>
#include <cwchar>
#include <string>

namespace hooklog {

void write(const wchar_t* format, ...)
{
    wchar_t buffer[hookipc::kMaxText]{};
    va_list args;
    va_start(args, format);
    _vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, format, args);
    va_end(args);

    OutputDebugStringW(buffer);
    OutputDebugStringW(L"\n");
    pipeclient::sendLog(std::wstring(buffer));
}

} // namespace hooklog
