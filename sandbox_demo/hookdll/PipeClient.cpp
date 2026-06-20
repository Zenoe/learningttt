#include "PipeClient.h"

#include "HookIpcProtocol.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>

namespace {

bool sendMessage(hookipc::MessageType type, const std::wstring& text)
{
    if (text.empty())
        return false;

    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 4; ++attempt) {
        pipe = CreateFileW(hookipc::kPipeName,
                           GENERIC_WRITE,
                           0,
                           nullptr,
                           OPEN_EXISTING,
                           0,
                           nullptr);
        if (pipe != INVALID_HANDLE_VALUE)
            break;

        const DWORD error = GetLastError();
        if (error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND)
            break;
        WaitNamedPipeW(hookipc::kPipeName, 250);
    }

    if (pipe == INVALID_HANDLE_VALUE)
        return false;

    hookipc::Message message{};
    message.magic = hookipc::kMagic;
    message.version = hookipc::kVersion;
    message.type = static_cast<std::uint32_t>(type);
    message.processId = GetCurrentProcessId();
    message.threadId = GetCurrentThreadId();

    const std::size_t length =
        (std::min)(text.size(), static_cast<std::size_t>(hookipc::kMaxText - 1));
    message.textLength = static_cast<std::uint32_t>(length);
    wmemcpy(message.text, text.data(), length);
    message.text[length] = L'\0';

    DWORD written = 0;
    const BOOL ok = WriteFile(pipe, &message, sizeof(message), &written, nullptr);
    CloseHandle(pipe);
    return ok && written == sizeof(message);
}

} // namespace

namespace pipeclient {

bool sendShowInFolder(const std::wstring& path)
{
    return sendMessage(hookipc::MessageType::ShowInFolder, path);
}

bool sendLog(const std::wstring& text)
{
    return sendMessage(hookipc::MessageType::HookLog, text);
}

} // namespace pipeclient
