#include "PipeClient.h"

#include "HookIpcProtocol.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <string>

namespace {

std::wstring currentBoxName()
{
    wchar_t box[hookipc::kMaxBox]{};
    const DWORD length = GetEnvironmentVariableW(L"SANDBOX_BOX", box,
                                                 hookipc::kMaxBox);
    if (length == 0 || length >= hookipc::kMaxBox)
        return {};
    return box;
}

void fillMessage(hookipc::Message& message,
                 hookipc::MessageType type,
                 const std::wstring& text)
{
    message = {};
    message.magic = hookipc::kMagic;
    message.version = hookipc::kVersion;
    message.type = static_cast<std::uint32_t>(type);
    message.processId = GetCurrentProcessId();
    message.threadId = GetCurrentThreadId();

    const std::wstring box = currentBoxName();
    if (!box.empty())
        wcsncpy_s(message.boxName, box.c_str(), hookipc::kMaxBox - 1);

    const std::size_t length =
        (std::min)(text.size(), static_cast<std::size_t>(hookipc::kMaxText - 1));
    message.textLength = static_cast<std::uint32_t>(length);
    if (length)
        wmemcpy(message.text, text.data(), length);
    message.text[length] = L'\0';
}

HANDLE openPipe(DWORD access)
{
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 4; ++attempt) {
        pipe = CreateFileW(hookipc::kPipeName,
                           access,
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

    return pipe;
}

bool sendMessage(hookipc::MessageType type,
                 const std::wstring& text,
                 bool allowEmpty = false)
{
    if (text.empty() && !allowEmpty)
        return false;

    HANDLE pipe = openPipe(GENERIC_WRITE);
    if (pipe == INVALID_HANDLE_VALUE)
        return false;

    hookipc::Message message{};
    fillMessage(message, type, text);

    DWORD written = 0;
    const BOOL ok = WriteFile(pipe, &message, sizeof(message), &written, nullptr);
    CloseHandle(pipe);
    return ok && written == sizeof(message);
}

bool requestMessage(hookipc::MessageType type,
                    const std::wstring& text,
                    hookipc::Message& response)
{
    HANDLE pipe = openPipe(GENERIC_READ | GENERIC_WRITE);
    if (pipe == INVALID_HANDLE_VALUE)
        return false;

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

    hookipc::Message message{};
    fillMessage(message, type, text);

    DWORD written = 0;
    BOOL ok = WriteFile(pipe, &message, sizeof(message), &written, nullptr);
    if (!ok || written != sizeof(message)) {
        CloseHandle(pipe);
        return false;
    }

    DWORD bytesRead = 0;
    response = {};
    ok = ReadFile(pipe, &response, sizeof(response), &bytesRead, nullptr);
    CloseHandle(pipe);
    return ok && hookipc::isValid(response, bytesRead);
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

bool setClipboardText(const std::wstring& text)
{
    hookipc::Message response{};
    if (!requestMessage(hookipc::MessageType::ClipboardSetText, text, response))
        return false;
    return static_cast<hookipc::MessageType>(response.type) ==
               hookipc::MessageType::ClipboardStatusResponse &&
           response.textLength == 1 &&
           response.text[0] == L'1';
}

bool getClipboardText(std::wstring& text)
{
    hookipc::Message response{};
    if (!requestMessage(hookipc::MessageType::ClipboardGetText, {}, response))
        return false;
    if (static_cast<hookipc::MessageType>(response.type) !=
        hookipc::MessageType::ClipboardTextResponse) {
        return false;
    }
    text.assign(response.text, response.text + response.textLength);
    return true;
}

bool hasClipboardText()
{
    hookipc::Message response{};
    if (!requestMessage(hookipc::MessageType::ClipboardHasText, {}, response))
        return false;
    return static_cast<hookipc::MessageType>(response.type) ==
               hookipc::MessageType::ClipboardStatusResponse &&
           response.textLength == 1 &&
           response.text[0] == L'1';
}

} // namespace pipeclient
