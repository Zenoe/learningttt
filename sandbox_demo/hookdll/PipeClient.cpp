#include "PipeClient.h"

#include "HookIpcProtocol.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>

namespace {

void fillMessage(hookipc::Message& message, hookipc::MessageType type,
                 const std::wstring& boxName, const std::wstring& text)
{
    message.magic = hookipc::kMagic;
    message.version = hookipc::kVersion;
    message.type = static_cast<std::uint32_t>(type);
    message.processId = GetCurrentProcessId();
    message.threadId = GetCurrentThreadId();

    const std::size_t boxLength =
        (std::min)(boxName.size(), static_cast<std::size_t>(hookipc::kMaxBox - 1));
    if (boxLength > 0)
        wmemcpy(message.boxName, boxName.data(), boxLength);
    message.boxName[boxLength] = L'\0';

    const std::size_t length =
        (std::min)(text.size(), static_cast<std::size_t>(hookipc::kMaxText - 1));
    message.textLength = static_cast<std::uint32_t>(length);
    if (length > 0)
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

bool sendMessage(hookipc::MessageType type, const std::wstring& text)
{
    if (text.empty())
        return false;

    HANDLE pipe = openPipe(GENERIC_WRITE);
    if (pipe == INVALID_HANDLE_VALUE)
        return false;

    hookipc::Message message{};
    fillMessage(message, type, {}, text);

    DWORD written = 0;
    const BOOL ok = WriteFile(pipe, &message, sizeof(message), &written, nullptr);
    CloseHandle(pipe);
    return ok && written == sizeof(message);
}

bool sendRequest(hookipc::MessageType type, const std::wstring& boxName,
                 const std::wstring& text, hookipc::Message& response)
{
    if (boxName.empty())
        return false;

    HANDLE pipe = openPipe(GENERIC_READ | GENERIC_WRITE);
    if (pipe == INVALID_HANDLE_VALUE)
        return false;

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

    hookipc::Message message{};
    fillMessage(message, type, boxName, text);

    DWORD written = 0;
    BOOL ok = WriteFile(pipe, &message, sizeof(message), &written, nullptr);
    if (ok && written == sizeof(message)) {
        DWORD bytesRead = 0;
        ok = ReadFile(pipe, &response, sizeof(response), &bytesRead, nullptr) &&
             hookipc::isValid(response, bytesRead);
    }

    CloseHandle(pipe);
    return ok != FALSE;
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

bool setClipboardText(const std::wstring& boxName, const std::wstring& text)
{
    hookipc::Message response{};
    return sendRequest(hookipc::MessageType::ClipboardSetText, boxName, text,
                       response) &&
           static_cast<hookipc::MessageType>(response.type) ==
               hookipc::MessageType::ClipboardStatusResponse &&
           response.result != 0;
}

bool clearClipboard(const std::wstring& boxName)
{
    hookipc::Message response{};
    return sendRequest(hookipc::MessageType::ClipboardClear, boxName, {},
                       response) &&
           static_cast<hookipc::MessageType>(response.type) ==
               hookipc::MessageType::ClipboardStatusResponse &&
           response.result != 0;
}

bool getClipboardText(const std::wstring& boxName, std::wstring& text,
                      bool& hasText)
{
    hookipc::Message response{};
    if (!sendRequest(hookipc::MessageType::ClipboardGetText, boxName, {},
                     response) ||
        static_cast<hookipc::MessageType>(response.type) !=
            hookipc::MessageType::ClipboardTextResponse) {
        return false;
    }

    hasText = response.result != 0;
    text.assign(response.text, response.text + response.textLength);
    return true;
}

bool hasClipboardText(const std::wstring& boxName, bool& hasText)
{
    hookipc::Message response{};
    if (!sendRequest(hookipc::MessageType::ClipboardHasText, boxName, {},
                     response) ||
        static_cast<hookipc::MessageType>(response.type) !=
            hookipc::MessageType::ClipboardStatusResponse) {
        return false;
    }

    hasText = response.result != 0;
    return true;
}

bool getSystemClipboardText(const std::wstring& boxName, std::wstring& text,
                            bool& hasText)
{
    hookipc::Message response{};
    if (!sendRequest(hookipc::MessageType::ClipboardGetSystemText, boxName, {},
                     response) ||
        static_cast<hookipc::MessageType>(response.type) !=
            hookipc::MessageType::ClipboardTextResponse) {
        return false;
    }

    hasText = response.result != 0;
    text.assign(response.text, response.text + response.textLength);
    return true;
}

bool hasSystemClipboardText(const std::wstring& boxName, bool& hasText)
{
    hookipc::Message response{};
    if (!sendRequest(hookipc::MessageType::ClipboardHasSystemText, boxName, {},
                     response) ||
        static_cast<hookipc::MessageType>(response.type) !=
            hookipc::MessageType::ClipboardStatusResponse) {
        return false;
    }

    hasText = response.result != 0;
    return true;
}

} // namespace pipeclient
