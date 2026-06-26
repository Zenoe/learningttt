#include "HookIpcServer.h"

#include "HookIpcProtocol.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

bool createPipeSecurityDescriptor(PSECURITY_DESCRIPTOR& descriptor)
{
    descriptor = nullptr;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    DWORD bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    std::vector<BYTE> storage(bytes);
    const bool gotUser = bytes != 0 &&
        GetTokenInformation(token, TokenUser, storage.data(), bytes, &bytes);
    CloseHandle(token);
    if (!gotUser)
        return false;

    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(storage.data());
    LPWSTR sidText = nullptr;
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidText))
        return false;

    // Same user and SYSTEM get full access. The explicit medium mandatory
    // label permits a medium-integrity Chrome browser to write to a pipe owned
    // by an elevated SandboxDemo process.
    const std::wstring sddl =
        L"D:P(A;;GA;;;" + std::wstring(sidText) +
        L")(A;;GA;;;SY)S:(ML;;NW;;;ME)";
    LocalFree(sidText);

    return ConvertStringSecurityDescriptorToSecurityDescriptorW(
               sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr) != FALSE;
}

void fillResponse(hookipc::Message& response,
                  hookipc::MessageType type,
                  const wchar_t* boxName,
                  const std::wstring& text)
{
    response = {};
    response.magic = hookipc::kMagic;
    response.version = hookipc::kVersion;
    response.type = static_cast<std::uint32_t>(type);
    response.processId = GetCurrentProcessId();
    response.threadId = GetCurrentThreadId();
    if (boxName && boxName[0])
        wcsncpy_s(response.boxName, boxName, hookipc::kMaxBox - 1);

    const std::size_t length =
        (std::min)(text.size(), static_cast<std::size_t>(hookipc::kMaxText - 1));
    response.textLength = static_cast<std::uint32_t>(length);
    if (length)
        wmemcpy(response.text, text.data(), length);
    response.text[length] = L'\0';
}

std::wstring readHostClipboardText()
{
    if (!OpenClipboard(nullptr))
        return {};

    std::wstring result;
    HANDLE data = nullptr;
    UINT format = 0;
    if (IsClipboardFormatAvailable(CF_UNICODETEXT)) {
        format = CF_UNICODETEXT;
        data = GetClipboardData(CF_UNICODETEXT);
    } else if (IsClipboardFormatAvailable(CF_TEXT)) {
        format = CF_TEXT;
        data = GetClipboardData(CF_TEXT);
    }

    if (data) {
        void* locked = GlobalLock(data);
        if (locked && format == CF_UNICODETEXT) {
            result = static_cast<const wchar_t*>(locked);
        } else if (locked && format == CF_TEXT) {
            const char* text = static_cast<const char*>(locked);
            const int needed = MultiByteToWideChar(CP_ACP, 0, text, -1,
                                                   nullptr, 0);
            if (needed > 0) {
                result.resize(static_cast<std::size_t>(needed - 1));
                MultiByteToWideChar(CP_ACP, 0, text, -1,
                                    result.data(), needed);
            }
        }
        if (locked)
            GlobalUnlock(data);
    }

    CloseClipboard();
    return result;
}

bool hostClipboardHasText()
{
    return IsClipboardFormatAvailable(CF_UNICODETEXT) ||
           IsClipboardFormatAvailable(CF_TEXT);
}

} // namespace

HookIpcServer::HookIpcServer(QObject* parent)
    : QObject(parent)
{
    m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    m_ioEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!m_stopEvent || !m_ioEvent) {
        emit serverError(QStringLiteral("Hook IPC event creation failed (GLE=%1)")
                             .arg(GetLastError()));
        return;
    }

    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
    if (!createPipeSecurityDescriptor(securityDescriptor)) {
        emit serverError(QStringLiteral(
            "Hook IPC security descriptor creation failed (GLE=%1)")
                             .arg(GetLastError()));
        return;
    }
    SECURITY_ATTRIBUTES securityAttributes{};
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.lpSecurityDescriptor = securityDescriptor;

    HANDLE pipe = CreateNamedPipeW(
        hookipc::kPipeName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        sizeof(hookipc::Message),
        sizeof(hookipc::Message),
        0,
        &securityAttributes);
    LocalFree(securityDescriptor);
    if (pipe == INVALID_HANDLE_VALUE) {
        emit serverError(QStringLiteral("Hook IPC pipe creation failed (GLE=%1)")
                             .arg(GetLastError()));
        return;
    }

    m_pipe = pipe;
    m_running = true;
    m_listening = true;
    m_thread = std::thread(&HookIpcServer::run, this);
}

HookIpcServer::~HookIpcServer()
{
    stop();
}

void HookIpcServer::stop()
{
    m_running = false;
    if (m_stopEvent)
        SetEvent(static_cast<HANDLE>(m_stopEvent));
    if (m_pipe)
        CancelIoEx(static_cast<HANDLE>(m_pipe), nullptr);
    if (m_thread.joinable())
        m_thread.join();

    if (m_pipe) {
        CloseHandle(static_cast<HANDLE>(m_pipe));
        m_pipe = nullptr;
    }
    if (m_stopEvent) {
        CloseHandle(static_cast<HANDLE>(m_stopEvent));
        m_stopEvent = nullptr;
    }
    if (m_ioEvent) {
        CloseHandle(static_cast<HANDLE>(m_ioEvent));
        m_ioEvent = nullptr;
    }
    m_listening = false;
}

void HookIpcServer::run()
{
    HANDLE pipe = static_cast<HANDLE>(m_pipe);
    HANDLE stopEvent = static_cast<HANDLE>(m_stopEvent);
    HANDLE ioEvent = static_cast<HANDLE>(m_ioEvent);
    std::unordered_map<std::wstring, std::wstring> textClipboardByBox;

    auto writeResponse = [&](const hookipc::Message& response) {
        OVERLAPPED writeOverlapped{};
        ResetEvent(ioEvent);
        writeOverlapped.hEvent = ioEvent;

        BOOL writeOk = WriteFile(pipe, &response, sizeof(response),
                                 nullptr, &writeOverlapped);
        if (!writeOk && GetLastError() == ERROR_IO_PENDING) {
            HANDLE waits[] = { stopEvent, ioEvent };
            const DWORD wait = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0) {
                CancelIoEx(pipe, &writeOverlapped);
                return false;
            }
            DWORD written = 0;
            writeOk = GetOverlappedResult(pipe, &writeOverlapped,
                                          &written, FALSE);
            return writeOk && written == sizeof(response);
        }
        return writeOk != FALSE;
    };

    while (m_running.load()) {
        OVERLAPPED connectOverlapped{};
        ResetEvent(ioEvent);
        connectOverlapped.hEvent = ioEvent;

        BOOL connected = ConnectNamedPipe(pipe, &connectOverlapped);
        if (!connected) {
            const DWORD error = GetLastError();
            if (error == ERROR_PIPE_CONNECTED) {
                connected = TRUE;
            } else if (error == ERROR_IO_PENDING) {
                HANDLE waits[] = { stopEvent, ioEvent };
                const DWORD wait = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
                if (wait == WAIT_OBJECT_0) {
                    CancelIoEx(pipe, &connectOverlapped);
                    break;
                }
                DWORD ignored = 0;
                connected = GetOverlappedResult(pipe, &connectOverlapped,
                                                &ignored, FALSE);
            }
        }

        if (!connected) {
            DisconnectNamedPipe(pipe);
            if (WaitForSingleObject(stopEvent, 25) == WAIT_OBJECT_0)
                break;
            continue;
        }

        hookipc::Message message{};
        DWORD bytesRead = 0;
        OVERLAPPED readOverlapped{};
        ResetEvent(ioEvent);
        readOverlapped.hEvent = ioEvent;

        BOOL readOk = ReadFile(pipe, &message, sizeof(message),
                               &bytesRead, &readOverlapped);
        if (!readOk && GetLastError() == ERROR_IO_PENDING) {
            HANDLE waits[] = { stopEvent, ioEvent };
            const DWORD wait = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0) {
                CancelIoEx(pipe, &readOverlapped);
                break;
            }
            readOk = GetOverlappedResult(pipe, &readOverlapped,
                                         &bytesRead, FALSE);
        }

        if (readOk && hookipc::isValid(message, bytesRead)) {
            const QString text = QString::fromWCharArray(
                message.text, static_cast<qsizetype>(message.textLength));
            const auto type = static_cast<hookipc::MessageType>(message.type);
            if (type == hookipc::MessageType::HookLog) {
                emit hookLogReceived(message.processId, message.threadId, text);
            } else if (type == hookipc::MessageType::ShowInFolder) {
                emit showInFolderRequested(message.processId, text);
            } else if (type == hookipc::MessageType::ClipboardSetText) {
                const std::wstring boxName = message.boxName;
                if (!boxName.empty()) {
                    textClipboardByBox[boxName] =
                        std::wstring(message.text, message.text + message.textLength);
                }
                hookipc::Message response{};
                fillResponse(response, hookipc::MessageType::ClipboardStatusResponse,
                             message.boxName,
                             boxName.empty() ? L"0" : L"1");
                writeResponse(response);
            } else if (type == hookipc::MessageType::ClipboardGetText ||
                       type == hookipc::MessageType::ClipboardHasText) {
                const std::wstring boxName = message.boxName;
                auto found = textClipboardByBox.find(boxName);
                const bool hasLocalClipboard = found != textClipboardByBox.end();
                const bool requestText =
                    type == hookipc::MessageType::ClipboardGetText;
                const std::wstring importedText =
                    hasLocalClipboard || !requestText
                        ? std::wstring()
                        : readHostClipboardText();
                const bool hasText = hasLocalClipboard
                    ? !found->second.empty()
                    : (requestText ? !importedText.empty() : hostClipboardHasText());
                hookipc::Message response{};
                if (type == hookipc::MessageType::ClipboardGetText) {
                    fillResponse(response,
                                 hookipc::MessageType::ClipboardTextResponse,
                                 message.boxName,
                                 hasLocalClipboard ? found->second : importedText);
                } else {
                    fillResponse(response,
                                 hookipc::MessageType::ClipboardStatusResponse,
                                 message.boxName,
                                 hasText ? L"1" : L"0");
                }
                writeResponse(response);
            }
        } else if (m_running.load()) {
            emit serverError(QStringLiteral("Hook IPC received an invalid frame (%1 bytes, GLE=%2)")
                                 .arg(bytesRead)
                                 .arg(readOk ? ERROR_SUCCESS : GetLastError()));
        }

        DisconnectNamedPipe(pipe);
    }

    m_listening = false;
}
