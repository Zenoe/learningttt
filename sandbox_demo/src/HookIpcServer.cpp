#include "HookIpcServer.h"

#include "HookIpcProtocol.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>

#include <algorithm>
#include <string>
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

    // Same user and SYSTEM get full access. The explicit low mandatory label
    // permits low-integrity browser children on Win10 to reach the broker while
    // the DACL still limits access to this user and SYSTEM.
    const std::wstring sddl =
        L"D:P(A;;GA;;;" + std::wstring(sidText) +
        L")(A;;GA;;;SY)S:(ML;;NW;;;LW)";
    LocalFree(sidText);

    return ConvertStringSecurityDescriptorToSecurityDescriptorW(
               sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr) != FALSE;
}

void fillResponse(hookipc::Message& response,
                  hookipc::MessageType type,
                  const std::wstring& boxName,
                  const std::wstring& text,
                  bool result)
{
    response.magic = hookipc::kMagic;
    response.version = hookipc::kVersion;
    response.type = static_cast<std::uint32_t>(type);
    response.processId = GetCurrentProcessId();
    response.threadId = GetCurrentThreadId();
    response.result = result ? 1u : 0u;

    const std::size_t boxLength =
        (std::min)(boxName.size(), static_cast<std::size_t>(hookipc::kMaxBox - 1));
    if (boxLength > 0)
        wmemcpy(response.boxName, boxName.data(), boxLength);
    response.boxName[boxLength] = L'\0';

    const std::size_t textLength =
        (std::min)(text.size(), static_cast<std::size_t>(hookipc::kMaxText - 1));
    response.textLength = static_cast<std::uint32_t>(textLength);
    if (textLength > 0)
        wmemcpy(response.text, text.data(), textLength);
    response.text[textLength] = L'\0';
}

std::wstring textFromClipboardHandle(HANDLE data, UINT format)
{
    if (!data)
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
    } else if (format == CF_TEXT) {
        const char* text = static_cast<const char*>(locked);
        std::size_t length = 0;
        while (length < size && text[length] != '\0')
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

bool readSystemClipboardText(std::wstring& text)
{
    text.clear();
    bool opened = false;
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (OpenClipboard(nullptr)) {
            opened = true;
            break;
        }
        Sleep(10);
    }
    if (!opened)
        return false;

    bool hasText = false;
    HANDLE data = GetClipboardData(CF_UNICODETEXT);
    if (data) {
        text = textFromClipboardHandle(data, CF_UNICODETEXT);
        hasText = true;
    } else {
        data = GetClipboardData(CF_TEXT);
        if (data) {
            text = textFromClipboardHandle(data, CF_TEXT);
            hasText = true;
        }
    }

    CloseClipboard();
    return hasText;
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

bool HookIpcServer::handleClipboardMessage(const hookipc::Message& message,
                                           hookipc::Message& response)
{
    const auto type = static_cast<hookipc::MessageType>(message.type);
    const std::wstring boxName(message.boxName);
    if (boxName.empty())
        return false;

    const std::wstring text(message.text, message.text + message.textLength);

    if (type == hookipc::MessageType::ClipboardGetSystemText) {
        std::wstring systemText;
        const bool hasText = readSystemClipboardText(systemText);
        fillResponse(response, hookipc::MessageType::ClipboardTextResponse,
                     boxName, systemText, hasText);
        return true;
    }

    if (type == hookipc::MessageType::ClipboardHasSystemText) {
        std::wstring systemText;
        const bool hasText = readSystemClipboardText(systemText);
        fillResponse(response, hookipc::MessageType::ClipboardStatusResponse,
                     boxName, {}, hasText);
        return true;
    }

    if (type == hookipc::MessageType::ClipboardSetText) {
        std::lock_guard<std::mutex> lock(m_clipboardMutex);
        m_clipboardByBox[boxName] = ClipboardState{
            text,
            GetClipboardSequenceNumber()
        };
        fillResponse(response, hookipc::MessageType::ClipboardStatusResponse,
                     boxName, {}, true);
        return true;
    }

    if (type == hookipc::MessageType::ClipboardClear) {
        std::lock_guard<std::mutex> lock(m_clipboardMutex);
        m_clipboardByBox.erase(boxName);
        fillResponse(response, hookipc::MessageType::ClipboardStatusResponse,
                     boxName, {}, true);
        return true;
    }

    if (type == hookipc::MessageType::ClipboardHasText) {
        ClipboardState state;
        bool hasPrivate = false;
        {
            std::lock_guard<std::mutex> lock(m_clipboardMutex);
            const auto it = m_clipboardByBox.find(boxName);
            hasPrivate = it != m_clipboardByBox.end();
            if (hasPrivate)
                state = it->second;
        }

        bool hasText = hasPrivate;
        if (!hasPrivate ||
            GetClipboardSequenceNumber() != state.systemSequenceAtSet) {
            std::wstring systemText;
            if (readSystemClipboardText(systemText))
                hasText = true;
        }
        fillResponse(response, hookipc::MessageType::ClipboardStatusResponse,
                     boxName, {}, hasText);
        return true;
    }

    if (type == hookipc::MessageType::ClipboardGetText) {
        ClipboardState state;
        bool hasPrivate = false;
        {
            std::lock_guard<std::mutex> lock(m_clipboardMutex);
            const auto it = m_clipboardByBox.find(boxName);
            hasPrivate = it != m_clipboardByBox.end();
            if (hasPrivate)
                state = it->second;
        }

        std::wstring resultText;
        bool hasText = false;
        if (!hasPrivate ||
            GetClipboardSequenceNumber() != state.systemSequenceAtSet) {
            hasText = readSystemClipboardText(resultText);
        }
        if (!hasText && hasPrivate) {
            resultText = state.text;
            hasText = true;
        }
        fillResponse(response, hookipc::MessageType::ClipboardTextResponse,
                     boxName, resultText, hasText);
        return true;
    }

    return false;
}

void HookIpcServer::run()
{
    HANDLE pipe = static_cast<HANDLE>(m_pipe);
    HANDLE stopEvent = static_cast<HANDLE>(m_stopEvent);
    HANDLE ioEvent = static_cast<HANDLE>(m_ioEvent);

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
            } else {
                hookipc::Message response{};
                if (handleClipboardMessage(message, response)) {
                    DWORD written = 0;
                    OVERLAPPED writeOverlapped{};
                    ResetEvent(ioEvent);
                    writeOverlapped.hEvent = ioEvent;
                    BOOL writeOk = WriteFile(pipe, &response, sizeof(response),
                                             &written, &writeOverlapped);
                    if (!writeOk && GetLastError() == ERROR_IO_PENDING) {
                        HANDLE waits[] = { stopEvent, ioEvent };
                        const DWORD wait = WaitForMultipleObjects(
                            2, waits, FALSE, INFINITE);
                        if (wait == WAIT_OBJECT_0) {
                            CancelIoEx(pipe, &writeOverlapped);
                            break;
                        }
                        GetOverlappedResult(pipe, &writeOverlapped, &written,
                                            FALSE);
                    }
                }
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
