#include "HookIpcServer.h"

#include "HookIpcProtocol.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

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

    HANDLE pipe = CreateNamedPipeW(
        hookipc::kPipeName,
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        sizeof(hookipc::Message),
        sizeof(hookipc::Message),
        0,
        nullptr);
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
