#pragma once

#include "HookIpcProtocol.h"

#include <QObject>
#include <QString>

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

class HookIpcServer : public QObject {
    Q_OBJECT
public:
    explicit HookIpcServer(QObject* parent = nullptr);
    ~HookIpcServer() override;

    bool isListening() const { return m_listening.load(); }
    void stop();

signals:
    void hookLogReceived(quint32 processId, quint32 threadId,
                         const QString& message);
    void showInFolderRequested(quint32 processId, const QString& path);
    void serverError(const QString& message);

private:
    void run();
    bool handleClipboardMessage(const hookipc::Message& message,
                                hookipc::Message& response);

    void* m_pipe = nullptr;
    void* m_stopEvent = nullptr;
    void* m_ioEvent = nullptr;
    std::thread m_thread;
    std::atomic_bool m_running{false};
    std::atomic_bool m_listening{false};
    std::mutex m_clipboardMutex;
    std::unordered_map<std::wstring, std::wstring> m_clipboardTextByBox;
};
