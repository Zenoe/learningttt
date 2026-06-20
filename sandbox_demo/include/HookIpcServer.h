#pragma once

#include <QObject>
#include <QString>

#include <atomic>
#include <thread>

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

    void* m_pipe = nullptr;
    void* m_stopEvent = nullptr;
    void* m_ioEvent = nullptr;
    std::thread m_thread;
    std::atomic_bool m_running{false};
    std::atomic_bool m_listening{false};
};
