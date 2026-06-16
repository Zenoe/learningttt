#pragma once
// ============================================================
//  ProcessMonitor.h
//  Qt6 QObject that polls live SandboxedProcess handles and
//  emits signals when a process exits or its state changes.
// ============================================================
#include <QObject>
#include <QTimer>
#include <vector>
#include <functional>
#include "SandboxEngine.h"

struct ProcessEntry {
    SandboxedProcess sp;
    QString          label;
    bool             reported = false;
};

class ProcessMonitor : public QObject {
    Q_OBJECT
public:
    explicit ProcessMonitor(QObject* parent = nullptr);
    ~ProcessMonitor() override;

    void track(SandboxedProcess sp, const QString& label);
    void stopAll();
    int  count() const { return static_cast<int>(m_entries.size()); }

signals:
    void processExited(DWORD pid, const QString& label, DWORD exitCode);
    void statusUpdate(const QString& summary);

private slots:
    void poll();

private:
    QTimer               m_timer;
    std::vector<ProcessEntry> m_entries;
};
