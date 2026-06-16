// ============================================================
//  ProcessMonitor.cpp
// ============================================================
#include "ProcessMonitor.h"
#include <QStringList>
#include <algorithm>

ProcessMonitor::ProcessMonitor(QObject* parent)
    : QObject(parent)
{
    connect(&m_timer, &QTimer::timeout, this, &ProcessMonitor::poll);
    m_timer.start(1000);  // poll every second
}

ProcessMonitor::~ProcessMonitor()
{
    stopAll();
}

void ProcessMonitor::track(SandboxedProcess sp, const QString& label)
{
    ProcessEntry entry;
    entry.sp    = std::move(sp);
    entry.label = label;
    m_entries.push_back(std::move(entry));
}

void ProcessMonitor::stopAll()
{
    m_timer.stop();
    m_entries.clear();
}

void ProcessMonitor::poll()
{
    int alive = 0;
    for (auto& e : m_entries) {
        if (e.reported) continue;
        if (!e.sp.valid) continue;

        if (!SandboxEngine::isAlive(e.sp)) {
            DWORD exitCode = 0;
            if (e.sp.hProcess)
                GetExitCodeProcess(e.sp.hProcess, &exitCode);
            emit processExited(e.sp.pid, e.label, exitCode);
            e.reported = true;
        } else {
            ++alive;
        }
    }

    QString summary = QString("Tracked: %1  |  Alive: %2")
        .arg(static_cast<int>(m_entries.size()))
        .arg(alive);
    emit statusUpdate(summary);
}
