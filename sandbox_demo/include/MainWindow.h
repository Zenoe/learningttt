#pragma once
// ============================================================
//  MainWindow.h  –  Qt6 GUI
//  Changes vs original:
//    • Added #include "SandboxExplorer.h"
//    • Added m_explorer member
//    • Added onFsRootChanged() slot
// ============================================================
#include <QMainWindow>
#include <QTreeWidget>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QGroupBox>
#include <QCheckBox>
#include <QComboBox>
#include <QTabWidget>
#include <QTimer>
#include <vector>
#include "SandboxEngine.h"
#include "ProcessMonitor.h"
#include "DriverManager.h"
#include "SandboxExplorer.h"   // ← NEW

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

private slots:
    void onBrowseExe();
    void onBrowseSys();
    void onInstallDriver();
    void onLoadDriver();
    void onUnloadDriver();
    void onLaunchNormal();
    void onLaunchSandboxed();
    void onKillSelected();
    void onKillAll();
    void onPolicyChanged();
    void onStatsTimer();
    void onFsRootChanged();                                    // ← NEW
    void onProcessExited(DWORD pid, const QString& label, DWORD exitCode);
    void onStatusUpdate(const QString& summary);

private:
    void setupUi();
    void appendLog(const QString& msg);
    void addProcessRow(const SandboxedProcess& sp, bool sandboxed);
    void refreshProcessTreeFromDriver(const SANDBOX_PROCESS_LIST& list);
    void updateDriverStatus();
    void syncDriverPids(SandboxedProcess& sp);
    void unregisterDriverPids(SandboxedProcess& sp);
    void updateSandboxWindowBorders();
    bool isSandboxWindow(HWND hwnd, std::wstring* boxName = nullptr) const;

    // ---- Driver panel ----
    QLineEdit*   m_sysPath      = nullptr;
    QPushButton* m_btnBrowseSys = nullptr;
    QPushButton* m_btnInstall   = nullptr;
    QPushButton* m_btnLoad      = nullptr;
    QPushButton* m_btnUnload    = nullptr;
    QLabel*      m_driverStatus = nullptr;

    // ---- Stats panel ----
    QLabel* m_lblBoxes     = nullptr;
    QLabel* m_lblPids      = nullptr;
    QLabel* m_lblRedirects = nullptr;
    QLabel* m_lblBlocked   = nullptr;
    QLabel* m_lblLastPath  = nullptr;

    // ---- Launch panel ----
    QComboBox*   m_exePath       = nullptr;
    QLineEdit*   m_boxName       = nullptr;
    QLineEdit*   m_fsRoot        = nullptr;
    QLineEdit*   m_extraArgs     = nullptr;
    QCheckBox*   m_chkRestrictUI = nullptr;
    QCheckBox*   m_chkKillOnClose= nullptr;
    QComboBox*   m_cmbPolicy     = nullptr;
    QPushButton* m_btnBrowse     = nullptr;
    QPushButton* m_btnNormal     = nullptr;
    QPushButton* m_btnSandboxed  = nullptr;
    QPushButton* m_btnKillSel    = nullptr;
    QPushButton* m_btnKillAll    = nullptr;

    // ---- Process list / log ----
    QTreeWidget*    m_processTree = nullptr;
    QPlainTextEdit* m_logView     = nullptr;
    QLabel*         m_statusBar   = nullptr;

    // ---- Engine / state ----
    SandboxEngine   m_engine;
    DriverManager   m_driver;
    SandboxExplorer m_explorer;                                // ← NEW
    ProcessMonitor* m_monitor    = nullptr;
    QTimer*         m_statsTimer = nullptr;
    QTimer*         m_borderTimer = nullptr;

    std::vector<SandboxedProcess> m_normalProcs;
    std::vector<SandboxedProcess> m_sandboxProcs;
};
