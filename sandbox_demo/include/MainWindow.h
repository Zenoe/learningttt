#pragma once
// ============================================================
//  MainWindow.h  –  Qt6 GUI
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

class HookIpcServer;
class SandboxFileExplorer;

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
    void onOpenBoxExplorer();
    void onKillSelected();
    void onKillAll();
    void onPolicyChanged();
    void onStatsTimer();
    void onFsRootChanged();
    void onHookLogReceived(quint32 processId, quint32 threadId,
                           const QString& message);
    void onShowInFolderRequested(quint32 processId, const QString& path);
    void onOpenSandboxFileRequested(const QString& path);
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
    bool hasOtherSandboxInBox(const std::wstring& boxName, DWORD exceptPid) const;
    void unregisterWfp(SandboxedProcess& sp);
    SandboxedProcess* findSandboxForPath(const QString& path);
    SandboxedProcess* findPassiveBox(const QString& boxName);
    QString boxDriveRoot(const SandboxedProcess& sp) const;
    QString chooseViewerExecutable(const QString& filePath) const;
    bool openConfiguredBoxVaultInExplorer();

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
    QLineEdit*   m_vaultDir      = nullptr;
    QLineEdit*   m_vaultSizeMb   = nullptr;
    QCheckBox*   m_chkQuickTest  = nullptr;
    QCheckBox*   m_chkPassphrase = nullptr;
    QLineEdit*   m_passphrase    = nullptr;
    QLineEdit*   m_extraArgs     = nullptr;
    QCheckBox*   m_chkRestrictUI = nullptr;
    QCheckBox*   m_chkKillOnClose= nullptr;
    QCheckBox*   m_chkWfpForce   = nullptr;
    QLineEdit*   m_wfpVnicIp     = nullptr;
    QComboBox*   m_cmbPolicy     = nullptr;
    QPushButton* m_btnBrowse     = nullptr;
    QPushButton* m_btnNormal     = nullptr;
    QPushButton* m_btnSandboxed  = nullptr;
    QPushButton* m_btnOpenExplorer = nullptr;
    QPushButton* m_btnKillSel    = nullptr;
    QPushButton* m_btnKillAll    = nullptr;

    // ---- Process list / log ----
    QTreeWidget*    m_processTree = nullptr;
    QPlainTextEdit* m_logView     = nullptr;
    QLabel*         m_statusBar   = nullptr;

    // ---- Engine / state ----
    SandboxEngine   m_engine;
    DriverManager   m_driver;
    VaultManager    m_explorerVault;
    ProcessMonitor* m_monitor    = nullptr;
    QTimer*         m_statsTimer = nullptr;
    QTimer*         m_borderTimer = nullptr;
    HookIpcServer*  m_hookIpc = nullptr;
    SandboxFileExplorer* m_fileExplorer = nullptr;

    std::vector<SandboxedProcess> m_normalProcs;
    std::vector<SandboxedProcess> m_sandboxProcs;
    std::vector<SandboxedProcess> m_passiveBoxSessions;
    std::vector<std::wstring> m_explorerMountedVaults;
};
