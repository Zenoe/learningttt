// ============================================================
//  MainWindow.cpp  —  Full Qt6 GUI with driver panel
//
//  Includes the host-side HookDll IPC broker and custom file explorer.
// ============================================================
#include "MainWindow.h"
#include "DetourProcessLauncher.h"
#include "HookIpcServer.h"
#include "SandboxFileExplorer.h"
#include <QApplication>
#include <QByteArray>
#include <QCoreApplication>
#include <QFileDialog>
#include <QEventLoop>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QSplitter>
#include <QFont>
#include <QDateTime>
#include <QTabWidget>
#include <QFrame>
#include <QScrollBar>
#include <QDir>
#include <QFileInfo>
#include <QHeaderView>
#include <QTreeWidgetItemIterator>
#include <QMetaObject>
#include <QMessageBox>
#include <QStandardPaths>
#include <algorithm>
#include <filesystem>
#include <functional>
#include <unordered_map>
#include <shlwapi.h>

// ---- Helpers -----------------------------------------------
static QLabel* makeLabel(const QString& t) {
    auto* l = new QLabel(t);
    l->setStyleSheet("color:#8899aa;");
    return l;
}

static bool isChromiumExecutable(const QString& path)
{
    const QString lower = QFileInfo(path).fileName().toLower();
    return lower.contains(QStringLiteral("chrome")) ||
           lower.contains(QStringLiteral("msedge")) ||
           lower.contains(QStringLiteral("brave"));
}

static QString chromiumProfileDirName(const QString& path)
{
    const QString lower = QFileInfo(path).fileName().toLower();
    if (lower.contains(QStringLiteral("msedge")))
        return QStringLiteral("edge");
    if (lower.contains(QStringLiteral("brave")))
        return QStringLiteral("brave");
    return QStringLiteral("chrome");
}

static bool isConsoleExecutable(const QString& path)
{
    const QString name = QFileInfo(path).fileName().toLower();
    return name == QStringLiteral("cmd.exe") ||
           name == QStringLiteral("powershell.exe") ||
           name == QStringLiteral("pwsh.exe");
}

static QString cleanAbsolutePath(const QString& path)
{
    return QDir::cleanPath(QFileInfo(path).absoluteFilePath()).replace('/', '\\');
}

static bool pathIsSameOrChildOf(const QString& path, const QString& root)
{
    if (path.isEmpty() || root.isEmpty())
        return false;
    QString candidate = cleanAbsolutePath(path);
    QString cleanRoot = cleanAbsolutePath(root);
    if (!cleanRoot.endsWith('\\'))
        cleanRoot += '\\';
    return candidate.compare(cleanRoot.left(cleanRoot.size() - 1),
                             Qt::CaseInsensitive) == 0 ||
           candidate.startsWith(cleanRoot, Qt::CaseInsensitive);
}

static std::wstring withTrailingSlash(std::wstring path)
{
    if (!path.empty() && path.back() != L'\\' && path.back() != L'/')
        path.push_back(L'\\');
    return path;
}

static std::wstring queryNtDeviceForMountPoint(const std::wstring& mountPoint)
{
    wchar_t volumeName[MAX_PATH]{};
    const std::wstring mount = withTrailingSlash(mountPoint);
    if (!GetVolumeNameForVolumeMountPointW(mount.c_str(),
                                           volumeName,
                                           MAX_PATH)) {
        return {};
    }

    std::wstring dosName(volumeName);
    if (dosName.rfind(L"\\\\?\\", 0) == 0)
        dosName.erase(0, 4);
    while (!dosName.empty() && dosName.back() == L'\\')
        dosName.pop_back();

    wchar_t deviceName[1024]{};
    if (!QueryDosDeviceW(dosName.c_str(), deviceName, 1024))
        return {};

    return deviceName;
}

static QLineEdit* makeEdit(const QString& ph, const QFont& f) {
    auto* e = new QLineEdit;
    e->setPlaceholderText(ph);
    e->setFont(f);
    e->setStyleSheet(
        "QLineEdit{background:#0e0e16;color:#d8d8e8;"
        "border:1px solid #2a2a3a;border-radius:3px;padding:3px 6px;}"
        "QLineEdit:focus{border-color:#0af;}");
    return e;
}

 static QComboBox * makeCombo(const QFont & f) {
    auto* c = new QComboBox;
    c->setEditable(true);
    c->setFont(f);
    c->setStyleSheet(
        "QComboBox{background:#0e0e16;color:#d8d8e8;border:1px solid #2a2a3a;"
         "border-radius:3px;padding:2px 6px;}"
         "QComboBox:focus{border-color:#0af;}"
         "QComboBox QAbstractItemView{background:#15151f;color:#ccc;}");
    return c;
    
}


static QPushButton* makeBtn(const QString& t, const QString& col,
                             int minH = 30) {
    auto* b = new QPushButton(t);
    b->setMinimumHeight(minH);
    b->setStyleSheet(QString(
        "QPushButton{background:%1;color:#fff;border:none;"
        "border-radius:4px;font-weight:bold;padding:0 14px;}"
        "QPushButton:hover{background:%1cc;}"
        "QPushButton:disabled{background:#252535;color:#555;}").arg(col));
    return b;
}

static QLabel* makeStatLabel() {
    auto* l = new QLabel("—");
    l->setStyleSheet("color:#00cc88;font-weight:bold;font-family:Consolas;");
    return l;
}

// ---- Host-side Sandboxie-style border overlay ----------------
// This catches UI windows in sandboxed child processes too.  The injected
// DLL is still useful for in-process hooks, but the host can reliably identify
// sandbox windows by Job membership.
static constexpr wchar_t kHostBorderClass[] = L"SandboxDemo_HostBorder";
static constexpr COLORREF kTransparentKey = RGB(255, 0, 255);
static constexpr COLORREF kSandboxYellow = RGB(255, 210, 0);
static constexpr int kBorderThickness = 4;

struct HostBorderEntry {
    HWND target = nullptr;
    HWND overlay = nullptr;
    bool hoverWindow = false;
    bool moving = false;
};

static std::vector<HostBorderEntry> g_hostBorders;
static HWINEVENTHOOK g_hostMoveHook = nullptr;

static LRESULT CALLBACK HostBorderWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_PAINT:
    {
        PAINTSTRUCT ps{};
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc{};
        GetClientRect(hwnd, &rc);

        HBRUSH transparent = CreateSolidBrush(kTransparentKey);
        FillRect(hdc, &rc, transparent);
        DeleteObject(transparent);

        HBRUSH yellow = CreateSolidBrush(kSandboxYellow);
        RECT top{ 0, 0, rc.right, kBorderThickness };
        RECT bottom{ 0, rc.bottom - kBorderThickness, rc.right, rc.bottom };
        RECT left{ 0, kBorderThickness, kBorderThickness, rc.bottom - kBorderThickness };
        RECT right{ rc.right - kBorderThickness, kBorderThickness, rc.right, rc.bottom - kBorderThickness };
        FillRect(hdc, &top, yellow);
        FillRect(hdc, &bottom, yellow);
        FillRect(hdc, &left, yellow);
        FillRect(hdc, &right, yellow);
        DeleteObject(yellow);

        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_NCHITTEST:
        return HTTRANSPARENT;
    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

static void RegisterHostBorderClass()
{
    static bool registered = false;
    if (registered) return;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = HostBorderWndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = kHostBorderClass;
    registered = RegisterClassExW(&wc) != 0 ||
        GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

static HWND FindHostBorder(HWND target)
{
    for (const auto& entry : g_hostBorders)
        if (entry.target == target)
            return entry.overlay;
    return nullptr;
}

static HostBorderEntry* FindHostBorderEntry(HWND target)
{
    for (auto& entry : g_hostBorders)
        if (entry.target == target)
            return &entry;
    return nullptr;
}

static bool IsHostCaptionHit(LRESULT hit)
{
    return hit == HTCAPTION || hit == HTSYSMENU || hit == HTMINBUTTON ||
        hit == HTMAXBUTTON || hit == HTCLOSE || hit == HTHELP;
}

static bool IsCursorOverHostWindow(HWND target)
{
    if (!IsWindow(target) || !IsWindowVisible(target) || IsIconic(target))
        return false;

    POINT pt{};
    if (!GetCursorPos(&pt))
        return false;

    RECT rc{};
    if (!GetWindowRect(target, &rc) || !PtInRect(&rc, pt))
        return false;

    DWORD_PTR hit = 0;
    if (!SendMessageTimeoutW(target, WM_NCHITTEST, 0,
        MAKELPARAM(pt.x, pt.y),
        SMTO_ABORTIFHUNG | SMTO_BLOCK,
        25,
        &hit)) {
        return false;
        
    }
    
	return IsHostCaptionHit((LRESULT)hit);

    //return true;
}


static void RepositionHostBorder(HWND overlay, HWND target, bool show)
{
    if (!IsWindow(overlay) || !IsWindow(target)) return;

    if (!show || !IsWindowVisible(target) || IsIconic(target)) {
        ShowWindow(overlay, SW_HIDE);
        return;
    }

    RECT rc{};
    GetWindowRect(target, &rc);
    SetWindowPos(overlay, HWND_TOPMOST,
        rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
        SWP_NOACTIVATE | SWP_SHOWWINDOW);
    InvalidateRect(overlay, nullptr, FALSE);
}

static void SyncHostBorder(HostBorderEntry& entry)
{
    entry.hoverWindow = IsCursorOverHostWindow(entry.target);
    RepositionHostBorder(entry.overlay, entry.target,
        entry.hoverWindow || entry.moving);
}

static void RefreshHostBorderVisibility()
{
    for (auto& entry : g_hostBorders)
        SyncHostBorder(entry);
}

static void CALLBACK HostBorderWinEventProc(
    HWINEVENTHOOK,
    DWORD event,
    HWND hwnd,
    LONG idObject,
    LONG,
    DWORD,
    DWORD)
{
    if (idObject != OBJID_WINDOW || !hwnd)
        return;

    auto* entry = FindHostBorderEntry(hwnd);
    if (!entry)
        return;

    switch (event) {
    case EVENT_SYSTEM_MOVESIZESTART:
        entry->moving = true;
        SyncHostBorder(*entry);
        break;
    case EVENT_SYSTEM_MOVESIZEEND:
        entry->moving = false;
        SyncHostBorder(*entry);
        break;
    case EVENT_OBJECT_LOCATIONCHANGE:
        if (entry->moving || entry->hoverWindow)
            SyncHostBorder(*entry);
        break;
    case EVENT_OBJECT_HIDE:
    case EVENT_OBJECT_DESTROY:
        ShowWindow(entry->overlay, SW_HIDE);
        break;
    }
}

static void StartHostBorderHooks()
{
    if (g_hostMoveHook)
        return;

    g_hostMoveHook = SetWinEventHook(
        EVENT_SYSTEM_MOVESIZESTART,
        EVENT_OBJECT_LOCATIONCHANGE,
        nullptr,
        HostBorderWinEventProc,
        0,
        0,
        WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
}

static void StopHostBorderHooks()
{
    if (g_hostMoveHook) {
        UnhookWinEvent(g_hostMoveHook);
        g_hostMoveHook = nullptr;
    }
}

static HWND EnsureHostBorder(HWND target)
{
    HWND overlay = FindHostBorder(target);
    if (overlay) {
        if (auto* entry = FindHostBorderEntry(target))
            SyncHostBorder(*entry);
        return overlay;
    }

    RegisterHostBorderClass();
    RECT rc{};
    GetWindowRect(target, &rc);
    overlay = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST |
        WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
        kHostBorderClass,
        L"",
        WS_POPUP,
        rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
        nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!overlay)
        return nullptr;

    SetLayeredWindowAttributes(overlay, kTransparentKey, 0, LWA_COLORKEY);
    g_hostBorders.push_back({ target, overlay });
    ShowWindow(overlay, SW_HIDE);
    SyncHostBorder(g_hostBorders.back());
    return overlay;
}


static void PrefixHostWindowTitle(HWND hwnd, const std::wstring& boxName)
{
    if (!(GetWindowLongW(hwnd, GWL_STYLE) & WS_CAPTION)) return;

    wchar_t title[512]{};
    GetWindowTextW(hwnd, title, 512);
    if (wcsncmp(title, L"[Sandbox:", 9) == 0)
        return;

    wchar_t newTitle[640]{};
    swprintf_s(newTitle, L"[Sandbox: %s] %s", boxName.c_str(), title);
    SetWindowTextW(hwnd, newTitle);
}

// ============================================================
MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , m_engine([this](const std::wstring& m) {
        const QString text = QString::fromStdWString(m);
        QMetaObject::invokeMethod(this, [this, text] { appendLog(text); },
            Qt::QueuedConnection);
    })
    , m_driver([this](const std::wstring& m) {
        const QString text = QString::fromStdWString(m);
        QMetaObject::invokeMethod(this, [this, text] { appendLog(text); },
            Qt::QueuedConnection);
    })
    , m_monitor(new ProcessMonitor(this))
    , m_statsTimer(new QTimer(this))
    , m_borderTimer(new QTimer(this))
{
    setWindowTitle("SandboxFlt Demo  —  Minifilter + Job Object + Namespace Isolation");
    setMinimumSize(1100, 750);

    // Dark palette
    QPalette p;
    p.setColor(QPalette::Window,        QColor(0x13,0x13,0x1c));
    p.setColor(QPalette::WindowText,    QColor(0xd5,0xd5,0xe5));
    p.setColor(QPalette::Base,          QColor(0x0c,0x0c,0x14));
    p.setColor(QPalette::AlternateBase, QColor(0x18,0x18,0x22));
    p.setColor(QPalette::Text,          QColor(0xcc,0xcc,0xdc));
    p.setColor(QPalette::Button,        QColor(0x20,0x20,0x2c));
    p.setColor(QPalette::ButtonText,    QColor(0xe0,0xe0,0xf0));
    p.setColor(QPalette::Highlight,     QColor(0x00,0xaa,0xff));
    p.setColor(QPalette::HighlightedText, Qt::white);
    QApplication::setPalette(p);

    setupUi();

    m_fileExplorer = new SandboxFileExplorer(this);
    connect(m_fileExplorer, &SandboxFileExplorer::openRequested,
            this, &MainWindow::onOpenSandboxFileRequested);
    m_hookIpc = new HookIpcServer(this);
    connect(m_hookIpc, &HookIpcServer::hookLogReceived,
            this, &MainWindow::onHookLogReceived, Qt::QueuedConnection);
    connect(m_hookIpc, &HookIpcServer::showInFolderRequested,
            this, &MainWindow::onShowInFolderRequested, Qt::QueuedConnection);
    connect(m_hookIpc, &HookIpcServer::serverError,
            this, [this](const QString& error) {
                appendLog(QStringLiteral("  [Hook IPC] ERROR: ") + error);
            }, Qt::QueuedConnection);

    connect(m_monitor,    &ProcessMonitor::processExited, this, &MainWindow::onProcessExited);
    connect(m_monitor,    &ProcessMonitor::statusUpdate,  this, &MainWindow::onStatusUpdate);
    connect(m_statsTimer, &QTimer::timeout,               this, &MainWindow::onStatsTimer);
    connect(m_borderTimer, &QTimer::timeout, this, [] {
        RefreshHostBorderVisibility();
    });
    m_statsTimer->start(1500);
    m_borderTimer->start(33);
    StartHostBorderHooks();

    appendLog("=== SandboxFlt Demo ===");
    appendLog("Step 1: Browse to SandboxFlt.sys → Install → Load");
    appendLog("Step 2: Browse to an EXE → Launch Sandboxed");
    appendLog("Step 3: Watch the driver redirect file I/O in the Stats panel");
    updateDriverStatus();

    appendLog(m_hookIpc->isListening()
        ? "  [Hook IPC] Named-pipe broker is listening."
        : "  [Hook IPC] Failed to start named-pipe broker.");
}

MainWindow::~MainWindow()
{
    if (m_hookIpc)
        m_hookIpc->stop();
    m_borderTimer->stop();
    m_statsTimer->stop();
    m_monitor->stopAll();
    StopHostBorderHooks();
    for (auto& entry : g_hostBorders) {
        if (IsWindow(entry.overlay))
            DestroyWindow(entry.overlay);
    }
    g_hostBorders.clear();
    for (auto& sp : m_sandboxProcs) {
        if (sp.valid && !sp.hJob && sp.hProcess)
            TerminateProcess(sp.hProcess, 0);
        unregisterDriverPids(sp);
        m_engine.release(sp);
    }
    for (auto& sp : m_passiveBoxSessions) {
        if (m_driver.isLoaded()) {
            m_driver.clearCryptoKey(sp.boxName);
            m_driver.removeBox(sp.boxName);
        }
        m_engine.release(sp);
    }
    for (auto& sp : m_normalProcs)  m_engine.release(sp);
    for (const std::wstring& vaultPath : m_explorerMountedVaults)
        m_explorerVault.unmount(vaultPath, nullptr);
}

// ============================================================
//  setupUi
// ============================================================
void MainWindow::setupUi()
{
    QFont mono("Consolas", 9);
    auto* central     = new QWidget(this);
    setCentralWidget(central);
    auto* rootLayout  = new QVBoxLayout(central);
    rootLayout->setContentsMargins(8,8,8,8);
    rootLayout->setSpacing(6);

    auto groupStyle = [](const QString& col) {
        return QString(
            "QGroupBox{font-weight:bold;color:%1;border:1px solid #252535;"
            "border-radius:4px;margin-top:8px;padding-top:8px;}"
            "QGroupBox::title{subcontrol-origin:margin;left:10px;}").arg(col);
    };

    // ================================================================
    //  ROW 1 — Driver panel  +  Stats panel
    // ================================================================
    auto* row1 = new QHBoxLayout;

    // ---- Driver panel ------------------------------------------
    auto* drvGroup = new QGroupBox("① Driver  (SandboxFlt.sys)", central);
    drvGroup->setStyleSheet(groupStyle("#ff9900"));
    auto* drvGrid  = new QGridLayout(drvGroup);
    drvGrid->setSpacing(5);

    m_sysPath      = makeEdit("Path to SandboxFlt.sys", mono);
    m_sysPath->setText(QString::fromStdWString(DriverManager::defaultSysPath()));
    m_btnBrowseSys = makeBtn("…", "#334", 26); m_btnBrowseSys->setFixedWidth(30);
    m_btnInstall   = makeBtn("Install", "#5544aa", 28);
    m_btnLoad      = makeBtn("Load",    "#226622", 28);
    m_btnUnload    = makeBtn("Unload",  "#882222", 28);
    m_driverStatus = new QLabel("● Not loaded");
    m_driverStatus->setStyleSheet("color:#ff4444;font-family:Consolas;font-weight:bold;");

    drvGrid->addWidget(makeLabel(".sys path:"), 0, 0);
    drvGrid->addWidget(m_sysPath,      0, 1);
    drvGrid->addWidget(m_btnBrowseSys, 0, 2);

    auto* drvBtnRow = new QHBoxLayout;
    drvBtnRow->addWidget(m_btnInstall);
    drvBtnRow->addWidget(m_btnLoad);
    drvBtnRow->addWidget(m_btnUnload);
    drvBtnRow->addStretch();
    drvBtnRow->addWidget(m_driverStatus);
    drvGrid->addLayout(drvBtnRow, 1, 0, 1, 3);

    // ---- Stats panel -------------------------------------------
    auto* statsGroup = new QGroupBox("② Live Driver Statistics", central);
    statsGroup->setStyleSheet(groupStyle("#00bbff"));
    auto* statsGrid  = new QGridLayout(statsGroup);
    statsGrid->setSpacing(4);

    m_lblBoxes     = makeStatLabel();
    m_lblPids      = makeStatLabel();
    m_lblRedirects = makeStatLabel();
    m_lblBlocked   = makeStatLabel();
    m_lblLastPath  = makeStatLabel();
    m_lblLastPath->setFont(mono);
    m_lblLastPath->setWordWrap(true);

    statsGrid->addWidget(makeLabel("Boxes:"),     0, 0);
    statsGrid->addWidget(m_lblBoxes,              0, 1);
    statsGrid->addWidget(makeLabel("PIDs:"),       0, 2);
    statsGrid->addWidget(m_lblPids,               0, 3);
    statsGrid->addWidget(makeLabel("Redirects:"), 1, 0);
    statsGrid->addWidget(m_lblRedirects,          1, 1);
    statsGrid->addWidget(makeLabel("Blocked:"),   1, 2);
    statsGrid->addWidget(m_lblBlocked,            1, 3);
    statsGrid->addWidget(makeLabel("Last path:"), 2, 0);
    statsGrid->addWidget(m_lblLastPath,           2, 1, 1, 3);

    row1->addWidget(drvGroup,   3);
    row1->addWidget(statsGroup, 4);
    rootLayout->addLayout(row1);

    // ================================================================
    //  ROW 2 — Launch configuration
    // ================================================================
    auto* cfgGroup = new QGroupBox("③ Launch Configuration", central);
    cfgGroup->setStyleSheet(groupStyle("#00dd77"));
    auto* cfgGrid  = new QGridLayout(cfgGroup);
    cfgGrid->setSpacing(5);

    //m_exePath   = makeEdit("C:\\Windows\\notepad.exe", mono);
    //m_exePath->setText("C:\\Windows\\notepad.exe");
    m_exePath = makeCombo(mono);
    m_exePath->addItems({
    "C:\\Program Files(x86)\\Microsoft\\Edge\\Application\\msedge.exe",
	"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Windows\\notepad.exe",
    "C:\\Users\\admin\\AppData\\Local\\Kingsoft\\WPS Office\\ksolaunch.exe",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
    "C:\\Windows\\System32\\cmd.exe"
     });

    m_boxName   = makeEdit("Box00", mono);
    m_boxName->setText("Box00");
    m_fsRoot    = makeEdit("C:\\SandboxMounts", mono);
    m_fsRoot->setText("C:\\SandboxMounts");
    m_vaultDir = makeEdit("C:\\SandboxBoxes", mono);
    m_vaultDir->setText("C:\\SandboxBoxes");
    m_vaultSizeMb = makeEdit("512", mono);
    m_vaultSizeMb->setText("512");
    m_vaultSizeMb->setFixedWidth(100);
    m_chkQuickTest = new QCheckBox("quickTest");
    m_chkQuickTest->setChecked(true);
    m_chkPassphrase = new QCheckBox("Use BitLocker passphrase");
    m_passphrase = makeEdit("(optional)", mono);
    m_passphrase->setEchoMode(QLineEdit::Password);
    m_passphrase->setEnabled(false);
    m_extraArgs = makeEdit("(optional extra arguments)", mono);

    m_btnBrowse = makeBtn("…", "#334", 26); m_btnBrowse->setFixedWidth(30);

    cfgGrid->addWidget(makeLabel("Executable:"), 0, 0);
    cfgGrid->addWidget(m_exePath,   0, 1); cfgGrid->addWidget(m_btnBrowse, 0, 2);
    cfgGrid->addWidget(makeLabel("Box Name:"),   1, 0);
    cfgGrid->addWidget(m_boxName,   1, 1);
    cfgGrid->addWidget(makeLabel("Mount Dir:"),  2, 0);
    cfgGrid->addWidget(m_fsRoot,    2, 1);
    cfgGrid->addWidget(makeLabel("Vault Dir:"),  3, 0);
    cfgGrid->addWidget(m_vaultDir,  3, 1);
    cfgGrid->addWidget(makeLabel("Vault Size:"), 4, 0);
    auto* vaultRow = new QHBoxLayout;
    vaultRow->addWidget(m_vaultSizeMb);
    vaultRow->addWidget(makeLabel("MB"));
    vaultRow->addSpacing(20);
    vaultRow->addWidget(m_chkQuickTest);
    vaultRow->addSpacing(20);
    vaultRow->addWidget(m_chkPassphrase);
    vaultRow->addWidget(m_passphrase, 1);
    cfgGrid->addLayout(vaultRow, 4, 1);
    cfgGrid->addWidget(makeLabel("Extra Args:"), 5, 0);
    cfgGrid->addWidget(m_extraArgs, 5, 1);

    // Options row
    auto* optRow = new QHBoxLayout;
    m_chkRestrictUI  = new QCheckBox("Restrict UI (Job UILimits)");
    m_chkKillOnClose = new QCheckBox("Kill-on-Close (Job)");
    m_chkWfpForce = new QCheckBox("Force network via vNIC (WFP)");
    m_chkRestrictUI->setChecked(true);
    m_chkKillOnClose->setChecked(true);
    QString cbStyle = "QCheckBox{color:#aab;}"
                      "QCheckBox::indicator:checked{background:#0af;}";
    m_chkQuickTest->setStyleSheet(cbStyle);
    m_chkPassphrase->setStyleSheet(cbStyle);
    m_chkRestrictUI->setStyleSheet(cbStyle);
    m_chkKillOnClose->setStyleSheet(cbStyle);
    m_chkWfpForce->setStyleSheet(cbStyle);

    auto* policyLabel = makeLabel("Write policy:");
    m_cmbPolicy = new QComboBox;
    m_cmbPolicy->addItems({"Redirect (copy-on-write)", "Block writes", "Pass-through"});
    m_cmbPolicy->setStyleSheet(
        "QComboBox{background:#0e0e16;color:#d8d8e8;border:1px solid #2a2a3a;"
        "border-radius:3px;padding:2px 6px;}"
        "QComboBox QAbstractItemView{background:#15151f;color:#ccc;}");

    auto* wfpLabel = makeLabel("vNIC IP:");
    m_wfpVnicIp = makeEdit("10.8.0.4", mono);
    m_wfpVnicIp->setText("10.8.0.4");
    m_wfpVnicIp->setFixedWidth(120);
    m_wfpVnicIp->setEnabled(false);

    optRow->addWidget(m_chkRestrictUI);
    optRow->addWidget(m_chkKillOnClose);
    optRow->addSpacing(20);
    optRow->addWidget(policyLabel);
    optRow->addWidget(m_cmbPolicy);
    optRow->addSpacing(20);
    optRow->addWidget(m_chkWfpForce);
    optRow->addWidget(wfpLabel);
    optRow->addWidget(m_wfpVnicIp);
    optRow->addStretch();
    cfgGrid->addLayout(optRow, 6, 0, 1, 3);

    // Launch buttons
    m_btnNormal    = makeBtn("▶  Launch Normal", "#1a4a88");
    m_btnSandboxed = makeBtn("⬡  Launch Sandboxed", "#0a6634");
    m_btnOpenExplorer = makeBtn("▣  Open Box Explorer", "#335577");
    m_btnKillSel   = makeBtn("✕  Kill Selected", "#773300");
    m_btnKillAll   = makeBtn("✕✕ Kill All",      "#550011");

    auto* launchRow = new QHBoxLayout;
    launchRow->addWidget(m_btnNormal);
    launchRow->addWidget(m_btnSandboxed);
    launchRow->addWidget(m_btnOpenExplorer);
    launchRow->addStretch();
    launchRow->addWidget(m_btnKillSel);
    launchRow->addWidget(m_btnKillAll);
    cfgGrid->addLayout(launchRow, 7, 0, 1, 3);

    rootLayout->addWidget(cfgGroup);

    // ================================================================
    //  ROW 3 — Process list | Log (splitter)
    // ================================================================
    auto* splitter = new QSplitter(Qt::Horizontal, central);

    auto* listGroup = new QGroupBox("④ Running Processes", splitter);
    listGroup->setStyleSheet(groupStyle("#aaaacc"));
    auto* listLay   = new QVBoxLayout(listGroup);
    m_processTree   = new QTreeWidget;
    m_processTree->setFont(mono);
    m_processTree->setColumnCount(5);
    m_processTree->setHeaderLabels({ "PID", "Box", "Parent", "Root", "Mode" });
    m_processTree->setAlternatingRowColors(true);
    m_processTree->setRootIsDecorated(true);
    m_processTree->setUniformRowHeights(true);
    m_processTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_processTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_processTree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_processTree->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_processTree->header()->setSectionResizeMode(4, QHeaderView::Stretch);
    m_processTree->setStyleSheet(
        "QTreeWidget{background:#0a0a12;color:#ccc;border:none;}"
        "QTreeWidget::item{padding:3px 6px;}"
        "QTreeWidget::item:selected{background:#003366;}"
        "QTreeWidget::item:alternate{background:#0d0d18;}"
        "QHeaderView::section{background:#10101a;color:#9aa;border:none;padding:4px 6px;}");
    listLay->addWidget(m_processTree);

    auto* logGroup = new QGroupBox("⑤ Engine Log", splitter);
    logGroup->setStyleSheet(groupStyle("#aaaacc"));
    auto* logLay   = new QVBoxLayout(logGroup);
    m_logView      = new QPlainTextEdit;
    m_logView->setReadOnly(true);
    m_logView->setFont(mono);
    m_logView->setMaximumBlockCount(3000);
    m_logView->setStyleSheet(
        "QPlainTextEdit{background:#070710;color:#00cc66;border:none;}");
    logLay->addWidget(m_logView);

    splitter->addWidget(listGroup);
    splitter->addWidget(logGroup);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 3);
    splitter->setStyleSheet("QSplitter::handle{background:#222;width:2px;}");
    rootLayout->addWidget(splitter, 1);

    // ---- Status bar ----
    m_statusBar = new QLabel("Ready.");
    m_statusBar->setFont(mono);
    m_statusBar->setStyleSheet(
        "QLabel{color:#666;background:#0a0a12;padding:3px 8px;"
        "border-top:1px solid #1a1a28;}");
    rootLayout->addWidget(m_statusBar);

    // ---- Connections ----
    connect(m_btnBrowseSys, &QPushButton::clicked, this, &MainWindow::onBrowseSys);
    connect(m_btnInstall,   &QPushButton::clicked, this, &MainWindow::onInstallDriver);
    connect(m_btnLoad,      &QPushButton::clicked, this, &MainWindow::onLoadDriver);
    connect(m_btnUnload,    &QPushButton::clicked, this, &MainWindow::onUnloadDriver);
    connect(m_btnBrowse,    &QPushButton::clicked, this, &MainWindow::onBrowseExe);
    connect(m_btnNormal,    &QPushButton::clicked, this, &MainWindow::onLaunchNormal);
    connect(m_btnSandboxed, &QPushButton::clicked, this, &MainWindow::onLaunchSandboxed);
    connect(m_btnOpenExplorer, &QPushButton::clicked, this, &MainWindow::onOpenBoxExplorer);
    connect(m_btnKillSel,   &QPushButton::clicked, this, &MainWindow::onKillSelected);
    connect(m_btnKillAll,   &QPushButton::clicked, this, &MainWindow::onKillAll);
    connect(m_cmbPolicy,    QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onPolicyChanged);
    connect(m_chkWfpForce, &QCheckBox::toggled,
            m_wfpVnicIp, &QLineEdit::setEnabled);
    connect(m_chkPassphrase, &QCheckBox::toggled,
            m_passphrase, &QLineEdit::setEnabled);
    connect(m_chkQuickTest, &QCheckBox::toggled, this, [this](bool checked) {
        m_vaultDir->setEnabled(!checked);
        m_vaultSizeMb->setEnabled(!checked);
        m_chkPassphrase->setEnabled(!checked);
        m_passphrase->setEnabled(!checked && m_chkPassphrase->isChecked());
        m_chkWfpForce->setEnabled(!checked);
        m_wfpVnicIp->setEnabled(!checked && m_chkWfpForce->isChecked());
        m_cmbPolicy->setEnabled(!checked);
    });
    m_vaultDir->setEnabled(!m_chkQuickTest->isChecked());
    m_vaultSizeMb->setEnabled(!m_chkQuickTest->isChecked());
    m_chkPassphrase->setEnabled(!m_chkQuickTest->isChecked());
    m_passphrase->setEnabled(!m_chkQuickTest->isChecked() &&
                             m_chkPassphrase->isChecked());
    m_chkWfpForce->setEnabled(!m_chkQuickTest->isChecked());
    m_wfpVnicIp->setEnabled(!m_chkQuickTest->isChecked() &&
                            m_chkWfpForce->isChecked());
    m_cmbPolicy->setEnabled(!m_chkQuickTest->isChecked());
    // ── NEW: restart pipe server if FS root changes
    connect(m_fsRoot, &QLineEdit::editingFinished,
            this, &MainWindow::onFsRootChanged);
}

// ============================================================
//  Driver lifecycle slots
// ============================================================
void MainWindow::onBrowseSys()
{
    QString p = QFileDialog::getOpenFileName(this, "Select SandboxFlt.sys",
        QString(), "Kernel Driver (*.sys)");
    if (!p.isEmpty())
        m_sysPath->setText(QDir::toNativeSeparators(p));
}

void MainWindow::onInstallDriver()
{
    if (!DriverManager::isElevated()) {
        appendLog("! Must run as Administrator to install driver.");
        return;
    }
    std::wstring path = m_sysPath->text().toStdWString();
    appendLog("--- Installing SandboxFlt.sys ---");
    bool ok = m_driver.install(path);
    updateDriverStatus();
    appendLog(ok ? "  Install OK." : "  Install FAILED — check log.");
}

void MainWindow::onLoadDriver()
{
    appendLog("--- Loading SandboxFlt driver ---");
    bool ok = m_driver.load();
    if (ok) ok = m_driver.open();
    updateDriverStatus();
    appendLog(ok ? "  Driver loaded and control device open."
                 : "  Load FAILED.");
}

void MainWindow::onUnloadDriver()
{
    appendLog("--- Unloading driver ---");
    m_driver.unload(false);
    updateDriverStatus();
}

void MainWindow::updateDriverStatus()
{
    if (m_driver.isLoaded()) {
        m_driverStatus->setText("● Loaded");
        m_driverStatus->setStyleSheet(
            "color:#00dd66;font-family:Consolas;font-weight:bold;");
    } else if (m_driver.isInstalled()) {
        m_driverStatus->setText("● Installed (not loaded)");
        m_driverStatus->setStyleSheet(
            "color:#ffaa00;font-family:Consolas;font-weight:bold;");
    } else {
        m_driverStatus->setText("● Not installed");
        m_driverStatus->setStyleSheet(
            "color:#ff4444;font-family:Consolas;font-weight:bold;");
    }
}

// ============================================================
//  Stats timer
// ============================================================
void MainWindow::onStatsTimer()
{
    updateSandboxWindowBorders();

    if (m_driver.isLoaded()) {
        SANDBOX_STATS st{};
        if (m_driver.queryStats(st)) {
            m_lblBoxes->setText(QString::number(st.TotalBoxes));
            m_lblPids->setText(QString::number(st.TotalTrackedPids));
            m_lblRedirects->setText(QString::number(st.TotalRedirects));
            m_lblBlocked->setText(QString::number(st.TotalBlocked));
            QString lp = QString::fromWCharArray(st.LastRedirectedPath);
            m_lblLastPath->setText(lp.isEmpty() ? "—" : lp);
        }

        SANDBOX_PROCESS_LIST processes{};
        if (m_driver.queryProcesses(processes))
            refreshProcessTreeFromDriver(processes);
    }
}

// ============================================================
//  Launch slots
// ============================================================
void MainWindow::onBrowseExe()
{
    QString p = QFileDialog::getOpenFileName(this, "Select Executable",
        "C:\\Windows", "Executables (*.exe);;All (*.*)");
    if (!p.isEmpty())
        m_exePath->setEditText(QDir::toNativeSeparators(p));
}

void MainWindow::onLaunchNormal()
{
    QString exe = m_exePath->currentText().trimmed();
    if (exe.isEmpty()) { appendLog("! No executable."); return; }
    appendLog("--- Launch NORMAL: " + exe + " ---");

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"" + exe.toStdWString() + L"\"";
    const QString extraArguments = m_extraArgs->text().trimmed();
    if (!extraArguments.isEmpty())
        cmd += L" " + extraArguments.toStdWString();

    const bool isChromium = isChromiumExecutable(exe);
    BOOL launched = FALSE;
    DWORD launchError = ERROR_SUCCESS;
    if (isChromium) {
        if (!m_hookIpc || !m_hookIpc->isListening()) {
            appendLog("! Hook IPC broker is not listening; normal Chrome launch aborted.");
            return;
        }

        const QString hookDll = QDir(QCoreApplication::applicationDirPath())
                                    .filePath(QStringLiteral("HookDll.dll"));
        const QByteArray hookDllA = QDir::toNativeSeparators(hookDll).toLocal8Bit();
        if (!QFileInfo::exists(hookDll) || hookDllA.isEmpty() ||
            GetFileAttributesA(hookDllA.constData()) == INVALID_FILE_ATTRIBUTES) {
            appendLog("! HookDll.dll not found or its path is not ANSI-safe: " + hookDll);
            return;
        }

        const QString profile = QDir(QDir::tempPath()).filePath(
            QStringLiteral("SandboxDemo/Profile/%1")
                .arg(chromiumProfileDirName(exe)));
        if (!QDir().mkpath(profile)) {
            appendLog("! Failed to create isolated normal browser profile: " + profile);
            return;
        }
        cmd += L" --user-data-dir=\"" +
               QDir::toNativeSeparators(profile).toStdWString() + L"\"";
        cmd += L" --no-first-run --no-default-browser-check";

        QString downloads = QStandardPaths::writableLocation(
            QStandardPaths::DownloadLocation);
        if (downloads.isEmpty())
            downloads = QDir::home().filePath(QStringLiteral("Downloads"));
        const std::wstring downloadsW =
            QDir::toNativeSeparators(downloads).toStdWString();

        const bool hadPreviousDownloads =
            qEnvironmentVariableIsSet("SANDBOX_DOWNLOADS");
        const std::wstring previousDownloads =
            qEnvironmentVariable("SANDBOX_DOWNLOADS").toStdWString();
        SetEnvironmentVariableW(L"SANDBOX_DOWNLOADS", downloadsW.c_str());

        const std::wstring executable = QDir::toNativeSeparators(exe).toStdWString();
        bool usedInteractiveToken = false;
        launched = DetourCreateProcessWithDllForInteractiveUser(
            executable.c_str(), cmd.data(), nullptr, nullptr, FALSE,
            CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi,
            hookDllA.constData(), &usedInteractiveToken);
        launchError = GetLastError();

        if (hadPreviousDownloads)
            SetEnvironmentVariableW(L"SANDBOX_DOWNLOADS", previousDownloads.c_str());
        else
            SetEnvironmentVariableW(L"SANDBOX_DOWNLOADS", nullptr);

        appendLog("  [HookDll] Detours payload: " +
                  QDir::toNativeSeparators(hookDll));
        if (usedInteractiveToken) {
            appendLog("  [Browser] Elevated host: launched with interactive medium-integrity token.");
        }
        appendLog("  [Browser] Isolated normal profile: " +
                  QDir::toNativeSeparators(profile));
    } else {
        launched = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr,
                                  FALSE, CREATE_NEW_CONSOLE,
                                  nullptr, nullptr, &si, &pi);
        launchError = GetLastError();
    }

    if (launched) {
        SandboxedProcess sp;
        sp.pid = pi.dwProcessId; sp.hProcess = pi.hProcess;
        sp.hThread = pi.hThread; sp.boxName = L"(normal)"; sp.valid = true;
        addProcessRow(sp, false);
        m_normalProcs.push_back(sp);
        m_monitor->track(sp, QString("Normal PID %1").arg(sp.pid));
        appendLog(QString("  PID %1 running (no sandbox%2)")
                      .arg(sp.pid)
                      .arg(isChromium ? ", HookDll injected" : ""));
    } else {
        appendLog(QString("! CreateProcess failed: %1").arg(launchError));
    }
}

void MainWindow::onLaunchSandboxed()
{
    QString exe = m_exePath->currentText().trimmed();
    if (exe.isEmpty()) { appendLog("! No executable."); return; }
    const bool isChromium = isChromiumExecutable(exe);

    //const QString exeName = QFileInfo(exe).fileName().toLower();
    //const bool isConsoleShell = exeName == "cmd.exe" ||
    //    +exeName == "powershell.exe" ||
    //    +exeName == "pwsh.exe";

    QString uniqueBox = m_boxName->text().trimmed();
    if (uniqueBox.isEmpty()) uniqueBox = "Box00";

    QString mountDir = m_fsRoot->text().trimmed();
    if (mountDir.isEmpty()) mountDir = "C:\\SandboxMounts";
    const bool quickTest = m_chkQuickTest->isChecked();
    QString vaultDir = m_vaultDir->text().trimmed();
    if (vaultDir.isEmpty()) vaultDir = "C:\\SandboxBoxes";
    bool sizeOk = false;
    uint64_t vaultSizeMb = m_vaultSizeMb->text().trimmed().toULongLong(&sizeOk);
    if (!quickTest && (!sizeOk || vaultSizeMb < 64)) {
        appendLog("! Vault size must be at least 64 MB.");
        return;
    }
    if (!quickTest && !DriverManager::isElevated()) {
        appendLog("! Vault-backed sandbox launch requires Administrator privileges.");
        appendLog("  CreateVirtualDisk/AttachVirtualDisk cannot run from a non-elevated process.");
        return;
    }

    appendLog("--- Launch SANDBOXED box=\"" + uniqueBox + "\" ---");
    if (quickTest) {
        appendLog("  [quickTest] Fast clipboard test mode: skipping driver, vault, BitLocker, WFP, and minifilter setup.");
    }
    else if (!m_driver.isLoaded()) {
        appendLog("  [!] Driver not loaded — FS redirection via driver DISABLED.");
        appendLog("      Job Object + namespace isolation still active.");
    }

    // ---- Launch via SandboxEngine (Job + Namespace) ----
    SandboxConfig cfg;
    cfg.boxName        = uniqueBox.toStdWString();
    cfg.executablePath = exe.toStdWString();
    cfg.commandLine    = m_extraArgs->text().toStdWString();
    cfg.fsRootBase     = (quickTest
        ? QDir(mountDir).filePath(QStringLiteral("_quickTest")).toStdWString()
        : mountDir.toStdWString());
    cfg.useVault       = !quickTest;
    cfg.vaultDir       = vaultDir.toStdWString();
    cfg.mountDir       = (quickTest
        ? mountDir.toStdWString()
        : QDir(mountDir).filePath(QStringLiteral("_vault")).toStdWString());
    cfg.vaultSizeMB    = vaultSizeMb;
    if (isChromium) {
        if (!m_hookIpc || !m_hookIpc->isListening()) {
            appendLog("! Hook IPC broker is not listening; sandboxed Chrome launch aborted.");
            return;
        }
        const QString hookDll = QDir(QCoreApplication::applicationDirPath())
                                    .filePath(QStringLiteral("HookDll.dll"));
        if (!QFileInfo::exists(hookDll)) {
            appendLog("! HookDll.dll not found next to SandboxDemo.exe: " + hookDll);
            appendLog("  Sandboxed Chrome launch aborted because Explorer suppression would be unavailable.");
            return;
        }
        cfg.borderDllPath = QDir::toNativeSeparators(hookDll).toStdWString();
        appendLog("  [HookDll] Detours payload: " + QDir::toNativeSeparators(hookDll));
    }
    cfg.restrictUI     = m_chkRestrictUI->isChecked() && !isChromium;
    cfg.killOnClose    = m_chkKillOnClose->isChecked();
    if (isChromium && m_chkRestrictUI->isChecked()) {
        appendLog("  [Chrome] Job UI limits disabled for Chromium compatibility.");
        appendLog("  [Chrome] Using --no-sandbox because the outer sandbox owns containment.");
    }

    SandboxedProcess* passiveBox = findPassiveBox(uniqueBox);
    const bool reusePassiveBox = !quickTest && passiveBox && passiveBox->valid &&
        passiveBox->hJob && !passiveBox->fsRoot.empty();

    SandboxedProcess sp;
    if (reusePassiveBox) {
        appendLog("  [Explorer] Reusing mounted passive box session.");
        cfg.useVault = false;
        sp = m_engine.launchInExistingBox(cfg,
                                          passiveBox->hJob,
                                          passiveBox->fsRoot);
        sp.vaultFilePath = passiveBox->vaultFilePath;
        sp.vaultMountPoint = passiveBox->vaultMountPoint;
        sp.mountPointNt = passiveBox->mountPointNt;
    }
    else {
        cfg.passphrase = m_chkPassphrase->isChecked()
            ? m_passphrase->text().toStdWString()
            : std::wstring();
        sp = m_engine.launch(cfg);
        SecureZeroMemory(cfg.passphrase.data(),
            cfg.passphrase.size() * sizeof(wchar_t));
        cfg.passphrase.clear();
    }
    if (!sp.valid) {
        appendLog("! Process launch failed.");
        return;
    }

    if (!reusePassiveBox && !sp.bitLockerRecoveryPassword.empty()) {
        QMessageBox recoveryBox(QMessageBox::Warning,
            "BitLocker recovery password",
            "A new BitLocker vault was created. Save its recovery password "
            "offline before continuing.",
            QMessageBox::Ok,
            this);
        recoveryBox.setInformativeText(
            "Open ‘Show Details’, copy the 48-digit password, and keep it "
            "separate from the .vault file. It will not be logged or shown again.");
        recoveryBox.setDetailedText(
            QString::fromStdWString(sp.bitLockerRecoveryPassword));
        recoveryBox.exec();
        SecureZeroMemory(sp.bitLockerRecoveryPassword.data(),
            sp.bitLockerRecoveryPassword.size() * sizeof(wchar_t));
        sp.bitLockerRecoveryPassword.clear();
    }

    // ---- Register the mounted vault root and crypto context with the driver. ----
    bool driverOk = false;
    if (reusePassiveBox) {
        driverOk = m_driver.isLoaded();
        if (!driverOk) {
            appendLog("! Passive box is open but SandboxFlt driver is not loaded; terminating suspended process.");
            m_engine.release(sp);
            return;
        }
    }
    else if (!quickTest && m_driver.isLoaded()) {
        QString sandboxRoot = QString::fromStdWString(sp.fsRoot + L"\\drive");
        QString sandboxVolRelative = sandboxRoot;
        if (sandboxVolRelative.length() >= 2 && sandboxVolRelative[1] == ':')
            sandboxVolRelative = sandboxVolRelative.mid(2);
        sandboxVolRelative = sandboxVolRelative.replace('/', '\\');
        if (!sandboxVolRelative.startsWith('\\'))
            sandboxVolRelative.prepend('\\');

        driverOk = m_driver.addBox(uniqueBox.toStdWString(),
                                    sandboxVolRelative.toStdWString(),
                                    L"\\");
        if (driverOk) {
            int pol = m_cmbPolicy->currentIndex();
            m_driver.setPolicy(uniqueBox.toStdWString(),
                               (SANDBOX_WRITE_POLICY)pol, true, false);
            if (!sp.mountPointNt.empty())
                driverOk = m_driver.setMountPoint(uniqueBox.toStdWString(),
                                                  sp.mountPointNt);
            // Vault contents are protected by BitLocker.  The minifilter keeps
            // access control/redirection only; do not layer custom file crypto.
        }

        if (!driverOk) {
            appendLog("! Driver box/vault registration failed; terminating suspended process.");
            if (!hasOtherSandboxInBox(uniqueBox.toStdWString(), sp.pid)) {
                m_driver.clearCryptoKey(uniqueBox.toStdWString());
                m_driver.removeBox(uniqueBox.toStdWString());
            }
            m_engine.release(sp);
            return;
        }
    }

    // ---- Tell the driver about the new PID ----
    if (driverOk) {
        bool pidOk = m_driver.addProcess(sp.pid, uniqueBox.toStdWString());
        appendLog(pidOk
            ? QString("  [Driver] PID %1 registered → box '%2'")
                .arg(sp.pid).arg(uniqueBox)
            : QString("  [Driver] addProcess failed for PID %1")
                .arg(sp.pid));
        if (!pidOk) {
            appendLog("! Driver PID registration failed; terminating suspended process.");
            if (!hasOtherSandboxInBox(uniqueBox.toStdWString(), sp.pid)) {
                m_driver.clearCryptoKey(uniqueBox.toStdWString());
                m_driver.removeBox(uniqueBox.toStdWString());
            }
            m_engine.release(sp);
            return;
        }
        sp.driverRegistered = true;
    }

    // ---- Optional WFP source-IP forcing.  Must be registered before resume
    //      so child processes (Chrome Network Service, etc.) inherit the rule
    //      before their first bind().
    if (!quickTest && m_chkWfpForce->isChecked()) {
        ULONG vnicIp = 0;
        std::wstring ipText = m_wfpVnicIp->text().trimmed().toStdWString();
        if (!DriverManager::parseIpv4(ipText, vnicIp)) {
            appendLog("! Invalid WFP vNIC IP: " + m_wfpVnicIp->text());
            if (driverOk) {
                m_driver.removeProcess(sp.pid);
                if (!hasOtherSandboxInBox(sp.boxName, sp.pid)) {
                    m_driver.clearCryptoKey(sp.boxName);
                    m_driver.removeBox(uniqueBox.toStdWString());
                }
            }
            m_engine.release(sp);
            return;
        }

        if (!driverOk) {
            appendLog("! WFP source-IP forcing requires SandboxFlt driver registration.");
            m_engine.release(sp);
            return;
        }

        if (!m_driver.setWfpPolicy(sp.pid, uniqueBox.toStdWString(), vnicIp, true)) {
            appendLog("! SandboxFlt WFP policy registration failed; terminating suspended process.");
            if (driverOk) {
                m_driver.removeProcess(sp.pid);
                if (!hasOtherSandboxInBox(sp.boxName, sp.pid)) {
                    m_driver.clearCryptoKey(sp.boxName);
                    m_driver.removeBox(uniqueBox.toStdWString());
                }
            }
            m_engine.release(sp);
            return;
        }

        sp.wfpEnabled = true;
        sp.wfpVnicIp = vnicIp;
        appendLog(QString("  [WFP] PID %1 registered for vNIC %2")
            .arg(sp.pid)
            .arg(QString::fromStdWString(DriverManager::formatIpv4(vnicIp))));
    }

    if (!cfg.borderDllPath.empty()) {
        appendLog(QString("  [HookDll] Detours injected payload into suspended PID %1")
                      .arg(sp.pid));
    }

    if (!m_engine.resume(sp)) {
        appendLog("! Failed to resume sandboxed process.");
        unregisterWfp(sp);
        if (driverOk) {
            m_driver.removeProcess(sp.pid);
            if (!hasOtherSandboxInBox(sp.boxName, sp.pid)) {
                m_driver.clearCryptoKey(sp.boxName);
                m_driver.removeBox(uniqueBox.toStdWString());
            }
        }
        m_engine.release(sp);
        return;
    }

    appendLog("  Job limits: " +
        QString::fromStdWString(SandboxEngine::describeJob(sp.hJob)));

    if (driverOk) {
        SANDBOX_PROCESS_LIST processes{};
        if (m_driver.queryProcesses(processes))
            refreshProcessTreeFromDriver(processes);
        else
            addProcessRow(sp, true);
    }
    else {
        addProcessRow(sp, true);
    }
    m_sandboxProcs.push_back(sp);
    m_monitor->track(sp, QString("Sandboxed[%1] PID %2")
                         .arg(uniqueBox).arg(sp.pid));
}

void MainWindow::onOpenBoxExplorer()
{
    SandboxedProcess* target = nullptr;

    if (auto* item = m_processTree->currentItem()) {
        if (item->data(0, Qt::UserRole + 1).toBool()) {
            const QString selectedBox = item->text(1);
            for (auto& sp : m_sandboxProcs) {
                if (!sp.valid)
                    continue;
                if (QString::fromStdWString(sp.boxName)
                        .compare(selectedBox, Qt::CaseInsensitive) == 0) {
                    target = &sp;
                    break;
                }
            }
        }
    }

    if (!target) {
        QString configuredBox = m_boxName->text().trimmed();
        if (configuredBox.isEmpty())
            configuredBox = QStringLiteral("Box00");
        for (auto& sp : m_sandboxProcs) {
            if (!sp.valid)
                continue;
            if (QString::fromStdWString(sp.boxName)
                    .compare(configuredBox, Qt::CaseInsensitive) == 0) {
                target = &sp;
                break;
            }
        }
    }

    if (!target) {
        int activeCount = 0;
        for (auto& sp : m_sandboxProcs) {
            if (!sp.valid)
                continue;
            target = &sp;
            ++activeCount;
        }
        if (activeCount > 1) {
            appendLog("! Select a sandbox process row before opening Box Explorer.");
            return;
        }
    }

    if (!target) {
        QString configuredBox = m_boxName->text().trimmed();
        if (configuredBox.isEmpty())
            configuredBox = QStringLiteral("Box00");
        if (auto* passive = findPassiveBox(configuredBox)) {
            target = passive;
        }
    }

    if (!target) {
        openConfiguredBoxVaultInExplorer();
        return;
    }

    const QString root = boxDriveRoot(*target);
    if (!QDir(root).exists()) {
        appendLog("! Box Explorer root not found: " + QDir::toNativeSeparators(root));
        return;
    }

    appendLog(QString("  [Explorer] Opening box '%1': %2")
                  .arg(QString::fromStdWString(target->boxName),
                       QDir::toNativeSeparators(root)));
    if (m_fileExplorer) {
        m_fileExplorer->showForPath(root,
            QString::fromStdWString(target->boxName),
            root);
    }
}

bool MainWindow::openConfiguredBoxVaultInExplorer()
{
    QString boxName = m_boxName->text().trimmed();
    if (boxName.isEmpty())
        boxName = QStringLiteral("Box00");

    if (auto* passive = findPassiveBox(boxName)) {
        const QString root = boxDriveRoot(*passive);
        if (m_fileExplorer)
            m_fileExplorer->showForPath(root, boxName, root);
        return true;
    }

    if (m_chkQuickTest->isChecked()) {
        QString mountDir = m_fsRoot->text().trimmed();
        if (mountDir.isEmpty())
            mountDir = QStringLiteral("C:\\SandboxMounts");
        const QString root = QDir::toNativeSeparators(
            QDir(mountDir).filePath(QStringLiteral("_quickTest\\") +
                                    boxName +
                                    QStringLiteral("\\drive")));
        QDir().mkpath(root);
        appendLog(QString("  [quickTest] Opening directory-backed box '%1': %2")
                      .arg(boxName, root));
        if (m_fileExplorer)
            m_fileExplorer->showForPath(root, boxName, root);
        return true;
    }

    QString vaultDir = m_vaultDir->text().trimmed();
    if (vaultDir.isEmpty())
        vaultDir = QStringLiteral("C:\\SandboxBoxes");

    QString mountDir = m_fsRoot->text().trimmed();
    if (mountDir.isEmpty())
        mountDir = QStringLiteral("C:\\SandboxMounts");

    const QString vaultPath = QDir(vaultDir).filePath(boxName + QStringLiteral(".vault"));
    if (!QFileInfo::exists(vaultPath)) {
        appendLog("! Box vault not found: " + QDir::toNativeSeparators(vaultPath));
        return false;
    }

    if (!m_driver.isLoaded()) {
        appendLog("! Opening files from a default box requires the SandboxFlt driver to be loaded.");
        appendLog("  Load the driver first so viewer PIDs can be registered before resume.");
        return false;
    }

    if (!DriverManager::isElevated()) {
        appendLog("! Opening a box vault directly requires Administrator privileges.");
        appendLog("  AttachVirtualDisk and BitLocker unlock cannot run from a non-elevated process.");
        return false;
    }

    VaultManager::VaultConfig cfg;
    cfg.boxName = boxName.toStdWString();
    cfg.vaultFilePath = QDir::toNativeSeparators(vaultPath).toStdWString();
    cfg.mountPoint = QDir::toNativeSeparators(
        QDir(mountDir).filePath(QStringLiteral("_vault\\") + boxName))
            .toStdWString();
    cfg.passphrase = m_chkPassphrase->isChecked()
        ? m_passphrase->text().toStdWString()
        : std::wstring();

    appendLog(QString("  [Explorer] Mounting box vault '%1': %2")
                  .arg(boxName, QDir::toNativeSeparators(vaultPath)));
    const std::wstring mounted = m_explorerVault.mount(cfg,
        [this](const std::wstring& message) {
            appendLog(QString::fromStdWString(message));
        });
    SecureZeroMemory(cfg.passphrase.data(),
        cfg.passphrase.size() * sizeof(wchar_t));
    cfg.passphrase.clear();

    if (mounted.empty()) {
        appendLog("! Failed to mount box vault for browsing.");
        return false;
    }

    const QString driveRoot = QDir::toNativeSeparators(
        QDir(QString::fromStdWString(mounted)).filePath(QStringLiteral("drive")));
    const QString explorerRoot = QDir(driveRoot).exists()
        ? driveRoot
        : QDir::toNativeSeparators(QString::fromStdWString(mounted));

    SandboxConfig sessionCfg;
    sessionCfg.boxName = boxName.toStdWString();
    sessionCfg.restrictUI = true;
    sessionCfg.killOnClose = false;
    SandboxedProcess session =
        m_engine.createBoxSession(sessionCfg, mounted);
    if (!session.valid) {
        appendLog("! Failed to create passive box job for mounted vault.");
        m_explorerVault.unmount(cfg.vaultFilePath, nullptr);
        return false;
    }
    session.vaultFilePath = cfg.vaultFilePath;
    session.vaultMountPoint = mounted;
    session.mountPointNt = queryNtDeviceForMountPoint(mounted);
    if (session.mountPointNt.empty()) {
        appendLog("! Failed to resolve vault mount NT device path.");
        m_engine.release(session);
        m_explorerVault.unmount(cfg.vaultFilePath, nullptr);
        return false;
    }

    QString sandboxRoot = QDir::toNativeSeparators(explorerRoot);
    QString sandboxVolRelative = sandboxRoot;
    if (sandboxVolRelative.length() >= 2 && sandboxVolRelative[1] == ':')
        sandboxVolRelative = sandboxVolRelative.mid(2);
    sandboxVolRelative = sandboxVolRelative.replace('/', '\\');
    if (!sandboxVolRelative.startsWith('\\'))
        sandboxVolRelative.prepend('\\');

    bool driverOk = m_driver.addBox(session.boxName,
                                    sandboxVolRelative.toStdWString(),
                                    L"\\");
    if (driverOk) {
        const int pol = m_cmbPolicy->currentIndex();
        m_driver.setPolicy(session.boxName,
                           (SANDBOX_WRITE_POLICY)pol,
                           true,
                           false);
        driverOk = m_driver.setMountPoint(session.boxName,
                                          session.mountPointNt);
    }
    if (!driverOk) {
        appendLog("! Failed to register passive box with SandboxFlt driver.");
        m_driver.clearCryptoKey(session.boxName);
        m_driver.removeBox(session.boxName);
        m_engine.release(session);
        m_explorerVault.unmount(cfg.vaultFilePath, nullptr);
        return false;
    }

    m_explorerMountedVaults.push_back(cfg.vaultFilePath);
    m_passiveBoxSessions.push_back(session);

    appendLog(QString("  [Explorer] Opening mounted vault '%1': %2")
                  .arg(boxName, explorerRoot));
    if (m_fileExplorer)
        m_fileExplorer->showForPath(explorerRoot, boxName, explorerRoot);
    return true;
}

void MainWindow::onKillSelected()
{
    auto* item = m_processTree->currentItem();
    if (!item) { appendLog("! Nothing selected."); return; }
    DWORD pid = item->data(0, Qt::UserRole).toUInt();
    bool sandboxed = item->data(0, Qt::UserRole + 1).toBool();
    appendLog(QString("--- Kill PID %1 ---").arg(pid));

    for (auto& sp : m_sandboxProcs) {
        if (sp.pid == pid && sp.valid) {
            if (!sp.hJob && sp.hProcess)
                TerminateProcess(sp.hProcess, 0);
            unregisterDriverPids(sp);
            m_engine.release(sp);
            item->setText(4, item->text(4) + " [killed]");
            for (int c = 0; c < m_processTree->columnCount(); ++c)
                item->setForeground(c, QColor(0xff,0x44,0x44));
            return;
        }
    }
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (h) { TerminateProcess(h,0); CloseHandle(h); }
    if (sandboxed)
        m_driver.removeProcess(pid);
    item->setText(4, item->text(4) + " [killed]");
    for (int c = 0; c < m_processTree->columnCount(); ++c)
        item->setForeground(c, QColor(0xff,0x44,0x44));
}

void MainWindow::onKillAll()
{
    appendLog("--- Kill All ---");
    m_monitor->stopAll();
    for (auto& sp : m_sandboxProcs) {
        if (sp.valid) {
            if (!sp.hJob && sp.hProcess)
                TerminateProcess(sp.hProcess, 0);
            unregisterDriverPids(sp);
            m_engine.release(sp);
        }
    }
    m_sandboxProcs.clear();
    for (auto& sp : m_passiveBoxSessions) {
        if (sp.valid) {
            if (m_driver.isLoaded()) {
                m_driver.clearCryptoKey(sp.boxName);
                m_driver.removeBox(sp.boxName);
            }
            m_engine.release(sp);
        }
    }
    m_passiveBoxSessions.clear();
    for (const std::wstring& vaultPath : m_explorerMountedVaults)
        m_explorerVault.unmount(vaultPath, nullptr);
    m_explorerMountedVaults.clear();
    for (auto& sp : m_normalProcs) {
        if (sp.hProcess) {
            TerminateProcess(sp.hProcess, 0);
            CloseHandle(sp.hProcess);
            CloseHandle(sp.hThread);
        }
    }
    m_normalProcs.clear();
    m_processTree->clear();
    appendLog("  All processes terminated, boxes unregistered.");
}

void MainWindow::onPolicyChanged()
{
    if (!m_driver.isLoaded()) return;
    int pol = m_cmbPolicy->currentIndex();
    for (auto& sp : m_sandboxProcs) {
        if (sp.valid)
            m_driver.setPolicy(sp.boxName, (SANDBOX_WRITE_POLICY)pol, true, false);
    }
    for (auto& sp : m_passiveBoxSessions) {
        if (sp.valid)
            m_driver.setPolicy(sp.boxName, (SANDBOX_WRITE_POLICY)pol, true, false);
    }
}

void MainWindow::unregisterWfp(SandboxedProcess& sp)
{
    if (!sp.wfpEnabled)
        return;

    if (m_driver.isLoaded())
        m_driver.setWfpPolicy(sp.pid, sp.boxName, 0, false);
    sp.wfpEnabled = false;
    sp.wfpVnicIp = 0;
}

bool MainWindow::hasOtherSandboxInBox(const std::wstring& boxName,
                                      DWORD exceptPid) const
{
    for (const auto& other : m_sandboxProcs) {
        if (!other.valid)
            continue;
        if (other.pid == exceptPid)
            continue;
        if (other.boxName == boxName)
            return true;
    }
    for (const auto& other : m_passiveBoxSessions) {
        if (other.valid && other.boxName == boxName)
            return true;
    }
    return false;
}

void MainWindow::syncDriverPids(SandboxedProcess& sp)
{
    if (!m_driver.isLoaded() || !sp.valid)
        return;
    for (DWORD pid : sp.driverPids) {
        if (m_driver.addProcess(pid, sp.boxName))
            sp.driverRegistered = true;
    }
}

void MainWindow::unregisterDriverPids(SandboxedProcess& sp)
{
    unregisterWfp(sp);
    const bool lastInBox = !hasOtherSandboxInBox(sp.boxName, sp.pid);
    if (lastInBox && m_fileExplorer && !sp.vaultMountPoint.empty()) {
        m_fileExplorer->releasePath(
            QString::fromStdWString(sp.vaultMountPoint));
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    }
    if (!m_driver.isLoaded() || !sp.driverRegistered)
        return;

    m_driver.removeProcess(sp.pid);
    for (DWORD pid : sp.driverPids) {
        if (pid != sp.pid)
            m_driver.removeProcess(pid);
    }

    if (lastInBox) {
        m_driver.clearCryptoKey(sp.boxName);
        m_driver.removeBox(sp.boxName);
    }
}

void MainWindow::onFsRootChanged()
{
    appendLog("  [Sandbox] Mount root changed: " + m_fsRoot->text());
}

SandboxedProcess* MainWindow::findSandboxForPath(const QString& path)
{
    for (auto& sp : m_sandboxProcs) {
        if (!sp.valid || sp.fsRoot.empty())
            continue;

        const QString fsRoot = QString::fromStdWString(sp.fsRoot);
        if (pathIsSameOrChildOf(path, fsRoot) ||
            pathIsSameOrChildOf(path, boxDriveRoot(sp))) {
            return &sp;
        }
    }
    for (auto& sp : m_passiveBoxSessions) {
        if (!sp.valid || sp.fsRoot.empty())
            continue;

        const QString fsRoot = QString::fromStdWString(sp.fsRoot);
        if (pathIsSameOrChildOf(path, fsRoot) ||
            pathIsSameOrChildOf(path, boxDriveRoot(sp))) {
            return &sp;
        }
    }
    return nullptr;
}

SandboxedProcess* MainWindow::findPassiveBox(const QString& boxName)
{
    for (auto& sp : m_passiveBoxSessions) {
        if (!sp.valid)
            continue;
        if (QString::fromStdWString(sp.boxName)
                .compare(boxName, Qt::CaseInsensitive) == 0) {
            return &sp;
        }
    }
    return nullptr;
}

QString MainWindow::boxDriveRoot(const SandboxedProcess& sp) const
{
    const QString fsRoot = QString::fromStdWString(sp.fsRoot);
    const QString driveRoot = QDir(fsRoot).filePath(QStringLiteral("drive"));
    return QDir(driveRoot).exists() ? QDir::toNativeSeparators(driveRoot)
                                    : QDir::toNativeSeparators(fsRoot);
}

QString MainWindow::chooseViewerExecutable(const QString& filePath) const
{
    auto usableViewer = [](const QString& path) {
        const QFileInfo info(path);
        const QString name = info.fileName().toLower();
        return info.exists() && info.isFile() &&
               !isConsoleExecutable(info.absoluteFilePath()) &&
               name != QStringLiteral("explorer.exe");
    };

    const QString suffix = QFileInfo(filePath).suffix();
    if (!suffix.isEmpty()) {
        const std::wstring association = L"." + suffix.toStdWString();
        DWORD chars = 0;
        HRESULT hr = AssocQueryStringW(
            ASSOCF_VERIFY | ASSOCF_NOTRUNCATE,
            ASSOCSTR_EXECUTABLE,
            association.c_str(),
            L"open",
            nullptr,
            &chars);
        if (hr == S_FALSE && chars > 1) {
            std::wstring buffer(chars, L'\0');
            hr = AssocQueryStringW(
                ASSOCF_VERIFY | ASSOCF_NOTRUNCATE,
                ASSOCSTR_EXECUTABLE,
                association.c_str(),
                L"open",
                buffer.data(),
                &chars);
            if (SUCCEEDED(hr)) {
                while (!buffer.empty() && buffer.back() == L'\0')
                    buffer.pop_back();
                const QString associated =
                    QDir::toNativeSeparators(QString::fromStdWString(buffer));
                if (usableViewer(associated))
                    return associated;
            }
        }
    }

    const QString configured =
        QDir::toNativeSeparators(m_exePath->currentText().trimmed());
    if (usableViewer(configured))
        return configured;

    wchar_t systemDirectory[MAX_PATH]{};
    if (GetSystemDirectoryW(systemDirectory, MAX_PATH)) {
        const QString notepad = QDir(QString::fromWCharArray(systemDirectory))
            .filePath(QStringLiteral("notepad.exe"));
        if (usableViewer(notepad))
            return QDir::toNativeSeparators(notepad);
    }

    return {};
}

void MainWindow::onHookLogReceived(quint32 processId, quint32 threadId,
                                   const QString& message)
{
    appendLog(QStringLiteral("  [HookDll pid=%1 tid=%2] %3")
                  .arg(processId)
                  .arg(threadId)
                  .arg(message));
}

void MainWindow::onShowInFolderRequested(quint32 processId, const QString& path)
{
    appendLog(QStringLiteral("  [HookDll pid=%1] Show in folder intercepted: %2")
                  .arg(processId)
                  .arg(QDir::toNativeSeparators(path)));
    SandboxedProcess* sp = findSandboxForPath(path);
    if (!sp) {
        appendLog("  [Explorer] Request ignored: path is not under an active box.");
        return;
    }
    if (m_fileExplorer) {
        m_fileExplorer->showForPath(path,
            QString::fromStdWString(sp->boxName),
            boxDriveRoot(*sp));
    }
}

void MainWindow::onOpenSandboxFileRequested(const QString& path)
{
    const QFileInfo fileInfo(path);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        appendLog("! Open blocked: selected item is not a file.");
        return;
    }

    SandboxedProcess* owner = findSandboxForPath(fileInfo.absoluteFilePath());
    if (!owner || !owner->valid || !owner->hJob) {
        appendLog("! Open blocked: file is not under an active sandbox job.");
        return;
    }
    if (!m_driver.isLoaded()) {
        appendLog("! Open blocked: SandboxFlt driver must be loaded so the viewer PID can be registered before resume.");
        return;
    }

    const QString viewer = chooseViewerExecutable(fileInfo.absoluteFilePath());
    if (viewer.isEmpty()) {
        appendLog("! Open blocked: no safe viewer executable was found.");
        return;
    }

    SandboxConfig cfg;
    cfg.boxName = owner->boxName;
    cfg.executablePath = viewer.toStdWString();
    cfg.commandLine = L"\"" + QDir::toNativeSeparators(fileInfo.absoluteFilePath()).toStdWString() + L"\"";
    cfg.useVault = false;
    cfg.restrictUI = false;
    cfg.killOnClose = false;

    if (isChromiumExecutable(viewer)) {
        const QString hookDll = QDir(QCoreApplication::applicationDirPath())
            .filePath(QStringLiteral("HookDll.dll"));
        if (QFileInfo::exists(hookDll)) {
            cfg.borderDllPath = QDir::toNativeSeparators(hookDll).toStdWString();
        }
    }

    appendLog(QString("  [Explorer] Open inside box '%1': %2")
                  .arg(QString::fromStdWString(owner->boxName),
                       QDir::toNativeSeparators(fileInfo.absoluteFilePath())));
    appendLog(QString("  [Explorer] Viewer: %1")
                  .arg(QDir::toNativeSeparators(viewer)));

    SandboxedProcess viewerProcess =
        m_engine.launchInExistingBox(cfg, owner->hJob, owner->fsRoot);
    if (!viewerProcess.valid) {
        appendLog("! Open failed: viewer process was not created.");
        return;
    }

    bool registered = m_driver.addProcess(viewerProcess.pid, owner->boxName);
    const bool pidRegistered = registered;
    if (registered && owner->wfpEnabled) {
        registered = m_driver.setWfpPolicy(viewerProcess.pid,
                                           owner->boxName,
                                           owner->wfpVnicIp,
                                           true);
    }
    if (!registered) {
        appendLog("! Open failed: viewer PID registration failed; terminating suspended viewer.");
        if (pidRegistered)
            m_driver.removeProcess(viewerProcess.pid);
        if (viewerProcess.hProcess)
            TerminateProcess(viewerProcess.hProcess, 1);
        if (viewerProcess.hThread)
            CloseHandle(viewerProcess.hThread);
        if (viewerProcess.hProcess)
            CloseHandle(viewerProcess.hProcess);
        return;
    }

    if (!m_engine.resume(viewerProcess)) {
        appendLog("! Open failed: viewer process could not be resumed.");
        m_driver.removeProcess(viewerProcess.pid);
        if (viewerProcess.hProcess)
            TerminateProcess(viewerProcess.hProcess, 1);
        if (viewerProcess.hThread)
            CloseHandle(viewerProcess.hThread);
        if (viewerProcess.hProcess)
            CloseHandle(viewerProcess.hProcess);
        return;
    }

    if (viewerProcess.hThread)
        CloseHandle(viewerProcess.hThread);
    if (viewerProcess.hProcess)
        CloseHandle(viewerProcess.hProcess);

    SANDBOX_PROCESS_LIST processes{};
    if (m_driver.queryProcesses(processes))
        refreshProcessTreeFromDriver(processes);
}

bool MainWindow::isSandboxWindow(HWND hwnd, std::wstring* boxName) const
{
    if (!hwnd || !IsWindow(hwnd)) return false;
    if (!IsWindowVisible(hwnd) || IsIconic(hwnd)) return false;
    if (GetAncestor(hwnd, GA_ROOT) != hwnd) return false;

    LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
    LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    //if (!(style & WS_CAPTION)) return false;
    if (style & WS_CHILD) return false;
    if (exStyle & WS_EX_TOOLWINDOW) return false;

    RECT rc{};
    if (!GetWindowRect(hwnd, &rc)) return false;
    if (rc.right - rc.left < 160 || rc.bottom - rc.top < 100) return false;

    wchar_t cls[64]{};
    GetClassNameW(hwnd, cls, 64);
    if (wcscmp(cls, kHostBorderClass) == 0)
        return false;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0 || pid == GetCurrentProcessId())
        return false;

    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc)
        return false;

    bool matched = false;
    auto matchJob = [&](const SandboxedProcess& sp) {
        if (!sp.valid || !sp.hJob)
            return false;

        BOOL inJob = FALSE;
        if (IsProcessInJob(proc, sp.hJob, &inJob) && inJob) {
            if (boxName)
                *boxName = sp.boxName;
            return true;
        }
        return false;
        };

    for (const auto& sp : m_sandboxProcs) {
        if (matchJob(sp)) {
            matched = true;
            break;
        }
    }
    if (!matched) {
        for (const auto& sp : m_passiveBoxSessions) {
            if (matchJob(sp)) {
                matched = true;
                break;
            }
        }
    }

    CloseHandle(proc);
    return matched;
}


void MainWindow::updateSandboxWindowBorders()
{
    struct EnumCtx {
        MainWindow* self;
        std::vector<HWND> seen;
    } ctx{ this, {} };

    EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
        auto* ctx = reinterpret_cast<EnumCtx*>(lp);
        std::wstring box;
        if (ctx->self->isSandboxWindow(hwnd, &box)) {
            PrefixHostWindowTitle(hwnd, box);
            EnsureHostBorder(hwnd);
            ctx->seen.push_back(hwnd);
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&ctx));

    auto it = g_hostBorders.begin();
    while (it != g_hostBorders.end()) {
        bool stillSeen = std::find(ctx.seen.begin(), ctx.seen.end(),
            it->target) != ctx.seen.end();
        if (!stillSeen || !IsWindow(it->target)) {
            if (IsWindow(it->overlay))
                DestroyWindow(it->overlay);
            it = g_hostBorders.erase(it);
        }
        else {
            SyncHostBorder(*it);
            ++it;
        }
    }
}

// ============================================================
//  Monitor callbacks
// ============================================================
void MainWindow::onProcessExited(DWORD pid, const QString& label, DWORD code)
{
    appendLog(QString("  [EXIT] %1  code=%2").arg(label).arg(code));

    for (auto& sp : m_sandboxProcs) {
        if (sp.pid == pid && sp.valid) {
            unregisterDriverPids(sp);
            m_engine.release(sp);
            break;
        }
    }

    for (auto& sp : m_normalProcs) {
        if (sp.pid == pid && sp.valid) {
            m_engine.release(sp);
            break;
        }
    }

    QTreeWidgetItemIterator it(m_processTree);
    while (*it) {
        auto* row = *it;
        if (row->data(0, Qt::UserRole).toUInt() == pid) {
            row->setText(4, row->text(4) + QString(" [exit %1]").arg(code));
            for (int c = 0; c < m_processTree->columnCount(); ++c)
                row->setForeground(c, QColor(0x77,0x77,0x77));
        }
        ++it;
    }
}

void MainWindow::onStatusUpdate(const QString& s) { m_statusBar->setText(s); }

// ============================================================
//  Helpers
// ============================================================
void MainWindow::appendLog(const QString& msg)
{
    QString ts = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");
    m_logView->appendPlainText("[" + ts + "] " + msg);
    auto* sb = m_logView->verticalScrollBar();
    if (sb) sb->setValue(sb->maximum());
}

void MainWindow::addProcessRow(const SandboxedProcess& sp, bool sandboxed)
{
    QString icon = sandboxed ? "⬡" : "▶";
    QString box  = sandboxed ? QString::fromStdWString(sp.boxName) : "(none)";
    QString mode = sandboxed ? icon + " Sandbox root" : icon + " Unsandboxed";
    if (sandboxed && sp.wfpEnabled) {
        mode += " | WFP " +
            QString::fromStdWString(DriverManager::formatIpv4(sp.wfpVnicIp));
    }

    auto* item = new QTreeWidgetItem({
        QString::number(sp.pid),
        box,
        sandboxed ? "0" : "—",
        sandboxed ? QString::number(sp.pid) : "—",
        mode
    });
    item->setData(0, Qt::UserRole, static_cast<uint>(sp.pid));
    item->setData(0, Qt::UserRole + 1, sandboxed);

    QColor color = sandboxed ? QColor(0x00,0xcc,0x66)
                             : QColor(0x55,0xaa,0xff);
    for (int c = 0; c < m_processTree->columnCount(); ++c)
        item->setForeground(c, color);

    m_processTree->addTopLevelItem(item);
    m_processTree->scrollToItem(item);
}

void MainWindow::refreshProcessTreeFromDriver(const SANDBOX_PROCESS_LIST& list)
{
    for (int i = m_processTree->topLevelItemCount() - 1; i >= 0; --i) {
        auto* item = m_processTree->topLevelItem(i);
        if (item->data(0, Qt::UserRole + 1).toBool())
            delete m_processTree->takeTopLevelItem(i);
    }

    std::unordered_map<DWORD, const SANDBOX_PROCESS_ENTRY*> byPid;
    byPid.reserve(list.Count);
    for (ULONG i = 0; i < list.Count && i < SANDBOX_MAX_TRACKED_PIDS; ++i)
        byPid[list.Entries[i].ProcessId] = &list.Entries[i];

    std::unordered_map<DWORD, QTreeWidgetItem*> items;
    std::function<QTreeWidgetItem*(DWORD)> addEntry = [&](DWORD pid) -> QTreeWidgetItem* {
        auto existing = items.find(pid);
        if (existing != items.end())
            return existing->second;

        auto found = byPid.find(pid);
        if (found == byPid.end())
            return nullptr;

        const auto* entry = found->second;
        const bool isRoot = entry->ProcessId == entry->RootProcessId ||
            entry->ParentProcessId == 0;

        QTreeWidgetItem* parent = nullptr;
        if (!isRoot && entry->ParentProcessId != 0 &&
            entry->ParentProcessId != entry->ProcessId) {
            parent = addEntry(entry->ParentProcessId);
        }
        if (!parent && !isRoot && entry->RootProcessId != 0 &&
            entry->RootProcessId != entry->ProcessId) {
            parent = addEntry(entry->RootProcessId);
        }

        QString mode = isRoot ? "⬡ Sandbox root" : "↳ Sandbox child";
        if (entry->WfpEnabled) {
            mode += " | WFP " +
                QString::fromStdWString(DriverManager::formatIpv4(entry->WfpVnicIp));
            if (entry->WfpNetworkSeen)
                mode += " active";
        }

        auto* item = new QTreeWidgetItem({
            QString::number(entry->ProcessId),
            QString::fromWCharArray(entry->BoxName),
            entry->ParentProcessId ? QString::number(entry->ParentProcessId) : "—",
            entry->RootProcessId ? QString::number(entry->RootProcessId) : "—",
            mode
        });
        item->setData(0, Qt::UserRole, static_cast<uint>(entry->ProcessId));
        item->setData(0, Qt::UserRole + 1, true);

        QColor color = isRoot ? QColor(0x00,0xcc,0x66) : QColor(0x88,0xdd,0xaa);
        for (int c = 0; c < m_processTree->columnCount(); ++c)
            item->setForeground(c, color);

        if (parent)
            parent->addChild(item);
        else
            m_processTree->addTopLevelItem(item);

        items[pid] = item;
        return item;
    };

    for (const auto& pair : byPid)
        addEntry(pair.first);

    m_processTree->expandAll();
}
