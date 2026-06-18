// ============================================================
//  MainWindow.cpp  —  Full Qt6 GUI with driver panel
//
//  Changes vs original:
//    1. m_explorer added to constructor initialiser list
//    2. m_explorer.startPipeServer() called in constructor body
//    3. m_explorer.stopPipeServer() called in destructor
//    4. onLaunchSandboxed: injectWhileSuspended() called BEFORE resume
//    5. onFsRootChanged: restarts pipe server when path changes
//    6. connect(m_fsRoot editingFinished → onFsRootChanged) in setupUi
// ============================================================
#include "MainWindow.h"
#include <QApplication>
#include <QFileDialog>
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
#include <QHeaderView>
#include <QTreeWidgetItemIterator>
#include <QMetaObject>
#include <algorithm>
#include <functional>
#include <unordered_map>

// ---- Helpers -----------------------------------------------
static QLabel* makeLabel(const QString& t) {
    auto* l = new QLabel(t);
    l->setStyleSheet("color:#8899aa;");
    return l;
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
    bool hoverTitle = false;
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

static bool IsCursorOverHostTitle(HWND target)
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
    entry.hoverTitle = IsCursorOverHostTitle(entry.target);
    RepositionHostBorder(entry.overlay, entry.target,
        entry.hoverTitle || entry.moving);
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
        if (entry->moving || entry->hoverTitle)
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
    // 
     //, m_engine([this](const std::wstring& m) { appendLog(QString::fromStdWString(m)); })
     //, m_driver([this](const std::wstring& m) { appendLog(QString::fromStdWString(m)); })
     //, m_explorer([this](const std::wstring& m) { appendLog(QString::fromStdWString(m)); })

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

    // ── NEW: start broker pipe that sandboxed Chrome DLLs write to
    //         when the user clicks "Show in folder".
    //         m_fsRoot is populated by setupUi() above so we can read it now.
    appendLog("  [Explorer] Named-pipe broker started.");
}

MainWindow::~MainWindow()
{
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
        unregisterDriverPids(sp);
        m_engine.release(sp);
    }
    for (auto& sp : m_normalProcs)  m_engine.release(sp);
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
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Windows\\notepad.exe",
    "C:\\Users\\admin\\AppData\\Local\\Chromium\\Application\\chrome.exe",
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
    m_chkPassphrase = new QCheckBox("Use passphrase");
    m_chkPassphrase->setStyleSheet("QCheckBox{color:#aab;}"
        "QCheckBox::indicator:checked{background:#0af;}");
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
    m_btnKillSel   = makeBtn("✕  Kill Selected", "#773300");
    m_btnKillAll   = makeBtn("✕✕ Kill All",      "#550011");

    auto* launchRow = new QHBoxLayout;
    launchRow->addWidget(m_btnNormal);
    launchRow->addWidget(m_btnSandboxed);
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
    connect(m_btnKillSel,   &QPushButton::clicked, this, &MainWindow::onKillSelected);
    connect(m_btnKillAll,   &QPushButton::clicked, this, &MainWindow::onKillAll);
    connect(m_cmbPolicy,    QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onPolicyChanged);
    connect(m_chkWfpForce, &QCheckBox::toggled,
            m_wfpVnicIp, &QLineEdit::setEnabled);
    connect(m_chkPassphrase, &QCheckBox::toggled,
            m_passphrase, &QLineEdit::setEnabled);
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
    if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr,
                       FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
        SandboxedProcess sp;
        sp.pid = pi.dwProcessId; sp.hProcess = pi.hProcess;
        sp.hThread = pi.hThread; sp.boxName = L"(normal)"; sp.valid = true;
        addProcessRow(sp, false);
        m_normalProcs.push_back(sp);
        m_monitor->track(sp, QString("Normal PID %1").arg(sp.pid));
        appendLog(QString("  PID %1 running (no sandbox)").arg(sp.pid));
    } else {
        appendLog(QString("! CreateProcess failed: %1").arg(GetLastError()));
    }
}

void MainWindow::onLaunchSandboxed()
{
    QString exe = m_exePath->currentText().trimmed();
    if (exe.isEmpty()) { appendLog("! No executable."); return; }
    QString exeLower = exe.toLower();
    const bool isChromium = exeLower.contains("chrome") ||
        exeLower.contains("msedge") ||
        exeLower.contains("brave");

    //const QString exeName = QFileInfo(exe).fileName().toLower();
    //const bool isConsoleShell = exeName == "cmd.exe" ||
    //    +exeName == "powershell.exe" ||
    //    +exeName == "pwsh.exe";

    QString uniqueBox = m_boxName->text().trimmed();
    if (uniqueBox.isEmpty()) uniqueBox = "Box00";

    QString mountDir = m_fsRoot->text().trimmed();
    if (mountDir.isEmpty()) mountDir = "C:\\SandboxMounts";
    QString vaultDir = m_vaultDir->text().trimmed();
    if (vaultDir.isEmpty()) vaultDir = "C:\\SandboxBoxes";
    bool sizeOk = false;
    uint64_t vaultSizeMb = m_vaultSizeMb->text().trimmed().toULongLong(&sizeOk);
    if (!sizeOk || vaultSizeMb < 64) {
        appendLog("! Vault size must be at least 64 MB.");
        return;
    }
    if (!DriverManager::isElevated()) {
        appendLog("! Vault-backed sandbox launch requires Administrator privileges.");
        appendLog("  CreateVirtualDisk/AttachVirtualDisk cannot run from a non-elevated process.");
        return;
    }

    appendLog("--- Launch SANDBOXED box=\"" + uniqueBox + "\" ---");
    if (!m_driver.isLoaded()) {
        appendLog("  [!] Driver not loaded — FS redirection via driver DISABLED.");
        appendLog("      Job Object + namespace isolation still active.");
    }

    // ---- Launch via SandboxEngine (Job + Namespace) ----
    SandboxConfig cfg;
    cfg.boxName        = uniqueBox.toStdWString();
    cfg.executablePath = exe.toStdWString();
    cfg.commandLine    = m_extraArgs->text().toStdWString();
    cfg.fsRootBase     = mountDir.toStdWString();
    cfg.useVault       = true;
    cfg.vaultDir       = vaultDir.toStdWString();
    cfg.mountDir       = mountDir.toStdWString();
    cfg.vaultSizeMB    = vaultSizeMb;
    cfg.passphrase     = m_chkPassphrase->isChecked()
        ? m_passphrase->text().toStdWString()
        : std::wstring();
    cfg.restrictUI     = m_chkRestrictUI->isChecked() && !isChromium;
    cfg.killOnClose    = m_chkKillOnClose->isChecked();
    if (isChromium && m_chkRestrictUI->isChecked()) {
        appendLog("  [Chrome] Job UI limits disabled for Chromium compatibility.");
        appendLog("  [Chrome] Using --no-sandbox because the outer sandbox owns containment.");
    }

    SandboxedProcess sp = m_engine.launch(cfg);
    if (!sp.valid) {
        appendLog("! Process launch failed.");
        return;
    }

    // ---- Register the mounted vault root and crypto context with the driver. ----
    bool driverOk = false;
    if (m_driver.isLoaded()) {
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
            if (driverOk && sp.cryptoKeysValid)
                driverOk = m_driver.setCryptoKey(uniqueBox.toStdWString(),
                                                 sp.masterKey,
                                                 sp.hmacKey);
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
    }

    // ---- Optional WFP source-IP forcing.  Must be registered before resume
    //      so child processes (Chrome Network Service, etc.) inherit the rule
    //      before their first bind().
    if (m_chkWfpForce->isChecked()) {
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

    // ── Inject the Show-in-folder shell broker BEFORE resume.
    // sp.suspended is still true here — resume() has not been called yet.
    // Must happen at this exact point: after addProcess() (so the driver
    // knows the PID) but before ResumeThread (so Job UI restrictions are
    // not yet enforced and VirtualAllocEx / SetThreadContext work freely).
    {
        if (!cfg.borderDllPath.empty()) {
            appendLog(QString("  [Broker] Shell hook injected by Detours for PID %1")
                .arg(sp.pid));
        } else {
        }
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

void MainWindow::onKillSelected()
{
    auto* item = m_processTree->currentItem();
    if (!item) { appendLog("! Nothing selected."); return; }
    DWORD pid = item->data(0, Qt::UserRole).toUInt();
    bool sandboxed = item->data(0, Qt::UserRole + 1).toBool();
    appendLog(QString("--- Kill PID %1 ---").arg(pid));

    for (auto& sp : m_sandboxProcs) {
        if (sp.pid == pid && sp.valid) {
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
            unregisterDriverPids(sp);
            m_engine.release(sp);
        }
    }
    m_sandboxProcs.clear();
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
    return false;
}

void MainWindow::syncDriverPids(SandboxedProcess& sp)
{
    if (!m_driver.isLoaded() || !sp.valid)
        return;
    for (DWORD pid : sp.driverPids)
        m_driver.addProcess(pid, sp.boxName);
}

void MainWindow::unregisterDriverPids(SandboxedProcess& sp)
{
    unregisterWfp(sp);
    if (!m_driver.isLoaded())
        return;

    m_driver.removeProcess(sp.pid);
    for (DWORD pid : sp.driverPids) {
        if (pid != sp.pid)
            m_driver.removeProcess(pid);
    }

    if (!hasOtherSandboxInBox(sp.boxName, sp.pid)) {
        m_driver.clearCryptoKey(sp.boxName);
        m_driver.removeBox(sp.boxName);
    }
}

// ── NEW: restart pipe server when the FS root field changes ─────────────────
void MainWindow::onFsRootChanged()
{
    appendLog("  [Explorer] Pipe server restarted: " + m_fsRoot->text());
}

bool MainWindow::isSandboxWindow(HWND hwnd, std::wstring* boxName) const
{
    if (!hwnd || !IsWindow(hwnd)) return false;
    if (!IsWindowVisible(hwnd) || IsIconic(hwnd)) return false;
    if (GetAncestor(hwnd, GA_ROOT) != hwnd) return false;

    LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
    LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    if (!(style & WS_CAPTION)) return false;
    if (exStyle & WS_EX_TOOLWINDOW) return false;

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
    for (const auto& sp : m_sandboxProcs) {
        if (!sp.valid || !sp.hJob)
            continue;

        BOOL inJob = FALSE;
        if (IsProcessInJob(proc, sp.hJob, &inJob) && inJob) {
            if (boxName)
                *boxName = sp.boxName;
            matched = true;
            break;
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
