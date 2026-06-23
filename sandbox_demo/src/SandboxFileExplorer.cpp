#include "SandboxFileExplorer.h"

#include "ui_SandboxFileExplorer.h"

#include <QAbstractItemView>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFileSystemModel>
#include <QHeaderView>
#include <QInputDialog>
#include <QItemSelectionModel>
#include <QLineEdit>
#include <QListView>
#include <QMenu>
#include <QMessageBox>
#include <QModelIndex>
#include <QRegularExpression>
#include <QStackedWidget>
#include <QTimer>
#include <QToolButton>
#include <QTreeView>

#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {

QString cleanAbsolutePath(const QString& path)
{
    return QDir::cleanPath(QFileInfo(path).absoluteFilePath());
}

QString canonicalOrAbsolutePath(const QString& path)
{
    const QFileInfo info(path);
    const QString canonical = info.canonicalFilePath();
    return QDir::cleanPath(canonical.isEmpty()
                               ? info.absoluteFilePath()
                               : canonical);
}

Qt::CaseSensitivity pathCaseSensitivity()
{
#ifdef Q_OS_WIN
    return Qt::CaseInsensitive;
#else
    return Qt::CaseSensitive;
#endif
}

QString comparisonPath(QString path)
{
    path = QDir::cleanPath(path);
    path.replace('\\', '/');
    return path;
}

QString formatByteSize(qint64 bytes)
{
    static constexpr double kUnit = 1024.0;
    static const char* kSuffixes[] = { "B", "KB", "MB", "GB", "TB" };
    double value = static_cast<double>(bytes);
    int suffix = 0;
    while (value >= kUnit && suffix < 4) {
        value /= kUnit;
        ++suffix;
    }
    if (suffix == 0)
        return QStringLiteral("%1 %2").arg(bytes).arg(kSuffixes[suffix]);
    return QStringLiteral("%1 %2")
        .arg(value, 0, 'f', value >= 10.0 ? 1 : 2)
        .arg(kSuffixes[suffix]);
}

bool containsInvalidFileNameCharacter(const QString& name)
{
    static const QRegularExpression invalid(QStringLiteral(R"([\\/:*?"<>|])"));
    return name.contains(invalid);
}

} // namespace

SandboxFileExplorer::SandboxFileExplorer(QWidget* parent)
    : QWidget(parent, Qt::Window)
    , m_ui(std::make_unique<Ui::SandboxFileExplorer>())
{
    m_ui->setupUi(this);
    setWindowTitle(QStringLiteral("Box Explorer"));
    resize(1080, 680);

    setObjectName(QStringLiteral("sandboxFileExplorer"));
    setStyleSheet(QStringLiteral(
        "#sandboxFileExplorer { background: #ffffff; color: #000000; "
        "border: 3px solid #ffd200; }"
        "QTabWidget::pane { border: 1px solid #d0d0d0; }"
        "QTabBar::tab { padding: 6px 18px; border: 1px solid #d0d0d0; "
        "border-bottom: none; background: #f3f3f3; color: #000000; }"
        "QTabBar::tab:selected { background: #ffffff; }"
        "QLineEdit { background: #ffffff; color: #000000; "
        "border: 1px solid #b8b8b8; padding: 3px 6px; }"
        "QToolButton { background: #f3f3f3; color: #000000; "
        "border: 1px solid #adadad; padding: 4px 10px; }"
        "QToolButton:hover { background: #e5f1fb; border-color: #0078d4; }"
        "QToolButton:checked { background: #cce8ff; border-color: #0078d4; }"
        "QTreeView, QListView { background: #ffffff; color: #000000; "
        "alternate-background-color: #f7f7f7; border: 1px solid #d0d0d0; }"
        "QTreeView::item, QListView::item { color: #000000; }"
        "QTreeView::item:selected, QListView::item:selected { "
        "background: #0078d7; color: #ffffff; }"
        "QHeaderView::section { background: #f3f3f3; color: #000000; "
        "padding: 4px 6px; border: 0; border-right: 1px solid #d0d0d0; }"
        "QMenu { background: #ffffff; color: #000000; border: 1px solid #d0d0d0; }"
        "QMenu::item:selected { background: #0078d7; color: #ffffff; }"
        "QLabel#statusLabel { color: #000000; padding: 2px 4px; }"));

    initializeModels();

    connect(m_ui->upButton, &QToolButton::clicked,
            this, &SandboxFileExplorer::navigateUp);
    connect(m_ui->refreshButton, &QToolButton::clicked,
            this, &SandboxFileExplorer::refresh);
    connect(m_ui->detailsButton, &QToolButton::clicked,
            this, &SandboxFileExplorer::showDetailsView);
    connect(m_ui->tilesButton, &QToolButton::clicked,
            this, &SandboxFileExplorer::showTilesView);
    connect(m_ui->detailsView, &QTreeView::doubleClicked,
            this, &SandboxFileExplorer::onContentActivated);
    connect(m_ui->tilesView, &QListView::doubleClicked,
            this, &SandboxFileExplorer::onContentActivated);
    connect(m_ui->directoryTree, &QTreeView::customContextMenuRequested,
            this, &SandboxFileExplorer::showContextMenu);
    connect(m_ui->detailsView, &QTreeView::customContextMenuRequested,
            this, &SandboxFileExplorer::showContextMenu);
    connect(m_ui->tilesView, &QListView::customContextMenuRequested,
            this, &SandboxFileExplorer::showContextMenu);
}

SandboxFileExplorer::~SandboxFileExplorer() = default;

void SandboxFileExplorer::initializeModels()
{
    m_directoryModel = new QFileSystemModel(this);
    m_directoryModel->setFilter(QDir::AllDirs | QDir::NoDotAndDotDot |
                                QDir::Hidden | QDir::System);
    m_directoryModel->setReadOnly(true);

    m_contentModel = new QFileSystemModel(this);
    m_contentModel->setFilter(QDir::AllEntries | QDir::NoDotAndDotDot |
                              QDir::Hidden | QDir::System);
    m_contentModel->setReadOnly(true);

    m_ui->directoryTree->setModel(m_directoryModel);
    m_ui->directoryTree->setHeaderHidden(true);
    m_ui->directoryTree->setUniformRowHeights(true);
    m_ui->directoryTree->setSortingEnabled(true);
    m_ui->directoryTree->sortByColumn(0, Qt::AscendingOrder);
    for (int column = 1; column < m_directoryModel->columnCount(); ++column)
        m_ui->directoryTree->hideColumn(column);

    m_ui->detailsView->setModel(m_contentModel);
    m_ui->detailsView->setSortingEnabled(true);
    m_ui->detailsView->sortByColumn(0, Qt::AscendingOrder);
    m_ui->detailsView->header()->setStretchLastSection(false);
    m_ui->detailsView->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    for (int column = 1; column < m_contentModel->columnCount(); ++column)
        m_ui->detailsView->header()->setSectionResizeMode(column,
                                                          QHeaderView::ResizeToContents);

    m_ui->tilesView->setModel(m_contentModel);
    m_ui->tilesView->setIconSize(QSize(48, 48));
    m_ui->tilesView->setGridSize(QSize(140, 96));

    connect(m_ui->directoryTree->selectionModel(),
            &QItemSelectionModel::currentChanged,
            this, &SandboxFileExplorer::onDirectorySelected);
}

void SandboxFileExplorer::showForPath(const QString& selectedPath,
                                      const QString& boxName,
                                      const QString& boxRoot)
{
    const QFileInfo rootInfo(cleanAbsolutePath(boxRoot));
    if (!rootInfo.exists() || !rootInfo.isDir())
        return;

    m_boxName = boxName.trimmed().isEmpty() ? QStringLiteral("Box") : boxName.trimmed();
    m_boxRoot = rootInfo.absoluteFilePath();
    m_boxRootCanonical = canonicalOrAbsolutePath(m_boxRoot);
    m_ui->boxTabs->setTabText(0, m_boxName);

    const QModelIndex root = m_directoryModel->setRootPath(m_boxRoot);
    m_ui->directoryTree->setRootIndex(root);

    QFileInfo selectedInfo(cleanAbsolutePath(selectedPath));
    QString directory = selectedInfo.isDir()
        ? selectedInfo.absoluteFilePath()
        : selectedInfo.absolutePath();
    if (!isPathInsideBox(directory))
        directory = m_boxRoot;

    navigateTo(directory,
               selectedInfo.isFile() && isPathInsideBox(selectedInfo.absoluteFilePath())
                   ? selectedInfo.absoluteFilePath()
                   : QString());

    showNormal();
    raise();
    activateWindow();

#ifdef Q_OS_WIN
    const HWND window = reinterpret_cast<HWND>(winId());
    SetWindowPos(window, HWND_TOPMOST, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    BringWindowToTop(window);
    SetForegroundWindow(window);
    SetActiveWindow(window);

    QTimer::singleShot(100, this, [this, window] {
        if (!IsWindow(window))
            return;
        SetWindowPos(window, HWND_NOTOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        BringWindowToTop(window);
        raise();
        activateWindow();
    });
#endif
}

void SandboxFileExplorer::releasePath(const QString& rootPath)
{
    const QString root = comparisonPath(canonicalOrAbsolutePath(rootPath));
    const QString currentRoot = comparisonPath(m_boxRootCanonical);
    if (!currentRoot.isEmpty() &&
        root.compare(currentRoot, pathCaseSensitivity()) != 0 &&
        !currentRoot.startsWith(root + QLatin1Char('/'), pathCaseSensitivity())) {
        return;
    }

    hide();
    clearTransfer();
    m_ui->directoryTree->setRootIndex(QModelIndex());
    m_ui->detailsView->setRootIndex(QModelIndex());
    m_ui->tilesView->setRootIndex(QModelIndex());
    m_directoryModel->setRootPath(QString());
    m_contentModel->setRootPath(QString());
    m_ui->addressEdit->clear();
    m_boxName.clear();
    m_boxRoot.clear();
    m_boxRootCanonical.clear();
    m_currentDirectory.clear();
    m_selectedPath.clear();
}

void SandboxFileExplorer::navigateTo(const QString& directory,
                                     const QString& selectedPath)
{
    const QString cleanDirectory = cleanAbsolutePath(directory);
    if (!canUsePath(cleanDirectory))
        return;

    if (m_currentDirectory.compare(cleanDirectory, pathCaseSensitivity()) == 0 &&
        selectedPath.isEmpty()) {
        return;
    }

    m_currentDirectory = cleanDirectory;
    m_selectedPath = selectedPath;
    m_ui->addressEdit->setText(QDir::toNativeSeparators(m_currentDirectory));
    setWindowTitle(QStringLiteral("%1 - Box Explorer").arg(m_boxName));

    const QModelIndex contentRoot = m_contentModel->setRootPath(m_currentDirectory);
    m_ui->detailsView->setRootIndex(contentRoot);
    m_ui->tilesView->setRootIndex(contentRoot);
    selectDirectoryInTree(m_currentDirectory);

    if (!m_selectedPath.isEmpty()) {
        QTimer::singleShot(0, this, [this] {
            const QModelIndex selected = m_contentModel->index(m_selectedPath);
            if (!selected.isValid())
                return;
            m_ui->detailsView->setCurrentIndex(selected);
            m_ui->detailsView->scrollTo(selected, QAbstractItemView::PositionAtCenter);
            m_ui->tilesView->setCurrentIndex(selected);
            m_ui->tilesView->scrollTo(selected, QAbstractItemView::PositionAtCenter);
        });
    }

    setStatus(QStringLiteral("Viewing %1").arg(QDir::toNativeSeparators(m_currentDirectory)));
}

void SandboxFileExplorer::selectDirectoryInTree(const QString& directory)
{
    const QModelIndex index = m_directoryModel->index(directory);
    if (!index.isValid())
        return;
    QTimer::singleShot(0, this, [this, index] {
        m_ui->directoryTree->setCurrentIndex(index);
        m_ui->directoryTree->scrollTo(index, QAbstractItemView::EnsureVisible);
    });
}

void SandboxFileExplorer::onDirectorySelected(const QModelIndex& current,
                                              const QModelIndex&)
{
    if (!current.isValid())
        return;
    const QString directory = pathForIndex(current, true);
    if (!directory.isEmpty())
        navigateTo(directory);
}

void SandboxFileExplorer::onContentActivated(const QModelIndex& index)
{
    const QString path = pathForIndex(index, false);
    if (!path.isEmpty())
        openPath(path);
}

void SandboxFileExplorer::navigateUp()
{
    if (m_currentDirectory.isEmpty() ||
        comparisonPath(m_currentDirectory).compare(comparisonPath(m_boxRoot),
                                                   pathCaseSensitivity()) == 0) {
        return;
    }

    QDir directory(m_currentDirectory);
    if (directory.cdUp() && isPathInsideBox(directory.absolutePath()))
        navigateTo(directory.absolutePath());
}

void SandboxFileExplorer::refresh()
{
    if (m_currentDirectory.isEmpty())
        return;
    const QString current = m_currentDirectory;
    const QString selected = m_selectedPath;
    m_contentModel->setRootPath(QString());
    navigateTo(current, selected);
}

void SandboxFileExplorer::showDetailsView()
{
    m_ui->contentStack->setCurrentWidget(m_ui->detailsPage);
    m_ui->detailsButton->setChecked(true);
    m_ui->tilesButton->setChecked(false);
}

void SandboxFileExplorer::showTilesView()
{
    m_ui->contentStack->setCurrentWidget(m_ui->tilesPage);
    m_ui->detailsButton->setChecked(false);
    m_ui->tilesButton->setChecked(true);
}

void SandboxFileExplorer::showContextMenu(const QPoint& position)
{
    auto* view = qobject_cast<QAbstractItemView*>(sender());
    if (!view)
        return;

    const QModelIndex clicked = view->indexAt(position);
    if (clicked.isValid() && !view->selectionModel()->isSelected(clicked))
        view->setCurrentIndex(clicked);

    const QStringList paths = selectedPaths(view);
    const bool hasSelection = !paths.isEmpty();
    bool allUsable = hasSelection;
    bool allModifiable = hasSelection;
    for (const QString& path : paths) {
        allUsable = allUsable && canUsePath(path) && !isReparsePoint(path);
        allModifiable = allModifiable && canModifyPath(path) && !isReparsePoint(path);
    }

    QMenu menu(this);
    QAction* openAction = menu.addAction(QStringLiteral("Open"));
    menu.addSeparator();
    QAction* cutAction = menu.addAction(QStringLiteral("Cut"));
    QAction* copyAction = menu.addAction(QStringLiteral("Copy"));
    QAction* pasteAction = menu.addAction(QStringLiteral("Paste Here"));
    QAction* importFilesAction = menu.addAction(QStringLiteral("Import Files Here..."));
    QAction* importFolderAction = menu.addAction(QStringLiteral("Import Folder Here..."));
    menu.addSeparator();
    QAction* renameAction = menu.addAction(QStringLiteral("Rename"));
    QAction* propertiesAction = menu.addAction(QStringLiteral("Properties"));
    QAction* deleteAction = menu.addAction(QStringLiteral("Delete"));

    openAction->setEnabled(paths.size() == 1 && allUsable);
    cutAction->setEnabled(allModifiable);
    copyAction->setEnabled(allUsable);
    pasteAction->setEnabled(m_transferMode != TransferMode::None &&
                            !m_transferPaths.isEmpty() &&
                            canUsePath(currentDirectory()));
    importFilesAction->setEnabled(canUsePath(currentDirectory()));
    importFolderAction->setEnabled(canUsePath(currentDirectory()));
    renameAction->setEnabled(paths.size() == 1 && allModifiable);
    propertiesAction->setEnabled(hasSelection && allUsable);
    deleteAction->setEnabled(allModifiable);

    QAction* chosen = menu.exec(view->viewport()->mapToGlobal(position));
    if (!chosen)
        return;
    if (chosen == openAction)
        openPath(paths.constFirst());
    else if (chosen == cutAction)
        cutSelection(paths);
    else if (chosen == copyAction)
        copySelection(paths);
    else if (chosen == pasteAction)
        pasteIntoCurrentDirectory();
    else if (chosen == importFilesAction)
        importFilesIntoCurrentDirectory();
    else if (chosen == importFolderAction)
        importFolderIntoCurrentDirectory();
    else if (chosen == renameAction)
        renameSelection(paths);
    else if (chosen == propertiesAction)
        showProperties(paths);
    else if (chosen == deleteAction)
        deleteSelection(paths);
}

void SandboxFileExplorer::openPath(const QString& path)
{
    if (!canUsePath(path)) {
        showError(QStringLiteral("Open blocked"),
                  QStringLiteral("The selected path is outside the current box."));
        return;
    }
    if (isReparsePoint(path)) {
        showError(QStringLiteral("Open blocked"),
                  QStringLiteral("Reparse points are not opened from the box explorer."));
        return;
    }

    const QFileInfo info(path);
    if (info.isDir()) {
        navigateTo(info.absoluteFilePath());
        return;
    }
    if (!info.isFile())
        return;

    setStatus(QStringLiteral("Opening %1 inside box %2")
                  .arg(info.fileName(), m_boxName));
    emit openRequested(info.absoluteFilePath());
}

void SandboxFileExplorer::cutSelection(const QStringList& paths)
{
    m_transferMode = TransferMode::Move;
    m_transferPaths = paths;
    setStatus(QStringLiteral("%1 item(s) marked for move inside this box.")
                  .arg(paths.size()));
}

void SandboxFileExplorer::copySelection(const QStringList& paths)
{
    m_transferMode = TransferMode::Copy;
    m_transferPaths = paths;
    setStatus(QStringLiteral("%1 item(s) marked for copy inside this box.")
                  .arg(paths.size()));
}

void SandboxFileExplorer::pasteIntoCurrentDirectory()
{
    if (m_transferMode == TransferMode::None || m_transferPaths.isEmpty())
        return;

    const QString destinationDirectory = currentDirectory();
    if (!canUsePath(destinationDirectory))
        return;

    QString error;
    int completed = 0;
    for (const QString& source : m_transferPaths) {
        if (!QFileInfo::exists(source))
            continue;
        const QString destination = uniqueDestinationPath(destinationDirectory, source);
        if (m_transferMode == TransferMode::Copy) {
            if (!copyPathRecursive(source, destination, &error))
                break;
        } else {
            if (!movePath(source, destination, &error))
                break;
        }
        ++completed;
    }

    if (!error.isEmpty()) {
        showError(QStringLiteral("Paste failed"), error);
    } else {
        setStatus(QStringLiteral("%1 item(s) pasted inside this box.").arg(completed));
        if (m_transferMode == TransferMode::Move)
            clearTransfer();
        refresh();
    }
}

void SandboxFileExplorer::importFilesIntoCurrentDirectory()
{
    const QString destinationDirectory = currentDirectory();
    if (!canUsePath(destinationDirectory))
        return;

    const QStringList files = QFileDialog::getOpenFileNames(
        this,
        QStringLiteral("Import files into box"),
        QString(),
        QStringLiteral("All files (*.*)"));
    if (files.isEmpty())
        return;

    QString error;
    int completed = 0;
    for (const QString& source : files) {
        const QString destination = uniqueDestinationPath(destinationDirectory, source);
        if (!copyPathRecursive(source, destination, &error))
            break;
        ++completed;
    }

    if (!error.isEmpty())
        showError(QStringLiteral("Import failed"), error);
    else
        setStatus(QStringLiteral("%1 file(s) imported into this box.").arg(completed));
    refresh();
}

void SandboxFileExplorer::importFolderIntoCurrentDirectory()
{
    const QString destinationDirectory = currentDirectory();
    if (!canUsePath(destinationDirectory))
        return;

    const QString source = QFileDialog::getExistingDirectory(
        this,
        QStringLiteral("Import folder into box"));
    if (source.isEmpty())
        return;

    const QString destination = uniqueDestinationPath(destinationDirectory, source);
    QString error;
    if (!copyPathRecursive(source, destination, &error)) {
        showError(QStringLiteral("Import failed"), error);
        return;
    }

    setStatus(QStringLiteral("Folder imported into this box."));
    refresh();
}

void SandboxFileExplorer::renameSelection(const QStringList& paths)
{
    if (paths.size() != 1 || !canModifyPath(paths.constFirst()))
        return;

    const QFileInfo info(paths.constFirst());
    bool ok = false;
    const QString newName = QInputDialog::getText(
        this,
        QStringLiteral("Rename"),
        QStringLiteral("New name:"),
        QLineEdit::Normal,
        info.fileName(),
        &ok).trimmed();
    if (!ok || newName.isEmpty() || newName == info.fileName())
        return;
    if (containsInvalidFileNameCharacter(newName)) {
        showError(QStringLiteral("Rename blocked"),
                  QStringLiteral("The name contains a character Windows does not allow."));
        return;
    }

    const QString destination = QDir(info.absolutePath()).filePath(newName);
    if (!isDestinationInsideBox(destination) || QFileInfo::exists(destination)) {
        showError(QStringLiteral("Rename blocked"),
                  QStringLiteral("The destination is invalid or already exists."));
        return;
    }

    QString error;
    if (!movePath(info.absoluteFilePath(), destination, &error)) {
        showError(QStringLiteral("Rename failed"), error);
        return;
    }
    setStatus(QStringLiteral("Renamed to %1.").arg(newName));
    refresh();
}

void SandboxFileExplorer::showProperties(const QStringList& paths)
{
    if (paths.isEmpty())
        return;
    if (paths.size() > 1) {
        QMessageBox::information(
            this,
            QStringLiteral("Properties"),
            QStringLiteral("%1 selected item(s)\nLocation: %2")
                .arg(paths.size())
                .arg(QDir::toNativeSeparators(currentDirectory())));
        return;
    }

    const QFileInfo info(paths.constFirst());
    QString type = QStringLiteral("Other");
    if (info.isDir())
        type = QStringLiteral("Folder");
    else if (info.isFile())
        type = QStringLiteral("File");

    const QString size = info.isFile()
        ? formatByteSize(info.size())
        : QStringLiteral("-");
    const QString text = QStringLiteral(
        "Name: %1\n"
        "Type: %2\n"
        "Location: %3\n"
        "Size: %4\n"
        "Modified: %5\n"
        "Read only: %6")
        .arg(info.fileName())
        .arg(type)
        .arg(QDir::toNativeSeparators(info.absolutePath()))
        .arg(size)
        .arg(info.lastModified().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")))
        .arg(info.isWritable() ? QStringLiteral("No") : QStringLiteral("Yes"));

    QMessageBox::information(this, QStringLiteral("Properties"), text);
}

void SandboxFileExplorer::deleteSelection(const QStringList& paths)
{
    if (paths.isEmpty())
        return;
    for (const QString& path : paths) {
        if (!canModifyPath(path) || isReparsePoint(path)) {
            showError(QStringLiteral("Delete blocked"),
                      QStringLiteral("Only ordinary files and folders inside the current box can be deleted."));
            return;
        }
    }

    const QMessageBox::StandardButton answer = QMessageBox::warning(
        this,
        QStringLiteral("Delete"),
        QStringLiteral("Permanently delete %1 selected item(s) from this box?")
            .arg(paths.size()),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (answer != QMessageBox::Yes)
        return;

    QString error;
    int completed = 0;
    for (const QString& path : paths) {
        if (!removePath(path, &error))
            break;
        ++completed;
    }
    if (!error.isEmpty())
        showError(QStringLiteral("Delete failed"), error);
    else
        setStatus(QStringLiteral("%1 item(s) deleted.").arg(completed));
    refresh();
}

QAbstractItemView* SandboxFileExplorer::activeContentView() const
{
    return m_ui->contentStack->currentWidget() == m_ui->tilesPage
        ? static_cast<QAbstractItemView*>(m_ui->tilesView)
        : static_cast<QAbstractItemView*>(m_ui->detailsView);
}

QStringList SandboxFileExplorer::selectedPaths(QAbstractItemView* view) const
{
    if (!view || !view->selectionModel())
        return {};

    const bool directoryModel = view == m_ui->directoryTree;
    QStringList paths;
    const QModelIndexList rows = view->selectionModel()->selectedRows(0);
    for (const QModelIndex& index : rows) {
        const QString path = pathForIndex(index, directoryModel);
        if (!path.isEmpty() && !paths.contains(path, pathCaseSensitivity()))
            paths.push_back(path);
    }

    if (paths.isEmpty() && view->currentIndex().isValid()) {
        const QString path = pathForIndex(view->currentIndex(), directoryModel);
        if (!path.isEmpty())
            paths.push_back(path);
    }
    return paths;
}

QString SandboxFileExplorer::pathForIndex(const QModelIndex& index,
                                          bool directoryModel) const
{
    if (!index.isValid())
        return {};
    const QModelIndex nameIndex = index.sibling(index.row(), 0);
    QFileSystemModel* model = directoryModel ? m_directoryModel : m_contentModel;
    return model ? model->fileInfo(nameIndex).absoluteFilePath() : QString();
}

QString SandboxFileExplorer::currentDirectory() const
{
    return m_currentDirectory.isEmpty() ? m_boxRoot : m_currentDirectory;
}

QString SandboxFileExplorer::uniqueDestinationPath(const QString& directory,
                                                   const QString& sourcePath) const
{
    const QFileInfo source(sourcePath);
    const QString originalName = source.fileName();
    QString candidate = QDir(directory).filePath(originalName);
    if (!QFileInfo::exists(candidate))
        return candidate;

    const QString suffix = source.isDir() ? QString() : source.completeSuffix();
    const QString base = suffix.isEmpty() || source.isDir()
        ? originalName
        : originalName.left(originalName.size() - suffix.size() - 1);

    int index = 1;
    while (true) {
        const QString copyName = suffix.isEmpty()
            ? QStringLiteral("%1 - Copy%2")
                  .arg(base, index == 1 ? QString() : QStringLiteral(" (%1)").arg(index))
            : QStringLiteral("%1 - Copy%2.%3")
                  .arg(base,
                       index == 1 ? QString() : QStringLiteral(" (%1)").arg(index),
                       suffix);
        candidate = QDir(directory).filePath(copyName);
        if (!QFileInfo::exists(candidate))
            return candidate;
        ++index;
    }
}

bool SandboxFileExplorer::copyPathRecursive(const QString& source,
                                            const QString& destination,
                                            QString* errorMessage) const
{
    if (!QFileInfo::exists(source) || !isDestinationInsideBox(destination) ||
        isReparsePoint(source)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Copy blocked because the source is unavailable or the destination leaves the current box.");
        return false;
    }
    if (isSameOrChildPath(destination, source)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("A folder cannot be copied into itself.");
        return false;
    }

    const QFileInfo sourceInfo(source);
    if (sourceInfo.isDir()) {
        if (!QDir().mkpath(destination)) {
            if (errorMessage)
                *errorMessage = QStringLiteral("Failed to create %1")
                    .arg(QDir::toNativeSeparators(destination));
            return false;
        }
        const QFileInfoList entries = QDir(source).entryInfoList(
            QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System,
            QDir::DirsFirst | QDir::Name);
        for (const QFileInfo& child : entries) {
            if (!copyPathRecursive(child.absoluteFilePath(),
                                   QDir(destination).filePath(child.fileName()),
                                   errorMessage)) {
                return false;
            }
        }
        return true;
    }

    if (!sourceInfo.isFile()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Unsupported file type: %1")
                .arg(QDir::toNativeSeparators(source));
        return false;
    }

    if (!QFile::copy(source, destination)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Failed to copy %1")
                .arg(QDir::toNativeSeparators(source));
        return false;
    }
    return true;
}

bool SandboxFileExplorer::removePath(const QString& path,
                                     QString* errorMessage) const
{
    if (!canModifyPath(path) || isReparsePoint(path)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Delete blocked for %1")
                .arg(QDir::toNativeSeparators(path));
        return false;
    }

    const QFileInfo info(path);
    const bool ok = info.isDir()
        ? QDir(path).removeRecursively()
        : QFile::remove(path);
    if (!ok && errorMessage)
        *errorMessage = QStringLiteral("Failed to delete %1")
            .arg(QDir::toNativeSeparators(path));
    return ok;
}

bool SandboxFileExplorer::movePath(const QString& source,
                                   const QString& destination,
                                   QString* errorMessage) const
{
    if (!canModifyPath(source) || !isDestinationInsideBox(destination) ||
        isReparsePoint(source)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Move blocked because a path leaves the current box.");
        return false;
    }
    if (isSameOrChildPath(destination, source)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("A folder cannot be moved into itself.");
        return false;
    }

    const QFileInfo sourceInfo(source);
    const bool renamed = sourceInfo.isDir()
        ? QDir().rename(source, destination)
        : QFile::rename(source, destination);
    if (renamed)
        return true;

    if (!copyPathRecursive(source, destination, errorMessage))
        return false;
    return removePath(source, errorMessage);
}

bool SandboxFileExplorer::canUsePath(const QString& path) const
{
    return isPathInsideBox(path) && QFileInfo::exists(path);
}

bool SandboxFileExplorer::canModifyPath(const QString& path) const
{
    if (!canUsePath(path))
        return false;
    return comparisonPath(canonicalOrAbsolutePath(path))
        .compare(comparisonPath(m_boxRootCanonical), pathCaseSensitivity()) != 0;
}

bool SandboxFileExplorer::isPathInsideBox(const QString& path) const
{
    if (m_boxRootCanonical.isEmpty() || path.isEmpty())
        return false;
    const QString root = comparisonPath(m_boxRootCanonical);
    const QString candidate = comparisonPath(canonicalOrAbsolutePath(path));
    return candidate.compare(root, pathCaseSensitivity()) == 0 ||
           candidate.startsWith(root + QLatin1Char('/'), pathCaseSensitivity());
}

bool SandboxFileExplorer::isDestinationInsideBox(const QString& path) const
{
    const QFileInfo info(path);
    return isPathInsideBox(info.absolutePath());
}

bool SandboxFileExplorer::isSameOrChildPath(const QString& path,
                                            const QString& parent) const
{
    const QString candidate = comparisonPath(canonicalOrAbsolutePath(path));
    const QString parentPath = comparisonPath(canonicalOrAbsolutePath(parent));
    return candidate.compare(parentPath, pathCaseSensitivity()) == 0 ||
           candidate.startsWith(parentPath + QLatin1Char('/'), pathCaseSensitivity());
}

bool SandboxFileExplorer::isReparsePoint(const QString& path) const
{
    const QFileInfo info(path);
    if (info.isSymLink())
        return true;
#ifdef Q_OS_WIN
    const QString native = QDir::toNativeSeparators(info.absoluteFilePath());
    const DWORD attributes = GetFileAttributesW(
        reinterpret_cast<LPCWSTR>(native.utf16()));
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    return false;
#endif
}

void SandboxFileExplorer::clearTransfer()
{
    m_transferMode = TransferMode::None;
    m_transferPaths.clear();
}

void SandboxFileExplorer::setStatus(const QString& message) const
{
    m_ui->statusLabel->setText(message);
}

void SandboxFileExplorer::showError(const QString& title,
                                    const QString& message) const
{
    QMessageBox::warning(const_cast<SandboxFileExplorer*>(this), title, message);
}
