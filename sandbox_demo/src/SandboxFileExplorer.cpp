#include "SandboxFileExplorer.h"

#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QFileSystemModel>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QModelIndex>
#include <QPushButton>
#include <QTimer>
#include <QTreeView>
#include <QUrl>
#include <QVBoxLayout>

SandboxFileExplorer::SandboxFileExplorer(QWidget* parent)
    : QWidget(parent, Qt::Window)
{
    setWindowTitle(QStringLiteral("Sandbox Downloads"));
    resize(960, 600);

    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(3, 3, 3, 3);
    outer->setSpacing(0);
    setObjectName(QStringLiteral("sandboxFileExplorer"));
    setStyleSheet(QStringLiteral(
        "#sandboxFileExplorer { border: 3px solid #ffd200; }"));

    auto* toolbar = new QHBoxLayout;
    toolbar->setContentsMargins(8, 8, 8, 6);
    auto* upButton = new QPushButton(QStringLiteral("Up"), this);
    auto* refreshButton = new QPushButton(QStringLiteral("Refresh"), this);
    m_address = new QLineEdit(this);
    m_address->setReadOnly(true);
    toolbar->addWidget(new QLabel(QStringLiteral("Sandbox folder:"), this));
    toolbar->addWidget(m_address, 1);
    toolbar->addWidget(upButton);
    toolbar->addWidget(refreshButton);
    outer->addLayout(toolbar);

    m_model = new QFileSystemModel(this);
    m_model->setFilter(QDir::AllEntries | QDir::NoDotAndDotDot);
    m_model->setReadOnly(true);

    m_view = new QTreeView(this);
    m_view->setModel(m_model);
    m_view->setAlternatingRowColors(true);
    m_view->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_view->setSortingEnabled(true);
    m_view->sortByColumn(0, Qt::AscendingOrder);
    m_view->header()->setStretchLastSection(false);
    m_view->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    for (int column = 1; column < 4; ++column)
        m_view->header()->setSectionResizeMode(column, QHeaderView::ResizeToContents);
    outer->addWidget(m_view, 1);

    connect(upButton, &QPushButton::clicked,
            this, &SandboxFileExplorer::navigateUp);
    connect(refreshButton, &QPushButton::clicked,
            this, &SandboxFileExplorer::refresh);
    connect(m_view, &QTreeView::doubleClicked,
            this, &SandboxFileExplorer::onActivated);
}

void SandboxFileExplorer::showForPath(const QString& selectedPath)
{
    const QFileInfo info(QDir::cleanPath(selectedPath));
    QString directory;
    if (info.exists() && info.isDir())
        directory = info.absoluteFilePath();
    else
        directory = info.absolutePath();

    if (directory.isEmpty() || !QDir(directory).exists())
        return;

    navigateTo(directory, info.isFile() ? info.absoluteFilePath() : QString());
    showNormal();
    raise();
    activateWindow();
}

void SandboxFileExplorer::navigateTo(const QString& directory,
                                     const QString& selectedPath)
{
    m_currentDirectory = QDir(directory).absolutePath();
    m_selectedPath = selectedPath;
    m_address->setText(QDir::toNativeSeparators(m_currentDirectory));
    setWindowTitle(QStringLiteral("Sandbox Downloads — %1")
                       .arg(QFileInfo(m_currentDirectory).fileName()));

    const QModelIndex root = m_model->setRootPath(m_currentDirectory);
    m_view->setRootIndex(root);

    if (!m_selectedPath.isEmpty()) {
        QTimer::singleShot(0, this, [this] {
            const QModelIndex selected = m_model->index(m_selectedPath);
            if (!selected.isValid())
                return;
            m_view->setCurrentIndex(selected);
            m_view->scrollTo(selected, QAbstractItemView::PositionAtCenter);
        });
    }
}

void SandboxFileExplorer::onActivated(const QModelIndex& index)
{
    if (!index.isValid())
        return;
    const QFileInfo info = m_model->fileInfo(index);
    if (info.isDir()) {
        navigateTo(info.absoluteFilePath());
    } else if (info.isFile()) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(info.absoluteFilePath()));
    }
}

void SandboxFileExplorer::navigateUp()
{
    QDir directory(m_currentDirectory);
    if (directory.cdUp())
        navigateTo(directory.absolutePath());
}

void SandboxFileExplorer::refresh()
{
    if (m_currentDirectory.isEmpty())
        return;
    const QString current = m_currentDirectory;
    m_model->setRootPath(QString());
    navigateTo(current, m_selectedPath);
}
