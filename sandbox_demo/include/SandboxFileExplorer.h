#pragma once

#include <QWidget>
#include <QStringList>

#include <memory>

class QFileSystemModel;
class QAbstractItemView;
class QModelIndex;
class QPoint;

namespace Ui {
class SandboxFileExplorer;
}

class SandboxFileExplorer : public QWidget {
    Q_OBJECT
public:
    explicit SandboxFileExplorer(QWidget* parent = nullptr);
    ~SandboxFileExplorer() override;

    void showForPath(const QString& selectedPath,
                     const QString& boxName,
                     const QString& boxRoot);
    void releasePath(const QString& rootPath);

signals:
    void openRequested(const QString& filePath);
    void statusMessageRequested(const QString& message);

private slots:
    void onDirectorySelected(const QModelIndex& current,
                             const QModelIndex& previous);
    void onContentActivated(const QModelIndex& index);
    void navigateUp();
    void refresh();
    void showDetailsView();
    void showTilesView();
    void showContextMenu(const QPoint& position);

private:
    enum class TransferMode {
        None,
        Copy,
        Move
    };

    void initializeModels();
    void navigateTo(const QString& directory, const QString& selectedPath = {});
    void selectDirectoryInTree(const QString& directory);
    void openPath(const QString& path);
    void cutSelection(const QStringList& paths);
    void copySelection(const QStringList& paths);
    void pasteIntoCurrentDirectory();
    void importFilesIntoCurrentDirectory();
    void importFolderIntoCurrentDirectory();
    void renameSelection(const QStringList& paths);
    void showProperties(const QStringList& paths);
    void deleteSelection(const QStringList& paths);

    QAbstractItemView* activeContentView() const;
    QStringList selectedPaths(QAbstractItemView* view) const;
    QString pathForIndex(const QModelIndex& index, bool directoryModel) const;
    QString currentDirectory() const;
    QString uniqueDestinationPath(const QString& directory,
                                  const QString& sourcePath) const;
    bool copyPathRecursive(const QString& source,
                           const QString& destination,
                           QString* errorMessage) const;
    bool removePath(const QString& path, QString* errorMessage) const;
    bool movePath(const QString& source,
                  const QString& destination,
                  QString* errorMessage) const;
    bool canUsePath(const QString& path) const;
    bool canModifyPath(const QString& path) const;
    bool isPathInsideBox(const QString& path) const;
    bool isDestinationInsideBox(const QString& path) const;
    bool isSameOrChildPath(const QString& path, const QString& parent) const;
    bool isReparsePoint(const QString& path) const;
    void clearTransfer();
    void setStatus(const QString& message) const;
    void showError(const QString& title, const QString& message) const;

    std::unique_ptr<Ui::SandboxFileExplorer> m_ui;
    QFileSystemModel* m_directoryModel = nullptr;
    QFileSystemModel* m_contentModel = nullptr;
    QString m_boxName;
    QString m_boxRoot;
    QString m_boxRootCanonical;
    QString m_currentDirectory;
    QString m_selectedPath;
    TransferMode m_transferMode = TransferMode::None;
    QStringList m_transferPaths;
};
