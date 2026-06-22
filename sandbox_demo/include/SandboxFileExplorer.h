#pragma once

#include <QWidget>

class QFileSystemModel;
class QLineEdit;
class QModelIndex;
class QTreeView;

class SandboxFileExplorer : public QWidget {
    Q_OBJECT
public:
    explicit SandboxFileExplorer(QWidget* parent = nullptr);

    void showForPath(const QString& selectedPath);
    void releasePath(const QString& rootPath);

private slots:
    void onActivated(const QModelIndex& index);
    void navigateUp();
    void refresh();

private:
    void navigateTo(const QString& directory, const QString& selectedPath = {});

    QFileSystemModel* m_model = nullptr;
    QTreeView* m_view = nullptr;
    QLineEdit* m_address = nullptr;
    QString m_currentDirectory;
    QString m_selectedPath;
};
