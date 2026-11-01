#pragma once

#include <QWidget>
#include <functional>
#include <optional>

#include "xrl/workspace.hpp"

class QLineEdit;
class QLabel;
class QListWidget;
class QModelIndex;
class QPlainTextEdit;
class QPushButton;
class QSplitter;
class QTableWidget;
class QTabWidget;
class QTimer;

namespace xrl::ui {

class WorkspaceWidget final : public QWidget {
    Q_OBJECT
public:
    using PersistFn = std::function<bool(const xrl::WorkspaceData&, bool, QString*)>;

    WorkspaceWidget(xrl::WorkspaceData& data, PersistFn persist, QWidget* parent = nullptr);
    void refresh(const QString& selectProjectId = {});
    void setStorageError(const QString& error);
    void clearStorageError();
    void setLoadedFile(const xrl::WorkspaceFile& file);
    void clearLoadedFile();

signals:
    void openFileRequested(const QString& path, const QString& expectedHash,
                           qulonglong addressOrOffset, const QString& locationKind);
    void addFileRequested(const QString& path);
    void projectActivated(const QString& projectId);
    void statusMessage(const QString& message, bool error);

private:
    xrl::WorkspaceData& data_;
    PersistFn persist_;
    std::optional<xrl::WorkspaceFile> loadedFile_;

    QListWidget* projects_ = nullptr;
    QLineEdit* projectSearch_ = nullptr;
    QLineEdit* detailSearch_ = nullptr;
    QLineEdit* projectName_ = nullptr;
    QLineEdit* projectCategory_ = nullptr;
    QPlainTextEdit* projectDescription_ = nullptr;
    QTabWidget* detailTabs_ = nullptr;
    QTableWidget* files_ = nullptr;
    QTableWidget* bookmarks_ = nullptr;
    QTableWidget* notes_ = nullptr;
    QTableWidget* history_ = nullptr;
    QTableWidget* comparisons_ = nullptr;
    QTableWidget* tags_ = nullptr;
    QLabel* projectSummary_ = nullptr;
    QLabel* storageStatus_ = nullptr;
    QPushButton* addLoadedButton_ = nullptr;
    QTimer* detailFilterTimer_ = nullptr;

    QWidget* buildProjectList();
    QWidget* buildProjectDetails();
    void refreshProjects(const QString& preferredId = {});
    void refreshDetails();
    void onProjectSelected(int row);
    void filterActiveTable(const QString& query);
    bool commit(xrl::WorkspaceData candidate, const QString& selectedId = {}, bool recover = false);
    xrl::WorkspaceProject* selectedProject();
    const xrl::WorkspaceProject* selectedProject() const;
    QString selectedProjectId() const;
    QString selectedFileId(const QTableWidget* table) const;
    QString selectedEntryId(const QTableWidget* table) const;
    void createProject();
    void renameProject();
    void duplicateProject();
    void deleteProject();
    void addCurrentFile();
    void removeSelectedFile();
    void locateSelectedFile();
    void addBookmark();
    void navigateBookmark(const QModelIndex& index);
    void addNote();
    void editNote();
    void deleteNote();
    void openAnalysisReport(const QModelIndex& index);
    void deleteAnalysis();
    void openComparisonReport(const QModelIndex& index);
    void deleteComparison();
    void addTag();
    void renameTag();
    void deleteTag();
    void backupWorkspace();
    void restoreWorkspace();
};

}  // namespace xrl::ui
