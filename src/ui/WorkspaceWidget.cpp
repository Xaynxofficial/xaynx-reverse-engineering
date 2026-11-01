#include "WorkspaceWidget.hpp"

#include <QDateTime>
#include <QDialog>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSaveFile>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <algorithm>
#include <unordered_map>

#include "UiUtil.hpp"

namespace xrl::ui {
namespace {

QTableWidget* makeTable(const QStringList& headers) {
    auto* table = new QTableWidget(0, static_cast<int>(headers.size()));
    table->setHorizontalHeaderLabels(headers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setAlternatingRowColors(true);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setStretchLastSection(true);
    table->horizontalHeader()->setSectionsMovable(true);
    table->horizontalHeader()->setResizeContentsPrecision(100);
    table->setSortingEnabled(true);
    return table;
}

QPushButton* makeButton(const QString& text, QWidget* parent = nullptr) {
    return new QPushButton(text, parent);
}

QWidget* buttonRow(std::initializer_list<QPushButton*> buttons) {
    auto* row = new QWidget;
    auto* layout = new QHBoxLayout(row);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);
    for (auto* button : buttons) layout->addWidget(button);
    layout->addStretch(1);
    return row;
}

QString text(const std::string& value) {
    return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
}

QString shortHash(const std::string& hash) {
    const QString value = text(hash);
    return value.size() > 20 ? value.left(12) + QStringLiteral("…") + value.right(6) : value;
}

QString timestampNow() {
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
}

std::vector<std::string> splitTags(const QString& value) {
    std::vector<std::string> tags;
    for (const QString& tag : value.split(',', Qt::SkipEmptyParts)) {
        const QString trimmed = tag.trimmed();
        if (!trimmed.isEmpty()) {
            const auto utf8 = trimmed.toUtf8();
            const std::string item(utf8.constData(), static_cast<size_t>(utf8.size()));
            if (std::find(tags.begin(), tags.end(), item) == tags.end()) tags.push_back(item);
        }
    }
    return tags;
}

QString joinTags(const std::vector<std::string>& values) {
    QStringList tags;
    for (const auto& value : values) tags.push_back(text(value));
    return tags.join(QStringLiteral(", "));
}

QTableWidgetItem* item(const QString& value, const QString& id = {}) {
    auto* result = new QTableWidgetItem(value);
    if (!id.isEmpty()) result->setData(Qt::UserRole, id);
    return result;
}

QString fileNameFromPath(const std::string& path) {
    return QFileInfo(text(path)).fileName();
}

void showReport(QWidget* parent, const QString& title, const std::string& reportJson) {
    QDialog dialog(parent);
    dialog.setWindowTitle(title);
    dialog.resize(780, 560);
    auto* layout = new QVBoxLayout(&dialog);
    auto* report = new QPlainTextEdit(&dialog);
    report->setReadOnly(true);
    report->setLineWrapMode(QPlainTextEdit::NoWrap);
    report->setPlainText(text(reportJson));
    layout->addWidget(report, 1);
    auto* buttons = new QHBoxLayout;
    auto* save = makeButton(QObject::tr("Export report…"), &dialog);
    auto* close = makeButton(QObject::tr("Close"), &dialog);
    buttons->addWidget(save);
    buttons->addStretch(1);
    buttons->addWidget(close);
    layout->addLayout(buttons);
    QObject::connect(save, &QPushButton::clicked, &dialog, [&] {
        const QString path = QFileDialog::getSaveFileName(&dialog, QObject::tr("Export saved analysis report"),
                                                          {}, QObject::tr("JSON (*.json)"));
        if (path.isEmpty()) return;
        QSaveFile file(path);
        const QByteArray bytes = reportJson.data() ? QByteArray(reportJson.data(), static_cast<qsizetype>(reportJson.size()))
                                                   : QByteArray();
        if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit()) {
            QMessageBox::warning(&dialog, QObject::tr("Export failed"),
                                 QObject::tr("Could not save the report. Check the destination and permissions."));
        }
    });
    QObject::connect(close, &QPushButton::clicked, &dialog, &QDialog::accept);
    dialog.exec();
}

WorkspaceProject cloneImportedProject(const WorkspaceProject& source) {
    WorkspaceProject result = source;
    result.id = makeWorkspaceId();
    result.name += " (restored)";
    result.createdAt = timestampNow().toStdString();
    result.modifiedAt = result.createdAt;
    result.version = 1;
    result.session = {};
    std::unordered_map<std::string, std::string> remap;
    for (auto& file : result.files) {
        const auto oldId = file.id;
        file.id = makeWorkspaceId();
        remap.emplace(oldId, file.id);
    }
    auto remapFile = [&](std::string& id) {
        if (id.empty()) return;
        const auto found = remap.find(id);
        id = found == remap.end() ? std::string{} : found->second;
    };
    for (auto& record : result.analyses) {
        record.id = makeWorkspaceId();
        remapFile(record.fileId);
    }
    for (auto& record : result.bookmarks) {
        record.id = makeWorkspaceId();
        remapFile(record.fileId);
    }
    for (auto& record : result.notes) {
        record.id = makeWorkspaceId();
        remapFile(record.fileId);
    }
    for (auto& record : result.comparisons) {
        record.id = makeWorkspaceId();
        remapFile(record.fileAId);
        remapFile(record.fileBId);
    }
    return result;
}

}  // namespace

WorkspaceWidget::WorkspaceWidget(WorkspaceData& data, PersistFn persist, QWidget* parent)
    : QWidget(parent), data_(data), persist_(std::move(persist)) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(24, 20, 24, 16);
    root->setSpacing(12);
    auto* heading = new QLabel(tr("Analysis Workspace"));
    heading->setObjectName("pageTitle");
    root->addWidget(heading);
    storageStatus_ = new QLabel(tr("Local workspace metadata is stored on this device. Source binaries remain at their original paths."));
    storageStatus_->setProperty("muted", true);
    storageStatus_->setWordWrap(true);
    root->addWidget(storageStatus_);

    auto* splitter = new QSplitter(Qt::Horizontal, this);
    splitter->setChildrenCollapsible(false);
    splitter->addWidget(buildProjectList());
    splitter->addWidget(buildProjectDetails());
    splitter->setStretchFactor(0, 0);
    splitter->setStretchFactor(1, 1);
    splitter->setSizes({260, 850});
    root->addWidget(splitter, 1);

    connect(projectSearch_, &QLineEdit::textChanged, this, [this](const QString& query) {
        const QString needle = query.trimmed();
        for (int row = 0; row < projects_->count(); ++row)
            projects_->item(row)->setHidden(!projects_->item(row)->text().contains(needle, Qt::CaseInsensitive));
    });
    connect(projects_, &QListWidget::currentRowChanged, this, &WorkspaceWidget::onProjectSelected);
    detailFilterTimer_ = new QTimer(this);
    detailFilterTimer_->setSingleShot(true);
    detailFilterTimer_->setInterval(120);
    connect(detailFilterTimer_, &QTimer::timeout, this,
            [this] { filterActiveTable(detailSearch_->text()); });
    connect(detailSearch_, &QLineEdit::textChanged, detailFilterTimer_,
            qOverload<>(&QTimer::start));
    connect(detailTabs_, &QTabWidget::currentChanged, this, [this] { filterActiveTable(detailSearch_->text()); });
    refresh();
}

QWidget* WorkspaceWidget::buildProjectList() {
    auto* panel = new QWidget;
    auto* layout = new QVBoxLayout(panel);
    layout->setContentsMargins(0, 0, 12, 0);
    layout->setSpacing(8);
    projectSearch_ = new QLineEdit;
    projectSearch_->setPlaceholderText(tr("Search projects"));
    layout->addWidget(projectSearch_);
    projects_ = new QListWidget;
    projects_->setObjectName("workspaceProjects");
    layout->addWidget(projects_, 1);
    auto* create = makeButton(tr("New Project"));
    auto* rename = makeButton(tr("Rename"));
    auto* duplicate = makeButton(tr("Duplicate"));
    auto* remove = makeButton(tr("Delete"));
    auto* first = new QHBoxLayout;
    first->addWidget(create);
    first->addWidget(rename);
    layout->addLayout(first);
    auto* second = new QHBoxLayout;
    second->addWidget(duplicate);
    second->addWidget(remove);
    layout->addLayout(second);
    auto* backup = makeButton(tr("Back up workspace…"));
    auto* restore = makeButton(tr("Restore backup…"));
    layout->addWidget(backup);
    layout->addWidget(restore);
    connect(create, &QPushButton::clicked, this, &WorkspaceWidget::createProject);
    connect(rename, &QPushButton::clicked, this, &WorkspaceWidget::renameProject);
    connect(duplicate, &QPushButton::clicked, this, &WorkspaceWidget::duplicateProject);
    connect(remove, &QPushButton::clicked, this, &WorkspaceWidget::deleteProject);
    connect(backup, &QPushButton::clicked, this, &WorkspaceWidget::backupWorkspace);
    connect(restore, &QPushButton::clicked, this, &WorkspaceWidget::restoreWorkspace);
    return panel;
}

QWidget* WorkspaceWidget::buildProjectDetails() {
    auto* panel = new QWidget;
    auto* layout = new QVBoxLayout(panel);
    layout->setContentsMargins(12, 0, 0, 0);
    layout->setSpacing(8);
    auto* nameRow = new QHBoxLayout;
    projectName_ = new QLineEdit;
    projectName_->setPlaceholderText(tr("Project name"));
    projectCategory_ = new QLineEdit;
    projectCategory_->setPlaceholderText(tr("Category"));
    nameRow->addWidget(projectName_, 2);
    nameRow->addWidget(projectCategory_, 1);
    layout->addLayout(nameRow);
    projectDescription_ = new QPlainTextEdit;
    projectDescription_->setMaximumHeight(70);
    projectDescription_->setPlaceholderText(tr("Project description and investigation context"));
    layout->addWidget(projectDescription_);
    auto* detailsRow = new QHBoxLayout;
    projectSummary_ = new QLabel;
    projectSummary_->setProperty("muted", true);
    projectSummary_->setWordWrap(true);
    detailsRow->addWidget(projectSummary_, 1);
    auto* saveDetails = makeButton(tr("Save project details"));
    detailsRow->addWidget(saveDetails);
    layout->addLayout(detailsRow);
    auto* actionRow = new QHBoxLayout;
    addLoadedButton_ = makeButton(tr("Add current binary"));
    auto* addFile = makeButton(tr("Add binary…"));
    auto* removeFile = makeButton(tr("Remove file reference"));
    auto* locateFile = makeButton(tr("Locate missing file…"));
    actionRow->addWidget(addLoadedButton_);
    actionRow->addWidget(addFile);
    actionRow->addWidget(removeFile);
    actionRow->addWidget(locateFile);
    actionRow->addStretch(1);
    layout->addLayout(actionRow);

    detailTabs_ = new QTabWidget;
    files_ = makeTable({tr("File"), tr("Path"), tr("SHA-256"), tr("Format"), tr("Architecture"), tr("Size"), tr("Availability")});
    bookmarks_ = makeTable({tr("Title"), tr("Type"), tr("Address"), tr("File offset"), tr("File"), tr("Tags")});
    notes_ = makeTable({tr("Title"), tr("Scope"), tr("File"), tr("Updated"), tr("Tags")});
    history_ = makeTable({tr("Type"), tr("File"), tr("Date"), tr("Status"), tr("Summary")});
    comparisons_ = makeTable({tr("File A"), tr("File B"), tr("Date"), tr("Summary")});
    tags_ = makeTable({tr("Tag"), tr("Color")});
    detailTabs_->addTab(files_, tr("Files"));
    detailTabs_->addTab(history_, tr("Analysis history"));
    detailTabs_->addTab(comparisons_, tr("Comparisons"));
    detailTabs_->addTab(bookmarks_, tr("Bookmarks"));
    detailTabs_->addTab(notes_, tr("Notes"));
    detailTabs_->addTab(tags_, tr("Tags"));
    layout->addWidget(detailTabs_, 1);
    detailSearch_ = new QLineEdit;
    detailSearch_->setPlaceholderText(tr("Filter rows in the selected tab"));
    layout->addWidget(detailSearch_);

    auto* noteButtons = buttonRow({makeButton(tr("Add note")), makeButton(tr("Edit note")), makeButton(tr("Delete note"))});
    auto* bookmarkButtons = buttonRow({makeButton(tr("Add bookmark…")), makeButton(tr("Open bookmark"))});
    auto* historyButtons = buttonRow({makeButton(tr("View / export report")), makeButton(tr("Delete entry"))});
    auto* comparisonButtons = buttonRow({makeButton(tr("View / export comparison")), makeButton(tr("Delete comparison"))});
    auto* tagButtons = buttonRow({makeButton(tr("Add tag")), makeButton(tr("Rename tag")), makeButton(tr("Delete tag"))});
    layout->addWidget(noteButtons);
    layout->addWidget(bookmarkButtons);
    layout->addWidget(historyButtons);
    layout->addWidget(comparisonButtons);
    layout->addWidget(tagButtons);

    connect(saveDetails, &QPushButton::clicked, this, [this] {
        auto candidate = data_;
        auto* project = findWorkspaceProject(candidate, selectedProjectId().toStdString());
        if (!project) return;
        project->name = projectName_->text().trimmed().toStdString();
        project->category = projectCategory_->text().trimmed().toStdString();
        project->description = projectDescription_->toPlainText().toStdString();
        if (project->name.empty()) {
            QMessageBox::warning(this, tr("Project name required"), tr("Enter a name before saving project details."));
            return;
        }
        project->modifiedAt = timestampNow().toStdString();
        commit(std::move(candidate), selectedProjectId());
    });
    connect(addLoadedButton_, &QPushButton::clicked, this, &WorkspaceWidget::addCurrentFile);
    connect(addFile, &QPushButton::clicked, this, [this] {
        const QString path = QFileDialog::getOpenFileName(this, tr("Select a binary to add to this project"));
        if (!path.isEmpty()) emit addFileRequested(path);
    });
    connect(removeFile, &QPushButton::clicked, this, &WorkspaceWidget::removeSelectedFile);
    connect(locateFile, &QPushButton::clicked, this, &WorkspaceWidget::locateSelectedFile);
    connect(files_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (row < 0 || row >= files_->rowCount()) return;
        const auto* project = selectedProject();
        if (!project) return;
        const QString fileId = files_->item(row, 0)->data(Qt::UserRole).toString();
        const auto* file = findWorkspaceFile(*project, fileId.toStdString());
        if (file) emit openFileRequested(text(file->path), text(file->sha256), 0, {});
    });
    connect(bookmarks_, &QTableWidget::cellDoubleClicked, this,
            [this](int row, int column) { navigateBookmark(bookmarks_->model()->index(row, column)); });
    connect(notes_, &QTableWidget::cellDoubleClicked, this,
            [this](int, int) { editNote(); });
    connect(history_, &QTableWidget::cellDoubleClicked, this,
            [this](int row, int column) { openAnalysisReport(history_->model()->index(row, column)); });
    connect(comparisons_, &QTableWidget::cellDoubleClicked, this,
            [this](int row, int column) { openComparisonReport(comparisons_->model()->index(row, column)); });

    auto* noteAdd = noteButtons->findChildren<QPushButton*>().value(0);
    auto* noteEdit = noteButtons->findChildren<QPushButton*>().value(1);
    auto* noteDelete = noteButtons->findChildren<QPushButton*>().value(2);
    connect(noteAdd, &QPushButton::clicked, this, &WorkspaceWidget::addNote);
    connect(noteEdit, &QPushButton::clicked, this, &WorkspaceWidget::editNote);
    connect(noteDelete, &QPushButton::clicked, this, &WorkspaceWidget::deleteNote);
    auto* bookmarkAdd = bookmarkButtons->findChildren<QPushButton*>().value(0);
    auto* bookmarkOpen = bookmarkButtons->findChildren<QPushButton*>().value(1);
    connect(bookmarkAdd, &QPushButton::clicked, this, &WorkspaceWidget::addBookmark);
    connect(bookmarkOpen, &QPushButton::clicked, this, [this] {
        navigateBookmark(bookmarks_->currentIndex());
    });
    auto* historyOpen = historyButtons->findChildren<QPushButton*>().value(0);
    auto* historyDelete = historyButtons->findChildren<QPushButton*>().value(1);
    connect(historyOpen, &QPushButton::clicked, this, [this] { openAnalysisReport(history_->currentIndex()); });
    connect(historyDelete, &QPushButton::clicked, this, &WorkspaceWidget::deleteAnalysis);
    auto* comparisonOpen = comparisonButtons->findChildren<QPushButton*>().value(0);
    auto* comparisonDelete = comparisonButtons->findChildren<QPushButton*>().value(1);
    connect(comparisonOpen, &QPushButton::clicked, this,
            [this] { openComparisonReport(comparisons_->currentIndex()); });
    connect(comparisonDelete, &QPushButton::clicked, this, &WorkspaceWidget::deleteComparison);
    auto* tagAdd = tagButtons->findChildren<QPushButton*>().value(0);
    auto* tagRename = tagButtons->findChildren<QPushButton*>().value(1);
    auto* tagDelete = tagButtons->findChildren<QPushButton*>().value(2);
    connect(tagAdd, &QPushButton::clicked, this, &WorkspaceWidget::addTag);
    connect(tagRename, &QPushButton::clicked, this, &WorkspaceWidget::renameTag);
    connect(tagDelete, &QPushButton::clicked, this, &WorkspaceWidget::deleteTag);
    return panel;
}

void WorkspaceWidget::refresh(const QString& selectProjectId) {
    refreshProjects(selectProjectId);
    refreshDetails();
}

void WorkspaceWidget::setStorageError(const QString& error) {
    storageStatus_->setProperty("error", true);
    storageStatus_->setText(tr("Saved workspace data could not be opened: %1. Existing data is preserved. Restore a valid backup to recover.")
                                .arg(error));
}

void WorkspaceWidget::clearStorageError() {
    storageStatus_->setProperty("error", false);
    storageStatus_->setText(tr("Local workspace metadata is stored on this device. Source binaries remain at their original paths."));
}

void WorkspaceWidget::refreshProjects(const QString& preferredId) {
    const QString wanted = preferredId.isEmpty() ? selectedProjectId() : preferredId;
    projects_->blockSignals(true);
    projects_->clear();
    std::vector<const WorkspaceProject*> sorted;
    sorted.reserve(data_.projects.size());
    for (const auto& project : data_.projects) sorted.push_back(&project);
    std::stable_sort(sorted.begin(), sorted.end(), [](const auto* a, const auto* b) {
        return a->modifiedAt > b->modifiedAt;
    });
    int selectedRow = -1;
    for (const auto* project : sorted) {
        auto* entry = new QListWidgetItem(text(project->name), projects_);
        entry->setData(Qt::UserRole, text(project->id));
        entry->setToolTip(text(project->description));
        if (text(project->id) == wanted) selectedRow = projects_->row(entry);
    }
    if (selectedRow < 0 && !data_.lastActiveProjectId.empty()) {
        for (int row = 0; row < projects_->count(); ++row)
            if (projects_->item(row)->data(Qt::UserRole).toString() == text(data_.lastActiveProjectId))
                selectedRow = row;
    }
    if (selectedRow < 0 && projects_->count() > 0) selectedRow = 0;
    projects_->setCurrentRow(selectedRow);
    projects_->blockSignals(false);
    if (selectedRow >= 0) data_.lastActiveProjectId = projects_->currentItem()->data(Qt::UserRole).toString().toStdString();
}

void WorkspaceWidget::refreshDetails() {
    const auto* project = selectedProject();
    const bool enabled = project != nullptr;
    projectName_->setEnabled(enabled);
    projectCategory_->setEnabled(enabled);
    projectDescription_->setEnabled(enabled);
    if (!project) {
        projectName_->clear();
        projectCategory_->clear();
        projectDescription_->clear();
        projectSummary_->setText(tr("Create or open a project to organize files and investigation notes."));
        for (auto* table : {files_, bookmarks_, notes_, history_, comparisons_, tags_}) table->setRowCount(0);
        addLoadedButton_->setEnabled(false);
        return;
    }
    projectName_->setText(text(project->name));
    projectCategory_->setText(text(project->category));
    projectDescription_->setPlainText(text(project->description));
    projectSummary_->setText(tr("Created %1 · Updated %2 · %3 file(s) · %4 analyses · %5 bookmarks · %6 notes")
                                 .arg(text(project->createdAt), text(project->modifiedAt))
                                 .arg(project->files.size()).arg(project->analyses.size())
                                 .arg(project->bookmarks.size()).arg(project->notes.size()));
    auto reset = [](QTableWidget* table) {
        table->setSortingEnabled(false);
        table->setRowCount(0);
    };
    for (auto* table : {files_, bookmarks_, notes_, history_, comparisons_, tags_}) reset(table);
    for (const auto& file : project->files) {
        const int row = files_->rowCount();
        files_->insertRow(row);
        const QFileInfo pathInfo(text(file.path));
        QString availability = pathInfo.exists() ? tr("Path exists; hash checked on open") : tr("Missing — locate to reopen");
        if (pathInfo.exists() && pathInfo.size() >= 0 &&
            static_cast<uint64_t>(pathInfo.size()) != file.size)
            availability = tr("Size changed — verify hash before use");
        files_->setItem(row, 0, item(pathInfo.fileName().isEmpty() ? text(file.path) : pathInfo.fileName(), text(file.id)));
        files_->setItem(row, 1, item(text(file.path)));
        files_->setItem(row, 2, item(shortHash(file.sha256)));
        files_->setItem(row, 3, item(text(file.format)));
        files_->setItem(row, 4, item(text(file.architecture)));
        files_->setItem(row, 5, item(QString::number(file.size)));
        files_->setItem(row, 6, item(availability));
    }
    for (const auto& bookmark : project->bookmarks) {
        const auto* file = findWorkspaceFile(*project, bookmark.fileId);
        const int row = bookmarks_->rowCount();
        bookmarks_->insertRow(row);
        bookmarks_->setItem(row, 0, item(text(bookmark.title), text(bookmark.id)));
        const bool stale = file && !bookmark.fileHash.empty() && bookmark.fileHash != file->sha256;
        bookmarks_->setItem(row, 1, item(text(bookmark.kind) + (stale ? tr(" · stale file version") : QString())));
        bookmarks_->setItem(row, 2, item(bookmark.address ? QStringLiteral("0x%1").arg(*bookmark.address, 0, 16) : QString()));
        bookmarks_->setItem(row, 3, item(bookmark.fileOffset ? QStringLiteral("0x%1").arg(*bookmark.fileOffset, 0, 16) : QString()));
        bookmarks_->setItem(row, 4, item(file ? fileNameFromPath(file->path) : tr("(file removed)")));
        bookmarks_->setItem(row, 5, item(joinTags(bookmark.tags)));
    }
    for (const auto& note : project->notes) {
        const auto* file = findWorkspaceFile(*project, note.fileId);
        const int row = notes_->rowCount();
        notes_->insertRow(row);
        notes_->setItem(row, 0, item(text(note.title), text(note.id)));
        const bool stale = file && !note.fileHash.empty() && note.fileHash != file->sha256;
        notes_->setItem(row, 1, item(text(note.scope) + (stale ? tr(" · stale file version") : QString())));
        notes_->setItem(row, 2, item(file ? fileNameFromPath(file->path) : tr("Project")));
        notes_->setItem(row, 3, item(text(note.modifiedAt)));
        notes_->setItem(row, 4, item(joinTags(note.tags)));
    }
    for (const auto& analysis : project->analyses) {
        const auto* file = findWorkspaceFile(*project, analysis.fileId);
        const int row = history_->rowCount();
        history_->insertRow(row);
        history_->setItem(row, 0, item(text(analysis.type), text(analysis.id)));
        history_->setItem(row, 1, item(file ? fileNameFromPath(file->path) : tr("(file removed)")));
        history_->setItem(row, 2, item(text(analysis.timestamp)));
        const bool stale = file && !analysis.fileHash.empty() && analysis.fileHash != file->sha256;
        history_->setItem(row, 3, item(text(analysis.status) + (stale ? tr(" · old file hash") : QString())));
        history_->setItem(row, 4, item(text(analysis.summary)));
    }
    for (const auto& comparison : project->comparisons) {
        const auto* fileA = findWorkspaceFile(*project, comparison.fileAId);
        const auto* fileB = findWorkspaceFile(*project, comparison.fileBId);
        const int row = comparisons_->rowCount();
        comparisons_->insertRow(row);
        comparisons_->setItem(row, 0, item(fileA ? fileNameFromPath(fileA->path) : shortHash(comparison.fileAHash),
                                          text(comparison.id)));
        comparisons_->setItem(row, 1, item(fileB ? fileNameFromPath(fileB->path) : shortHash(comparison.fileBHash)));
        comparisons_->setItem(row, 2, item(text(comparison.timestamp)));
        comparisons_->setItem(row, 3, item(text(comparison.summary)));
    }
    for (const auto& tag : project->tags) {
        const int row = tags_->rowCount();
        tags_->insertRow(row);
        tags_->setItem(row, 0, item(text(tag.name)));
        tags_->setItem(row, 1, item(text(tag.color)));
    }
    for (auto* table : {files_, bookmarks_, notes_, history_, comparisons_, tags_}) {
        table->setSortingEnabled(true);
        table->resizeColumnsToContents();
    }
    addLoadedButton_->setEnabled(loadedFile_.has_value());
    filterActiveTable(detailSearch_->text());
}

void WorkspaceWidget::onProjectSelected(int row) {
    if (row < 0 || !projects_->currentItem()) {
        refreshDetails();
        return;
    }
    const QString id = projects_->currentItem()->data(Qt::UserRole).toString();
    auto candidate = data_;
    candidate.lastActiveProjectId = id.toStdString();
    if (auto* project = findWorkspaceProject(candidate, id.toStdString()); project && !project->files.empty()) {
        const auto selected = std::find_if(project->files.begin(), project->files.end(), [&](const WorkspaceFile& file) {
            return file.id == project->session.selectedFileId;
        });
        if (selected == project->files.end()) project->session.selectedFileId = project->files.front().id;
    }
    const auto* oldProject = findWorkspaceProject(data_, id.toStdString());
    const auto* newProject = findWorkspaceProject(candidate, id.toStdString());
    const bool sessionChanged = oldProject && newProject &&
                                oldProject->session.selectedFileId != newProject->session.selectedFileId;
    if (candidate.lastActiveProjectId != data_.lastActiveProjectId || sessionChanged) {
        if (persist_) {
            QString error;
            if (persist_(candidate, false, &error)) data_ = std::move(candidate);
            else {
                emit statusMessage(tr("Could not save workspace selection: %1").arg(error), true);
                refreshProjects(text(data_.lastActiveProjectId));
                refreshDetails();
                return;
            }
        } else {
            data_ = std::move(candidate);
        }
    }
    refreshDetails();
    emit projectActivated(id);
}

bool WorkspaceWidget::commit(WorkspaceData candidate, const QString& selectedId, bool recover) {
    QString error;
    if (persist_ && !persist_(candidate, recover, &error)) {
        QMessageBox::warning(this, tr("Workspace was not saved"),
                             tr("The change could not be committed to local storage.\n\n%1").arg(error));
        refresh(selectedId);
        return false;
    }
    data_ = std::move(candidate);
    refresh(selectedId);
    emit statusMessage(tr("Workspace saved locally."), false);
    return true;
}

WorkspaceProject* WorkspaceWidget::selectedProject() {
    return findWorkspaceProject(data_, selectedProjectId().toStdString());
}

const WorkspaceProject* WorkspaceWidget::selectedProject() const {
    return findWorkspaceProject(data_, selectedProjectId().toStdString());
}

QString WorkspaceWidget::selectedProjectId() const {
    return projects_ && projects_->currentItem() ? projects_->currentItem()->data(Qt::UserRole).toString() : QString();
}

QString WorkspaceWidget::selectedFileId(const QTableWidget* table) const {
    if (!table || !table->currentItem()) return {};
    const auto* first = table->item(table->currentRow(), 0);
    return first ? first->data(Qt::UserRole).toString() : QString();
}

QString WorkspaceWidget::selectedEntryId(const QTableWidget* table) const {
    return selectedFileId(table);
}

void WorkspaceWidget::filterActiveTable(const QString& query) {
    QTableWidget* table = nullptr;
    switch (detailTabs_->currentIndex()) {
        case 0: table = files_; break;
        case 1: table = history_; break;
        case 2: table = comparisons_; break;
        case 3: table = bookmarks_; break;
        case 4: table = notes_; break;
        case 5: table = tags_; break;
        default: break;
    }
    if (!table) return;
    for (int row = 0; row < table->rowCount(); ++row) {
        bool matches = query.trimmed().isEmpty();
        for (int column = 0; !matches && column < table->columnCount(); ++column)
            if (table->item(row, column) && table->item(row, column)->text().contains(query, Qt::CaseInsensitive))
                matches = true;
        table->setRowHidden(row, !matches);
    }
}

void WorkspaceWidget::createProject() {
    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("Create project"), tr("Project name"),
                                               QLineEdit::Normal, {}, &ok).trimmed();
    if (!ok) return;
    if (name.isEmpty()) {
        QMessageBox::warning(this, tr("Project name required"), tr("Enter a project name."));
        return;
    }
    auto candidate = data_;
    const auto id = createWorkspaceProject(candidate, name.toStdString());
    if (id.empty()) {
        QMessageBox::warning(this, tr("Project not created"), tr("The project name or project count is invalid."));
        return;
    }
    commit(std::move(candidate), text(id));
    emit projectActivated(text(id));
}

void WorkspaceWidget::renameProject() {
    const auto* project = selectedProject();
    if (!project) return;
    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("Rename project"), tr("Project name"),
                                               QLineEdit::Normal, text(project->name), &ok).trimmed();
    if (!ok) return;
    auto candidate = data_;
    if (!renameWorkspaceProject(candidate, selectedProjectId().toStdString(), name.toStdString())) {
        QMessageBox::warning(this, tr("Project not renamed"), tr("Enter a non-empty name of at most 512 bytes."));
        return;
    }
    commit(std::move(candidate), selectedProjectId());
}

void WorkspaceWidget::duplicateProject() {
    const auto* project = selectedProject();
    if (!project) return;
    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("Duplicate project"), tr("New project name"),
                                               QLineEdit::Normal, text(project->name) + tr(" Copy"), &ok).trimmed();
    if (!ok) return;
    auto candidate = data_;
    const auto id = duplicateWorkspaceProject(candidate, selectedProjectId().toStdString(), name.toStdString());
    if (!id) {
        QMessageBox::warning(this, tr("Project not duplicated"), tr("The project name or project count is invalid."));
        return;
    }
    commit(std::move(candidate), text(*id));
    emit projectActivated(text(*id));
}

void WorkspaceWidget::deleteProject() {
    const QString id = selectedProjectId();
    const auto* project = selectedProject();
    if (!project) return;
    if (QMessageBox::question(this, tr("Delete project"),
                              tr("Delete project “%1” and its local notes, bookmarks, and reports?\n\n"
                                 "Referenced source binaries are not deleted.")
                                  .arg(text(project->name))) != QMessageBox::Yes) return;
    auto candidate = data_;
    if (!deleteWorkspaceProject(candidate, id.toStdString())) return;
    commit(std::move(candidate));
}

void WorkspaceWidget::addCurrentFile() {
    const auto* project = selectedProject();
    if (!project || !loadedFile_) return;
    auto candidate = data_;
    auto* target = findWorkspaceProject(candidate, selectedProjectId().toStdString());
    const auto result = addWorkspaceFile(*target, *loadedFile_);
    if (!result) {
        QMessageBox::warning(this, tr("File not added"), tr("The file reference is invalid or the project reached its file limit."));
        return;
    }
    target->session.selectedFileId = *result;
    commit(std::move(candidate), selectedProjectId());
}

void WorkspaceWidget::removeSelectedFile() {
    const QString fileId = selectedFileId(files_);
    if (fileId.isEmpty()) return;
    const auto* project = selectedProject();
    const auto* file = project ? findWorkspaceFile(*project, fileId.toStdString()) : nullptr;
    if (!file) return;
    if (QMessageBox::question(this, tr("Remove file reference"),
                              tr("Remove “%1” and its project-specific analysis history, bookmarks, notes, and comparisons?\n\n"
                                 "The original binary on disk will not be deleted.")
                                  .arg(fileNameFromPath(file->path))) != QMessageBox::Yes) return;
    auto candidate = data_;
    auto* target = findWorkspaceProject(candidate, selectedProjectId().toStdString());
    removeWorkspaceFile(*target, fileId.toStdString());
    commit(std::move(candidate), selectedProjectId());
}

void WorkspaceWidget::locateSelectedFile() {
    const QString fileId = selectedFileId(files_);
    const auto* project = selectedProject();
    const auto* file = project ? findWorkspaceFile(*project, fileId.toStdString()) : nullptr;
    if (!file) return;
    const QString path = QFileDialog::getOpenFileName(this, tr("Locate the referenced binary"),
                                                       QFileInfo(text(file->path)).absolutePath(),
                                                       tr("All files (*)"));
    if (path.isEmpty()) return;
    emit openFileRequested(path, text(file->sha256), 0, {});
}

void WorkspaceWidget::addBookmark() {
    const auto* project = selectedProject();
    if (!project) return;
    const auto* file = findWorkspaceFile(*project, project->session.selectedFileId);
    if (!file && project->files.size() == 1) file = &project->files.front();
    if (!file) {
        QMessageBox::information(this, tr("Select a project file"),
                                 tr("Add or select a binary file in the Files tab before creating a bookmark."));
        return;
    }
    bool ok = false;
    const QString title = QInputDialog::getText(this, tr("Add bookmark"), tr("Bookmark title"),
                                                QLineEdit::Normal, {}, &ok).trimmed();
    if (!ok || title.isEmpty()) return;
    const QStringList kinds{tr("File offset"), tr("Virtual address"), tr("Function"),
                            tr("Basic block"), tr("String"), tr("XREF"), tr("Static finding"), tr("Diff region")};
    bool kindOk = false;
    const QString kind = QInputDialog::getItem(this, tr("Bookmark type"), tr("Location type"),
                                               kinds, 0, false, &kindOk);
    if (!kindOk) return;
    QString defaultAddress;
    if (loadedFile_ && loadedFile_->sha256 == file->sha256) {
        const auto* current = selectedProject();
        if (current && current->session.selectedAddress)
            defaultAddress = QStringLiteral("0x%1").arg(*current->session.selectedAddress, 0, 16);
    }
    const QString addressText = QInputDialog::getText(this, tr("Bookmark address"),
                                                       tr("Address or file offset (decimal or 0x-prefixed hex)"),
                                                       QLineEdit::Normal, defaultAddress, &ok).trimmed();
    if (!ok || addressText.isEmpty()) return;
    bool addressOk = false;
    const int base = addressText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ? 16 : 10;
    const auto address = addressText.toULongLong(&addressOk, base);
    if (!addressOk) {
        QMessageBox::warning(this, tr("Invalid address"), tr("Enter a valid non-negative address."));
        return;
    }
    const QString description = QInputDialog::getMultiLineText(this, tr("Bookmark description"),
                                                                tr("Description"), {}, &ok);
    if (!ok) return;
    const QString tagText = QInputDialog::getText(this, tr("Bookmark tags"), tr("Comma-separated tags"),
                                                   QLineEdit::Normal, {}, &ok);
    if (!ok) return;
    auto candidate = data_;
    auto* target = findWorkspaceProject(candidate, selectedProjectId().toStdString());
    WorkspaceBookmark bookmark;
    bookmark.id = makeWorkspaceId();
    bookmark.fileId = file->id;
    bookmark.fileHash = file->sha256;
    bookmark.title = title.toStdString();
    bookmark.description = description.toStdString();
    bookmark.kind = kind.toStdString();
    bookmark.address = address;
    if (kind == kinds.front()) {
        if (address >= file->size) {
            QMessageBox::warning(this, tr("Offset out of range"), tr("The file offset is outside the referenced file."));
            return;
        }
        bookmark.fileOffset = address;
    }
    bookmark.createdAt = timestampNow().toStdString();
    bookmark.tags = splitTags(tagText);
    target->bookmarks.push_back(std::move(bookmark));
    target->session.selectedFileId = file->id;
    target->session.selectedAddress = address;
    commit(std::move(candidate), selectedProjectId());
}

void WorkspaceWidget::navigateBookmark(const QModelIndex& index) {
    const auto* project = selectedProject();
    if (!project || !index.isValid()) return;
    const QString id = selectedEntryId(bookmarks_);
    const auto found = std::find_if(project->bookmarks.begin(), project->bookmarks.end(),
                                    [&](const WorkspaceBookmark& bookmark) { return bookmark.id == id.toStdString(); });
    if (found == project->bookmarks.end()) return;
    const auto* file = findWorkspaceFile(*project, found->fileId);
    if (!file) {
        emit statusMessage(tr("This bookmark no longer has a project file reference."), true);
        return;
    }
    if (!found->fileHash.empty() && found->fileHash != file->sha256) {
        emit statusMessage(tr("This bookmark belongs to a different file version. Create a new bookmark for the current hash before navigating."),
                           true);
        return;
    }
    const uint64_t target = found->fileOffset.value_or(found->address.value_or(0));
    emit openFileRequested(text(file->path), text(found->fileHash), target, text(found->kind));
}

void WorkspaceWidget::addNote() {
    const auto* project = selectedProject();
    if (!project) return;
    bool ok = false;
    const QString title = QInputDialog::getText(this, tr("New investigation note"), tr("Title"),
                                                QLineEdit::Normal, {}, &ok).trimmed();
    if (!ok || title.isEmpty()) return;
    const QString body = QInputDialog::getMultiLineText(this, tr("New investigation note"),
                                                        tr("Markdown note"), {}, &ok);
    if (!ok || body.isEmpty()) return;
    const QString tags = QInputDialog::getText(this, tr("Note tags"), tr("Comma-separated tags"),
                                                QLineEdit::Normal, {}, &ok);
    if (!ok) return;
    auto candidate = data_;
    auto* target = findWorkspaceProject(candidate, selectedProjectId().toStdString());
    const auto* file = findWorkspaceFile(*target, target->session.selectedFileId);
    WorkspaceNote note;
    note.id = makeWorkspaceId();
    note.scope = file ? "file" : "project";
    note.fileId = file ? file->id : std::string{};
    note.fileHash = file ? file->sha256 : std::string{};
    note.title = title.toStdString();
    note.markdown = body.toStdString();
    note.createdAt = timestampNow().toStdString();
    note.modifiedAt = note.createdAt;
    note.address = target->session.selectedAddress;
    note.tags = splitTags(tags);
    target->notes.push_back(std::move(note));
    commit(std::move(candidate), selectedProjectId());
}

void WorkspaceWidget::editNote() {
    const auto* project = selectedProject();
    const QString id = selectedEntryId(notes_);
    if (!project || id.isEmpty()) return;
    const auto existing = std::find_if(project->notes.begin(), project->notes.end(),
                                       [&](const WorkspaceNote& note) { return note.id == id.toStdString(); });
    if (existing == project->notes.end()) return;
    bool ok = false;
    const QString title = QInputDialog::getText(this, tr("Edit note"), tr("Title"),
                                                QLineEdit::Normal, text(existing->title), &ok).trimmed();
    if (!ok || title.isEmpty()) return;
    const QString body = QInputDialog::getMultiLineText(this, tr("Edit note"), tr("Markdown note"),
                                                        text(existing->markdown), &ok);
    if (!ok) return;
    const QString tags = QInputDialog::getText(this, tr("Edit note"), tr("Comma-separated tags"),
                                                QLineEdit::Normal, joinTags(existing->tags), &ok);
    if (!ok) return;
    auto candidate = data_;
    auto* target = findWorkspaceProject(candidate, selectedProjectId().toStdString());
    auto note = std::find_if(target->notes.begin(), target->notes.end(),
                             [&](const WorkspaceNote& value) { return value.id == id.toStdString(); });
    note->title = title.toStdString();
    note->markdown = body.toStdString();
    note->tags = splitTags(tags);
    note->modifiedAt = timestampNow().toStdString();
    commit(std::move(candidate), selectedProjectId());
}

void WorkspaceWidget::deleteNote() {
    const QString id = selectedEntryId(notes_);
    if (id.isEmpty() || QMessageBox::question(this, tr("Delete note"),
                                               tr("Delete the selected note?")) != QMessageBox::Yes) return;
    auto candidate = data_;
    auto* target = findWorkspaceProject(candidate, selectedProjectId().toStdString());
    std::erase_if(target->notes, [&](const WorkspaceNote& note) { return note.id == id.toStdString(); });
    commit(std::move(candidate), selectedProjectId());
}

void WorkspaceWidget::openAnalysisReport(const QModelIndex& index) {
    const auto* project = selectedProject();
    if (!project || !index.isValid()) return;
    const QString id = selectedEntryId(history_);
    const auto found = std::find_if(project->analyses.begin(), project->analyses.end(),
                                    [&](const WorkspaceAnalysis& analysis) { return analysis.id == id.toStdString(); });
    if (found == project->analyses.end()) return;
    if (found->reportJson.empty()) {
        QMessageBox::information(this, tr("No saved report"), tr("This entry has no complete report snapshot."));
        return;
    }
    showReport(this, text(found->type) + tr(" report"), found->reportJson);
}

void WorkspaceWidget::deleteAnalysis() {
    const QString id = selectedEntryId(history_);
    if (id.isEmpty() || QMessageBox::question(this, tr("Delete analysis history"),
                                               tr("Delete this history entry and its saved report?")) != QMessageBox::Yes) return;
    auto candidate = data_;
    auto* target = findWorkspaceProject(candidate, selectedProjectId().toStdString());
    std::erase_if(target->analyses, [&](const WorkspaceAnalysis& value) { return value.id == id.toStdString(); });
    commit(std::move(candidate), selectedProjectId());
}

void WorkspaceWidget::openComparisonReport(const QModelIndex& index) {
    const auto* project = selectedProject();
    if (!project || !index.isValid()) return;
    const QString id = selectedEntryId(comparisons_);
    const auto found = std::find_if(project->comparisons.begin(), project->comparisons.end(),
                                    [&](const WorkspaceComparison& comparison) { return comparison.id == id.toStdString(); });
    if (found == project->comparisons.end()) return;
    if (found->reportJson.empty()) {
        QMessageBox::information(this, tr("No saved report"), tr("This comparison has no report snapshot."));
        return;
    }
    showReport(this, tr("Binary Diff report"), found->reportJson);
}

void WorkspaceWidget::deleteComparison() {
    const QString id = selectedEntryId(comparisons_);
    if (id.isEmpty() || QMessageBox::question(this, tr("Delete comparison"),
                                               tr("Delete this saved comparison and its report?")) != QMessageBox::Yes) return;
    auto candidate = data_;
    auto* target = findWorkspaceProject(candidate, selectedProjectId().toStdString());
    std::erase_if(target->comparisons, [&](const WorkspaceComparison& value) { return value.id == id.toStdString(); });
    commit(std::move(candidate), selectedProjectId());
}

void WorkspaceWidget::addTag() {
    if (!selectedProject()) return;
    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("Create tag"), tr("Tag name"),
                                               QLineEdit::Normal, {}, &ok).trimmed();
    if (!ok || name.isEmpty()) return;
    const QString color = QInputDialog::getText(this, tr("Create tag"), tr("Color (optional, e.g. #c4a000)"),
                                                QLineEdit::Normal, QStringLiteral("#8b8b92"), &ok).trimmed();
    if (!ok) return;
    auto candidate = data_;
    auto* target = findWorkspaceProject(candidate, selectedProjectId().toStdString());
    if (std::any_of(target->tags.begin(), target->tags.end(),
                    [&](const WorkspaceTag& tag) { return tag.name == name.toStdString(); })) {
        QMessageBox::warning(this, tr("Tag already exists"), tr("Choose a different tag name."));
        return;
    }
    target->tags.push_back({name.toStdString(), color.toStdString()});
    commit(std::move(candidate), selectedProjectId());
}

void WorkspaceWidget::renameTag() {
    if (!selectedProject() || tags_->currentRow() < 0) return;
    const auto* tagItem = tags_->item(tags_->currentRow(), 0);
    if (!tagItem) return;
    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("Rename tag"), tr("New name"),
                                               QLineEdit::Normal, tagItem->text(), &ok).trimmed();
    if (!ok) return;
    auto candidate = data_;
    auto* target = findWorkspaceProject(candidate, selectedProjectId().toStdString());
    if (!renameWorkspaceTag(*target, tagItem->text().toStdString(), name.toStdString())) {
        QMessageBox::warning(this, tr("Tag not renamed"), tr("The new tag name is empty or already in use."));
        return;
    }
    commit(std::move(candidate), selectedProjectId());
}

void WorkspaceWidget::deleteTag() {
    if (!selectedProject() || tags_->currentRow() < 0) return;
    const auto* tagItem = tags_->item(tags_->currentRow(), 0);
    if (!tagItem) return;
    if (QMessageBox::question(this, tr("Delete tag"),
                              tr("Delete “%1” from this project and all its notes, bookmarks, and files?")
                                  .arg(tagItem->text())) != QMessageBox::Yes) return;
    auto candidate = data_;
    auto* target = findWorkspaceProject(candidate, selectedProjectId().toStdString());
    deleteWorkspaceTag(*target, tagItem->text().toStdString());
    commit(std::move(candidate), selectedProjectId());
}

void WorkspaceWidget::backupWorkspace() {
    const QString path = QFileDialog::getSaveFileName(this, tr("Back up local workspace"),
                                                       QStringLiteral("xaynx-workspace.json"),
                                                       tr("Xaynx workspace JSON (*.json)"));
    if (path.isEmpty()) return;
    std::string error;
    if (!writeWorkspace(toPath(path), data_, &error)) {
        QMessageBox::warning(this, tr("Backup failed"), text(error));
        return;
    }
    emit statusMessage(tr("Workspace backup saved to %1").arg(path), false);
}

void WorkspaceWidget::restoreWorkspace() {
    const QString path = QFileDialog::getOpenFileName(this, tr("Restore workspace backup"), {},
                                                       tr("Xaynx workspace JSON (*.json);;All files (*)"));
    if (path.isEmpty()) return;
    const auto loaded = readWorkspace(toPath(path));
    if (!loaded.ok) {
        QMessageBox::warning(this, tr("Backup could not be restored"), text(loaded.error));
        return;
    }
    if (loaded.data.projects.empty()) {
        QMessageBox::information(this, tr("Empty backup"), tr("The selected backup contains no projects."));
        return;
    }
    if (QMessageBox::question(this, tr("Restore workspace backup"),
                              tr("Add %1 project(s) from this backup as new projects?\n\n"
                                 "Existing projects will not be replaced. Source binaries are not copied.")
                                  .arg(loaded.data.projects.size())) != QMessageBox::Yes) return;
    auto candidate = data_;
    QString selected;
    for (const auto& project : loaded.data.projects) {
        auto restored = cloneImportedProject(project);
        selected = text(restored.id);
        candidate.projects.push_back(std::move(restored));
    }
    candidate.lastActiveProjectId = selected.toStdString();
    if (!commit(std::move(candidate), selected, true)) return;
    if (!loaded.warnings.empty())
        emit statusMessage(text(loaded.warnings.front()), false);
}

void WorkspaceWidget::setLoadedFile(const WorkspaceFile& file) {
    loadedFile_ = file;
    addLoadedButton_->setEnabled(selectedProject() != nullptr);
}

void WorkspaceWidget::clearLoadedFile() {
    loadedFile_.reset();
    addLoadedButton_->setEnabled(false);
}

}  // namespace xrl::ui
