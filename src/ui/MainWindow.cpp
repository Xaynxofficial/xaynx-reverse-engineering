#include "MainWindow.hpp"

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QCompleter>
#include <QCoreApplication>
#include <QDateTime>
#include <QDoubleSpinBox>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFile>
#include <QFontDatabase>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenuBar>
#include <QMessageBox>
#include <QMimeData>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QStandardPaths>
#include <QSettings>
#include <QSpinBox>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QItemSelectionModel>
#include <QTabWidget>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>
#include <QtConcurrent>
#include <algorithm>
#include <fstream>
#include <unordered_map>

#include "GhidraRunner.hpp"
#include "CfgGraphView.hpp"
#include "EntropyHeatmap.hpp"
#include "HexView.hpp"
#include "StringsTable.hpp"
#include "XrefGraphView.hpp"
#include "TableWidgets.hpp"
#include "Theme.hpp"
#include "UiUtil.hpp"
#include "WorkspaceWidget.hpp"
#include "xrl/report.hpp"
#include "xrl/util.hpp"

namespace xrl::ui {
namespace {

QFont monoFont() { return QFontDatabase::systemFont(QFontDatabase::FixedFont); }

QLabel* mutedLabel(const QString& text, QWidget* parent = nullptr) {
    auto* l = new QLabel(text, parent);
    l->setProperty("muted", true);
    l->setWordWrap(true);
    return l;
}

QFrame* makeCard(const QString& title, QLayout* content) {
    auto* card = new QFrame;
    card->setObjectName("card");
    auto* lay = new QVBoxLayout(card);
    lay->setContentsMargins(16, 14, 16, 16);
    lay->setSpacing(10);
    auto* t = new QLabel(title.toUpper());
    t->setObjectName("cardTitle");
    lay->addWidget(t);
    lay->addLayout(content, 1);
    return card;
}

QLabel* pageTitle(const QString& text) {
    auto* l = new QLabel(text);
    l->setObjectName("pageTitle");
    return l;
}

QWidget* pageWrap(QLayout* l) {
    auto* w = new QWidget;
    l->setContentsMargins(24, 20, 24, 16);
    l->setSpacing(14);
    w->setLayout(l);
    return w;
}

void setPrimary(QPushButton* b) {
    b->setProperty("primary", true);
    b->style()->unpolish(b);
    b->style()->polish(b);
}

QString availabilityText(xrl::Availability a, const std::string& note) {
    QString prefix;
    switch (a) {
        case xrl::Availability::Present: prefix = {}; break;
        case xrl::Availability::Absent: prefix = QObject::tr("Confirmed absent from this file. "); break;
        case xrl::Availability::NotParsed: prefix = QObject::tr("Unavailable: this information could not be determined (not the same as absent). "); break;
    }
    return prefix + q(note);
}

QString perms(const xrl::Section& s) {
    return QString(s.readable ? 'r' : '-') + (s.writable ? 'w' : '-') + (s.executable ? 'x' : '-');
}

QString tabLabel(const QString& name, xrl::Availability a, size_t count) {
    return a == xrl::Availability::NotParsed ? QObject::tr("%1 (n/a)").arg(name)
                                             : QStringLiteral("%1 (%2)").arg(name).arg(count);
}

constexpr quint64 kMiB = 1024ull * 1024ull;

}  // namespace

// ============================================================================ construction
MainWindow::MainWindow() {
    setWindowTitle(QStringLiteral("Xaynx Reverse Lab"));
    setAcceptDrops(true);
    resize(1280, 800);
    setMinimumSize(900, 560);
    const QString workspaceDirectory = QDir(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation))
                                           .filePath(QStringLiteral("workspace"));
    workspacePath_ = QDir(workspaceDirectory).filePath(QStringLiteral("workspace.json"));
    if (!QDir().mkpath(workspaceDirectory)) {
        workspaceLoadError_ = tr("Could not create the private local workspace directory.");
    }
#ifdef Q_OS_UNIX
    if (workspaceLoadError_.isEmpty() &&
        !QFile::setPermissions(workspaceDirectory, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner))
        workspaceLoadError_ = tr("Could not restrict workspace directory access to the current user.");
#endif
    const auto loadedWorkspace = workspaceLoadError_.isEmpty()
                                     ? xrl::readWorkspace(toPath(workspacePath_))
                                     : xrl::WorkspaceLoadResult{};
    if (loadedWorkspace.ok) workspace_ = loadedWorkspace.data;
    else if (workspaceLoadError_.isEmpty()) workspaceLoadError_ = q(loadedWorkspace.error);

    auto* central = new QWidget;
    auto* h = new QHBoxLayout(central);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(0);

    sidebar_ = new QListWidget;
    sidebar_->setObjectName("sidebar");
    sidebar_->setFixedWidth(190);
    sidebar_->setFocusPolicy(Qt::NoFocus);
    for (const char* n : {"Overview", "File Analysis", "Static Analysis", "XREF", "Hex Viewer", "Strings Explorer", "Disassembly",
                          "Control Flow Graph", "Binary Diff", "Entropy Heatmap", "Reports", "Workspace", "Settings", "Function Explorer"})
        sidebar_->addItem(tr(n));

    stack_ = new QStackedWidget;
    stack_->addWidget(buildOverviewPage());
    stack_->addWidget(buildAnalysisPage());
    stack_->addWidget(buildStaticAnalysisPage());
    stack_->addWidget(buildXrefPage());
    stack_->addWidget(buildHexPage());
    stack_->addWidget(buildStringsPage());
    stack_->addWidget(buildDisasmPage());
    stack_->addWidget(buildCfgPage());
    stack_->addWidget(buildDiffPage());
    stack_->addWidget(buildEntropyPage());
    stack_->addWidget(buildReportsPage());
    stack_->addWidget(buildWorkspacePage());
    stack_->addWidget(buildSettingsPage());
    stack_->addWidget(buildFunctionExplorerPage());

    h->addWidget(sidebar_);
    h->addWidget(stack_, 1);
    setCentralWidget(central);

    statusLabel_ = new QLabel(tr("Ready. Open a PE, ELF or Mach-O file to begin."));
    progress_ = new QProgressBar;
    progress_->setRange(0, 100);
    progress_->setFixedWidth(180);
    progress_->setTextVisible(false);
    progress_->hide();
    statusBar()->addWidget(statusLabel_, 1);
    statusBar()->addPermanentWidget(progress_);
    statusBar()->setSizeGripEnabled(false);

    buildMenus();

    connect(sidebar_, &QListWidget::currentRowChanged, this, [this](int row) {
        stack_->setCurrentIndex(row);
        if (row == PageReports) refreshReportPreview();
        if (row >= 0) {
            if (auto* project = xrl::findWorkspaceProject(workspace_, workspace_.lastActiveProjectId))
                project->session.activePage = row;
        }
    });
    int initialPage = PageOverview;
    if (const auto* project = xrl::findWorkspaceProject(workspace_, workspace_.lastActiveProjectId))
        initialPage = std::clamp(project->session.activePage, 0, sidebar_->count() - 1);
    sidebar_->setCurrentRow(initialPage);
    connect(workspaceWidget_, &WorkspaceWidget::statusMessage, this, &MainWindow::showStatus);
    connect(workspaceWidget_, &WorkspaceWidget::openFileRequested, this,
            [this](const QString& path, const QString& hash, qulonglong offset, const QString& kind) {
                openWorkspaceFile(path, hash, offset, kind);
            });
    connect(workspaceWidget_, &WorkspaceWidget::addFileRequested, this, [this](const QString& path) {
        if (busy_) {
            showStatus(tr("Wait for the current analysis to finish before adding another file."), true);
            return;
        }
        if (haveResult_ && QMessageBox::question(
                this, tr("Load file into workspace"),
                tr("Loading this binary replaces the current analysis view. Continue?")) != QMessageBox::Yes)
            return;
        workspaceAddAfterLoad_ = true;
        loadFile(path);
    });
    connect(workspaceWidget_, &WorkspaceWidget::projectActivated, this, [this](const QString& projectId) {
        workspace_.lastActiveProjectId = projectId.toStdString();
        const auto* project = xrl::findWorkspaceProject(workspace_, projectId.toStdString());
        if (!project || project->session.selectedFileId.empty()) return;
        const auto* file = xrl::findWorkspaceFile(*project, project->session.selectedFileId);
        if (file && QFileInfo::exists(q(file->path)))
            openWorkspaceFile(q(file->path), q(file->sha256), 0, {});
    });
    connect(&watcher_, &QFutureWatcher<xrl::AnalysisResult>::finished, this, &MainWindow::onAnalysisFinished);
    connect(&staticWatcher_, &QFutureWatcher<StaticJobResult>::finished,
            this, &MainWindow::onStaticAnalysisFinished);
    connect(&xrefWatcher_, &QFutureWatcher<XrefJobResult>::finished,
            this, &MainWindow::onXrefAnalysisFinished);
    connect(&diffWatcher_, &QFutureWatcher<xrl::BinaryDiffResult>::finished, this, &MainWindow::onDiffFinished);
    connect(&entropyWatcher_, &QFutureWatcher<EntropyJobResult>::finished, this, &MainWindow::onEntropyFinished);
    connect(&stringsWatcher_, &QFutureWatcher<xrl::StringExtractionResult>::finished, this, &MainWindow::onStringsFinished);
    connect(&cfgWatcher_, &QFutureWatcher<xrl::ControlFlowGraph>::finished, this, &MainWindow::onCfgAnalysisFinished);

    ghidraRunner_ = new GhidraRunner(this);
    connect(ghidraCancel_, &QPushButton::clicked, this, [this] { ghidraRunner_->cancel(); });
    connect(ghidraRunner_, &GhidraRunner::logText, this, [this](const QString& t) {
        ghidraLog_->moveCursor(QTextCursor::End);
        ghidraLog_->insertPlainText(t);
    });
    connect(ghidraRunner_, &GhidraRunner::finished, this, &MainWindow::onGhidraFinished);

    QSettings s;
    restoreGeometry(s.value("window/geometry").toByteArray());
    populateAll();
    refreshGhidraStatus();
    updateEnabled();
    if (!workspaceLoadError_.isEmpty()) {
        showStatus(tr("Workspace data could not be loaded: %1. The original file was left untouched.")
                       .arg(workspaceLoadError_), true);
    } else if (const auto* project = xrl::findWorkspaceProject(workspace_, workspace_.lastActiveProjectId);
               project && !project->session.selectedFileId.empty()) {
        if (const auto* file = xrl::findWorkspaceFile(*project, project->session.selectedFileId)) {
            if (QFileInfo::exists(q(file->path))) {
                pendingWorkspaceFileId_ = q(file->id);
                pendingWorkspaceHash_ = q(file->sha256);
                if (project->session.selectedAddress) {
                    pendingWorkspaceOffset_ = *project->session.selectedAddress;
                    pendingWorkspaceLocationKind_ = QStringLiteral("offset");
                }
                loadFile(q(file->path));
            } else {
                showStatus(tr("The last workspace file is missing. Use Workspace → Locate missing file to reconnect it."),
                           true);
            }
        }
    }
}

MainWindow::~MainWindow() {
    if (entropyCancel_) entropyCancel_->store(true);
    if (stringsCancel_) stringsCancel_->store(true);
    if (cfgCancel_) cfgCancel_->store(true);
    if (xrefCancel_) xrefCancel_->store(true);
    if (watcher_.isRunning()) watcher_.waitForFinished();
    if (entropyWatcher_.isRunning()) entropyWatcher_.waitForFinished();
    if (stringsWatcher_.isRunning()) stringsWatcher_.waitForFinished();
    if (cfgWatcher_.isRunning()) cfgWatcher_.waitForFinished();
    if (xrefWatcher_.isRunning()) xrefWatcher_.waitForFinished();
}

void MainWindow::buildMenus() {
    auto* file = menuBar()->addMenu(tr("&File"));
    auto* open = file->addAction(tr("&Open..."), this, &MainWindow::openFileDialog);
    open->setShortcut(QKeySequence::Open);
    file->addSeparator();
    actExportJson_ = file->addAction(tr("Export Report as &JSON..."), this, [this] { exportReport(true); });
    actExportText_ = file->addAction(tr("Export Report as &Text..."), this, [this] { exportReport(false); });
    file->addSeparator();
    auto* quit = file->addAction(tr("&Quit"), this, &QWidget::close);
    quit->setShortcut(QKeySequence::Quit);
    quit->setMenuRole(QAction::QuitRole);

    auto* view = menuBar()->addMenu(tr("&View"));
    for (int i = 0; i < sidebar_->count(); ++i) {
        auto* a = view->addAction(sidebar_->item(i)->text(), this, [this, i] { sidebar_->setCurrentRow(i); });
        a->setShortcut(QKeySequence(QStringLiteral("Ctrl+%1").arg(i + 1)));
    }

    auto* help = menuBar()->addMenu(tr("&Help"));
    auto* about = help->addAction(tr("&About Xaynx Reverse Lab"), this, [this] {
        QMessageBox::about(
            this, tr("About Xaynx Reverse Lab"),
            tr("<b>Xaynx Reverse Lab %1</b><br>Static binary analysis (PE, ELF, Mach-O). Files are parsed, never executed.<br><br>"
               "Disassembly engine: %2<br>Qt: %3<br><br>"
               "The CFG page analyzes reachable flow from metadata candidates; whole-program function discovery and decompilation remain optional through Ghidra.<br>"
               "Released under the MIT License.")
                .arg(XRL_VERSION, q(xrl::disassemblerVersion()), QString::fromLatin1(qVersion())));
    });
    about->setMenuRole(QAction::AboutRole);
}

QWidget* MainWindow::buildOverviewPage() {
    auto* root = new QVBoxLayout;
    root->addWidget(pageTitle(tr("Overview")));

    auto* fileLay = new QVBoxLayout;
    filePathLabel_ = new QLabel(tr("No file selected"));
    filePathLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    filePathLabel_->setFont(monoFont());
    auto* row = new QHBoxLayout;
    openButton_ = new QPushButton(tr("Open file..."));
    setPrimary(openButton_);
    copyHashButton_ = new QPushButton(tr("Copy SHA-256"));
    row->addWidget(openButton_);
    row->addWidget(copyHashButton_);
    row->addStretch(1);
    dropHint_ = mutedLabel(tr("Choose a local file or drop one onto this window. Files are read and parsed only; they are never executed or loaded."));
    fileLay->addWidget(filePathLabel_);
    fileLay->addLayout(row);
    fileLay->addWidget(dropHint_);
    root->addWidget(makeCard(tr("File"), fileLay));
    connect(openButton_, &QPushButton::clicked, this, &MainWindow::openFileDialog);
    connect(copyHashButton_, &QPushButton::clicked, this, [this] {
        if (haveResult_ && !current_.info.sha256.empty()) {
            QApplication::clipboard()->setText(q(current_.info.sha256));
            showStatus(tr("SHA-256 copied to clipboard."));
        }
    });

    auto* cols = new QHBoxLayout;
    cols->setSpacing(14);
    auto* metaLay = new QVBoxLayout;
    metaView_ = new QTableView;
    metaModel_ = new StringTableModel(this);
    metaView_->setModel(metaModel_);
    metaView_->horizontalHeader()->hide();
    metaView_->verticalHeader()->hide();
    metaView_->horizontalHeader()->setStretchLastSection(true);
    metaView_->setShowGrid(false);
    metaView_->setAlternatingRowColors(true);
    metaView_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    metaView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    metaView_->verticalHeader()->setDefaultSectionSize(26);
    metaLay->addWidget(metaView_);
    cols->addWidget(makeCard(tr("File metadata"), metaLay), 3);

    auto* sumLay = new QVBoxLayout;
    summary_ = new QPlainTextEdit;
    summary_->setReadOnly(true);
    summary_->setFrameShape(QFrame::NoFrame);
    sumLay->addWidget(summary_);
    cols->addWidget(makeCard(tr("Analysis summary"), sumLay), 2);
    root->addLayout(cols, 1);
    return pageWrap(root);
}

QWidget* MainWindow::buildAnalysisPage() {
    auto* root = new QVBoxLayout;
    root->addWidget(pageTitle(tr("File Analysis")));
    analysisTabs_ = new QTabWidget;
    sectionsTable_ = new FilterTable;
    importsTable_ = new FilterTable;
    exportsTable_ = new FilterTable;
    librariesTable_ = new FilterTable;
    symbolsTable_ = new FilterTable;
    findingsTable_ = new FilterTable;
    analysisTabs_->addTab(sectionsTable_, tr("Sections"));
    analysisTabs_->addTab(importsTable_, tr("Imports"));
    analysisTabs_->addTab(exportsTable_, tr("Exports"));
    analysisTabs_->addTab(librariesTable_, tr("Libraries"));
    analysisTabs_->addTab(symbolsTable_, tr("Symbols"));
    analysisTabs_->addTab(findingsTable_, tr("Findings"));
    root->addWidget(analysisTabs_, 1);
    root->addWidget(mutedLabel(tr("Double-click a section to show its data in the hex viewer. Findings are heuristic observations, not verdicts.")));

    connect(sectionsTable_->view(), &QTableView::doubleClicked, this, [this](const QModelIndex& idx) {
        const auto src = sectionsTable_->proxy()->mapToSource(idx);
        const auto n = xrl::parseNumber(sectionsTable_->model()->rowAt(src.row()).value(4).toStdString());
        if (n) showInHex(*n);
    });
    return pageWrap(root);
}

QWidget* MainWindow::buildStaticAnalysisPage() {
    auto* root = new QVBoxLayout;
    root->addWidget(pageTitle(tr("Explainable Static Analysis")));
    root->addWidget(mutedLabel(tr("Local, evidence-backed inspection of the currently loaded file. Findings are investigative indicators, never a malware verdict.")));

    auto* actionRow = new QHBoxLayout;
    staticRunButton_ = new QPushButton(tr("Analyze Current File"));
    setPrimary(staticRunButton_);
    staticCancelButton_ = new QPushButton(tr("Cancel"));
    staticCancelButton_->setEnabled(false);
    staticProgress_ = new QProgressBar;
    staticProgress_->setRange(0, 100);
    staticProgress_->setFixedWidth(150);
    staticProgress_->setTextVisible(false);
    staticProgress_->hide();
    staticStatusLabel_ = mutedLabel(tr("Open a PE, ELF, or Mach-O file to begin."));
    staticExportJsonButton_ = new QPushButton(tr("Export JSON..."));
    staticExportHtmlButton_ = new QPushButton(tr("Export HTML..."));
    staticOpenEvidenceButton_ = new QPushButton(tr("Open related view"));
    staticOpenEvidenceButton_->setEnabled(false);
    actionRow->addWidget(staticRunButton_);
    actionRow->addWidget(staticCancelButton_);
    actionRow->addWidget(staticProgress_);
    actionRow->addWidget(staticStatusLabel_, 1);
    actionRow->addWidget(staticOpenEvidenceButton_);
    actionRow->addWidget(staticExportJsonButton_);
    actionRow->addWidget(staticExportHtmlButton_);
    root->addLayout(actionRow);

    staticSummaryLabel_ = mutedLabel(tr("Risk score is an evidence-prioritization aid; it is not a probability or classification."));
    staticSummaryLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    root->addWidget(staticSummaryLabel_);

    auto* filters = new QHBoxLayout;
    staticSeverityFilter_ = new QComboBox;
    staticSeverityFilter_->addItems({tr("All severities"), tr("Informational"), tr("Low"),
                                     tr("Medium"), tr("High"), tr("Critical")});
    staticCategoryFilter_ = new QComboBox;
    staticCategoryFilter_->addItems({tr("All categories"), tr("Structure"), tr("Memory"),
                                     tr("Imports"), tr("Entropy"), tr("Strings"),
                                     tr("Control flow"), tr("Correlation")});
    filters->addWidget(new QLabel(tr("Severity")));
    filters->addWidget(staticSeverityFilter_);
    filters->addWidget(new QLabel(tr("Category")));
    filters->addWidget(staticCategoryFilter_);
    filters->addStretch(1);
    root->addLayout(filters);

    auto* split = new QSplitter(Qt::Vertical);
    staticFindingsTable_ = new FilterTable;
    staticFindingsTable_->filterEdit()->setPlaceholderText(tr("Search rules, findings, and evidence..."));
    staticDetails_ = new QPlainTextEdit;
    staticDetails_->setReadOnly(true);
    staticDetails_->setFont(monoFont());
    staticDetails_->setPlaceholderText(tr("Select a finding to inspect its evidence, confidence, benign explanations, and recommended next step."));
    split->addWidget(staticFindingsTable_);
    split->addWidget(staticDetails_);
    split->setStretchFactor(0, 3);
    split->setStretchFactor(1, 2);
    root->addWidget(split, 1);

    connect(staticRunButton_, &QPushButton::clicked, this, &MainWindow::runStaticAnalysis);
    connect(staticCancelButton_, &QPushButton::clicked, this, [this] {
        if (staticCancel_) {
            staticCancel_->store(true);
            staticStatusLabel_->setText(tr("Cancelling static analysis..."));
        }
    });
    connect(staticExportJsonButton_, &QPushButton::clicked, this, [this] { exportStaticReport(false); });
    connect(staticExportHtmlButton_, &QPushButton::clicked, this, [this] { exportStaticReport(true); });
    connect(staticOpenEvidenceButton_, &QPushButton::clicked, this, &MainWindow::openStaticFinding);
    connect(staticSeverityFilter_, qOverload<int>(&QComboBox::currentIndexChanged),
            this, &MainWindow::updateStaticFindings);
    connect(staticCategoryFilter_, qOverload<int>(&QComboBox::currentIndexChanged),
            this, &MainWindow::updateStaticFindings);
    connect(staticFindingsTable_->view()->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, &MainWindow::selectStaticFinding);
    connect(staticFindingsTable_->filterEdit(), &QLineEdit::textChanged,
            this, [this](const QString&) { selectStaticFinding(staticFindingsTable_->view()->currentIndex()); });
    return pageWrap(root);
}

QWidget* MainWindow::buildXrefPage() {
    auto* root = new QVBoxLayout;
    root->addWidget(pageTitle(tr("Cross-Reference Explorer")));
    root->addWidget(mutedLabel(tr("Evidence-backed code, symbol, data, and string relationships from the current file. Unresolved targets remain unresolved.")));

    auto* actions = new QHBoxLayout;
    xrefRunButton_ = new QPushButton(tr("Build XREF Index"));
    setPrimary(xrefRunButton_);
    xrefCancelButton_ = new QPushButton(tr("Cancel"));
    xrefCancelButton_->setEnabled(false);
    xrefExportJsonButton_ = new QPushButton(tr("JSON..."));
    xrefExportCsvButton_ = new QPushButton(tr("CSV..."));
    xrefExportDotButton_ = new QPushButton(tr("Call Graph DOT..."));
    xrefProgress_ = new QProgressBar;
    xrefProgress_->setRange(0, 100);
    xrefProgress_->setFixedWidth(150);
    xrefProgress_->setTextVisible(false);
    xrefProgress_->hide();
    xrefStatusLabel_ = mutedLabel(tr("Load a supported file to index references."));
    actions->addWidget(xrefRunButton_);
    actions->addWidget(xrefCancelButton_);
    actions->addWidget(xrefProgress_);
    actions->addWidget(xrefStatusLabel_, 1);
    actions->addWidget(xrefExportJsonButton_);
    actions->addWidget(xrefExportCsvButton_);
    actions->addWidget(xrefExportDotButton_);
    root->addLayout(actions);

    xrefSummaryLabel_ = mutedLabel(tr("XREF decodes discovered function candidates only; stripped binaries may have limited function coverage."));
    xrefSummaryLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    root->addWidget(xrefSummaryLabel_);

    auto* filterRow = new QHBoxLayout;
    xrefSearchEdit_ = new QLineEdit;
    xrefSearchEdit_->setPlaceholderText(tr("Search address, function, symbol, string, or evidence..."));
    xrefSearchEdit_->setClearButtonEnabled(true);
    xrefSearchTimer_ = new QTimer(this);
    xrefSearchTimer_->setSingleShot(true);
    xrefSearchTimer_->setInterval(140);
    connect(xrefSearchTimer_, &QTimer::timeout, this, &MainWindow::updateXrefReferences);
    xrefTypeFilter_ = new QComboBox;
    xrefTypeFilter_->addItem(tr("All reference types"));
    for (int type = 0; type <= static_cast<int>(xrl::XrefType::Symbol); ++type)
        xrefTypeFilter_->addItem(QString::fromLatin1(xrl::toString(static_cast<xrl::XrefType>(type))));
    xrefDirectionFilter_ = new QComboBox;
    xrefDirectionFilter_->addItems({tr("All directions"), tr("Incoming to address"), tr("Outgoing from address"),
                                    tr("Unresolved only")});
    filterRow->addWidget(xrefSearchEdit_, 1);
    filterRow->addWidget(xrefTypeFilter_);
    filterRow->addWidget(xrefDirectionFilter_);
    root->addLayout(filterRow);

    auto* split = new QSplitter(Qt::Horizontal);
    xrefGraphView_ = new XrefGraphView;
    auto* right = new QSplitter(Qt::Vertical);
    xrefReferencesTable_ = new FilterTable;
    xrefReferencesTable_->layout()->setContentsMargins(0, 0, 0, 0);
    xrefReferencesTable_->filterEdit()->setPlaceholderText(tr("Filter reference rows..."));
    xrefCandidatesTable_ = new FilterTable;
    xrefCandidatesTable_->layout()->setContentsMargins(0, 0, 0, 0);
    xrefCandidatesTable_->filterEdit()->setPlaceholderText(tr("Filter unreferenced candidates..."));
    xrefResultTabs_ = new QTabWidget;
    xrefResultTabs_->addTab(xrefReferencesTable_, tr("References"));
    xrefResultTabs_->addTab(xrefCandidatesTable_, tr("Unreferenced candidates"));
    xrefDetails_ = new QPlainTextEdit;
    xrefDetails_->setReadOnly(true);
    xrefDetails_->setFont(monoFont());
    xrefDetails_->setPlaceholderText(tr("Select a reference to inspect its evidence and confidence."));
    auto* detailPane = new QWidget;
    auto* detailLayout = new QVBoxLayout(detailPane);
    detailLayout->setContentsMargins(8, 8, 8, 8);
    detailLayout->addWidget(xrefDetails_, 1);
    auto* navigation = new QHBoxLayout;
    xrefDisasmButton_ = new QPushButton(tr("Open Disassembly"));
    xrefHexButton_ = new QPushButton(tr("Open Hex"));
    xrefCfgButton_ = new QPushButton(tr("Open CFG"));
    xrefStringButton_ = new QPushButton(tr("Open String"));
    navigation->addWidget(xrefDisasmButton_);
    navigation->addWidget(xrefHexButton_);
    navigation->addWidget(xrefCfgButton_);
    navigation->addWidget(xrefStringButton_);
    detailLayout->addLayout(navigation);
    right->addWidget(xrefResultTabs_);
    right->addWidget(detailPane);
    right->setStretchFactor(0, 3);
    right->setStretchFactor(1, 2);
    split->addWidget(xrefGraphView_);
    split->addWidget(right);
    split->setStretchFactor(0, 2);
    split->setStretchFactor(1, 3);
    root->addWidget(split, 1);

    connect(xrefRunButton_, &QPushButton::clicked, this, &MainWindow::runXrefAnalysis);
    connect(xrefCancelButton_, &QPushButton::clicked, this, [this] {
        if (xrefCancel_) {
            xrefCancel_->store(true);
            xrefStatusLabel_->setText(tr("Cancelling XREF indexing..."));
        }
    });
    connect(xrefTypeFilter_, qOverload<int>(&QComboBox::currentIndexChanged),
            this, [this](int) { updateXrefReferences(); });
    connect(xrefDirectionFilter_, qOverload<int>(&QComboBox::currentIndexChanged),
            this, [this](int) { updateXrefReferences(); });
    connect(xrefSearchEdit_, &QLineEdit::textChanged,
            this, [this](const QString&) { xrefSearchTimer_->start(); });
    connect(xrefReferencesTable_->filterEdit(), &QLineEdit::textChanged,
            this, [this](const QString&) { selectXrefReference(xrefReferencesTable_->view()->currentIndex()); });
    connect(xrefReferencesTable_->view()->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, [this](const QModelIndex& current, const QModelIndex&) { selectXrefReference(current); });
    connect(xrefCandidatesTable_->view(), &QTableView::doubleClicked, this, [this](const QModelIndex& index) {
        const QModelIndex source = xrefCandidatesTable_->proxy()->mapToSource(index);
        const auto& row = xrefCandidatesTable_->model()->rowAt(source.row());
        if (row.size() < 4) return;
        const auto offset = xrl::parseNumber(row[3].toStdString());
        if (offset) showInHex(*offset);
        else showStatus(tr("This candidate has no validated file-offset mapping."), true);
    });
    connect(xrefDisasmButton_, &QPushButton::clicked, this, &MainWindow::navigateXrefDisassembly);
    connect(xrefHexButton_, &QPushButton::clicked, this, &MainWindow::navigateXrefHex);
    connect(xrefCfgButton_, &QPushButton::clicked, this, &MainWindow::navigateXrefCfg);
    connect(xrefStringButton_, &QPushButton::clicked, this, &MainWindow::navigateXrefString);
    connect(xrefGraphView_, &XrefGraphView::addressSelected, this, [this](quint64 address) {
        xrefSearchEdit_->setText(hex64(address));
    });
    connect(xrefExportJsonButton_, &QPushButton::clicked, this, [this] { exportXref(0); });
    connect(xrefExportCsvButton_, &QPushButton::clicked, this, [this] { exportXref(1); });
    connect(xrefExportDotButton_, &QPushButton::clicked, this, [this] { exportXref(2); });
    return pageWrap(root);
}

void MainWindow::runXrefAnalysis() {
    if (xrefWatcher_.isRunning()) return;
    if (!haveResult_ || !current_.data || current_.info.filePath.empty()) {
        showStatus(tr("Open a file before building a cross-reference index."), true);
        return;
    }
    if (!xrl::cfgSupported(current_.info)) {
        showStatus(tr("XREF code indexing requires Capstone and a supported x86, x86-64, or ARM64 file."), true);
        return;
    }
    const auto path = q(current_.info.filePath);
    auto canonical = [](const QString& candidate) {
        QString resolved = QFileInfo(candidate).canonicalFilePath();
        return resolved.isEmpty() ? QFileInfo(candidate).absoluteFilePath() : resolved;
    };
    const QString resolvedPath = canonical(path);
    const auto info = current_.info;
    const auto fileData = current_.data;
    const bool reuseStrings = haveStrings_ && !stringsResult_.truncated && stringsResult_.minLength == 4 &&
                              !stringsResult_.sha256.empty() && stringsResult_.sha256 == info.sha256 &&
                              canonical(q(stringsResult_.filePath)) == resolvedPath;
    auto cachedStrings = reuseStrings ? stringsResult_ : xrl::StringExtractionResult{};
    xrefAnalysisPath_ = resolvedPath;
    xrefResult_ = {};
    haveXref_ = false;
    xrefSelectedReferenceId_.clear();
    xrefDetails_->clear();
    xrefReferencesTable_->clear(tr("Building the cross-reference index..."));
    xrefGraphView_->clearGraph(tr("Indexing discovered function candidates and instruction references..."));
    xrefSummaryLabel_->setText(tr("The index is built from local file bytes and parsed metadata. Target binaries are never executed."));
    xrefStatusLabel_->setText(tr("Preparing XREF analysis..."));
    xrefProgress_->setValue(0);
    xrefProgress_->show();
    xrefCancel_ = std::make_shared<std::atomic_bool>(false);
    const auto cancel = xrefCancel_;
    updateEnabled();
    xrefWatcher_.setFuture(QtConcurrent::run(
        [this, info, fileData, path, reuseStrings,
         cachedStrings = std::move(cachedStrings), cancel]() mutable {
            XrefJobResult job;
            QStringList collectionWarnings;
            auto emitProgress = [this](int percent, const std::string& stage) {
                QMetaObject::invokeMethod(this, [this, percent, text = q(stage)] {
                    onXrefProgress(percent, text);
                }, Qt::QueuedConnection);
            };
            const auto filesystemPath = toPath(path);
            if (reuseStrings) {
                job.strings = std::move(cachedStrings);
                job.hasStrings = job.strings.ok;
                emitProgress(8, "Reusing verified Strings Explorer results");
            } else {
                job.strings = xrl::extractStringsFile(
                    filesystemPath, {},
                    [&emitProgress](int percent, const std::string& stage) {
                        emitProgress(percent * 15 / 100, stage);
                    },
                    [cancel] { return cancel->load(); });
                job.hasStrings = job.strings.ok && job.strings.sha256 == info.sha256;
                if (!job.strings.ok && !job.strings.cancelled)
                    collectionWarnings << tr("String indexing unavailable: %1").arg(q(job.strings.error));
                else if (job.strings.ok && !job.hasStrings)
                    collectionWarnings << tr("The file changed during string extraction; string references were excluded.");
                if (job.hasStrings && job.strings.truncated)
                    collectionWarnings << tr("String extraction was truncated by its output limits; some string references may be absent.");
            }
            if (cancel->load()) {
                job.xref.cancelled = true;
                job.xref.error = "XREF analysis cancelled.";
                return job;
            }
            xrl::XrefOptions options;
            options.maxFunctions = 256;
            options.maxReferences = 200'000;
            options.maxBlocksPerFunction = 512;
            options.maxTotalDecodedBytes = 64ull * 1024 * 1024;
            job.xref = xrl::analyzeCrossReferences(
                info, *fileData, job.hasStrings ? &job.strings : nullptr, options,
                [&emitProgress](int percent, const std::string& stage) {
                    emitProgress(15 + percent * 85 / 100, stage);
                },
                [cancel] { return cancel->load(); });
            for (const auto& warning : collectionWarnings)
                job.xref.warnings.push_back(warning.toStdString());
            if (job.xref.sha256 != info.sha256 && job.xref.ok) {
                job.xref.ok = false;
                job.xref.error = "Loaded file identity changed during XREF analysis.";
            }
            emitProgress(100, job.xref.ok ? "XREF indexing complete" : "XREF indexing incomplete");
            return job;
        }));
}

void MainWindow::onXrefProgress(int percent, const QString& stage) {
    if (!xrefWatcher_.isRunning()) return;
    xrefProgress_->setValue(percent);
    xrefStatusLabel_->setText(stage + QStringLiteral("..."));
}

void MainWindow::onXrefAnalysisFinished() {
    auto job = xrefWatcher_.result();
    xrefProgress_->hide();
    xrefCancel_.reset();
    const QString currentPath = QFileInfo(q(current_.info.filePath)).canonicalFilePath();
    const QString expectedPath = xrefAnalysisPath_;
    if (expectedPath.isEmpty() || !haveResult_ ||
        (!currentPath.isEmpty() && expectedPath != currentPath)) {
        updateEnabled();
        return;
    }
    xrefResult_ = std::move(job.xref);
    haveXref_ = xrefResult_.ok;
    if (job.hasStrings && job.strings.sha256 == current_.info.sha256) {
        stringsResult_ = std::move(job.strings);
        haveStrings_ = true;
        stringsTable_->setStrings(&stringsResult_.strings,
            tr("Strings extracted for XREF. Pattern classifications do not establish runtime use."));
    }
    if (!haveXref_) {
        xrefStatusLabel_->setText(xrefResult_.cancelled
                                      ? tr("XREF analysis cancelled.")
                                      : tr("XREF analysis failed: %1").arg(q(xrefResult_.error)));
        xrefGraphView_->clearGraph(xrefStatusLabel_->text());
        showStatus(xrefStatusLabel_->text(), !xrefResult_.cancelled);
        updateEnabled();
        return;
    }
    updateXrefReferences();
    updateXrefCandidates();
    xrefGraphView_->setReferenceGraph(xrefResult_);
    xrefSummaryLabel_->setText(
        tr("%1 function candidate(s) analyzed · %2 references · %3 unresolved indirect calls · %4 bytes decoded%5")
            .arg(xrefResult_.analyzedFunctions)
            .arg(xrefResult_.references.size())
            .arg(xrefResult_.unresolvedIndirectCalls)
            .arg(xrl::humanSize(xrefResult_.analyzedBytes))
            .arg(xrefResult_.truncated ? tr(" · limits reached; results are partial") : QString()));
    xrefStatusLabel_->setText(xrefResult_.warnings.empty()
                                  ? tr("XREF index complete.")
                                  : tr("XREF index complete with %1 warning(s).").arg(xrefResult_.warnings.size()));
    showStatus(xrefStatusLabel_->text(), xrefResult_.truncated);
    recordWorkspaceAnalysis(
        tr("XREF"), q(current_.info.filePath), q(current_.info.sha256),
        tr("%1 references across %2 analyzed function candidates")
            .arg(xrefResult_.references.size()).arg(xrefResult_.analyzedFunctions),
        xrl::renderXrefJson(xrefResult_));
    updateFunctionExplorer();
    updateEnabled();
}

void MainWindow::updateXrefReferences() {
    if (!xrefReferencesTable_) return;
    QVector<QStringList> rows;
    if (haveXref_) {
        const QString query = xrefSearchEdit_->text().trimmed();
        const int typeFilter = xrefTypeFilter_->currentIndex() - 1;
        rows.reserve(static_cast<qsizetype>(xrefResult_.references.size()));
        for (size_t i = 0; i < xrefResult_.references.size(); ++i) {
            const auto& reference = xrefResult_.references[i];
            if (typeFilter >= 0 && static_cast<int>(reference.type) != typeFilter) continue;
            const QString source = reference.sourceAddress ? hex64(*reference.sourceAddress) : tr("n/a");
            const QString destination = reference.destinationAddress ? hex64(*reference.destinationAddress) : tr("unresolved");
            const QString sourceFunction = q(reference.sourceFunctionName);
            const QString destinationFunction = q(reference.destinationFunctionName);
            const QString symbol = q(reference.symbolName);
            const QString evidence = q(reference.evidenceSource);
            const QString sourceFunctionAddress = reference.sourceFunction ? hex64(*reference.sourceFunction) : QString();
            const QString destinationFunctionAddress = reference.destinationFunction ? hex64(*reference.destinationFunction) : QString();
            const QString searchable = QStringList{source, destination, sourceFunction, destinationFunction,
                                                    sourceFunctionAddress, destinationFunctionAddress,
                                                    symbol, q(reference.dataTarget), evidence,
                                                    QString::fromLatin1(xrl::toString(reference.type))}
                                           .join(QLatin1Char(' '));
            const int direction = xrefDirectionFilter_->currentIndex();
            if (direction == 3 && reference.confidence != xrl::XrefConfidence::Unresolved) continue;
            if (direction == 1 && !query.isEmpty() &&
                !destination.contains(query, Qt::CaseInsensitive) &&
                !destinationFunctionAddress.contains(query, Qt::CaseInsensitive)) continue;
            if (direction == 2 && !query.isEmpty() &&
                !source.contains(query, Qt::CaseInsensitive) &&
                !sourceFunctionAddress.contains(query, Qt::CaseInsensitive)) continue;
            if (!query.isEmpty() && direction != 1 && direction != 2 &&
                !searchable.contains(query, Qt::CaseInsensitive)) continue;
            rows.push_back({QString::fromLatin1(xrl::toString(reference.type)), source, destination,
                            sourceFunction, destinationFunction, symbol,
                            reference.fileOffset ? hex64(*reference.fileOffset) : tr("n/a"),
                            reference.destinationFileOffset ? hex64(*reference.destinationFileOffset) : tr("n/a"),
                            QString::fromLatin1(xrl::toString(reference.confidence)), evidence,
                            QString::number(i)});
        }
    }
    const QString note = xrefResult_.truncated
                             ? tr("Partial index: configured function, decode, or reference limits were reached.")
                             : tr("Only decoded direct targets and statically resolved data addresses are shown. Unresolved indirect calls are never guessed.");
    xrefReferencesTable_->setContent(
        {tr("Type"), tr("Source"), tr("Destination"), tr("Source function"), tr("Destination function"),
         tr("Symbol"), tr("Instruction offset"), tr("Target offset"), tr("Confidence"), tr("Evidence"), tr("Index")},
        rows, haveXref_ ? note : tr("Run XREF on the current file to build the index."),
        {1, 2, 6, 7, 10});
    xrefReferencesTable_->view()->setSortingEnabled(true);
    xrefReferencesTable_->view()->setColumnHidden(10, true);
    if (xrefReferencesTable_->view()->model()->columnCount() > 0) {
        xrefReferencesTable_->view()->setColumnWidth(0, 130);
        xrefReferencesTable_->view()->setColumnWidth(1, 110);
        xrefReferencesTable_->view()->setColumnWidth(2, 110);
    }
    if (rows.isEmpty()) {
        xrefSelectedReferenceId_.clear();
        xrefDetails_->clear();
        xrefDisasmButton_->setEnabled(false);
        xrefHexButton_->setEnabled(false);
        xrefCfgButton_->setEnabled(false);
        xrefStringButton_->setEnabled(false);
    }
}

void MainWindow::updateXrefCandidates() {
    if (!xrefCandidatesTable_) return;
    QVector<QStringList> rows;
    if (haveXref_) {
        std::unordered_map<uint64_t, const xrl::XrefFunction*> functionsByAddress;
        functionsByAddress.reserve(xrefResult_.functions.size());
        for (const auto& function : xrefResult_.functions)
            functionsByAddress.emplace(function.candidate.address, &function);
        std::unordered_map<uint64_t, const xrl::ExtractedString*> stringsByOffset;
        stringsByOffset.reserve(stringsResult_.strings.size());
        for (const auto& string : stringsResult_.strings)
            stringsByOffset.emplace(string.offset, &string);
        for (const uint64_t address : xrefResult_.unreferencedFunctionCandidates) {
            const auto function = functionsByAddress.find(address);
            if (function == functionsByAddress.end()) continue;
            rows.push_back({tr("Function candidate"), q(function->second->candidate.name), hex64(address),
                            hex64(function->second->candidate.fileOffset),
                            tr("No direct call site was found in the analyzed candidate set. This is not proof of dead code.")});
        }
        for (const uint64_t offset : xrefResult_.unreferencedStringOffsets) {
            const auto string = stringsByOffset.find(offset);
            if (string == stringsByOffset.end()) continue;
            rows.push_back({tr("String candidate"), q(string->second->value),
                            current_.info.fileOffsetToVirtual(offset)
                                ? hex64(*current_.info.fileOffsetToVirtual(offset)) : tr("n/a"),
                            hex64(offset),
                            tr("No statically resolved instruction reference to this string start was found.")});
        }
    }
    xrefCandidatesTable_->setContent(
        {tr("Candidate type"), tr("Name / value"), tr("Address"), tr("File offset"), tr("Evidence limitation")},
        rows,
        tr("Candidate means no matching reference was found in the bounded index; it does not mean dead code or unused data."),
        {2, 3});
}

void MainWindow::selectXrefReference(const QModelIndex& current) {
    if (!current.isValid() || !haveXref_) return;
    const QModelIndex sourceIndex = xrefReferencesTable_->proxy()->mapToSource(current);
    if (!sourceIndex.isValid()) return;
    const auto& row = xrefReferencesTable_->model()->rowAt(sourceIndex.row());
    if (row.size() <= 10) return;
    bool parsed = false;
    const size_t index = row[10].toULongLong(&parsed);
    if (!parsed || index >= xrefResult_.references.size()) return;
    xrefSelectedReferenceId_ = QString::number(index);
    const auto& reference = xrefResult_.references[index];
    QStringList details;
    details << tr("%1 · %2")
                   .arg(QString::fromLatin1(xrl::toString(reference.type)),
                        QString::fromLatin1(xrl::toString(reference.confidence)));
    details << tr("Source: %1").arg(reference.sourceAddress ? hex64(*reference.sourceAddress) : tr("n/a"));
    details << tr("Destination: %1").arg(reference.destinationAddress ? hex64(*reference.destinationAddress)
                                                                       : tr("unresolved"));
    details << tr("Instruction: %1").arg(reference.instructionAddress ? hex64(*reference.instructionAddress)
                                                                       : tr("n/a"));
    details << tr("File offset: %1").arg(reference.fileOffset ? hex64(*reference.fileOffset) : tr("n/a"));
    details << tr("Destination file offset: %1")
                   .arg(reference.destinationFileOffset ? hex64(*reference.destinationFileOffset) : tr("n/a"));
    if (!reference.sourceFunctionName.empty())
        details << tr("Source function: %1 @ %2").arg(q(reference.sourceFunctionName),
                                                       reference.sourceFunction ? hex64(*reference.sourceFunction) : tr("n/a"));
    if (!reference.destinationFunctionName.empty())
        details << tr("Destination function: %1 @ %2").arg(q(reference.destinationFunctionName),
                                                            reference.destinationFunction ? hex64(*reference.destinationFunction) : tr("n/a"));
    if (!reference.symbolName.empty()) details << tr("Symbol: %1").arg(q(reference.symbolName));
    if (!reference.dataTarget.empty()) details << tr("Data target: %1").arg(q(reference.dataTarget));
    details << tr("Evidence: %1").arg(q(reference.evidenceSource));
    if (reference.sourceFunction) {
        const auto function = std::find_if(xrefResult_.functions.begin(), xrefResult_.functions.end(),
                                           [&](const xrl::XrefFunction& item) {
                                               return item.candidate.address == *reference.sourceFunction;
                                           });
        if (function != xrefResult_.functions.end())
            details << tr("Function call graph: %1 incoming · %2 outgoing · depth %3%4")
                           .arg(function->incomingCalls).arg(function->outgoingCalls).arg(function->callDepth)
                           .arg(function->recursive ? tr(" · recursive") : QString());
    }
    xrefDetails_->setPlainText(details.join(QLatin1Char('\n')));
    const auto targetOffset = reference.destinationAddress
                                  ? current_.info.virtualToFileOffset(*reference.destinationAddress) : std::nullopt;
    const bool sourceMapped = reference.fileOffset && *reference.fileOffset < current_.info.fileSize;
    xrefDisasmButton_->setEnabled(reference.instructionAddress.has_value() && sourceMapped);
    xrefHexButton_->setEnabled(sourceMapped ||
                               (reference.destinationFileOffset &&
                                *reference.destinationFileOffset < current_.info.fileSize));
    xrefCfgButton_->setEnabled(reference.sourceFunction.has_value() || reference.destinationFunction.has_value());
    xrefStringButton_->setEnabled(reference.type == xrl::XrefType::String && targetOffset.has_value() && haveStrings_);
}

void MainWindow::navigateXrefDisassembly() {
    bool valid = false;
    const size_t index = xrefSelectedReferenceId_.toULongLong(&valid);
    if (!valid || index >= xrefResult_.references.size()) return;
    const auto& reference = xrefResult_.references[index];
    if (!reference.instructionAddress || !reference.fileOffset ||
        *reference.fileOffset >= current_.info.fileSize) {
        showStatus(tr("This instruction has no validated file-offset mapping."), true);
        return;
    }
    startModeCombo_->setCurrentIndex(0);
    startEdit_->setText(hex64(*reference.fileOffset));
    countSpin_->setValue(128);
    sidebar_->setCurrentRow(PageDisasm);
    runDisassembly();
    for (int row = 0; row < disasmTable_->model()->rowCount(); ++row) {
        const auto& values = disasmTable_->model()->rowAt(row);
        if (values.empty() || xrl::parseNumber(values[0].toStdString()) != reference.instructionAddress) continue;
        const QModelIndex source = disasmTable_->model()->index(row, 0);
        const QModelIndex proxy = disasmTable_->proxy()->mapFromSource(source);
        if (proxy.isValid()) {
            disasmTable_->view()->selectRow(proxy.row());
            disasmTable_->view()->scrollTo(proxy, QAbstractItemView::PositionAtCenter);
        }
        break;
    }
}

void MainWindow::navigateXrefHex() {
    bool valid = false;
    const size_t index = xrefSelectedReferenceId_.toULongLong(&valid);
    if (!valid || index >= xrefResult_.references.size()) return;
    const auto& reference = xrefResult_.references[index];
    std::optional<uint64_t> offset;
    offset = reference.destinationFileOffset;
    if (!offset && reference.fileOffset) offset = reference.fileOffset;
    if (!offset && reference.sourceAddress) offset = current_.info.virtualToFileOffset(*reference.sourceAddress);
    if (!offset || *offset >= current_.info.fileSize) {
        showStatus(tr("No validated file-offset mapping is available for this reference."), true);
        return;
    }
    showInHex(*offset);
}

void MainWindow::navigateXrefCfg() {
    bool valid = false;
    const size_t index = xrefSelectedReferenceId_.toULongLong(&valid);
    if (!valid || index >= xrefResult_.references.size()) return;
    const auto& reference = xrefResult_.references[index];
    const auto address = reference.sourceFunction ? reference.sourceFunction : reference.destinationFunction;
    if (!address) return;
    for (size_t i = 0; i < cfgCandidates_.size(); ++i) {
        if (cfgCandidates_[i].address == *address) {
            cfgFunctionCombo_->setCurrentIndex(static_cast<int>(i));
            cfgAddressEdit_->clear();
            break;
        }
    }
    sidebar_->setCurrentRow(PageCfg);
    runCfgAnalysis();
}

void MainWindow::navigateXrefString() {
    bool valid = false;
    const size_t index = xrefSelectedReferenceId_.toULongLong(&valid);
    if (!valid || index >= xrefResult_.references.size()) return;
    const auto& reference = xrefResult_.references[index];
    if (reference.type != xrl::XrefType::String || !reference.destinationAddress) return;
    const auto offset = current_.info.virtualToFileOffset(*reference.destinationAddress);
    if (!offset || !stringsTable_->selectOffset(*offset)) {
        showStatus(tr("The referenced string is not present in the current Strings Explorer results."), true);
        return;
    }
    sidebar_->setCurrentRow(PageStrings);
}

bool MainWindow::exportXref(int format) {
    if (!haveXref_) return false;
    QSettings settings;
    const QString base = QFileInfo(q(current_.info.fileName)).completeBaseName();
    const QString suffix = format == 0 ? QStringLiteral(".xref.json")
                         : format == 1 ? QStringLiteral(".xref.csv")
                                       : QStringLiteral(".xref.dot");
    const QString filter = format == 0 ? tr("JSON (*.json)")
                        : format == 1 ? tr("CSV (*.csv)")
                                      : tr("Graphviz DOT (*.dot)");
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Export cross-reference data"),
        QDir(settings.value("ui/lastExportDir", QDir::homePath()).toString()).filePath(base + suffix),
        filter);
    if (path.isEmpty()) return false;
    settings.setValue("ui/lastExportDir", QFileInfo(path).absolutePath());
    const std::string content = format == 0 ? xrl::renderXrefJson(xrefResult_)
                                : format == 1 ? xrl::renderXrefCsv(xrefResult_)
                                              : xrl::renderXrefDot(xrefResult_);
    std::ofstream output(toPath(path), std::ios::binary | std::ios::trunc);
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    output.flush();
    if (!output) {
        showStatus(tr("Failed to write XREF export to %1").arg(path), true);
        return false;
    }
    showStatus(tr("XREF data exported to %1").arg(path));
    return true;
}

QWidget* MainWindow::buildHexPage() {
    auto* root = new QVBoxLayout;
    root->addWidget(pageTitle(tr("Hex Viewer")));
    auto* bar = new QHBoxLayout;
    hexOffsetEdit_ = new QLineEdit;
    hexOffsetEdit_->setPlaceholderText(tr("Offset: 0x1F40 or decimal"));
    hexOffsetEdit_->setFixedWidth(240);
    hexOffsetEdit_->setFont(monoFont());
    hexGoButton_ = new QPushButton(tr("Go to offset"));
    hexInfo_ = mutedLabel({});
    bar->addWidget(hexOffsetEdit_);
    bar->addWidget(hexGoButton_);
    bar->addSpacing(12);
    bar->addWidget(hexInfo_, 1);
    root->addLayout(bar);
    hex_ = new HexView;
    auto* frame = new QFrame;
    frame->setObjectName("card");
    auto* fl = new QVBoxLayout(frame);
    fl->setContentsMargins(1, 1, 1, 1);
    fl->addWidget(hex_);
    root->addWidget(frame, 1);
    connect(hexGoButton_, &QPushButton::clicked, this, &MainWindow::goToHexOffset);
    connect(hexOffsetEdit_, &QLineEdit::returnPressed, this, &MainWindow::goToHexOffset);
    connect(hex_, &HexView::selectionChanged, this, &MainWindow::onHexSelection);
    return pageWrap(root);
}

QWidget* MainWindow::buildStringsPage() {
    auto* root = new QVBoxLayout;
    root->addWidget(pageTitle(tr("Strings Explorer")));

    auto* source = new QHBoxLayout;
    stringsPathLabel_ = new QLabel(tr("No file loaded"));
    stringsPathLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    stringsPathLabel_->setFont(monoFont());
    stringsPathLabel_->setToolTip(tr("The currently loaded file is scanned directly from disk."));
    stringsMinLengthSpin_ = new QSpinBox;
    stringsMinLengthSpin_->setRange(1, 256);
    stringsMinLengthSpin_->setValue(4);
    stringsMinLengthSpin_->setSuffix(tr(" characters minimum"));
    stringsRunButton_ = new QPushButton(tr("Extract strings"));
    setPrimary(stringsRunButton_);
    stringsCancelButton_ = new QPushButton(tr("Cancel"));
    stringsCancelButton_->setEnabled(false);
    source->addWidget(stringsPathLabel_, 1);
    source->addWidget(stringsMinLengthSpin_);
    source->addWidget(stringsRunButton_);
    source->addWidget(stringsCancelButton_);
    stringsProgress_ = new QProgressBar;
    stringsProgress_->setRange(0, 100);
    stringsProgress_->setTextVisible(false);
    stringsProgress_->setFixedWidth(150);
    stringsProgress_->hide();
    stringsStatusLabel_ = mutedLabel(
        tr("Extract printable strings from the loaded file. Results are pattern-based observations, not proof a program uses them."));
    source->addWidget(stringsProgress_);
    source->addWidget(stringsStatusLabel_, 1);
    root->addLayout(source);

    stringsTable_ = new StringsTable;
    stringsTable_->clear(tr("Open a file, then choose Extract strings. Files are scanned as untrusted data and are never executed."));
    root->addWidget(stringsTable_, 1);

    auto* footer = new QHBoxLayout;
    footer->addWidget(mutedLabel(tr("Limits: 100,000 results, 32 MiB retained string text, and 1 MiB per string. Search is literal text, not regular expressions.")), 1);
    stringsExportCsvButton_ = new QPushButton(tr("Export CSV..."));
    stringsExportJsonButton_ = new QPushButton(tr("Export JSON..."));
    stringsExportCsvButton_->setEnabled(false);
    stringsExportJsonButton_->setEnabled(false);
    footer->addWidget(stringsExportCsvButton_);
    footer->addWidget(stringsExportJsonButton_);
    root->addLayout(footer);

    connect(stringsRunButton_, &QPushButton::clicked, this, &MainWindow::runStringsExtraction);
    connect(stringsCancelButton_, &QPushButton::clicked, this, [this] {
        if (stringsCancel_) {
            stringsCancel_->store(true);
            stringsStatusLabel_->setText(tr("Cancelling string extraction..."));
        }
    });
    connect(stringsExportCsvButton_, &QPushButton::clicked, this, [this] { exportStrings(false); });
    connect(stringsExportJsonButton_, &QPushButton::clicked, this, [this] { exportStrings(true); });
    connect(stringsTable_, &StringsTable::stringSelected, this, &MainWindow::showStringInHex);
    return pageWrap(root);
}

QWidget* MainWindow::buildDisasmPage() {
    auto* root = new QVBoxLayout;
    root->addWidget(pageTitle(tr("Disassembly")));
    disasmTabs_ = new QTabWidget;

    // ---- linear disassembly
    auto* lin = new QWidget;
    auto* ll = new QVBoxLayout(lin);
    ll->setContentsMargins(12, 12, 12, 12);
    ll->addWidget(mutedLabel(tr("Linear-sweep disassembly from a chosen location. Use Control Flow Graph for bounded function-level "
                                "flow analysis; this listing alone does not infer function boundaries.")));
    auto* bar = new QHBoxLayout;
    startCombo_ = new QComboBox;
    startCombo_->setMinimumWidth(300);
    startModeCombo_ = new QComboBox;
    startModeCombo_->addItems({tr("File offset"), tr("Virtual address")});
    startEdit_ = new QLineEdit;
    startEdit_->setFont(monoFont());
    startEdit_->setPlaceholderText(tr("0x... or decimal"));
    startEdit_->setFixedWidth(180);
    countSpin_ = new QSpinBox;
    countSpin_->setRange(1, 20000);
    countSpin_->setValue(500);
    countSpin_->setSuffix(tr(" instr."));
    disasmButton_ = new QPushButton(tr("Disassemble"));
    setPrimary(disasmButton_);
    bar->addWidget(startCombo_, 1);
    bar->addWidget(startModeCombo_);
    bar->addWidget(startEdit_);
    bar->addWidget(countSpin_);
    bar->addWidget(disasmButton_);
    ll->addLayout(bar);
    disasmInfo_ = mutedLabel({});
    ll->addWidget(disasmInfo_);
    disasmTable_ = new FilterTable;
    disasmTable_->layout()->setContentsMargins(0, 0, 0, 0);
    ll->addWidget(disasmTable_, 1);
    disasmTabs_->addTab(lin, tr("Linear disassembly (Capstone)"));
    disasmTabs_->addTab(buildGhidraTab(), tr("Ghidra (optional)"));
    root->addWidget(disasmTabs_, 1);

    connect(startCombo_, &QComboBox::activated, this, [this](int i) {
        if (i < 0 || static_cast<size_t>(i) >= startPoints_.size()) return;
        startModeCombo_->setCurrentIndex(0);
        startEdit_->setText(q(xrl::hex(startPoints_[static_cast<size_t>(i)].fileOffset)));
    });
    connect(disasmButton_, &QPushButton::clicked, this, &MainWindow::runDisassembly);
    connect(startEdit_, &QLineEdit::returnPressed, this, &MainWindow::runDisassembly);
    connect(disasmTable_->view(), &QTableView::doubleClicked, this, [this](const QModelIndex& idx) {
        const auto src = disasmTable_->proxy()->mapToSource(idx);
        const auto n = xrl::parseNumber(disasmTable_->model()->rowAt(src.row()).value(1).toStdString());
        if (n) showInHex(*n);
    });
    connect(disasmTable_->view()->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this](const QModelIndex& current, const QModelIndex&) { onCfgInstructionSelected(current); });
    return pageWrap(root);
}

QWidget* MainWindow::buildCfgPage() {
    auto* root = new QVBoxLayout;
    root->addWidget(pageTitle(tr("Control Flow Graph")));
    root->addWidget(mutedLabel(tr("Builds a graph from executable bytes reachable from a metadata-backed or manually supplied start address. "
                                  "Candidates are evidence-labelled; unresolved indirect control flow stays explicit.")));

    auto* functionRow = new QHBoxLayout;
    cfgFunctionCombo_ = new QComboBox;
    cfgFunctionCombo_->setEditable(true);
    cfgFunctionCombo_->setMinimumWidth(280);
    cfgFunctionCombo_->setInsertPolicy(QComboBox::NoInsert);
    cfgFunctionCombo_->setPlaceholderText(tr("Search metadata function candidates"));
    cfgFunctionCombo_->completer()->setCaseSensitivity(Qt::CaseInsensitive);
    cfgAddressModeCombo_ = new QComboBox;
    cfgAddressModeCombo_->addItems({tr("Virtual address"), tr("File offset")});
    cfgAddressEdit_ = new QLineEdit;
    cfgAddressEdit_->setFont(monoFont());
    cfgAddressEdit_->setPlaceholderText(tr("Optional start address: 0x..."));
    cfgAddressEdit_->setFixedWidth(190);
    cfgRunButton_ = new QPushButton(tr("Analyze function"));
    setPrimary(cfgRunButton_);
    cfgCancelButton_ = new QPushButton(tr("Cancel"));
    cfgCancelButton_->setEnabled(false);
    functionRow->addWidget(cfgFunctionCombo_, 1);
    functionRow->addWidget(cfgAddressModeCombo_);
    functionRow->addWidget(cfgAddressEdit_);
    functionRow->addWidget(cfgRunButton_);
    functionRow->addWidget(cfgCancelButton_);
    root->addLayout(functionRow);

    auto* toolsRow = new QHBoxLayout;
    cfgBlockSearchEdit_ = new QLineEdit;
    cfgBlockSearchEdit_->setFont(monoFont());
    cfgBlockSearchEdit_->setPlaceholderText(tr("Find block address"));
    cfgBlockSearchEdit_->setFixedWidth(190);
    cfgFindBlockButton_ = new QPushButton(tr("Find block"));
    cfgFitButton_ = new QPushButton(tr("Fit graph"));
    cfgHexButton_ = new QPushButton(tr("Open selected block in Hex"));
    cfgHexButton_->setEnabled(false);
    cfgConditionalCheck_ = new QCheckBox(tr("Conditional edges"));
    cfgConditionalCheck_->setChecked(true);
    cfgUnresolvedCheck_ = new QCheckBox(tr("External / unresolved"));
    cfgUnresolvedCheck_->setChecked(true);
    cfgExportJsonButton_ = new QPushButton(tr("JSON..."));
    cfgExportDotButton_ = new QPushButton(tr("Graphviz DOT..."));
    toolsRow->addWidget(cfgBlockSearchEdit_);
    toolsRow->addWidget(cfgFindBlockButton_);
    toolsRow->addWidget(cfgFitButton_);
    toolsRow->addWidget(cfgHexButton_);
    toolsRow->addStretch(1);
    toolsRow->addWidget(cfgConditionalCheck_);
    toolsRow->addWidget(cfgUnresolvedCheck_);
    toolsRow->addWidget(cfgExportJsonButton_);
    toolsRow->addWidget(cfgExportDotButton_);
    root->addLayout(toolsRow);

    auto* statusRow = new QHBoxLayout;
    cfgProgress_ = new QProgressBar;
    cfgProgress_->setRange(0, 100);
    cfgProgress_->setTextVisible(false);
    cfgProgress_->setFixedWidth(150);
    cfgProgress_->hide();
    cfgStatusLabel_ = mutedLabel(tr("Load a supported executable to choose a start point."));
    statusRow->addWidget(cfgProgress_);
    statusRow->addWidget(cfgStatusLabel_, 1);
    root->addLayout(statusRow);

    auto* split = new QSplitter(Qt::Horizontal);
    cfgGraphView_ = new CfgGraphView;
    cfgDetails_ = new QPlainTextEdit;
    cfgDetails_->setReadOnly(true);
    cfgDetails_->setFont(monoFont());
    cfgDetails_->setMinimumWidth(270);
    cfgDetails_->setPlaceholderText(tr("Function metrics, selected block metadata, calls, and uncertainty notes appear here."));
    split->addWidget(cfgGraphView_);
    split->addWidget(cfgDetails_);
    split->setStretchFactor(0, 4);
    split->setStretchFactor(1, 1);
    split->setSizes({820, 360});
    root->addWidget(split, 1);
    root->addWidget(mutedLabel(tr("Legend: blue = conditional, violet = direct jump, gray = fall-through, amber dashed = external or unresolved. "
                                  "Metrics use only decoded intraprocedural edges; they do not prove complete function recovery.")));

    connect(cfgRunButton_, &QPushButton::clicked, this, &MainWindow::runCfgAnalysis);
    connect(cfgCancelButton_, &QPushButton::clicked, this, [this] {
        if (cfgCancel_) {
            cfgCancel_->store(true);
            cfgStatusLabel_->setText(tr("Cancelling CFG analysis..."));
        }
    });
    connect(cfgFindBlockButton_, &QPushButton::clicked, this, &MainWindow::findCfgBlock);
    connect(cfgBlockSearchEdit_, &QLineEdit::returnPressed, this, &MainWindow::findCfgBlock);
    connect(cfgFitButton_, &QPushButton::clicked, cfgGraphView_, &CfgGraphView::fitGraph);
    connect(cfgHexButton_, &QPushButton::clicked, this, [this] {
        const auto address = cfgGraphView_->selectedBlockAddress();
        if (address) showCfgBlockInHex(*address);
    });
    connect(cfgExportJsonButton_, &QPushButton::clicked, this, [this] { exportCfg(false); });
    connect(cfgExportDotButton_, &QPushButton::clicked, this, [this] { exportCfg(true); });
    connect(cfgConditionalCheck_, &QCheckBox::toggled, cfgGraphView_, &CfgGraphView::setShowConditionalEdges);
    connect(cfgUnresolvedCheck_, &QCheckBox::toggled, cfgGraphView_, &CfgGraphView::setShowUnresolvedEdges);
    connect(cfgGraphView_, &CfgGraphView::blockSelected, this, &MainWindow::onCfgBlockSelected);
    connect(cfgGraphView_, &CfgGraphView::blockActivated, this, &MainWindow::showCfgBlockInHex);
    connect(cfgFunctionCombo_, qOverload<int>(&QComboBox::activated), this, [this](int) {
        cfgAddressEdit_->clear();
    });
    return pageWrap(root);
}

QWidget* MainWindow::buildGhidraTab() {
    auto* w = new QWidget;
    auto* l = new QVBoxLayout(w);
    l->setContentsMargins(12, 12, 12, 12);
    ghidraStatus_ = mutedLabel({});
    l->addWidget(ghidraStatus_);
    l->addWidget(mutedLabel(tr("Runs Ghidra's headless analyzer on the selected file only when you press Run. Function names, sizes and "
                               "decompiled code shown here are exactly what Ghidra reports; Xaynx Reverse Lab adds nothing to them.")));
    auto* bar = new QHBoxLayout;
    ghidraDecompile_ = new QCheckBox(tr("Also run Ghidra's decompiler (slow)"));
    ghidraMaxDecomp_ = new QSpinBox;
    ghidraMaxDecomp_->setRange(1, 2000);
    ghidraMaxDecomp_->setValue(50);
    ghidraMaxDecomp_->setPrefix(tr("up to "));
    ghidraMaxDecomp_->setSuffix(tr(" functions"));
    ghidraRun_ = new QPushButton(tr("Run Ghidra analysis"));
    setPrimary(ghidraRun_);
    ghidraCancel_ = new QPushButton(tr("Cancel"));
    bar->addWidget(ghidraDecompile_);
    bar->addWidget(ghidraMaxDecomp_);
    bar->addStretch(1);
    bar->addWidget(ghidraRun_);
    bar->addWidget(ghidraCancel_);
    l->addLayout(bar);

    auto* split = new QSplitter(Qt::Vertical);
    ghidraFunctions_ = new FilterTable;
    ghidraFunctions_->layout()->setContentsMargins(0, 0, 0, 0);
    auto* tabs = new QTabWidget;
    ghidraDecompiled_ = new QPlainTextEdit;
    ghidraDecompiled_->setReadOnly(true);
    ghidraDecompiled_->setFont(monoFont());
    ghidraDecompiled_->setPlaceholderText(tr("Select a function to view Ghidra's decompiler output (if it was requested)."));
    ghidraLog_ = new QPlainTextEdit;
    ghidraLog_->setReadOnly(true);
    ghidraLog_->setFont(monoFont());
    ghidraLog_->setMaximumBlockCount(5000);
    tabs->addTab(ghidraDecompiled_, tr("Decompiled (Ghidra)"));
    tabs->addTab(ghidraLog_, tr("Ghidra log"));
    split->addWidget(ghidraFunctions_);
    split->addWidget(tabs);
    split->setStretchFactor(0, 3);
    split->setStretchFactor(1, 2);
    l->addWidget(split, 1);

    connect(ghidraRun_, &QPushButton::clicked, this, &MainWindow::runGhidra);
    connect(ghidraFunctions_->view()->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this] { showGhidraFunction(); });
    return w;
}

QWidget* MainWindow::buildDiffPage() {
    auto* root = new QVBoxLayout;
    root->addWidget(pageTitle(tr("Binary Diff & Comparison")));

    auto* topLay = new QVBoxLayout;

    // Baseline (A)
    auto* rowA = new QHBoxLayout;
    diffPathLabelA_ = new QLabel(tr("No baseline file selected"));
    diffPathLabelA_->setFont(monoFont());
    diffPathLabelA_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    diffBtnA_ = new QPushButton(tr("Select File A (Baseline)..."));
    diffUseCurrentBtn_ = new QPushButton(tr("Use Current Loaded File"));
    diffInfoLabelA_ = mutedLabel(tr("File A info"));
    rowA->addWidget(new QLabel(tr("<b>Baseline (A):</b>")));
    rowA->addWidget(diffPathLabelA_, 1);
    rowA->addWidget(diffBtnA_);
    rowA->addWidget(diffUseCurrentBtn_);
    topLay->addLayout(rowA);
    topLay->addWidget(diffInfoLabelA_);

    // Comparison (B)
    auto* rowB = new QHBoxLayout;
    diffPathLabelB_ = new QLabel(tr("No comparison file selected"));
    diffPathLabelB_->setFont(monoFont());
    diffPathLabelB_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    diffBtnB_ = new QPushButton(tr("Select File B (Comparison)..."));
    diffInfoLabelB_ = mutedLabel(tr("File B info"));
    rowB->addWidget(new QLabel(tr("<b>Comparison (B):</b>")));
    rowB->addWidget(diffPathLabelB_, 1);
    rowB->addWidget(diffBtnB_);
    topLay->addLayout(rowB);
    topLay->addWidget(diffInfoLabelB_);

    // Actions & Progress
    auto* rowAct = new QHBoxLayout;
    diffRunBtn_ = new QPushButton(tr("Compare Binaries"));
    setPrimary(diffRunBtn_);
    diffProgress_ = new QProgressBar;
    diffProgress_->setRange(0, 100);
    diffProgress_->setFixedWidth(180);
    diffProgress_->setTextVisible(false);
    diffProgress_->hide();
    diffStatusLabel_ = mutedLabel(tr("Select two files to compare at the byte and executable structure levels."));
    diffExportJsonBtn_ = new QPushButton(tr("Export Diff JSON..."));
    diffExportJsonBtn_->setEnabled(false);

    rowAct->addWidget(diffRunBtn_);
    rowAct->addWidget(diffProgress_);
    rowAct->addWidget(diffStatusLabel_, 1);
    rowAct->addWidget(diffExportJsonBtn_);
    topLay->addLayout(rowAct);

    root->addWidget(makeCard(tr("File inputs & action"), topLay));

    // Center splitter
    auto* vSplit = new QSplitter(Qt::Vertical);

    // Top: Navigation bar + Synchronized Hex Views
    auto* hexContainer = new QWidget;
    auto* hexLay = new QVBoxLayout(hexContainer);
    hexLay->setContentsMargins(0, 0, 0, 0);
    hexLay->setSpacing(6);

    auto* navBar = new QHBoxLayout;
    diffPrevBtn_ = new QPushButton(tr("◀ Previous Diff"));
    diffNextBtn_ = new QPushButton(tr("Next Diff ▶"));
    diffPrevBtn_->setEnabled(false);
    diffNextBtn_->setEnabled(false);
    diffNavLabel_ = mutedLabel(tr("No differences to display."));
    navBar->addWidget(diffPrevBtn_);
    navBar->addWidget(diffNextBtn_);
    navBar->addWidget(diffNavLabel_, 1);
    hexLay->addLayout(navBar);

    auto* hHexSplit = new QSplitter(Qt::Horizontal);

    auto* frameA = new QFrame;
    frameA->setObjectName("card");
    auto* layA = new QVBoxLayout(frameA);
    layA->setContentsMargins(6, 6, 6, 6);
    layA->addWidget(new QLabel(tr("<b>Baseline File (A)</b>")));
    diffHexA_ = new HexView;
    layA->addWidget(diffHexA_, 1);

    auto* frameB = new QFrame;
    frameB->setObjectName("card");
    auto* layB = new QVBoxLayout(frameB);
    layB->setContentsMargins(6, 6, 6, 6);
    layB->addWidget(new QLabel(tr("<b>Comparison File (B)</b>")));
    diffHexB_ = new HexView;
    layB->addWidget(diffHexB_, 1);

    hHexSplit->addWidget(frameA);
    hHexSplit->addWidget(frameB);
    hexLay->addWidget(hHexSplit, 1);
    vSplit->addWidget(hexContainer);

    // Synchronized scroll connection
    connect(diffHexA_, &HexView::scrolled, diffHexB_, &HexView::setExternalScroll);
    connect(diffHexB_, &HexView::scrolled, diffHexA_, &HexView::setExternalScroll);

    // Bottom: Tabs for Metadata changes, Byte diff list, and Text summary
    auto* diffTabs = new QTabWidget;
    diffMetaTable_ = new FilterTable;
    diffByteTable_ = new FilterTable;
    diffSummaryText_ = new QPlainTextEdit;
    diffSummaryText_->setReadOnly(true);
    diffSummaryText_->setFont(monoFont());

    diffTabs->addTab(diffMetaTable_, tr("Executable Metadata Changes"));
    diffTabs->addTab(diffByteTable_, tr("Byte Difference Regions"));
    diffTabs->addTab(diffSummaryText_, tr("Comparison Summary"));

    vSplit->addWidget(diffTabs);
    vSplit->setStretchFactor(0, 3);
    vSplit->setStretchFactor(1, 2);

    root->addWidget(vSplit, 1);

    // Connections
    connect(diffBtnA_, &QPushButton::clicked, this, &MainWindow::selectDiffFileA);
    connect(diffBtnB_, &QPushButton::clicked, this, &MainWindow::selectDiffFileB);
    connect(diffUseCurrentBtn_, &QPushButton::clicked, this, &MainWindow::useCurrentAsBaseline);
    connect(diffRunBtn_, &QPushButton::clicked, this, &MainWindow::runDiff);
    connect(diffExportJsonBtn_, &QPushButton::clicked, this, [this] { exportDiffReport(true); });
    connect(diffPrevBtn_, &QPushButton::clicked, this, &MainWindow::prevDiff);
    connect(diffNextBtn_, &QPushButton::clicked, this, &MainWindow::nextDiff);

    // Double-click jumps on tables
    connect(diffMetaTable_->view(), &QTableView::doubleClicked, this, [this](const QModelIndex& idx) {
        const auto src = diffMetaTable_->proxy()->mapToSource(idx);
        const auto row = diffMetaTable_->model()->rowAt(src.row());
        if (row.size() > 6) {
            const auto offA = xrl::parseNumber(row[5].toStdString());
            const auto offB = xrl::parseNumber(row[6].toStdString());
            if (offA) diffHexA_->goToOffset(*offA);
            if (offB) diffHexB_->goToOffset(*offB);
        }
    });

    connect(diffByteTable_->view(), &QTableView::doubleClicked, this, [this](const QModelIndex& idx) {
        const auto src = diffByteTable_->proxy()->mapToSource(idx);
        jumpToDiff(src.row());
    });

    return pageWrap(root);
}

QWidget* MainWindow::buildEntropyPage() {
    auto* root = new QVBoxLayout;
    root->addWidget(pageTitle(tr("Entropy Heatmap")));

    auto* controls = new QVBoxLayout;
    auto* rowA = new QHBoxLayout;
    entropyPathAEdit_ = new QLineEdit;
    entropyPathAEdit_->setReadOnly(true);
    entropyPathAEdit_->setPlaceholderText(tr("Choose a file or use the currently loaded file"));
    entropyPathAEdit_->setFont(monoFont());
    auto* chooseA = new QPushButton(tr("Choose File A..."));
    auto* useCurrent = new QPushButton(tr("Use Current File"));
    rowA->addWidget(new QLabel(tr("File A")));
    rowA->addWidget(entropyPathAEdit_, 1);
    rowA->addWidget(chooseA);
    rowA->addWidget(useCurrent);
    controls->addLayout(rowA);

    auto* rowB = new QHBoxLayout;
    entropyPathBEdit_ = new QLineEdit;
    entropyPathBEdit_->setReadOnly(true);
    entropyPathBEdit_->setPlaceholderText(tr("Optional comparison file"));
    entropyPathBEdit_->setFont(monoFont());
    auto* chooseB = new QPushButton(tr("Choose File B..."));
    auto* clearB = new QPushButton(tr("Clear B"));
    rowB->addWidget(new QLabel(tr("File B")));
    rowB->addWidget(entropyPathBEdit_, 1);
    rowB->addWidget(chooseB);
    rowB->addWidget(clearB);
    controls->addLayout(rowB);

    auto* actions = new QHBoxLayout;
    entropyBlockSizeCombo_ = new QComboBox;
    for (const size_t bytes : {64u, 128u, 256u, 512u, 1024u, 4096u}) {
        entropyBlockSizeCombo_->addItem(tr("%1 bytes").arg(bytes), static_cast<qulonglong>(bytes));
    }
    entropyBlockSizeCombo_->setCurrentIndex(2);
    entropyThresholdSpin_ = new QDoubleSpinBox;
    entropyThresholdSpin_->setRange(0.0, 8.0);
    entropyThresholdSpin_->setSingleStep(0.25);
    entropyThresholdSpin_->setValue(1.5);
    entropyThresholdSpin_->setSuffix(tr(" bit variation"));
    entropyRunBtn_ = new QPushButton(tr("Analyze Entropy"));
    setPrimary(entropyRunBtn_);
    entropyCancelBtn_ = new QPushButton(tr("Cancel"));
    entropyCancelBtn_->setEnabled(false);
    entropyProgress_ = new QProgressBar;
    entropyProgress_->setRange(0, 100);
    entropyProgress_->setFixedWidth(150);
    entropyProgress_->setTextVisible(false);
    entropyProgress_->hide();
    entropyStatusLabel_ = mutedLabel(tr("Choose File A to inspect byte entropy. Entropy is descriptive, not a malware verdict."));
    actions->addWidget(new QLabel(tr("Block size")));
    actions->addWidget(entropyBlockSizeCombo_);
    actions->addWidget(entropyThresholdSpin_);
    actions->addSpacing(8);
    actions->addWidget(entropyRunBtn_);
    actions->addWidget(entropyCancelBtn_);
    actions->addWidget(entropyProgress_);
    actions->addWidget(entropyStatusLabel_, 1);
    controls->addLayout(actions);
    root->addWidget(makeCard(tr("Inputs & analysis settings"), controls));

    auto* heatmapFrame = new QFrame;
    heatmapFrame->setObjectName("card");
    auto* heatmapLayout = new QVBoxLayout(heatmapFrame);
    heatmapLayout->setContentsMargins(8, 8, 8, 8);
    entropyHeatmap_ = new EntropyHeatmap;
    entropyHeatmap_->setMinimumHeight(190);
    heatmapLayout->addWidget(entropyHeatmap_, 1);
    auto* legend = new QHBoxLayout;
    legend->addWidget(mutedLabel(tr("Entropy scale:")));
    for (const auto& entry : {std::pair<QString, QString>{tr("0 bits"), QStringLiteral("#426784")},
                              {tr("≈4 bits"), QStringLiteral("#2a9d8f")},
                              {tr("8 bits"), QStringLiteral("#f2a65a")}}) {
        auto* swatch = new QLabel(QStringLiteral("  "));
        swatch->setStyleSheet(QStringLiteral("background:%1; border-radius:2px;").arg(entry.second));
        legend->addWidget(swatch);
        legend->addWidget(mutedLabel(entry.first));
    }
    auto* unusualSwatch = new QLabel(QStringLiteral("  "));
    unusualSwatch->setStyleSheet(QStringLiteral("background:#ff786f; border-radius:2px;"));
    legend->addWidget(unusualSwatch);
    legend->addWidget(mutedLabel(tr("Unusual change")));
    legend->addStretch(1);
    legend->addWidget(mutedLabel(tr("Ctrl + scroll to zoom")));
    heatmapLayout->addLayout(legend);
    root->addWidget(heatmapFrame, 2);

    entropyDetails_ = new QPlainTextEdit;
    entropyDetails_->setReadOnly(true);
    entropyDetails_->setFont(monoFont());
    entropyDetails_->setMaximumHeight(210);
    entropyDetails_->setPlaceholderText(tr("File entropy, block statistics, extreme regions, SHA-256, and comparison results appear here."));
    root->addWidget(entropyDetails_);
    auto* exportRow = new QHBoxLayout;
    exportRow->addWidget(mutedLabel(tr("JSON includes summary, extreme regions, and every block. CSV exports block-level data.")), 1);
    entropyExportCsvBtn_ = new QPushButton(tr("Export Blocks CSV..."));
    entropyExportJsonBtn_ = new QPushButton(tr("Export JSON Report..."));
    entropyExportCsvBtn_->setEnabled(false);
    entropyExportJsonBtn_->setEnabled(false);
    exportRow->addWidget(entropyExportCsvBtn_);
    exportRow->addWidget(entropyExportJsonBtn_);
    root->addLayout(exportRow);

    connect(chooseA, &QPushButton::clicked, this, [this] { chooseEntropyFile(false); });
    connect(chooseB, &QPushButton::clicked, this, [this] { chooseEntropyFile(true); });
    connect(clearB, &QPushButton::clicked, this, [this] {
        entropyPathB_.clear();
        entropyPathBEdit_->clear();
        haveEntropyComparison_ = false;
        entropyComparison_ = {};
        updateEntropyPresentation();
    });
    connect(useCurrent, &QPushButton::clicked, this, [this] {
        if (!haveResult_ || current_.info.filePath.empty()) {
            showStatus(tr("No file is currently loaded."), true);
            return;
        }
        entropyPathA_ = q(current_.info.filePath);
        entropyPathAEdit_->setText(entropyPathA_);
        haveEntropyPrimary_ = false;
        haveEntropyComparison_ = false;
        entropyComparison_ = {};
        updateEntropyPresentation();
        updateEnabled();
    });
    connect(entropyRunBtn_, &QPushButton::clicked, this, &MainWindow::runEntropyAnalysis);
    connect(entropyCancelBtn_, &QPushButton::clicked, this, [this] {
        if (entropyCancel_) {
            entropyCancel_->store(true);
            entropyStatusLabel_->setText(tr("Cancelling entropy analysis..."));
        }
    });
    connect(entropyThresholdSpin_, qOverload<double>(&QDoubleSpinBox::valueChanged), this,
            [this](double value) {
                entropyHeatmap_->setVariationThreshold(value);
                updateEntropyPresentation();
            });
    connect(entropyExportJsonBtn_, &QPushButton::clicked, this, [this] { exportEntropy(false); });
    connect(entropyExportCsvBtn_, &QPushButton::clicked, this, [this] { exportEntropy(true); });
    connect(entropyHeatmap_, &EntropyHeatmap::blockSelected, this, [this](quint64 offset) {
        if (!haveEntropyPrimary_ || !haveResult_ || !current_.data) return;
        const QString analyzed = QFileInfo(entropyPathA_).canonicalFilePath();
        const QString loaded = QFileInfo(q(current_.info.filePath)).canonicalFilePath();
        if (!analyzed.isEmpty() && analyzed == loaded) showInHex(offset);
        else showStatus(tr("The selected block belongs to File A, not the file currently open in the Hex Viewer."));
    });
    return pageWrap(root);
}

QWidget* MainWindow::buildReportsPage() {
    auto* root = new QVBoxLayout;
    root->addWidget(pageTitle(tr("Reports")));
    auto* bar = new QHBoxLayout;
    reportIncludeDisasm_ = new QCheckBox(tr("Include last disassembly listing"));
    reportIncludeGhidra_ = new QCheckBox(tr("Include Ghidra results"));
    reportIncludeDisasm_->setChecked(true);
    reportIncludeGhidra_->setChecked(true);
    exportJsonButton_ = new QPushButton(tr("Export JSON..."));
    exportTextButton_ = new QPushButton(tr("Export text..."));
    setPrimary(exportJsonButton_);
    bar->addWidget(reportIncludeDisasm_);
    bar->addWidget(reportIncludeGhidra_);
    bar->addStretch(1);
    bar->addWidget(exportTextButton_);
    bar->addWidget(exportJsonButton_);
    root->addLayout(bar);
    reportPreview_ = new QPlainTextEdit;
    reportPreview_->setReadOnly(true);
    reportPreview_->setFont(monoFont());
    reportPreview_->setLineWrapMode(QPlainTextEdit::NoWrap);
    root->addWidget(reportPreview_, 1);
    root->addWidget(mutedLabel(tr("The preview is the plain-text report. JSON export contains the same data in a structured form. "
                                  "Heuristic findings are labelled and are not verdicts.")));
    connect(exportJsonButton_, &QPushButton::clicked, this, [this] { exportReport(true); });
    connect(exportTextButton_, &QPushButton::clicked, this, [this] { exportReport(false); });
    connect(reportIncludeDisasm_, &QCheckBox::toggled, this, &MainWindow::refreshReportPreview);
    connect(reportIncludeGhidra_, &QCheckBox::toggled, this, &MainWindow::refreshReportPreview);
    return pageWrap(root);
}

QWidget* MainWindow::buildWorkspacePage() {
    workspaceWidget_ = new WorkspaceWidget(
        workspace_,
        [this](const xrl::WorkspaceData& data, bool recover, QString* error) {
            return persistWorkspace(data, recover, error);
        });
    if (!workspaceLoadError_.isEmpty())
        workspaceWidget_->setStorageError(workspaceLoadError_);
    return workspaceWidget_;
}

QWidget* MainWindow::buildFunctionExplorerPage() {
    auto* root = new QVBoxLayout;
    root->addWidget(pageTitle(tr("Function Explorer")));
    root->addWidget(mutedLabel(tr("Browse metadata-backed function candidates, parsed relocations, and available debug identifiers. "
                                  "Candidates are not proof of complete function discovery; unavailable analysis is shown explicitly.")));

    functionExplorerTabs_ = new QTabWidget;
    functionExplorerTable_ = new FilterTable;
    relocationExplorerTable_ = new FilterTable;
    debugInfoTable_ = new FilterTable;

    auto* functionsPage = new QWidget;
    auto* functionsLayout = new QVBoxLayout(functionsPage);
    auto* actions = new QHBoxLayout;
    functionCfgButton_ = new QPushButton(tr("Analyze in CFG"));
    functionDisasmButton_ = new QPushButton(tr("Disassemble"));
    functionHexButton_ = new QPushButton(tr("Show in Hex"));
    actions->addWidget(functionCfgButton_);
    actions->addWidget(functionDisasmButton_);
    actions->addWidget(functionHexButton_);
    actions->addStretch(1);
    functionsLayout->addLayout(actions);
    functionsLayout->addWidget(functionExplorerTable_, 1);
    functionExplorerTabs_->addTab(functionsPage, tr("Functions"));
    functionExplorerTabs_->addTab(relocationExplorerTable_, tr("Relocations"));
    functionExplorerTabs_->addTab(debugInfoTable_, tr("Debug information"));
    root->addWidget(functionExplorerTabs_, 1);

    connect(functionExplorerTable_->view()->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, [this] {
                const bool selected = selectedExplorerFunction().has_value();
                functionCfgButton_->setEnabled(selected && haveResult_ && current_.data &&
                                               xrl::cfgSupported(current_.info) && !cfgWatcher_.isRunning());
                functionDisasmButton_->setEnabled(selected && haveResult_ && current_.data &&
                                                  xrl::disassemblySupported(current_.info));
                functionHexButton_->setEnabled(selected && haveResult_ && current_.data);
            });
    connect(functionExplorerTable_->view(), &QTableView::doubleClicked, this, [this] {
        openExplorerFunctionDisassembly();
    });
    connect(functionCfgButton_, &QPushButton::clicked, this, &MainWindow::openExplorerFunctionCfg);
    connect(functionDisasmButton_, &QPushButton::clicked, this, &MainWindow::openExplorerFunctionDisassembly);
    connect(functionHexButton_, &QPushButton::clicked, this, [this] {
        if (const auto address = selectedExplorerFunction()) {
            const auto candidate = std::find_if(cfgCandidates_.begin(), cfgCandidates_.end(),
                                                [address](const auto& item) { return item.address == *address; });
            if (candidate != cfgCandidates_.end()) showInHex(candidate->fileOffset);
        }
    });
    return pageWrap(root);
}

QWidget* MainWindow::buildSettingsPage() {
    auto* root = new QVBoxLayout;
    root->addWidget(pageTitle(tr("Settings")));

    QSettings s;
    auto* gl = new QVBoxLayout;
    gl->addWidget(mutedLabel(tr("Ghidra is optional. Select the Ghidra installation directory (the folder containing 'ghidraRun' and 'support'). "
                                "Ghidra also requires a compatible JDK, which is not managed by this application.")));
    auto* row = new QHBoxLayout;
    ghidraPathEdit_ = new QLineEdit(s.value("ghidra/path").toString());
    ghidraPathEdit_->setPlaceholderText(tr("Not configured"));
    auto* browse = new QPushButton(tr("Browse..."));
    auto* detect = new QPushButton(tr("Detect"));
    row->addWidget(ghidraPathEdit_, 1);
    row->addWidget(browse);
    row->addWidget(detect);
    gl->addLayout(row);
    ghidraPathStatus_ = mutedLabel({});
    gl->addWidget(ghidraPathStatus_);
    root->addWidget(makeCard(tr("Ghidra integration"), gl));

    auto* ll = new QVBoxLayout;
    auto* lrow = new QHBoxLayout;
    maxFileSpin_ = new QSpinBox;
    maxFileSpin_->setRange(1, 4096);
    maxFileSpin_->setSuffix(tr(" MiB"));
    maxFileSpin_->setValue(s.value("limits/maxMiB", 512).toInt());
    lrow->addWidget(new QLabel(tr("Maximum file size to load")));
    lrow->addWidget(maxFileSpin_);
    lrow->addStretch(1);
    ll->addLayout(lrow);
    ll->addWidget(mutedLabel(tr("Files larger than this are rejected without being read. The whole file is held in memory while open. "
                                "Takes effect for the next file opened.")));
    root->addWidget(makeCard(tr("Limits"), ll));

    auto* al = new QVBoxLayout;
    al->addWidget(mutedLabel(tr("Version %1\nDisassembly engine: %2\nQt %3").arg(XRL_VERSION, q(xrl::disassemblerVersion()), QString::fromLatin1(qVersion()))));
    root->addWidget(makeCard(tr("Build"), al));
    root->addStretch(1);

    connect(browse, &QPushButton::clicked, this, &MainWindow::browseGhidra);
    connect(detect, &QPushButton::clicked, this, &MainWindow::detectGhidraInstall);
    connect(ghidraPathEdit_, &QLineEdit::editingFinished, this, &MainWindow::applyGhidraPath);
    connect(maxFileSpin_, qOverload<int>(&QSpinBox::valueChanged), this,
            [](int v) { QSettings().setValue("limits/maxMiB", v); });
    return pageWrap(root);
}

// ============================================================================ loading
xrl::Limits MainWindow::currentLimits() const {
    xrl::Limits l;
    l.maxFileSize = static_cast<uint64_t>(maxFileSpin_->value()) * kMiB;
    return l;
}

void MainWindow::openFileDialog() {
    if (busy_) return;
    QSettings s;
    const QString path = QFileDialog::getOpenFileName(this, tr("Select a binary to analyse"), s.value("ui/lastDir").toString(),
                                                      tr("All files (*)"));
    if (path.isEmpty()) return;
    s.setValue("ui/lastDir", QFileInfo(path).absolutePath());
    loadFile(path);
}

void MainWindow::loadFile(const QString& path) {
    if (busy_) {
        showStatus(tr("An analysis is already in progress."), true);
        return;
    }
    if (stringsCancel_) stringsCancel_->store(true);
    if (cfgCancel_) cfgCancel_->store(true);
    if (xrefCancel_) xrefCancel_->store(true);
    if (staticCancel_) staticCancel_->store(true);
    staticAnalysisPath_.clear();
    xrefAnalysisPath_.clear();
    cfgAnalysisPath_.clear();
    setBusy(true, tr("Reading %1").arg(QFileInfo(path).fileName()));
    if (stringsRunButton_) stringsRunButton_->setEnabled(false);
    updateEnabled();
    const auto limits = currentLimits();
    const auto fsPath = toPath(path);
    watcher_.setFuture(QtConcurrent::run([this, limits, fsPath] {
        return xrl::analyzeFile(fsPath, limits, [this](int pct, const std::string& stage) {
            QMetaObject::invokeMethod(this, [this, pct, s = q(stage)] { onProgress(pct, s); }, Qt::QueuedConnection);
        });
    }));
}

void MainWindow::onProgress(int percent, const QString& stage) {
    if (!busy_) return;
    progress_->setValue(percent);
    statusLabel_->setText(stage + QStringLiteral("..."));
}

void MainWindow::onAnalysisFinished() {
    current_ = watcher_.result();
    haveResult_ = true;
    haveDisasm_ = false;
    haveGhidra_ = false;
    disasm_ = {};
    ghidra_ = {};
    stringsResult_ = {};
    haveStrings_ = false;
    cfgResult_ = {};
    haveCfg_ = false;
    staticAnalysis_ = {};
    haveStaticAnalysis_ = false;
    xrefResult_ = {};
    haveXref_ = false;
    xrefSelectedReferenceId_.clear();
    xrefDetails_->clear();
    xrefReferencesTable_->clear(tr("The current file changed. Build the XREF index for this file."));
    xrefGraphView_->clearGraph(tr("The current file changed. Build the XREF index for this file."));
    xrefStatusLabel_->setText(tr("Ready to index the current file."));
    xrefSummaryLabel_->setText(tr("XREF decodes discovered function candidates only; stripped binaries may have limited function coverage."));
    staticSelectedFindingId_.clear();
    staticDetails_->clear();
    staticFindingsTable_->clear(tr("Analyze the current file to produce evidence-backed findings."));
    staticSummaryLabel_->setText(tr("Risk score is an evidence-prioritization aid; it is not a probability or classification."));
    staticStatusLabel_->setText(tr("Ready to analyze the current file."));
    cfgCandidates_.clear();
    cfgGraphView_->clearGraph(tr("Choose a function to build its control-flow graph."));
    cfgDetails_->clear();
    cfgStatusLabel_->setText(tr("The current file changed. Select a function and analyze it."));
    hex_->setData(current_.data);
    stringsPathLabel_->setText(current_.info.filePath.empty() ? tr("No file loaded") : q(current_.info.filePath));
    stringsTable_->clear(tr("The current file changed. Extract strings to populate this view."));
    stringsStatusLabel_->setText(tr("Choose Extract strings to scan the current file."));
    stringsExportCsvButton_->setEnabled(false);
    stringsExportJsonButton_->setEnabled(false);
    if (!current_.info.filePath.empty()) {
        entropyPathA_ = q(current_.info.filePath);
        entropyPathAEdit_->setText(entropyPathA_);
        entropyPrimary_ = {};
        entropyComparison_ = {};
        haveEntropyPrimary_ = false;
        haveEntropyComparison_ = false;
        updateEntropyPresentation();
        entropyStatusLabel_->setText(tr("Current file loaded as File A. Choose Analyze Entropy to start."));
    }
    ghidraLog_->clear();
    setBusy(false);
    populateAll();
    if (!current_.info.filePath.empty()) useCurrentAsBaseline();
    updateWorkspaceLoadedFile();
    const auto& i = current_.info;
    setWindowTitle(QStringLiteral("Xaynx Reverse Lab - %1").arg(q(i.fileName)));
    if (!i.ok()) showStatus(q(i.error), true);
    else if (!i.warnings.empty()) showStatus(tr("Analysis complete with %1 warning(s).").arg(i.warnings.size()));
    else showStatus(tr("Analysis complete: %1, %2.").arg(q(i.formatName), q(i.archName)));
    if (i.ok()) {
        xrl::ReportInputs inputs;
        inputs.info = &i;
        recordWorkspaceAnalysis(tr("File analysis"), q(i.filePath), q(i.sha256),
                                tr("%1 · %2 · %3 bytes").arg(q(i.formatName), q(i.archName)).arg(i.fileSize),
                                xrl::renderJsonReport(inputs));
    }
    updateEnabled();
}

void MainWindow::setBusy(bool busy, const QString& message) {
    busy_ = busy;
    progress_->setVisible(busy);
    progress_->setValue(0);
    if (busy) {
        statusLabel_->setProperty("error", false);
        statusLabel_->setText(message);
    }
    openButton_->setEnabled(!busy);
}

void MainWindow::showStatus(const QString& message, bool isError) {
    statusLabel_->setProperty("error", isError);
    statusLabel_->style()->unpolish(statusLabel_);
    statusLabel_->style()->polish(statusLabel_);
    statusLabel_->setText(message);
    statusLabel_->setToolTip(message);
}

bool MainWindow::persistWorkspace(const xrl::WorkspaceData& data, bool recover, QString* error) {
    if (!workspaceLoadError_.isEmpty() && !recover) {
        if (error) *error = tr("Saved workspace is invalid. Restore a verified backup before saving changes.");
        return false;
    }
    if (recover && !workspaceLoadError_.isEmpty()) {
        const QString preserved = workspacePath_ + QStringLiteral(".corrupt-") +
                                  QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd-HHmmss"));
        if (QFileInfo::exists(workspacePath_) && !QFile::copy(workspacePath_, preserved)) {
            if (error) *error = tr("Could not preserve the damaged workspace at %1.").arg(preserved);
            return false;
        }
    }
    std::string saveError;
    if (!xrl::writeWorkspace(toPath(workspacePath_), data, &saveError)) {
        if (error) *error = q(saveError);
        return false;
    }
    workspace_ = data;
    if (recover) {
        workspaceLoadError_.clear();
        if (workspaceWidget_) workspaceWidget_->clearStorageError();
    }
    return true;
}

void MainWindow::openWorkspaceFile(const QString& path, const QString& expectedHash,
                                   quint64 offset, const QString& locationKind) {
    if (busy_) {
        showStatus(tr("Wait for the current analysis to finish before opening a workspace file."), true);
        return;
    }
    if (!QFileInfo::exists(path)) {
        showStatus(tr("The referenced binary is missing. Use Locate missing file and choose its current location."), true);
        return;
    }
    auto navigate = [this, offset, locationKind] {
        if (offset == 0) return;
        std::optional<uint64_t> fileOffset;
        const bool rawOffset = locationKind.isEmpty() ||
                               locationKind.contains(QStringLiteral("offset"), Qt::CaseInsensitive);
        if (rawOffset) fileOffset = offset;
        else fileOffset = current_.info.virtualToFileOffset(offset);
        if (!fileOffset || *fileOffset >= current_.info.fileSize) {
            showStatus(tr("This saved address has no validated file-offset mapping in the loaded binary."), true);
            return;
        }
        showInHex(*fileOffset);
    };
    if (haveResult_ && current_.info.sha256 == expectedHash.toStdString() && !expectedHash.isEmpty()) {
        navigate();
        return;
    }
    pendingWorkspaceFileId_.clear();
    pendingWorkspaceHash_ = expectedHash;
    pendingWorkspaceOffset_ = offset;
    pendingWorkspaceLocationKind_ = locationKind;
    if (!expectedHash.isEmpty()) {
        if (auto* project = xrl::findWorkspaceProject(workspace_, workspace_.lastActiveProjectId)) {
            const auto found = std::find_if(project->files.begin(), project->files.end(), [&](const xrl::WorkspaceFile& file) {
                return file.sha256 == expectedHash.toStdString() || file.path == toPath(path).string();
            });
            if (found != project->files.end()) pendingWorkspaceFileId_ = q(found->id);
        }
    }
    loadFile(path);
}

void MainWindow::updateWorkspaceLoadedFile() {
    if (!workspaceWidget_ || !haveResult_ || current_.info.filePath.empty()) return;
    const auto& info = current_.info;
    xrl::WorkspaceFile loaded;
    loaded.path = QFileInfo(q(info.filePath)).absoluteFilePath().toStdString();
    loaded.sha256 = info.sha256;
    loaded.format = info.formatName;
    loaded.architecture = info.archName;
    loaded.size = info.fileSize;
    workspaceWidget_->setLoadedFile(loaded);

    bool associated = false;
    bool persist = false;
    xrl::WorkspaceData candidate = workspace_;
    auto* target = xrl::findWorkspaceProject(candidate, workspace_.lastActiveProjectId);
    if (target && !pendingWorkspaceFileId_.isEmpty()) {
        auto* file = xrl::findWorkspaceFile(*target, pendingWorkspaceFileId_.toStdString());
        if (file) {
            const bool sameHash = !file->sha256.empty() && file->sha256 == info.sha256;
            if (!sameHash) {
                const auto choice = QMessageBox::question(
                    this, tr("Binary identity changed"),
                    tr("The selected path now contains a different binary than the project reference.\n\n"
                       "Update the project file's hash and path to this binary? Previous notes, bookmarks, "
                       "and analysis reports remain tied to the old hash and will not be treated as current."),
                    QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
                if (choice == QMessageBox::Yes) {
                    file->sha256 = info.sha256;
                    file->size = info.fileSize;
                    file->format = info.formatName;
                    file->architecture = info.archName;
                    file->path = loaded.path;
                    pendingWorkspaceLocationKind_.clear();
                    associated = true;
                    persist = true;
                }
            } else {
                file->path = loaded.path;
                file->size = info.fileSize;
                file->format = info.formatName;
                file->architecture = info.archName;
                associated = true;
                persist = true;
            }
            if (associated) {
                target->session.selectedFileId = file->id;
                candidate.lastActiveProjectId = target->id;
            }
        }
    } else if (target && !info.sha256.empty()) {
        const auto found = std::find_if(target->files.begin(), target->files.end(), [&](const xrl::WorkspaceFile& file) {
            return file.sha256 == info.sha256;
        });
        if (found != target->files.end()) {
            found->path = loaded.path;
            found->size = info.fileSize;
            found->format = info.formatName;
            found->architecture = info.archName;
            target->session.selectedFileId = found->id;
            associated = true;
            persist = true;
        }
    }

    if (workspaceAddAfterLoad_) {
        workspaceAddAfterLoad_ = false;
        addLoadedFileToWorkspace();
        return;
    }
    if (persist) {
        QString error;
        if (!persistWorkspace(candidate, false, &error)) {
            showStatus(tr("File loaded, but workspace metadata was not saved: %1").arg(error), true);
        } else {
            if (workspaceWidget_) workspaceWidget_->refresh(q(workspace_.lastActiveProjectId));
        }
    }
    if (associated && !pendingWorkspaceFileId_.isEmpty()) {
        const quint64 offset = pendingWorkspaceOffset_;
        const QString kind = pendingWorkspaceLocationKind_;
        const bool hasTarget = !kind.isEmpty();
        pendingWorkspaceFileId_.clear();
        pendingWorkspaceHash_.clear();
        pendingWorkspaceOffset_ = 0;
        pendingWorkspaceLocationKind_.clear();
        if (hasTarget) {
            const bool rawOffset = kind.contains(QStringLiteral("offset"), Qt::CaseInsensitive);
            const auto mapped = rawOffset ? std::optional<uint64_t>(offset)
                                          : current_.info.virtualToFileOffset(offset);
            if (mapped && *mapped < current_.info.fileSize) showInHex(*mapped);
            else showStatus(tr("The saved address is not mapped to bytes in this file version."), true);
        }
    } else if (!pendingWorkspaceFileId_.isEmpty() && !associated) {
        pendingWorkspaceFileId_.clear();
        pendingWorkspaceHash_.clear();
        pendingWorkspaceOffset_ = 0;
        pendingWorkspaceLocationKind_.clear();
        showStatus(tr("File opened for analysis, but it was not associated with the saved project file identity."), true);
    }
}

void MainWindow::addLoadedFileToWorkspace() {
    if (!haveResult_ || current_.info.sha256.empty()) {
        showStatus(tr("The current file has no verified SHA-256 identity and cannot be added to a project."), true);
        return;
    }
    auto candidate = workspace_;
    auto* project = xrl::findWorkspaceProject(candidate, candidate.lastActiveProjectId);
    if (!project) {
        showStatus(tr("Create or select a workspace project before adding the current binary."), true);
        return;
    }
    xrl::WorkspaceFile file;
    file.path = QFileInfo(q(current_.info.filePath)).absoluteFilePath().toStdString();
    file.sha256 = current_.info.sha256;
    file.format = current_.info.formatName;
    file.architecture = current_.info.archName;
    file.size = current_.info.fileSize;
    const auto priorCount = project->files.size();
    const auto fileId = xrl::addWorkspaceFile(*project, std::move(file));
    if (!fileId) {
        showStatus(tr("Could not add the binary reference to this project."), true);
        return;
    }
    project->session.selectedFileId = *fileId;
    project->session.activePage = sidebar_->currentRow();
    QString error;
    if (!persistWorkspace(candidate, false, &error)) {
        showStatus(tr("Binary was not added to the workspace: %1").arg(error), true);
        return;
    }
    if (workspaceWidget_) {
        workspaceWidget_->setLoadedFile({*fileId, QFileInfo(q(current_.info.filePath)).absoluteFilePath().toStdString(),
                                         current_.info.sha256, current_.info.formatName, current_.info.archName,
                                         current_.info.fileSize, {}});
        workspaceWidget_->refresh(q(workspace_.lastActiveProjectId));
    }
    showStatus(priorCount == project->files.size()
                   ? tr("This binary is already referenced by the project (matched by SHA-256).")
                   : tr("Binary reference added. The original file remains at its source path."));
}

void MainWindow::recordWorkspaceAnalysis(const QString& type, const QString& filePath,
                                         const QString& fileHash, const QString& summary,
                                         const std::string& reportJson) {
    if (!workspaceLoadError_.isEmpty() || fileHash.isEmpty() || reportJson.empty()) return;
    if (reportJson.size() > xrl::kMaxWorkspaceReportBytes) {
        showStatus(tr("%1 completed, but its report exceeds the workspace history size limit and was not saved.")
                       .arg(type), true);
        return;
    }
    auto candidate = workspace_;
    auto* project = xrl::findWorkspaceProject(candidate, candidate.lastActiveProjectId);
    if (!project) return;
    auto file = std::find_if(project->files.begin(), project->files.end(), [&](const xrl::WorkspaceFile& entry) {
        return entry.sha256 == fileHash.toStdString();
    });
    if (file == project->files.end()) return;
    const auto parsed = xrl::Json::parse(reportJson);
    if (!parsed.value) {
        showStatus(tr("Analysis completed, but its report could not be validated for workspace storage."), true);
        return;
    }
    xrl::WorkspaceAnalysis analysis;
    analysis.id = xrl::makeWorkspaceId();
    analysis.type = type.toStdString();
    analysis.fileId = file->id;
    analysis.fileHash = fileHash.toStdString();
    analysis.timestamp = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs).toStdString();
    analysis.engineVersion = XRL_VERSION;
    analysis.status = "complete";
    analysis.summary = summary.toStdString();
    analysis.reportJson = reportJson;
    project->analyses.push_back(std::move(analysis));
    project->modifiedAt = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs).toStdString();
    QString error;
    if (!persistWorkspace(candidate, false, &error)) {
        showStatus(tr("%1 completed, but the result was not saved: %2").arg(type, error), true);
        return;
    }
    if (workspaceWidget_) workspaceWidget_->refresh(q(project->id));
    (void)filePath;
}

void MainWindow::recordWorkspaceComparison() {
    if (!haveDiff_ || workspaceLoadError_.size()) return;
    auto candidate = workspace_;
    auto* project = xrl::findWorkspaceProject(candidate, candidate.lastActiveProjectId);
    if (!project) return;
    const auto findFile = [&](const std::string& hash) {
        return std::find_if(project->files.begin(), project->files.end(),
                            [&](const xrl::WorkspaceFile& file) { return file.sha256 == hash; });
    };
    const auto a = findFile(diffResult_.infoA.sha256);
    const auto b = findFile(diffResult_.infoB.sha256);
    if (a == project->files.end() || b == project->files.end()) return;
    xrl::WorkspaceComparison comparison;
    comparison.id = xrl::makeWorkspaceId();
    comparison.fileAId = a->id;
    comparison.fileAHash = a->sha256;
    comparison.fileBId = b->id;
    comparison.fileBHash = b->sha256;
    comparison.timestamp = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs).toStdString();
    comparison.summary = tr("%1 difference region(s); %2 modified byte(s)")
                             .arg(diffResult_.summary.totalDiffRegions)
                             .arg(diffResult_.summary.totalModifiedBytes).toStdString();
    comparison.reportJson = xrl::renderDiffJsonReport(diffResult_);
    if (comparison.reportJson.size() > xrl::kMaxWorkspaceReportBytes) {
        showStatus(tr("Comparison completed, but its report is too large for workspace history."), true);
        return;
    }
    project->comparisons.push_back(std::move(comparison));
    project->modifiedAt = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs).toStdString();
    QString error;
    if (!persistWorkspace(candidate, false, &error)) {
        showStatus(tr("Comparison completed, but it was not saved: %1").arg(error), true);
        return;
    }
    if (workspaceWidget_) workspaceWidget_->refresh(q(project->id));
}

bool MainWindow::saveWorkspaceSession() {
    if (workspaceLoadError_.isEmpty()) {
        if (auto* project = xrl::findWorkspaceProject(workspace_, workspace_.lastActiveProjectId)) {
            project->session.activePage = std::max(0, sidebar_->currentRow());
        }
        QString error;
        if (persistWorkspace(workspace_, false, &error)) return true;
        {
            const auto choice = QMessageBox::question(
                this, tr("Workspace state not saved"),
                tr("Could not save your workspace state:\n%1\n\nClose the application anyway?")
                    .arg(error),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
            return choice == QMessageBox::Yes;
        }
    }
    return true;
}

void MainWindow::updateEnabled() {
    const bool res = haveResult_;
    const bool data = res && current_.data != nullptr;
    const bool parsed = res && current_.info.recognized();
    copyHashButton_->setEnabled(res && !current_.info.sha256.empty());
    hexOffsetEdit_->setEnabled(data);
    hexGoButton_->setEnabled(data);
    const bool canDis = data && parsed && xrl::disassemblySupported(current_.info);
    startCombo_->setEnabled(canDis);
    startModeCombo_->setEnabled(canDis);
    startEdit_->setEnabled(canDis);
    countSpin_->setEnabled(canDis);
    disasmButton_->setEnabled(canDis);
    ghidraRun_->setEnabled(data && !ghidraRunner_->isRunning());
    ghidraCancel_->setEnabled(ghidraRunner_->isRunning());
    ghidraDecompile_->setEnabled(!ghidraRunner_->isRunning());
    exportJsonButton_->setEnabled(res);
    exportTextButton_->setEnabled(res);
    actExportJson_->setEnabled(res);
    actExportText_->setEnabled(res);
    reportIncludeDisasm_->setEnabled(haveDisasm_);
    reportIncludeGhidra_->setEnabled(haveGhidra_);

    if (diffUseCurrentBtn_) diffUseCurrentBtn_->setEnabled(res && !current_.info.filePath.empty());
    if (diffRunBtn_) diffRunBtn_->setEnabled(!busy_ && !diffPathA_.isEmpty() && !diffPathB_.isEmpty());
    if (diffExportJsonBtn_) diffExportJsonBtn_->setEnabled(haveDiff_);
    if (entropyRunBtn_) entropyRunBtn_->setEnabled(!entropyWatcher_.isRunning() && !entropyPathA_.isEmpty());
    if (entropyExportJsonBtn_) entropyExportJsonBtn_->setEnabled(haveEntropyPrimary_);
    if (entropyExportCsvBtn_) entropyExportCsvBtn_->setEnabled(haveEntropyPrimary_);
    if (stringsRunButton_)
        stringsRunButton_->setEnabled(res && !current_.info.filePath.empty() && !stringsWatcher_.isRunning() && !busy_);
    if (stringsCancelButton_) stringsCancelButton_->setEnabled(stringsWatcher_.isRunning());
    if (stringsExportCsvButton_) stringsExportCsvButton_->setEnabled(haveStrings_);
    if (stringsExportJsonButton_) stringsExportJsonButton_->setEnabled(haveStrings_);
    if (staticRunButton_)
        staticRunButton_->setEnabled(data && !staticWatcher_.isRunning() && !busy_);
    if (staticCancelButton_) staticCancelButton_->setEnabled(staticWatcher_.isRunning());
    if (staticExportJsonButton_) staticExportJsonButton_->setEnabled(haveStaticAnalysis_);
    if (staticExportHtmlButton_) staticExportHtmlButton_->setEnabled(haveStaticAnalysis_);
    if (xrefRunButton_)
        xrefRunButton_->setEnabled(data && xrl::cfgSupported(current_.info) &&
                                   !xrefWatcher_.isRunning() && !busy_);
    if (xrefCancelButton_) xrefCancelButton_->setEnabled(xrefWatcher_.isRunning());
    if (xrefExportJsonButton_) xrefExportJsonButton_->setEnabled(haveXref_);
    if (xrefExportCsvButton_) xrefExportCsvButton_->setEnabled(haveXref_);
    if (xrefExportDotButton_) xrefExportDotButton_->setEnabled(haveXref_);
    if (cfgFunctionCombo_) {
        const bool canCfg = data && xrl::cfgSupported(current_.info);
        cfgFunctionCombo_->setEnabled(canCfg && !cfgWatcher_.isRunning() && !busy_);
        cfgAddressModeCombo_->setEnabled(canCfg && !cfgWatcher_.isRunning() && !busy_);
        cfgAddressEdit_->setEnabled(canCfg && !cfgWatcher_.isRunning() && !busy_);
        cfgRunButton_->setEnabled(canCfg && !cfgWatcher_.isRunning() && !busy_);
        cfgCancelButton_->setEnabled(cfgWatcher_.isRunning());
        cfgFindBlockButton_->setEnabled(haveCfg_);
        cfgBlockSearchEdit_->setEnabled(haveCfg_);
        cfgFitButton_->setEnabled(haveCfg_);
        cfgHexButton_->setEnabled(haveCfg_ && cfgGraphView_->selectedBlockAddress().has_value());
        cfgExportJsonButton_->setEnabled(haveCfg_);
        cfgExportDotButton_->setEnabled(haveCfg_);
        cfgConditionalCheck_->setEnabled(haveCfg_);
        cfgUnresolvedCheck_->setEnabled(haveCfg_);
    }
}

// ============================================================================ population
void MainWindow::populateAll() {
    populateOverview();
    populateAnalysis();
    populateStartPoints();
    cfgCandidates_.clear();
    cfgFunctionCombo_->clear();
    if (haveResult_ && current_.data && current_.info.recognized()) {
        cfgCandidates_ = xrl::discoverFunctionCandidates(current_.info);
        if (xrl::cfgSupported(current_.info)) {
            for (size_t i = 0; i < cfgCandidates_.size(); ++i) {
                const auto& candidate = cfgCandidates_[i];
                const QString name = candidate.name.empty() ? hex64(candidate.address) : q(candidate.name);
                const QString evidence = candidate.startConfirmed
                                             ? tr("confirmed start")
                                             : (candidate.evidence == xrl::FunctionEvidence::SectionStart
                                                    ? tr("section start, unconfirmed")
                                                    : tr("candidate"));
                cfgFunctionCombo_->addItem(QStringLiteral("%1  @ %2  (%3)")
                                               .arg(name, hex64(candidate.address), evidence),
                                           QVariant::fromValue<qulonglong>(i));
            }
        }
        cfgFunctionCombo_->setCurrentIndex(cfgCandidates_.empty() ? -1 : 0);
    }
    if (!haveResult_) cfgStatusLabel_->setText(tr("Open a supported executable to list metadata-backed candidates."));
    else if (!xrl::cfgSupported(current_.info))
        cfgStatusLabel_->setText(tr("CFG is available for x86, x86-64, and ARM64 files in Capstone-enabled builds."));
    else if (cfgCandidates_.empty())
        cfgStatusLabel_->setText(tr("No executable section start was found. Enter an address mapped to executable file data."));
    else
        cfgStatusLabel_->setText(tr("%1 start point(s). Candidates are evidence-labelled; section starts are not confirmed functions.")
                                     .arg(cfgCandidates_.size()));
    updateFunctionExplorer();
    hexInfo_->setText(haveResult_ && current_.data ? tr("%1 bytes. Click a byte to select it; arrow keys move the selection.").arg(current_.data->size())
                                                    : tr("No file loaded."));
    ghidraFunctions_->clear(tr("No Ghidra results. Ghidra only runs when you press \"Run Ghidra analysis\"."));
    ghidraDecompiled_->clear();
    disasmTable_->clear({});
    if (!haveResult_) disasmInfo_->setText(tr("No file loaded."));
    else if (!xrl::disassemblerCompiledIn()) disasmInfo_->setText(tr("This build has no disassembly engine (compiled without Capstone)."));
    else if (!current_.info.recognized()) disasmInfo_->setText(tr("The file format was not recognised; disassembly is unavailable."));
    else if (!xrl::disassemblySupported(current_.info))
        disasmInfo_->setText(tr("Disassembly is not supported for architecture \"%1\".").arg(q(current_.info.archName)));
    else disasmInfo_->setText(tr("%1. Choose a start point or enter one, then press Disassemble.").arg(q(xrl::disassemblerVersion())));
}

void MainWindow::populateOverview() {
    QVector<QStringList> rows;
    QString summary;
    if (!haveResult_) {
        filePathLabel_->setText(tr("No file selected"));
        metaModel_->reset({tr("Property"), tr("Value")}, {});
        summary_->setPlainText(tr("Open a file to see its analysis summary.\n\nOnly information read from the file is shown. "
                                  "Nothing is estimated or simulated."));
        return;
    }
    const auto& i = current_.info;
    filePathLabel_->setText(q(i.filePath));
    auto add = [&](const QString& k, const QString& v) { rows.push_back({k, v}); };
    add(tr("Name"), q(i.fileName));
    add(tr("Size"), q(xrl::humanSize(i.fileSize)));
    add(tr("SHA-256"), i.sha256.empty() ? tr("(not computed)") : q(i.sha256));
    add(tr("Format"), i.recognized() ? q(i.formatName) : tr("Unrecognised"));
    add(tr("File type"), i.fileType.empty() ? tr("(unknown)") : q(i.fileType));
    add(tr("Architecture"), q(i.archName));
    add(tr("Bitness"), i.bits ? tr("%1-bit").arg(i.bits) : tr("unknown"));
    add(tr("Endianness"), q(xrl::toString(i.endian)));
    add(tr("Entry point"), i.entryPoint ? hex64(*i.entryPoint) : tr("(none / unknown)"));
    for (const auto& [k, v] : i.metadata) add(q(k), q(v));
    metaModel_->reset({tr("Property"), tr("Value")}, rows, {1});
    metaView_->resizeColumnToContents(0);

    // summary
    QStringList s;
    if (!i.ok()) s << tr("STATUS: analysis problem\n%1\n").arg(q(i.error));
    else s << tr("STATUS: parsed successfully\n");
    auto cat = [&](const QString& name, xrl::Availability a, size_t n) {
        s << QStringLiteral("%1: %2").arg(name, a == xrl::Availability::NotParsed ? tr("unavailable (not determined)")
                                               : a == xrl::Availability::Absent ? tr("confirmed absent")
                                                                                 : tr("%1 found").arg(n));
    };
    s << tr("Sections: %1").arg(i.sectionsParsed ? tr("%1 entries").arg(i.sections.size()) : tr("unavailable (not determined)"));
    cat(tr("Imports"), i.imports.state, i.imports.items.size());
    cat(tr("Exports"), i.exports.state, i.exports.items.size());
    cat(tr("Libraries"), i.libraries.state, i.libraries.items.size());
    cat(tr("Symbols"), i.symbols.state, i.symbols.items.size());
    cat(tr("Relocations"), i.relocations.state, i.relocations.items.size());
    s << QString();
    s << tr("Warnings: %1").arg(i.warnings.size());
    s << tr("Heuristic observations: %1 (see File Analysis > Findings; these are unverified and are not verdicts)").arg(i.findings.size());
    s << QString();
    if (xrl::disassemblySupported(i)) s << tr("Disassembly: available (%1), linear sweep only").arg(q(xrl::disassemblerVersion()));
    else s << tr("Disassembly: not available for this file or build");
    s << tr("CFG: bounded reachable-block analysis from metadata candidates or a supplied start address (x86, x86-64, ARM64).");
    s << tr("Whole-program function discovery / decompilation: optional via Ghidra.");
    if (i.format == xrl::Format::MachO && i.metadata.size() && q(i.formatName).contains("Mach-O"))
        for (const auto& [k, v] : i.metadata)
            if (k == "Universal binary slices") s << tr("Universal binary: only the first slice is analysed.");
    summary_->setPlainText(s.join('\n'));
}

void MainWindow::populateAnalysis() {
    const QString none = tr("No file loaded.");
    if (!haveResult_) {
        for (auto* t : {sectionsTable_, importsTable_, exportsTable_, librariesTable_, symbolsTable_, findingsTable_}) t->clear(none);
        return;
    }
    const auto& i = current_.info;

    QVector<QStringList> rows;
    for (const auto& s : i.sections)
        rows.push_back({q(s.kind), q(s.name), q(s.segment), hex64(s.virtualAddress), hex64(s.fileOffset),
                        QString::number(s.virtualSize), QString::number(s.fileSize), perms(s),
                        s.entropy ? QString::number(*s.entropy, 'f', 2) : QStringLiteral("-"), q(s.note)});
    // Column 4 (file offset) is used by the double-click handler.
    sectionsTable_->setContent({tr("Kind"), tr("Name"), tr("Segment"), tr("Virtual address"), tr("File offset"), tr("Virtual size"),
                                tr("File size"), tr("Perms"), tr("Entropy"), tr("Notes")},
                               rows,
                               i.sectionsParsed ? QString() : tr("Unavailable: the section table could not be parsed for this file."),
                               {3, 4, 5, 6});
    analysisTabs_->setTabText(0, i.sectionsParsed ? tr("Sections (%1)").arg(i.sections.size()) : tr("Sections (n/a)"));

    auto symRows = [](const xrl::Category<xrl::Symbol>& c, bool withLib) {
        QVector<QStringList> r;
        r.reserve(static_cast<qsizetype>(c.items.size()));
        for (const auto& s : c.items) {
            QStringList row{q(s.name)};
            if (withLib) row << q(s.library);
            row << (s.address ? hex64(*s.address) : QString()) << (s.ordinal ? QString::number(*s.ordinal) : QString()) << q(s.type);
            r.push_back(row);
        }
        return r;
    };
    importsTable_->setContent({tr("Name"), tr("Library"), tr("Address"), tr("Ordinal"), tr("Type")}, symRows(i.imports, true),
                              availabilityText(i.imports.state, i.imports.note), {2});
    exportsTable_->setContent({tr("Name"), tr("Forwarder / library"), tr("Address"), tr("Ordinal"), tr("Type")}, symRows(i.exports, true),
                              availabilityText(i.exports.state, i.exports.note), {2});
    symbolsTable_->setContent({tr("Name"), tr("Address"), tr("Ordinal"), tr("Type")}, symRows(i.symbols, false),
                              availabilityText(i.symbols.state, i.symbols.note), {1});
    QVector<QStringList> libs;
    for (const auto& l : i.libraries.items) libs.push_back({q(l)});
    librariesTable_->setContent({tr("Library")}, libs, availabilityText(i.libraries.state, i.libraries.note));
    analysisTabs_->setTabText(1, tabLabel(tr("Imports"), i.imports.state, i.imports.items.size()));
    analysisTabs_->setTabText(2, tabLabel(tr("Exports"), i.exports.state, i.exports.items.size()));
    analysisTabs_->setTabText(3, tabLabel(tr("Libraries"), i.libraries.state, i.libraries.items.size()));
    analysisTabs_->setTabText(4, tabLabel(tr("Symbols"), i.symbols.state, i.symbols.items.size()));

    QVector<QStringList> f;
    for (const auto& w : i.warnings) f.push_back({tr("Warning"), QString(), q(w)});
    for (const auto& x : i.findings) f.push_back({tr("Heuristic"), q(x.title), q(x.detail)});
    if (!i.error.empty()) f.push_front({tr("Error"), tr("Analysis problem"), q(i.error)});
    findingsTable_->setContent({tr("Type"), tr("Title"), tr("Detail")}, f,
                               tr("Heuristic findings are unverified observations that can have benign explanations. They are not verdicts."));
    analysisTabs_->setTabText(5, tr("Findings (%1)").arg(f.size()));
}

void MainWindow::runStaticAnalysis() {
    if (staticWatcher_.isRunning()) return;
    if (!haveResult_ || !current_.data) {
        showStatus(tr("Open a file before running static analysis."), true);
        return;
    }

    const QString path = q(current_.info.filePath);
    if (path.isEmpty()) {
        showStatus(tr("The loaded file has no source path; string and entropy analysis cannot be reused."), true);
        return;
    }
    const auto fileData = current_.data;
    const auto info = current_.info;
    auto canonical = [](const QString& candidate) {
        QString resolved = QFileInfo(candidate).canonicalFilePath();
        return resolved.isEmpty() ? QFileInfo(candidate).absoluteFilePath() : resolved;
    };
    const QString resolvedPath = canonical(path);
    const bool reuseStrings = haveStrings_ && !stringsResult_.truncated && stringsResult_.minLength == 4 &&
                              !stringsResult_.sha256.empty() && stringsResult_.sha256 == current_.info.sha256 &&
                              canonical(q(stringsResult_.filePath)) == resolvedPath;
    const bool reuseEntropy = haveEntropyPrimary_ && !entropyPrimary_.sha256.empty() &&
                              entropyPrimary_.sha256 == current_.info.sha256 &&
                              canonical(entropyPathA_) == resolvedPath;
    const bool reuseCfg = haveCfg_ && canonical(cfgAnalysisPath_) == resolvedPath;
    auto cachedStrings = reuseStrings ? stringsResult_ : xrl::StringExtractionResult{};
    auto cachedEntropy = reuseEntropy ? entropyPrimary_ : xrl::EntropyAnalysisResult{};
    auto cachedCfg = reuseCfg ? cfgResult_ : xrl::ControlFlowGraph{};

    staticAnalysisPath_ = resolvedPath;
    staticAnalysis_ = {};
    haveStaticAnalysis_ = false;
    staticSelectedFindingId_.clear();
    staticDetails_->clear();
    staticFindingsTable_->clear(tr("Analysis is running..."));
    staticSummaryLabel_->setText(tr("Analyzing the loaded file locally; the binary will not be executed or uploaded."));
    staticProgress_->setValue(0);
    staticProgress_->show();
    staticStatusLabel_->setText(tr("Preparing analysis..."));
    staticCancel_ = std::make_shared<std::atomic_bool>(false);
    const auto cancel = staticCancel_;
    updateEnabled();

    staticWatcher_.setFuture(QtConcurrent::run(
        [this, info, fileData, path, resolvedPath, reuseStrings, reuseEntropy, reuseCfg,
         cachedStrings = std::move(cachedStrings), cachedEntropy = std::move(cachedEntropy),
         cachedCfg = std::move(cachedCfg), cancel]() mutable {
            StaticJobResult job;
            auto emitProgress = [this](int percent, const std::string& stage) {
                QMetaObject::invokeMethod(this, [this, percent, text = q(stage)] {
                    onStaticProgress(percent, text);
                }, Qt::QueuedConnection);
            };
            const auto filesystemPath = toPath(path);
            if (reuseStrings) {
                job.strings = std::move(cachedStrings);
                job.hasStrings = job.strings.ok;
                emitProgress(35, "Reusing String Explorer results");
            } else {
                job.strings = xrl::extractStringsFile(
                    filesystemPath, {},
                    [&emitProgress](int percent, const std::string& stage) {
                        emitProgress(5 + percent * 30 / 100, stage);
                    },
                    [cancel] { return cancel->load(); });
                job.hasStrings = job.strings.ok;
                if (!job.strings.ok && !job.strings.cancelled)
                    job.warnings << tr("String extraction unavailable: %1").arg(q(job.strings.error));
                if (job.strings.truncated)
                    job.warnings << tr("String extraction reached its configured output limit: %1").arg(q(job.strings.warning));
                if (job.hasStrings && job.strings.sha256 != info.sha256) {
                    job.hasStrings = false;
                    job.warnings << tr("The file changed after it was loaded; extracted strings were excluded from this report.");
                }
            }
            if (cancel->load()) {
                job.analysis.cancelled = true;
                job.analysis.error = "Static analysis cancelled.";
                return job;
            }

            xrl::EntropyAnalysisResult entropy;
            bool haveEntropy = false;
            if (reuseEntropy) {
                entropy = std::move(cachedEntropy);
                haveEntropy = entropy.ok;
                emitProgress(65, "Reusing Entropy Heatmap results");
            } else {
                entropy = xrl::analyzeEntropyFile(
                    filesystemPath, xrl::kDefaultEntropyBlockSize,
                    [&emitProgress](int percent, const std::string& stage) {
                        emitProgress(35 + percent * 30 / 100, stage);
                    },
                    [cancel] { return cancel->load(); });
                haveEntropy = entropy.ok;
                if (!entropy.ok && !entropy.cancelled)
                    job.warnings << tr("Whole-file entropy unavailable: %1").arg(q(entropy.error));
                if (haveEntropy && entropy.sha256 != info.sha256) {
                    haveEntropy = false;
                    job.warnings << tr("The file changed after it was loaded; entropy results were excluded from this report.");
                }
            }
            if (cancel->load()) {
                job.analysis.cancelled = true;
                job.analysis.error = "Static analysis cancelled.";
                return job;
            }
            if (!reuseCfg)
                job.warnings << tr("No existing CFG result was available; CFG rules were not evaluated.");

            job.analysis = xrl::analyzeStatic(
                info, *fileData, job.hasStrings ? &job.strings : nullptr,
                haveEntropy ? &entropy : nullptr, reuseCfg ? &cachedCfg : nullptr,
                [&emitProgress](int percent, const std::string& stage) {
                    emitProgress(65 + percent * 35 / 100, stage);
                },
                [cancel] { return cancel->load(); });
            if (haveEntropy) {
                job.entropy = std::move(entropy);
                job.hasEntropy = true;
            }
            for (const auto& warning : job.warnings)
                job.analysis.warnings.push_back(warning.toStdString());
            emitProgress(100, job.analysis.ok ? "Static analysis complete" : "Static analysis incomplete");
            return job;
        }));
}

void MainWindow::onStaticProgress(int percent, const QString& stage) {
    if (!staticWatcher_.isRunning()) return;
    staticProgress_->setValue(percent);
    staticStatusLabel_->setText(stage + QStringLiteral("..."));
}

void MainWindow::onStaticAnalysisFinished() {
    StaticJobResult job = staticWatcher_.result();
    staticProgress_->hide();
    staticCancel_.reset();
    const QString currentPath = QFileInfo(q(current_.info.filePath)).canonicalFilePath();
    const QString expectedPath = staticAnalysisPath_;
    if (expectedPath.isEmpty() || !haveResult_ ||
        (!currentPath.isEmpty() && expectedPath != currentPath)) {
        updateEnabled();
        return;
    }
    staticAnalysis_ = std::move(job.analysis);
    haveStaticAnalysis_ = staticAnalysis_.ok;
    if (job.hasStrings) {
        stringsResult_ = std::move(job.strings);
        haveStrings_ = true;
        stringsTable_->setStrings(&stringsResult_.strings,
            tr("Pattern-based classifications are suggestions only; extracted strings do not prove runtime use."));
        stringsStatusLabel_->setText(tr("Extracted %1 strings for static analysis.").arg(stringsResult_.strings.size()));
    }
    if (job.hasEntropy && job.entropy.sha256 == staticAnalysis_.sha256) {
        entropyPrimary_ = std::move(job.entropy);
        haveEntropyPrimary_ = true;
        entropyPathA_ = staticAnalysisPath_;
        entropyComparison_ = {};
        haveEntropyComparison_ = false;
        updateEntropyPresentation();
    }
    if (!haveStaticAnalysis_) {
        staticStatusLabel_->setText(staticAnalysis_.cancelled
                                        ? tr("Static analysis cancelled.")
                                        : tr("Static analysis failed: %1").arg(q(staticAnalysis_.error)));
        showStatus(staticStatusLabel_->text(), !staticAnalysis_.cancelled);
        updateEnabled();
        return;
    }
    updateStaticFindings();
    size_t severityCounts[5]{};
    for (const auto& finding : staticAnalysis_.findings)
        ++severityCounts[static_cast<size_t>(finding.severity)];
    staticSummaryLabel_->setText(
        tr("Evidence score %1/100%2  ·  Findings: %3  ·  Critical %4 / High %5 / Medium %6 / Low %7 / Info %8  ·  %9")
            .arg(staticAnalysis_.risk.score)
            .arg(staticAnalysis_.risk.inconclusive ? tr(" (inconclusive)") : tr(" (not a malware verdict)"))
            .arg(staticAnalysis_.findings.size())
            .arg(severityCounts[static_cast<size_t>(xrl::StaticSeverity::Critical)])
            .arg(severityCounts[static_cast<size_t>(xrl::StaticSeverity::High)])
            .arg(severityCounts[static_cast<size_t>(xrl::StaticSeverity::Medium)])
            .arg(severityCounts[static_cast<size_t>(xrl::StaticSeverity::Low)])
            .arg(severityCounts[static_cast<size_t>(xrl::StaticSeverity::Informational)])
            .arg(q(staticAnalysis_.fileName)));
    staticStatusLabel_->setText(staticAnalysis_.warnings.empty()
                                    ? tr("Analysis complete. Findings are based on local parser and analysis evidence.")
                                    : tr("Analysis complete with %1 limitation(s) or warning(s).").arg(staticAnalysis_.warnings.size()));
    showStatus(staticStatusLabel_->text());
    recordWorkspaceAnalysis(
        tr("Static Analysis"), q(staticAnalysis_.filePath), q(staticAnalysis_.sha256),
        tr("Evidence score %1/100 · %2 findings").arg(staticAnalysis_.risk.score).arg(staticAnalysis_.findings.size()),
        xrl::renderStaticJsonReport(staticAnalysis_));
    updateEnabled();
}

void MainWindow::updateStaticFindings() {
    if (!staticFindingsTable_) return;
    QVector<QStringList> rows;
    if (haveStaticAnalysis_) {
        const int severityFilter = staticSeverityFilter_->currentIndex() - 1;
        const int categoryFilter = staticCategoryFilter_->currentIndex() - 1;
        for (const auto& finding : staticAnalysis_.findings) {
            if (severityFilter >= 0 && static_cast<int>(finding.severity) != severityFilter) continue;
            if (categoryFilter >= 0 && static_cast<int>(finding.category) != categoryFilter) continue;
            rows.push_back({QString::fromLatin1(xrl::toString(finding.severity)),
                            q(finding.ruleId),
                            QString::fromLatin1(xrl::toString(finding.category)),
                            QStringLiteral("%1%").arg(finding.confidence),
                            q(finding.title), q(finding.id)});
        }
    }
    QString note = tr("Risk points are deduplicated by evidence group; correlations do not add points.");
    if (!staticAnalysis_.warnings.empty()) {
        for (const auto& warning : staticAnalysis_.warnings)
            note += QStringLiteral(" ") + q(warning);
    }
    staticFindingsTable_->setContent(
        {tr("Severity"), tr("Rule"), tr("Category"), tr("Confidence"), tr("Finding"), tr("ID")},
        rows, haveStaticAnalysis_ ? note : tr("Analyze the current file to produce findings."), {1, 3});
    staticFindingsTable_->view()->setColumnHidden(5, true);
    if (!rows.isEmpty()) {
        staticFindingsTable_->view()->selectRow(0);
        selectStaticFinding(staticFindingsTable_->view()->currentIndex());
    } else {
        staticDetails_->clear();
        staticSelectedFindingId_.clear();
        staticOpenEvidenceButton_->setEnabled(false);
    }
}

void MainWindow::selectStaticFinding(const QModelIndex& current) {
    if (!current.isValid() || !haveStaticAnalysis_) return;
    const QModelIndex sourceIndex = staticFindingsTable_->proxy()->mapToSource(current);
    if (!sourceIndex.isValid()) return;
    const auto& row = staticFindingsTable_->model()->rowAt(sourceIndex.row());
    if (row.size() < 6) return;
    staticSelectedFindingId_ = row[5];
    const auto found = std::find_if(staticAnalysis_.findings.begin(), staticAnalysis_.findings.end(),
                                    [this](const xrl::StaticFinding& finding) {
                                        return q(finding.id) == staticSelectedFindingId_;
                                    });
    if (found == staticAnalysis_.findings.end()) return;

    QStringList details;
    details << tr("%1 · %2 · confidence %3% · evidence quality %4%")
                   .arg(q(found->ruleId), q(found->title))
                   .arg(found->confidence).arg(found->evidenceQuality);
    details << q(found->description);
    details << tr("Why it matters: %1").arg(q(found->whyItMatters));
    details << tr("Benign explanations: %1").arg(q(found->benignExplanations));
    details << tr("Next step: %1").arg(q(found->nextSteps));
    details << tr("Related view: %1").arg(q(xrl::toString(found->relatedView)));
    for (const auto& evidence : found->evidence) {
        QString line = QStringLiteral("Evidence: %1 — %2")
                           .arg(q(evidence.description), q(evidence.value));
        if (evidence.fileOffset) line += tr(" · file offset %1").arg(hex64(*evidence.fileOffset));
        if (evidence.virtualAddress) line += tr(" · virtual address %1").arg(hex64(*evidence.virtualAddress));
        details << line;
    }
    const auto contribution = std::find_if(staticAnalysis_.risk.contributions.begin(),
                                           staticAnalysis_.risk.contributions.end(),
                                           [&found](const xrl::RiskContribution& item) {
                                               return item.findingId == found->id;
                                           });
    if (contribution != staticAnalysis_.risk.contributions.end())
        details << tr("Risk contribution: %1 points, %2. %3")
                       .arg(contribution->points, 0, 'f', 2)
                       .arg(contribution->counted ? tr("counted") : tr("not counted"))
                       .arg(q(contribution->reason));
    staticDetails_->setPlainText(details.join('\n'));
    staticOpenEvidenceButton_->setEnabled(found->relatedView != xrl::StaticView::None);
    staticOpenEvidenceButton_->setText(found->relatedView == xrl::StaticView::Hex
                                           ? tr("Open in Hex")
                                           : tr("Open %1").arg(q(xrl::toString(found->relatedView))));
}

void MainWindow::openStaticFinding() {
    if (!haveStaticAnalysis_) return;
    const auto found = std::find_if(staticAnalysis_.findings.begin(), staticAnalysis_.findings.end(),
                                    [this](const xrl::StaticFinding& finding) {
                                        return q(finding.id) == staticSelectedFindingId_;
                                    });
    if (found == staticAnalysis_.findings.end()) return;
    if (found->relatedView == xrl::StaticView::Hex) {
        if (!found->evidence.empty() && found->evidence.front().fileOffset)
            showInHex(*found->evidence.front().fileOffset);
        else
            showStatus(tr("This finding has no validated file offset."), true);
        return;
    }
    switch (found->relatedView) {
        case xrl::StaticView::Sections:
            sidebar_->setCurrentRow(PageAnalysis);
            analysisTabs_->setCurrentIndex(0);
            break;
        case xrl::StaticView::Imports:
            sidebar_->setCurrentRow(PageAnalysis);
            analysisTabs_->setCurrentIndex(1);
            break;
        case xrl::StaticView::Strings:
            sidebar_->setCurrentRow(PageStrings);
            break;
        case xrl::StaticView::Entropy:
            sidebar_->setCurrentRow(PageEntropy);
            break;
        case xrl::StaticView::ControlFlow:
            sidebar_->setCurrentRow(PageCfg);
            break;
        case xrl::StaticView::None:
        case xrl::StaticView::Hex:
            break;
    }
}

bool MainWindow::exportStaticReport(bool html) {
    if (!haveStaticAnalysis_) return false;
    QSettings settings;
    const QString suffix = html ? QStringLiteral(".static-analysis.html") :
                                   QStringLiteral(".static-analysis.json");
    const QString base = QFileInfo(q(staticAnalysis_.fileName)).completeBaseName();
    const QString initial = QDir(settings.value("ui/lastExportDir", QDir::homePath()).toString())
                                .filePath(base + suffix);
    const QString path = QFileDialog::getSaveFileName(
        this, html ? tr("Export static analysis HTML") : tr("Export static analysis JSON"),
        initial, html ? tr("HTML report (*.html)") : tr("JSON report (*.json)"));
    if (path.isEmpty()) return false;
    settings.setValue("ui/lastExportDir", QFileInfo(path).absolutePath());
    const std::string content = html ? xrl::renderStaticHtmlReport(staticAnalysis_)
                                     : xrl::renderStaticJsonReport(staticAnalysis_);
    std::ofstream output(toPath(path), std::ios::binary | std::ios::trunc);
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    output.flush();
    if (!output) {
        showStatus(tr("Failed to write static analysis report to %1").arg(path), true);
        return false;
    }
    showStatus(tr("Static analysis report exported to %1").arg(path));
    return true;
}

// ============================================================================ hex
void MainWindow::goToHexOffset() {
    if (!haveResult_ || !current_.data) return;
    const std::string text = hexOffsetEdit_->text().toStdString();
    const auto n = xrl::parseNumber(text);
    if (!n) {
        showStatus(tr("Invalid offset \"%1\". Use hex (0x1F40) or decimal digits; the value must fit in 64 bits.").arg(hexOffsetEdit_->text()), true);
        return;
    }
    if (!hex_->goToOffset(*n)) {
        showStatus(tr("Offset %1 is outside the file (size %2 bytes).").arg(hex64(*n)).arg(current_.data->size()), true);
        return;
    }
    showStatus(tr("Moved to offset %1.").arg(hex64(*n)));
}

void MainWindow::showInHex(quint64 offset) {
    if (!haveResult_ || !current_.data) return;
    hex_->clearRangeHighlight();
    if (!hex_->goToOffset(offset)) {
        showStatus(tr("Offset %1 is outside the file.").arg(hex64(offset)), true);
        return;
    }
    if (auto* project = xrl::findWorkspaceProject(workspace_, workspace_.lastActiveProjectId)) {
        project->session.selectedAddress = offset;
    }
    sidebar_->setCurrentRow(PageHex);
}

void MainWindow::showStringInHex(quint64 offset, quint64 length) {
    if (!haveStrings_ || !haveResult_ || !current_.data) {
        showStatus(tr("Hex navigation is unavailable because the current file is not loaded in memory."), true);
        return;
    }
    const QString extractedPath = QFileInfo(q(stringsResult_.filePath)).canonicalFilePath();
    const QString loadedPath = QFileInfo(q(current_.info.filePath)).canonicalFilePath();
#ifdef Q_OS_WIN
    constexpr Qt::CaseSensitivity pathSensitivity = Qt::CaseInsensitive;
#else
    constexpr Qt::CaseSensitivity pathSensitivity = Qt::CaseSensitive;
#endif
    if (extractedPath.isEmpty() || loadedPath.isEmpty() ||
        extractedPath.compare(loadedPath, pathSensitivity) != 0) {
        showStatus(tr("This string belongs to a different file than the one currently shown in the Hex Viewer."), true);
        return;
    }
    if (offset >= current_.data->size() || length == 0 || length > current_.data->size() - offset) {
        showStatus(tr("The extracted string range is outside the Hex Viewer data."), true);
        return;
    }
    if (!hex_->setRangeHighlight(offset, length) || !hex_->goToOffset(offset)) {
        hex_->clearRangeHighlight();
        showStatus(tr("Could not navigate to the extracted string range."), true);
        return;
    }
    sidebar_->setCurrentRow(PageHex);
    showStatus(tr("Highlighted %1 bytes at offset %2 in the Hex Viewer.")
                   .arg(length).arg(hex64(offset)));
}

void MainWindow::onHexSelection(quint64 off) {
    if (!current_.data || off >= current_.data->size()) return;
    const uint8_t b = (*current_.data)[static_cast<size_t>(off)];
    QString va;
    if (auto v = current_.info.fileOffsetToVirtual(off)) va = tr("   VA %1").arg(hex64(*v));
    hexInfo_->setText(tr("Offset %1 (%2)   value 0x%3 (%4)%5")
                          .arg(hex64(off), QString::number(off), QString::number(b, 16).rightJustified(2, '0'), QString::number(b), va));
}

// ============================================================================ disassembly
void MainWindow::populateStartPoints() {
    startCombo_->clear();
    startPoints_.clear();
    startEdit_->clear();
    if (!haveResult_ || !current_.info.recognized()) return;
    startPoints_ = xrl::knownStartPoints(current_.info);
    for (const auto& p : startPoints_) startCombo_->addItem(q(p.label));
    if (!startPoints_.empty()) startEdit_->setText(q(xrl::hex(startPoints_[0].fileOffset)));
    else startCombo_->addItem(tr("(no known start points in file metadata)"));
}

void MainWindow::updateFunctionExplorer() {
    if (!functionExplorerTable_) return;
    QVector<QStringList> functions;
    QString functionNote;
    if (!haveResult_) {
        functionNote = tr("Open a supported executable to inspect function candidates.");
    } else if (cfgCandidates_.empty()) {
        functionNote = tr("No function candidates were found from the parsed entry point, symbols, exports, or executable section starts. Stripped files may provide fewer candidates.");
    } else {
        functionNote = tr("%1 metadata-backed candidate(s). Section starts and entry points are candidates, not confirmed function boundaries.")
                           .arg(cfgCandidates_.size());
        const bool matchingXref = haveXref_ && xrefResult_.sha256 == current_.info.sha256;
        auto evidenceText = [](xrl::FunctionEvidence evidence) {
            switch (evidence) {
                case xrl::FunctionEvidence::EntryPoint: return tr("Entry point candidate");
                case xrl::FunctionEvidence::Export: return tr("Export");
                case xrl::FunctionEvidence::Symbol: return tr("Function symbol");
                case xrl::FunctionEvidence::SectionStart: return tr("Executable section start");
                case xrl::FunctionEvidence::UserAddress: return tr("User address");
            }
            return tr("Unknown evidence");
        };
        for (const auto& candidate : cfgCandidates_) {
            const auto indexed = matchingXref
                                     ? std::find_if(xrefResult_.functions.begin(), xrefResult_.functions.end(),
                                                    [&candidate](const auto& item) { return item.candidate.address == candidate.address; })
                                     : xrefResult_.functions.end();
            const bool hasMetrics = matchingXref && indexed != xrefResult_.functions.end();
            functions.push_back({
                candidate.name.empty() ? tr("(unnamed candidate)") : q(candidate.name),
                hex64(candidate.address),
                hex64(candidate.fileOffset),
                evidenceText(candidate.evidence),
                candidate.startConfirmed ? tr("confirmed start") : tr("candidate start"),
                hasMetrics ? QString::number(indexed->incomingCalls) : (matchingXref ? tr("not indexed") : tr("not analyzed")),
                hasMetrics ? QString::number(indexed->outgoingCalls) : (matchingXref ? tr("not indexed") : tr("not analyzed")),
                hasMetrics ? QString::number(indexed->callDepth) : (matchingXref ? tr("not indexed") : tr("not analyzed")),
                hasMetrics ? (indexed->recursive ? tr("yes") : tr("no")) : (matchingXref ? tr("not indexed") : tr("not analyzed")),
                hasMetrics ? QString::number(indexed->unresolvedIndirectCalls) : (matchingXref ? tr("not indexed") : tr("not analyzed"))
            });
        }
    }
    functionExplorerTable_->setContent(
        {tr("Name"), tr("Address"), tr("File offset"), tr("Evidence"), tr("Start status"), tr("Incoming calls"),
         tr("Outgoing calls"), tr("Call depth"), tr("Recursive"), tr("Unresolved indirect calls")},
        std::move(functions), functionNote, {1, 2});

    QVector<QStringList> relocations;
    const auto* relocationCategory = haveResult_ ? &current_.info.relocations : nullptr;
    if (relocationCategory) {
        for (const auto& relocation : relocationCategory->items) {
            relocations.push_back({
                hex64(relocation.address),
                relocation.fileOffset ? hex64(*relocation.fileOffset) : tr("(unmapped)"),
                relocation.typeName.empty() ? QString::number(relocation.type) : q(relocation.typeName),
                relocation.symbolName.empty() ? tr("(no symbol)") : q(relocation.symbolName),
                relocation.targetAddress ? hex64(*relocation.targetAddress) : tr("(unresolved)"),
                relocation.addend ? QString::number(*relocation.addend) : tr("(not present)"),
                q(relocation.source)
            });
        }
    }
    const QString relocationNote = !haveResult_
                                      ? tr("Open a file to inspect parsed relocation records.")
                                      : relocationCategory->state == xrl::Availability::NotParsed
                                            ? tr("Relocations are unavailable (not determined). %1").arg(q(relocationCategory->note))
                                            : relocationCategory->state == xrl::Availability::Absent
                                                  ? tr("No relocation records were found. %1").arg(q(relocationCategory->note))
                                                  : tr("%1 parsed relocation record(s). Missing symbol targets and file mappings remain unresolved.")
                                                        .arg(relocationCategory->items.size());
    relocationExplorerTable_->setContent(
        {tr("Address"), tr("File offset"), tr("Type"), tr("Symbol"), tr("Target"), tr("Addend"), tr("Evidence source")},
        std::move(relocations), relocationNote, {0, 1, 4});

    QVector<QStringList> debugRows;
    QStringList debugKeys{QStringLiteral("CodeView"), QStringLiteral("PDB"), QStringLiteral("debug"),
                          QStringLiteral("DWARF"), QStringLiteral("GNU build ID"), QStringLiteral("UUID")};
    if (haveResult_) {
        for (const auto& [key, value] : current_.info.metadata) {
            const QString keyText = q(key);
            if (std::any_of(debugKeys.cbegin(), debugKeys.cend(), [&keyText](const QString& marker) {
                    return keyText.contains(marker, Qt::CaseInsensitive);
                }))
                debugRows.push_back({keyText, q(value)});
        }
    }
    const QString debugNote = !haveResult_
                                  ? tr("Open a file to inspect debug-symbol identifiers.")
                                  : debugRows.empty()
                                        ? tr("No supported debug identifier or debug-section metadata was found. This does not establish that no external symbols exist.")
                                    : tr("%1 identifier or debug-section metadata item(s). External PDB/dSYM/debug files are not loaded or decoded.")
                                              .arg(debugRows.size());
    debugInfoTable_->setContent({tr("Identifier"), tr("Value")}, std::move(debugRows), debugNote, {1});

    const bool selected = selectedExplorerFunction().has_value();
    functionCfgButton_->setEnabled(selected && haveResult_ && current_.data &&
                                   xrl::cfgSupported(current_.info) && !cfgWatcher_.isRunning());
    functionDisasmButton_->setEnabled(selected && haveResult_ && current_.data &&
                                      xrl::disassemblySupported(current_.info));
    functionHexButton_->setEnabled(selected && haveResult_ && current_.data);
}

std::optional<uint64_t> MainWindow::selectedExplorerFunction() const {
    if (!functionExplorerTable_) return std::nullopt;
    const QModelIndex currentIndex = functionExplorerTable_->view()->currentIndex();
    if (!currentIndex.isValid()) return std::nullopt;
    const QModelIndex sourceIndex = functionExplorerTable_->proxy()->mapToSource(currentIndex);
    if (sourceIndex.row() < 0 || sourceIndex.row() >= functionExplorerTable_->model()->rowCount())
        return std::nullopt;
    const QStringList& row = functionExplorerTable_->model()->rowAt(sourceIndex.row());
    if (row.size() <= 1) return std::nullopt;
    const auto address = xrl::parseNumber(row[1].toStdString());
    if (!address) return std::nullopt;
    return address;
}

void MainWindow::openExplorerFunctionCfg() {
    const auto address = selectedExplorerFunction();
    if (!address || !xrl::cfgSupported(current_.info)) return;
    for (int i = 0; i < cfgFunctionCombo_->count(); ++i) {
        const auto candidateIndex = cfgFunctionCombo_->itemData(i).toULongLong();
        if (candidateIndex < cfgCandidates_.size() && cfgCandidates_[candidateIndex].address == *address) {
            cfgFunctionCombo_->setCurrentIndex(i);
            cfgAddressEdit_->clear();
            sidebar_->setCurrentRow(PageCfg);
            runCfgAnalysis();
            return;
        }
    }
}

void MainWindow::openExplorerFunctionDisassembly() {
    const auto address = selectedExplorerFunction();
    if (!address || !current_.data || !xrl::disassemblySupported(current_.info)) return;
    const auto candidate = std::find_if(cfgCandidates_.begin(), cfgCandidates_.end(),
                                        [address](const auto& item) { return item.address == *address; });
    if (candidate == cfgCandidates_.end()) return;
    sidebar_->setCurrentRow(PageDisasm);
    startModeCombo_->setCurrentIndex(0);
    startEdit_->setText(q(xrl::hex(candidate->fileOffset)));
    runDisassembly();
}

void MainWindow::runDisassembly() {
    if (!haveResult_ || !current_.data) return;
    const auto n = xrl::parseNumber(startEdit_->text().toStdString());
    if (!n) {
        showStatus(tr("Invalid start location. Use hex (0x401000) or decimal digits."), true);
        return;
    }
    uint64_t fileOff = *n;
    if (startModeCombo_->currentIndex() == 1) {
        const auto off = current_.info.virtualToFileOffset(*n);
        if (!off) {
            showStatus(tr("Virtual address %1 is not backed by file data in any parsed section.").arg(hex64(*n)), true);
            return;
        }
        fileOff = *off;
    }
    xrl::DisasmRequest req;
    req.fileOffset = fileOff;
    req.maxInstructions = static_cast<size_t>(countSpin_->value());
    req.maxBytes = static_cast<uint64_t>(countSpin_->value()) * 16;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    disasm_ = xrl::disassemble(current_.info, *current_.data, req);
    QApplication::restoreOverrideCursor();
    haveDisasm_ = disasm_.ok;
    if (!disasm_.ok) {
        showStatus(q(disasm_.error), true);
        disasmInfo_->setText(q(disasm_.error));
        updateEnabled();
        return;
    }
    QVector<QStringList> rows;
    rows.reserve(static_cast<qsizetype>(disasm_.instructions.size()));
    size_t bad = 0;
    for (const auto& ins : disasm_.instructions) {
        if (!ins.valid) ++bad;
        rows.push_back({hex64(ins.address, 8), hex64(ins.fileOffset), q(xrl::hexBytes(ins.bytes)), q(ins.mnemonic), q(ins.operands)});
    }
    disasmTable_->setContent({tr("Address"), tr("File offset"), tr("Bytes"), tr("Mnemonic"), tr("Operands")}, rows, {}, {0, 1, 2, 3, 4});
    QString info = tr("%1 instructions from %2 (%3). Linear sweep; this is not function-level analysis.")
                       .arg(disasm_.instructions.size())
                       .arg(hex64(disasm_.startAddress), disasm_.addressIsFileOffset ? tr("file offset") : tr("virtual address"));
    if (bad) info += tr(" %1 undecodable byte run(s) shown as .byte.").arg(bad);
    if (!disasm_.note.empty()) info += QStringLiteral(" ") + q(disasm_.note);
    disasmInfo_->setText(info);
    showStatus(tr("Disassembled %1 instructions.").arg(disasm_.instructions.size()));
    updateEnabled();
}

void MainWindow::runCfgAnalysis() {
    if (cfgWatcher_.isRunning()) return;
    if (!haveResult_ || !current_.data) {
        showStatus(tr("Open a file before analyzing control flow."), true);
        return;
    }
    if (!xrl::cfgSupported(current_.info)) {
        showStatus(tr("CFG analysis requires Capstone and a supported x86, x86-64, or ARM64 executable."), true);
        return;
    }

    xrl::FunctionCandidate candidate;
    const QString manualAddress = cfgAddressEdit_->text().trimmed();
    if (!manualAddress.isEmpty()) {
        const auto value = xrl::parseNumber(manualAddress.toStdString());
        if (!value) {
            showStatus(tr("Invalid start address. Enter hexadecimal (0x...) or decimal digits."), true);
            return;
        }
        std::optional<uint64_t> address = *value;
        if (cfgAddressModeCombo_->currentIndex() == 1) address = current_.info.fileOffsetToVirtual(*value);
        if (!address) {
            showStatus(tr("The selected file offset is not mapped to a virtual address."), true);
            return;
        }
        const auto offset = current_.info.virtualToFileOffset(*address);
        if (!offset) {
            showStatus(tr("The selected virtual address is not backed by file data."), true);
            return;
        }
        candidate = {tr("User-supplied start").toStdString(), *address, *offset,
                     xrl::FunctionEvidence::UserAddress, false};
    } else {
        int selected = -1;
        if (cfgFunctionCombo_->currentData().isValid()) {
            const qulonglong candidateIndex = cfgFunctionCombo_->currentData().toULongLong();
            if (candidateIndex < cfgCandidates_.size()) selected = static_cast<int>(candidateIndex);
        }
        if (selected < 0 && !cfgFunctionCombo_->currentText().trimmed().isEmpty()) {
            selected = cfgFunctionCombo_->findText(cfgFunctionCombo_->currentText(), Qt::MatchExactly);
        }
        if (selected < 0 || static_cast<size_t>(selected) >= cfgCandidates_.size()) {
            showStatus(tr("Choose a listed start point, or enter a virtual address/file offset in the address field."), true);
            return;
        }
        candidate = cfgCandidates_[static_cast<size_t>(selected)];
    }

    const auto fileData = current_.data;
    const auto info = current_.info;
    cfgCancel_ = std::make_shared<std::atomic_bool>(false);
    const auto cancel = cfgCancel_;
    cfgAnalysisPath_ = QFileInfo(q(current_.info.filePath)).canonicalFilePath();
    if (cfgAnalysisPath_.isEmpty()) cfgAnalysisPath_ = QFileInfo(q(current_.info.filePath)).absoluteFilePath();
    cfgResult_ = {};
    haveCfg_ = false;
    cfgGraphView_->clearGraph(tr("Analyzing control flow..."));
    cfgDetails_->clear();
    cfgProgress_->setValue(0);
    cfgProgress_->show();
    cfgStatusLabel_->setText(tr("Analyzing reachable blocks from %1...").arg(hex64(candidate.address)));
    updateEnabled();
    cfgWatcher_.setFuture(QtConcurrent::run([this, info, fileData, candidate, cancel] {
        return xrl::analyzeControlFlow(
            info, *fileData, candidate, {},
            [this](int percent, const std::string& stage) {
                QMetaObject::invokeMethod(this, [this, percent, text = q(stage)] { onCfgProgress(percent, text); },
                                          Qt::QueuedConnection);
            },
            [cancel] { return cancel->load(); });
    }));
}

void MainWindow::onCfgProgress(int percent, const QString& stage) {
    if (!cfgWatcher_.isRunning()) return;
    cfgProgress_->setValue(percent);
    cfgStatusLabel_->setText(stage);
}

void MainWindow::onCfgAnalysisFinished() {
    const auto result = cfgWatcher_.result();
    cfgProgress_->hide();
    const QString currentPath = QFileInfo(q(current_.info.filePath)).canonicalFilePath();
    const QString expectedPath = cfgAnalysisPath_;
    if (expectedPath.isEmpty() || currentPath.isEmpty() || expectedPath != currentPath || !haveResult_) {
        updateEnabled();
        return;
    }
    cfgResult_ = result;
    haveCfg_ = result.ok;
    if (!result.ok) {
        cfgGraphView_->clearGraph(QString::fromStdString(result.error));
        cfgDetails_->setPlainText(QString::fromStdString(result.error));
        cfgStatusLabel_->setText(QString::fromStdString(result.error));
        showStatus(QString::fromStdString(result.error), true);
        updateEnabled();
        return;
    }
    cfgGraphView_->setGraph(cfgResult_);
    const QString confidence = result.function.startConfirmed
                                  ? tr("metadata confirms a function-start symbol")
                                  : tr("candidate start only; function boundary is not confirmed");
    QStringList details;
    details << tr("%1 @ %2").arg(q(result.function.name), hex64(result.function.address));
    details << confidence;
    details << tr("Analysed bytes: %1").arg(result.analyzedBytes);
    details << tr("Basic blocks: %1 (%2 reachable)")
                   .arg(result.blocks.size()).arg(result.metrics.reachableBlocks);
    details << tr("Resolved intraprocedural edges: %1; conditional branches: %2")
                   .arg(result.metrics.edgeCount).arg(result.metrics.conditionalBranches);
    details << tr("Cyclomatic complexity: %1")
                   .arg(result.metrics.cyclomaticComplexity);
    details << tr("Dominator back-edges / natural-loop headers: %1 / %2")
                   .arg(result.metrics.backEdges).arg(result.metrics.naturalLoops);
    details << tr("Non-trivial strongly connected components: %1")
                   .arg(result.metrics.stronglyConnectedComponents);
    details << tr("Function size: unavailable (no reliable end boundary)");
    details << tr("Incoming cross-function references: unavailable without whole-program call-graph analysis");
    details << tr("Direct calls recorded: %1 (indirect calls remain unresolved)")
                   .arg(result.calls.size());
    for (const auto& call : result.calls) {
        details << tr("  %1 -> %2%3")
                       .arg(hex64(call.instructionAddress),
                            call.targetAddress ? hex64(*call.targetAddress) : tr("unresolved indirect target"),
                            call.recursive ? tr(" (recursive)") : QString());
    }
    details << tr("Metrics: complexity = internal edges + exit edges - reachable blocks + 1; "
                  "dominators are fixed-point sets; back-edges target a dominator; SCCs use Tarjan.");
    if (result.truncated) details << tr("Analysis was truncated by an explicit resource limit; the graph is partial.");
    cfgDetails_->setPlainText(details.join('\n'));
    cfgStatusLabel_->setText(tr("%1 blocks, %2 instructions. Double-click a block to open its mapped bytes in Hex.")
                                 .arg(result.blocks.size())
                                 .arg(result.analyzedBytes));
    onCfgBlockSelected(result.function.address);
    recordWorkspaceAnalysis(
        tr("Control Flow Graph"), q(current_.info.filePath), q(current_.info.sha256),
        tr("%1 blocks · %2 instructions")
            .arg(result.blocks.size()).arg(result.analyzedBytes),
        xrl::exportCfgJson(result));
    updateEnabled();
}

void MainWindow::onCfgBlockSelected(quint64 address) {
    if (!haveCfg_) return;
    const auto block = std::find_if(cfgResult_.blocks.begin(), cfgResult_.blocks.end(),
                                    [address](const xrl::BasicBlock& item) { return item.startAddress == address; });
    if (block == cfgResult_.blocks.end()) return;

    QStringList details{tr("Selected block %1").arg(hex64(block->startAddress)),
                        tr("Virtual range: [%1, %2)").arg(hex64(block->startAddress), hex64(block->endAddress)),
                        tr("File offset: %1").arg(hex64(block->fileOffset)),
                        tr("Instructions: %1").arg(block->instructions.size()),
                        tr("Predecessors: %1").arg(block->predecessors.size()),
                        tr("Successors: %1").arg(block->successors.size())};
    if (block->hasUnresolvedFlow) details << tr("This block has unresolved control flow.");
    for (const auto& edge : cfgResult_.edges) {
        if (edge.from != block->id) continue;
        const QString target = edge.to && *edge.to < cfgResult_.blocks.size()
                                   ? hex64(cfgResult_.blocks[*edge.to].startAddress)
                                   : edge.targetAddress ? hex64(edge.targetAddress) : tr("unknown target");
        details << tr("  %1 -> %2 (%3%4)")
                       .arg(hex64(block->startAddress), target,
                            QString::fromStdString(edge.label),
                            edge.targetResolved ? QString() : tr(", unresolved/external"));
    }
    QString baseDetails = cfgDetails_->toPlainText();
    const qsizetype selectedAt = baseDetails.indexOf(tr("\nSelected block "));
    if (selectedAt >= 0) baseDetails.truncate(selectedAt);
    cfgDetails_->setPlainText(baseDetails + QStringLiteral("\n\n") + details.join('\n'));
    cfgHexButton_->setEnabled(true);

    QVector<QStringList> rows;
    rows.reserve(static_cast<qsizetype>(block->instructions.size()));
    for (const auto& instruction : block->instructions) {
        rows.push_back({hex64(instruction.address, 8), hex64(instruction.fileOffset),
                        q(xrl::hexBytes(instruction.bytes)), q(instruction.mnemonic), q(instruction.operands)});
    }
    syncingCfgDisasm_ = true;
    disasmTable_->setContent({tr("Address"), tr("File offset"), tr("Bytes"), tr("Mnemonic"), tr("Operands")},
                             rows, tr("Showing the selected CFG block. Choose another block to update this listing."),
                             {0, 1, 2, 3, 4});
    disasmInfo_->setText(tr("CFG block %1; instruction addresses are virtual addresses and file offsets are mapped from parsed sections.")
                             .arg(hex64(block->startAddress)));
    haveDisasm_ = false;
    if (!rows.isEmpty()) disasmTable_->view()->selectRow(0);
    syncingCfgDisasm_ = false;
    reportIncludeDisasm_->setEnabled(false);
    updateEnabled();
}

void MainWindow::onCfgInstructionSelected(const QModelIndex& current) {
    if (syncingCfgDisasm_ || !haveCfg_ || !current.isValid()) return;
    const auto source = disasmTable_->proxy()->mapToSource(current);
    if (!source.isValid()) return;
    const auto value = xrl::parseNumber(disasmTable_->model()->rowAt(source.row()).value(0).toStdString());
    if (!value) return;
    const auto block = std::find_if(cfgResult_.blocks.begin(), cfgResult_.blocks.end(),
                                    [address = *value](const xrl::BasicBlock& item) {
                                        return address >= item.startAddress && address < item.endAddress;
                                    });
    if (block != cfgResult_.blocks.end()) cfgGraphView_->selectBlockByAddress(block->startAddress, false);
}

void MainWindow::findCfgBlock() {
    if (!haveCfg_) return;
    const auto address = xrl::parseNumber(cfgBlockSearchEdit_->text().toStdString());
    if (!address) {
        showStatus(tr("Enter a valid block or instruction address."), true);
        return;
    }
    const auto block = std::find_if(cfgResult_.blocks.begin(), cfgResult_.blocks.end(),
                                    [value = *address](const xrl::BasicBlock& item) {
                                        return value >= item.startAddress && value < item.endAddress;
                                    });
    if (block == cfgResult_.blocks.end()) {
        showStatus(tr("Address %1 is not part of this analyzed graph.").arg(hex64(*address)), true);
        return;
    }
    cfgGraphView_->selectBlockByAddress(block->startAddress);
}

bool MainWindow::exportCfg(bool dot) {
    if (!haveCfg_) return false;
    QSettings settings;
    const QString base = cfgResult_.function.name.empty()
                             ? QStringLiteral("function-%1").arg(hex64(cfgResult_.function.address))
                             : q(cfgResult_.function.name);
    const QString suffix = dot ? QStringLiteral(".cfg.dot") : QStringLiteral(".cfg.json");
    const QString initial = QDir(settings.value("ui/lastExportDir", QDir::homePath()).toString()).filePath(base + suffix);
    const QString path = QFileDialog::getSaveFileName(this, dot ? tr("Export graph as Graphviz DOT")
                                                                : tr("Export control-flow graph as JSON"),
                                                      initial, dot ? tr("Graphviz DOT (*.dot)") : tr("JSON (*.json)"));
    if (path.isEmpty()) return false;
    settings.setValue("ui/lastExportDir", QFileInfo(path).absolutePath());
    const std::string content = dot ? xrl::exportCfgDot(cfgResult_) : xrl::exportCfgJson(cfgResult_);
    std::ofstream output(toPath(path), std::ios::binary | std::ios::trunc);
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    output.flush();
    if (!output) {
        showStatus(tr("Failed to write CFG export to %1").arg(path), true);
        return false;
    }
    showStatus(tr("Control-flow graph exported to %1").arg(path));
    return true;
}

void MainWindow::showCfgBlockInHex(quint64 address) {
    if (!haveCfg_ || !haveResult_ || !current_.data) {
        showStatus(tr("Hex navigation is unavailable for this CFG result."), true);
        return;
    }
    const QString loadedPath = QFileInfo(q(current_.info.filePath)).canonicalFilePath();
    if (loadedPath.isEmpty() || loadedPath != cfgAnalysisPath_) {
        showStatus(tr("The CFG belongs to a different file than the one currently loaded."), true);
        return;
    }
    const auto block = std::find_if(cfgResult_.blocks.begin(), cfgResult_.blocks.end(),
                                    [address](const xrl::BasicBlock& item) { return item.startAddress == address; });
    if (block == cfgResult_.blocks.end() || block->endAddress <= block->startAddress) {
        showStatus(tr("The selected block has no valid byte range."), true);
        return;
    }
    const uint64_t length = block->endAddress - block->startAddress;
    if (block->fileOffset >= current_.data->size() || length > current_.data->size() - block->fileOffset ||
        !hex_->setRangeHighlight(block->fileOffset, length) || !hex_->goToOffset(block->fileOffset)) {
        hex_->clearRangeHighlight();
        showStatus(tr("The selected block does not map to a valid file range."), true);
        return;
    }
    sidebar_->setCurrentRow(PageHex);
    showStatus(tr("Highlighted CFG block %1 at file offset %2.")
                   .arg(hex64(block->startAddress), hex64(block->fileOffset)));
}

// ============================================================================ ghidra
xrl::GhidraInstall MainWindow::currentGhidra(QString* error) const {
    const QString path = ghidraPathEdit_->text().trimmed();
    xrl::GhidraInstall g;
    if (path.isEmpty()) {
        g.error = "No Ghidra directory configured. Set it under Settings.";
    } else {
        g = xrl::validateGhidraInstall(toPath(path));
    }
    if (!g.valid && error) *error = q(g.error);
    return g;
}

void MainWindow::refreshGhidraStatus() {
    QString err;
    const auto g = currentGhidra(&err);
    if (g.valid) {
        ghidraStatus_->setText(tr("Ghidra found at %1%2.").arg(q(g.root), g.version.empty() ? QString() : tr(" (version %1)").arg(q(g.version))));
        ghidraPathStatus_->setText(tr("Valid Ghidra installation%1.").arg(g.version.empty() ? QString() : tr(", version %1").arg(q(g.version))));
    } else if (ghidraPathEdit_->text().trimmed().isEmpty()) {
        ghidraStatus_->setText(tr("Ghidra is not configured. The rest of the application works without it. Set the location under Settings."));
        ghidraPathStatus_->setText(tr("Not configured."));
    } else {
        ghidraStatus_->setText(tr("Configured Ghidra path is not valid: %1").arg(err));
        ghidraPathStatus_->setText(tr("Invalid: %1").arg(err));
    }
}

void MainWindow::runGhidra() {
    if (!haveResult_ || current_.info.filePath.empty()) return;
    QString err;
    const auto g = currentGhidra(&err);
    if (!g.valid) {
        showStatus(tr("Cannot run Ghidra: %1").arg(err), true);
        sidebar_->setCurrentRow(PageSettings);
        return;
    }
    xrl::GhidraOptions opts;
    opts.decompile = ghidraDecompile_->isChecked();
    opts.maxDecompiled = ghidraMaxDecomp_->value();
    const auto scriptDir = xrl::findGhidraScriptDir(toPath(QCoreApplication::applicationDirPath()));
    ghidraLog_->clear();
    haveGhidra_ = false;
    if (!ghidraRunner_->start(g, q(current_.info.filePath), opts, scriptDir, &err)) {
        showStatus(err, true);
        return;
    }
    ghidraFunctions_->clear(tr("Ghidra is running. Large files can take several minutes..."));
    setBusy(true, tr("Running Ghidra headless analysis"));
    progress_->setRange(0, 0);  // indeterminate: Ghidra does not report percentages
    updateEnabled();
}

void MainWindow::onGhidraFinished(const xrl::GhidraResult& r) {
    progress_->setRange(0, 100);
    setBusy(false);
    ghidra_ = r;
    haveGhidra_ = r.ok;
    if (!r.ok) {
        ghidraFunctions_->clear(tr("Ghidra analysis failed: %1").arg(q(r.error)));
        showStatus(tr("Ghidra: %1").arg(q(r.error)), true);
        updateEnabled();
        return;
    }
    QVector<QStringList> rows;
    for (const auto& f : r.functions) {
        QStringList flags;
        if (f.external) flags << tr("external");
        if (f.thunk) flags << tr("thunk");
        if (f.hasDecompilation) flags << tr("decompiled");
        rows.push_back({hex64(f.entry), q(f.name), QString::number(f.size), q(f.signature), flags.join(", ")});
    }
    ghidraFunctions_->setContent({tr("Entry"), tr("Name"), tr("Size"), tr("Signature (Ghidra)"), tr("Flags")}, rows,
                                 tr("Ghidra %1, language %2, compiler %3. %4 function(s) reported.")
                                     .arg(q(r.ghidraVersion), q(r.language), q(r.compiler)).arg(r.totalFunctions),
                                 {0, 2});
    showStatus(tr("Ghidra analysis complete: %1 function(s).").arg(r.functions.size()));
    updateEnabled();
}

void MainWindow::showGhidraFunction() {
    const auto idx = ghidraFunctions_->view()->currentIndex();
    if (!idx.isValid()) return;
    const int row = ghidraFunctions_->proxy()->mapToSource(idx).row();
    if (row < 0 || static_cast<size_t>(row) >= ghidra_.functions.size()) return;
    const auto& f = ghidra_.functions[static_cast<size_t>(row)];
    ghidraDecompiled_->setPlainText(f.hasDecompilation
                                        ? q(f.decompiled)
                                        : tr("// No decompiler output for this function (decompilation not requested, limit reached, "
                                             "external/thunk function, or Ghidra could not decompile it)."));
}

// ============================================================================ diff & comparison
void MainWindow::selectDiffFileA() {
    QSettings s;
    const QString p = QFileDialog::getOpenFileName(this, tr("Select Baseline File (A)"),
                                                   s.value("ui/lastDir").toString(), tr("All files (*)"));
    if (p.isEmpty()) return;
    s.setValue("ui/lastDir", QFileInfo(p).absolutePath());
    diffPathA_ = p;
    diffDataA_.reset();
    diffPathLabelA_->setText(QFileInfo(p).fileName());
    diffPathLabelA_->setToolTip(p);
    QFileInfo fi(p);
    diffInfoLabelA_->setText(tr("Size: %1").arg(q(xrl::humanSize(fi.size()))));
    updateEnabled();
}

void MainWindow::selectDiffFileB() {
    QSettings s;
    const QString p = QFileDialog::getOpenFileName(this, tr("Select Comparison File (B)"),
                                                   s.value("ui/lastDir").toString(), tr("All files (*)"));
    if (p.isEmpty()) return;
    s.setValue("ui/lastDir", QFileInfo(p).absolutePath());
    diffPathB_ = p;
    diffDataB_.reset();
    diffPathLabelB_->setText(QFileInfo(p).fileName());
    diffPathLabelB_->setToolTip(p);
    QFileInfo fi(p);
    diffInfoLabelB_->setText(tr("Size: %1").arg(q(xrl::humanSize(fi.size()))));
    updateEnabled();
}

void MainWindow::useCurrentAsBaseline() {
    if (!haveResult_ || current_.info.filePath.empty()) {
        showStatus(tr("No file currently loaded to use as baseline."), true);
        return;
    }
    diffPathA_ = q(current_.info.filePath);
    diffDataA_ = current_.data;
    diffPathLabelA_->setText(QFileInfo(diffPathA_).fileName());
    diffPathLabelA_->setToolTip(diffPathA_);
    diffInfoLabelA_->setText(tr("%1, %2").arg(q(xrl::humanSize(current_.info.fileSize)), q(current_.info.formatName)));
    diffHexA_->setData(diffDataA_);
    diffResult_ = {};
    haveDiff_ = false;
    currentDiffIndex_ = -1;
    diffByteTable_->clear(tr("Run Binary Diff to compare File A with File B."));
    diffMetaTable_->clear(tr("Run Binary Diff to compare executable metadata."));
    diffSummaryText_->clear();
    diffStatusLabel_->setText(tr("Current file loaded as File A. Choose File B to compare."));
    updateEnabled();
}

void MainWindow::runDiff() {
    if (diffPathA_.isEmpty() || diffPathB_.isEmpty()) {
        showStatus(tr("Please select both a Baseline (A) and Comparison (B) file."), true);
        return;
    }
    diffRunBtn_->setEnabled(false);
    diffProgress_->show();
    diffProgress_->setValue(0);
    diffStatusLabel_->setText(tr("Comparing files..."));

    const auto limits = currentLimits();
    const auto pA = toPath(diffPathA_);
    const auto pB = toPath(diffPathB_);

    diffWatcher_.setFuture(QtConcurrent::run([this, pA, pB, limits] {
        return xrl::compareFiles(pA, pB, limits, [this](int pct, const std::string& stage) {
            QMetaObject::invokeMethod(this, [this, pct, s = q(stage)] {
                diffProgress_->setValue(pct);
                diffStatusLabel_->setText(s + QStringLiteral("..."));
            }, Qt::QueuedConnection);
        });
    }));
}

void MainWindow::onDiffFinished() {
    diffResult_ = diffWatcher_.result();
    diffProgress_->hide();
    diffRunBtn_->setEnabled(true);
    haveDiff_ = diffResult_.ok;

    if (!diffResult_.ok) {
        diffStatusLabel_->setText(tr("Comparison failed: %1").arg(q(diffResult_.error)));
        showStatus(tr("Diff error: %1").arg(q(diffResult_.error)), true);
        updateEnabled();
        return;
    }

    auto loadBuf = [](const QString& p) -> std::shared_ptr<const std::vector<uint8_t>> {
        std::ifstream in(toPath(p), std::ios::binary);
        if (!in) return nullptr;
        in.seekg(0, std::ios::end);
        const auto sz = in.tellg();
        in.seekg(0, std::ios::beg);
        if (sz > 64 * 1024 * 1024) return nullptr;
        auto b = std::make_shared<std::vector<uint8_t>>(static_cast<size_t>(sz));
        in.read(reinterpret_cast<char*>(b->data()), sz);
        return b;
    };

    if (!diffDataA_ || diffDataA_->empty()) diffDataA_ = loadBuf(diffPathA_);
    if (!diffDataB_ || diffDataB_->empty()) diffDataB_ = loadBuf(diffPathB_);

    diffHexA_->setData(diffDataA_);
    diffHexB_->setData(diffDataB_);

    std::vector<HexView::HighlightSpan> hlA, hlB;
    for (const auto& d : diffResult_.byteDiffs) {
        if (d.kind == xrl::DiffKind::Modified) {
            hlA.push_back({d.offsetA, d.sizeA, HexView::DiffModified});
            hlB.push_back({d.offsetB, d.sizeB, HexView::DiffModified});
        } else if (d.kind == xrl::DiffKind::Inserted) {
            hlB.push_back({d.offsetB, d.sizeB, HexView::DiffInserted});
        } else if (d.kind == xrl::DiffKind::Deleted) {
            hlA.push_back({d.offsetA, d.sizeA, HexView::DiffDeleted});
        }
    }
    diffHexA_->setDiffHighlights(std::move(hlA));
    diffHexB_->setDiffHighlights(std::move(hlB));

    populateDiffResults();
    recordWorkspaceComparison();
    updateEnabled();
}

void MainWindow::populateDiffResults() {
    if (!haveDiff_) return;

    const auto& s = diffResult_.summary;
    if (s.identical) {
        diffStatusLabel_->setText(tr("Files are IDENTICAL. (0 differences)"));
    } else {
        diffStatusLabel_->setText(tr("Different: %1 diff region(s), %2 modified, %3 inserted, %4 deleted bytes; %5 metadata change(s)")
                                      .arg(s.totalDiffRegions)
                                      .arg(s.totalModifiedBytes)
                                      .arg(s.totalInsertedBytes)
                                      .arg(s.totalDeletedBytes)
                                      .arg(s.addedMetadataCount + s.removedMetadataCount + s.modifiedMetadataCount));
    }

    // Metadata changes table
    QVector<QStringList> metaRows;
    for (const auto& m : diffResult_.metadataDiffs) {
        metaRows.push_back({
            q(m.category),
            q(m.key),
            q(xrl::toString(m.change)),
            q(m.oldValue),
            q(m.newValue),
            m.offsetA ? hex64(*m.offsetA) : QStringLiteral("-"),
            m.offsetB ? hex64(*m.offsetB) : QStringLiteral("-"),
            q(m.note)
        });
    }
    diffMetaTable_->setContent(
        {tr("Category"), tr("Key / Item"), tr("Change"), tr("Baseline (A)"), tr("Comparison (B)"), tr("Offset A"), tr("Offset B"), tr("Notes")},
        metaRows,
        tr("Double-click any entry with an offset to navigate both Hex views to that location."),
        {5, 6});

    // Byte diff regions table
    QVector<QStringList> byteRows;
    for (size_t i = 0; i < diffResult_.byteDiffs.size(); ++i) {
        const auto& b = diffResult_.byteDiffs[i];
        byteRows.push_back({
            QString::number(i + 1),
            q(xrl::toString(b.kind)),
            hex64(b.offsetA),
            QString::number(b.sizeA),
            hex64(b.offsetB),
            QString::number(b.sizeB)
        });
    }
    diffByteTable_->setContent(
        {tr("Region #"), tr("Diff Type"), tr("Offset A"), tr("Size A"), tr("Offset B"), tr("Size B")},
        byteRows,
        tr("Double-click a difference region to jump directly to it in both Hex views."),
        {2, 3, 4, 5});

    diffSummaryText_->setPlainText(q(xrl::renderDiffTextReport(diffResult_)));

    if (!diffResult_.byteDiffs.empty()) {
        jumpToDiff(0);
    } else {
        currentDiffIndex_ = -1;
        diffNavLabel_->setText(tr("Files are byte-for-byte identical."));
        diffPrevBtn_->setEnabled(false);
        diffNextBtn_->setEnabled(false);
    }
}

void MainWindow::jumpToDiff(int index) {
    if (!haveDiff_ || index < 0 || static_cast<size_t>(index) >= diffResult_.byteDiffs.size()) return;
    currentDiffIndex_ = index;
    const auto& d = diffResult_.byteDiffs[static_cast<size_t>(index)];

    diffHexA_->goToOffset(d.offsetA);
    diffHexB_->goToOffset(d.offsetB);

    diffNavLabel_->setText(tr("Diff %1 of %2: %3 (A: %4, B: %5)")
                               .arg(index + 1)
                               .arg(diffResult_.byteDiffs.size())
                               .arg(q(xrl::toString(d.kind)), hex64(d.offsetA), hex64(d.offsetB)));
    diffPrevBtn_->setEnabled(index > 0);
    diffNextBtn_->setEnabled(static_cast<size_t>(index + 1) < diffResult_.byteDiffs.size());
}

void MainWindow::nextDiff() {
    if (haveDiff_ && static_cast<size_t>(currentDiffIndex_ + 1) < diffResult_.byteDiffs.size()) {
        jumpToDiff(currentDiffIndex_ + 1);
    }
}

void MainWindow::prevDiff() {
    if (haveDiff_ && currentDiffIndex_ > 0) {
        jumpToDiff(currentDiffIndex_ - 1);
    }
}

bool MainWindow::exportDiffReport(bool json) {
    if (!haveDiff_) return false;
    QSettings s;
    const QString defName = QStringLiteral("diff_report.") + (json ? QStringLiteral("json") : QStringLiteral("txt"));
    const QString def = QDir(s.value("ui/lastExportDir", QDir::homePath()).toString()).filePath(defName);
    const QString path = QFileDialog::getSaveFileName(
        this,
        json ? tr("Export Comparison JSON Report") : tr("Export Comparison Text Report"),
        def,
        json ? tr("JSON (*.json)") : tr("Text (*.txt)"));
    if (path.isEmpty()) return false;
    s.setValue("ui/lastExportDir", QFileInfo(path).absolutePath());

    const std::string content = json ? xrl::renderDiffJsonReport(diffResult_) : xrl::renderDiffTextReport(diffResult_);
    std::ofstream out(toPath(path), std::ios::binary | std::ios::trunc);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!out) {
        showStatus(tr("Failed to write report to %1").arg(path), true);
        return false;
    }
    showStatus(tr("Comparison report exported to %1").arg(path));
    return true;
}

// ============================================================================ entropy
void MainWindow::chooseEntropyFile(bool comparison) {
    QSettings settings;
    const QString path = QFileDialog::getOpenFileName(
        this, comparison ? tr("Select comparison file (B)") : tr("Select entropy file (A)"),
        settings.value("ui/lastDir").toString(), tr("All files (*)"));
    if (path.isEmpty()) return;
    settings.setValue("ui/lastDir", QFileInfo(path).absolutePath());
    if (comparison) {
        entropyPathB_ = path;
        entropyPathBEdit_->setText(path);
        haveEntropyComparison_ = false;
    } else {
        entropyPathA_ = path;
        entropyPathAEdit_->setText(path);
        haveEntropyPrimary_ = false;
        haveEntropyComparison_ = false;
    }
    updateEntropyPresentation();
    updateEnabled();
}

void MainWindow::runEntropyAnalysis() {
    if (entropyWatcher_.isRunning()) return;
    if (entropyPathA_.isEmpty()) {
        showStatus(tr("Choose File A or load a file before analysing entropy."), true);
        return;
    }

    entropyPrimary_ = {};
    entropyComparison_ = {};
    haveEntropyPrimary_ = false;
    haveEntropyComparison_ = false;
    updateEntropyPresentation();
    entropyCancel_ = std::make_shared<std::atomic_bool>(false);
    const auto cancel = entropyCancel_;
    const auto pathA = toPath(entropyPathA_);
    const auto pathB = toPath(entropyPathB_);
    const bool hasComparison = !entropyPathB_.isEmpty();
    const size_t blockSize = static_cast<size_t>(entropyBlockSizeCombo_->currentData().toULongLong());
    entropyRunBtn_->setEnabled(false);
    entropyCancelBtn_->setEnabled(true);
    entropyProgress_->setValue(0);
    entropyProgress_->show();
    entropyStatusLabel_->setText(tr("Analyzing File A..."));
    entropyWatcher_.setFuture(QtConcurrent::run([this, cancel, pathA, pathB, hasComparison, blockSize] {
        EntropyJobResult job;
        job.primary = xrl::analyzeEntropyFile(pathA, blockSize,
            [this](int percent, const std::string& stage) {
                QMetaObject::invokeMethod(this, [this, percent, text = q(stage)] {
                    entropyProgress_->setValue(percent / 2);
                    entropyStatusLabel_->setText(text + QStringLiteral(" (File A)..."));
                }, Qt::QueuedConnection);
            },
            [cancel] { return cancel->load(); });
        if (job.primary.ok && hasComparison && !cancel->load()) {
            job.hasComparison = true;
            job.comparison = xrl::analyzeEntropyFile(pathB, blockSize,
                [this](int percent, const std::string& stage) {
                    QMetaObject::invokeMethod(this, [this, percent, text = q(stage)] {
                        entropyProgress_->setValue(50 + percent / 2);
                        entropyStatusLabel_->setText(text + QStringLiteral(" (File B)..."));
                    }, Qt::QueuedConnection);
                },
                [cancel] { return cancel->load(); });
        }
        return job;
    }));
    updateEnabled();
}

void MainWindow::onEntropyFinished() {
    const EntropyJobResult job = entropyWatcher_.result();
    entropyPrimary_ = job.primary;
    entropyComparison_ = job.comparison;
    haveEntropyPrimary_ = entropyPrimary_.ok;
    haveEntropyComparison_ = job.hasComparison && entropyComparison_.ok;
    entropyProgress_->hide();
    entropyCancelBtn_->setEnabled(false);
    entropyCancel_.reset();
    updateEntropyPresentation();

    if (!entropyPrimary_.ok) {
        entropyStatusLabel_->setText(entropyPrimary_.cancelled
                                         ? tr("Entropy analysis cancelled.")
                                         : tr("File A analysis failed: %1").arg(q(entropyPrimary_.error)));
        showStatus(entropyStatusLabel_->text(), !entropyPrimary_.cancelled);
    } else if (job.hasComparison && !entropyComparison_.ok) {
        entropyStatusLabel_->setText(entropyComparison_.cancelled
                                         ? tr("File A analyzed; File B comparison cancelled.")
                                         : tr("File A analyzed; File B comparison failed: %1").arg(q(entropyComparison_.error)));
        showStatus(entropyStatusLabel_->text(), !entropyComparison_.cancelled);
    } else if (haveEntropyComparison_) {
        entropyStatusLabel_->setText(tr("Entropy analysis and distribution comparison complete."));
        showStatus(entropyStatusLabel_->text());
    } else {
        entropyStatusLabel_->setText(tr("Entropy analysis complete."));
        showStatus(entropyStatusLabel_->text());
    }
    if (haveEntropyPrimary_) {
        recordWorkspaceAnalysis(
            tr("Entropy"), q(entropyPrimary_.filePath), q(entropyPrimary_.sha256),
            tr("%1 blocks · overall entropy %2 bits/byte")
                .arg(entropyPrimary_.blocks.size())
                .arg(entropyPrimary_.overallEntropy ? QString::number(*entropyPrimary_.overallEntropy, 'f', 3) : tr("n/a")),
            xrl::renderEntropyJsonReport(
                entropyPrimary_, haveEntropyComparison_ ? &entropyComparison_ : nullptr,
                entropyThresholdSpin_ ? entropyThresholdSpin_->value() : 1.5));
    }
    updateEnabled();
}

void MainWindow::updateEntropyPresentation() {
    entropyHeatmap_->setBlocks(haveEntropyPrimary_ ? &entropyPrimary_.blocks : nullptr,
                               haveEntropyPrimary_ ? entropyPrimary_.blockSize : xrl::kDefaultEntropyBlockSize);
    entropyHeatmap_->setComparisonBlocks(haveEntropyComparison_ ? &entropyComparison_.blocks : nullptr);
    entropyHeatmap_->setVariationThreshold(entropyThresholdSpin_->value());
    if (!haveEntropyPrimary_) {
        entropyDetails_->clear();
        return;
    }

    auto formatted = [](const std::optional<double>& value) {
        return value ? QString::number(*value, 'f', 4) + QStringLiteral(" bits/byte") : QStringLiteral("n/a");
    };
    QStringList lines;
    lines << tr("File: %1").arg(entropyPathA_);
    lines << tr("Size: %1    SHA-256: %2").arg(q(xrl::humanSize(entropyPrimary_.fileSize)),
                                                q(entropyPrimary_.sha256));
    lines << tr("Block size: %1 bytes    Analyzed blocks: %2")
                 .arg(entropyPrimary_.blockSize).arg(entropyPrimary_.blocks.size());
    lines << tr("Overall entropy: %1    Min block: %2    Max block: %3    Average block: %4")
                 .arg(formatted(entropyPrimary_.overallEntropy), formatted(entropyPrimary_.minBlockEntropy),
                      formatted(entropyPrimary_.maxBlockEntropy), formatted(entropyPrimary_.averageBlockEntropy));

    auto showRegions = [&](bool highest, const QString& heading) {
        std::vector<const xrl::EntropyBlock*> selected;
        constexpr size_t count = 5;
        for (const auto& block : entropyPrimary_.blocks) {
            auto position = selected.begin();
            while (position != selected.end() &&
                   (highest ? (*position)->entropy >= block.entropy : (*position)->entropy <= block.entropy)) {
                ++position;
            }
            selected.insert(position, &block);
            if (selected.size() > count) selected.pop_back();
        }
        lines << heading;
        if (selected.empty()) {
            lines << tr("  n/a (the file contains no bytes)");
            return;
        }
        for (const auto* block : selected) {
            lines << tr("  %1  %2 bytes  %3 bits/byte")
                         .arg(hex64(block->offset), QString::number(block->size),
                              QString::number(block->entropy, 'f', 4));
        }
    };
    showRegions(true, tr("Highest-entropy regions:"));
    showRegions(false, tr("Lowest-entropy regions:"));

    if (haveEntropyComparison_) {
        const size_t matched = std::min(entropyPrimary_.blocks.size(), entropyComparison_.blocks.size());
        double deltaSum = 0.0;
        size_t unusualCount = 0;
        const double threshold = entropyThresholdSpin_->value();
        for (size_t i = 0; i < matched; ++i) {
            const double delta = std::abs(entropyPrimary_.blocks[i].entropy - entropyComparison_.blocks[i].entropy);
            deltaSum += delta;
            if (threshold > 0.0 && delta >= threshold) ++unusualCount;
        }
        lines << tr("Comparison: %1").arg(entropyPathB_);
        if (matched == 0) lines << tr("  No aligned blocks to compare.");
        else lines << tr("  %1 aligned blocks; mean absolute entropy difference %2 bits/byte; %3 above threshold %4.")
                          .arg(matched)
                          .arg(deltaSum / static_cast<double>(matched), 0, 'f', 4)
                          .arg(unusualCount)
                          .arg(threshold, 0, 'f', 2);
        if (entropyPrimary_.blocks.size() != entropyComparison_.blocks.size())
            lines << tr("  Unmatched trailing blocks are excluded.");
    }
    lines << tr("Entropy describes byte-value distribution only; it does not classify files as malicious.");
    entropyDetails_->setPlainText(lines.join(QLatin1Char('\n')));
}

bool MainWindow::exportEntropy(bool blocksOnly) {
    if (!haveEntropyPrimary_) return false;
    QSettings settings;
    const QString base = QFileInfo(entropyPathA_).completeBaseName();
    const QString suffix = blocksOnly ? QStringLiteral(".entropy.csv") : QStringLiteral(".entropy.json");
    const QString initial = QDir(settings.value("ui/lastExportDir", QDir::homePath()).toString()).filePath(base + suffix);
    const QString path = QFileDialog::getSaveFileName(this,
        blocksOnly ? tr("Export block-level entropy data") : tr("Export entropy analysis report"),
        initial, blocksOnly ? tr("CSV (*.csv)") : tr("JSON (*.json)"));
    if (path.isEmpty()) return false;
    settings.setValue("ui/lastExportDir", QFileInfo(path).absolutePath());

    const std::string content = blocksOnly
                                    ? xrl::renderEntropyCsv(entropyPrimary_)
                                    : xrl::renderEntropyJsonReport(
                                          entropyPrimary_, haveEntropyComparison_ ? &entropyComparison_ : nullptr,
                                          entropyThresholdSpin_->value());
    std::ofstream output(toPath(path), std::ios::binary | std::ios::trunc);
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    output.flush();
    if (!output) {
        showStatus(tr("Failed to write entropy export to %1").arg(path), true);
        return false;
    }
    showStatus(tr("Entropy data exported to %1").arg(path));
    return true;
}

// ============================================================================ strings
void MainWindow::runStringsExtraction() {
    if (stringsWatcher_.isRunning()) return;
    if (!haveResult_ || current_.info.filePath.empty()) {
        showStatus(tr("Open a file before extracting strings."), true);
        return;
    }

    const auto path = toPath(q(current_.info.filePath));
    xrl::StringExtractionOptions options;
    options.minLength = static_cast<size_t>(stringsMinLengthSpin_->value());
    stringsCancel_ = std::make_shared<std::atomic_bool>(false);
    const auto cancel = stringsCancel_;
    stringsResult_ = {};
    haveStrings_ = false;
    stringsTable_->clear(tr("Scanning the current file..."));
    stringsStatusLabel_->setText(tr("Extracting ASCII, UTF-8, and UTF-16 strings..."));
    stringsProgress_->setValue(0);
    stringsProgress_->show();
    updateEnabled();
    stringsWatcher_.setFuture(QtConcurrent::run([this, path, options, cancel] {
        return xrl::extractStringsFile(path, options,
            [this](int percent, const std::string& stage) {
                QMetaObject::invokeMethod(this, [this, percent, text = q(stage)] {
                    onStringsProgress(percent, text);
                }, Qt::QueuedConnection);
            },
            [cancel] { return cancel->load(); });
    }));
    updateEnabled();
}

void MainWindow::onStringsProgress(int percent, const QString& stage) {
    if (!stringsWatcher_.isRunning()) return;
    stringsProgress_->setValue(percent);
    stringsStatusLabel_->setText(stage + QStringLiteral("..."));
}

void MainWindow::onStringsFinished() {
    stringsResult_ = stringsWatcher_.result();
    stringsProgress_->hide();
    haveStrings_ = stringsResult_.ok;
    if (haveStrings_) {
        QString note = tr("Pattern-based classifications are suggestions only; a matching string does not prove that the program uses it.");
        if (stringsResult_.truncated)
            note += QStringLiteral(" ") + q(stringsResult_.warning);
        stringsTable_->setStrings(&stringsResult_.strings, note);
        stringsStatusLabel_->setText(stringsResult_.truncated
                                         ? tr("String extraction completed with configured output limits applied.")
                                         : tr("Extracted %1 strings from %2 bytes.")
                                               .arg(stringsResult_.strings.size()).arg(stringsResult_.fileSize));
        showStatus(stringsStatusLabel_->text());
        recordWorkspaceAnalysis(
            tr("Strings"), q(stringsResult_.filePath), q(stringsResult_.sha256),
            tr("%1 strings extracted").arg(stringsResult_.strings.size()),
            xrl::renderStringsJsonReport(stringsResult_));
    } else {
        stringsTable_->clear(stringsResult_.cancelled
                                 ? tr("Extraction cancelled; partial results were discarded.")
                                 : tr("String extraction failed."));
        stringsStatusLabel_->setText(stringsResult_.cancelled ? tr("String extraction cancelled.")
                                                               : q(stringsResult_.error));
        if (!stringsResult_.cancelled) showStatus(q(stringsResult_.error), true);
    }
    updateEnabled();
}

bool MainWindow::exportStrings(bool json) {
    if (!haveStrings_) return false;
    QSettings settings;
    const QString base = QFileInfo(q(stringsResult_.filePath)).completeBaseName();
    const QString suffix = json ? QStringLiteral(".strings.json") : QStringLiteral(".strings.csv");
    const QString initial = QDir(settings.value("ui/lastExportDir", QDir::homePath()).toString()).filePath(base + suffix);
    const QString path = QFileDialog::getSaveFileName(this,
        json ? tr("Export string analysis as JSON") : tr("Export extracted strings as CSV"),
        initial, json ? tr("JSON (*.json)") : tr("CSV (*.csv)"));
    if (path.isEmpty()) return false;
    settings.setValue("ui/lastExportDir", QFileInfo(path).absolutePath());
    const std::string content = json ? xrl::renderStringsJsonReport(stringsResult_)
                                     : xrl::renderStringsCsv(stringsResult_);
    std::ofstream output(toPath(path), std::ios::binary | std::ios::trunc);
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    output.flush();
    if (!output) {
        showStatus(tr("Failed to write string export to %1").arg(path), true);
        return false;
    }
    showStatus(tr("String data exported to %1").arg(path));
    return true;
}

// ============================================================================ reports
QString MainWindow::buildReportText() {
    xrl::ReportInputs in;
    in.info = &current_.info;
    in.disassembly = (haveDisasm_ && reportIncludeDisasm_->isChecked()) ? &disasm_ : nullptr;
    in.ghidra = (haveGhidra_ && reportIncludeGhidra_->isChecked()) ? &ghidra_ : nullptr;
    return q(xrl::renderTextReport(in));
}

void MainWindow::refreshReportPreview() {
    if (!haveResult_) {
        reportPreview_->setPlainText(tr("No file loaded. Open a file to generate a report."));
        return;
    }
    reportPreview_->setPlainText(buildReportText());
}

bool MainWindow::exportReport(bool json) {
    if (!haveResult_) return false;
    xrl::ReportInputs in;
    in.info = &current_.info;
    in.disassembly = (haveDisasm_ && reportIncludeDisasm_->isChecked()) ? &disasm_ : nullptr;
    in.ghidra = (haveGhidra_ && reportIncludeGhidra_->isChecked()) ? &ghidra_ : nullptr;

    QSettings s;
    const QString base = QFileInfo(q(current_.info.fileName)).completeBaseName();
    const QString def = QDir(s.value("ui/lastExportDir", QDir::homePath()).toString()).filePath(base + (json ? ".xrl.json" : ".xrl.txt"));
    const QString path = QFileDialog::getSaveFileName(this, json ? tr("Export JSON report") : tr("Export text report"), def,
                                                      json ? tr("JSON (*.json)") : tr("Text (*.txt)"));
    if (path.isEmpty()) return false;
    s.setValue("ui/lastExportDir", QFileInfo(path).absolutePath());

    const std::string content = json ? xrl::renderJsonReport(in) : xrl::renderTextReport(in);
    std::ofstream out(toPath(path), std::ios::binary | std::ios::trunc);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    out.flush();
    if (!out) {
        showStatus(tr("Failed to write report to %1").arg(path), true);
        return false;
    }
    showStatus(tr("Report exported to %1").arg(path));
    return true;
}

// ============================================================================ settings
void MainWindow::browseGhidra() {
    const QString dir = QFileDialog::getExistingDirectory(this, tr("Select Ghidra installation directory"), ghidraPathEdit_->text());
    if (dir.isEmpty()) return;
    ghidraPathEdit_->setText(dir);
    applyGhidraPath();
}

void MainWindow::detectGhidraInstall() {
    const auto found = xrl::detectGhidra();
    if (found.empty()) {
        ghidraPathStatus_->setText(tr("No Ghidra installation was found in the usual locations (GHIDRA_INSTALL_DIR, /Applications, "
                                      "Homebrew, C:\\, home directory). Use Browse to select it manually."));
        return;
    }
    QString chosen = q(found[0].root);
    if (found.size() > 1) {
        QStringList items;
        for (const auto& g : found) items << q(g.root);
        bool ok = false;
        chosen = QInputDialog::getItem(this, tr("Multiple installations found"), tr("Select a Ghidra installation:"), items, 0, false, &ok);
        if (!ok) return;
    }
    ghidraPathEdit_->setText(chosen);
    applyGhidraPath();
}

void MainWindow::applyGhidraPath() {
    QSettings().setValue("ghidra/path", ghidraPathEdit_->text().trimmed());
    refreshGhidraStatus();
}

// ============================================================================ events
void MainWindow::dragEnterEvent(QDragEnterEvent* e) {
    if (e->mimeData()->hasUrls() && e->mimeData()->urls().size() == 1 && e->mimeData()->urls().first().isLocalFile())
        e->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent* e) {
    if (!e->mimeData()->hasUrls() || e->mimeData()->urls().isEmpty()) return;
    loadFile(e->mimeData()->urls().first().toLocalFile());
}

void MainWindow::closeEvent(QCloseEvent* e) {
    QSettings().setValue("window/geometry", saveGeometry());
    if (!saveWorkspaceSession()) {
        e->ignore();
        return;
    }
    if (entropyCancel_) entropyCancel_->store(true);
    if (stringsCancel_) stringsCancel_->store(true);
    if (staticCancel_) staticCancel_->store(true);
    if (xrefCancel_) xrefCancel_->store(true);
    if (ghidraRunner_->isRunning()) ghidraRunner_->cancel();
    QMainWindow::closeEvent(e);
}

}  // namespace xrl::ui
