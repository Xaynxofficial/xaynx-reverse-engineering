#pragma once
#include <QFutureWatcher>
#include <QMainWindow>
#include <atomic>
#include <memory>

#include "xrl/analyzer.hpp"
#include "xrl/cfg.hpp"
#include "xrl/diff.hpp"
#include "xrl/disassembler.hpp"
#include "xrl/entropy.hpp"
#include "xrl/ghidra.hpp"
#include "xrl/strings.hpp"
#include "xrl/static_analysis.hpp"
#include "xrl/xref.hpp"
#include "xrl/workspace.hpp"

class QCheckBox;
class QComboBox;
class QDoubleSpinBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QModelIndex;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QSpinBox;
class QStackedWidget;
class QTabWidget;
class QTableView;
class QTimer;

namespace xrl::ui {

class FilterTable;
class HexView;
class EntropyHeatmap;
class CfgGraphView;
class XrefGraphView;
class StringsTable;
class StringTableModel;
class GhidraRunner;
class WorkspaceWidget;

struct EntropyJobResult {
    xrl::EntropyAnalysisResult primary;
    xrl::EntropyAnalysisResult comparison;
    bool hasComparison = false;
};

struct StaticJobResult {
    xrl::StaticAnalysisResult analysis;
    xrl::StringExtractionResult strings;
    xrl::EntropyAnalysisResult entropy;
    bool hasStrings = false;
    bool hasEntropy = false;
    QStringList warnings;
};

struct XrefJobResult {
    xrl::XrefResult xref;
    xrl::StringExtractionResult strings;
    bool hasStrings = false;
};

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow();
    ~MainWindow() override;

    // Reads and analyses `path` in a background thread. The file is never executed.
    void loadFile(const QString& path);

protected:
    void dragEnterEvent(QDragEnterEvent*) override;
    void dropEvent(QDropEvent*) override;
    void closeEvent(QCloseEvent*) override;

private:
    enum Page {
        PageOverview,
        PageAnalysis,
        PageStaticAnalysis,
        PageXref,
        PageHex,
        PageStrings,
        PageDisasm,
        PageCfg,
        PageDiff,
        PageEntropy,
        PageReports,
        PageWorkspace,
        PageSettings,
        PageFunctions
    };

    // construction
    QWidget* buildOverviewPage();
    QWidget* buildAnalysisPage();
    QWidget* buildStaticAnalysisPage();
    QWidget* buildHexPage();
    QWidget* buildStringsPage();
    QWidget* buildDisasmPage();
    QWidget* buildCfgPage();
    QWidget* buildGhidraTab();
    QWidget* buildDiffPage();
    QWidget* buildEntropyPage();
    QWidget* buildReportsPage();
    QWidget* buildWorkspacePage();
    QWidget* buildFunctionExplorerPage();
    QWidget* buildSettingsPage();
    void buildMenus();

    // state + presentation
    void openFileDialog();
    void onProgress(int percent, const QString& stage);
    void onAnalysisFinished();
    void populateAll();
    void populateOverview();
    void populateAnalysis();
    void runStaticAnalysis();
    void onStaticAnalysisFinished();
    void onStaticProgress(int percent, const QString& stage);
    void updateStaticFindings();
    void selectStaticFinding(const QModelIndex& current);
    void openStaticFinding();
    bool exportStaticReport(bool html);
    QWidget* buildXrefPage();
    void runXrefAnalysis();
    void onXrefAnalysisFinished();
    void onXrefProgress(int percent, const QString& stage);
    void updateXrefReferences();
    void updateXrefCandidates();
    void selectXrefReference(const QModelIndex& current);
    void navigateXrefDisassembly();
    void navigateXrefHex();
    void navigateXrefCfg();
    void navigateXrefString();
    bool exportXref(int format);
    void updateEnabled();
    void setBusy(bool busy, const QString& message = {});
    void showStatus(const QString& message, bool isError = false);
    bool persistWorkspace(const xrl::WorkspaceData& data, bool recover, QString* error);
    void openWorkspaceFile(const QString& path, const QString& expectedHash, quint64 offset,
                           const QString& locationKind);
    void updateWorkspaceLoadedFile();
    void addLoadedFileToWorkspace();
    void recordWorkspaceAnalysis(const QString& type, const QString& filePath,
                                 const QString& fileHash, const QString& summary,
                                 const std::string& reportJson);
    void recordWorkspaceComparison();
    bool saveWorkspaceSession();

    // hex
    void goToHexOffset();
    void onHexSelection(quint64 off);
    void showInHex(quint64 offset);
    void showStringInHex(quint64 offset, quint64 length);

    // disassembly
    void populateStartPoints();
    void updateFunctionExplorer();
    std::optional<uint64_t> selectedExplorerFunction() const;
    void openExplorerFunctionCfg();
    void openExplorerFunctionDisassembly();
    void runDisassembly();
    void runCfgAnalysis();
    void onCfgAnalysisFinished();
    void onCfgProgress(int percent, const QString& stage);
    void onCfgBlockSelected(quint64 address);
    void onCfgInstructionSelected(const QModelIndex& current);
    void findCfgBlock();
    bool exportCfg(bool dot);
    void showCfgBlockInHex(quint64 address);

    // diff & comparison
    void selectDiffFileA();
    void selectDiffFileB();
    void useCurrentAsBaseline();
    void runDiff();
    void onDiffFinished();
    void jumpToDiff(int index);
    void nextDiff();
    void prevDiff();
    bool exportDiffReport(bool json);
    void populateDiffResults();

    // entropy
    void chooseEntropyFile(bool comparison);
    void runEntropyAnalysis();
    void onEntropyFinished();
    void updateEntropyPresentation();
    bool exportEntropy(bool blocksOnly);

    // strings
    void runStringsExtraction();
    void onStringsFinished();
    void onStringsProgress(int percent, const QString& stage);
    bool exportStrings(bool json);

    // ghidra
    xrl::GhidraInstall currentGhidra(QString* error = nullptr) const;
    void runGhidra();
    void onGhidraFinished(const xrl::GhidraResult& r);
    void showGhidraFunction();
    void refreshGhidraStatus();

    // reports
    void refreshReportPreview();
    bool exportReport(bool json);
    QString buildReportText();

    // settings
    void browseGhidra();
    void detectGhidraInstall();
    void applyGhidraPath();
    xrl::Limits currentLimits() const;

    // data
    xrl::AnalysisResult current_;
    bool haveResult_ = false;
    xrl::DisasmResult disasm_;
    bool haveDisasm_ = false;
    xrl::GhidraResult ghidra_;
    bool haveGhidra_ = false;
    std::vector<xrl::StartPoint> startPoints_;
    QFutureWatcher<xrl::AnalysisResult> watcher_;
    bool busy_ = false;
    xrl::StaticAnalysisResult staticAnalysis_;
    bool haveStaticAnalysis_ = false;
    std::shared_ptr<std::atomic_bool> staticCancel_;
    QString staticAnalysisPath_;
    QFutureWatcher<StaticJobResult> staticWatcher_;
    xrl::XrefResult xrefResult_;
    bool haveXref_ = false;
    std::shared_ptr<std::atomic_bool> xrefCancel_;
    QString xrefAnalysisPath_;
    QFutureWatcher<XrefJobResult> xrefWatcher_;
    xrl::ControlFlowGraph cfgResult_;
    bool haveCfg_ = false;
    bool syncingCfgDisasm_ = false;
    std::vector<xrl::FunctionCandidate> cfgCandidates_;
    std::shared_ptr<std::atomic_bool> cfgCancel_;
    QString cfgAnalysisPath_;
    QFutureWatcher<xrl::ControlFlowGraph> cfgWatcher_;

    xrl::EntropyAnalysisResult entropyPrimary_;
    xrl::EntropyAnalysisResult entropyComparison_;
    bool haveEntropyPrimary_ = false;
    bool haveEntropyComparison_ = false;
    std::shared_ptr<std::atomic_bool> entropyCancel_;
    QFutureWatcher<EntropyJobResult> entropyWatcher_;
    QString entropyPathA_, entropyPathB_;
    xrl::StringExtractionResult stringsResult_;
    bool haveStrings_ = false;
    std::shared_ptr<std::atomic_bool> stringsCancel_;
    QFutureWatcher<xrl::StringExtractionResult> stringsWatcher_;

    xrl::WorkspaceData workspace_;
    QString workspacePath_;
    QString workspaceLoadError_;
    QString pendingWorkspaceFileId_;
    QString pendingWorkspaceHash_;
    quint64 pendingWorkspaceOffset_ = 0;
    QString pendingWorkspaceLocationKind_;
    bool workspaceAddAfterLoad_ = false;

    // diff data
    QString diffPathA_, diffPathB_;
    std::shared_ptr<const std::vector<uint8_t>> diffDataA_, diffDataB_;
    xrl::BinaryDiffResult diffResult_;
    bool haveDiff_ = false;
    int currentDiffIndex_ = -1;
    QFutureWatcher<xrl::BinaryDiffResult> diffWatcher_;

    // widgets
    QListWidget* sidebar_ = nullptr;
    QStackedWidget* stack_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QProgressBar* progress_ = nullptr;
    WorkspaceWidget* workspaceWidget_ = nullptr;
    QTabWidget* functionExplorerTabs_ = nullptr;
    FilterTable* functionExplorerTable_ = nullptr;
    FilterTable* relocationExplorerTable_ = nullptr;
    FilterTable* debugInfoTable_ = nullptr;
    QPushButton* functionCfgButton_ = nullptr;
    QPushButton* functionDisasmButton_ = nullptr;
    QPushButton* functionHexButton_ = nullptr;

    QLabel* filePathLabel_ = nullptr;
    QLabel* dropHint_ = nullptr;
    QPushButton* openButton_ = nullptr;
    QPushButton* copyHashButton_ = nullptr;
    QTableView* metaView_ = nullptr;
    StringTableModel* metaModel_ = nullptr;
    QPlainTextEdit* summary_ = nullptr;

    QTabWidget* analysisTabs_ = nullptr;
    FilterTable *sectionsTable_ = nullptr, *importsTable_ = nullptr, *exportsTable_ = nullptr,
                *librariesTable_ = nullptr, *symbolsTable_ = nullptr, *findingsTable_ = nullptr;
    QComboBox* staticSeverityFilter_ = nullptr;
    QComboBox* staticCategoryFilter_ = nullptr;
    QPushButton* staticRunButton_ = nullptr;
    QPushButton* staticCancelButton_ = nullptr;
    QPushButton* staticExportJsonButton_ = nullptr;
    QPushButton* staticExportHtmlButton_ = nullptr;
    QPushButton* staticOpenEvidenceButton_ = nullptr;
    QProgressBar* staticProgress_ = nullptr;
    QLabel* staticStatusLabel_ = nullptr;
    QLabel* staticSummaryLabel_ = nullptr;
    FilterTable* staticFindingsTable_ = nullptr;
    QPlainTextEdit* staticDetails_ = nullptr;
    QString staticSelectedFindingId_;

    QPushButton* xrefRunButton_ = nullptr;
    QPushButton* xrefCancelButton_ = nullptr;
    QPushButton* xrefExportJsonButton_ = nullptr;
    QPushButton* xrefExportCsvButton_ = nullptr;
    QPushButton* xrefExportDotButton_ = nullptr;
    QPushButton* xrefDisasmButton_ = nullptr;
    QPushButton* xrefHexButton_ = nullptr;
    QPushButton* xrefCfgButton_ = nullptr;
    QPushButton* xrefStringButton_ = nullptr;
    QComboBox* xrefTypeFilter_ = nullptr;
    QComboBox* xrefDirectionFilter_ = nullptr;
    QLineEdit* xrefSearchEdit_ = nullptr;
    QTimer* xrefSearchTimer_ = nullptr;
    QProgressBar* xrefProgress_ = nullptr;
    QLabel* xrefStatusLabel_ = nullptr;
    QLabel* xrefSummaryLabel_ = nullptr;
    FilterTable* xrefReferencesTable_ = nullptr;
    QPlainTextEdit* xrefDetails_ = nullptr;
    XrefGraphView* xrefGraphView_ = nullptr;
    QTabWidget* xrefResultTabs_ = nullptr;
    FilterTable* xrefCandidatesTable_ = nullptr;
    QString xrefSelectedReferenceId_;

    HexView* hex_ = nullptr;
    QLineEdit* hexOffsetEdit_ = nullptr;
    QPushButton* hexGoButton_ = nullptr;
    QLabel* hexInfo_ = nullptr;

    QTabWidget* disasmTabs_ = nullptr;
    QComboBox* startCombo_ = nullptr;
    QComboBox* startModeCombo_ = nullptr;
    QLineEdit* startEdit_ = nullptr;
    QSpinBox* countSpin_ = nullptr;
    QPushButton* disasmButton_ = nullptr;
    QLabel* disasmInfo_ = nullptr;
    FilterTable* disasmTable_ = nullptr;

    QComboBox* cfgFunctionCombo_ = nullptr;
    QComboBox* cfgAddressModeCombo_ = nullptr;
    QLineEdit* cfgAddressEdit_ = nullptr;
    QLineEdit* cfgBlockSearchEdit_ = nullptr;
    QPushButton* cfgRunButton_ = nullptr;
    QPushButton* cfgCancelButton_ = nullptr;
    QPushButton* cfgFindBlockButton_ = nullptr;
    QPushButton* cfgFitButton_ = nullptr;
    QPushButton* cfgHexButton_ = nullptr;
    QPushButton* cfgExportJsonButton_ = nullptr;
    QPushButton* cfgExportDotButton_ = nullptr;
    QCheckBox* cfgConditionalCheck_ = nullptr;
    QCheckBox* cfgUnresolvedCheck_ = nullptr;
    QProgressBar* cfgProgress_ = nullptr;
    QLabel* cfgStatusLabel_ = nullptr;
    QPlainTextEdit* cfgDetails_ = nullptr;
    CfgGraphView* cfgGraphView_ = nullptr;

    // diff widgets
    QLabel* diffPathLabelA_ = nullptr;
    QLabel* diffInfoLabelA_ = nullptr;
    QLabel* diffPathLabelB_ = nullptr;
    QLabel* diffInfoLabelB_ = nullptr;
    QPushButton* diffBtnA_ = nullptr;
    QPushButton* diffBtnB_ = nullptr;
    QPushButton* diffUseCurrentBtn_ = nullptr;
    QPushButton* diffRunBtn_ = nullptr;
    QPushButton* diffExportJsonBtn_ = nullptr;
    QLabel* diffStatusLabel_ = nullptr;
    QProgressBar* diffProgress_ = nullptr;
    HexView* diffHexA_ = nullptr;
    HexView* diffHexB_ = nullptr;
    QPushButton* diffPrevBtn_ = nullptr;
    QPushButton* diffNextBtn_ = nullptr;
    QLabel* diffNavLabel_ = nullptr;
    FilterTable* diffMetaTable_ = nullptr;
    FilterTable* diffByteTable_ = nullptr;
    QPlainTextEdit* diffSummaryText_ = nullptr;

    QLineEdit* entropyPathAEdit_ = nullptr;
    QLineEdit* entropyPathBEdit_ = nullptr;
    QComboBox* entropyBlockSizeCombo_ = nullptr;
    QDoubleSpinBox* entropyThresholdSpin_ = nullptr;
    QPushButton* entropyRunBtn_ = nullptr;
    QPushButton* entropyCancelBtn_ = nullptr;
    QPushButton* entropyExportJsonBtn_ = nullptr;
    QPushButton* entropyExportCsvBtn_ = nullptr;
    QProgressBar* entropyProgress_ = nullptr;
    QLabel* entropyStatusLabel_ = nullptr;
    QPlainTextEdit* entropyDetails_ = nullptr;
    EntropyHeatmap* entropyHeatmap_ = nullptr;

    QLabel* stringsPathLabel_ = nullptr;
    QSpinBox* stringsMinLengthSpin_ = nullptr;
    QPushButton* stringsRunButton_ = nullptr;
    QPushButton* stringsCancelButton_ = nullptr;
    QPushButton* stringsExportCsvButton_ = nullptr;
    QPushButton* stringsExportJsonButton_ = nullptr;
    QProgressBar* stringsProgress_ = nullptr;
    QLabel* stringsStatusLabel_ = nullptr;
    StringsTable* stringsTable_ = nullptr;

    QLabel* ghidraStatus_ = nullptr;
    QCheckBox* ghidraDecompile_ = nullptr;
    QSpinBox* ghidraMaxDecomp_ = nullptr;
    QPushButton* ghidraRun_ = nullptr;
    QPushButton* ghidraCancel_ = nullptr;
    FilterTable* ghidraFunctions_ = nullptr;
    QPlainTextEdit* ghidraDecompiled_ = nullptr;
    QPlainTextEdit* ghidraLog_ = nullptr;
    GhidraRunner* ghidraRunner_ = nullptr;

    QPlainTextEdit* reportPreview_ = nullptr;
    QCheckBox* reportIncludeDisasm_ = nullptr;
    QCheckBox* reportIncludeGhidra_ = nullptr;
    QPushButton* exportJsonButton_ = nullptr;
    QPushButton* exportTextButton_ = nullptr;
    QAction *actExportJson_ = nullptr, *actExportText_ = nullptr;

    QLineEdit* ghidraPathEdit_ = nullptr;
    QLabel* ghidraPathStatus_ = nullptr;
    QSpinBox* maxFileSpin_ = nullptr;
};

}  // namespace xrl::ui
