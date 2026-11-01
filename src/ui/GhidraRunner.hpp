#pragma once
#include <QObject>
#include <QProcess>
#include <QTemporaryDir>
#include <filesystem>
#include <memory>

#include "xrl/ghidra.hpp"

namespace xrl::ui {

// Runs Ghidra's analyzeHeadless as a child process, only when start() is called by the user.
// Ghidra imports and analyses the file statically; the analysed binary is never executed by us.
class GhidraRunner : public QObject {
    Q_OBJECT
public:
    explicit GhidraRunner(QObject* parent = nullptr);
    ~GhidraRunner() override;

    bool isRunning() const { return proc_ && proc_->state() != QProcess::NotRunning; }
    bool start(const xrl::GhidraInstall& install, const QString& binaryPath, const xrl::GhidraOptions& opts,
               const std::filesystem::path& scriptDir, QString* errorOut);
    void cancel();

signals:
    void logText(const QString& text);
    void finished(const xrl::GhidraResult& result);

private:
    void onFinished(int exitCode, QProcess::ExitStatus status);
    QProcess* proc_ = nullptr;
    std::unique_ptr<QTemporaryDir> tmp_;
    xrl::GhidraCommand cmd_;
    bool cancelled_ = false;
    bool startFailed_ = false;
    QString tail_;
};

}  // namespace xrl::ui

