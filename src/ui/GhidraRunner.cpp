#include "GhidraRunner.hpp"

#include <QFile>
#include <QTimer>

#include "UiUtil.hpp"

namespace xrl::ui {

GhidraRunner::GhidraRunner(QObject* parent) : QObject(parent) {}

GhidraRunner::~GhidraRunner() {
    if (proc_) {
        proc_->disconnect(this);
        if (proc_->state() != QProcess::NotRunning) {
            proc_->kill();
            proc_->waitForFinished(2000);
        }
    }
}

bool GhidraRunner::start(const xrl::GhidraInstall& install, const QString& binaryPath, const xrl::GhidraOptions& opts,
                         const std::filesystem::path& scriptDir, QString* errorOut) {
    auto fail = [&](const QString& m) {
        if (errorOut) *errorOut = m;
        return false;
    };
    if (isRunning()) return fail(tr("A Ghidra analysis is already running."));
    if (!install.valid) return fail(tr("Ghidra installation is not configured or invalid."));
    if (scriptDir.empty()) return fail(tr("The helper script XrlExport.java could not be located next to the application."));

    tmp_ = std::make_unique<QTemporaryDir>();
    if (!tmp_->isValid()) return fail(tr("Could not create a temporary working directory."));

    cmd_ = xrl::buildGhidraCommand(install, toPath(binaryPath), toPath(tmp_->path()), scriptDir, opts);
    cancelled_ = false;
    startFailed_ = false;
    tail_.clear();

    delete proc_;
    proc_ = new QProcess(this);
    proc_->setProcessChannelMode(QProcess::MergedChannels);
    connect(proc_, &QProcess::readyRead, this, [this] {
        const QString text = QString::fromLocal8Bit(proc_->readAll());
        tail_ += text;
        if (tail_.size() > 200'000) tail_.remove(0, tail_.size() - 200'000);
        emit logText(text);
    });
    connect(proc_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError e) {
        if (e != QProcess::FailedToStart) return;
        startFailed_ = true;
        xrl::GhidraResult r;
        r.error = tr("Could not start Ghidra (%1).").arg(proc_->errorString()).toStdString();
        emit finished(r);
    });
    connect(proc_, &QProcess::finished, this, &GhidraRunner::onFinished);

    QStringList args;
    for (const auto& a : cmd_.args) args << q(a);
    emit logText(tr("> %1 %2\n").arg(q(cmd_.program), args.join(' ')));
    proc_->start(q(cmd_.program), args);

    // Safety net: Ghidra has its own per-file timeout; this kills a hung process afterwards.
    QTimer::singleShot((opts.analysisTimeoutSeconds + 600) * 1000, proc_, [p = proc_] {
        if (p->state() != QProcess::NotRunning) p->kill();
    });
    return true;
}

void GhidraRunner::cancel() {
    if (!isRunning()) return;
    cancelled_ = true;
    proc_->kill();
}

void GhidraRunner::onFinished(int exitCode, QProcess::ExitStatus status) {
    if (startFailed_) return;
    xrl::GhidraResult r;
    if (cancelled_) {
        r.error = tr("Cancelled by user.").toStdString();
    } else {
        QFile f(q(cmd_.outputJson));
        if (!f.exists() || !f.open(QIODevice::ReadOnly)) {
            r.error = tr("Ghidra finished (exit code %1%2) without writing the export file. See the log for details; "
                         "Ghidra needs a compatible JDK and may not support this file type.")
                          .arg(exitCode)
                          .arg(status == QProcess::CrashExit ? tr(", crashed") : QString())
                          .toStdString();
        } else {
            r = xrl::parseGhidraOutput(f.readAll().toStdString());
        }
    }
    r.log = tail_.toStdString();
    emit finished(r);
}

}  // namespace xrl::ui

