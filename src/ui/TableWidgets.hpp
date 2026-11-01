#pragma once
// Small reusable table widgets: a string-backed model and a filterable table page.
#include <QAbstractTableModel>
#include <QFontDatabase>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QSet>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>

namespace xrl::ui {

class StringTableModel : public QAbstractTableModel {
public:
    using QAbstractTableModel::QAbstractTableModel;

    void reset(QStringList headers, QVector<QStringList> rows, QSet<int> monoColumns = {}) {
        beginResetModel();
        headers_ = std::move(headers);
        rows_ = std::move(rows);
        mono_ = std::move(monoColumns);
        endResetModel();
    }
    int rowCount(const QModelIndex& p = {}) const override { return p.isValid() ? 0 : static_cast<int>(rows_.size()); }
    int columnCount(const QModelIndex& p = {}) const override { return p.isValid() ? 0 : static_cast<int>(headers_.size()); }
    QVariant data(const QModelIndex& i, int role) const override {
        if (!i.isValid() || i.row() >= rows_.size()) return {};
        const auto& row = rows_[i.row()];
        if (role == Qt::DisplayRole || role == Qt::ToolTipRole)
            return i.column() < row.size() ? QVariant(row[i.column()]) : QVariant();
        if (role == Qt::FontRole && mono_.contains(i.column())) return QFontDatabase::systemFont(QFontDatabase::FixedFont);
        return {};
    }
    QVariant headerData(int s, Qt::Orientation o, int role) const override {
        if (o == Qt::Horizontal && role == Qt::DisplayRole && s < headers_.size()) return headers_[s];
        return {};
    }
    const QStringList& rowAt(int r) const { return rows_[r]; }

private:
    QStringList headers_;
    QVector<QStringList> rows_;
    QSet<int> mono_;
};

// Table with a note line (availability explanation) and a substring filter over all columns.
class FilterTable : public QWidget {
public:
    explicit FilterTable(QWidget* parent = nullptr) : QWidget(parent) {
        auto* lay = new QVBoxLayout(this);
        lay->setContentsMargins(12, 12, 12, 12);
        note_ = new QLabel;
        note_->setWordWrap(true);
        note_->setProperty("muted", true);
        filter_ = new QLineEdit;
        filter_->setPlaceholderText(tr("Filter rows..."));
        filter_->setClearButtonEnabled(true);
        count_ = new QLabel;
        count_->setProperty("muted", true);
        auto* top = new QHBoxLayout;
        top->addWidget(filter_, 1);
        top->addWidget(count_);
        view_ = new QTableView;
        view_->setAlternatingRowColors(true);
        view_->setSelectionBehavior(QAbstractItemView::SelectRows);
        view_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        view_->setShowGrid(false);
        view_->verticalHeader()->setVisible(false);
        view_->verticalHeader()->setDefaultSectionSize(24);
        view_->horizontalHeader()->setStretchLastSection(true);
        view_->horizontalHeader()->setHighlightSections(false);
        view_->horizontalHeader()->setResizeContentsPrecision(100);
        view_->setWordWrap(false);
        model_ = new StringTableModel(this);
        proxy_ = new QSortFilterProxyModel(this);
        proxy_->setSourceModel(model_);
        proxy_->setFilterKeyColumn(-1);
        proxy_->setFilterCaseSensitivity(Qt::CaseInsensitive);
        view_->setModel(proxy_);
        filterTimer_ = new QTimer(this);
        filterTimer_->setSingleShot(true);
        filterTimer_->setInterval(120);
        lay->addWidget(note_);
        lay->addLayout(top);
        lay->addWidget(view_, 1);
        connect(filterTimer_, &QTimer::timeout, this, [this] {
            proxy_->setFilterFixedString(filter_->text());
            updateCount();
        });
        connect(filter_, &QLineEdit::textChanged, filterTimer_,
                qOverload<>(&QTimer::start));
    }

    void setContent(const QStringList& headers, QVector<QStringList> rows, const QString& note,
                    QSet<int> monoColumns = {}) {
        model_->reset(headers, std::move(rows), std::move(monoColumns));
        note_->setText(note);
        note_->setVisible(!note.isEmpty());
        for (int c = 0; c < headers.size() - 1; ++c) view_->resizeColumnToContents(c);
        for (int c = 0; c < headers.size() - 1; ++c)
            if (view_->columnWidth(c) > 420) view_->setColumnWidth(c, 420);
        updateCount();
    }
    void clear(const QString& note) { setContent({}, {}, note); }
    QTableView* view() const { return view_; }
    StringTableModel* model() const { return model_; }
    QSortFilterProxyModel* proxy() const { return proxy_; }
    QLineEdit* filterEdit() const { return filter_; }

private:
    void updateCount() {
        count_->setText(proxy_->rowCount() == model_->rowCount()
                            ? tr("%1 rows").arg(model_->rowCount())
                            : tr("%1 of %2 rows").arg(proxy_->rowCount()).arg(model_->rowCount()));
    }
    QLabel* note_;
    QLineEdit* filter_;
    QLabel* count_;
    QTableView* view_;
    StringTableModel* model_;
    QSortFilterProxyModel* proxy_;
    QTimer* filterTimer_;
};

}  // namespace xrl::ui
