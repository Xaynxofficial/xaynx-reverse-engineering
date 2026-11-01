#include "StringsTable.hpp"

#include <QAbstractTableModel>
#include <QCheckBox>
#include <QComboBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QItemSelectionModel>
#include <QSortFilterProxyModel>
#include <QSignalBlocker>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>
#include <algorithm>

namespace xrl::ui {
namespace {

class ExtractedStringsModel final : public QAbstractTableModel {
public:
    explicit ExtractedStringsModel(StringsTable* owner) : QAbstractTableModel(owner), owner_(owner) {}

    static QString categories(const xrl::ExtractedString& entry) {
        QStringList values;
        for (const auto category : entry.categories)
            values.push_back(QString::fromLatin1(xrl::toString(category)));
        return values.join(QStringLiteral(", "));
    }

    int rowCount(const QModelIndex& parent = {}) const override {
        if (parent.isValid() || !owner_->strings()) return 0;
        return static_cast<int>(owner_->strings()->size());
    }

    int columnCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : 5; }

    QVariant data(const QModelIndex& index, int role) const override {
        if (!index.isValid() || !owner_->strings() || index.row() < 0 ||
            static_cast<size_t>(index.row()) >= owner_->strings()->size()) return {};
        const auto& entry = (*owner_->strings())[static_cast<size_t>(index.row())];
        if (role == Qt::UserRole) {
            switch (index.column()) {
                case 0: return QString::fromUtf8(entry.value.data(), static_cast<qsizetype>(entry.value.size()));
                case 1: return QVariant::fromValue<qulonglong>(entry.offset);
                case 2: return QVariant::fromValue<qulonglong>(entry.length);
                case 3: return QString::fromLatin1(xrl::toString(entry.encoding));
                case 4: return categories(entry);
                default: return {};
            }
        }
        if (role != Qt::DisplayRole && role != Qt::ToolTipRole) return {};
        switch (index.column()) {
            case 0: return QString::fromUtf8(entry.value.data(), static_cast<qsizetype>(entry.value.size()));
            case 1: return QStringLiteral("0x%1").arg(entry.offset, 0, 16);
            case 2: return QString::number(entry.length);
            case 3: return QString::fromLatin1(xrl::toString(entry.encoding));
            case 4: return categories(entry);
            default: return {};
        }
    }

    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
        static const QStringList headers{tr("String"), tr("Offset"), tr("Length (bytes)"),
                                         tr("Encoding"), tr("Classification")};
        return section >= 0 && section < headers.size() ? QVariant(headers[section]) : QVariant();
    }

    void refresh() {
        beginResetModel();
        endResetModel();
    }

private:
    StringsTable* owner_;
};

class ExtractedStringsProxy final : public QSortFilterProxyModel {
public:
    explicit ExtractedStringsProxy(StringsTable* owner) : QSortFilterProxyModel(owner), owner_(owner) {
        setSortCaseSensitivity(Qt::CaseInsensitive);
        setDynamicSortFilter(true);
    }

    void setFilters(QString query, int categoryIndex, int encodingIndex, bool caseSensitive) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
        beginFilterChange();
#endif
        query_ = std::move(query);
        categoryIndex_ = categoryIndex;
        encodingIndex_ = encodingIndex;
        caseSensitive_ = caseSensitive;
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
        endFilterChange();
#else
        invalidateFilter();
#endif
    }

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex&) const override {
        if (!owner_->strings() || sourceRow < 0 ||
            static_cast<size_t>(sourceRow) >= owner_->strings()->size()) return false;
        const auto& entry = (*owner_->strings())[static_cast<size_t>(sourceRow)];
        if (encodingIndex_ > 0 && static_cast<int>(entry.encoding) != encodingIndex_ - 1) return false;
        if (categoryIndex_ > 0) {
            const auto wanted = static_cast<xrl::StringCategory>(categoryIndex_ - 1);
            if (std::find(entry.categories.begin(), entry.categories.end(), wanted) == entry.categories.end())
                return false;
        }
        if (query_.isEmpty()) return true;
        const auto value = QString::fromUtf8(entry.value.data(), static_cast<qsizetype>(entry.value.size()));
        const auto categoriesValue = ExtractedStringsModel::categories(entry);
        const auto sensitivity = caseSensitive_ ? Qt::CaseSensitive : Qt::CaseInsensitive;
        return value.contains(query_, sensitivity) || categoriesValue.contains(query_, sensitivity);
    }

    bool lessThan(const QModelIndex& left, const QModelIndex& right) const override {
        const QVariant a = sourceModel()->data(left, Qt::UserRole);
        const QVariant b = sourceModel()->data(right, Qt::UserRole);
        if (left.column() == 1 || left.column() == 2) return a.toULongLong() < b.toULongLong();
        return QString::localeAwareCompare(a.toString(), b.toString()) < 0;
    }

private:
    StringsTable* owner_;
    QString query_;
    int categoryIndex_ = 0;
    int encodingIndex_ = 0;
    bool caseSensitive_ = false;
};

}  // namespace

StringsTable::StringsTable(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(8);

    note_ = new QLabel;
    note_->setWordWrap(true);
    note_->setProperty("muted", true);
    layout->addWidget(note_);

    search_ = new QLineEdit;
    search_->setPlaceholderText(tr("Search extracted strings..."));
    search_->setClearButtonEnabled(true);
    category_ = new QComboBox;
    category_->addItem(tr("All categories"));
    for (int i = 0; i <= static_cast<int>(xrl::StringCategory::Other); ++i)
        category_->addItem(QString::fromLatin1(xrl::toString(static_cast<xrl::StringCategory>(i))));
    encoding_ = new QComboBox;
    encoding_->addItem(tr("All encodings"));
    for (int i = 0; i <= static_cast<int>(xrl::StringEncoding::Utf16BE); ++i)
        encoding_->addItem(QString::fromLatin1(xrl::toString(static_cast<xrl::StringEncoding>(i))));
    caseSensitive_ = new QCheckBox(tr("Match case"));
    caseSensitive_->setToolTip(tr("Searches extracted values and classifications. Regular expressions are not enabled."));
    count_ = new QLabel(tr("0 strings"));
    count_->setProperty("muted", true);
    auto* filters = new QHBoxLayout;
    filters->addWidget(search_, 1);
    filters->addWidget(category_);
    filters->addWidget(encoding_);
    filters->addWidget(caseSensitive_);
    filters->addWidget(count_);
    layout->addLayout(filters);

    view_ = new QTableView;
    view_->setAlternatingRowColors(true);
    view_->setSelectionBehavior(QAbstractItemView::SelectRows);
    view_->setSelectionMode(QAbstractItemView::SingleSelection);
    view_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    view_->setShowGrid(false);
    view_->setWordWrap(false);
    view_->verticalHeader()->setVisible(false);
    view_->verticalHeader()->setDefaultSectionSize(24);
    view_->horizontalHeader()->setStretchLastSection(true);
    view_->horizontalHeader()->setHighlightSections(false);
    view_->horizontalHeader()->setResizeContentsPrecision(100);
    auto* model = new ExtractedStringsModel(this);
    proxy_ = new ExtractedStringsProxy(this);
    proxy_->setSourceModel(model);
    view_->setModel(proxy_);
    view_->setSortingEnabled(true);
    view_->sortByColumn(1, Qt::AscendingOrder);
    layout->addWidget(view_, 1);

    filterTimer_ = new QTimer(this);
    filterTimer_->setSingleShot(true);
    filterTimer_->setInterval(120);
    auto updateFilters = [this] {
        static_cast<ExtractedStringsProxy*>(proxy_)->setFilters(
            search_->text(), category_->currentIndex(), encoding_->currentIndex(), caseSensitive_->isChecked());
        updateCount();
    };
    connect(filterTimer_, &QTimer::timeout, this, updateFilters);
    connect(search_, &QLineEdit::textChanged, filterTimer_, qOverload<>(&QTimer::start));
    connect(category_, qOverload<int>(&QComboBox::currentIndexChanged), this,
            [this](int) { filterTimer_->start(); });
    connect(encoding_, qOverload<int>(&QComboBox::currentIndexChanged), this,
            [this](int) { filterTimer_->start(); });
    connect(caseSensitive_, &QCheckBox::toggled, this,
            [this](bool) { filterTimer_->start(); });
    connect(view_->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this](const QModelIndex& current, const QModelIndex&) {
                if (!current.isValid() || !strings_) return;
                const QModelIndex source = proxy_->mapToSource(current);
                if (source.row() < 0 || static_cast<size_t>(source.row()) >= strings_->size()) return;
                const auto& entry = (*strings_)[static_cast<size_t>(source.row())];
                emit stringSelected(entry.offset, entry.length);
            });
}

void StringsTable::setStrings(const std::vector<xrl::ExtractedString>* strings, const QString& note) {
    strings_ = strings;
    note_->setText(note);
    note_->setVisible(!note.isEmpty());
    static_cast<ExtractedStringsModel*>(proxy_->sourceModel())->refresh();
    for (int column = 0; column < 4; ++column) view_->resizeColumnToContents(column);
    updateCount();
}

void StringsTable::clear(const QString& note) {
    strings_ = nullptr;
    setStrings(nullptr, note);
}

bool StringsTable::selectOffset(quint64 offset) {
    if (!strings_) return false;
    const auto first = std::lower_bound(strings_->begin(), strings_->end(), offset,
                                        [](const xrl::ExtractedString& entry, quint64 value) {
                                            return entry.offset < value;
                                        });
    for (auto entry = first; entry != strings_->end() && entry->offset == offset; ++entry) {
        const int sourceRow = static_cast<int>(std::distance(strings_->begin(), entry));
        const QModelIndex proxyIndex = proxy_->mapFromSource(proxy_->sourceModel()->index(sourceRow, 1));
        if (!proxyIndex.isValid()) continue;
        const QSignalBlocker blocker(view_->selectionModel());
        view_->selectRow(proxyIndex.row());
        view_->scrollTo(proxyIndex, QAbstractItemView::PositionAtCenter);
        return true;
    }
    return false;
}

void StringsTable::updateCount() {
    const int visible = proxy_->rowCount();
    const size_t total = strings_ ? strings_->size() : 0;
    count_->setText(visible == static_cast<int>(total)
                        ? tr("%1 strings").arg(total)
                        : tr("%1 of %2 strings").arg(visible).arg(total));
}

}  // namespace xrl::ui
