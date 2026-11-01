#pragma once

#include <QWidget>
#include <vector>

#include "xrl/strings.hpp"

class QComboBox;
class QLineEdit;
class QTableView;
class QCheckBox;
class QLabel;
class QSortFilterProxyModel;
class QTimer;

namespace xrl::ui {

class StringsTable : public QWidget {
    Q_OBJECT
public:
    explicit StringsTable(QWidget* parent = nullptr);
    void setStrings(const std::vector<xrl::ExtractedString>* strings, const QString& note = {});
    void clear(const QString& note);
    bool selectOffset(quint64 offset);
    const std::vector<xrl::ExtractedString>* strings() const { return strings_; }

signals:
    void stringSelected(quint64 offset, quint64 length);

private:
    void updateCount();

    const std::vector<xrl::ExtractedString>* strings_ = nullptr;
    QLineEdit* search_ = nullptr;
    QComboBox* category_ = nullptr;
    QComboBox* encoding_ = nullptr;
    QCheckBox* caseSensitive_ = nullptr;
    QLabel* count_ = nullptr;
    QLabel* note_ = nullptr;
    QTableView* view_ = nullptr;
    QSortFilterProxyModel* proxy_ = nullptr;
    QTimer* filterTimer_ = nullptr;
};

}  // namespace xrl::ui
