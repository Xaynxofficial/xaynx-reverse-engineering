#pragma once

#include <QGraphicsView>
#include <QHash>
#include <optional>

#include "xrl/xref.hpp"

class QGraphicsScene;
class QWheelEvent;

namespace xrl::ui {

class XrefGraphView : public QGraphicsView {
    Q_OBJECT
public:
    explicit XrefGraphView(QWidget* parent = nullptr);
    void setReferenceGraph(const xrl::XrefResult& result);
    void clearGraph(const QString& message);
    void fitGraph();

signals:
    void addressSelected(quint64 address);

protected:
    void wheelEvent(QWheelEvent* event) override;

private:
    QGraphicsScene* scene_ = nullptr;
    QHash<QString, QGraphicsItem*> nodes_;
};

}  // namespace xrl::ui
