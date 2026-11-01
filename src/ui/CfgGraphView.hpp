#pragma once

#include <QGraphicsView>
#include <QHash>
#include <QPair>
#include <QVector>
#include <optional>

#include "xrl/cfg.hpp"

class QGraphicsItem;
class QGraphicsScene;
class QWheelEvent;

namespace xrl::ui {

class CfgGraphView : public QGraphicsView {
    Q_OBJECT
public:
    explicit CfgGraphView(QWidget* parent = nullptr);

    void setGraph(const xrl::ControlFlowGraph& graph);
    void clearGraph(const QString& message);
    void fitGraph();
    void selectBlockByAddress(quint64 address, bool center = true);
    std::optional<quint64> selectedBlockAddress() const;
    void setShowConditionalEdges(bool show);
    void setShowUnresolvedEdges(bool show);

signals:
    void blockSelected(quint64 address);
    void blockActivated(quint64 address);

protected:
    void wheelEvent(QWheelEvent* event) override;
    void mouseDoubleClickEvent(QMouseEvent* event) override;

private:
    QGraphicsScene* scene_ = nullptr;
    QHash<quint64, QGraphicsItem*> blockItems_;
    QHash<quint64, quint64> addressByBlockId_;
    QVector<QPair<QGraphicsItem*, int>> edgeItems_;
    QGraphicsItem* messageItem_ = nullptr;
    bool showConditional_ = true;
    bool showUnresolved_ = true;
    qreal zoom_ = 1.0;
};

}  // namespace xrl::ui
