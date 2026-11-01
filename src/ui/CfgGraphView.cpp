#include "CfgGraphView.hpp"

#include <QGraphicsItemGroup>
#include <QGraphicsPathItem>
#include <QGraphicsPolygonItem>
#include <QGraphicsRectItem>
#include <QGraphicsScene>
#include <QGraphicsTextItem>
#include <QFontDatabase>
#include <QMouseEvent>
#include <QPainter>
#include <QQueue>
#include <QFrame>
#include <QWheelEvent>
#include <cmath>
#include <limits>

namespace xrl::ui {
namespace {

QColor edgeColor(int kind) {
    switch (static_cast<xrl::CfgEdgeKind>(kind)) {
        case xrl::CfgEdgeKind::ConditionalTrue: return QColor("#6ca8e8");
        case xrl::CfgEdgeKind::ConditionalFalse: return QColor("#8b8b92");
        case xrl::CfgEdgeKind::Unconditional: return QColor("#b39be8");
        case xrl::CfgEdgeKind::Fallthrough: return QColor("#66666d");
        case xrl::CfgEdgeKind::ExternalBranch: return QColor("#dc9c55");
        case xrl::CfgEdgeKind::Unresolved: return QColor("#e6b45e");
    }
    return QColor("#8b8b92");
}

qreal nodeHeight(size_t instructionCount) {
    const size_t visible = std::min<size_t>(instructionCount, 4);
    return std::max<qreal>(92.0, 48.0 + static_cast<qreal>(visible) * 17.0);
}

QPointF arrowPoint(const QPointF& end, const QPointF& tangent, qreal distance, qreal side) {
    const qreal length = std::hypot(tangent.x(), tangent.y());
    if (length == 0) return end;
    const QPointF unit(tangent.x() / length, tangent.y() / length);
    return end - unit * distance + QPointF(-unit.y(), unit.x()) * side;
}

}  // namespace

CfgGraphView::CfgGraphView(QWidget* parent) : QGraphicsView(parent), scene_(new QGraphicsScene(this)) {
    setScene(scene_);
    setRenderHint(QPainter::Antialiasing);
    setRenderHint(QPainter::TextAntialiasing);
    setViewportUpdateMode(QGraphicsView::BoundingRectViewportUpdate);
    setDragMode(QGraphicsView::ScrollHandDrag);
    setTransformationAnchor(QGraphicsView::AnchorUnderMouse);
    setResizeAnchor(QGraphicsView::AnchorViewCenter);
    setBackgroundBrush(QColor("#0d0d0e"));
    setFrameShape(QFrame::NoFrame);
    connect(scene_, &QGraphicsScene::selectionChanged, this, [this] {
        QGraphicsItem* selected = nullptr;
        for (auto* item : scene_->selectedItems()) {
            if (item->data(0).isValid()) { selected = item; break; }
        }
        for (auto it = blockItems_.cbegin(); it != blockItems_.cend(); ++it) {
            auto* node = static_cast<QGraphicsRectItem*>(it.value());
            const bool isSelected = node == selected;
            node->setPen(QPen(isSelected ? QColor("#f2f2f3") : QColor("#34343b"), isSelected ? 2.2 : 1.0));
            node->setBrush(isSelected ? QColor("#202024") : QColor("#151517"));
        }
        if (selected) {
            const quint64 id = selected->data(0).toULongLong();
            if (addressByBlockId_.contains(id)) emit blockSelected(addressByBlockId_.value(id));
        }
    });
    clearGraph(tr("Choose a function to build its control-flow graph."));
}

void CfgGraphView::clearGraph(const QString& message) {
    blockItems_.clear();
    addressByBlockId_.clear();
    edgeItems_.clear();
    scene_->clear();
    auto* text = scene_->addText(message);
    text->setDefaultTextColor(QColor("#8b8b92"));
    text->setPos(24, 24);
    messageItem_ = text;
    scene_->setSceneRect(0, 0, 560, 180);
    zoom_ = 1.0;
    resetTransform();
}

void CfgGraphView::setGraph(const xrl::ControlFlowGraph& graph) {
    blockItems_.clear();
    addressByBlockId_.clear();
    edgeItems_.clear();
    scene_->clear();
    messageItem_ = nullptr;
    zoom_ = 1.0;
    resetTransform();
    if (graph.blocks.empty()) {
        clearGraph(graph.error.empty() ? tr("No basic blocks were produced.")
                                       : QString::fromStdString(graph.error));
        return;
    }

    constexpr qreal nodeWidth = 250;
    constexpr qreal columnGap = 110;
    constexpr qreal rowGap = 46;
    const size_t count = graph.blocks.size();
    std::vector<int> layers(count, -1);
    QQueue<size_t> queue;
    layers[0] = 0;
    queue.enqueue(0);
    int maxLayer = 0;
    while (!queue.isEmpty()) {
        const size_t current = queue.dequeue();
        for (const size_t next : graph.blocks[current].successors) {
            if (next >= count || layers[next] >= 0) continue;
            layers[next] = layers[current] + 1;
            maxLayer = std::max(maxLayer, layers[next]);
            queue.enqueue(next);
        }
    }
    for (auto& layer : layers)
        if (layer < 0) layer = ++maxLayer;

    std::vector<size_t> rowInLayer(static_cast<size_t>(maxLayer + 1), 0);
    std::vector<QPointF> positions(count);
    for (size_t i = 0; i < count; ++i) {
        const size_t layer = static_cast<size_t>(layers[i]);
        const size_t row = rowInLayer[layer]++;
        positions[i] = QPointF(static_cast<qreal>(layer) * (nodeWidth + columnGap),
                               static_cast<qreal>(row) * (132 + rowGap));
    }

    for (size_t i = 0; i < count; ++i) {
        const auto& block = graph.blocks[i];
        const qreal height = nodeHeight(block.instructions.size());
        auto* node = scene_->addRect(QRectF(positions[i], QSizeF(nodeWidth, height)),
                                     QPen(block.isExit ? QColor("#3d7556") : QColor("#34343b"), 1.0),
                                     QBrush(QColor("#151517")));
        node->setFlag(QGraphicsItem::ItemIsSelectable);
        node->setData(0, QVariant::fromValue<qulonglong>(block.id));
        node->setToolTip(tr("Block %1\n[%2, %3)\n%4 instruction(s)%5")
                             .arg(block.id)
                             .arg(QString::number(block.startAddress, 16), QString::number(block.endAddress, 16))
                             .arg(block.instructions.size())
                             .arg(block.hasUnresolvedFlow ? tr("\nContains unresolved control flow") : QString()));
        auto* text = new QGraphicsTextItem(node);
        text->setDefaultTextColor(QColor("#f2f2f3"));
        text->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        text->setTextWidth(nodeWidth - 20);
        QStringList lines{QStringLiteral("%1%2  %3 instruction(s)")
                              .arg(block.isEntry ? QStringLiteral("ENTRY  ") : QString())
                              .arg(QStringLiteral("0x%1").arg(block.startAddress, 0, 16))
                              .arg(block.instructions.size())};
        if (block.isExit) lines[0].prepend(QStringLiteral("EXIT  "));
        const size_t shown = std::min<size_t>(block.instructions.size(), 4);
        for (size_t j = 0; j < shown; ++j) {
            const auto& instruction = block.instructions[j];
            lines << QStringLiteral("0x%1  %2 %3")
                         .arg(instruction.address, 0, 16)
                         .arg(QString::fromStdString(instruction.mnemonic),
                              QString::fromStdString(instruction.operands));
        }
        if (block.instructions.size() > shown) lines << QStringLiteral("…");
        if (block.hasUnresolvedFlow) lines << tr("Unresolved flow");
        text->setPlainText(lines.join('\n'));
        text->setPos(positions[i] + QPointF(10, 7));
        node->setZValue(1);
        blockItems_.insert(block.startAddress, node);
        addressByBlockId_.insert(static_cast<quint64>(block.id), block.startAddress);
    }

    for (const auto& edge : graph.edges) {
        if (edge.from >= count) continue;
        const int edgeType = static_cast<int>(edge.kind);
        const QColor color = edgeColor(edgeType);
        const QPointF sourcePos = positions[edge.from];
        const qreal sourceHeight = nodeHeight(graph.blocks[edge.from].instructions.size());
        QPointF start(sourcePos.x() + nodeWidth, sourcePos.y() + sourceHeight / 2);
        QPointF end;
        QPointF tangent;
        if (edge.to && *edge.to < count) {
            const size_t target = *edge.to;
            const QPointF targetPos = positions[target];
            const qreal targetHeight = nodeHeight(graph.blocks[target].instructions.size());
            if (target == edge.from) {
                start = QPointF(sourcePos.x() + nodeWidth * 0.75, sourcePos.y());
                end = QPointF(sourcePos.x() + nodeWidth * 0.25, sourcePos.y());
                const QPointF c1(start.x() + 40, start.y() - 70);
                const QPointF c2(end.x() - 40, end.y() - 70);
                QPainterPath path(start);
                path.cubicTo(c1, c2, end);
                tangent = end - c2;
                auto* line = scene_->addPath(path, QPen(color, 1.8));
                QPolygonF arrow{end, arrowPoint(end, tangent, 10, 4), arrowPoint(end, tangent, 10, -4)};
                auto* tip = scene_->addPolygon(arrow, QPen(color), QBrush(color));
                auto* group = scene_->createItemGroup({line, tip});
                group->setZValue(0);
                edgeItems_.push_back({group, edgeType});
                continue;
            }
            const bool forward = targetPos.x() >= sourcePos.x();
            start = QPointF(sourcePos.x() + (forward ? nodeWidth : 0), sourcePos.y() + sourceHeight / 2);
            end = QPointF(targetPos.x() + (forward ? 0 : nodeWidth), targetPos.y() + targetHeight / 2);
            const qreal dx = std::max<qreal>(44, std::abs(end.x() - start.x()) * 0.45);
            const QPointF c1(start.x() + (forward ? dx : -dx), start.y());
            const QPointF c2(end.x() - (forward ? dx : -dx), end.y());
            QPainterPath path(start);
            path.cubicTo(c1, c2, end);
            tangent = end - c2;
            auto* line = scene_->addPath(path, QPen(color, edge.kind == CfgEdgeKind::Fallthrough ? 1.2 : 1.8));
            QPolygonF arrow{end, arrowPoint(end, tangent, 10, 4), arrowPoint(end, tangent, 10, -4)};
            auto* tip = scene_->addPolygon(arrow, QPen(color), QBrush(color));
            QList<QGraphicsItem*> parts{line, tip};
            if (!edge.label.empty()) {
                auto* label = scene_->addText(QString::fromStdString(edge.label));
                label->setDefaultTextColor(color);
                label->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
                label->setPos((start + end) / 2);
                parts.push_back(label);
            }
            auto* group = scene_->createItemGroup(parts);
            group->setZValue(0);
            edgeItems_.push_back({group, edgeType});
        } else {
            start = QPointF(sourcePos.x() + nodeWidth, sourcePos.y() + sourceHeight / 2);
            end = start + QPointF(64, 0);
            QPainterPath path(start);
            path.lineTo(end);
            const Qt::PenStyle style = edge.kind == CfgEdgeKind::Unresolved ||
                                               edge.kind == CfgEdgeKind::ExternalBranch
                                           ? Qt::DashLine : Qt::SolidLine;
            auto* line = scene_->addPath(path, QPen(color, 1.6, style));
            auto* label = scene_->addText(edge.targetAddress
                                              ? QStringLiteral("%1 0x%2").arg(QString::fromStdString(edge.label))
                                                    .arg(edge.targetAddress, 0, 16)
                                              : QString::fromStdString(edge.label));
            label->setDefaultTextColor(color);
            label->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
            label->setPos(end + QPointF(4, -12));
            auto* group = scene_->createItemGroup({line, label});
            group->setZValue(0);
            edgeItems_.push_back({group, edgeType});
        }
    }
    setShowConditionalEdges(showConditional_);
    setShowUnresolvedEdges(showUnresolved_);
    scene_->setSceneRect(scene_->itemsBoundingRect().adjusted(-40, -40, 100, 50));
    selectBlockByAddress(graph.function.address, false);
    fitGraph();
}

void CfgGraphView::fitGraph() {
    if (scene_->items().isEmpty()) return;
    resetTransform();
    zoom_ = 1.0;
    fitInView(scene_->sceneRect(), Qt::KeepAspectRatio);
    zoom_ = transform().m11();
}

void CfgGraphView::selectBlockByAddress(quint64 address, bool center) {
    auto* item = blockItems_.value(address, nullptr);
    if (!item) return;
    item->setSelected(true);
    if (center) centerOn(item);
}

std::optional<quint64> CfgGraphView::selectedBlockAddress() const {
    for (auto* item : scene_->selectedItems()) {
        if (!item->data(0).isValid()) continue;
        const quint64 id = item->data(0).toULongLong();
        if (addressByBlockId_.contains(id)) return addressByBlockId_.value(id);
    }
    return std::nullopt;
}

void CfgGraphView::setShowConditionalEdges(bool show) {
    showConditional_ = show;
    for (const auto& entry : edgeItems_) {
        const auto edgeKind = static_cast<xrl::CfgEdgeKind>(entry.second);
        if (edgeKind == xrl::CfgEdgeKind::ConditionalTrue || edgeKind == xrl::CfgEdgeKind::ConditionalFalse)
            entry.first->setVisible(show);
    }
}

void CfgGraphView::setShowUnresolvedEdges(bool show) {
    showUnresolved_ = show;
    for (const auto& entry : edgeItems_) {
        const auto edgeKind = static_cast<xrl::CfgEdgeKind>(entry.second);
        if (edgeKind == xrl::CfgEdgeKind::Unresolved || edgeKind == xrl::CfgEdgeKind::ExternalBranch)
            entry.first->setVisible(show);
    }
}

void CfgGraphView::wheelEvent(QWheelEvent* event) {
    const qreal factor = event->angleDelta().y() > 0 ? 1.15 : 1.0 / 1.15;
    const qreal nextZoom = zoom_ * factor;
    if (nextZoom < 0.12 || nextZoom > 4.0) return;
    scale(factor, factor);
    zoom_ = nextZoom;
    event->accept();
}

void CfgGraphView::mouseDoubleClickEvent(QMouseEvent* event) {
    QGraphicsItem* item = itemAt(event->pos());
    while (item && !item->data(0).isValid()) item = item->parentItem();
    if (item) {
        const quint64 id = item->data(0).toULongLong();
        if (addressByBlockId_.contains(id)) {
            emit blockActivated(addressByBlockId_.value(id));
            event->accept();
            return;
        }
    }
    QGraphicsView::mouseDoubleClickEvent(event);
}

}  // namespace xrl::ui
