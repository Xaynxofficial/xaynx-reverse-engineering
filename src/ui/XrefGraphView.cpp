#include "XrefGraphView.hpp"

#include <QGraphicsItemGroup>
#include <QGraphicsPathItem>
#include <QGraphicsPolygonItem>
#include <QGraphicsRectItem>
#include <QGraphicsScene>
#include <QGraphicsTextItem>
#include <QFontDatabase>
#include <QFrame>
#include <QPainter>
#include <QVariant>
#include <QWheelEvent>
#include <algorithm>
#include <cmath>
#include <map>
#include <set>
#include <tuple>

#include "xrl/xref.hpp"
#include "xrl/util.hpp"

namespace xrl::ui {
namespace {

struct Node {
    QString key;
    QString label;
    QString detail;
    quint64 address = 0;
    bool hasAddress = false;
    QColor color;
};

QString typeColor(const XrefReference& reference) {
    switch (reference.type) {
        case XrefType::Call: return QStringLiteral("#6ca8e8");
        case XrefType::ConditionalBranch: return QStringLiteral("#b39be8");
        case XrefType::UnconditionalBranch: return QStringLiteral("#d49c63");
        case XrefType::Import: return QStringLiteral("#d49c63");
        case XrefType::Export: return QStringLiteral("#72b68a");
        case XrefType::String: return QStringLiteral("#60b9ac");
        case XrefType::Data: return QStringLiteral("#8b8b92");
        case XrefType::Code: case XrefType::Relocation: case XrefType::Symbol:
            return QStringLiteral("#8b8b92");
    }
    return QStringLiteral("#8b8b92");
}

QPointF arrowPoint(const QPointF& end, const QPointF& tangent, qreal distance, qreal side) {
    const qreal length = std::hypot(tangent.x(), tangent.y());
    if (length == 0) return end;
    const QPointF unit(tangent.x() / length, tangent.y() / length);
    return end - unit * distance + QPointF(-unit.y(), unit.x()) * side;
}

}  // namespace

XrefGraphView::XrefGraphView(QWidget* parent) : QGraphicsView(parent), scene_(new QGraphicsScene(this)) {
    setScene(scene_);
    setRenderHint(QPainter::Antialiasing);
    setRenderHint(QPainter::TextAntialiasing);
    setDragMode(QGraphicsView::ScrollHandDrag);
    setTransformationAnchor(QGraphicsView::AnchorUnderMouse);
    setResizeAnchor(QGraphicsView::AnchorViewCenter);
    setBackgroundBrush(QColor("#0d0d0e"));
    setFrameShape(QFrame::NoFrame);
    connect(scene_, &QGraphicsScene::selectionChanged, this, [this] {
        for (auto it = nodes_.cbegin(); it != nodes_.cend(); ++it) {
            auto* rect = qgraphicsitem_cast<QGraphicsRectItem*>(it.value());
            if (!rect) continue;
            const bool selected = rect->isSelected();
            rect->setPen(QPen(selected ? QColor("#f2f2f3") : QColor("#34343b"), selected ? 2.2 : 1.0));
            rect->setBrush(selected ? QColor("#202024") : QColor("#151517"));
            if (selected && rect->data(0).isValid())
                emit addressSelected(rect->data(0).toULongLong());
        }
    });
    clearGraph(tr("Run XREF to build an evidence-backed relationship graph."));
}

void XrefGraphView::clearGraph(const QString& message) {
    nodes_.clear();
    scene_->clear();
    auto* text = scene_->addText(message);
    text->setDefaultTextColor(QColor("#8b8b92"));
    text->setPos(24, 24);
    scene_->setSceneRect(0, 0, 600, 180);
    resetTransform();
}

void XrefGraphView::setReferenceGraph(const xrl::XrefResult& result) {
    nodes_.clear();
    scene_->clear();
    resetTransform();
    constexpr size_t maxNodes = 180;
    constexpr size_t maxEdges = 360;
    constexpr qreal nodeWidth = 220;
    constexpr qreal nodeHeight = 68;
    constexpr qreal columnGap = 110;
    constexpr qreal rowGap = 36;
    std::map<QString, Node> nodeMap;
    struct Link { QString from; QString to; QString label; QColor color; };
    std::vector<Link> links;
    std::set<std::tuple<QString, QString, QString>> uniqueLinks;
    auto insertNode = [&](Node node) {
        if (nodeMap.contains(node.key)) return true;
        if (nodeMap.size() >= maxNodes) return false;
        nodeMap.emplace(node.key, std::move(node));
        return true;
    };
    for (const auto& reference : result.references) {
        if (links.size() >= maxEdges) break;
        if (!reference.sourceAddress) continue;
        QString sourceKey;
        if (reference.sourceFunction) sourceKey = QStringLiteral("function:%1").arg(*reference.sourceFunction);
        else sourceKey = QStringLiteral("address:%1").arg(*reference.sourceAddress);
        const QString sourceName = QString::fromStdString(reference.sourceFunctionName);
        const QString sourceLabel = sourceName.isEmpty() ? QStringLiteral("Address") : QStringLiteral("Function");
        const QString sourceDetail = sourceName.isEmpty()
                                         ? QStringLiteral("0x%1").arg(*reference.sourceAddress, 0, 16)
                                         : QStringLiteral("0x%1").arg(*reference.sourceFunction, 0, 16);
        const quint64 sourceAddress = reference.sourceFunction.value_or(*reference.sourceAddress);
        if (!insertNode({sourceKey, sourceName.isEmpty() ? sourceLabel : sourceName, sourceDetail,
                         sourceAddress, true, QColor("#6ca8e8")})) continue;

        QString targetKey;
        QString targetLabel;
        quint64 targetAddress = 0;
        bool targetHasAddress = false;
        if (!reference.destinationAddress) {
            targetKey = QStringLiteral("unresolved:%1")
                            .arg(reference.instructionAddress.value_or(*reference.sourceAddress));
            targetLabel = QStringLiteral("Indirect target unresolved");
        } else {
            targetAddress = *reference.destinationAddress;
            targetHasAddress = true;
            if (reference.destinationFunction) {
                targetKey = QStringLiteral("function:%1").arg(*reference.destinationFunction);
                targetLabel = reference.destinationFunctionName.empty()
                                  ? QStringLiteral("Function") : QString::fromStdString(reference.destinationFunctionName);
            } else if (reference.type == XrefType::String) {
                targetKey = QStringLiteral("string:%1").arg(targetAddress);
                targetLabel = QString::fromStdString(reference.dataTarget);
            } else if (!reference.symbolName.empty()) {
                targetKey = QStringLiteral("symbol:%1:%2").arg(targetAddress).arg(QString::fromStdString(reference.symbolName));
                targetLabel = QString::fromStdString(reference.symbolName);
            } else {
                targetKey = QStringLiteral("address:%1").arg(targetAddress);
                targetLabel = QStringLiteral("Address");
            }
        }
        const QString targetDetail = targetHasAddress ? QStringLiteral("0x%1").arg(targetAddress, 0, 16)
                                                      : QStringLiteral("Target is not statically resolved");
        if (!insertNode({targetKey, targetLabel.left(64), targetDetail, targetAddress, targetHasAddress,
                         QColor(typeColor(reference))})) continue;
        const QString edgeLabel = QString::fromLatin1(xrl::toString(reference.type));
        if (uniqueLinks.emplace(sourceKey, targetKey, edgeLabel).second)
            links.push_back({sourceKey, targetKey, edgeLabel, QColor(typeColor(reference))});
    }
    if (nodeMap.empty()) {
        clearGraph(tr("No resolvable graph relationships were found in the analyzed references."));
        return;
    }

    QHash<QString, QPointF> positions;
    size_t index = 0;
    for (const auto& [key, node] : nodeMap) {
        const qreal x = static_cast<qreal>(index % 4) * (nodeWidth + columnGap);
        const qreal y = static_cast<qreal>(index / 4) * (nodeHeight + rowGap);
        const QPointF pos(x, y);
        positions.insert(key, pos);
        auto* rect = scene_->addRect(QRectF(pos, QSizeF(nodeWidth, nodeHeight)),
                                     QPen(QColor("#34343b"), 1.0), QBrush(QColor("#151517")));
        rect->setFlag(QGraphicsItem::ItemIsSelectable);
        rect->setData(0, node.hasAddress ? QVariant::fromValue<qulonglong>(node.address) : QVariant());
        rect->setToolTip(node.detail);
        auto* title = new QGraphicsTextItem(rect);
        title->setDefaultTextColor(node.color);
        title->setFont(QFont(QStringLiteral("Sans Serif"), 9, QFont::DemiBold));
        title->setTextWidth(nodeWidth - 18);
        title->setPlainText(node.label);
        title->setPos(pos + QPointF(9, 7));
        auto* detail = new QGraphicsTextItem(rect);
        detail->setDefaultTextColor(QColor("#a3a3aa"));
        detail->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        detail->setTextWidth(nodeWidth - 18);
        detail->setPlainText(node.detail);
        detail->setPos(pos + QPointF(9, 36));
        rect->setZValue(1);
        nodes_.insert(key, rect);
        ++index;
    }
    for (const auto& link : links) {
        const QPointF from = positions.value(link.from) + QPointF(nodeWidth, nodeHeight / 2);
        const QPointF to = positions.value(link.to) + QPointF(0, nodeHeight / 2);
        const QPointF control1 = from + QPointF(columnGap * 0.45, 0);
        const QPointF control2 = to - QPointF(columnGap * 0.45, 0);
        QPainterPath path(from);
        path.cubicTo(control1, control2, to);
        auto* line = scene_->addPath(path, QPen(link.color, 1.5));
        const QPointF tangent = to - control2;
        const QPolygonF arrow{to, arrowPoint(to, tangent, 9, 4), arrowPoint(to, tangent, 9, -4)};
        auto* tip = scene_->addPolygon(arrow, QPen(link.color), QBrush(link.color));
        auto* label = scene_->addText(link.label);
        label->setDefaultTextColor(link.color);
        label->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        label->setPos((from + to) / 2);
        auto* group = scene_->createItemGroup({line, tip, label});
        group->setZValue(0);
    }
    if (result.functions.size() > maxNodes || result.references.size() > maxEdges) {
        auto* note = scene_->addText(tr("Graph is bounded to %1 nodes and %2 edges; filter the reference list for focused analysis.")
                                         .arg(maxNodes).arg(maxEdges));
        note->setDefaultTextColor(QColor("#a3a3aa"));
        note->setPos(0, static_cast<qreal>((nodeMap.size() + 3) / 4) * (nodeHeight + rowGap));
    }
    scene_->setSceneRect(scene_->itemsBoundingRect().adjusted(-40, -40, 60, 60));
    fitGraph();
}

void XrefGraphView::fitGraph() {
    if (scene_->items().isEmpty()) return;
    fitInView(scene_->sceneRect(), Qt::KeepAspectRatio);
}

void XrefGraphView::wheelEvent(QWheelEvent* event) {
    const qreal factor = event->angleDelta().y() > 0 ? 1.15 : 1.0 / 1.15;
    const qreal current = transform().m11();
    if (current * factor < 0.12 || current * factor > 4.5) return;
    scale(factor, factor);
}

}  // namespace xrl::ui
