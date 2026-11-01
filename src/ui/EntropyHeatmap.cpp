#include "EntropyHeatmap.hpp"

#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QScrollBar>
#include <QToolTip>
#include <QWheelEvent>
#include <algorithm>
#include <cmath>

#include "Theme.hpp"
#include "UiUtil.hpp"

namespace xrl::ui {
namespace {

QColor entropyColor(double entropy) {
    const QColor low("#426784");
    const QColor middle("#2a9d8f");
    const QColor high("#f2a65a");
    const double value = std::clamp(entropy / 8.0, 0.0, 1.0);
    const QColor from = value < 0.55 ? low : middle;
    const QColor to = value < 0.55 ? middle : high;
    const double t = value < 0.55 ? value / 0.55 : (value - 0.55) / 0.45;
    return QColor::fromRgbF(static_cast<float>(from.redF() + (to.redF() - from.redF()) * t),
                            static_cast<float>(from.greenF() + (to.greenF() - from.greenF()) * t),
                            static_cast<float>(from.blueF() + (to.blueF() - from.blueF()) * t));
}

}  // namespace

EntropyHeatmap::EntropyHeatmap(QWidget* parent) : QAbstractScrollArea(parent) {
    setFrameShape(QFrame::NoFrame);
    setFocusPolicy(Qt::StrongFocus);
    setMouseTracking(true);
    viewport()->setMouseTracking(true);
    viewport()->setAutoFillBackground(false);
    connect(verticalScrollBar(), &QScrollBar::valueChanged, viewport(),
            qOverload<>(&QWidget::update));
}

void EntropyHeatmap::setBlocks(const std::vector<xrl::EntropyBlock>* blocks, size_t blockSize) {
    if (blocks_ == blocks && blockSize_ == blockSize) {
        updateScrollBars();
        viewport()->update();
        return;
    }
    blocks_ = blocks;
    blockSize_ = blockSize;
    selectedIndex_ = 0;
    hasSelection_ = false;
    updateScrollBars();
    viewport()->update();
}

void EntropyHeatmap::setComparisonBlocks(const std::vector<xrl::EntropyBlock>* blocks) {
    comparisonBlocks_ = blocks;
    viewport()->update();
}

void EntropyHeatmap::setVariationThreshold(double threshold) {
    variationThreshold_ = std::clamp(threshold, 0.0, 8.0);
    viewport()->update();
}

int EntropyHeatmap::columns() const {
    return std::max(1, viewport()->width() / (cellSize_ + 2));
}

void EntropyHeatmap::updateScrollBars() {
    const quint64 count = blocks_ ? static_cast<quint64>(blocks_->size()) : 0;
    const quint64 cols = static_cast<quint64>(columns());
    const quint64 rows = count / cols + (count % cols != 0 ? 1 : 0);
    const int rowHeight = cellSize_ + 2;
    const quint64 visible = static_cast<quint64>(std::max(1, viewport()->height() / rowHeight));
    const quint64 maxScroll = rows > visible ? rows - visible : 0;
    verticalScrollBar()->setRange(0, static_cast<int>(std::min<quint64>(maxScroll, INT32_MAX)));
    verticalScrollBar()->setPageStep(static_cast<int>(std::min<quint64>(visible, INT32_MAX)));
    verticalScrollBar()->setSingleStep(1);
    horizontalScrollBar()->setRange(0, 0);
}

void EntropyHeatmap::resizeEvent(QResizeEvent* event) {
    QAbstractScrollArea::resizeEvent(event);
    updateScrollBars();
    viewport()->update();
}

void EntropyHeatmap::paintEvent(QPaintEvent*) {
    QPainter painter(viewport());
    painter.fillRect(viewport()->rect(), QColor(Colors::background));
    if (!blocks_ || blocks_->empty()) {
        painter.setPen(QColor(Colors::muted));
        painter.drawText(viewport()->rect(), Qt::AlignCenter, tr("Analyze a file to render its entropy map."));
        return;
    }

    const quint64 cols = static_cast<quint64>(columns());
    const quint64 firstRow = static_cast<quint64>(verticalScrollBar()->value());
    const int rowHeight = cellSize_ + 2;
    const int visibleRows = viewport()->height() / rowHeight + 2;
    const int cellWidth = std::max(1, viewport()->width() / static_cast<int>(cols));
    for (int row = 0; row < visibleRows; ++row) {
        const quint64 gridRow = firstRow + static_cast<quint64>(row);
        const quint64 firstIndex = gridRow * cols;
        if (firstIndex >= blocks_->size()) break;
        const int count = static_cast<int>(std::min<quint64>(cols, blocks_->size() - firstIndex));
        for (int col = 0; col < count; ++col) {
            const quint64 index = firstIndex + static_cast<quint64>(col);
            const auto& block = (*blocks_)[static_cast<size_t>(index)];
            const QRect rect(col * cellWidth + 1, row * rowHeight + 1, std::max(1, cellWidth - 3), cellSize_);
            painter.fillRect(rect, entropyColor(block.entropy));

            bool unusual = false;
            if (variationThreshold_ > 0.0 && index > 0) {
                unusual = std::abs(block.entropy - (*blocks_)[static_cast<size_t>(index - 1)].entropy) >= variationThreshold_;
            }
            if (variationThreshold_ > 0.0 && comparisonBlocks_ && index < comparisonBlocks_->size()) {
                unusual = unusual || std::abs(block.entropy -
                    (*comparisonBlocks_)[static_cast<size_t>(index)].entropy) >= variationThreshold_;
            }
            if (unusual) {
                painter.setPen(QPen(QColor("#ff786f"), 1));
                painter.setBrush(Qt::NoBrush);
                painter.drawRect(rect.adjusted(0, 0, -1, -1));
            }
            if (hasSelection_ && index == selectedIndex_) {
                painter.setPen(QPen(QColor(Colors::text), 1));
                painter.setBrush(Qt::NoBrush);
                painter.drawRect(rect.adjusted(0, 0, -1, -1));
            }
        }
    }
}

quint64 EntropyHeatmap::indexAt(const QPoint& point) const {
    if (!blocks_ || blocks_->empty() || point.x() < 0 || point.y() < 0) return UINT64_MAX;
    const int colWidth = std::max(1, viewport()->width() / columns());
    const int col = point.x() / colWidth;
    const int row = point.y() / (cellSize_ + 2);
    if (col >= columns()) return UINT64_MAX;
    const quint64 index = (static_cast<quint64>(verticalScrollBar()->value()) + static_cast<quint64>(row)) *
                              static_cast<quint64>(columns()) +
                          static_cast<quint64>(col);
    return index < blocks_->size() ? index : UINT64_MAX;
}

void EntropyHeatmap::select(quint64 index) {
    if (!blocks_ || index >= blocks_->size()) return;
    selectedIndex_ = index;
    hasSelection_ = true;
    viewport()->update();
    emit blockSelected((*blocks_)[static_cast<size_t>(index)].offset);
}

void EntropyHeatmap::mouseMoveEvent(QMouseEvent* event) {
    const quint64 index = indexAt(event->pos());
    if (index == UINT64_MAX) {
        QToolTip::hideText();
        return;
    }
    const auto& block = (*blocks_)[static_cast<size_t>(index)];
    const quint64 last = block.offset + block.size - 1;
    const QString tip = tr("Block %1\nBytes %2–%3\nSize %4 bytes\nEntropy %5 bits/byte")
                            .arg(index + 1)
                            .arg(hex64(block.offset), hex64(last))
                            .arg(block.size)
                            .arg(block.entropy, 0, 'f', 4);
    QToolTip::showText(event->globalPosition().toPoint(), tip, this);
}

void EntropyHeatmap::mousePressEvent(QMouseEvent* event) {
    if (event->button() != Qt::LeftButton) return;
    setFocus();
    const quint64 index = indexAt(event->pos());
    if (index != UINT64_MAX) select(index);
}

void EntropyHeatmap::leaveEvent(QEvent* event) {
    QToolTip::hideText();
    QAbstractScrollArea::leaveEvent(event);
}

void EntropyHeatmap::wheelEvent(QWheelEvent* event) {
    if (event->modifiers() & Qt::ControlModifier) {
        const int delta = event->angleDelta().y();
        cellSize_ = std::clamp(cellSize_ + (delta > 0 ? 2 : -2), 6, 32);
        updateScrollBars();
        viewport()->update();
        event->accept();
        return;
    }
    QAbstractScrollArea::wheelEvent(event);
}

void EntropyHeatmap::keyPressEvent(QKeyEvent* event) {
    if (!blocks_ || blocks_->empty()) return;
    quint64 index = hasSelection_ ? selectedIndex_ : 0;
    const quint64 cols = static_cast<quint64>(columns());
    switch (event->key()) {
        case Qt::Key_Left: if (index > 0) --index; break;
        case Qt::Key_Right: if (index + 1 < blocks_->size()) ++index; break;
        case Qt::Key_Up: if (index >= cols) index -= cols; break;
        case Qt::Key_Down: if (index + cols < blocks_->size()) index += cols; break;
        default: QAbstractScrollArea::keyPressEvent(event); return;
    }
    select(index);
    const quint64 row = index / cols;
    const int first = verticalScrollBar()->value();
    const int visible = std::max(1, viewport()->height() / (cellSize_ + 2));
    if (row < static_cast<quint64>(first)) verticalScrollBar()->setValue(static_cast<int>(row));
    else if (row >= static_cast<quint64>(first + visible))
        verticalScrollBar()->setValue(static_cast<int>(std::min<quint64>(row - visible + 1, INT32_MAX)));
}

}  // namespace xrl::ui
