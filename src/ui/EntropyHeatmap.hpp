#pragma once

#include <QAbstractScrollArea>
#include <cstddef>
#include <vector>

#include "xrl/entropy.hpp"

namespace xrl::ui {

class EntropyHeatmap : public QAbstractScrollArea {
    Q_OBJECT
public:
    explicit EntropyHeatmap(QWidget* parent = nullptr);

    void setBlocks(const std::vector<xrl::EntropyBlock>* blocks, size_t blockSize);
    void setComparisonBlocks(const std::vector<xrl::EntropyBlock>* blocks);
    void setVariationThreshold(double threshold);

signals:
    void blockSelected(quint64 offset);

protected:
    void paintEvent(QPaintEvent*) override;
    void resizeEvent(QResizeEvent*) override;
    void mouseMoveEvent(QMouseEvent*) override;
    void mousePressEvent(QMouseEvent*) override;
    void leaveEvent(QEvent*) override;
    void wheelEvent(QWheelEvent*) override;
    void keyPressEvent(QKeyEvent*) override;

private:
    quint64 indexAt(const QPoint& point) const;
    int columns() const;
    void updateScrollBars();
    void select(quint64 index);

    const std::vector<xrl::EntropyBlock>* blocks_ = nullptr;
    const std::vector<xrl::EntropyBlock>* comparisonBlocks_ = nullptr;
    size_t blockSize_ = xrl::kDefaultEntropyBlockSize;
    quint64 selectedIndex_ = 0;
    bool hasSelection_ = false;
    int cellSize_ = 14;
    double variationThreshold_ = 1.5;
};

}  // namespace xrl::ui
