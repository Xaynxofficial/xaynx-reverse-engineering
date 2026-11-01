#pragma once
#include <QAbstractScrollArea>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace xrl::ui {

// Read-only hex + ASCII viewer over an in-memory buffer. Offsets are 64-bit throughout;
// all access is bounds-checked against the buffer size.
class HexView : public QAbstractScrollArea {
    Q_OBJECT
public:
    enum DiffHighlightType {
        DiffNone = 0,
        DiffModified = 1,
        DiffInserted = 2,
        DiffDeleted = 3
    };

    struct HighlightSpan {
        quint64 offset = 0;
        quint64 size = 0;
        DiffHighlightType type = DiffModified;
    };

    explicit HexView(QWidget* parent = nullptr);

    void setData(std::shared_ptr<const std::vector<uint8_t>> data);
    // Selects and scrolls to `offset`. Returns false (and changes nothing) when out of range.
    bool goToOffset(quint64 offset);
    bool hasSelection() const { return hasSel_; }
    quint64 selectedOffset() const { return sel_; }
    quint64 dataSize() const { return data_ ? data_->size() : 0; }

    void setDiffHighlights(std::vector<HighlightSpan> highlights);
    void clearDiffHighlights();
    bool setRangeHighlight(quint64 offset, quint64 size);
    void clearRangeHighlight();

    void setExternalScroll(int vValue, int hValue);

signals:
    void selectionChanged(quint64 offset);
    void scrolled(int vValue, int hValue);

protected:
    void paintEvent(QPaintEvent*) override;
    void resizeEvent(QResizeEvent*) override;
    void mousePressEvent(QMouseEvent*) override;
    void keyPressEvent(QKeyEvent*) override;

private:
    static constexpr int kBytesPerRow = 16;
    quint64 rowCount() const;
    int visibleRows() const;
    int offsetDigits() const;
    int hexX(int col) const;   // x (content coordinates) of byte `col`
    int asciiX() const;
    int totalWidth() const;
    void updateScrollBars();
    void select(quint64 off, bool ensureVisible);
    void ensureVisible(quint64 off);
    DiffHighlightType highlightForOffset(quint64 off) const;

    std::shared_ptr<const std::vector<uint8_t>> data_;
    std::vector<HighlightSpan> highlights_;
    std::optional<HighlightSpan> rangeHighlight_;
    bool hasSel_ = false;
    quint64 sel_ = 0;
    int rowH_ = 18, charW_ = 8, headerH_ = 24, margin_ = 12;
    bool syncingScroll_ = false;
};

}  // namespace xrl::ui
