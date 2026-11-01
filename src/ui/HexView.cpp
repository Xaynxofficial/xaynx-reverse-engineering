#include "HexView.hpp"

#include <QFontDatabase>
#include <QFontMetrics>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPaintEvent>
#include <QPainter>
#include <QScrollBar>
#include <algorithm>

#include "Theme.hpp"

namespace xrl::ui {

HexView::HexView(QWidget* parent) : QAbstractScrollArea(parent) {
    QFont f = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    f.setPointSize(std::max(11, f.pointSize()));
    viewport()->setFont(f);
    const QFontMetrics fm(f);
    rowH_ = fm.height() + 4;
    charW_ = fm.horizontalAdvance(QLatin1Char('0'));
    headerH_ = rowH_ + 8;
    setFocusPolicy(Qt::StrongFocus);
    setFrameShape(QFrame::NoFrame);
    viewport()->setAutoFillBackground(false);

    auto onScroll = [this] {
        viewport()->update();
        if (!syncingScroll_) {
            emit scrolled(verticalScrollBar()->value(), horizontalScrollBar()->value());
        }
    };
    connect(verticalScrollBar(), &QScrollBar::valueChanged, this, onScroll);
    connect(horizontalScrollBar(), &QScrollBar::valueChanged, this, onScroll);
}

void HexView::setData(std::shared_ptr<const std::vector<uint8_t>> data) {
    data_ = std::move(data);
    rangeHighlight_.reset();
    hasSel_ = false;
    sel_ = 0;
    updateScrollBars();
    verticalScrollBar()->setValue(0);
    horizontalScrollBar()->setValue(0);
    viewport()->update();
}

void HexView::setDiffHighlights(std::vector<HighlightSpan> highlights) {
    highlights_ = std::move(highlights);
    std::sort(highlights_.begin(), highlights_.end(), [](const HighlightSpan& a, const HighlightSpan& b) {
        return a.offset < b.offset;
    });
    viewport()->update();
}

void HexView::clearDiffHighlights() {
    highlights_.clear();
    viewport()->update();
}

bool HexView::setRangeHighlight(quint64 offset, quint64 size) {
    if (size == 0 || offset >= dataSize() || size > dataSize() - offset) return false;
    rangeHighlight_ = HighlightSpan{offset, size, DiffModified};
    viewport()->update();
    return true;
}

void HexView::clearRangeHighlight() {
    rangeHighlight_.reset();
    viewport()->update();
}

void HexView::setExternalScroll(int vValue, int hValue) {
    syncingScroll_ = true;
    verticalScrollBar()->setValue(vValue);
    horizontalScrollBar()->setValue(hValue);
    syncingScroll_ = false;
    viewport()->update();
}

HexView::DiffHighlightType HexView::highlightForOffset(quint64 off) const {
    if (highlights_.empty()) return DiffNone;

    auto it = std::upper_bound(highlights_.begin(), highlights_.end(), off,
                               [](quint64 val, const HighlightSpan& span) {
                                   return val < span.offset;
                               });
    if (it != highlights_.begin()) {
        --it;
        if (off >= it->offset && off < it->offset + it->size) {
            return it->type;
        }
    }
    return DiffNone;
}

quint64 HexView::rowCount() const {
    const quint64 n = dataSize();
    return n / kBytesPerRow + (n % kBytesPerRow ? 1 : 0);
}
int HexView::visibleRows() const { return std::max(1, (viewport()->height() - headerH_) / rowH_); }
int HexView::offsetDigits() const { return dataSize() > 0xFFFFFFFFull ? 16 : 8; }
int HexView::hexX(int col) const { return margin_ + (offsetDigits() + 2 + col * 3 + (col >= 8 ? 1 : 0)) * charW_; }
int HexView::asciiX() const { return margin_ + (offsetDigits() + 2 + kBytesPerRow * 3 + 3) * charW_; }
int HexView::totalWidth() const { return asciiX() + (kBytesPerRow + 1) * charW_ + margin_; }

void HexView::updateScrollBars() {
    const quint64 rows = rowCount();
    const quint64 vis = static_cast<quint64>(visibleRows());
    const quint64 maxScroll = rows > vis ? rows - vis : 0;
    verticalScrollBar()->setRange(0, static_cast<int>(std::min<quint64>(maxScroll, INT32_MAX)));
    verticalScrollBar()->setPageStep(visibleRows());
    verticalScrollBar()->setSingleStep(1);
    horizontalScrollBar()->setRange(0, std::max(0, totalWidth() - viewport()->width()));
    horizontalScrollBar()->setPageStep(viewport()->width());
}

void HexView::resizeEvent(QResizeEvent* e) {
    QAbstractScrollArea::resizeEvent(e);
    updateScrollBars();
}

void HexView::ensureVisible(quint64 off) {
    const quint64 row = off / kBytesPerRow;
    const quint64 first = static_cast<quint64>(verticalScrollBar()->value());
    const quint64 vis = static_cast<quint64>(visibleRows());
    if (row < first) verticalScrollBar()->setValue(static_cast<int>(row));
    else if (row >= first + vis) verticalScrollBar()->setValue(static_cast<int>(std::min<quint64>(row - vis + 1, INT32_MAX)));
}

void HexView::select(quint64 off, bool ensure) {
    if (off >= dataSize()) return;
    sel_ = off;
    hasSel_ = true;
    if (ensure) ensureVisible(off);
    viewport()->update();
    emit selectionChanged(off);
}

bool HexView::goToOffset(quint64 offset) {
    if (offset >= dataSize()) return false;
    sel_ = offset;
    hasSel_ = true;
    const quint64 row = offset / kBytesPerRow;
    const quint64 half = static_cast<quint64>(visibleRows()) / 2;
    verticalScrollBar()->setValue(static_cast<int>(std::min<quint64>(row > half ? row - half : 0, INT32_MAX)));
    viewport()->update();
    emit selectionChanged(offset);
    return true;
}

void HexView::paintEvent(QPaintEvent*) {
    QPainter p(viewport());
    p.fillRect(viewport()->rect(), QColor(Colors::background));
    const QColor cText(Colors::text), cMuted(Colors::muted), cDim(Colors::dim), cSel(Colors::selection);
    const QColor cModBg("#3d2212"), cModFg("#fca311");
    const QColor cInsBg("#143822"), cInsFg("#70e000");
    const QColor cDelBg("#3d1419"), cDelFg("#ef233c");
    const QColor cRangeBg("#17364a"), cRangeFg("#9bdcff");

    const int dx = -horizontalScrollBar()->value();
    const QFontMetrics fm(p.font());
    const int ascent = fm.ascent() + 2;

    if (!data_ || data_->empty()) {
        p.setPen(cMuted);
        p.drawText(viewport()->rect(), Qt::AlignCenter, tr("No file loaded"));
        return;
    }

    // header row
    p.setPen(cMuted);
    p.drawText(dx + margin_, ascent + 2, tr("Offset"));
    for (int c = 0; c < kBytesPerRow; ++c)
        p.drawText(dx + hexX(c), ascent + 2, QStringLiteral("%1").arg(c, 2, 16, QLatin1Char('0')).toUpper());
    p.drawText(dx + asciiX(), ascent + 2, tr("ASCII"));
    p.setPen(QColor(Colors::border));
    p.drawLine(0, headerH_ - 2, viewport()->width(), headerH_ - 2);

    const auto& d = *data_;
    const quint64 rows = rowCount();
    const quint64 first = static_cast<quint64>(verticalScrollBar()->value());
    const int nvis = visibleRows() + 1;
    for (int r = 0; r < nvis; ++r) {
        const quint64 row = first + static_cast<quint64>(r);
        if (row >= rows) break;
        const quint64 base = row * kBytesPerRow;
        const int y = headerH_ + r * rowH_;
        p.setPen(cMuted);
        p.drawText(dx + margin_, y + ascent, QStringLiteral("%1").arg(base, offsetDigits(), 16, QLatin1Char('0')));
        for (int c = 0; c < kBytesPerRow; ++c) {
            const quint64 off = base + static_cast<quint64>(c);
            if (off >= d.size()) break;
            const uint8_t b = d[static_cast<size_t>(off)];
            const bool selected = hasSel_ && off == sel_;
            const bool rangeSelected = rangeHighlight_ && off >= rangeHighlight_->offset &&
                                       off - rangeHighlight_->offset < rangeHighlight_->size;
            const DiffHighlightType diffType = highlightForOffset(off);

            // Background highlighting
            if (selected) {
                p.fillRect(QRect(dx + hexX(c) - 3, y, charW_ * 2 + 6, rowH_), cSel);
                p.fillRect(QRect(dx + asciiX() + c * charW_, y, charW_, rowH_), cSel);
            } else if (rangeSelected) {
                p.fillRect(QRect(dx + hexX(c) - 2, y + 1, charW_ * 2 + 4, rowH_ - 2), cRangeBg);
                p.fillRect(QRect(dx + asciiX() + c * charW_, y + 1, charW_, rowH_ - 2), cRangeBg);
            } else if (diffType != DiffNone) {
                const QColor bg = (diffType == DiffModified) ? cModBg : (diffType == DiffInserted ? cInsBg : cDelBg);
                p.fillRect(QRect(dx + hexX(c) - 2, y + 1, charW_ * 2 + 4, rowH_ - 2), bg);
                p.fillRect(QRect(dx + asciiX() + c * charW_, y + 1, charW_, rowH_ - 2), bg);
            }

            // Foreground text color
            QColor textColor = b == 0 ? cDim : cText;
            if (diffType != DiffNone && !selected) {
                textColor = (diffType == DiffModified) ? cModFg : (diffType == DiffInserted ? cInsFg : cDelFg);
            }
            if (rangeSelected && !selected) textColor = cRangeFg;

            p.setPen(textColor);
            p.drawText(dx + hexX(c), y + ascent, QStringLiteral("%1").arg(b, 2, 16, QLatin1Char('0')));
            const bool printable = b >= 0x20 && b < 0x7F;
            p.setPen(printable ? textColor : cDim);
            p.drawText(dx + asciiX() + c * charW_, y + ascent, printable ? QString(QChar(b)) : QStringLiteral("."));
        }
    }
}

void HexView::mousePressEvent(QMouseEvent* e) {
    setFocus();
    if (!data_ || data_->empty() || e->button() != Qt::LeftButton) return;
    const int x = static_cast<int>(e->position().x()) + horizontalScrollBar()->value();
    const int y = static_cast<int>(e->position().y());
    if (y < headerH_) return;
    const quint64 row = static_cast<quint64>(verticalScrollBar()->value()) + static_cast<quint64>((y - headerH_) / rowH_);
    int col = -1;
    if (x >= asciiX() && x < asciiX() + kBytesPerRow * charW_) col = (x - asciiX()) / charW_;
    else
        for (int c = 0; c < kBytesPerRow; ++c)
            if (x >= hexX(c) - 3 && x < hexX(c) + charW_ * 2 + 3) { col = c; break; }
    if (col < 0) return;
    select(row * kBytesPerRow + static_cast<quint64>(col), false);
}

void HexView::keyPressEvent(QKeyEvent* e) {
    if (data_ && !data_->empty() && hasSel_) {
        const quint64 n = dataSize();
        switch (e->key()) {
            case Qt::Key_Left: if (sel_ > 0) select(sel_ - 1, true); return;
            case Qt::Key_Right: if (sel_ + 1 < n) select(sel_ + 1, true); return;
            case Qt::Key_Up: if (sel_ >= kBytesPerRow) select(sel_ - kBytesPerRow, true); return;
            case Qt::Key_Down: if (n - sel_ > kBytesPerRow) select(sel_ + kBytesPerRow, true); return;
            default: break;
        }
    }
    QAbstractScrollArea::keyPressEvent(e);
}

}  // namespace xrl::ui
