#include "Theme.hpp"

#include <QPalette>
#include <QStyleFactory>

namespace xrl::ui {

void applyTheme(QApplication& app) {
    app.setStyle(QStyleFactory::create("Fusion"));

    QPalette p;
    const QColor bg(Colors::background), panel(Colors::panel), text(Colors::text), muted(Colors::muted);
    p.setColor(QPalette::Window, bg);
    p.setColor(QPalette::WindowText, text);
    p.setColor(QPalette::Base, panel);
    p.setColor(QPalette::AlternateBase, QColor("#18181a"));
    p.setColor(QPalette::Text, text);
    p.setColor(QPalette::Button, QColor("#1c1c1f"));
    p.setColor(QPalette::ButtonText, text);
    p.setColor(QPalette::PlaceholderText, QColor(Colors::dim));
    p.setColor(QPalette::Highlight, QColor(Colors::selection));
    p.setColor(QPalette::HighlightedText, text);
    p.setColor(QPalette::ToolTipBase, panel);
    p.setColor(QPalette::ToolTipText, text);
    p.setColor(QPalette::Disabled, QPalette::Text, QColor(Colors::dim));
    p.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(Colors::dim));
    p.setColor(QPalette::Disabled, QPalette::WindowText, QColor(Colors::dim));
    app.setPalette(p);

    app.setStyleSheet(R"(
        QWidget { color: #f2f2f3; }
        QMainWindow, QDialog, QStackedWidget > QWidget { background: #0d0d0e; }
        QMenuBar { background: #0d0d0e; }
        QMenuBar::item:selected { background: #2a2a2f; }
        QMenu { background: #151517; border: 1px solid #26262a; }
        QMenu::item:selected { background: #2a2a2f; }

        QListWidget#sidebar { background: #09090a; border: none; border-right: 1px solid #26262a; outline: 0; padding-top: 8px; }
        QListWidget#sidebar::item { padding: 10px 18px; color: #8b8b92; border-left: 2px solid transparent; }
        QListWidget#sidebar::item:hover { color: #f2f2f3; }
        QListWidget#sidebar::item:selected { background: #151517; color: #f2f2f3; border-left: 2px solid #f2f2f3; }

        QFrame#card { background: #151517; border: 1px solid #26262a; border-radius: 6px; }
        QLabel#cardTitle { color: #8b8b92; font-size: 11px; font-weight: 600; letter-spacing: 1px; }
        QLabel#pageTitle { font-size: 20px; font-weight: 600; }
        QLabel[muted="true"] { color: #8b8b92; }
        QLabel[error="true"] { color: #d9776f; }

        QPushButton { background: #1c1c1f; border: 1px solid #2e2e33; border-radius: 5px; padding: 6px 14px; }
        QPushButton:hover { background: #26262a; }
        QPushButton:pressed { background: #2f2f34; }
        QPushButton:disabled { color: #4d4d54; border-color: #222226; }
        QPushButton[primary="true"] { background: #f2f2f3; color: #0d0d0e; border: 1px solid #f2f2f3; font-weight: 600; }
        QPushButton[primary="true"]:hover { background: #ffffff; }
        QPushButton[primary="true"]:disabled { background: #2a2a2f; color: #4d4d54; border-color: #2a2a2f; }

        QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTextEdit {
            background: #101012; border: 1px solid #26262a; border-radius: 5px; padding: 5px 8px;
            selection-background-color: #3a3a40; }
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QPlainTextEdit:focus { border-color: #5a5a62; }
        QComboBox QAbstractItemView { background: #151517; border: 1px solid #26262a; selection-background-color: #2a2a2f; }
        QCheckBox { spacing: 8px; }

        QTableView { background: #101012; alternate-background-color: #131315; border: 1px solid #26262a;
                     gridline-color: transparent; selection-background-color: #2a2a2f; border-radius: 5px; }
        QTableView::item { padding: 2px 6px; }
        QHeaderView::section { background: #151517; color: #8b8b92; border: none; border-bottom: 1px solid #26262a;
                               padding: 6px 8px; font-weight: 600; }
        QTableCornerButton::section { background: #151517; border: none; }

        QTabWidget::pane { border: 1px solid #26262a; border-radius: 5px; top: -1px; }
        QTabBar::tab { background: transparent; color: #8b8b92; padding: 8px 16px; border: none; border-bottom: 2px solid transparent; }
        QTabBar::tab:hover { color: #f2f2f3; }
        QTabBar::tab:selected { color: #f2f2f3; border-bottom: 2px solid #f2f2f3; }

        QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
        QScrollBar::handle:vertical { background: #2e2e33; border-radius: 5px; min-height: 28px; }
        QScrollBar::handle:vertical:hover { background: #45454c; }
        QScrollBar:horizontal { background: transparent; height: 10px; margin: 0; }
        QScrollBar::handle:horizontal { background: #2e2e33; border-radius: 5px; min-width: 28px; }
        QScrollBar::handle:horizontal:hover { background: #45454c; }
        QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
        QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

        QProgressBar { background: #151517; border: 1px solid #26262a; border-radius: 3px; height: 8px; text-align: center; color: transparent; }
        QProgressBar::chunk { background: #f2f2f3; border-radius: 2px; }
        QStatusBar { background: #09090a; border-top: 1px solid #26262a; }
        QStatusBar::item { border: none; }
        QSplitter::handle { background: #26262a; }
        QToolTip { background: #151517; color: #f2f2f3; border: 1px solid #26262a; }
    )");
}

}  // namespace xrl::ui

