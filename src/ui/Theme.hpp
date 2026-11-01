#pragma once
#include <QApplication>

namespace xrl::ui {

// Applies the dark, minimal theme (Fusion style + palette + stylesheet).
void applyTheme(QApplication& app);

// Colors shared with custom-painted widgets.
struct Colors {
    static constexpr const char* background = "#0d0d0e";
    static constexpr const char* panel = "#151517";
    static constexpr const char* border = "#26262a";
    static constexpr const char* text = "#f2f2f3";
    static constexpr const char* muted = "#8b8b92";
    static constexpr const char* dim = "#4d4d54";
    static constexpr const char* selection = "#2a2a2f";
    static constexpr const char* error = "#d9776f";
};

}  // namespace xrl::ui

