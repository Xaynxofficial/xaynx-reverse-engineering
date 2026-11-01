#pragma once
#include <QString>
#include <filesystem>
#include <string>

namespace xrl::ui {

inline std::filesystem::path toPath(const QString& s) {
#ifdef _WIN32
    return std::filesystem::path(s.toStdWString());
#else
    return std::filesystem::path(s.toStdString());  // UTF-8
#endif
}

inline QString q(const std::string& s) { return QString::fromUtf8(s.data(), static_cast<qsizetype>(s.size())); }
inline std::string utf8(const QString& s) { return s.toStdString(); }

inline QString hex64(quint64 v, int width = 0) {
    return QStringLiteral("0x") + QString::number(v, 16).rightJustified(width, QLatin1Char('0'));
}

}  // namespace xrl::ui

