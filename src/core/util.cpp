#include "xrl/util.hpp"

#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <ctime>
#include <cstdio>

namespace xrl {

std::string hex(uint64_t value, int width) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    do {
        out.insert(out.begin(), digits[value & 0xF]);
        value >>= 4;
    } while (value != 0);
    while (static_cast<int>(out.size()) < width) out.insert(out.begin(), '0');
    return "0x" + out;
}

std::string hexBytes(std::span<const uint8_t> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0xF]);
    }
    return out;
}

double shannonEntropy(std::span<const uint8_t> bytes) {
    if (bytes.empty()) return 0.0;
    std::array<uint64_t, 256> counts{};
    for (uint8_t b : bytes) ++counts[b];
    const double n = static_cast<double>(bytes.size());
    double h = 0.0;
    for (uint64_t c : counts) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / n;
        h -= p * std::log2(p);
    }
    return h;
}

std::string humanSize(uint64_t bytes) {
    static constexpr const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = static_cast<double>(bytes);
    int u = 0;
    while (v >= 1024.0 && u < 4) {
        v /= 1024.0;
        ++u;
    }
    char buf[64];
    if (u == 0)
        std::snprintf(buf, sizeof buf, "%llu B", static_cast<unsigned long long>(bytes));
    else
        std::snprintf(buf, sizeof buf, "%.2f %s (%llu bytes)", v, units[u],
                      static_cast<unsigned long long>(bytes));
    return buf;
}

std::optional<uint64_t> parseNumber(std::string_view text, bool defaultHex) {
    // trim
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.remove_prefix(1);
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) text.remove_suffix(1);
    if (text.empty()) return std::nullopt;

    unsigned base = defaultHex ? 16 : 10;
    if (text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text.remove_prefix(2);
    } else if (!text.empty() && (text.back() == 'h' || text.back() == 'H') && text.size() > 1) {
        base = 16;
        text.remove_suffix(1);
    }
    if (text.empty()) return std::nullopt;

    uint64_t value = 0;
    for (char c : text) {
        unsigned d;
        if (c >= '0' && c <= '9') d = static_cast<unsigned>(c - '0');
        else if (c >= 'a' && c <= 'f') d = static_cast<unsigned>(c - 'a') + 10;
        else if (c >= 'A' && c <= 'F') d = static_cast<unsigned>(c - 'A') + 10;
        else if (c == '_' || c == '\'') continue;  // digit separators
        else return std::nullopt;
        if (d >= base) return std::nullopt;
        if (value > (UINT64_MAX - d) / base) return std::nullopt;  // overflow
        value = value * base + d;
    }
    return value;
}

std::string sanitizeText(std::string_view s) {
    std::string out(s);
    for (char& c : out) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7F) c = '?';
    }
    return out;
}

std::string pathUtf8(const std::filesystem::path& p) {
    const auto u = p.u8string();
    return std::string(reinterpret_cast<const char*>(u.data()), u.size());
}

std::string utcNowIso8601() {
    const std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

}  // namespace xrl
