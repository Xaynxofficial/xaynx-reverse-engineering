#include "xrl/json.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <limits>

namespace xrl {

Json::Json(uint64_t v) {
    if (v <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        type_ = Type::Int;
        i_ = static_cast<int64_t>(v);
    } else {
        type_ = Type::Double;
        d_ = static_cast<double>(v);
    }
}

int64_t Json::asInt(int64_t def) const {
    if (type_ == Type::Int) return i_;
    if (type_ == Type::Double) return static_cast<int64_t>(d_);
    return def;
}
double Json::asDouble(double def) const {
    if (type_ == Type::Double) return d_;
    if (type_ == Type::Int) return static_cast<double>(i_);
    return def;
}

Json& Json::push(Json v) {
    arr_.push_back(std::move(v));
    return arr_.back();
}
Json& Json::set(std::string key, Json v) {
    obj_.emplace_back(std::move(key), std::move(v));
    return obj_.back().second;
}
const Json* Json::find(std::string_view key) const {
    if (type_ != Type::Object) return nullptr;
    for (const auto& [k, v] : obj_)
        if (k == key) return &v;
    return nullptr;
}

namespace {

// Appends `s` as a JSON string. Invalid UTF-8 bytes (possible in names taken from
// untrusted binaries) are replaced with U+FFFD so the output is always valid JSON.
void escapeInto(std::string& out, const std::string& s) {
    static constexpr char digits[] = "0123456789abcdef";
    out.push_back('"');
    const size_t n = s.size();
    for (size_t i = 0; i < n;) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                default:
                    if (c < 0x20 || c == 0x7F) {
                        out += "\\u00";
                        out.push_back(digits[c >> 4]);
                        out.push_back(digits[c & 0xF]);
                    } else {
                        out.push_back(static_cast<char>(c));
                    }
            }
            ++i;
            continue;
        }
        // multi-byte sequence validation
        size_t len = 0;
        uint32_t cp = 0;
        if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
        bool ok = len != 0 && i + len <= n;
        for (size_t k = 1; ok && k < len; ++k) {
            const auto cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) ok = false;
            else cp = (cp << 6) | (cc & 0x3F);
        }
        if (ok) {
            const uint32_t minCp = len == 2 ? 0x80 : len == 3 ? 0x800 : 0x10000;
            if (cp < minCp || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) ok = false;
        }
        if (ok) {
            out.append(s, i, len);
            i += len;
        } else {
            out += "\xEF\xBF\xBD";
            ++i;
        }
    }
    out.push_back('"');
}

}  // namespace

void Json::dumpTo(std::string& out, int indent, int depth) const {
    const bool pretty = indent >= 0;
    auto nl = [&](int d) {
        if (!pretty) return;
        out.push_back('\n');
        out.append(static_cast<size_t>(d * indent), ' ');
    };
    switch (type_) {
        case Type::Null: out += "null"; break;
        case Type::Bool: out += b_ ? "true" : "false"; break;
        case Type::Int: out += std::to_string(i_); break;
        case Type::Double: {
            if (!std::isfinite(d_)) { out += "null"; break; }  // JSON has no NaN/Inf
            char buf[40];
            std::snprintf(buf, sizeof buf, "%.17g", d_);
            out += buf;
            break;
        }
        case Type::String: escapeInto(out, s_); break;
        case Type::Array:
            if (arr_.empty()) { out += "[]"; break; }
            out.push_back('[');
            for (size_t i = 0; i < arr_.size(); ++i) {
                if (i) out.push_back(',');
                nl(depth + 1);
                arr_[i].dumpTo(out, indent, depth + 1);
            }
            nl(depth);
            out.push_back(']');
            break;
        case Type::Object:
            if (obj_.empty()) { out += "{}"; break; }
            out.push_back('{');
            for (size_t i = 0; i < obj_.size(); ++i) {
                if (i) out.push_back(',');
                nl(depth + 1);
                escapeInto(out, obj_[i].first);
                out += pretty ? ": " : ":";
                obj_[i].second.dumpTo(out, indent, depth + 1);
            }
            nl(depth);
            out.push_back('}');
            break;
    }
}

std::string Json::dump(int indent) const {
    std::string out;
    dumpTo(out, indent, 0);
    return out;
}

// ------------------------------------------------------------------ parser
namespace {

struct Parser {
    std::string_view t;
    size_t p = 0;
    std::string err;

    bool fail(const char* msg) {
        if (err.empty()) err = std::string(msg) + " at byte " + std::to_string(p);
        return false;
    }
    void ws() {
        while (p < t.size() && (t[p] == ' ' || t[p] == '\t' || t[p] == '\n' || t[p] == '\r')) ++p;
    }
    bool lit(std::string_view w) {
        if (t.substr(p, w.size()) == w) { p += w.size(); return true; }
        return false;
    }
    static void utf8(std::string& s, uint32_t cp) {
        if (cp < 0x80) s.push_back(static_cast<char>(cp));
        else if (cp < 0x800) {
            s.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            s.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            s.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            s.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            s.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            s.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    bool hex4(uint32_t& v) {
        if (p + 4 > t.size()) return fail("Truncated \\u escape");
        v = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = t[p++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
            else return fail("Bad \\u escape");
        }
        return true;
    }
    bool str(std::string& out) {
        if (p >= t.size() || t[p] != '"') return fail("Expected string");
        ++p;
        while (p < t.size()) {
            const auto c = static_cast<unsigned char>(t[p++]);
            if (c == '"') return true;
            if (c < 0x20) return fail("Control character in string");
            if (c != '\\') { out.push_back(static_cast<char>(c)); continue; }
            if (p >= t.size()) break;
            const char e = t[p++];
            switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    uint32_t cp;
                    if (!hex4(cp)) return false;
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        uint32_t lo;
                        if (!lit("\\u") || !hex4(lo) || lo < 0xDC00 || lo > 0xDFFF)
                            return fail("Invalid surrogate pair");
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        return fail("Lone low surrogate");
                    }
                    utf8(out, cp);
                    break;
                }
                default: return fail("Bad escape");
            }
        }
        return fail("Unterminated string");
    }
    bool number(Json& out) {
        const size_t start = p;
        bool isInt = true;
        if (p < t.size() && t[p] == '-') ++p;
        if (p >= t.size()) return fail("Bad number");
        if (t[p] == '0') ++p;
        else if (t[p] >= '1' && t[p] <= '9') while (p < t.size() && t[p] >= '0' && t[p] <= '9') ++p;
        else return fail("Bad number");
        if (p < t.size() && t[p] == '.') {
            isInt = false; ++p;
            const size_t s = p;
            while (p < t.size() && t[p] >= '0' && t[p] <= '9') ++p;
            if (p == s) return fail("Bad fraction");
        }
        if (p < t.size() && (t[p] == 'e' || t[p] == 'E')) {
            isInt = false; ++p;
            if (p < t.size() && (t[p] == '+' || t[p] == '-')) ++p;
            const size_t s = p;
            while (p < t.size() && t[p] >= '0' && t[p] <= '9') ++p;
            if (p == s) return fail("Bad exponent");
        }
        const std::string num(t.substr(start, p - start));
        if (isInt) {
            char* end = nullptr;
            errno = 0;
            const long long v = std::strtoll(num.c_str(), &end, 10);
            if (errno == 0) { out = Json(static_cast<int64_t>(v)); return true; }
        }
        out = Json(std::strtod(num.c_str(), nullptr));
        return true;
    }
    bool value(Json& out, int depth) {
        if (depth > 128) return fail("Nesting too deep");
        ws();
        if (p >= t.size()) return fail("Unexpected end of input");
        const char c = t[p];
        if (c == '{') {
            ++p;
            out = Json::object();
            ws();
            if (p < t.size() && t[p] == '}') { ++p; return true; }
            for (;;) {
                ws();
                std::string key;
                if (!str(key)) return false;
                ws();
                if (p >= t.size() || t[p] != ':') return fail("Expected ':'");
                ++p;
                Json v;
                if (!value(v, depth + 1)) return false;
                out.set(std::move(key), std::move(v));
                ws();
                if (p < t.size() && t[p] == ',') { ++p; continue; }
                if (p < t.size() && t[p] == '}') { ++p; return true; }
                return fail("Expected ',' or '}'");
            }
        }
        if (c == '[') {
            ++p;
            out = Json::array();
            ws();
            if (p < t.size() && t[p] == ']') { ++p; return true; }
            for (;;) {
                Json v;
                if (!value(v, depth + 1)) return false;
                out.push(std::move(v));
                ws();
                if (p < t.size() && t[p] == ',') { ++p; continue; }
                if (p < t.size() && t[p] == ']') { ++p; return true; }
                return fail("Expected ',' or ']'");
            }
        }
        if (c == '"') {
            std::string s;
            if (!str(s)) return false;
            out = Json(std::move(s));
            return true;
        }
        if (lit("true")) { out = Json(true); return true; }
        if (lit("false")) { out = Json(false); return true; }
        if (lit("null")) { out = Json(); return true; }
        return number(out);
    }
};

}  // namespace

Json::ParseResult Json::parse(std::string_view text) {
    Parser ps;
    ps.t = text;
    Json v;
    if (!ps.value(v, 0)) return {std::nullopt, ps.err};
    ps.ws();
    if (ps.p != text.size()) return {std::nullopt, "Trailing characters after JSON value at byte " + std::to_string(ps.p)};
    return {std::move(v), {}};
}

}  // namespace xrl
