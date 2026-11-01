#pragma once
// Bounds-checked little/big-endian reader. Every access validates offset + length
// without risk of integer overflow and throws ParseError on violation.
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

#include "xrl/util.hpp"

namespace xrl {

class ParseError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class Reader {
public:
    explicit Reader(std::span<const uint8_t> data, bool little = true) : d_(data), le_(little) {}

    uint64_t size() const { return d_.size(); }
    void setLittleEndian(bool le) { le_ = le; }
    bool littleEndian() const { return le_; }

    bool inRange(uint64_t off, uint64_t len) const { return off <= size() && len <= size() - off; }

    void require(uint64_t off, uint64_t len, const char* what = "data") const {
        if (!inRange(off, len))
            throw ParseError(std::string("Truncated or out-of-range read of ") + what + " at offset " +
                             hex(off) + " (length " + std::to_string(len) + ", file size " +
                             std::to_string(size()) + ")");
    }

    template <class T>
    T read(uint64_t off, const char* what = "field") const {
        static_assert(std::is_unsigned_v<T>);
        require(off, sizeof(T), what);
        T v = 0;
        for (size_t i = 0; i < sizeof(T); ++i) {
            const T byte = d_[static_cast<size_t>(off) + i];
            const size_t shift = le_ ? i : sizeof(T) - 1 - i;
            v = static_cast<T>(v | static_cast<T>(byte << (8 * shift)));
        }
        return v;
    }
    uint8_t u8(uint64_t off, const char* what = "field") const { return read<uint8_t>(off, what); }
    uint16_t u16(uint64_t off, const char* what = "field") const { return read<uint16_t>(off, what); }
    uint32_t u32(uint64_t off, const char* what = "field") const { return read<uint32_t>(off, what); }
    uint64_t u64(uint64_t off, const char* what = "field") const { return read<uint64_t>(off, what); }

    std::span<const uint8_t> bytes(uint64_t off, uint64_t len, const char* what = "data") const {
        require(off, len, what);
        return d_.subspan(static_cast<size_t>(off), static_cast<size_t>(len));
    }

    // NUL-terminated string starting at `off`, never reading past `maxLen` bytes or the end of data.
    std::string cstring(uint64_t off, size_t maxLen = 1024) const {
        require(off, 0, "string");
        std::string s;
        for (uint64_t i = off; i < size() && s.size() < maxLen; ++i) {
            const char c = static_cast<char>(d_[static_cast<size_t>(i)]);
            if (c == '\0') break;
            s.push_back(c);
        }
        return sanitizeText(s);
    }

    // Fixed-width, possibly non-terminated field (e.g. 8-byte PE section names).
    std::string fixedString(uint64_t off, size_t len) const {
        const auto b = bytes(off, len, "fixed string");
        std::string s;
        for (uint8_t c : b) {
            if (c == 0) break;
            s.push_back(static_cast<char>(c));
        }
        return sanitizeText(s);
    }

private:
    std::span<const uint8_t> d_;
    bool le_;
};

}  // namespace xrl

