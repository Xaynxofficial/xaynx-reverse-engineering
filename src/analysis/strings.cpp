#include "xrl/strings.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <sstream>
#include <system_error>
#include <unordered_map>

#include "xrl/util.hpp"
#include "xrl/sha256.hpp"

namespace xrl {
namespace {

constexpr size_t kReadBufferSize = 64 * 1024;

bool isPrintable(uint32_t codepoint) {
    return codepoint >= 0x20 && !(codepoint >= 0x7F && codepoint <= 0x9F) &&
           codepoint <= 0x10FFFF && !(codepoint >= 0xD800 && codepoint <= 0xDFFF);
}

void appendUtf8(std::string& value, uint32_t cp) {
    if (cp <= 0x7F) {
        value.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        value.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        value.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        value.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        value.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        value.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        value.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        value.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        value.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        value.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

char asciiLower(char value) {
    const auto c = static_cast<unsigned char>(value);
    return static_cast<char>(std::tolower(c));
}

std::string lowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), asciiLower);
    return value;
}

bool startsWithInsensitive(const std::string& value, const char* prefix) {
    const size_t length = std::char_traits<char>::length(prefix);
    if (value.size() < length) return false;
    for (size_t i = 0; i < length; ++i)
        if (asciiLower(value[i]) != asciiLower(prefix[i])) return false;
    return true;
}

bool isPathSeparator(char c) { return c == '/' || c == '\\'; }

bool isIPv4(const std::string& value) {
    size_t pos = 0;
    for (int part = 0; part < 4; ++part) {
        if (pos >= value.size()) return false;
        const size_t start = pos;
        unsigned number = 0;
        while (pos < value.size() && value[pos] >= '0' && value[pos] <= '9') {
            if (pos - start >= 3) return false;
            number = number * 10 + static_cast<unsigned>(value[pos] - '0');
            ++pos;
        }
        if (pos == start || number > 255) return false;
        if (part < 3) {
            if (pos >= value.size() || value[pos] != '.') return false;
            ++pos;
        }
    }
    return pos == value.size();
}

bool validDomain(const std::string& host) {
    if (host.size() < 4 || host.size() > 253 || host.front() == '.' || host.back() == '.') return false;
    size_t labelStart = 0;
    size_t lastDot = std::string::npos;
    for (size_t i = 0; i <= host.size(); ++i) {
        if (i != host.size() && host[i] != '.') {
            const char c = host[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
            continue;
        }
        const size_t length = i - labelStart;
        if (length == 0 || length > 63 || host[labelStart] == '-' || host[i - 1] == '-') return false;
        labelStart = i + 1;
        lastDot = i;
    }
    if (lastDot == std::string::npos) return false;
    const size_t tldLength = host.size() - lastDot - 1;
    if (tldLength < 2) return false;
    for (size_t i = lastDot + 1; i < host.size(); ++i)
        if (host[i] < 'a' || host[i] > 'z') return false;
    return true;
}

std::string domainCandidate(const std::string& value) {
    std::string candidate = lowerAscii(value);
    const size_t scheme = candidate.find("://");
    if (scheme != std::string::npos) candidate.erase(0, scheme + 3);
    const size_t at = candidate.rfind('@');
    if (at != std::string::npos) candidate.erase(0, at + 1);
    const size_t end = candidate.find_first_of("/:?#");
    if (end != std::string::npos) candidate.resize(end);
    while (!candidate.empty() && (candidate.back() == '.' || candidate.back() == ',' ||
                                  candidate.back() == ';' || candidate.back() == ')')) {
        candidate.pop_back();
    }
    return candidate;
}

bool hasEnvironmentReference(const std::string& value) {
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '%') {
            const size_t end = value.find('%', i + 1);
            if (end != std::string::npos && end > i + 1) return true;
        } else if (value[i] == '$') {
            if (i + 1 < value.size() && value[i + 1] == '{' &&
                value.find('}', i + 2) != std::string::npos) return true;
            if (i + 1 < value.size() &&
                ((value[i + 1] >= 'A' && value[i + 1] <= 'Z') ||
                 (value[i + 1] >= 'a' && value[i + 1] <= 'z') || value[i + 1] == '_')) return true;
        }
    }
    return false;
}

bool isCommonApi(const std::string& lower) {
    static const std::set<std::string> names = {
        "createfile", "createfilea", "createfilew", "readfile", "writefile", "virtualalloc",
        "virtualprotect", "virtualfree", "loadlibrary", "loadlibrarya", "loadlibraryw",
        "getprocaddress", "regopenkeyex", "regopenkeyexa", "regopenkeyexw", "regqueryvalueex",
        "regsetvalueex", "internetopen", "internetconnect", "winhttpopen", "winhttpsendrequest",
        "socket", "connect", "bind", "listen", "accept", "send", "recv", "execve", "execvp",
        "system", "popen", "fopen", "open", "read", "write", "malloc", "calloc", "free",
        "memcpy", "memmove", "strcmp", "strcpy", "dlopen", "dlsym", "ptrace"};
    std::string name = lower;
    if (!name.empty() && (name.back() == 'a' || name.back() == 'w')) name.pop_back();
    return names.contains(lower) || names.contains(name);
}

std::vector<StringCategory> classify(const std::string& value) {
    std::vector<StringCategory> result;
    auto add = [&](StringCategory category) {
        if (std::find(result.begin(), result.end(), category) == result.end()) result.push_back(category);
    };

    const std::string lower = lowerAscii(value);
    if (startsWithInsensitive(value, "http://") || startsWithInsensitive(value, "https://") ||
        startsWithInsensitive(value, "ftp://")) add(StringCategory::Url);
    if (isIPv4(value)) add(StringCategory::IPv4);
    const size_t at = value.find('@');
    if (at != std::string::npos && at > 0 && value.find('@', at + 1) == std::string::npos) {
        const size_t dot = value.find('.', at + 1);
        if (dot != std::string::npos && dot > at + 1 && dot + 1 < value.size())
            add(StringCategory::Email);
    }

    const bool drivePath = value.size() >= 3 &&
                           ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) &&
                           value[1] == ':' && isPathSeparator(value[2]);
    const bool uncPath = value.size() >= 3 && isPathSeparator(value[0]) &&
                         isPathSeparator(value[1]) && value[2] != ' ';
    const bool absoluteUnixPath = value.size() > 1 && value[0] == '/' && value.find('/', 1) != std::string::npos;
    const bool relativePath = (startsWithInsensitive(value, "./") || startsWithInsensitive(value, "../") ||
                               startsWithInsensitive(value, ".\\") || startsWithInsensitive(value, "..\\")) &&
                              value.find_first_of("/\\") != std::string::npos;
    if (drivePath || uncPath || absoluteUnixPath || relativePath) add(StringCategory::FilePath);

    if (startsWithInsensitive(value, "hkey_") || startsWithInsensitive(value, "hkcu\\") ||
        startsWithInsensitive(value, "hklm\\") || startsWithInsensitive(value, "hkcr\\") ||
        startsWithInsensitive(value, "hku\\") || startsWithInsensitive(value, "hkcc\\"))
        add(StringCategory::RegistryPath);
    if (hasEnvironmentReference(value)) add(StringCategory::EnvironmentVariable);

    const bool library = lower.ends_with(".dll") || lower.ends_with(".dylib") ||
                         lower.ends_with(".so") || lower.find(".so.") != std::string::npos;
    if (library) add(StringCategory::Library);
    const std::string host = domainCandidate(value);
    if (validDomain(host)) add(StringCategory::Domain);
    if (isCommonApi(lower)) add(StringCategory::ApiName);
    if (result.empty()) add(StringCategory::Other);
    return result;
}

struct Candidate {
    ExtractedString value;
    unsigned confidence = 0;
};

class Collector {
public:
    Collector(StringExtractionResult& result, const StringExtractionOptions& options)
        : result_(result), options_(options) {}

    bool add(uint64_t offset, uint64_t length, StringEncoding encoding, std::string value,
             unsigned confidence = 0) {
        if (value.empty() || offset >= result_.fileSize || length == 0 || length > result_.fileSize - offset) {
            result_.error = "Invalid string range produced during extraction.";
            return false;
        }
        const auto key = std::make_pair(offset, length);
        const auto existing = candidates_.find(key);
        if (existing != candidates_.end()) {
            if (confidence > existing->second.confidence) {
                existing->second.value = {offset, length, encoding, std::move(value), {}};
                existing->second.confidence = confidence;
            }
            return true;
        }
        const bool wideEncoding = encoding == StringEncoding::Utf16LE || encoding == StringEncoding::Utf16BE;
        if (wideEncoding) {
            const auto priorKey = wideCandidateByOffset_.find(offset);
            if (priorKey != wideCandidateByOffset_.end()) {
                auto prior = candidates_.find(priorKey->second);
                if (prior != candidates_.end()) {
                    if (prior->second.confidence >= confidence) return true;
                    retainedBytes_ -= prior->second.value.value.size();
                    candidates_.erase(prior);
                }
                wideCandidateByOffset_.erase(priorKey);
            }
        }
        if (candidates_.size() >= options_.maxResults ||
            value.size() > options_.maxRetainedStringBytes - retainedBytes_) {
            result_.truncated = true;
            result_.warning = candidates_.size() >= options_.maxResults
                                  ? "String result limit reached; remaining file data was not scanned."
                                  : "Retained string data limit reached; remaining file data was not scanned.";
            return false;
        }
        retainedBytes_ += value.size();
        candidates_.emplace(key, Candidate{{offset, length, encoding, std::move(value), {}}, confidence});
        if (wideEncoding) wideCandidateByOffset_.emplace(offset, key);
        return true;
    }

    void finish() {
        result_.strings.reserve(candidates_.size());
        for (auto& [range, candidate] : candidates_) {
            (void)range;
            candidate.value.categories = classify(candidate.value.value);
            result_.strings.push_back(std::move(candidate.value));
        }
        std::sort(result_.strings.begin(), result_.strings.end(), [](const ExtractedString& a, const ExtractedString& b) {
            if (a.offset != b.offset) return a.offset < b.offset;
            if (a.length != b.length) return a.length < b.length;
            return static_cast<int>(a.encoding) < static_cast<int>(b.encoding);
        });
    }

private:
    StringExtractionResult& result_;
    const StringExtractionOptions& options_;
    std::map<std::pair<uint64_t, uint64_t>, Candidate> candidates_;
    std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> wideCandidateByOffset_;
    size_t retainedBytes_ = 0;
};

class Utf8Scanner {
public:
    Utf8Scanner(Collector& collector, const StringExtractionOptions& options)
        : collector_(collector), options_(options) {}

    bool feed(uint8_t byte, uint64_t offset) {
        bool retry = true;
        while (retry) {
            retry = false;
            if (pending_.empty()) {
                if (byte <= 0x7F) {
                    if (isPrintable(byte)) return append(byte, offset, 1, byte >= 0x80);
                    return flush();
                }
                if (byte >= 0xC2 && byte <= 0xDF) expected_ = 2;
                else if (byte >= 0xE0 && byte <= 0xEF) expected_ = 3;
                else if (byte >= 0xF0 && byte <= 0xF4) expected_ = 4;
                else return flush();
                pending_.push_back(byte);
                pendingOffset_ = offset;
                return true;
            }
            if ((byte & 0xC0) != 0x80) {
                pending_.clear();
                expected_ = 0;
                if (!flush()) return false;
                retry = true;
                continue;
            }
            pending_.push_back(byte);
            if (pending_.size() < expected_) return true;

            const uint32_t cp = decodePending();
            const uint32_t minimumCodepoint = expected_ == 2 ? 0x80 : expected_ == 3 ? 0x800 : 0x10000;
            const bool valid = cp >= minimumCodepoint && isPrintable(cp);
            if (valid) {
                for (size_t i = 0; i < pending_.size(); ++i)
                    if (!appendByte(pending_[i], pendingOffset_ + static_cast<uint64_t>(i))) return false;
                ++characters_;
                hasNonAscii_ = true;
            } else if (!flush()) {
                return false;
            }
            pending_.clear();
            expected_ = 0;
        }
        return true;
    }

    bool finish() {
        pending_.clear();
        return flush();
    }

private:
    uint32_t decodePending() const {
        uint32_t cp = pending_[0] & (expected_ == 2 ? 0x1F : expected_ == 3 ? 0x0F : 0x07);
        for (size_t i = 1; i < pending_.size(); ++i) cp = (cp << 6) | (pending_[i] & 0x3F);
        return cp;
    }

    bool append(uint32_t cp, uint64_t offset, uint64_t bytes, bool nonAscii) {
        if (value_.empty()) offset_ = offset;
        if (!appendByte(static_cast<uint8_t>(cp), offset)) return false;
        ++characters_;
        hasNonAscii_ = hasNonAscii_ || nonAscii;
        end_ = offset + bytes;
        return true;
    }

    bool appendByte(uint8_t byte, uint64_t offset) {
        if (value_.empty()) offset_ = offset;
        if (value_.size() >= options_.maxStringBytes) {
            overlong_ = true;
            value_.clear();
            characters_ = 0;
            return true;
        }
        if (!overlong_) value_.push_back(static_cast<char>(byte));
        end_ = offset + 1;
        return true;
    }

    bool flush() {
        if (!overlong_ && characters_ >= options_.minLength && !value_.empty()) {
            if (!collector_.add(offset_, end_ - offset_, hasNonAscii_ ? StringEncoding::Utf8 : StringEncoding::Ascii,
                                std::move(value_))) return false;
        }
        value_.clear();
        characters_ = 0;
        hasNonAscii_ = false;
        overlong_ = false;
        return true;
    }

    Collector& collector_;
    const StringExtractionOptions& options_;
    std::string value_;
    std::vector<uint8_t> pending_;
    uint64_t offset_ = 0;
    uint64_t end_ = 0;
    uint64_t pendingOffset_ = 0;
    size_t characters_ = 0;
    size_t expected_ = 0;
    bool hasNonAscii_ = false;
    bool overlong_ = false;
};

class Utf16Scanner {
public:
    Utf16Scanner(Collector& collector, const StringExtractionOptions& options, bool littleEndian, uint64_t parity)
        : collector_(collector), options_(options), littleEndian_(littleEndian), parity_(parity) {}

    bool feed(uint8_t byte, uint64_t offset) {
        if (!haveFirst_) {
            if (offset < parity_ || (offset & 1u) != parity_) return true;
            first_ = byte;
            firstOffset_ = offset;
            haveFirst_ = true;
            return true;
        }
        if (offset != firstOffset_ + 1) {
            haveFirst_ = false;
            return true;
        }
        const uint8_t firstByte = first_;
        const uint16_t unit = littleEndian_
                                  ? static_cast<uint16_t>(first_ | (static_cast<uint16_t>(byte) << 8))
                                  : static_cast<uint16_t>((static_cast<uint16_t>(first_) << 8) | byte);
        const uint64_t unitOffset = firstOffset_;
        haveFirst_ = false;
        return acceptUnit(unit, unitOffset, firstByte, byte);
    }

    bool finish() {
        haveFirst_ = false;
        if (highSurrogate_ != 0) {
            highSurrogate_ = 0;
            return flush();
        }
        return flush();
    }

private:
    bool acceptUnit(uint16_t unit, uint64_t offset, uint8_t firstByte, uint8_t secondByte) {
        if (highSurrogate_ != 0) {
            if (unit >= 0xDC00 && unit <= 0xDFFF) {
                const uint32_t cp = 0x10000 + ((static_cast<uint32_t>(highSurrogate_ - 0xD800) << 10) |
                                               static_cast<uint32_t>(unit - 0xDC00));
                const uint64_t start = highOffset_;
                highSurrogate_ = 0;
                return appendCodepoint(cp, start, offset + 2, false);
            }
            highSurrogate_ = 0;
            if (!flush()) return false;
        }
        if (unit >= 0xD800 && unit <= 0xDBFF) {
            highSurrogate_ = unit;
            highOffset_ = offset;
            return true;
        }
        if (unit >= 0xDC00 && unit <= 0xDFFF) return flush();
        if (!isPrintable(unit)) return flush();
        const bool expectedZero = littleEndian_ ? secondByte == 0 : firstByte == 0;
        return appendCodepoint(unit, offset, offset + 2, expectedZero);
    }

    bool appendCodepoint(uint32_t cp, uint64_t start, uint64_t end, bool expectedZero) {
        if (value_.empty()) start_ = start;
        if (value_.size() + 4 > options_.maxStringBytes || end - start_ > options_.maxStringBytes) {
            overlong_ = true;
            value_.clear();
            characters_ = 0;
            end_ = end;
            return true;
        }
        if (!overlong_) appendUtf8(value_, cp);
        ++characters_;
        end_ = end;
        if (cp < 0x80 && expectedZero) ++confidence_;
        return true;
    }

    bool flush() {
        if (!overlong_ && characters_ >= options_.minLength && !value_.empty()) {
            if (!collector_.add(start_, end_ - start_,
                                littleEndian_ ? StringEncoding::Utf16LE : StringEncoding::Utf16BE,
                                std::move(value_),
                                characters_ == 0 ? 0 : confidence_ * 1000u / static_cast<unsigned>(characters_)))
                return false;
        }
        value_.clear();
        characters_ = 0;
        confidence_ = 0;
        overlong_ = false;
        return true;
    }

    Collector& collector_;
    const StringExtractionOptions& options_;
    bool littleEndian_;
    uint64_t parity_;
    bool haveFirst_ = false;
    uint8_t first_ = 0;
    uint64_t firstOffset_ = 0;
    uint16_t highSurrogate_ = 0;
    uint64_t highOffset_ = 0;
    uint64_t start_ = 0;
    uint64_t end_ = 0;
    size_t characters_ = 0;
    unsigned confidence_ = 0;
    std::string value_;
    bool overlong_ = false;
};

void report(const ProgressFn& progress, int percent) {
    if (progress) progress(percent, "Extracting strings");
}

}  // namespace

const char* toString(StringEncoding encoding) {
    switch (encoding) {
        case StringEncoding::Ascii: return "ASCII";
        case StringEncoding::Utf8: return "UTF-8";
        case StringEncoding::Utf16LE: return "UTF-16 LE";
        case StringEncoding::Utf16BE: return "UTF-16 BE";
    }
    return "Unknown";
}

const char* toString(StringCategory category) {
    switch (category) {
        case StringCategory::Url: return "URL";
        case StringCategory::IPv4: return "IPv4";
        case StringCategory::Email: return "Email";
        case StringCategory::FilePath: return "File path";
        case StringCategory::RegistryPath: return "Registry path";
        case StringCategory::Domain: return "Domain";
        case StringCategory::Library: return "Library";
        case StringCategory::ApiName: return "API / function";
        case StringCategory::EnvironmentVariable: return "Environment variable";
        case StringCategory::Other: return "Other";
    }
    return "Other";
}

StringExtractionResult extractStringsFile(const std::filesystem::path& path,
                                          const StringExtractionOptions& options,
                                          const ProgressFn& progress,
                                          const std::function<bool()>& shouldCancel) {
    StringExtractionResult result;
    result.filePath = pathUtf8(path);
    result.minLength = options.minLength;
    if (options.minLength == 0 || options.maxStringBytes == 0 || options.maxResults == 0 ||
        options.maxRetainedStringBytes == 0) {
        result.error = "String extraction limits must all be greater than zero.";
        return result;
    }
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) {
        result.error = ec ? "Cannot access file: " + ec.message() : "Not a regular file.";
        return result;
    }
    const uint64_t size = std::filesystem::file_size(path, ec);
    if (ec) {
        result.error = "Cannot determine file size: " + ec.message();
        return result;
    }
    result.fileSize = size;
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        result.error = "Cannot open file for reading.";
        return result;
    }

    Collector collector(result, options);
    Utf8Scanner utf8(collector, options);
    std::array<Utf16Scanner, 4> utf16 = {Utf16Scanner(collector, options, true, 0),
                                         Utf16Scanner(collector, options, true, 1),
                                         Utf16Scanner(collector, options, false, 0),
                                         Utf16Scanner(collector, options, false, 1)};
    std::array<uint8_t, kReadBufferSize> buffer{};
    Sha256 sha;
    uint64_t offset = 0;
    report(progress, 0);
    try {
        while (offset < size) {
            if (shouldCancel && shouldCancel()) {
                result.cancelled = true;
                result.error = "String extraction cancelled.";
                result.strings.clear();
                return result;
            }
            const auto amount = static_cast<std::streamsize>(
                std::min<uint64_t>(size - offset, static_cast<uint64_t>(buffer.size())));
            input.read(reinterpret_cast<char*>(buffer.data()), amount);
            if (input.gcount() != amount) {
                result.error = "Short read: the file changed or could not be fully read.";
                return result;
            }
            const size_t bytesRead = static_cast<size_t>(amount);
            sha.update(std::span<const uint8_t>(buffer.data(), bytesRead));
            for (size_t i = 0; i < bytesRead; ++i) {
                const uint64_t absolute = offset + static_cast<uint64_t>(i);
                if (!utf8.feed(buffer[i], absolute)) break;
                for (auto& scanner : utf16) {
                    if (!scanner.feed(buffer[i], absolute)) break;
                }
                if (result.truncated || !result.error.empty()) break;
            }
            if (result.truncated || !result.error.empty()) break;
            offset += static_cast<uint64_t>(amount);
            report(progress, size == 0 ? 100 : static_cast<int>(
                (static_cast<long double>(offset) * 100.0L) / static_cast<long double>(size)));
        }
    } catch (const std::bad_alloc&) {
        result.error = "Not enough memory to store extracted strings.";
        return result;
    } catch (const std::length_error&) {
        result.error = "String extraction exceeded an implementation limit.";
        return result;
    }

    if (!result.truncated && result.error.empty()) {
        if (!utf8.finish()) {
            if (result.error.empty() && !result.truncated) result.error = "Failed to finalize extracted strings.";
        }
        for (auto& scanner : utf16) {
            if (!scanner.finish()) {
                if (result.error.empty() && !result.truncated) result.error = "Failed to finalize extracted strings.";
                break;
            }
        }
    }
    if (!result.error.empty()) return result;
    if (!result.truncated && offset == size) {
        if (input.peek() != std::char_traits<char>::eof()) {
            result.error = "The file grew while it was being analysed.";
            return result;
        }
        if (input.bad()) {
            result.error = "An I/O error occurred while reading the file.";
            return result;
        }
        result.sha256 = hexBytes(sha.finish());
    }
    collector.finish();
    result.ok = true;
    report(progress, 100);
    return result;
}

Json buildStringsJsonReport(const StringExtractionResult& result) {
    Json report = Json::object();
    report.set("schema_version", "1.0");
    report.set("status", result.ok ? (result.truncated ? "truncated" : "complete")
                                   : (result.cancelled ? "cancelled" : "error"));
    report.set("error", result.error.empty() ? Json() : Json(result.error));
    report.set("warning", result.warning.empty() ? Json() : Json(result.warning));
    report.set("file_path", result.filePath);
    report.set("file_size_bytes", result.ok ? Json(result.fileSize) : Json());
    report.set("sha256", result.sha256.empty() ? Json() : Json(result.sha256));
    report.set("minimum_string_length", static_cast<uint64_t>(result.minLength));
    report.set("extracted_string_count", result.ok ? Json(static_cast<uint64_t>(result.strings.size())) : Json());
    Json strings = Json::array();
    for (const auto& entry : result.strings) {
        Json item = Json::object();
        item.set("value", entry.value);
        item.set("offset", entry.offset);
        item.set("length_bytes", entry.length);
        item.set("encoding", toString(entry.encoding));
        Json categories = Json::array();
        for (const auto category : entry.categories) categories.push(toString(category));
        item.set("classification", std::move(categories));
        strings.push(std::move(item));
    }
    report.set("strings", std::move(strings));
    return report;
}

std::string renderStringsJsonReport(const StringExtractionResult& result) {
    return buildStringsJsonReport(result).dump(2);
}

std::string renderStringsCsv(const StringExtractionResult& result) {
    std::ostringstream output;
    output << "value,offset,length_bytes,encoding,classification\n";
    for (const auto& entry : result.strings) {
        auto csv = [](const std::string& value) {
            std::string escaped = "\"";
            for (const char c : value) {
                if (c == '"') escaped.push_back('"');
                escaped.push_back(c);
            }
            escaped.push_back('"');
            return escaped;
        };
        std::string categories;
        for (size_t i = 0; i < entry.categories.size(); ++i) {
            if (i) categories += "; ";
            categories += toString(entry.categories[i]);
        }
        output << csv(entry.value) << ',' << entry.offset << ',' << entry.length << ','
               << csv(toString(entry.encoding)) << ',' << csv(categories) << '\n';
    }
    return output.str();
}

}  // namespace xrl
