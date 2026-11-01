#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include "xrl/analyzer.hpp"
#include "xrl/json.hpp"

namespace xrl {

enum class StringEncoding { Ascii, Utf8, Utf16LE, Utf16BE };
enum class StringCategory {
    Url,
    IPv4,
    Email,
    FilePath,
    RegistryPath,
    Domain,
    Library,
    ApiName,
    EnvironmentVariable,
    Other
};

const char* toString(StringEncoding encoding);
const char* toString(StringCategory category);

struct ExtractedString {
    uint64_t offset = 0;
    uint64_t length = 0;
    StringEncoding encoding = StringEncoding::Ascii;
    std::string value;
    std::vector<StringCategory> categories;
};

struct StringExtractionOptions {
    size_t minLength = 4;
    size_t maxStringBytes = 1024 * 1024;
    size_t maxResults = 100'000;
    size_t maxRetainedStringBytes = 32 * 1024 * 1024;
};

struct StringExtractionResult {
    bool ok = false;
    bool cancelled = false;
    bool truncated = false;
    std::string error;
    std::string warning;
    std::string filePath;
    uint64_t fileSize = 0;
    std::string sha256;
    size_t minLength = 0;
    std::vector<ExtractedString> strings;
};

StringExtractionResult extractStringsFile(const std::filesystem::path& path,
                                          const StringExtractionOptions& options = {},
                                          const ProgressFn& progress = {},
                                          const std::function<bool()>& shouldCancel = {});

Json buildStringsJsonReport(const StringExtractionResult& result);
std::string renderStringsJsonReport(const StringExtractionResult& result);
std::string renderStringsCsv(const StringExtractionResult& result);

}  // namespace xrl
