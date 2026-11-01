#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "xrl/strings.hpp"

using namespace xrl;
namespace fs = std::filesystem;

namespace {
class TempFile {
public:
    explicit TempFile(const std::vector<uint8_t>& data) {
        static uint64_t counter = 0;
        const auto id = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = fs::temp_directory_path() /
                ("xrl_strings_" + std::to_string(id) + "_" + std::to_string(++counter) + ".bin");
        std::ofstream out(path_, std::ios::binary);
        if (!out) throw std::runtime_error("could not create strings test fixture");
        if (!data.empty()) out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!out) throw std::runtime_error("could not write strings test fixture");
    }

    ~TempFile() {
        std::error_code ec;
        fs::remove(path_, ec);
    }

    const fs::path& path() const { return path_; }

private:
    fs::path path_;
};

const ExtractedString* findAt(const StringExtractionResult& result, uint64_t offset) {
    for (const auto& entry : result.strings)
        if (entry.offset == offset) return &entry;
    return nullptr;
}

bool hasCategory(const ExtractedString& entry, StringCategory category) {
    return std::find(entry.categories.begin(), entry.categories.end(), category) != entry.categories.end();
}

std::vector<uint8_t> utf16(const std::u16string& text, bool littleEndian) {
    std::vector<uint8_t> bytes;
    for (const char16_t unit : text) {
        const auto value = static_cast<uint16_t>(unit);
        if (littleEndian) {
            bytes.push_back(static_cast<uint8_t>(value & 0xFF));
            bytes.push_back(static_cast<uint8_t>(value >> 8));
        } else {
            bytes.push_back(static_cast<uint8_t>(value >> 8));
            bytes.push_back(static_cast<uint8_t>(value & 0xFF));
        }
    }
    return bytes;
}
}  // namespace

TEST(Strings, ExtractsAsciiUtf8AndClassifiesPatternsAtExactOffsets) {
    const std::string ascii = "https://example.com/a";
    const std::string utf8 = "caf\xC3\xA9-test";
    std::vector<uint8_t> data{0};
    const uint64_t asciiOffset = data.size();
    data.insert(data.end(), ascii.begin(), ascii.end());
    data.push_back(0);
    const uint64_t utf8Offset = data.size();
    data.insert(data.end(), utf8.begin(), utf8.end());
    data.push_back(0);
    const uint64_t emailOffset = data.size();
    const std::string email = "analyst@example.org";
    data.insert(data.end(), email.begin(), email.end());
    data.push_back(0);
    const std::string variables = "%TEMP%/sample.dll";
    const uint64_t variableOffset = data.size();
    data.insert(data.end(), variables.begin(), variables.end());
    const TempFile file(data);

    const auto result = extractStringsFile(file.path());
    ASSERT_TRUE(result.ok) << result.error;
    const auto* url = findAt(result, asciiOffset);
    ASSERT_NE(url, nullptr);
    EXPECT_EQ(url->value, ascii);
    EXPECT_EQ(url->encoding, StringEncoding::Ascii);
    EXPECT_EQ(url->length, ascii.size());
    EXPECT_TRUE(hasCategory(*url, StringCategory::Url));
    EXPECT_TRUE(hasCategory(*url, StringCategory::Domain));

    const auto* unicode = findAt(result, utf8Offset);
    ASSERT_NE(unicode, nullptr);
    EXPECT_EQ(unicode->value, utf8);
    EXPECT_EQ(unicode->encoding, StringEncoding::Utf8);

    const auto* mail = findAt(result, emailOffset);
    ASSERT_NE(mail, nullptr);
    EXPECT_TRUE(hasCategory(*mail, StringCategory::Email));

    const auto* env = findAt(result, variableOffset);
    ASSERT_NE(env, nullptr);
    EXPECT_TRUE(hasCategory(*env, StringCategory::EnvironmentVariable));
    EXPECT_TRUE(hasCategory(*env, StringCategory::Library));
}

TEST(Strings, ExtractsUtf16LittleEndianAndBigEndianWithoutDuplicateRanges) {
    auto little = utf16(u"CreateFileW", true);
    auto big = utf16(u"RegistryValue", false);
    std::vector<uint8_t> data{0};
    const uint64_t littleOffset = data.size();
    data.insert(data.end(), little.begin(), little.end());
    data.push_back(0);
    data.push_back(0);
    const uint64_t bigOffset = data.size();
    data.insert(data.end(), big.begin(), big.end());
    data.push_back(0);
    const TempFile file(data);

    const auto result = extractStringsFile(file.path());
    ASSERT_TRUE(result.ok) << result.error;
    const auto* le = findAt(result, littleOffset);
    ASSERT_NE(le, nullptr);
    EXPECT_EQ(le->value, "CreateFileW");
    EXPECT_EQ(le->length, little.size());
    EXPECT_EQ(le->encoding, StringEncoding::Utf16LE);
    EXPECT_TRUE(hasCategory(*le, StringCategory::ApiName));
    const auto* be = findAt(result, bigOffset);
    ASSERT_NE(be, nullptr);
    EXPECT_EQ(be->value, "RegistryValue");
    EXPECT_EQ(be->length, big.size());
    EXPECT_EQ(be->encoding, StringEncoding::Utf16BE);

    std::set<std::pair<uint64_t, uint64_t>> ranges;
    for (const auto& entry : result.strings) EXPECT_TRUE(ranges.emplace(entry.offset, entry.length).second);
}

TEST(Strings, DecodesUtf16SurrogatePairsToUtf8AndPreservesByteLength) {
    const auto encoded = utf16(u"Start\U0001F642End", true);
    std::vector<uint8_t> data{0};
    const uint64_t offset = data.size();
    data.insert(data.end(), encoded.begin(), encoded.end());
    const TempFile file(data);

    const auto result = extractStringsFile(file.path());
    ASSERT_TRUE(result.ok) << result.error;
    const auto* found = findAt(result, offset);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->value, "Start🙂End");
    EXPECT_EQ(found->encoding, StringEncoding::Utf16LE);
    EXPECT_EQ(found->length, encoded.size());
}

TEST(Strings, HonorsMinimumLengthAndDeduplicatesAsciiUtf8Subsequence) {
    const std::vector<uint8_t> data = {'a', 'b', 'c', 0, 'l', 'o', 'n', 'g', 'e', 'r', '-', 's', 't', 'r', 'i', 'n', 'g', 0};
    const TempFile file(data);
    StringExtractionOptions options;
    options.minLength = 6;

    const auto result = extractStringsFile(file.path(), options);
    ASSERT_TRUE(result.ok) << result.error;
    for (const auto& entry : result.strings) {
        EXPECT_FALSE(entry.offset == 0 && entry.encoding == StringEncoding::Ascii && entry.value == "abc");
    }
    const auto* found = findAt(result, 4);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->value, "longer-string");
    EXPECT_EQ(found->encoding, StringEncoding::Ascii);
    size_t copies = 0;
    for (const auto& entry : result.strings)
        if (entry.offset == 4 && entry.length == found->length) ++copies;
    EXPECT_EQ(copies, 1u);
}

TEST(Strings, FindsUtf8AndUtf16StringsAcrossReadBufferBoundaries) {
    std::vector<uint8_t> data(65'535, 0);
    const std::string utf8 = "A\xc3\xa9" "BC";
    const uint64_t utf8Offset = data.size();
    data.insert(data.end(), utf8.begin(), utf8.end());
    data.push_back(0);
    data.resize(131'071, 0);
    const uint64_t wideOffset = data.size();
    const auto wide = utf16(u"WideText", true);
    data.insert(data.end(), wide.begin(), wide.end());
    const TempFile file(data);

    const auto result = extractStringsFile(file.path());
    ASSERT_TRUE(result.ok) << result.error;
    const auto* narrow = findAt(result, utf8Offset);
    ASSERT_NE(narrow, nullptr);
    EXPECT_EQ(narrow->value, utf8);
    EXPECT_EQ(narrow->encoding, StringEncoding::Utf8);
    const auto* wideText = findAt(result, wideOffset);
    ASSERT_NE(wideText, nullptr);
    EXPECT_EQ(wideText->value, "WideText");
    EXPECT_EQ(wideText->encoding, StringEncoding::Utf16LE);
}

TEST(Strings, ClassifiesPathsRegistryLibraryAddressAndApiNames) {
    const std::vector<std::string> values = {
        "C:\\Windows\\System32\\kernel32.dll",
        "HKLM\\Software\\Xaynx\\Settings",
        "192.168.1.25",
        "CreateFileW",
        "library-name.so.1"};
    std::vector<uint8_t> data;
    std::vector<uint64_t> offsets;
    for (const auto& value : values) {
        offsets.push_back(data.size());
        data.insert(data.end(), value.begin(), value.end());
        data.push_back(0);
    }
    const TempFile file(data);
    const auto result = extractStringsFile(file.path());
    ASSERT_TRUE(result.ok) << result.error;
    ASSERT_NE(findAt(result, offsets[0]), nullptr);
    EXPECT_TRUE(hasCategory(*findAt(result, offsets[0]), StringCategory::FilePath));
    EXPECT_TRUE(hasCategory(*findAt(result, offsets[0]), StringCategory::Library));
    EXPECT_TRUE(hasCategory(*findAt(result, offsets[1]), StringCategory::RegistryPath));
    EXPECT_TRUE(hasCategory(*findAt(result, offsets[2]), StringCategory::IPv4));
    EXPECT_TRUE(hasCategory(*findAt(result, offsets[3]), StringCategory::ApiName));
    EXPECT_TRUE(hasCategory(*findAt(result, offsets[4]), StringCategory::Library));
}

TEST(Strings, LargeFileReportsProgressAndHonorsExplicitResultCaps) {
    std::vector<uint8_t> data(2 * 1024 * 1024, 0);
    const std::string needle = "LargeFileString";
    const uint64_t needleOffset = 1'500'000;
    std::copy(needle.begin(), needle.end(), data.begin() + static_cast<std::ptrdiff_t>(needleOffset));
    const TempFile file(data);
    int lastProgress = -1;
    const auto result = extractStringsFile(file.path(), {},
        [&](int percent, const std::string&) {
            EXPECT_GE(percent, lastProgress);
            lastProgress = percent;
        });
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_NE(findAt(result, needleOffset), nullptr);
    EXPECT_EQ(lastProgress, 100);

    StringExtractionOptions capped;
    capped.minLength = 2;
    capped.maxResults = 1;
    const TempFile many({0, 'a', 'b', 0, 'c', 'd', 0});
    const auto limited = extractStringsFile(many.path(), capped);
    ASSERT_TRUE(limited.ok) << limited.error;
    EXPECT_TRUE(limited.truncated);
    EXPECT_FALSE(limited.warning.empty());
}

TEST(Strings, InvalidPathsCancellationAndExportsAreExplicit) {
    const auto missing = fs::temp_directory_path() / "xrl_strings_missing.bin";
    EXPECT_FALSE(extractStringsFile(missing).ok);
    EXPECT_FALSE(extractStringsFile(fs::temp_directory_path()).ok);

    const TempFile empty({});
    const auto emptyResult = extractStringsFile(empty.path());
    ASSERT_TRUE(emptyResult.ok) << emptyResult.error;
    EXPECT_TRUE(emptyResult.strings.empty());

    const TempFile file({0, 'h', 'e', 'l', 'l', 'o', 0});
    const auto cancelled = extractStringsFile(file.path(), {}, {}, [] { return true; });
    EXPECT_FALSE(cancelled.ok);
    EXPECT_TRUE(cancelled.cancelled);

    const auto result = extractStringsFile(file.path());
    ASSERT_TRUE(result.ok);
    const auto json = Json::parse(renderStringsJsonReport(result));
    ASSERT_TRUE(json.value) << json.error;
    EXPECT_EQ(json.value->find("extracted_string_count")->asInt(), 1);
    EXPECT_NE(renderStringsCsv(result).find("value,offset,length_bytes,encoding,classification"), std::string::npos);

    StringExtractionOptions invalid;
    invalid.minLength = 0;
    EXPECT_FALSE(extractStringsFile(file.path(), invalid).ok);
}
