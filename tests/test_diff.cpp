#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <vector>

#include "fixtures.hpp"
#include "xrl/analyzer.hpp"
#include "xrl/diff.hpp"

using namespace xrl;
namespace fs = std::filesystem;

namespace {
struct ScopedTempFile {
    fs::path path;
    explicit ScopedTempFile(const std::string& name, const std::vector<uint8_t>& data) {
        path = fs::temp_directory_path() / ("xrl_diff_test_" + name);
        std::ofstream out(path, std::ios::binary);
        if (!data.empty()) {
            out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        }
    }
    ~ScopedTempFile() {
        std::error_code ec;
        fs::remove(path, ec);
    }
};
}  // namespace

TEST(Diff, IdenticalEmptyBuffers) {
    const std::vector<uint8_t> a, b;
    const auto diffs = computeByteDiff(a, b);
    EXPECT_TRUE(diffs.empty());
}

TEST(Diff, IdenticalNonEmptyBuffers) {
    const std::vector<uint8_t> a = {1, 2, 3, 4, 5, 6, 7, 8};
    const std::vector<uint8_t> b = a;
    const auto diffs = computeByteDiff(a, b);
    EXPECT_TRUE(diffs.empty());
}

TEST(Diff, SingleByteChangeAtStart) {
    const std::vector<uint8_t> a = {0xAA, 2, 3, 4, 5};
    const std::vector<uint8_t> b = {0xBB, 2, 3, 4, 5};
    const auto diffs = computeByteDiff(a, b);
    ASSERT_EQ(diffs.size(), 1u);
    EXPECT_EQ(diffs[0].kind, DiffKind::Modified);
    EXPECT_EQ(diffs[0].offsetA, 0u);
    EXPECT_EQ(diffs[0].sizeA, 1u);
    EXPECT_EQ(diffs[0].offsetB, 0u);
    EXPECT_EQ(diffs[0].sizeB, 1u);
}

TEST(Diff, SingleByteChangeInMiddle) {
    const std::vector<uint8_t> a = {1, 2, 0x11, 4, 5};
    const std::vector<uint8_t> b = {1, 2, 0x22, 4, 5};
    const auto diffs = computeByteDiff(a, b);
    ASSERT_EQ(diffs.size(), 1u);
    EXPECT_EQ(diffs[0].kind, DiffKind::Modified);
    EXPECT_EQ(diffs[0].offsetA, 2u);
    EXPECT_EQ(diffs[0].sizeA, 1u);
    EXPECT_EQ(diffs[0].offsetB, 2u);
    EXPECT_EQ(diffs[0].sizeB, 1u);
}

TEST(Diff, SingleByteChangeAtEnd) {
    const std::vector<uint8_t> a = {1, 2, 3, 4, 0x99};
    const std::vector<uint8_t> b = {1, 2, 3, 4, 0x88};
    const auto diffs = computeByteDiff(a, b);
    ASSERT_EQ(diffs.size(), 1u);
    EXPECT_EQ(diffs[0].kind, DiffKind::Modified);
    EXPECT_EQ(diffs[0].offsetA, 4u);
    EXPECT_EQ(diffs[0].sizeA, 1u);
}

TEST(Diff, DisjointDifferencesAreDetected) {
    const std::vector<uint8_t> a(200, 0x00);
    std::vector<uint8_t> b = a;
    b[10] = 0xFF;
    b[150] = 0xEE;
    const auto diffs = computeByteDiff(a, b);
    ASSERT_EQ(diffs.size(), 2u);
    EXPECT_EQ(diffs[0].offsetA, 10u);
    EXPECT_EQ(diffs[1].offsetA, 150u);
}

TEST(Diff, InsertedBytes) {
    // 4 bytes inserted in the middle
    const std::vector<uint8_t> a = {'A', 'B', 'C', 'D', 'E'};
    const std::vector<uint8_t> b = {'A', 'B', 'X', 'Y', 'Z', 'W', 'C', 'D', 'E'};
    const auto diffs = computeByteDiff(a, b);
    ASSERT_EQ(diffs.size(), 1u);
    EXPECT_EQ(diffs[0].kind, DiffKind::Inserted);
    EXPECT_EQ(diffs[0].offsetA, 2u);
    EXPECT_EQ(diffs[0].sizeA, 0u);
    EXPECT_EQ(diffs[0].offsetB, 2u);
    EXPECT_EQ(diffs[0].sizeB, 4u);
}

TEST(Diff, DeletedBytes) {
    // 3 bytes deleted from middle
    const std::vector<uint8_t> a = {'H', 'E', 'L', 'L', 'O', ' ', 'W', 'O', 'R', 'L', 'D'};
    const std::vector<uint8_t> b = {'H', 'E', 'L', 'L', 'O', 'R', 'L', 'D'};
    const auto diffs = computeByteDiff(a, b);
    ASSERT_EQ(diffs.size(), 1u);
    EXPECT_EQ(diffs[0].kind, DiffKind::Deleted);
    EXPECT_EQ(diffs[0].offsetA, 5u);
    EXPECT_EQ(diffs[0].sizeA, 3u);
    EXPECT_EQ(diffs[0].offsetB, 5u);
    EXPECT_EQ(diffs[0].sizeB, 0u);
}

TEST(Diff, DifferentFileSizesEntirely) {
    const std::vector<uint8_t> a(10, 0xAA);
    const std::vector<uint8_t> b(30, 0xBB);
    const auto diffs = computeByteDiff(a, b);
    ASSERT_FALSE(diffs.empty());
}

TEST(Diff, EmptyVsNonEmptyBuffer) {
    const std::vector<uint8_t> empty;
    const std::vector<uint8_t> nonEm(16, 0x42);

    const auto ins = computeByteDiff(empty, nonEm);
    ASSERT_EQ(ins.size(), 1u);
    EXPECT_EQ(ins[0].kind, DiffKind::Inserted);
    EXPECT_EQ(ins[0].sizeB, 16u);

    const auto del = computeByteDiff(nonEm, empty);
    ASSERT_EQ(del.size(), 1u);
    EXPECT_EQ(del[0].kind, DiffKind::Deleted);
    EXPECT_EQ(del[0].sizeA, 16u);
}

TEST(Diff, FileBasedDiffIdenticalAndDifferent) {
    const auto data = fixtures::makeELF();
    ScopedTempFile file1("sample1.bin", data);
    ScopedTempFile file2("sample2.bin", data);

    const auto resIdentical = compareFiles(file1.path, file2.path);
    ASSERT_TRUE(resIdentical.ok) << resIdentical.error;
    EXPECT_TRUE(resIdentical.summary.identical);
    EXPECT_EQ(resIdentical.summary.totalDiffRegions, 0u);

    // Modify one byte in file2
    auto dataMod = data;
    dataMod[0x100] ^= 0x55;
    ScopedTempFile file3("sample3.bin", dataMod);

    const auto resDiff = compareFiles(file1.path, file3.path);
    ASSERT_TRUE(resDiff.ok);
    EXPECT_FALSE(resDiff.summary.identical);
    EXPECT_GT(resDiff.summary.totalDiffRegions, 0u);
    EXPECT_GT(resDiff.summary.totalModifiedBytes, 0u);
}

TEST(Diff, FileReadErrorOnMissingFile) {
    const auto res = compareFiles(fs::temp_directory_path() / "nonexistent_xrl_a.bin",
                                  fs::temp_directory_path() / "nonexistent_xrl_b.bin");
    EXPECT_FALSE(res.ok);
    EXPECT_FALSE(res.error.empty());
}

TEST(Diff, LargeUnequalFilesAreComparedThroughEnd) {
    constexpr size_t prefixSize = 32 * 1024 * 1024 + 128;
    std::vector<uint8_t> dataA(prefixSize, 0x41);
    auto dataB = dataA;
    dataB[prefixSize - 1] = 0x42;
    dataB.push_back(0x43);
    ScopedTempFile fileA("large_unequal_a.bin", dataA);
    ScopedTempFile fileB("large_unequal_b.bin", dataB);

    std::string error;
    const auto diffs = computeFileByteDiff(fileA.path, fileB.path, dataA.size(), dataB.size(), {}, {}, &error);
    EXPECT_TRUE(error.empty()) << error;
    ASSERT_EQ(diffs.size(), 2u);
    EXPECT_EQ(diffs[0].kind, DiffKind::Modified);
    EXPECT_EQ(diffs[0].offsetA, prefixSize - 1);
    EXPECT_EQ(diffs[1].kind, DiffKind::Inserted);
    EXPECT_EQ(diffs[1].offsetB, prefixSize);
    EXPECT_EQ(diffs[1].sizeB, 1u);
}

TEST(Diff, StreamedFileReadErrorsAreNotReportedAsNoDifferences) {
    std::string error;
    const auto diffs = computeFileByteDiff(fs::temp_directory_path() / "xrl_missing_diff_a.bin",
                                           fs::temp_directory_path() / "xrl_missing_diff_b.bin",
                                           1, 1, {}, {}, &error);
    EXPECT_TRUE(diffs.empty());
    EXPECT_FALSE(error.empty());

    const auto compare = compareFiles(fs::temp_directory_path() / "xrl_missing_diff_a.bin",
                                      fs::temp_directory_path() / "xrl_missing_diff_b.bin");
    EXPECT_FALSE(compare.ok);
    EXPECT_FALSE(compare.error.empty());
}

TEST(Diff, ZeroLengthFilesAreValidatedBeforeReturningRanges) {
    ScopedTempFile emptyA("empty_diff_a.bin", {});
    ScopedTempFile emptyB("empty_diff_b.bin", {});
    ScopedTempFile nonEmpty("nonempty_diff.bin", {0x42});

    std::string error;
    EXPECT_TRUE(computeFileByteDiff(emptyA.path, emptyB.path, 0, 0, {}, {}, &error).empty());
    EXPECT_TRUE(error.empty());

    const auto inserted = computeFileByteDiff(emptyA.path, nonEmpty.path, 0, 1, {}, {}, &error);
    ASSERT_EQ(inserted.size(), 1u);
    EXPECT_EQ(inserted[0].kind, DiffKind::Inserted);
    EXPECT_TRUE(error.empty());

    const auto missing = computeFileByteDiff(
        fs::temp_directory_path() / "xrl_missing_empty_a.bin", emptyB.path, 0, 0, {}, {}, &error);
    EXPECT_TRUE(missing.empty());
    EXPECT_FALSE(error.empty());
}

TEST(Diff, MetadataComparisonSectionChange) {
    auto peA = fixtures::makePE64();
    auto peB = peA;

    // Modify section raw size of .text in peB
    const size_t secText = 0x84 + 20 + 240;
    peB[secText + 16] = 0x80;  // Change raw size

    const auto infoA = analyzeBuffer(peA);
    const auto infoB = analyzeBuffer(peB);

    const auto metaDiffs = compareMetadata(infoA, infoB);
    ASSERT_FALSE(metaDiffs.empty());

    bool foundSectionChange = false;
    for (const auto& m : metaDiffs) {
        if (m.category == "Section" && m.key == ".text") {
            foundSectionChange = true;
            EXPECT_EQ(m.change, MetadataChangeType::Modified);
            EXPECT_TRUE(m.offsetA.has_value());
            EXPECT_TRUE(m.offsetB.has_value());
        }
    }
    EXPECT_TRUE(foundSectionChange);
}

TEST(Diff, MetadataComparisonAddedAndRemovedSections) {
    BinaryInfo infoA, infoB;
    infoA.sectionsParsed = infoB.sectionsParsed = true;

    Section s1;
    s1.name = ".text";
    s1.virtualAddress = 0x1000;
    s1.fileOffset = 0x400;
    s1.fileSize = 0x200;
    infoA.sections.push_back(s1);

    Section s2;
    s2.name = ".rdata";
    s2.virtualAddress = 0x2000;
    s2.fileOffset = 0x600;
    s2.fileSize = 0x100;
    infoB.sections.push_back(s2);

    const auto metaDiffs = compareMetadata(infoA, infoB);
    ASSERT_EQ(metaDiffs.size(), 2u);

    bool hasAdd = false, hasRem = false;
    for (const auto& m : metaDiffs) {
        if (m.key == ".rdata" && m.change == MetadataChangeType::Added) hasAdd = true;
        if (m.key == ".text" && m.change == MetadataChangeType::Removed) hasRem = true;
    }
    EXPECT_TRUE(hasAdd);
    EXPECT_TRUE(hasRem);
}

TEST(Diff, JsonReportStructure) {
    BinaryDiffResult r;
    r.ok = true;
    r.infoA.fileName = "a.bin";
    r.infoA.fileSize = 100;
    r.infoA.sha256 = "1111111111111111111111111111111111111111111111111111111111111111";
    r.infoB.fileName = "b.bin";
    r.infoB.fileSize = 105;
    r.infoB.sha256 = "2222222222222222222222222222222222222222222222222222222222222222";

    r.summary.totalDiffRegions = 1;
    r.summary.totalInsertedBytes = 5;
    r.byteDiffs.push_back({10, 0, 10, 5, DiffKind::Inserted});

    r.metadataDiffs.push_back({"Section", ".data", MetadataChangeType::Added, "(absent)", "size 5", std::nullopt, 10, ""});

    const Json json = buildDiffJsonReport(r);
    ASSERT_TRUE(json.isObject());
    EXPECT_EQ(json.find("schema_version")->asString(), "1.0");
    EXPECT_FALSE(json.find("summary")->find("identical")->asBool());
    EXPECT_EQ(json.find("summary")->find("total_diff_regions")->asInt(), 1);
    EXPECT_EQ(json.find("byte_differences")->items().size(), 1u);
    EXPECT_EQ(json.find("byte_differences")->items()[0].find("kind")->asString(), "Inserted");
    EXPECT_EQ(json.find("metadata_differences")->items().size(), 1u);
    EXPECT_EQ(json.find("metadata_differences")->items()[0].find("key")->asString(), ".data");

    const std::string text = renderDiffTextReport(r);
    EXPECT_NE(text.find("DIFFERENT"), std::string::npos);
    EXPECT_NE(text.find("a.bin"), std::string::npos);
    EXPECT_NE(text.find("b.bin"), std::string::npos);
    EXPECT_NE(text.find(".data"), std::string::npos);
}
