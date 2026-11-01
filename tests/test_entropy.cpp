#include <gtest/gtest.h>

#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <vector>

#include "xrl/entropy.hpp"

using namespace xrl;
namespace fs = std::filesystem;

namespace {
class TempFile {
public:
    explicit TempFile(const std::vector<uint8_t>& data) {
        static uint64_t counter = 0;
        const auto id = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = fs::temp_directory_path() /
                ("xrl_entropy_" + std::to_string(id) + "_" + std::to_string(++counter) + ".bin");
        std::ofstream out(path_, std::ios::binary);
        if (!out) throw std::runtime_error("could not create entropy test fixture");
        if (!data.empty()) {
            out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        }
        if (!out) throw std::runtime_error("could not write entropy test fixture");
    }

    ~TempFile() {
        std::error_code ec;
        fs::remove(path_, ec);
    }

    const fs::path& path() const { return path_; }

private:
    fs::path path_;
};
}  // namespace

TEST(Entropy, EmptyFileHasHashButUndefinedEntropyStatistics) {
    const TempFile file({});
    const auto result = analyzeEntropyFile(file.path());
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_EQ(result.fileSize, 0u);
    EXPECT_TRUE(result.blocks.empty());
    EXPECT_FALSE(result.overallEntropy);
    EXPECT_FALSE(result.minBlockEntropy);
    EXPECT_FALSE(result.maxBlockEntropy);
    EXPECT_FALSE(result.averageBlockEntropy);
    EXPECT_EQ(result.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Entropy, ZeroAndRepeatedByteFilesHaveZeroEntropy) {
    const TempFile zeros(std::vector<uint8_t>(513, 0));
    const auto zeroResult = analyzeEntropyFile(zeros.path());
    ASSERT_TRUE(zeroResult.ok) << zeroResult.error;
    ASSERT_EQ(zeroResult.blocks.size(), 3u);
    EXPECT_DOUBLE_EQ(*zeroResult.overallEntropy, 0.0);
    EXPECT_DOUBLE_EQ(*zeroResult.minBlockEntropy, 0.0);
    EXPECT_DOUBLE_EQ(*zeroResult.maxBlockEntropy, 0.0);
    EXPECT_DOUBLE_EQ(*zeroResult.averageBlockEntropy, 0.0);
    EXPECT_EQ(zeroResult.blocks.back().size, 1u);

    const TempFile repeated(std::vector<uint8_t>(101, 0xA5));
    const auto repeatedResult = analyzeEntropyFile(repeated.path(), 32);
    ASSERT_TRUE(repeatedResult.ok) << repeatedResult.error;
    EXPECT_DOUBLE_EQ(*repeatedResult.overallEntropy, 0.0);
    for (const auto& block : repeatedResult.blocks) EXPECT_DOUBLE_EQ(block.entropy, 0.0);
}

TEST(Entropy, UniformByteDistributionIsEightBitsPerByte) {
    std::vector<uint8_t> data;
    data.reserve(1024);
    for (int repeat = 0; repeat < 4; ++repeat)
        for (int value = 0; value < 256; ++value)
            data.push_back(static_cast<uint8_t>(value));
    const TempFile file(data);
    const auto result = analyzeEntropyFile(file.path());
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_NEAR(*result.overallEntropy, 8.0, 1e-12);
    ASSERT_EQ(result.blocks.size(), 4u);
    for (const auto& block : result.blocks) EXPECT_NEAR(block.entropy, 8.0, 1e-12);
}

TEST(Entropy, SmallFileAndIncompleteFinalBlock) {
    const TempFile file({0, 1, 2, 3, 4, 5});
    const auto result = analyzeEntropyFile(file.path(), 4);
    ASSERT_TRUE(result.ok) << result.error;
    ASSERT_EQ(result.blocks.size(), 2u);
    EXPECT_EQ(result.blocks[0].offset, 0u);
    EXPECT_EQ(result.blocks[0].size, 4u);
    EXPECT_NEAR(result.blocks[0].entropy, 2.0, 1e-12);
    EXPECT_EQ(result.blocks[1].offset, 4u);
    EXPECT_EQ(result.blocks[1].size, 2u);
    EXPECT_NEAR(result.blocks[1].entropy, 1.0, 1e-12);
    EXPECT_NEAR(*result.overallEntropy, std::log2(6.0), 1e-12);
    EXPECT_NEAR(*result.averageBlockEntropy, 1.5, 1e-12);
}

TEST(Entropy, LargeFileIsStreamedAndReportsProgress) {
    const std::vector<uint8_t> data(3 * 1024 * 1024 + 19, 0x5A);
    const TempFile file(data);
    int lastProgress = -1;
    const auto result = analyzeEntropyFile(file.path(), 4096,
                                           [&](int percent, const std::string&) {
                                               EXPECT_GE(percent, lastProgress);
                                               lastProgress = percent;
                                           });
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_EQ(result.fileSize, data.size());
    EXPECT_EQ(result.blocks.size(), (data.size() + 4095) / 4096);
    EXPECT_EQ(result.blocks.back().size, 19u);
    EXPECT_EQ(lastProgress, 100);
    EXPECT_DOUBLE_EQ(*result.overallEntropy, 0.0);
}

TEST(Entropy, InvalidPathsAndBlockSizeReturnErrors) {
    const auto missing = fs::temp_directory_path() / "xrl_entropy_missing_file.bin";
    const auto missingResult = analyzeEntropyFile(missing);
    EXPECT_FALSE(missingResult.ok);
    EXPECT_FALSE(missingResult.error.empty());

    const auto directoryResult = analyzeEntropyFile(fs::temp_directory_path());
    EXPECT_FALSE(directoryResult.ok);
    EXPECT_FALSE(directoryResult.error.empty());

    const TempFile file({1, 2, 3});
    const auto invalidBlockResult = analyzeEntropyFile(file.path(), 0);
    EXPECT_FALSE(invalidBlockResult.ok);
    EXPECT_FALSE(invalidBlockResult.error.empty());
}

TEST(Entropy, SupportsCancellationAndStructuredExports) {
    const TempFile file({0, 1, 2, 3, 4});
    const auto cancelled = analyzeEntropyFile(file.path(), 2, {}, [] { return true; });
    EXPECT_FALSE(cancelled.ok);
    EXPECT_TRUE(cancelled.cancelled);

    const auto result = analyzeEntropyFile(file.path(), 2);
    ASSERT_TRUE(result.ok);
    const auto parsed = Json::parse(renderEntropyJsonReport(result));
    ASSERT_TRUE(parsed.value) << parsed.error;
    ASSERT_TRUE(parsed.value->isObject());
    EXPECT_EQ(parsed.value->find("analyzed_block_count")->asInt(), 3);
    EXPECT_EQ(renderEntropyCsv(result).find("offset,size_bytes,entropy_bits_per_byte"), 0u);

    const TempFile comparisonFile({0, 0, 0, 0, 0});
    const auto comparison = analyzeEntropyFile(comparisonFile.path(), 2);
    ASSERT_TRUE(comparison.ok);
    const auto comparisonReport = Json::parse(renderEntropyJsonReport(result, &comparison, 1.0));
    ASSERT_TRUE(comparisonReport.value) << comparisonReport.error;
    const Json* comparisonData = comparisonReport.value->find("comparison");
    ASSERT_NE(comparisonData, nullptr);
    ASSERT_TRUE(comparisonData->isObject());
    EXPECT_EQ(comparisonData->find("aligned_block_count")->asInt(), 3);
}
