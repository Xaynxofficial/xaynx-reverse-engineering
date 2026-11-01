#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "xrl/analyzer.hpp"
#include "xrl/json.hpp"

namespace xrl {

inline constexpr size_t kDefaultEntropyBlockSize = 256;

struct EntropyBlock {
    uint64_t offset = 0;
    uint64_t size = 0;
    double entropy = 0.0;
};

struct EntropyAnalysisResult {
    bool ok = false;
    bool cancelled = false;
    std::string error;
    std::string filePath;
    uint64_t fileSize = 0;
    size_t blockSize = kDefaultEntropyBlockSize;
    std::string sha256;
    std::optional<double> overallEntropy;
    std::optional<double> minBlockEntropy;
    std::optional<double> maxBlockEntropy;
    std::optional<double> averageBlockEntropy;
    std::vector<EntropyBlock> blocks;
};

EntropyAnalysisResult analyzeEntropyFile(const std::filesystem::path& path,
                                         size_t blockSize = kDefaultEntropyBlockSize,
                                         const ProgressFn& progress = {},
                                         const std::function<bool()>& shouldCancel = {});

Json buildEntropyJsonReport(const EntropyAnalysisResult& result,
                            const EntropyAnalysisResult* comparison = nullptr,
                            double variationThreshold = 1.5);
std::string renderEntropyJsonReport(const EntropyAnalysisResult& result,
                                    const EntropyAnalysisResult* comparison = nullptr,
                                    double variationThreshold = 1.5);
std::string renderEntropyCsv(const EntropyAnalysisResult& result);

}  // namespace xrl
