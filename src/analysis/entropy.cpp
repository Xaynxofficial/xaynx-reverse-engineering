#include "xrl/entropy.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <new>
#include <sstream>
#include <stdexcept>
#include <system_error>

#include "xrl/sha256.hpp"
#include "xrl/util.hpp"

namespace xrl {
namespace {

constexpr size_t kReadBufferSize = 64 * 1024;
using Counts = std::array<uint64_t, 256>;

double entropyOf(const Counts& counts, uint64_t size) {
    if (size == 0) return 0.0;
    const double n = static_cast<double>(size);
    double entropy = 0.0;
    for (const uint64_t count : counts) {
        if (count == 0) continue;
        const double probability = static_cast<double>(count) / n;
        entropy -= probability * std::log2(probability);
    }
    return entropy;
}

void report(const ProgressFn& progress, int percent, const char* stage) {
    if (progress) progress(percent, stage);
}

}  // namespace

EntropyAnalysisResult analyzeEntropyFile(const std::filesystem::path& path, size_t blockSize,
                                         const ProgressFn& progress,
                                         const std::function<bool()>& shouldCancel) {
    EntropyAnalysisResult result;
    result.filePath = pathUtf8(path);
    result.blockSize = blockSize;
    if (blockSize == 0) {
        result.error = "Entropy block size must be greater than zero.";
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
    const uint64_t blockSize64 = static_cast<uint64_t>(blockSize);
    const uint64_t blockCount = size / blockSize64 + (size % blockSize64 != 0 ? 1 : 0);
    if (blockCount > static_cast<uint64_t>(result.blocks.max_size())) {
        result.error = "The requested block size would produce too many entropy blocks.";
        return result;
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        result.error = "Cannot open file for reading.";
        return result;
    }
    try {
        result.blocks.reserve(static_cast<size_t>(blockCount));
    } catch (const std::bad_alloc&) {
        result.error = "Not enough memory to store block-level entropy results.";
        return result;
    } catch (const std::length_error&) {
        result.error = "The requested block size would produce too many entropy blocks.";
        return result;
    }

    report(progress, 0, "Reading file and calculating entropy");
    Sha256 sha;
    Counts totalCounts{};
    Counts blockCounts{};
    std::array<uint8_t, kReadBufferSize> buffer{};
    uint64_t offset = 0;
    uint64_t blockOffset = 0;
    uint64_t blockBytes = 0;
    double entropySum = 0.0;

    while (offset < size) {
        if (shouldCancel && shouldCancel()) {
            result.cancelled = true;
            result.error = "Entropy analysis cancelled.";
            result.blocks.clear();
            return result;
        }

        const auto remaining = size - offset;
        const auto amount = static_cast<std::streamsize>(
            std::min<uint64_t>(remaining, static_cast<uint64_t>(buffer.size())));
        input.read(reinterpret_cast<char*>(buffer.data()), amount);
        if (input.gcount() != amount) {
            result.error = "Short read: the file changed or could not be fully read.";
            result.blocks.clear();
            return result;
        }

        const auto bytesRead = static_cast<size_t>(amount);
        const std::span<const uint8_t> chunk(buffer.data(), bytesRead);
        sha.update(chunk);
        for (const uint8_t byte : chunk) ++totalCounts[byte];

        size_t cursor = 0;
        while (cursor < bytesRead) {
            const uint64_t blockRemaining = blockSize64 - blockBytes;
            const size_t take = static_cast<size_t>(
                std::min<uint64_t>(static_cast<uint64_t>(bytesRead - cursor), blockRemaining));
            for (size_t i = 0; i < take; ++i) ++blockCounts[buffer[cursor + i]];
            cursor += take;
            blockBytes += take;
            if (blockBytes == blockSize64 || offset + cursor == size) {
                const double entropy = entropyOf(blockCounts, blockBytes);
                result.blocks.push_back({blockOffset, blockBytes, entropy});
                entropySum += entropy;
                blockOffset += blockBytes;
                blockBytes = 0;
                blockCounts.fill(0);
            }
        }

        offset += static_cast<uint64_t>(amount);
        const int percent = size == 0 ? 100 : static_cast<int>(
            (static_cast<long double>(offset) * 100.0L) / static_cast<long double>(size));
        report(progress, percent, "Reading file and calculating entropy");
    }

    if (input.peek() != std::char_traits<char>::eof()) {
        result.error = "The file grew while it was being analysed.";
        result.blocks.clear();
        return result;
    }
    if (input.bad()) {
        result.error = "An I/O error occurred while reading the file.";
        result.blocks.clear();
        return result;
    }

    if (!result.blocks.empty()) {
        result.minBlockEntropy = result.blocks.front().entropy;
        result.maxBlockEntropy = result.blocks.front().entropy;
        for (const auto& block : result.blocks) {
            result.minBlockEntropy = std::min(*result.minBlockEntropy, block.entropy);
            result.maxBlockEntropy = std::max(*result.maxBlockEntropy, block.entropy);
        }
        result.averageBlockEntropy = entropySum / static_cast<double>(result.blocks.size());
    }
    if (size > 0) result.overallEntropy = entropyOf(totalCounts, size);
    result.sha256 = hexBytes(sha.finish());
    result.ok = true;
    report(progress, 100, "Entropy analysis complete");
    return result;
}

Json buildEntropyJsonReport(const EntropyAnalysisResult& result,
                            const EntropyAnalysisResult* comparison,
                            double variationThreshold) {
    Json reportJson = Json::object();
    reportJson.set("schema_version", "1.0");
    reportJson.set("status", result.ok ? "complete" : (result.cancelled ? "cancelled" : "error"));
    reportJson.set("error", result.error.empty() ? Json() : Json(result.error));
    reportJson.set("file_path", result.filePath);
    reportJson.set("file_size_bytes", result.ok ? Json(result.fileSize) : Json());
    reportJson.set("block_size_bytes", static_cast<uint64_t>(result.blockSize));
    reportJson.set("sha256", result.sha256.empty() ? Json() : Json(result.sha256));
    reportJson.set("overall_entropy_bits_per_byte",
                   result.overallEntropy ? Json(*result.overallEntropy) : Json());
    reportJson.set("minimum_block_entropy_bits_per_byte",
                   result.minBlockEntropy ? Json(*result.minBlockEntropy) : Json());
    reportJson.set("maximum_block_entropy_bits_per_byte",
                   result.maxBlockEntropy ? Json(*result.maxBlockEntropy) : Json());
    reportJson.set("average_block_entropy_bits_per_byte",
                   result.averageBlockEntropy ? Json(*result.averageBlockEntropy) : Json());
    reportJson.set("analyzed_block_count", result.ok ? Json(static_cast<uint64_t>(result.blocks.size())) : Json());

    auto regions = [&](bool highest) {
        std::vector<const EntropyBlock*> selected;
        constexpr size_t kRegionCount = 5;
        for (const auto& block : result.blocks) {
            auto position = selected.begin();
            while (position != selected.end() &&
                   (highest ? (*position)->entropy >= block.entropy : (*position)->entropy <= block.entropy)) {
                ++position;
            }
            selected.insert(position, &block);
            if (selected.size() > kRegionCount) selected.pop_back();
        }
        Json array = Json::array();
        for (const auto* block : selected) {
            Json item = Json::object();
            item.set("offset", block->offset);
            item.set("size_bytes", block->size);
            item.set("entropy_bits_per_byte", block->entropy);
            array.push(std::move(item));
        }
        return array;
    };
    reportJson.set("highest_entropy_regions", regions(true));
    reportJson.set("lowest_entropy_regions", regions(false));

    Json blocks = Json::array();
    for (const auto& block : result.blocks) {
        Json item = Json::object();
        item.set("offset", block.offset);
        item.set("size_bytes", block.size);
        item.set("entropy_bits_per_byte", block.entropy);
        blocks.push(std::move(item));
    }
    reportJson.set("blocks", std::move(blocks));
    if (comparison) {
        Json comparisonJson = buildEntropyJsonReport(*comparison);
        const bool sameBlockSize = result.blockSize == comparison->blockSize;
        const size_t matched = result.ok && comparison->ok && sameBlockSize
                                   ? std::min(result.blocks.size(), comparison->blocks.size())
                                   : 0;
        double deltaSum = 0.0;
        uint64_t unusualCount = 0;
        for (size_t i = 0; i < matched; ++i) {
            const double delta = std::abs(result.blocks[i].entropy - comparison->blocks[i].entropy);
            deltaSum += delta;
            if (variationThreshold > 0.0 && delta >= variationThreshold) ++unusualCount;
        }
        comparisonJson.set("alignment",
                           sameBlockSize ? "same block index / file offset"
                                         : "unavailable: block sizes differ");
        comparisonJson.set("aligned_block_count", result.ok && comparison->ok
                                                        ? Json(static_cast<uint64_t>(matched))
                                                        : Json());
        comparisonJson.set("mean_absolute_entropy_difference_bits_per_byte",
                           matched ? Json(deltaSum / static_cast<double>(matched)) : Json());
        comparisonJson.set("variation_threshold_bits_per_byte", variationThreshold);
        comparisonJson.set("blocks_above_variation_threshold", result.ok && comparison->ok
                                                                   ? Json(unusualCount)
                                                                   : Json());
        reportJson.set("comparison", std::move(comparisonJson));
    }
    return reportJson;
}

std::string renderEntropyJsonReport(const EntropyAnalysisResult& result,
                                    const EntropyAnalysisResult* comparison,
                                    double variationThreshold) {
    return buildEntropyJsonReport(result, comparison, variationThreshold).dump(2);
}

std::string renderEntropyCsv(const EntropyAnalysisResult& result) {
    std::ostringstream output;
    output << "offset,size_bytes,entropy_bits_per_byte\n" << std::setprecision(std::numeric_limits<double>::max_digits10);
    for (const auto& block : result.blocks) {
        output << block.offset << ',' << block.size << ',' << block.entropy << '\n';
    }
    return output.str();
}

}  // namespace xrl
