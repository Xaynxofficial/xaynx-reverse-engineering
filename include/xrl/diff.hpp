#pragma once
// Binary Diff & Comparison Engine
//
// Compares two arbitrary binary files at the byte level and (when recognized)
// at the executable structure level (PE, ELF, Mach-O).
// Files are treated as untrusted input and are never executed.
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "xrl/analyzer.hpp"
#include "xrl/json.hpp"
#include "xrl/types.hpp"

namespace xrl {

enum class DiffKind {
    Equal,
    Modified,
    Inserted,
    Deleted
};

const char* toString(DiffKind kind);

struct ByteDiffRange {
    uint64_t offsetA = 0;
    uint64_t sizeA = 0;
    uint64_t offsetB = 0;
    uint64_t sizeB = 0;
    DiffKind kind = DiffKind::Modified;
};

enum class MetadataChangeType {
    Added,
    Removed,
    Modified
};

const char* toString(MetadataChangeType type);

struct MetadataDiffItem {
    std::string category;  // "Header", "Section", "Import", "Export", "Library", "Symbol"
    std::string key;       // Identifier (e.g. section name, symbol name, header field)
    MetadataChangeType change = MetadataChangeType::Modified;
    std::string oldValue;
    std::string newValue;
    std::optional<uint64_t> offsetA;  // File offset in A (if mapped)
    std::optional<uint64_t> offsetB;  // File offset in B (if mapped)
    std::string note;
};

struct BinaryDiffSummary {
    uint64_t totalDiffRegions = 0;
    uint64_t totalModifiedBytes = 0;
    uint64_t totalInsertedBytes = 0;
    uint64_t totalDeletedBytes = 0;
    uint64_t addedMetadataCount = 0;
    uint64_t removedMetadataCount = 0;
    uint64_t modifiedMetadataCount = 0;
    bool identical = false;
};

struct BinaryDiffResult {
    bool ok = false;
    std::string error;
    BinaryInfo infoA;
    BinaryInfo infoB;
    BinaryDiffSummary summary;
    std::vector<ByteDiffRange> byteDiffs;
    std::vector<MetadataDiffItem> metadataDiffs;
};

using CancelFn = std::function<bool()>;

// Compute byte-level difference ranges between two in-memory buffers or streams.
// Coalesces consecutive modified bytes up to `maxCoalesceGap` bytes.
std::vector<ByteDiffRange> computeByteDiff(std::span<const uint8_t> dataA,
                                           std::span<const uint8_t> dataB,
                                           const ProgressFn& progress = {},
                                           const CancelFn& shouldCancel = {});

// Streamed byte diff between two files on disk (avoids keeping both entirely in memory).
std::vector<ByteDiffRange> computeFileByteDiff(const std::filesystem::path& pathA,
                                               const std::filesystem::path& pathB,
                                               uint64_t sizeA,
                                               uint64_t sizeB,
                                               const ProgressFn& progress = {},
                                               const CancelFn& shouldCancel = {},
                                               std::string* error = nullptr);

// Compare structured executable metadata from already parsed BinaryInfo objects.
std::vector<MetadataDiffItem> compareMetadata(const BinaryInfo& a, const BinaryInfo& b);

// Full comparison pipeline for two files on disk.
BinaryDiffResult compareFiles(const std::filesystem::path& pathA,
                              const std::filesystem::path& pathB,
                              const Limits& limits = {},
                              const ProgressFn& progress = {},
                              const CancelFn& shouldCancel = {});

// Full comparison pipeline for two in-memory buffers and their pre-computed BinaryInfos.
BinaryDiffResult compareBuffers(std::span<const uint8_t> dataA,
                                std::span<const uint8_t> dataB,
                                const BinaryInfo& infoA,
                                const BinaryInfo& infoB,
                                const ProgressFn& progress = {},
                                const CancelFn& shouldCancel = {});

// Report generation
Json buildDiffJsonReport(const BinaryDiffResult& diff);
std::string renderDiffJsonReport(const BinaryDiffResult& diff);
std::string renderDiffTextReport(const BinaryDiffResult& diff);

}  // namespace xrl
