#pragma once
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "xrl/types.hpp"

namespace xrl {

// Explicit resource limits. The analyser never allocates or iterates beyond these.
struct Limits {
    uint64_t maxFileSize = 512ull * 1024 * 1024;  // files above this are rejected unread
    size_t maxSections = 4096;
    size_t maxSymbols = 200'000;                  // per category
    size_t maxLoadCommands = 16'384;
    size_t maxImportDlls = 4096;
    size_t maxStringLength = 1024;
};

struct AnalysisResult {
    std::shared_ptr<const std::vector<uint8_t>> data;  // null when the file was not loaded
    BinaryInfo info;
};

using ProgressFn = std::function<void(int percent, const std::string& stage)>;

// Identify the container format from magic bytes only.
Format detectFormat(std::span<const uint8_t> data);

// Analyse an in-memory buffer. Never throws for malformed input; problems are
// reported through BinaryInfo::error / warnings.
BinaryInfo analyzeBuffer(std::span<const uint8_t> data, const Limits& limits = {},
                         const ProgressFn& progress = {});

// Load a file (respecting limits.maxFileSize) and analyse it. The file is only read, never executed.
AnalysisResult analyzeFile(const std::filesystem::path& path, const Limits& limits = {},
                           const ProgressFn& progress = {});

// Heuristic observations (see docs/analysis-notes.md). Invoked by analyzeBuffer.
void runHeuristics(BinaryInfo& info);

}  // namespace xrl

