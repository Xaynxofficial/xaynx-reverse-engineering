#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "xrl/cfg.hpp"
#include "xrl/entropy.hpp"
#include "xrl/json.hpp"
#include "xrl/strings.hpp"

namespace xrl {

enum class StaticSeverity { Informational, Low, Medium, High, Critical };
enum class StaticCategory { Structure, Memory, Imports, Entropy, Strings, ControlFlow, Correlation };
enum class StaticView { None, Hex, Sections, Imports, Strings, Entropy, ControlFlow };

const char* toString(StaticSeverity severity);
const char* toString(StaticCategory category);
const char* toString(StaticView view);

struct StaticEvidence {
    std::string description;
    std::string value;
    std::string deduplicationKey;
    std::optional<uint64_t> fileOffset;
    std::optional<uint64_t> virtualAddress;
};

struct StaticFinding {
    std::string id;
    std::string ruleId;
    std::string title;
    std::string description;
    StaticCategory category = StaticCategory::Structure;
    StaticSeverity severity = StaticSeverity::Informational;
    unsigned confidence = 0;
    unsigned evidenceQuality = 0;
    std::vector<StaticEvidence> evidence;
    std::string whyItMatters;
    std::string benignExplanations;
    std::string nextSteps;
    StaticView relatedView = StaticView::None;
};

struct StaticCorrelation {
    std::string id;
    std::string title;
    std::string explanation;
    std::vector<std::string> findingIds;
};

struct RiskContribution {
    std::string findingId;
    std::string evidenceGroup;
    double points = 0.0;
    bool counted = false;
    std::string reason;
};

struct StaticRiskScore {
    unsigned score = 0;
    bool inconclusive = true;
    std::string methodology;
    std::vector<RiskContribution> contributions;
};

struct StaticAnalysisResult {
    bool ok = false;
    bool cancelled = false;
    std::string error;
    std::string fileName;
    std::string filePath;
    std::string format;
    std::string architecture;
    uint64_t fileSize = 0;
    std::string sha256;
    std::optional<uint64_t> entryPoint;
    std::vector<std::pair<std::string, std::string>> metadata;
    std::string generatedAtUtc;
    std::string engineVersion;
    std::vector<std::string> warnings;
    std::vector<StaticFinding> findings;
    std::vector<StaticCorrelation> correlations;
    StaticRiskScore risk;
    size_t omittedStringEvidence = 0;
};

using StaticProgressFn = std::function<void(int percent, const std::string& stage)>;
using StaticCancelFn = std::function<bool()>;

StaticAnalysisResult analyzeStatic(const BinaryInfo& info, std::span<const uint8_t> fileData,
                                   const StringExtractionResult* strings = nullptr,
                                   const EntropyAnalysisResult* entropy = nullptr,
                                   const ControlFlowGraph* cfg = nullptr,
                                   const StaticProgressFn& progress = {},
                                   const StaticCancelFn& cancelled = {});

Json buildStaticJsonReport(const StaticAnalysisResult& result);
std::string renderStaticJsonReport(const StaticAnalysisResult& result);
std::string renderStaticHtmlReport(const StaticAnalysisResult& result);

}  // namespace xrl
