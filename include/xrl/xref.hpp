#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "xrl/cfg.hpp"
#include "xrl/strings.hpp"

namespace xrl {

enum class XrefType {
    Code,
    Data,
    Call,
    ConditionalBranch,
    UnconditionalBranch,
    Import,
    Export,
    Relocation,
    String,
    Symbol
};

enum class XrefConfidence { Confirmed, Inferred, Unresolved };

const char* toString(XrefType type);
const char* toString(XrefConfidence confidence);

struct XrefReference {
    std::optional<uint64_t> sourceAddress;
    std::optional<uint64_t> destinationAddress;
    std::optional<uint64_t> sourceFunction;
    std::optional<uint64_t> destinationFunction;
    std::optional<uint64_t> instructionAddress;
    std::optional<uint64_t> fileOffset;
    std::optional<uint64_t> destinationFileOffset;
    XrefType type = XrefType::Code;
    XrefConfidence confidence = XrefConfidence::Confirmed;
    std::string sourceFunctionName;
    std::string destinationFunctionName;
    std::string symbolName;
    std::string dataTarget;
    std::string evidenceSource;
};

struct XrefFunction {
    FunctionCandidate candidate;
    size_t incomingCalls = 0;
    size_t outgoingCalls = 0;
    size_t callDepth = 0;
    size_t unresolvedIndirectCalls = 0;
    bool recursive = false;
};

struct XrefOptions {
    size_t maxFunctions = 256;
    size_t maxReferences = 200'000;
    size_t maxBlocksPerFunction = 512;
    uint64_t maxTotalDecodedBytes = 64ull * 1024 * 1024;
};

struct XrefResult {
    bool ok = false;
    bool cancelled = false;
    bool truncated = false;
    std::string error;
    uint64_t fileSize = 0;
    std::string sha256;
    std::vector<XrefFunction> functions;
    std::vector<XrefReference> references;
    std::vector<uint64_t> unreferencedFunctionCandidates;
    std::vector<uint64_t> unreferencedStringOffsets;
    std::unordered_map<uint64_t, std::vector<size_t>> incomingByAddress;
    std::unordered_map<uint64_t, std::vector<size_t>> outgoingByAddress;
    size_t unresolvedIndirectCalls = 0;
    size_t analyzedFunctions = 0;
    uint64_t analyzedBytes = 0;
    std::vector<std::string> warnings;
};

using XrefProgressFn = std::function<void(int percent, const std::string& stage)>;
using XrefCancelFn = std::function<bool()>;

XrefResult analyzeCrossReferences(const BinaryInfo& info, std::span<const uint8_t> fileData,
                                  const StringExtractionResult* strings = nullptr,
                                  const XrefOptions& options = {},
                                  const XrefProgressFn& progress = {},
                                  const XrefCancelFn& cancelled = {});

std::string renderXrefJson(const XrefResult& result);
std::string renderXrefCsv(const XrefResult& result);
std::string renderXrefDot(const XrefResult& result, size_t maxNodes = 256, size_t maxEdges = 2000);

}  // namespace xrl
