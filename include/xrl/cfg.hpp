#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "xrl/disassembler.hpp"

namespace xrl {

enum class FunctionEvidence { EntryPoint, Export, Symbol, SectionStart, UserAddress };

struct FunctionCandidate {
    std::string name;
    uint64_t address = 0;
    uint64_t fileOffset = 0;
    FunctionEvidence evidence = FunctionEvidence::UserAddress;
    bool startConfirmed = false;
};

enum class CfgEdgeKind {
    Fallthrough,
    ConditionalTrue,
    ConditionalFalse,
    Unconditional,
    ExternalBranch,
    Unresolved
};

struct CfgEdge {
    size_t from = 0;
    std::optional<size_t> to;
    uint64_t targetAddress = 0;
    CfgEdgeKind kind = CfgEdgeKind::Fallthrough;
    std::string label;
    bool targetResolved = false;
};

struct BasicBlock {
    size_t id = 0;
    uint64_t startAddress = 0;
    uint64_t endAddress = 0;  // exclusive
    uint64_t fileOffset = 0;
    std::vector<Instruction> instructions;
    std::vector<size_t> successors;
    std::vector<size_t> predecessors;
    bool isEntry = false;
    bool isExit = false;
    bool hasUnresolvedFlow = false;
};

struct CfgCallReference {
    uint64_t instructionAddress = 0;
    std::optional<uint64_t> targetAddress;
    bool recursive = false;
};

struct CfgMetrics {
    size_t reachableBlocks = 0;
    size_t edgeCount = 0;
    size_t conditionalBranches = 0;
    size_t backEdges = 0;
    size_t naturalLoops = 0;
    size_t stronglyConnectedComponents = 0;
    size_t cyclomaticComplexity = 0;
    std::vector<std::optional<size_t>> immediateDominators;
};

struct ControlFlowGraph {
    bool ok = false;
    std::string error;
    FunctionCandidate function;
    std::vector<BasicBlock> blocks;
    std::vector<CfgEdge> edges;
    std::vector<CfgCallReference> calls;
    CfgMetrics metrics;
    uint64_t analyzedBytes = 0;
    bool truncated = false;
};

struct CfgOptions {
    size_t maxBlocks = 2048;
    size_t maxInstructionsPerBlock = 512;
    uint64_t maxDecodedBytes = 16ull * 1024 * 1024;
};

using CfgProgressFn = std::function<void(int percent, const std::string& stage)>;
using CfgCancelFn = std::function<bool()>;

bool cfgSupported(const BinaryInfo& info);
std::vector<FunctionCandidate> discoverFunctionCandidates(const BinaryInfo& info, size_t maxCandidates = 4096);
ControlFlowGraph analyzeControlFlow(const BinaryInfo& info, std::span<const uint8_t> fileData,
                                    const FunctionCandidate& function, const CfgOptions& options = {},
                                    const CfgProgressFn& progress = {}, const CfgCancelFn& cancelled = {});

std::string exportCfgJson(const ControlFlowGraph& graph);
std::string exportCfgDot(const ControlFlowGraph& graph);

}  // namespace xrl
