#include "xrl/cfg.hpp"

#include <algorithm>
#include <deque>
#include <functional>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "xrl/json.hpp"
#include "xrl/util.hpp"

namespace xrl {
namespace {

struct SectionRange {
    size_t index = 0;
    uint64_t address = 0;
    uint64_t offset = 0;
    uint64_t size = 0;
};

struct EdgeDraft {
    uint64_t target = 0;
    CfgEdgeKind kind = CfgEdgeKind::Fallthrough;
    std::string label;
};

struct BlockDraft {
    uint64_t start = 0;
    uint64_t offset = 0;
    uint64_t end = 0;
    std::vector<Instruction> instructions;
    std::vector<EdgeDraft> edges;
    bool exit = false;
    bool unresolved = false;
};

std::optional<SectionRange> executableRangeAtAddress(const BinaryInfo& info, uint64_t address,
                                                     size_t fileSize) {
    for (size_t i = 0; i < info.sections.size(); ++i) {
        const auto& section = info.sections[i];
        if (!section.executable || !section.hasFileData || !section.boundsValid || section.fileSize == 0)
            continue;
        const uint64_t span = std::min(section.virtualSize ? section.virtualSize : section.fileSize, section.fileSize);
        if (address < section.virtualAddress || address - section.virtualAddress >= span) continue;
        if (section.fileOffset > fileSize) continue;
        const uint64_t available = std::min(span, static_cast<uint64_t>(fileSize) - section.fileOffset);
        if (available == 0) continue;
        return SectionRange{i, section.virtualAddress, section.fileOffset, available};
    }
    return std::nullopt;
}

std::string evidenceName(FunctionEvidence evidence) {
    switch (evidence) {
        case FunctionEvidence::EntryPoint: return "entry-point";
        case FunctionEvidence::Export: return "export";
        case FunctionEvidence::Symbol: return "function-symbol";
        case FunctionEvidence::SectionStart: return "executable-section-start";
        case FunctionEvidence::UserAddress: return "user-address";
    }
    return "unknown";
}

std::string edgeKindName(CfgEdgeKind kind) {
    switch (kind) {
        case CfgEdgeKind::Fallthrough: return "fallthrough";
        case CfgEdgeKind::ConditionalTrue: return "conditional-true";
        case CfgEdgeKind::ConditionalFalse: return "conditional-false";
        case CfgEdgeKind::Unconditional: return "unconditional";
        case CfgEdgeKind::ExternalBranch: return "external-branch";
        case CfgEdgeKind::Unresolved: return "unresolved";
    }
    return "unknown";
}

Json instructionJson(const Instruction& instruction) {
    Json item = Json::object();
    item.set("address", hex(instruction.address));
    item.set("file_offset", hex(instruction.fileOffset));
    item.set("mnemonic", instruction.mnemonic);
    item.set("operands", instruction.operands);
    item.set("valid", instruction.valid);
    Json bytes = Json::array();
    for (const uint8_t byte : instruction.bytes) bytes.push(static_cast<int>(byte));
    item.set("bytes", std::move(bytes));
    if (instruction.flowTarget) item.set("flow_target", hex(*instruction.flowTarget));
    return item;
}

void addCandidate(std::vector<FunctionCandidate>& out, std::unordered_map<uint64_t, size_t>& byAddress,
                  const BinaryInfo& info, const Symbol& symbol, FunctionEvidence evidence, size_t maxCandidates) {
    if (out.size() >= maxCandidates || !symbol.address) return;
    const auto range = executableRangeAtAddress(info, *symbol.address, static_cast<size_t>(info.fileSize));
    if (!range) return;
    const bool confirmed = symbol.type == "func";
    auto found = byAddress.find(*symbol.address);
    if (found != byAddress.end()) {
        if (confirmed && !out[found->second].startConfirmed) {
            out[found->second] = {symbol.name, *symbol.address, range->offset, evidence, true};
        }
        return;
    }
    byAddress.emplace(*symbol.address, out.size());
    out.push_back({symbol.name.empty() ? hex(*symbol.address) : symbol.name, *symbol.address, range->offset,
                   evidence, confirmed});
}

std::string flowLabel(const Instruction& instruction) {
    if (instruction.mnemonic.empty()) return "branch";
    return instruction.mnemonic;
}

void computeMetrics(ControlFlowGraph& graph) {
    const size_t count = graph.blocks.size();
    graph.metrics.immediateDominators.assign(count, std::nullopt);
    if (count == 0) return;

    std::vector<bool> reachable(count, false);
    std::vector<size_t> stack{0};
    reachable[0] = true;
    while (!stack.empty()) {
        const size_t current = stack.back();
        stack.pop_back();
        for (const size_t successor : graph.blocks[current].successors) {
            if (successor < count && !reachable[successor]) {
                reachable[successor] = true;
                stack.push_back(successor);
            }
        }
    }
    graph.metrics.reachableBlocks = static_cast<size_t>(std::count(reachable.begin(), reachable.end(), true));

    std::vector<std::vector<bool>> dominates(count, std::vector<bool>(count, true));
    for (size_t i = 0; i < count; ++i) {
        if (!reachable[i]) continue;
        if (i == 0) {
            std::fill(dominates[i].begin(), dominates[i].end(), false);
            dominates[i][i] = true;
        }
    }
    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t node = 1; node < count; ++node) {
            if (!reachable[node]) continue;
            std::vector<bool> next(count, true);
            bool hasPred = false;
            for (const size_t pred : graph.blocks[node].predecessors) {
                if (!reachable[pred]) continue;
                if (!hasPred) { next = dominates[pred]; hasPred = true; }
                else for (size_t i = 0; i < count; ++i) next[i] = next[i] && dominates[pred][i];
            }
            if (!hasPred) std::fill(next.begin(), next.end(), false);
            next[node] = true;
            if (next != dominates[node]) {
                dominates[node] = std::move(next);
                changed = true;
            }
        }
    }

    for (size_t node = 1; node < count; ++node) {
        if (!reachable[node]) continue;
        size_t best = count;
        size_t depth = 0;
        for (size_t candidate = 0; candidate < count; ++candidate) {
            if (candidate == node || !dominates[node][candidate]) continue;
            const size_t candidateDepth = static_cast<size_t>(
                std::count(dominates[candidate].begin(), dominates[candidate].end(), true));
            if (candidateDepth > depth) {
                best = candidate;
                depth = candidateDepth;
            }
        }
        if (best != count) graph.metrics.immediateDominators[node] = best;
    }

    std::set<std::pair<size_t, size_t>> loopHeaders;
    for (const auto& edge : graph.edges) {
        if (!edge.to || !edge.targetResolved || !reachable[edge.from] || !reachable[*edge.to]) continue;
        ++graph.metrics.edgeCount;
        if (edge.kind == CfgEdgeKind::ConditionalTrue) ++graph.metrics.conditionalBranches;
        if (dominates[edge.from][*edge.to]) {
            ++graph.metrics.backEdges;
            loopHeaders.emplace(*edge.to, edge.from);
        }
    }
    std::set<size_t> headers;
    for (const auto& [header, tail] : loopHeaders) {
        (void)tail;
        headers.insert(header);
    }
    graph.metrics.naturalLoops = headers.size();
    size_t exitEdges = 0;
    for (size_t i = 0; i < count; ++i)
        if (reachable[i] && graph.blocks[i].isExit) ++exitEdges;
    for (const auto& edge : graph.edges)
        if (reachable[edge.from] && edge.kind == CfgEdgeKind::ExternalBranch) ++exitEdges;
    graph.metrics.cyclomaticComplexity =
        graph.metrics.edgeCount + exitEdges >= graph.metrics.reachableBlocks
            ? graph.metrics.edgeCount + exitEdges - graph.metrics.reachableBlocks + 1
            : 1;

    std::vector<int> index(count, -1), low(count, -1);
    std::vector<size_t> componentStack;
    std::vector<bool> onStack(count, false);
    int nextIndex = 0;
    size_t components = 0;
    std::function<void(size_t)> visit = [&](size_t node) {
        index[node] = nextIndex;
        low[node] = nextIndex++;
        componentStack.push_back(node);
        onStack[node] = true;
        for (const size_t successor : graph.blocks[node].successors) {
            if (!reachable[successor]) continue;
            if (index[successor] < 0) {
                visit(successor);
                low[node] = std::min(low[node], low[successor]);
            } else if (onStack[successor]) {
                low[node] = std::min(low[node], index[successor]);
            }
        }
        if (low[node] != index[node]) return;
        size_t members = 0;
        while (!componentStack.empty()) {
            const size_t member = componentStack.back();
            componentStack.pop_back();
            onStack[member] = false;
            ++members;
            if (member == node) break;
        }
        if (members > 1) ++components;
        else if (std::find(graph.blocks[node].successors.begin(), graph.blocks[node].successors.end(), node) !=
                 graph.blocks[node].successors.end()) ++components;
    };
    for (size_t node = 0; node < count; ++node)
        if (reachable[node] && index[node] < 0) visit(node);
    graph.metrics.stronglyConnectedComponents = components;
}

}  // namespace

bool cfgSupported(const BinaryInfo& info) {
    if (!disassemblerCompiledIn()) return false;
    return (info.arch == Arch::X86 && info.bits == 32) ||
           (info.arch == Arch::X86_64 && info.bits == 64) ||
           (info.arch == Arch::Arm64 && info.bits == 64);
}

std::vector<FunctionCandidate> discoverFunctionCandidates(const BinaryInfo& info, size_t maxCandidates) {
    std::vector<FunctionCandidate> result;
    if (maxCandidates == 0 || info.fileSize > static_cast<uint64_t>(SIZE_MAX)) return result;
    std::unordered_map<uint64_t, size_t> byAddress;

    if (info.entryPoint) {
        if (const auto range = executableRangeAtAddress(info, *info.entryPoint, static_cast<size_t>(info.fileSize))) {
            byAddress.emplace(*info.entryPoint, result.size());
            result.push_back({"Entry point", *info.entryPoint, range->offset, FunctionEvidence::EntryPoint, false});
        }
    }
    for (const auto& symbol : info.symbols.items)
        addCandidate(result, byAddress, info, symbol, FunctionEvidence::Symbol, maxCandidates);
    for (const auto& symbol : info.exports.items)
        addCandidate(result, byAddress, info, symbol, FunctionEvidence::Export, maxCandidates);
    if (result.empty()) {
        for (const auto& section : info.sections) {
            if (result.size() >= maxCandidates) break;
            if (!section.executable || !section.hasFileData || !section.boundsValid || section.fileSize == 0)
                continue;
            const auto range = executableRangeAtAddress(info, section.virtualAddress,
                                                        static_cast<size_t>(info.fileSize));
            if (!range || byAddress.contains(section.virtualAddress)) continue;
            byAddress.emplace(section.virtualAddress, result.size());
            const std::string name = section.name.empty() ? "Executable section start" : section.name + " start";
            result.push_back({name, section.virtualAddress, range->offset, FunctionEvidence::SectionStart, false});
        }
    }
    if (result.size() > maxCandidates) result.resize(maxCandidates);
    return result;
}

ControlFlowGraph analyzeControlFlow(const BinaryInfo& info, std::span<const uint8_t> data,
                                   const FunctionCandidate& function, const CfgOptions& options,
                                   const CfgProgressFn& progress, const CfgCancelFn& cancelled) {
    ControlFlowGraph graph;
    graph.function = function;
    if (!cfgSupported(info)) {
        graph.error = "CFG analysis is supported only for x86, x86-64, and ARM64 when Capstone is available.";
        return graph;
    }
    if (data.size() > static_cast<size_t>(UINT64_MAX)) {
        graph.error = "The file is too large for 64-bit CFG offsets.";
        return graph;
    }
    const auto range = executableRangeAtAddress(info, function.address, data.size());
    if (!range) {
        graph.error = "The function address is not mapped to file-backed executable bytes.";
        return graph;
    }
    if (options.maxBlocks == 0 || options.maxInstructionsPerBlock == 0) {
        graph.error = "CFG analysis limits must be greater than zero.";
        return graph;
    }

    std::deque<uint64_t> pending{function.address};
    std::unordered_set<uint64_t> queued{function.address};
    std::unordered_set<uint64_t> otherFunctionStarts;
    for (const auto& candidate : discoverFunctionCandidates(info))
        if (candidate.address != function.address && candidate.evidence != FunctionEvidence::SectionStart)
            otherFunctionStarts.insert(candidate.address);
    std::map<uint64_t, BlockDraft> drafts;
    std::map<uint64_t, uint64_t> decodedRanges;
    constexpr uint64_t maxBytesPerBlock = 64 * 1024;
    const uint64_t maxTotalDecodedBytes = options.maxDecodedBytes;
    uint64_t totalBytes = 0;
    size_t processed = 0;

    while (!pending.empty()) {
        if (cancelled && cancelled()) {
            graph.error = "CFG analysis cancelled.";
            return graph;
        }
        if (drafts.size() >= options.maxBlocks) {
            graph.truncated = true;
            break;
        }
        const uint64_t start = pending.front();
        pending.pop_front();
        if (drafts.contains(start)) continue;
        auto containing = drafts.upper_bound(start);
        if (containing != drafts.begin()) {
            auto parent = std::prev(containing);
            auto& current = parent->second;
            if (current.start < start && start < current.end) {
                const auto split = std::find_if(current.instructions.begin(), current.instructions.end(),
                                                [start](const Instruction& instruction) {
                                                    return instruction.address == start;
                                                });
                if (split != current.instructions.end()) {
                    BlockDraft suffix;
                    suffix.start = start;
                    suffix.offset = split->fileOffset;
                    suffix.end = current.end;
                    suffix.instructions.assign(split, current.instructions.end());
                    suffix.edges = std::move(current.edges);
                    suffix.exit = current.exit;
                    suffix.unresolved = current.unresolved;
                    current.instructions.erase(split, current.instructions.end());
                    current.end = start;
                    current.edges = {{start, CfgEdgeKind::Fallthrough, "split block"}};
                    current.exit = false;
                    current.unresolved = false;
                    drafts.emplace(start, std::move(suffix));
                    continue;
                }
            }
        }

        const uint64_t delta = start - range->address;
        if (delta >= range->size || range->offset > data.size() || delta > data.size() - range->offset) continue;
        const uint64_t offset = range->offset + delta;
        const uint64_t available = std::min(range->size - delta, maxTotalDecodedBytes - std::min(totalBytes, maxTotalDecodedBytes));
        if (available == 0) {
            graph.truncated = true;
            break;
        }
        DisasmRequest request;
        request.fileOffset = offset;
        request.maxBytes = std::min(available, maxBytesPerBlock);
        request.maxInstructions = options.maxInstructionsPerBlock;
        const auto decoded = disassemble(info, data, request);
        if (!decoded.ok) {
            graph.error = decoded.error;
            return graph;
        }

        BlockDraft block;
        block.start = start;
        block.offset = offset;
        block.end = start;
        bool terminated = false;
        for (const auto& instruction : decoded.instructions) {
            if (instruction.address < start || instruction.fileOffset < offset) continue;
            if (!block.instructions.empty() && instruction.address != block.end) break;
            const uint64_t instructionSize = static_cast<uint64_t>(instruction.bytes.size());
            if (instructionSize == 0 || instruction.address > UINT64_MAX - instructionSize ||
                instruction.fileOffset > UINT64_MAX - instructionSize) {
                graph.error = "Decoded instruction range overflows the file address space.";
                return graph;
            }
            if (auto existing = decodedRanges.upper_bound(instruction.address);
                existing != decodedRanges.begin() && std::prev(existing)->second > instruction.address) {
                block.unresolved = true;
                block.edges.push_back({instruction.address, CfgEdgeKind::Unresolved, "overlapping decode"});
                terminated = true;
                break;
            }
            if (auto existing = decodedRanges.find(instruction.address); existing != decodedRanges.end()) {
                if (instruction.address != start) {
                    block.edges.push_back({instruction.address, CfgEdgeKind::Fallthrough, "existing block"});
                    if (queued.insert(instruction.address).second) pending.push_back(instruction.address);
                    terminated = true;
                    break;
                }
            }
            block.instructions.push_back(instruction);
            block.end = instruction.address + instructionSize;
            totalBytes += instructionSize;

            if (!instruction.valid) {
                block.unresolved = true;
                block.edges.push_back({block.end, CfgEdgeKind::Unresolved, "invalid instruction"});
                terminated = true;
                break;
            }
            if (instruction.flow == InstructionFlow::Call) {
                graph.calls.push_back({instruction.address, instruction.flowTarget,
                                       instruction.flowTarget && *instruction.flowTarget == function.address});
            } else if (instruction.flow == InstructionFlow::IndirectCall) {
                graph.calls.push_back({instruction.address, std::nullopt, false});
            } else if (instruction.flow == InstructionFlow::Return) {
                block.exit = true;
                terminated = true;
                break;
            } else if (instruction.flow == InstructionFlow::ConditionalBranch) {
                const uint64_t fallthrough = block.end;
                if (instruction.flowTarget) {
                    block.edges.push_back({*instruction.flowTarget, CfgEdgeKind::ConditionalTrue, flowLabel(instruction)});
                    if (*instruction.flowTarget >= range->address &&
                        *instruction.flowTarget - range->address < range->size &&
                        !otherFunctionStarts.contains(*instruction.flowTarget) &&
                        queued.insert(*instruction.flowTarget).second)
                        pending.push_back(*instruction.flowTarget);
                } else {
                    block.unresolved = true;
                    block.edges.push_back({0, CfgEdgeKind::Unresolved, "unresolved conditional target"});
                }
                block.edges.push_back({fallthrough, CfgEdgeKind::ConditionalFalse, "fallthrough"});
                if (fallthrough >= range->address && fallthrough - range->address < range->size &&
                    !otherFunctionStarts.contains(fallthrough) &&
                    queued.insert(fallthrough).second)
                    pending.push_back(fallthrough);
                terminated = true;
                break;
            } else if (instruction.flow == InstructionFlow::UnconditionalBranch) {
                if (instruction.flowTarget) {
                    block.edges.push_back({*instruction.flowTarget, CfgEdgeKind::Unconditional, flowLabel(instruction)});
                    if (*instruction.flowTarget >= range->address &&
                        *instruction.flowTarget - range->address < range->size &&
                        !otherFunctionStarts.contains(*instruction.flowTarget) &&
                        queued.insert(*instruction.flowTarget).second)
                        pending.push_back(*instruction.flowTarget);
                } else {
                    block.unresolved = true;
                    block.edges.push_back({0, CfgEdgeKind::Unresolved, "unresolved branch target"});
                }
                terminated = true;
                break;
            } else if (instruction.flow == InstructionFlow::IndirectBranch) {
                block.unresolved = true;
                block.edges.push_back({0, CfgEdgeKind::Unresolved, "indirect branch"});
                terminated = true;
                break;
            }
        }

        if (block.instructions.empty()) {
            block.unresolved = true;
            block.edges.push_back({start, CfgEdgeKind::Unresolved, "no instruction decoded"});
            block.end = start;
        } else if (!terminated) {
            block.unresolved = true;
            block.edges.push_back({block.end, CfgEdgeKind::Unresolved, "block decode limit reached"});
            graph.truncated = true;
        }
        for (const auto& instruction : block.instructions)
            decodedRanges.emplace(instruction.address,
                                  instruction.address + static_cast<uint64_t>(instruction.bytes.size()));
        graph.analyzedBytes = totalBytes;
        drafts.emplace(start, std::move(block));
        ++processed;
        if (progress) progress(pending.empty() ? 100 : static_cast<int>(std::min<size_t>(99, processed * 100 / (processed + pending.size()))),
                               "Analyzing control flow");
    }

    if (drafts.empty()) {
        graph.error = "No basic blocks could be decoded at the selected function address.";
        return graph;
    }
    if (!pending.empty()) graph.truncated = true;

    std::unordered_map<uint64_t, size_t> blockIds;
    graph.blocks.reserve(drafts.size());
    std::vector<uint64_t> orderedAddresses;
    orderedAddresses.reserve(drafts.size());
    orderedAddresses.push_back(function.address);
    for (const auto& [address, draft] : drafts) {
        (void)draft;
        if (address != function.address) orderedAddresses.push_back(address);
    }
    for (const uint64_t address : orderedAddresses) {
        const auto& draft = drafts.at(address);
        const size_t id = graph.blocks.size();
        blockIds.emplace(address, id);
        BasicBlock block;
        block.id = id;
        block.startAddress = draft.start;
        block.endAddress = draft.end;
        block.fileOffset = draft.offset;
        block.instructions = draft.instructions;
        block.isEntry = address == function.address;
        block.isExit = draft.exit;
        block.hasUnresolvedFlow = draft.unresolved;
        graph.blocks.push_back(std::move(block));
    }
    for (const auto& [address, draft] : drafts) {
        const size_t from = blockIds.at(address);
        for (const auto& edge : draft.edges) {
            CfgEdge result;
            result.from = from;
            result.targetAddress = edge.target;
            result.kind = edge.kind;
            result.label = edge.label;
            if (const auto target = blockIds.find(edge.target); target != blockIds.end() &&
                edge.kind != CfgEdgeKind::Unresolved) {
                result.to = target->second;
                result.targetResolved = true;
            } else if (edge.kind != CfgEdgeKind::Unresolved) {
                result.targetResolved = false;
                const bool inCodeRange = edge.target >= range->address &&
                                         edge.target - range->address < range->size &&
                                         !otherFunctionStarts.contains(edge.target);
                result.kind = inCodeRange ? CfgEdgeKind::Unresolved : CfgEdgeKind::ExternalBranch;
                if (result.label.empty())
                    result.label = inCodeRange ? "target block not analyzed" : "outside analyzed function";
            }
            graph.edges.push_back(std::move(result));
        }
    }
    for (const auto& edge : graph.edges) {
        if (!edge.to || !edge.targetResolved) continue;
        graph.blocks[edge.from].successors.push_back(*edge.to);
        graph.blocks[*edge.to].predecessors.push_back(edge.from);
    }
    computeMetrics(graph);
    graph.ok = true;
    if (progress) progress(100, "Control-flow graph complete");
    return graph;
}

std::string exportCfgJson(const ControlFlowGraph& graph) {
    Json root = Json::object();
    root.set("schema_version", "1.0");
    root.set("function", graph.function.name);
    root.set("entry_address", hex(graph.function.address));
    root.set("evidence", evidenceName(graph.function.evidence));
    root.set("start_confirmed", graph.function.startConfirmed);
    root.set("ok", graph.ok);
    root.set("error", graph.error);
    root.set("truncated", graph.truncated);
    root.set("analyzed_bytes", graph.analyzedBytes);
    Json blocks = Json::array();
    for (const auto& block : graph.blocks) {
        Json item = Json::object();
        item.set("id", static_cast<int64_t>(block.id));
        item.set("start_address", hex(block.startAddress));
        item.set("end_address_exclusive", hex(block.endAddress));
        item.set("file_offset", hex(block.fileOffset));
        item.set("instruction_count", static_cast<int64_t>(block.instructions.size()));
        item.set("entry", block.isEntry);
        item.set("exit", block.isExit);
        item.set("unresolved_flow", block.hasUnresolvedFlow);
        Json instructions = Json::array();
        for (const auto& instruction : block.instructions) instructions.push(instructionJson(instruction));
        item.set("instructions", std::move(instructions));
        blocks.push(std::move(item));
    }
    root.set("blocks", std::move(blocks));
    Json edges = Json::array();
    for (const auto& edge : graph.edges) {
        Json item = Json::object();
        item.set("from", static_cast<int64_t>(edge.from));
        if (edge.to) item.set("to", static_cast<int64_t>(*edge.to));
        else item.set("to", Json());
        item.set("target_address", hex(edge.targetAddress));
        item.set("kind", edgeKindName(edge.kind));
        item.set("label", edge.label);
        item.set("target_resolved", edge.targetResolved);
        edges.push(std::move(item));
    }
    root.set("edges", std::move(edges));
    Json calls = Json::array();
    for (const auto& call : graph.calls) {
        Json item = Json::object();
        item.set("instruction_address", hex(call.instructionAddress));
        item.set("target_address", call.targetAddress ? Json(hex(*call.targetAddress)) : Json());
        item.set("recursive", call.recursive);
        calls.push(std::move(item));
    }
    root.set("calls", std::move(calls));
    Json metrics = Json::object();
    metrics.set("reachable_blocks", static_cast<int64_t>(graph.metrics.reachableBlocks));
    metrics.set("edge_count", static_cast<int64_t>(graph.metrics.edgeCount));
    metrics.set("conditional_branches", static_cast<int64_t>(graph.metrics.conditionalBranches));
    metrics.set("back_edges", static_cast<int64_t>(graph.metrics.backEdges));
    metrics.set("natural_loops", static_cast<int64_t>(graph.metrics.naturalLoops));
    metrics.set("strongly_connected_components", static_cast<int64_t>(graph.metrics.stronglyConnectedComponents));
    metrics.set("cyclomatic_complexity", static_cast<int64_t>(graph.metrics.cyclomaticComplexity));
    root.set("metrics", std::move(metrics));
    return root.dump();
}

std::string exportCfgDot(const ControlFlowGraph& graph) {
    std::string out = "digraph CFG {\n  rankdir=TB;\n  node [shape=box, fontname=\"monospace\"];\n";
    for (const auto& block : graph.blocks) {
        out += "  b" + std::to_string(block.id) + " [label=\"" + hex(block.startAddress) + "\\n";
        for (const auto& instruction : block.instructions) {
            for (char c : instruction.mnemonic + " " + instruction.operands) {
                if (c == '"' || c == '\\') out.push_back('\\');
                if (c == '\n' || c == '\r') out += "\\n";
                else out.push_back(c);
            }
            out += "\\n";
        }
        out += "\"";
        if (block.isEntry) out += ", style=bold";
        if (block.hasUnresolvedFlow) out += ", color=orange";
        out += "];\n";
    }
    for (const auto& edge : graph.edges) {
        if (edge.to)
            out += "  b" + std::to_string(edge.from) + " -> b" + std::to_string(*edge.to) +
                   " [label=\"" + edgeKindName(edge.kind) + (edge.label.empty() ? "" : ": " + edge.label) + "\"];\n";
        else
            out += "  b" + std::to_string(edge.from) + " -> \"external_" + hex(edge.targetAddress) +
                   "\" [style=dashed, label=\"" + edgeKindName(edge.kind) + "\"];\n";
    }
    out += "}\n";
    return out;
}

}  // namespace xrl
