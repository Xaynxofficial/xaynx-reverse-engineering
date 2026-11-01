#include "xrl/xref.hpp"

#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <unordered_set>

#include "xrl/util.hpp"

namespace xrl {
namespace {

std::string addressText(const std::optional<uint64_t>& value) {
    return value ? hex(*value) : std::string{};
}

std::string csvEscape(const std::string& value) {
    std::string escaped = "\"";
    for (const char c : value) {
        if (c == '"') escaped += "\"\"";
        else escaped.push_back(c);
    }
    escaped.push_back('"');
    return escaped;
}

std::string dotEscape(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (const char c : value) {
        if (c == '\\' || c == '"') escaped.push_back('\\');
        if (c == '\n' || c == '\r') {
            escaped += "\\n";
            continue;
        }
        escaped.push_back(c);
    }
    return escaped;
}

Json optionalAddress(const std::optional<uint64_t>& address) {
    return address ? Json(hex(*address)) : Json();
}

}  // namespace

const char* toString(XrefType type) {
    switch (type) {
        case XrefType::Code: return "code";
        case XrefType::Data: return "data";
        case XrefType::Call: return "call";
        case XrefType::ConditionalBranch: return "conditional-branch";
        case XrefType::UnconditionalBranch: return "unconditional-branch";
        case XrefType::Import: return "import";
        case XrefType::Export: return "export";
        case XrefType::Relocation: return "relocation";
        case XrefType::String: return "string";
        case XrefType::Symbol: return "symbol";
    }
    return "code";
}

const char* toString(XrefConfidence confidence) {
    switch (confidence) {
        case XrefConfidence::Confirmed: return "confirmed";
        case XrefConfidence::Inferred: return "inferred";
        case XrefConfidence::Unresolved: return "unresolved";
    }
    return "unresolved";
}

XrefResult analyzeCrossReferences(const BinaryInfo& info, std::span<const uint8_t> fileData,
                                  const StringExtractionResult* strings, const XrefOptions& options,
                                  const XrefProgressFn& progress, const XrefCancelFn& cancelled) {
    XrefResult result;
    result.fileSize = fileData.size();
    result.sha256 = info.sha256;
    if (fileData.size() != info.fileSize) {
        result.error = "Loaded file data size does not match parsed metadata.";
        return result;
    }
    if (!cfgSupported(info)) {
        result.error = "XREF code analysis requires Capstone and a supported x86, x86-64, or ARM64 executable.";
        return result;
    }
    if (options.maxFunctions == 0 || options.maxReferences == 0 ||
        options.maxBlocksPerFunction == 0 || options.maxTotalDecodedBytes == 0) {
        result.error = "XREF analysis limits must be greater than zero.";
        return result;
    }
    const bool usableStrings = strings && strings->ok && strings->fileSize == fileData.size() &&
                               !info.sha256.empty() && strings->sha256 == info.sha256;
    if (strings && strings->ok && !usableStrings)
        result.warnings.push_back("String references were omitted because string results do not match the loaded file SHA-256.");

    auto isCancelled = [&] {
        if (cancelled && cancelled()) {
            result.cancelled = true;
            result.error = "XREF analysis cancelled.";
            return true;
        }
        return false;
    };
    auto report = [&](int percent, const char* stage) {
        if (progress) progress(percent, stage);
    };
    const auto candidates = discoverFunctionCandidates(info);
    if (candidates.empty()) {
        result.error = "No executable function candidates were discovered from available file metadata.";
        return result;
    }
    const size_t functionLimit = std::min(options.maxFunctions, candidates.size());
    if (functionLimit < candidates.size()) {
        result.truncated = true;
        result.warnings.push_back("Function analysis stopped at the configured candidate limit.");
    }
    result.functions.reserve(functionLimit);
    std::unordered_map<uint64_t, size_t> functionIndex;
    for (size_t i = 0; i < functionLimit; ++i) {
        functionIndex.emplace(candidates[i].address, i);
        result.functions.push_back({candidates[i]});
    }

    std::unordered_map<uint64_t, std::vector<const Symbol*>> symbolsAt;
    std::unordered_set<const Symbol*> importedSymbols;
    std::unordered_set<const Symbol*> exportedSymbols;
    importedSymbols.reserve(info.imports.items.size());
    exportedSymbols.reserve(info.exports.items.size());
    for (const auto& symbol : info.imports.items) importedSymbols.insert(&symbol);
    for (const auto& symbol : info.exports.items) exportedSymbols.insert(&symbol);
    for (const auto* category : {&info.imports, &info.exports, &info.symbols})
        for (const auto& symbol : category->items)
            if (symbol.address) symbolsAt[*symbol.address].push_back(&symbol);
    std::unordered_map<uint64_t, const ExtractedString*> stringsAt;
    if (usableStrings)
        for (const auto& string : strings->strings)
            if (string.offset < fileData.size() && string.length > 0 &&
                string.length <= fileData.size() - string.offset)
                stringsAt.emplace(string.offset, &string);

    std::set<std::tuple<uint64_t, uint64_t, int, uint64_t>> dedup;
    auto addReference = [&](XrefReference reference) {
        if (result.references.size() >= options.maxReferences) {
            result.truncated = true;
            return false;
        }
        const uint64_t source = reference.sourceAddress.value_or(UINT64_MAX);
        const uint64_t destination = reference.destinationAddress.value_or(UINT64_MAX);
        const uint64_t instruction = reference.instructionAddress.value_or(UINT64_MAX);
        const auto key = std::make_tuple(source, destination, static_cast<int>(reference.type), instruction);
        if (!dedup.insert(key).second) return true;
        const size_t index = result.references.size();
        result.references.push_back(std::move(reference));
        const auto& added = result.references.back();
        if (added.sourceAddress) result.outgoingByAddress[*added.sourceAddress].push_back(index);
        if (added.destinationAddress) result.incomingByAddress[*added.destinationAddress].push_back(index);
        return true;
    };

    auto enrichSymbols = [&](XrefReference& reference, uint64_t target) {
        auto found = symbolsAt.find(target);
        if (found == symbolsAt.end()) return;
        for (const auto* symbol : found->second) {
            if (reference.symbolName.empty() && !symbol->name.empty()) reference.symbolName = symbol->name;
            XrefReference symbolRef = reference;
            symbolRef.type = XrefType::Symbol;
            symbolRef.dataTarget = symbol->name;
            symbolRef.evidenceSource = "direct instruction target matches parsed symbol address";
            addReference(std::move(symbolRef));
            if (importedSymbols.contains(symbol)) {
                XrefReference importRef = reference;
                importRef.type = XrefType::Import;
                importRef.dataTarget = symbol->library.empty() ? symbol->name : symbol->library + "!" + symbol->name;
                importRef.evidenceSource = "instruction target matches parsed import address";
                addReference(std::move(importRef));
            } else if (exportedSymbols.contains(symbol)) {
                XrefReference exportRef = reference;
                exportRef.type = XrefType::Export;
                exportRef.dataTarget = symbol->name;
                exportRef.evidenceSource = "instruction target matches parsed export address";
                addReference(std::move(exportRef));
            }
        }
    };

    for (size_t fi = 0; fi < functionLimit; ++fi) {
        if (isCancelled()) return result;
        const auto& candidate = candidates[fi];
        const uint64_t remainingBudget = options.maxTotalDecodedBytes -
                                         std::min(options.maxTotalDecodedBytes, result.analyzedBytes);
        if (remainingBudget == 0) {
            result.truncated = true;
            result.warnings.push_back("Total XREF instruction decoding budget was reached.");
            break;
        }
        CfgOptions cfgOptions;
        cfgOptions.maxBlocks = options.maxBlocksPerFunction;
        cfgOptions.maxDecodedBytes = remainingBudget;
        const auto cfg = analyzeControlFlow(info, fileData, candidate, cfgOptions, {}, cancelled);
        if (!cfg.ok) {
            if (isCancelled()) return result;
            result.warnings.push_back("Could not analyze " + candidate.name + " at " + hex(candidate.address) +
                                      ": " + cfg.error);
            continue;
        }
        ++result.analyzedFunctions;
        result.analyzedBytes += cfg.analyzedBytes;
        if (cfg.truncated) {
            result.truncated = true;
            result.warnings.push_back("CFG decoding for " + candidate.name + " reached a configured limit.");
        }
        const auto sourceFunction = candidate.address;
        std::vector<std::vector<const CfgEdge*>> edgesByBlock(cfg.blocks.size());
        for (const auto& edge : cfg.edges)
            if (edge.from < edgesByBlock.size()) edgesByBlock[edge.from].push_back(&edge);
        for (const auto& block : cfg.blocks) {
            if (block.instructions.empty()) continue;
            const auto& terminator = block.instructions.back();
            if (block.id >= edgesByBlock.size()) continue;
            for (const auto* edgePointer : edgesByBlock[block.id]) {
                const auto& edge = *edgePointer;
                if (edge.kind == CfgEdgeKind::Fallthrough || edge.kind == CfgEdgeKind::ConditionalFalse) continue;
                XrefReference reference;
                reference.sourceAddress = terminator.address;
                reference.destinationAddress = edge.targetAddress ? std::optional<uint64_t>(edge.targetAddress) : std::nullopt;
                reference.sourceFunction = sourceFunction;
                reference.sourceFunctionName = candidate.name;
                reference.instructionAddress = terminator.address;
                reference.fileOffset = terminator.fileOffset;
                reference.confidence = edge.kind == CfgEdgeKind::Unresolved
                                           ? XrefConfidence::Unresolved : XrefConfidence::Confirmed;
                reference.type = edge.kind == CfgEdgeKind::ConditionalTrue
                                    ? XrefType::ConditionalBranch
                                    : edge.kind == CfgEdgeKind::Unconditional || edge.kind == CfgEdgeKind::ExternalBranch
                                          ? XrefType::UnconditionalBranch : XrefType::Code;
                reference.evidenceSource = "Capstone-decoded instruction and existing CFG edge";
                if (reference.destinationAddress) {
                    if (const auto offset = info.virtualToFileOffset(*reference.destinationAddress);
                        offset && *offset < fileData.size())
                        reference.destinationFileOffset = *offset;
                    if (const auto target = functionIndex.find(*reference.destinationAddress);
                        target != functionIndex.end()) {
                        reference.destinationFunction = *reference.destinationAddress;
                        reference.destinationFunctionName = candidates[target->second].name;
                    }
                    enrichSymbols(reference, *reference.destinationAddress);
                }
                addReference(std::move(reference));
            }
            for (const auto& instruction : block.instructions) {
                if (instruction.flow == InstructionFlow::Call || instruction.flow == InstructionFlow::IndirectCall) {
                    XrefReference reference;
                    reference.sourceAddress = instruction.address;
                    reference.destinationAddress = instruction.flowTarget;
                    reference.sourceFunction = sourceFunction;
                    reference.sourceFunctionName = candidate.name;
                    reference.instructionAddress = instruction.address;
                    reference.fileOffset = instruction.fileOffset;
                    reference.type = XrefType::Call;
                    reference.confidence = instruction.flowTarget ? XrefConfidence::Confirmed : XrefConfidence::Unresolved;
                    reference.evidenceSource = instruction.flowTarget
                                                   ? "Capstone-decoded direct call target"
                                                   : "Capstone identified an indirect call; target unresolved";
                    if (instruction.flowTarget) {
                        if (const auto offset = info.virtualToFileOffset(*instruction.flowTarget);
                            offset && *offset < fileData.size())
                            reference.destinationFileOffset = *offset;
                        if (const auto target = functionIndex.find(*instruction.flowTarget);
                            target != functionIndex.end()) {
                            reference.destinationFunction = *instruction.flowTarget;
                            reference.destinationFunctionName = candidates[target->second].name;
                        }
                        enrichSymbols(reference, *instruction.flowTarget);
                    } else {
                        ++result.unresolvedIndirectCalls;
                        ++result.functions[fi].unresolvedIndirectCalls;
                    }
                    addReference(std::move(reference));
                } else if (instruction.flow == InstructionFlow::None) {
                    for (const uint64_t target : instruction.dataTargets) {
                        XrefReference reference;
                        reference.sourceAddress = instruction.address;
                        reference.destinationAddress = target;
                        reference.sourceFunction = sourceFunction;
                        reference.sourceFunctionName = candidate.name;
                        reference.instructionAddress = instruction.address;
                        reference.fileOffset = instruction.fileOffset;
                        reference.type = XrefType::Data;
                        reference.confidence = XrefConfidence::Confirmed;
                        reference.evidenceSource = "Capstone statically resolved memory or ADR address operand";
                        if (const auto offset = info.virtualToFileOffset(target)) {
                            if (*offset < fileData.size()) {
                                reference.destinationFileOffset = *offset;
                                reference.dataTarget = "file data";
                                if (const auto string = stringsAt.find(*offset); string != stringsAt.end()) {
                                    reference.dataTarget = string->second->value;
                                    XrefReference stringRef = reference;
                                    stringRef.type = XrefType::String;
                                    stringRef.evidenceSource = "resolved instruction data address matches extracted string start";
                                    addReference(std::move(stringRef));
                                }
                            }
                        }
                        enrichSymbols(reference, target);
                        addReference(std::move(reference));
                    }
                }
            }
        }
        if (result.truncated && result.references.size() >= options.maxReferences) break;
        report(static_cast<int>((fi + 1) * 90 / functionLimit), "Indexing function references");
    }

    for (const auto& relocation : info.relocations.items) {
        if (result.references.size() >= options.maxReferences) {
            result.truncated = true;
            result.warnings.push_back("XREF index reached the reference limit while adding relocations.");
            break;
        }
        XrefReference reference;
        reference.sourceAddress = relocation.address;
        reference.destinationAddress = relocation.targetAddress;
        reference.fileOffset = relocation.fileOffset;
        reference.type = XrefType::Relocation;
        reference.confidence = relocation.targetAddress ? XrefConfidence::Inferred : XrefConfidence::Unresolved;
        reference.symbolName = relocation.symbolName;
        reference.dataTarget = relocation.typeName;
        reference.evidenceSource = relocation.source;
        if (relocation.targetAddress) {
            if (const auto offset = info.virtualToFileOffset(*relocation.targetAddress);
                offset && *offset < fileData.size())
                reference.destinationFileOffset = *offset;
        }
        addReference(std::move(reference));
    }

    std::vector<std::vector<size_t>> calls(result.functions.size());
    for (const auto& reference : result.references) {
        if (reference.type != XrefType::Call || !reference.destinationFunction || !reference.sourceFunction) continue;
        const auto source = functionIndex.find(*reference.sourceFunction);
        const auto target = functionIndex.find(*reference.destinationFunction);
        if (source == functionIndex.end() || target == functionIndex.end()) continue;
        calls[source->second].push_back(target->second);
        ++result.functions[source->second].outgoingCalls;
        ++result.functions[target->second].incomingCalls;
        if (source->second == target->second) result.functions[source->second].recursive = true;
    }

    std::vector<uint8_t> state(result.functions.size(), 0);
    std::vector<size_t> depth(result.functions.size(), 0);
    std::vector<size_t> stack;
    std::function<size_t(size_t)> measureDepth = [&](size_t node) -> size_t {
        if (state[node] == 2) return depth[node];
        if (state[node] == 1) {
            const auto cycle = std::find(stack.begin(), stack.end(), node);
            for (auto it = cycle; it != stack.end(); ++it) result.functions[*it].recursive = true;
            return 0;
        }
        state[node] = 1;
        stack.push_back(node);
        size_t longest = 0;
        for (const size_t target : calls[node]) {
            if (state[target] == 1) {
                const auto cycle = std::find(stack.begin(), stack.end(), target);
                for (auto it = cycle; it != stack.end(); ++it) result.functions[*it].recursive = true;
                continue;
            }
            longest = std::max(longest, 1 + measureDepth(target));
        }
        stack.pop_back();
        state[node] = 2;
        depth[node] = longest;
        result.functions[node].callDepth = longest;
        return longest;
    };
    for (size_t i = 0; i < result.functions.size(); ++i) measureDepth(i);

    std::unordered_set<uint64_t> called;
    std::unordered_set<uint64_t> referencedStringOffsets;
    for (const auto& reference : result.references) {
        if (reference.type == XrefType::Call && reference.destinationFunction)
            called.insert(*reference.destinationFunction);
        if (reference.type == XrefType::String && reference.destinationAddress) {
            if (const auto offset = info.virtualToFileOffset(*reference.destinationAddress))
                referencedStringOffsets.insert(*offset);
        }
    }
    for (const auto& function : result.functions)
        if (!called.contains(function.candidate.address) &&
            function.candidate.evidence != FunctionEvidence::EntryPoint &&
            function.candidate.evidence != FunctionEvidence::SectionStart)
            result.unreferencedFunctionCandidates.push_back(function.candidate.address);
    if (usableStrings)
        for (const auto& string : strings->strings)
            if (!referencedStringOffsets.contains(string.offset))
                result.unreferencedStringOffsets.push_back(string.offset);

    result.ok = true;
    report(100, "XREF indexing complete");
    return result;
}

std::string renderXrefJson(const XrefResult& result) {
    Json root = Json::object();
    root.set("schema_version", "1.0");
    root.set("ok", result.ok);
    root.set("cancelled", result.cancelled);
    root.set("truncated", result.truncated);
    root.set("error", result.error);
    root.set("file_size", result.fileSize);
    root.set("sha256", result.sha256);
    root.set("analyzed_functions", static_cast<uint64_t>(result.analyzedFunctions));
    root.set("analyzed_bytes", result.analyzedBytes);
    root.set("unresolved_indirect_calls", static_cast<uint64_t>(result.unresolvedIndirectCalls));
    Json warnings = Json::array();
    for (const auto& warning : result.warnings) warnings.push(warning);
    root.set("warnings", std::move(warnings));
    Json functions = Json::array();
    for (const auto& function : result.functions) {
        Json item = Json::object();
        item.set("name", function.candidate.name);
        item.set("address", hex(function.candidate.address));
        item.set("file_offset", hex(function.candidate.fileOffset));
        item.set("start_confirmed", function.candidate.startConfirmed);
        item.set("incoming_calls", static_cast<uint64_t>(function.incomingCalls));
        item.set("outgoing_calls", static_cast<uint64_t>(function.outgoingCalls));
        item.set("call_depth", static_cast<uint64_t>(function.callDepth));
        item.set("recursive", function.recursive);
        item.set("unresolved_indirect_calls", static_cast<uint64_t>(function.unresolvedIndirectCalls));
        functions.push(std::move(item));
    }
    root.set("functions", std::move(functions));
    Json references = Json::array();
    for (const auto& reference : result.references) {
        Json item = Json::object();
        item.set("source_address", optionalAddress(reference.sourceAddress));
        item.set("destination_address", optionalAddress(reference.destinationAddress));
        item.set("source_function", optionalAddress(reference.sourceFunction));
        item.set("destination_function", optionalAddress(reference.destinationFunction));
        item.set("instruction_address", optionalAddress(reference.instructionAddress));
        item.set("file_offset", optionalAddress(reference.fileOffset));
        item.set("destination_file_offset", optionalAddress(reference.destinationFileOffset));
        item.set("type", toString(reference.type));
        item.set("confidence", toString(reference.confidence));
        item.set("source_function_name", reference.sourceFunctionName);
        item.set("destination_function_name", reference.destinationFunctionName);
        item.set("symbol_name", reference.symbolName);
        item.set("data_target", reference.dataTarget);
        item.set("evidence_source", reference.evidenceSource);
        references.push(std::move(item));
    }
    root.set("references", std::move(references));
    Json unreferencedFunctions = Json::array();
    for (const uint64_t address : result.unreferencedFunctionCandidates)
        unreferencedFunctions.push(hex(address));
    root.set("unreferenced_function_candidates", std::move(unreferencedFunctions));
    Json unreferencedStrings = Json::array();
    for (const uint64_t offset : result.unreferencedStringOffsets)
        unreferencedStrings.push(hex(offset));
    root.set("unreferenced_string_candidates", std::move(unreferencedStrings));
    return root.dump(2) + "\n";
}

std::string renderXrefCsv(const XrefResult& result) {
    std::ostringstream csv;
    csv << "source_address,destination_address,source_function,destination_function,instruction_address,"
           "file_offset,destination_file_offset,type,confidence,symbol_name,data_target,evidence_source\n";
    for (const auto& reference : result.references) {
        csv << csvEscape(addressText(reference.sourceAddress)) << ','
            << csvEscape(addressText(reference.destinationAddress)) << ','
            << csvEscape(reference.sourceFunctionName) << ','
            << csvEscape(reference.destinationFunctionName) << ','
            << csvEscape(addressText(reference.instructionAddress)) << ','
            << csvEscape(addressText(reference.fileOffset)) << ','
            << csvEscape(addressText(reference.destinationFileOffset)) << ','
            << csvEscape(toString(reference.type)) << ','
            << csvEscape(toString(reference.confidence)) << ','
            << csvEscape(reference.symbolName) << ','
            << csvEscape(reference.dataTarget) << ','
            << csvEscape(reference.evidenceSource) << '\n';
    }
    return csv.str();
}

std::string renderXrefDot(const XrefResult& result, size_t maxNodes, size_t maxEdges) {
    std::ostringstream dot;
    dot << "digraph xref {\n  rankdir=LR;\n  node [shape=box];\n";
    std::unordered_map<std::string, size_t> nodeIds;
    std::vector<std::pair<std::string, std::string>> nodes;
    struct DotEdge { size_t from; size_t to; std::string label; std::string tooltip; };
    std::vector<DotEdge> edges;
    std::set<std::tuple<size_t, size_t, std::string, uint64_t>> uniqueEdges;
    bool graphTruncated = false;
    auto addNode = [&](std::string key, std::string label) -> std::optional<size_t> {
        if (const auto found = nodeIds.find(key); found != nodeIds.end()) return found->second;
        if (nodes.size() >= maxNodes) return std::nullopt;
        const size_t id = nodes.size();
        nodeIds.emplace(std::move(key), id);
        nodes.emplace_back("n" + std::to_string(id), std::move(label));
        return id;
    };
    for (const auto& reference : result.references) {
        if (edges.size() >= maxEdges) {
            graphTruncated = true;
            break;
        }
        if (!reference.sourceAddress) continue;
        const uint64_t sourceAddress = reference.sourceFunction.value_or(*reference.sourceAddress);
        const std::string sourceKey = reference.sourceFunction
                                          ? "function:" + hex(sourceAddress)
                                          : "address:" + hex(sourceAddress);
        const std::string sourceLabel = (reference.sourceFunctionName.empty() ? "Address" : reference.sourceFunctionName) +
                                        "\n" + hex(sourceAddress);
        const auto from = addNode(sourceKey, sourceLabel);
        if (!from) {
            graphTruncated = true;
            continue;
        }

        std::string targetKey;
        std::string targetLabel;
        if (reference.destinationAddress) {
            const uint64_t address = *reference.destinationAddress;
            if (reference.destinationFunction) {
                targetKey = "function:" + hex(address);
                targetLabel = (reference.destinationFunctionName.empty() ? "Function" : reference.destinationFunctionName) +
                              "\n" + hex(address);
            } else if (reference.type == XrefType::String) {
                targetKey = "string:" + hex(address);
                targetLabel = (reference.dataTarget.empty() ? "String" : reference.dataTarget) + "\n" + hex(address);
            } else if (!reference.symbolName.empty()) {
                targetKey = "symbol:" + hex(address) + ":" + reference.symbolName;
                targetLabel = reference.symbolName + "\n" + hex(address);
            } else {
                targetKey = "address:" + hex(address);
                targetLabel = "Address\n" + hex(address);
            }
        } else {
            targetKey = "unresolved:" + hex(reference.instructionAddress.value_or(*reference.sourceAddress));
            targetLabel = "Indirect target unresolved";
        }
        const auto to = addNode(targetKey, targetLabel);
        if (!to) {
            graphTruncated = true;
            continue;
        }
        const std::string type = toString(reference.type);
        const uint64_t evidenceAddress = reference.instructionAddress.value_or(*reference.sourceAddress);
        if (uniqueEdges.emplace(*from, *to, type, evidenceAddress).second) {
            std::ostringstream tooltip;
            tooltip << "source=" << addressText(reference.sourceAddress)
                    << "; destination=" << addressText(reference.destinationAddress)
                    << "; instruction=" << addressText(reference.instructionAddress)
                    << "; file_offset=" << addressText(reference.fileOffset)
                    << "; destination_file_offset=" << addressText(reference.destinationFileOffset)
                    << "; confidence=" << toString(reference.confidence);
            if (!reference.symbolName.empty()) tooltip << "; symbol=" << reference.symbolName;
            if (!reference.evidenceSource.empty()) tooltip << "; evidence=" << reference.evidenceSource;
            edges.push_back({*from, *to, type, tooltip.str()});
        }
    }
    for (const auto& [id, label] : nodes)
        dot << "  " << id << " [label=\"" << dotEscape(label) << "\"];\n";
    for (const auto& edge : edges)
        dot << "  n" << edge.from << " -> n" << edge.to << " [label=\"" << dotEscape(edge.label)
            << "\", tooltip=\"" << dotEscape(edge.tooltip) << "\"];\n";
    if (graphTruncated)
        dot << "  omitted [label=\"Graph bounded to " << maxNodes << " nodes; some references omitted\"];\n";
    dot << "}\n";
    return dot.str();
}

}  // namespace xrl
