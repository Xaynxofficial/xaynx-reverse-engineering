#include "xrl/static_analysis.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <ctime>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "xrl/util.hpp"

#ifndef XRL_VERSION
#define XRL_VERSION "unknown"
#endif

namespace xrl {
namespace {

constexpr size_t kMaxFindings = 600;
constexpr size_t kMaxStringEvidence = 250;

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string nowUtc() {
    const std::time_t now = std::time(nullptr);
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    std::ostringstream out;
    out << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

bool hasAny(const std::string& value, std::initializer_list<std::string_view> needles) {
    for (const auto needle : needles)
        if (value.find(needle) != std::string::npos) return true;
    return false;
}

unsigned severityWeight(StaticSeverity severity) {
    switch (severity) {
        case StaticSeverity::Informational: return 0;
        case StaticSeverity::Low: return 8;
        case StaticSeverity::Medium: return 18;
        case StaticSeverity::High: return 32;
        case StaticSeverity::Critical: return 45;
    }
    return 0;
}

std::string evidenceKey(const std::string& prefix, uint64_t offset, const std::string& suffix = {}) {
    return prefix + ":" + std::to_string(offset) + ":" + suffix;
}

void report(const StaticProgressFn& progress, int percent, const char* stage) {
    if (progress) progress(percent, stage);
}

void addFinding(StaticAnalysisResult& result, StaticFinding finding) {
    if (result.findings.size() >= kMaxFindings) return;
    finding.id = finding.ruleId + "." + std::to_string(result.findings.size() + 1);
    result.findings.push_back(std::move(finding));
}

StaticFinding makeFinding(std::string ruleId, std::string title, std::string description,
                          StaticCategory category, StaticSeverity severity,
                          unsigned confidence, unsigned quality, StaticView view,
                          StaticEvidence evidence, std::string why, std::string benign,
                          std::string next) {
    StaticFinding finding;
    finding.ruleId = std::move(ruleId);
    finding.title = std::move(title);
    finding.description = std::move(description);
    finding.category = category;
    finding.severity = severity;
    finding.confidence = confidence;
    finding.evidenceQuality = quality;
    finding.relatedView = view;
    finding.evidence.push_back(std::move(evidence));
    finding.whyItMatters = std::move(why);
    finding.benignExplanations = std::move(benign);
    finding.nextSteps = std::move(next);
    return finding;
}

std::optional<uint64_t> sectionOffset(const Section& section, uint64_t fileSize) {
    if (!section.hasFileData || !section.boundsValid || section.fileOffset > fileSize ||
        section.fileSize > fileSize - section.fileOffset || section.fileSize == 0) return std::nullopt;
    return section.fileOffset;
}

std::vector<std::string> importCategories(const Symbol& symbol) {
    const std::string name = lowercase(symbol.name);
    std::vector<std::string> categories;
    auto add = [&](const char* label) { categories.emplace_back(label); };
    if (hasAny(name, {"writeprocessmemory", "createremotethread", "virtualallocex",
                      "ntunmapviewofsection", "ptrace", "process_vm_writev"}))
        add("Cross-process memory / process control");
    if (hasAny(name, {"virtualalloc", "virtualprotect", "mmap", "mprotect", "heapalloc"}))
        add("Memory management");
    if (hasAny(name, {"loadlibrary", "getprocaddress", "dlopen", "dlsym"}))
        add("Dynamic library loading");
    if (hasAny(name, {"winhttp", "internetopen", "internetconnect", "httpsendrequest",
                      "socket", "connect", "send", "recv", "curl_easy"}))
        add("Network communication");
    if (hasAny(name, {"bcrypt", "crypt", "evp_", "ssl_", "crypto"}))
        add("Cryptographic operations");
    if (hasAny(name, {"createfile", "readfile", "writefile", "fopen", "open", "unlink", "deletefile"}))
        add("File system access");
    if (hasAny(name, {"isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstring", "ptrace"}))
        add("Debugging and process inspection");
    if (hasAny(name, {"regopenkey", "regsetvalue", "regcreatekey", "setenv", "putenv"}))
        add("System configuration");
    return categories;
}

std::string importExplanation(const std::string& category) {
    if (category == "Cross-process memory / process control")
        return "The import can inspect or modify another process, depending on how it is called.";
    if (category == "Memory management")
        return "The import allocates memory or changes memory mapping/protection.";
    if (category == "Dynamic library loading")
        return "The import can load libraries or resolve symbols dynamically.";
    if (category == "Network communication")
        return "The import provides network communication capabilities.";
    if (category == "Cryptographic operations")
        return "The import exposes cryptographic or TLS-related functionality.";
    if (category == "File system access")
        return "The import provides file creation, reading, writing, or deletion capabilities.";
    if (category == "Debugging and process inspection")
        return "The import can inspect debugger/process state or emit diagnostic output.";
    return "The import can read or modify system configuration.";
}

std::string htmlEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (const char ch : value) {
        switch (ch) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out.push_back(ch); break;
        }
    }
    return out;
}

Json evidenceJson(const StaticEvidence& evidence) {
    Json item = Json::object();
    item.set("description", evidence.description);
    item.set("value", evidence.value);
    item.set("deduplication_key", evidence.deduplicationKey);
    if (evidence.fileOffset) item.set("file_offset", hex(*evidence.fileOffset));
    else item.set("file_offset", Json());
    if (evidence.virtualAddress) item.set("virtual_address", hex(*evidence.virtualAddress));
    else item.set("virtual_address", Json());
    return item;
}

Json findingJson(const StaticFinding& finding) {
    Json item = Json::object();
    item.set("id", finding.id);
    item.set("rule_id", finding.ruleId);
    item.set("title", finding.title);
    item.set("description", finding.description);
    item.set("category", toString(finding.category));
    item.set("severity", toString(finding.severity));
    item.set("confidence_percent", static_cast<int>(finding.confidence));
    item.set("evidence_quality_percent", static_cast<int>(finding.evidenceQuality));
    Json evidence = Json::array();
    for (const auto& entry : finding.evidence) evidence.push(evidenceJson(entry));
    item.set("evidence", std::move(evidence));
    item.set("why_it_matters", finding.whyItMatters);
    item.set("benign_explanations", finding.benignExplanations);
    item.set("next_steps", finding.nextSteps);
    item.set("related_view", toString(finding.relatedView));
    return item;
}

}  // namespace

const char* toString(StaticSeverity severity) {
    switch (severity) {
        case StaticSeverity::Informational: return "informational";
        case StaticSeverity::Low: return "low";
        case StaticSeverity::Medium: return "medium";
        case StaticSeverity::High: return "high";
        case StaticSeverity::Critical: return "critical";
    }
    return "unknown";
}

const char* toString(StaticCategory category) {
    switch (category) {
        case StaticCategory::Structure: return "structure";
        case StaticCategory::Memory: return "memory";
        case StaticCategory::Imports: return "imports";
        case StaticCategory::Entropy: return "entropy";
        case StaticCategory::Strings: return "strings";
        case StaticCategory::ControlFlow: return "control-flow";
        case StaticCategory::Correlation: return "correlation";
    }
    return "unknown";
}

const char* toString(StaticView view) {
    switch (view) {
        case StaticView::None: return "none";
        case StaticView::Hex: return "hex";
        case StaticView::Sections: return "sections";
        case StaticView::Imports: return "imports";
        case StaticView::Strings: return "strings";
        case StaticView::Entropy: return "entropy";
        case StaticView::ControlFlow: return "control-flow";
    }
    return "none";
}

StaticAnalysisResult analyzeStatic(const BinaryInfo& info, std::span<const uint8_t> fileData,
                                   const StringExtractionResult* strings,
                                   const EntropyAnalysisResult* entropy,
                                   const ControlFlowGraph* cfg,
                                   const StaticProgressFn& progress,
                                   const StaticCancelFn& cancelled) {
    StaticAnalysisResult result;
    result.fileName = info.fileName;
    result.filePath = info.filePath;
    result.format = info.formatName;
    result.architecture = info.archName;
    result.fileSize = info.fileSize;
    result.sha256 = info.sha256;
    result.entryPoint = info.entryPoint;
    result.metadata = info.metadata;
    result.generatedAtUtc = nowUtc();
    result.engineVersion = XRL_VERSION;
    if (fileData.size() != info.fileSize) {
        result.error = "Loaded file data size does not match parsed metadata.";
        return result;
    }
    const bool stringsUsable = strings && strings->ok && strings->fileSize == fileData.size() &&
                               !info.sha256.empty() && strings->sha256 == info.sha256;
    const bool entropyUsable = entropy && entropy->ok && entropy->fileSize == fileData.size() &&
                               !info.sha256.empty() && entropy->sha256 == info.sha256;
    if (strings && strings->ok && !stringsUsable)
        result.warnings.push_back("String evidence was ignored because its file size or SHA-256 does not match the loaded file.");
    if (entropy && entropy->ok && !entropyUsable)
        result.warnings.push_back("Entropy evidence was ignored because its file size or SHA-256 does not match the loaded file.");
    auto isCancelled = [&] {
        if (cancelled && cancelled()) {
            result.cancelled = true;
            result.error = "Static analysis cancelled.";
            return true;
        }
        return false;
    };

    if (!info.error.empty()) {
        result.warnings.push_back("Format parsing was incomplete: " + info.error);
        addFinding(result, makeFinding("XRL.STRUCT.000", "Executable parsing reported an error",
            "The existing format parser could not fully interpret the file; findings below use only the metadata that was successfully parsed.",
            StaticCategory::Structure, StaticSeverity::Medium, 98, 92, StaticView::Sections,
            {"Parser diagnostic", info.error, "parser-error:" + info.sha256, std::nullopt, std::nullopt},
            "Incomplete parsing limits the reliability and coverage of all downstream observations.",
            "The file may be truncated, use an unsupported variant, or contain uncommon but valid structures.",
            "Inspect the parser diagnostic and validate the binary with another trusted format inspector."));
    }

    report(progress, 5, "Checking binary structure and memory permissions");
    size_t sectionIndex = 0;
    for (const auto& section : info.sections) {
        if (isCancelled()) return result;
        const auto offset = sectionOffset(section, fileData.size());
        const std::string label = section.name.empty() ? "(unnamed)" : section.name;
        if (!section.boundsValid || (section.hasFileData && !offset)) {
            StaticEvidence evidence{"Parsed section range", label + " offset=" + hex(section.fileOffset) +
                                         " size=" + std::to_string(section.fileSize),
                                    evidenceKey("section-range", section.fileOffset, label),
                                    section.fileOffset, section.virtualAddress};
            addFinding(result, makeFinding("XRL.STRUCT.001", "Section range exceeds available file data",
                "The parsed section declares file-backed bytes that do not fit within the loaded file.",
                StaticCategory::Structure, StaticSeverity::High, 96, 95, StaticView::Sections,
                std::move(evidence), "Truncated or inconsistent section ranges can hide missing data or indicate a malformed file.",
                "Interrupted copying, post-link editing, or a parser-limited unusual layout can produce inconsistent metadata.",
                "Inspect the section table and compare its raw range with the file length."));
        }
        if (section.writable && section.executable) {
            StaticEvidence evidence{"Writable and executable section/segment", label,
                                    evidenceKey("section-permissions", section.fileOffset, label),
                                    offset, section.virtualAddress};
            addFinding(result, makeFinding("XRL.MEM.001", "Writable and executable memory region",
                "The parsed permissions mark this region both writable and executable.",
                StaticCategory::Memory, StaticSeverity::High, 88, 90, StaticView::Sections,
                std::move(evidence), "Writable executable mappings can enable runtime code generation or modification and deserve context.",
                "JIT runtimes, compatibility layers, packers, legacy toolchains, and platform-specific loaders may use such permissions.",
                "Inspect the region's purpose, size, imports, and runtime mapping policy."));
        }
        if (section.virtualSize > section.fileSize &&
            section.virtualSize - section.fileSize >= 1024 * 1024) {
            StaticEvidence evidence{"Large virtual/raw size difference",
                                    "virtual=" + std::to_string(section.virtualSize) +
                                        " raw=" + std::to_string(section.fileSize),
                                    evidenceKey("section-size-gap", section.fileOffset, label),
                                    offset, section.virtualAddress};
            addFinding(result, makeFinding("XRL.STRUCT.002", "Large virtual-to-raw section size gap",
                "The declared virtual size exceeds the file-backed size by at least 1 MiB.",
                StaticCategory::Structure, StaticSeverity::Low, 76, 80, StaticView::Sections,
                std::move(evidence), "A large gap may affect loader memory layout and merits review alongside section permissions.",
                "Zero-initialized data, alignment, sparse mappings, and ordinary linker layout can explain this difference.",
                "Compare virtual/raw sizes with neighboring sections and format conventions."));
        }
        if (section.executable && section.entropy && section.fileSize >= 4096 &&
            *section.entropy >= 7.2 && offset) {
            StaticEvidence evidence{"Section Shannon entropy",
                                    std::to_string(*section.entropy) + " bits/byte over " +
                                        std::to_string(section.fileSize) + " bytes",
                                    evidenceKey("section-entropy", section.fileOffset, label),
                                    offset, section.virtualAddress};
            addFinding(result, makeFinding("XRL.ENTROPY.001", "High entropy executable section",
                "The executable section has entropy at or above 7.2 bits per byte over at least 4096 bytes.",
                StaticCategory::Entropy, StaticSeverity::Medium, 68, 82, StaticView::Entropy,
                std::move(evidence), "High entropy in executable data can be consistent with packed or encrypted code, but does not establish either.",
                "Compressed code/resources, generated tables, embedded assets, or naturally diverse instruction/data bytes may produce high entropy.",
                "Compare its heatmap profile with section permissions, names, size, and other independent evidence."));
        }
        if (sectionIndex < info.sections.size() - 1)
            report(progress, 5 + static_cast<int>(35 * (sectionIndex + 1) / info.sections.size()),
                   "Checking binary structure and memory permissions");
        ++sectionIndex;
    }

    if (info.entryPoint) {
        const auto mapped = info.virtualToFileOffset(*info.entryPoint);
        const auto executable = std::find_if(info.sections.begin(), info.sections.end(), [&](const Section& section) {
            if (!section.executable) return false;
            const uint64_t span = std::max(section.virtualSize, section.fileSize);
            return *info.entryPoint >= section.virtualAddress &&
                   *info.entryPoint - section.virtualAddress < span;
        });
        if (!mapped || executable == info.sections.end()) {
            StaticEvidence evidence{"Parsed executable entry point", hex(*info.entryPoint),
                                    evidenceKey("entry-point", *info.entryPoint),
                                    mapped, *info.entryPoint};
            addFinding(result, makeFinding("XRL.STRUCT.003", "Entry point is not mapped to executable file data",
                "The parsed entry point does not map to bytes in a parsed executable section.",
                StaticCategory::Structure, StaticSeverity::Medium, 86, 85, StaticView::Sections,
                std::move(evidence), "A loader may be unable to transfer control to the declared entry point as expected.",
                "Unusual loaders, incomplete section metadata, or parser coverage limits may cause this observation.",
                "Inspect the format's entry point mapping and section table."));
        }
    }

    report(progress, 45, "Reviewing imported API capabilities");
    std::map<std::string, std::vector<const Symbol*>> importGroups;
    for (const auto& symbol : info.imports.items) {
        for (const auto& category : importCategories(symbol))
            importGroups[category].push_back(&symbol);
    }
    for (const auto& [category, symbols] : importGroups) {
        if (isCancelled()) return result;
        if (symbols.empty()) continue;
        const auto severity = category == "Cross-process memory / process control" ||
                                      category == "Dynamic library loading"
                                  ? StaticSeverity::Medium
                                  : StaticSeverity::Low;
        const unsigned confidence = info.imports.state == Availability::Present ? 88 : 60;
        StaticFinding finding = makeFinding(
            category == "Cross-process memory / process control" ? "XRL.IMPORT.001" : "XRL.IMPORT.002",
            category + " imports observed",
            importExplanation(category) + " This reports declared import capability, not runtime behavior.",
            StaticCategory::Imports, severity, confidence,
            info.imports.state == Availability::Present ? 92u : 55u, StaticView::Imports,
            {"Imported symbol(s)", {}, "import-category:" + category, std::nullopt, std::nullopt},
            "The capability can help prioritize review when corroborated by code or other independent indicators.",
            "The imports may be unused, used only in optional code paths, or part of ordinary application functionality.",
            "Review the named imports and their callers before drawing conclusions.");
        for (const auto* symbol : symbols) {
            const std::string library = symbol->library.empty() ? "library unavailable" : symbol->library;
            const std::string location = symbol->address ? " @ " + hex(*symbol->address) : "";
            finding.evidence.front().value += (finding.evidence.front().value.empty() ? "" : "; ") +
                                              symbol->name + " from " + library + location;
            if (symbol->address) {
                if (const auto fileOffset = info.virtualToFileOffset(*symbol->address))
                    finding.evidence.front().fileOffset = fileOffset;
            }
        }
        addFinding(result, std::move(finding));
    }
    if ((info.imports.state == Availability::Present || info.imports.state == Availability::Absent) &&
        info.imports.items.empty()) {
        addFinding(result, makeFinding("XRL.IMPORT.003", "No imported functions were listed",
            info.imports.state == Availability::Absent
                ? "The parser reports that this file has no import category."
                : "The parser reports an import table/category but it contains no named imports.",
            StaticCategory::Imports, StaticSeverity::Informational, 78, 70, StaticView::Imports,
            {"Import category", "present, 0 named functions", "imports:empty", std::nullopt, std::nullopt},
            "Some programs resolve dependencies dynamically or do not require external functions.",
            "Freestanding programs, static linking, stripped/import-free images, and parser limitations are possible explanations.",
            "Check library metadata and the format-specific import table state."));
    }

    report(progress, 60, "Reviewing extracted strings and optional analysis results");
    if (stringsUsable) {
        struct StringAggregate {
            size_t count = 0;
            std::vector<StaticEvidence> evidence;
        };
        std::map<StringCategory, StringAggregate> aggregates;
        for (const auto& item : strings->strings) {
            if (isCancelled()) return result;
            if (item.offset >= fileData.size() || item.length == 0 ||
                item.length > fileData.size() - item.offset) continue;
            for (const auto category : item.categories) {
                auto& aggregate = aggregates[category];
                ++aggregate.count;
                if (aggregate.evidence.size() < kMaxStringEvidence) {
                    aggregate.evidence.push_back({"Extracted " + std::string(toString(category)) + " string",
                        item.value, evidenceKey("string", item.offset, std::to_string(item.length)),
                        item.offset, std::nullopt});
                } else {
                    ++result.omittedStringEvidence;
                }
            }
        }
        for (auto& [category, aggregate] : aggregates) {
            if (category == StringCategory::Other || aggregate.count == 0) continue;
            const std::string categoryText = toString(category);
            StaticFinding finding = makeFinding(
                "XRL.STRING.001", categoryText + " string indicator(s) observed",
                std::to_string(aggregate.count) + " extracted string(s) were classified by the Strings Explorer's deterministic pattern rules.",
                StaticCategory::Strings, StaticSeverity::Informational, 70, 72, StaticView::Strings,
                aggregate.evidence.front(),
                "Strings can provide leads for understanding intended configuration, endpoints, files, or capabilities.",
                "Embedded documentation, test data, dead strings, and ordinary configuration commonly produce these patterns.",
                "Review each offset in Strings Explorer and determine whether any code references it.");
            finding.evidence = std::move(aggregate.evidence);
            if (aggregate.count > finding.evidence.size())
                finding.description += " Evidence is capped per category; additional matching strings are omitted.";
            addFinding(result, std::move(finding));
        }
        std::vector<StaticEvidence> commandFragments;
        size_t commandMatches = 0;
        for (const auto& item : strings->strings) {
            const std::string value = lowercase(item.value);
            if (item.offset >= fileData.size() || item.length == 0 ||
                item.length > fileData.size() - item.offset ||
                !hasAny(value, {"cmd.exe", "powershell", "/bin/sh", "/bin/bash", "bash -c",
                                "sh -c", "cmd /c", " --"})) continue;
            ++commandMatches;
            if (commandFragments.size() < kMaxStringEvidence)
                commandFragments.push_back({"Command-line-like extracted string", item.value,
                    evidenceKey("command-fragment", item.offset, std::to_string(item.length)),
                    item.offset, std::nullopt});
        }
        if (commandMatches > 0) {
            StaticFinding finding = makeFinding(
                "XRL.STRING.002", "Command-line-like string fragment(s) observed",
                std::to_string(commandMatches) + " extracted string(s) contain explicit shell or command interpreter markers.",
                StaticCategory::Strings, StaticSeverity::Informational, 65, 68, StaticView::Strings,
                commandFragments.front(),
                "Command fragments may identify supported workflows or configuration worth reviewing.",
                "Help text, examples, build scripts, test fixtures, and embedded documentation can contain these tokens.",
                "Inspect the full string and search for code references; presence does not prove execution.");
            finding.evidence = std::move(commandFragments);
            addFinding(result, std::move(finding));
        }
    }

    if (entropyUsable && entropy->overallEntropy) {
        const std::string value = std::to_string(*entropy->overallEntropy) + " bits/byte";
        if (*entropy->overallEntropy >= 7.2 && entropy->fileSize >= 4096) {
            addFinding(result, makeFinding("XRL.ENTROPY.002", "High whole-file entropy",
                "The existing Entropy Heatmap analysis measured whole-file entropy at or above 7.2 bits per byte.",
                StaticCategory::Entropy, StaticSeverity::Low, 64, 80, StaticView::Entropy,
                {"Whole-file Shannon entropy", value, "file-entropy:" + info.sha256,
                 std::nullopt, std::nullopt},
                "A high value may justify checking the heatmap for concentrated regions rather than uniform benign data.",
                "Compressed archives, media, encrypted content, and mixed-format files can all have high entropy.",
                "Inspect the per-block heatmap and compare it with executable section boundaries."));
        }
        std::vector<StaticEvidence> highBlocks;
        size_t highBlockCount = 0;
        for (const auto& block : entropy->blocks) {
            if (block.entropy < 7.2 || block.offset >= fileData.size() || block.size == 0 ||
                block.size > fileData.size() - block.offset) continue;
            ++highBlockCount;
            if (highBlocks.size() < 20) {
                highBlocks.push_back({"High-entropy heatmap block",
                    std::to_string(block.entropy) + " bits/byte over " +
                        std::to_string(block.size) + " bytes",
                    evidenceKey("entropy-block", block.offset, std::to_string(block.size)),
                    block.offset, info.fileOffsetToVirtual(block.offset)});
            }
        }
        if (highBlockCount > 0) {
            StaticFinding finding = makeFinding(
                "XRL.ENTROPY.003", "High-entropy heatmap region(s) observed",
                std::to_string(highBlockCount) + " block(s) measured at or above 7.2 bits per byte; at most 20 are listed.",
                StaticCategory::Entropy, StaticSeverity::Informational, 78, 82, StaticView::Entropy,
                highBlocks.front(),
                "Concentrated high-entropy regions can help prioritize where to inspect the heatmap and section map.",
                "Compressed assets, encrypted resources, and ordinary binary data can produce the same measurements.",
                "Compare listed offsets with section boundaries and inspect nearby blocks before inferring a cause.");
            finding.evidence = std::move(highBlocks);
            addFinding(result, std::move(finding));
        }
    }

    if (cfg && cfg->ok) {
        if (cfg->metrics.cyclomaticComplexity >= 20 || cfg->metrics.conditionalBranches >= 16) {
            StaticEvidence evidence{"CFG function metrics",
                "complexity=" + std::to_string(cfg->metrics.cyclomaticComplexity) +
                    ", conditional_branches=" + std::to_string(cfg->metrics.conditionalBranches) +
                    ", reachable_blocks=" + std::to_string(cfg->metrics.reachableBlocks),
                evidenceKey("cfg-function", cfg->function.address),
                cfg->function.fileOffset, cfg->function.address};
            addFinding(result, makeFinding("XRL.CFG.001", "High control-flow complexity in analyzed function",
                "The selected CFG has complexity >=20 or at least 16 conditional branches.",
                StaticCategory::ControlFlow, StaticSeverity::Low, 72, 78, StaticView::ControlFlow,
                std::move(evidence), "Complex control flow can make auditing and behavioral reasoning more difficult.",
                "Generated code, parsers, state machines, protocol handlers, and optimized code often have many branches.",
                "Inspect the CFG's branches, loops, and function identity before comparing it with peers."));
        }
        if (std::any_of(cfg->edges.begin(), cfg->edges.end(), [](const CfgEdge& edge) {
                return edge.kind == CfgEdgeKind::Unresolved;
            })) {
            addFinding(result, makeFinding("XRL.CFG.002", "Unresolved control-flow edge",
                "The selected CFG contains one or more indirect or otherwise unresolved edges.",
                StaticCategory::ControlFlow, StaticSeverity::Informational, 96, 90,
                StaticView::ControlFlow,
                {"CFG edge set", "at least one edge remains unresolved",
                 evidenceKey("cfg-unresolved", cfg->function.address),
                 cfg->function.fileOffset, cfg->function.address},
                "Unresolved flow limits conclusions about the reachable graph.",
                "Indirect dispatch, jump tables, exception mechanisms, and unsupported instruction semantics can produce unresolved edges.",
                "Inspect the source block's instructions and use a fuller disassembly or dynamic trace if authorized."));
        }
    }

    report(progress, 78, "Correlating independent findings");
    auto findRule = [&](const std::string& rule) -> std::vector<const StaticFinding*> {
        std::vector<const StaticFinding*> matches;
        for (const auto& finding : result.findings)
            if (finding.ruleId == rule) matches.push_back(&finding);
        return matches;
    };
    auto addCorrelation = [&](std::string id, std::string title, std::string explanation,
                              std::vector<const StaticFinding*> linked) {
        if (linked.size() < 2) return;
        StaticCorrelation correlation;
        correlation.id = std::move(id);
        correlation.title = std::move(title);
        correlation.explanation = std::move(explanation);
        for (const auto* finding : linked) correlation.findingIds.push_back(finding->id);
        result.correlations.push_back(correlation);
        StaticFinding finding = makeFinding(
            correlation.id, correlation.title, correlation.explanation,
            StaticCategory::Correlation, StaticSeverity::Medium, 62, 65, StaticView::None,
            {"Underlying independent findings", {}, "correlation:" + correlation.id,
             std::nullopt, std::nullopt},
            "Independent evidence can make a combination more useful to investigate than either indicator alone.",
            "The underlying indicators retain their individual benign explanations and are not proof of intent.",
            "Follow the linked findings and verify that the same file region or behavior is actually involved.");
        finding.evidence.front().value.clear();
        for (const auto* member : linked)
            finding.evidence.front().value += (finding.evidence.front().value.empty() ? "" : ", ") + member->id;
        finding.evidence.front().deduplicationKey = "correlation-no-added-score:" + correlation.id;
        finding.relatedView = StaticView::None;
        addFinding(result, std::move(finding));
    };

    auto wx = findRule("XRL.MEM.001");
    auto proc = findRule("XRL.IMPORT.001");
    wx.insert(wx.end(), proc.begin(), proc.end());
    addCorrelation("XRL.CORR.001", "Writable executable region with process-control imports",
                   "A writable/executable region and imports for cross-process memory or process control are both present. "
                   "This is a correlation of separate static indicators, not proof they are connected at runtime.", wx);

    auto highEntropy = findRule("XRL.ENTROPY.001");
    auto largeGap = findRule("XRL.STRUCT.002");
    highEntropy.insert(highEntropy.end(), largeGap.begin(), largeGap.end());
    addCorrelation("XRL.CORR.002", "High-entropy executable content with unusual section sizing",
                   "High entropy in an executable section coincides with a large virtual-to-raw size gap. "
                   "Neither indicator alone establishes packing or encryption.", highEntropy);

    const auto networkImports = findRule("XRL.IMPORT.002");
    const auto stringFindings = findRule("XRL.STRING.001");
    const auto networkImport = std::find_if(networkImports.begin(), networkImports.end(), [](const StaticFinding* finding) {
        return lowercase(finding->title).find("network communication") != std::string::npos;
    });
    std::vector<const StaticFinding*> endpointEvidence;
    for (const auto* finding : stringFindings) {
        const std::string title = lowercase(finding->title);
        if (title.find("url") != std::string::npos ||
            title.find("domain") != std::string::npos ||
            title.find("ipv4") != std::string::npos)
            endpointEvidence.push_back(finding);
    }
    if (networkImport != networkImports.end() && !endpointEvidence.empty()) {
        endpointEvidence.push_back(*networkImport);
        addCorrelation("XRL.CORR.003", "Network imports and endpoint-like strings",
                       "The file has network-related imports and extracted strings matching endpoint patterns. "
                       "The analysis does not establish that the strings are passed to those APIs.",
                       endpointEvidence);
    }

    report(progress, 90, "Calculating explainable evidence score");
    const std::string methodology =
        "Each non-correlation finding has a documented severity weight (informational 0, low 8, medium 18, high 32, critical 45). "
        "Its candidate points are weight × confidence/100 × evidence-quality/100. Findings sharing an evidence-group key "
        "contribute only the highest candidate value for that group. Correlations never add points. The sum is rounded and "
        "capped at 100. This prioritization score is not a probability or malware classification.";
    result.risk.methodology = methodology;
    std::map<std::string, size_t> bestByEvidence;
    for (size_t i = 0; i < result.findings.size(); ++i) {
        const auto& finding = result.findings[i];
        const std::string group = finding.evidence.empty() ? finding.id :
            (finding.evidence.front().deduplicationKey.empty() ? finding.id :
             finding.evidence.front().deduplicationKey);
        const double points = static_cast<double>(severityWeight(finding.severity)) *
                              static_cast<double>(finding.confidence) / 100.0 *
                              static_cast<double>(finding.evidenceQuality) / 100.0;
        if (finding.category == StaticCategory::Correlation || points <= 0.0) {
            result.risk.contributions.push_back({finding.id, group, points, false,
                finding.category == StaticCategory::Correlation ? "Correlation is informational and does not add score." :
                                                                  "Informational finding has zero severity weight."});
            continue;
        }
        auto prior = bestByEvidence.find(group);
        if (prior == bestByEvidence.end()) {
            bestByEvidence.emplace(group, i);
            result.risk.contributions.push_back({finding.id, group, points, true,
                                                   "Highest weighted finding for this independent evidence group."});
        } else {
            auto& previous = result.risk.contributions[prior->second];
            if (points > previous.points) {
                previous.counted = false;
                previous.reason = "Superseded by a higher weighted finding for the same evidence group.";
                bestByEvidence[group] = i;
                result.risk.contributions.push_back({finding.id, group, points, true,
                                                       "Highest weighted finding for this independent evidence group."});
            } else {
                result.risk.contributions.push_back({finding.id, group, points, false,
                                                       "Same evidence group already has an equal or higher contribution."});
            }
        }
    }
    double score = 0.0;
    for (const auto& contribution : result.risk.contributions)
        if (contribution.counted) score += contribution.points;
    result.risk.score = static_cast<unsigned>(std::clamp(std::lround(score), 0l, 100l));
    result.risk.inconclusive = bestByEvidence.size() < 2;
    result.ok = true;
    report(progress, 100, "Static analysis complete");
    return result;
}

Json buildStaticJsonReport(const StaticAnalysisResult& result) {
    Json root = Json::object();
    root.set("schema_version", "1.0");
    root.set("analysis_engine_version", result.engineVersion);
    root.set("analysis_timestamp_utc", result.generatedAtUtc);
    Json file = Json::object();
    file.set("name", result.fileName);
    file.set("path", result.filePath);
    file.set("size", result.fileSize);
    file.set("sha256", result.sha256);
    file.set("format", result.format);
    file.set("architecture", result.architecture);
    if (result.entryPoint) file.set("entry_point", hex(*result.entryPoint));
    else file.set("entry_point", Json());
    root.set("file", std::move(file));
    Json metadata = Json::array();
    for (const auto& [key, value] : result.metadata) {
        Json item = Json::object();
        item.set("key", key);
        item.set("value", value);
        metadata.push(std::move(item));
    }
    root.set("format_metadata", std::move(metadata));
    Json warnings = Json::array();
    for (const auto& warning : result.warnings) warnings.push(warning);
    root.set("warnings", std::move(warnings));
    root.set("ok", result.ok);
    root.set("cancelled", result.cancelled);
    root.set("error", result.error);
    Json risk = Json::object();
    risk.set("score", static_cast<int>(result.risk.score));
    risk.set("inconclusive", result.risk.inconclusive);
    risk.set("meaning", "Evidence prioritization only; not a malware probability or verdict.");
    risk.set("methodology", result.risk.methodology);
    Json contributions = Json::array();
    for (const auto& entry : result.risk.contributions) {
        Json item = Json::object();
        item.set("finding_id", entry.findingId);
        item.set("evidence_group", entry.evidenceGroup);
        item.set("points", entry.points);
        item.set("counted", entry.counted);
        item.set("reason", entry.reason);
        contributions.push(std::move(item));
    }
    risk.set("contributions", std::move(contributions));
    root.set("risk", std::move(risk));
    Json findings = Json::array();
    for (const auto& finding : result.findings) findings.push(findingJson(finding));
    root.set("findings", std::move(findings));
    Json severityCounts = Json::object();
    for (const auto severity : {StaticSeverity::Informational, StaticSeverity::Low, StaticSeverity::Medium,
                                StaticSeverity::High, StaticSeverity::Critical}) {
        const auto count = std::count_if(result.findings.begin(), result.findings.end(),
                                         [severity](const StaticFinding& finding) {
                                             return finding.severity == severity;
                                         });
        severityCounts.set(toString(severity), static_cast<uint64_t>(count));
    }
    root.set("severity_breakdown", std::move(severityCounts));
    Json correlations = Json::array();
    for (const auto& correlation : result.correlations) {
        Json item = Json::object();
        item.set("id", correlation.id);
        item.set("title", correlation.title);
        item.set("explanation", correlation.explanation);
        Json linked = Json::array();
        for (const auto& id : correlation.findingIds) linked.push(id);
        item.set("finding_ids", std::move(linked));
        correlations.push(std::move(item));
    }
    root.set("correlations", std::move(correlations));
    Json limitations = Json::array();
    limitations.push("Static imports do not prove that a capability executes at runtime.");
    limitations.push("String classifications are heuristic and do not prove use, execution, or network activity.");
    limitations.push("Entropy alone does not establish packing or encryption.");
    limitations.push("Relocation and debug-directory records are not exposed in the current shared BinaryInfo model.");
    limitations.push("CFG indicators are included only when a valid CFG result is supplied by the existing CFG workflow.");
    root.set("limitations", std::move(limitations));
    root.set("omitted_string_evidence_count", static_cast<uint64_t>(result.omittedStringEvidence));
    return root;
}

std::string renderStaticJsonReport(const StaticAnalysisResult& result) {
    return buildStaticJsonReport(result).dump(2) + "\n";
}

std::string renderStaticHtmlReport(const StaticAnalysisResult& result) {
    std::ostringstream html;
    html << "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>Xaynx Reverse Lab static analysis</title>"
            "<style>body{margin:2rem auto;max-width:1100px;padding:0 1.25rem;background:#0d0d0e;color:#f2f2f3;"
            "font:15px/1.55 system-ui,sans-serif}h1,h2{line-height:1.2}section{border-top:1px solid #343438;padding:1rem 0}"
            "table{border-collapse:collapse;width:100%}td,th{text-align:left;vertical-align:top;padding:.55rem;border-bottom:1px solid #29292d}"
            "code,pre{font-family:ui-monospace,monospace;overflow-wrap:anywhere}.meta{color:#b4b4bb}.finding{padding:1rem 0;border-top:1px solid #343438}"
            ".severity{font-weight:700;text-transform:uppercase}.high,.critical{color:#ff837a}.medium{color:#f5c46b}"
            ".low{color:#85c9b0}.info{color:#9baed0}.warn{color:#c7c7cd}</style></head><body>";
    html << "<h1>Explainable static analysis</h1><p class=\"meta\">"
         << htmlEscape(result.fileName) << " · " << htmlEscape(result.format) << " · "
         << htmlEscape(result.architecture) << " · generated "
         << htmlEscape(result.generatedAtUtc) << "</p>";
    html << "<section><h2>File</h2><table><tbody><tr><th>Size</th><td>"
         << result.fileSize << " bytes</td></tr><tr><th>SHA-256</th><td><code>"
         << htmlEscape(result.sha256) << "</code></td></tr><tr><th>Engine</th><td>"
         << htmlEscape(result.engineVersion) << "</td></tr></tbody></table></section>";
    html << "<section><h2>Evidence prioritization score</h2><p><strong>"
         << result.risk.score << "/100</strong> — "
         << (result.risk.inconclusive ? "inconclusive: insufficient independent evidence groups" :
                                        "not a malware probability or classification")
         << "</p><p>" << htmlEscape(result.risk.methodology) << "</p></section>";
    if (!result.warnings.empty()) {
        html << "<section><h2>Analysis warnings</h2><ul>";
        for (const auto& warning : result.warnings)
            html << "<li>" << htmlEscape(warning) << "</li>";
        html << "</ul></section>";
    }
    html << "<section><h2>Findings (" << result.findings.size() << ")</h2>";
    for (const auto& finding : result.findings) {
        html << "<article class=\"finding\"><h3><span class=\"severity "
             << htmlEscape(toString(finding.severity)) << "\">"
             << htmlEscape(toString(finding.severity)) << "</span> — "
             << htmlEscape(finding.title) << "</h3><p>"
             << htmlEscape(finding.description) << "</p><p><strong>Rule:</strong> "
             << htmlEscape(finding.ruleId) << " · <strong>Confidence:</strong> "
             << finding.confidence << "% · <strong>Evidence quality:</strong> "
             << finding.evidenceQuality << "%</p><p><strong>Why it matters:</strong> "
             << htmlEscape(finding.whyItMatters) << "</p><p><strong>Benign explanations:</strong> "
             << htmlEscape(finding.benignExplanations) << "</p><p><strong>Next:</strong> "
             << htmlEscape(finding.nextSteps) << "</p>";
        for (const auto& evidence : finding.evidence) {
            html << "<p><strong>" << htmlEscape(evidence.description) << ":</strong> <code>"
                 << htmlEscape(evidence.value) << "</code>";
            if (evidence.fileOffset) html << " · file offset " << htmlEscape(hex(*evidence.fileOffset));
            if (evidence.virtualAddress) html << " · virtual address " << htmlEscape(hex(*evidence.virtualAddress));
            html << "</p>";
        }
        html << "</article>";
    }
    html << "</section><section><h2>Correlations (" << result.correlations.size()
         << ")</h2>";
    for (const auto& correlation : result.correlations) {
        html << "<article><h3>" << htmlEscape(correlation.title) << "</h3><p>"
             << htmlEscape(correlation.explanation) << "</p><p class=\"meta\">Findings: ";
        for (size_t i = 0; i < correlation.findingIds.size(); ++i)
            html << (i ? ", " : "") << htmlEscape(correlation.findingIds[i]);
        html << "</p></article>";
    }
    html << "</section><section><h2>Limitations</h2><p class=\"warn\">"
            "Static indicators are not proof of runtime behavior or malicious intent. "
            "Relocation and debug-directory records are not exposed by the current parser model. "
            "CFG results are included only when already available from the CFG workflow.</p></section></body></html>\n";
    return html.str();
}

}  // namespace xrl
