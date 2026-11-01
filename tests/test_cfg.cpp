#include <algorithm>
#include <gtest/gtest.h>

#include "fixtures.hpp"
#include "xrl/analyzer.hpp"
#include "xrl/cfg.hpp"
#include "xrl/json.hpp"

using namespace xrl;

namespace {

BinaryInfo mappedCode(const std::vector<uint8_t>& bytes, Arch arch = Arch::X86_64, int bits = 64) {
    BinaryInfo info;
    info.fileSize = bytes.size();
    info.arch = arch;
    info.bits = bits;
    info.endian = Endian::Little;
    info.sections.push_back({".text", {}, "section", 0x1000, bytes.size(), 0, bytes.size(),
                             0, true, false, true, true, true, std::nullopt, {}});
    return info;
}

FunctionCandidate entryAt(uint64_t address = 0x1000) {
    return {"test function", address, address - 0x1000, FunctionEvidence::UserAddress, false};
}

const CfgEdge* findEdge(const ControlFlowGraph& graph, size_t from, CfgEdgeKind kind) {
    for (const auto& edge : graph.edges)
        if (edge.from == from && edge.kind == kind) return &edge;
    return nullptr;
}

}  // namespace

TEST(CFG, FunctionCandidatesUseExecutableMetadataAndKeepEvidence) {
    const auto data = fixtures::makeELF();
    const auto info = analyzeBuffer(data);
    const auto candidates = discoverFunctionCandidates(info);
    ASSERT_FALSE(candidates.empty());
    EXPECT_EQ(candidates.front().address, 0x401000u);
    EXPECT_EQ(candidates.front().evidence, FunctionEvidence::Export);
    EXPECT_TRUE(candidates.front().startConfirmed);

    auto symbolInfo = mappedCode({0xC3});
    symbolInfo.fileSize = 1;
    symbolInfo.symbols.items.push_back({"confirmed_function", {}, 0x1000, std::nullopt, "func"});
    const auto symbolCandidates = discoverFunctionCandidates(symbolInfo);
    ASSERT_EQ(symbolCandidates.size(), 1u);
    EXPECT_EQ(symbolCandidates.front().evidence, FunctionEvidence::Symbol);
    EXPECT_TRUE(symbolCandidates.front().startConfirmed);
}

TEST(CFG, OffersExecutableSectionStartWhenMetadataHasNoCandidates) {
    const auto info = mappedCode({0x90, 0xC3});
    const auto candidates = discoverFunctionCandidates(info);
    ASSERT_EQ(candidates.size(), 1u);
    EXPECT_EQ(candidates.front().name, ".text start");
    EXPECT_EQ(candidates.front().address, 0x1000u);
    EXPECT_EQ(candidates.front().fileOffset, 0u);
    EXPECT_EQ(candidates.front().evidence, FunctionEvidence::SectionStart);
    EXPECT_FALSE(candidates.front().startConfirmed);
}

#ifdef XRL_HAS_CAPSTONE
TEST(CFG, BuildsLinearBlockAndTracksExactInstructionRanges) {
    const std::vector<uint8_t> data{0x90, 0x90, 0xC3};
    const auto info = mappedCode(data);
    const auto graph = analyzeControlFlow(info, data, entryAt());
    ASSERT_TRUE(graph.ok) << graph.error;
    ASSERT_EQ(graph.blocks.size(), 1u);
    EXPECT_EQ(graph.blocks[0].startAddress, 0x1000u);
    EXPECT_EQ(graph.blocks[0].endAddress, 0x1003u);
    EXPECT_EQ(graph.blocks[0].fileOffset, 0u);
    EXPECT_EQ(graph.blocks[0].instructions.size(), 3u);
    EXPECT_TRUE(graph.blocks[0].isEntry);
    EXPECT_TRUE(graph.blocks[0].isExit);
    EXPECT_EQ(graph.analyzedBytes, data.size());
}

TEST(CFG, SeparatesConditionalBranchesAndUnconditionalJumps) {
    const std::vector<uint8_t> data{0x75, 0x03, 0x90, 0xEB, 0x02, 0xC3, 0x90, 0xC3};
    const auto graph = analyzeControlFlow(mappedCode(data), data, entryAt());
    ASSERT_TRUE(graph.ok) << graph.error;
    ASSERT_EQ(graph.blocks.size(), 4u);
    EXPECT_EQ(graph.blocks[0].startAddress, 0x1000u);
    EXPECT_EQ(graph.blocks[1].startAddress, 0x1002u);
    EXPECT_EQ(graph.blocks[2].startAddress, 0x1005u);
    EXPECT_EQ(graph.blocks[3].startAddress, 0x1007u);
    const auto* trueEdge = findEdge(graph, 0, CfgEdgeKind::ConditionalTrue);
    const auto* falseEdge = findEdge(graph, 0, CfgEdgeKind::ConditionalFalse);
    ASSERT_NE(trueEdge, nullptr);
    ASSERT_NE(falseEdge, nullptr);
    ASSERT_TRUE(trueEdge->to.has_value());
    ASSERT_TRUE(falseEdge->to.has_value());
    EXPECT_EQ(graph.blocks[*trueEdge->to].startAddress, 0x1005u);
    EXPECT_EQ(graph.blocks[*falseEdge->to].startAddress, 0x1002u);
    const auto* jump = findEdge(graph, 1, CfgEdgeKind::Unconditional);
    ASSERT_NE(jump, nullptr);
    ASSERT_TRUE(jump->to.has_value());
    EXPECT_EQ(graph.blocks[*jump->to].startAddress, 0x1007u);
    EXPECT_EQ(graph.metrics.conditionalBranches, 1u);
    EXPECT_EQ(graph.metrics.cyclomaticComplexity, 2u);
}

TEST(CFG, KeepsTheSelectedFunctionAsEntryWhenBranchesReachLowerAddresses) {
    const std::vector<uint8_t> data{0xC3, 0x90, 0x75, 0xFC, 0xC3};
    const auto graph = analyzeControlFlow(mappedCode(data), data, entryAt(0x1002));
    ASSERT_TRUE(graph.ok) << graph.error;
    ASSERT_EQ(graph.blocks.size(), 3u);
    EXPECT_TRUE(graph.blocks[0].isEntry);
    EXPECT_EQ(graph.blocks[0].startAddress, 0x1002u);
    EXPECT_EQ(graph.metrics.reachableBlocks, 3u);
    const auto* back = findEdge(graph, 0, CfgEdgeKind::ConditionalTrue);
    ASSERT_NE(back, nullptr);
    ASSERT_TRUE(back->to.has_value());
    EXPECT_EQ(graph.blocks[*back->to].startAddress, 0x1000u);
}

TEST(CFG, DetectsDominatedBackEdgesNaturalLoopsAndStronglyConnectedComponents) {
    const std::vector<uint8_t> data{0x90, 0x75, 0xFD, 0xC3};
    const auto graph = analyzeControlFlow(mappedCode(data), data, entryAt());
    ASSERT_TRUE(graph.ok) << graph.error;
    EXPECT_EQ(graph.blocks.size(), 2u);
    EXPECT_EQ(graph.metrics.backEdges, 1u);
    EXPECT_EQ(graph.metrics.naturalLoops, 1u);
    EXPECT_EQ(graph.metrics.stronglyConnectedComponents, 1u);
    EXPECT_EQ(graph.metrics.cyclomaticComplexity, 2u);
    ASSERT_EQ(graph.metrics.immediateDominators.size(), 2u);
    EXPECT_EQ(graph.metrics.immediateDominators[1], 0u);
}

TEST(CFG, SplitsAnAlreadyDecodedBlockWhenAForwardPathTargetsItsInterior) {
    const std::vector<uint8_t> data{
        0x74, 0x08,                         // je 0x100a
        0x90, 0x90, 0x90, 0x90, 0xC3,     // fall-through region
        0x90, 0x90, 0x90,
        0xEB, 0xF8                          // jmp back to 0x1004
    };
    const auto graph = analyzeControlFlow(mappedCode(data), data, entryAt());
    ASSERT_TRUE(graph.ok) << graph.error;
    ASSERT_EQ(graph.blocks.size(), 4u);
    EXPECT_EQ(graph.blocks[0].startAddress, 0x1000u);
    EXPECT_EQ(graph.blocks[1].startAddress, 0x1002u);
    EXPECT_EQ(graph.blocks[2].startAddress, 0x1004u);
    EXPECT_EQ(graph.blocks[3].startAddress, 0x100Au);
    const auto* back = findEdge(graph, 3, CfgEdgeKind::Unconditional);
    ASSERT_NE(back, nullptr);
    ASSERT_TRUE(back->to.has_value());
    EXPECT_EQ(graph.blocks[*back->to].startAddress, 0x1004u);
}

TEST(CFG, RecordsDirectCallsAndRecursiveReferencesWithoutInventingCalleeBlocks) {
    const std::vector<uint8_t> recursive{0xE8, 0xFB, 0xFF, 0xFF, 0xFF, 0xC3};
    const auto graph = analyzeControlFlow(mappedCode(recursive), recursive, entryAt());
    ASSERT_TRUE(graph.ok) << graph.error;
    ASSERT_EQ(graph.calls.size(), 1u);
    EXPECT_EQ(graph.calls[0].targetAddress, 0x1000u);
    EXPECT_TRUE(graph.calls[0].recursive);
    EXPECT_EQ(graph.blocks.size(), 1u);

    const std::vector<uint8_t> indirect{0xFF, 0xE0};
    const auto indirectGraph = analyzeControlFlow(mappedCode(indirect), indirect, entryAt());
    ASSERT_TRUE(indirectGraph.ok) << indirectGraph.error;
    EXPECT_TRUE(indirectGraph.blocks[0].hasUnresolvedFlow);
    EXPECT_NE(findEdge(indirectGraph, 0, CfgEdgeKind::Unresolved), nullptr);
}

TEST(CFG, HandlesHundredsOfReachableBlocksWithinTheConfiguredBound) {
    constexpr size_t branchCount = 400;
    std::vector<uint8_t> data(branchCount * 4 + 1, 0x90);
    for (size_t i = 0; i < branchCount; ++i) {
        const size_t offset = i * 4;
        data[offset] = 0x74;
        data[offset + 1] = 0x02;
        data[offset + 2] = 0xEB;
        data[offset + 3] = 0x00;
    }
    data.back() = 0xC3;
    const auto graph = analyzeControlFlow(mappedCode(data), data, entryAt());
    ASSERT_TRUE(graph.ok) << graph.error;
    EXPECT_EQ(graph.blocks.size(), branchCount * 2 + 1);
    EXPECT_EQ(graph.metrics.reachableBlocks, graph.blocks.size());
    EXPECT_FALSE(graph.truncated);
}

TEST(CFG, HandlesMultipleReturnsAndExportsActualGraphData) {
    const std::vector<uint8_t> data{0x74, 0x01, 0xC3, 0xC3};
    const auto graph = analyzeControlFlow(mappedCode(data), data, entryAt());
    ASSERT_TRUE(graph.ok) << graph.error;
    ASSERT_EQ(graph.blocks.size(), 3u);
    EXPECT_EQ(std::count_if(graph.blocks.begin(), graph.blocks.end(),
                            [](const BasicBlock& block) { return block.isExit; }), 2);

    const auto json = Json::parse(exportCfgJson(graph));
    ASSERT_TRUE(json.value.has_value()) << json.error;
    const auto* blocks = json.value->find("blocks");
    ASSERT_NE(blocks, nullptr);
    EXPECT_EQ(blocks->size(), graph.blocks.size());
    EXPECT_NE(exportCfgDot(graph).find("digraph CFG"), std::string::npos);
    EXPECT_NE(exportCfgDot(graph).find("conditional-true"), std::string::npos);
}

TEST(CFG, ReportsDecodeLimitsCancellationAndMalformedMappings) {
    const std::vector<uint8_t> data{0x75, 0x03, 0x90, 0xEB, 0x02, 0xC3, 0x90, 0xC3};
    CfgOptions limits;
    limits.maxBlocks = 1;
    const auto limited = analyzeControlFlow(mappedCode(data), data, entryAt(), limits);
    ASSERT_TRUE(limited.ok);
    EXPECT_TRUE(limited.truncated);
    const auto cancelled = analyzeControlFlow(mappedCode(data), data, entryAt(), {},
                                              {}, [] { return true; });
    EXPECT_FALSE(cancelled.ok);
    EXPECT_NE(cancelled.error.find("cancelled"), std::string::npos);

    auto unmapped = mappedCode(data);
    unmapped.sections.clear();
    const auto badMap = analyzeControlFlow(unmapped, data, entryAt());
    EXPECT_FALSE(badMap.ok);
    EXPECT_NE(badMap.error.find("mapped"), std::string::npos);

    const std::vector<uint8_t> invalid{0x06};
    const auto invalidGraph = analyzeControlFlow(mappedCode(invalid), invalid, entryAt());
    ASSERT_TRUE(invalidGraph.ok);
    EXPECT_TRUE(invalidGraph.blocks[0].hasUnresolvedFlow);
}

TEST(CFG, SupportsArm64ConditionalBranches) {
    const std::vector<uint8_t> data{
        0x40, 0x00, 0x00, 0x54,  // b.eq +8
        0xC0, 0x03, 0x5F, 0xD6,  // ret
        0xC0, 0x03, 0x5F, 0xD6   // ret
    };
    const auto graph = analyzeControlFlow(mappedCode(data, Arch::Arm64, 64), data, entryAt());
    ASSERT_TRUE(graph.ok) << graph.error;
    ASSERT_EQ(graph.blocks.size(), 3u);
    EXPECT_NE(findEdge(graph, 0, CfgEdgeKind::ConditionalTrue), nullptr);
    EXPECT_NE(findEdge(graph, 0, CfgEdgeKind::ConditionalFalse), nullptr);

    const std::vector<uint8_t> cbzData{
        0x40, 0x00, 0x00, 0xB4,  // cbz x0, +8
        0xC0, 0x03, 0x5F, 0xD6,
        0xC0, 0x03, 0x5F, 0xD6
    };
    const auto cbzGraph = analyzeControlFlow(mappedCode(cbzData, Arch::Arm64, 64), cbzData, entryAt());
    ASSERT_TRUE(cbzGraph.ok) << cbzGraph.error;
    const auto* cbzTrue = findEdge(cbzGraph, 0, CfgEdgeKind::ConditionalTrue);
    ASSERT_NE(cbzTrue, nullptr);
    ASSERT_TRUE(cbzTrue->to.has_value());
    EXPECT_EQ(cbzGraph.blocks[*cbzTrue->to].startAddress, 0x1008u);

    const std::vector<uint8_t> tbzData{
        0x40, 0x00, 0x00, 0x36,  // tbz w0, #0, +8
        0xC0, 0x03, 0x5F, 0xD6,
        0xC0, 0x03, 0x5F, 0xD6
    };
    const auto tbzGraph = analyzeControlFlow(mappedCode(tbzData, Arch::Arm64, 64), tbzData, entryAt());
    ASSERT_TRUE(tbzGraph.ok) << tbzGraph.error;
    const auto* tbzTrue = findEdge(tbzGraph, 0, CfgEdgeKind::ConditionalTrue);
    ASSERT_NE(tbzTrue, nullptr);
    ASSERT_TRUE(tbzTrue->to.has_value());
    EXPECT_EQ(tbzGraph.blocks[*tbzTrue->to].startAddress, 0x1008u);
}
#else
TEST(CFG, ReportsMissingCapstone) {
    const std::vector<uint8_t> data{0xC3};
    const auto result = analyzeControlFlow(mappedCode(data), data, entryAt());
    EXPECT_FALSE(result.ok);
    EXPECT_FALSE(cfgSupported(mappedCode(data)));
}
#endif
