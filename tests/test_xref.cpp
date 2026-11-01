#include <algorithm>
#include <gtest/gtest.h>

#include "xrl/json.hpp"
#include "xrl/xref.hpp"

using namespace xrl;

namespace {

BinaryInfo x86Info(const std::vector<uint8_t>& bytes) {
    BinaryInfo info;
    info.fileSize = bytes.size();
    info.sha256 = "fixture-sha256";
    info.arch = Arch::X86_64;
    info.archName = "x86-64";
    info.bits = 64;
    info.endian = Endian::Little;
    info.sections.push_back({".text", {}, "section", 0x1000, bytes.size(), 0, bytes.size(),
                             0, true, false, true, true, true, std::nullopt, {}});
    return info;
}

const XrefReference* findReference(const XrefResult& result, XrefType type,
                                   std::optional<uint64_t> source = {},
                                   std::optional<uint64_t> destination = {}) {
    const auto found = std::find_if(result.references.begin(), result.references.end(),
                                    [&](const XrefReference& reference) {
        return reference.type == type && (!source || reference.sourceAddress == source) &&
               (!destination || reference.destinationAddress == destination);
    });
    return found == result.references.end() ? nullptr : &*found;
}

}  // namespace

TEST(XREF, IndexesDirectCallsRipRelativeStringDataAndImportedSymbols) {
    if (!disassemblerCompiledIn()) GTEST_SKIP();
    std::vector<uint8_t> bytes(80, 0x90);
    bytes[0] = 0xE8; bytes[1] = 0x0B; bytes[2] = 0; bytes[3] = 0; bytes[4] = 0;
    bytes[5] = 0xC3;
    bytes[16] = 0xC3;
    const uint8_t loadString[] = {0x48, 0x8B, 0x05, 0x11, 0, 0, 0, 0xC3};
    std::copy(std::begin(loadString), std::end(loadString), bytes.begin() + 32);
    const uint8_t loadImport[] = {0x48, 0x8B, 0x05, 0x19, 0, 0, 0, 0xC3};
    std::copy(std::begin(loadImport), std::end(loadImport), bytes.begin() + 40);
    const std::string stringValue = "example-text";
    std::copy(stringValue.begin(), stringValue.end(), bytes.begin() + 56);

    auto info = x86Info(bytes);
    info.symbols.items.push_back({"caller", {}, 0x1000, std::nullopt, "func"});
    info.symbols.items.push_back({"callee", {}, 0x1010, std::nullopt, "func"});
    info.exports.items.push_back({"public_callee", {}, 0x1010, std::nullopt, "func"});
    info.symbols.items.push_back({"string_user", {}, 0x1020, std::nullopt, "func"});
    info.symbols.items.push_back({"import_user", {}, 0x1028, std::nullopt, "func"});
    info.imports.state = Availability::Present;
    info.imports.items.push_back({"ImportedApi", "library.so", 0x1048, std::nullopt, "func"});
    info.relocations.state = Availability::Present;
    info.relocations.items.push_back({0x1030, 48, 1, "test relocation", "ImportedApi", -4, 0x1048, "fixture relocation"});
    StringExtractionResult strings;
    strings.ok = true;
    strings.fileSize = bytes.size();
    strings.sha256 = info.sha256;
    strings.strings.push_back({56, stringValue.size(), StringEncoding::Ascii, stringValue, {}});

    const auto result = analyzeCrossReferences(info, bytes, &strings);
    ASSERT_TRUE(result.ok) << result.error;
    const auto* call = findReference(result, XrefType::Call, 0x1000, 0x1010);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->destinationFunctionName, "callee");
    EXPECT_EQ(call->fileOffset, 0u);
    EXPECT_NE(findReference(result, XrefType::Export, 0x1000, 0x1010), nullptr);
    const auto* data = findReference(result, XrefType::Data, 0x1020, 0x1038);
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->fileOffset, 32u);
    EXPECT_EQ(data->destinationFileOffset, 56u);
    EXPECT_NE(findReference(result, XrefType::String, 0x1020, 0x1038), nullptr);
    const auto* imported = findReference(result, XrefType::Import, 0x1028, 0x1048);
    ASSERT_NE(imported, nullptr);
    EXPECT_EQ(imported->symbolName, "ImportedApi");
    const auto* relocation = findReference(result, XrefType::Relocation, 0x1030, 0x1048);
    ASSERT_NE(relocation, nullptr);
    EXPECT_EQ(relocation->confidence, XrefConfidence::Inferred);
    EXPECT_EQ(relocation->evidenceSource, "fixture relocation");
    EXPECT_EQ(result.functions[0].outgoingCalls, 1u);
    EXPECT_EQ(result.functions[1].incomingCalls, 1u);
    EXPECT_TRUE(result.unreferencedStringOffsets.empty());
}

TEST(XREF, RecordsConditionalAndUnconditionalBranchReferences) {
    if (!disassemblerCompiledIn()) GTEST_SKIP();
    const std::vector<uint8_t> bytes{0x75, 0x02, 0xEB, 0x00, 0xC3};
    auto info = x86Info(bytes);
    info.entryPoint = 0x1000;
    const auto result = analyzeCrossReferences(info, bytes);
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_NE(findReference(result, XrefType::ConditionalBranch, 0x1000, 0x1004), nullptr);
    EXPECT_NE(findReference(result, XrefType::UnconditionalBranch, 0x1002, 0x1004), nullptr);
}

TEST(XREF, DetectsRecursionAndKeepsIndirectCallsUnresolved) {
    if (!disassemblerCompiledIn()) GTEST_SKIP();
    const std::vector<uint8_t> recursive{0xE8, 0xFB, 0xFF, 0xFF, 0xFF, 0xC3};
    auto info = x86Info(recursive);
    info.symbols.items.push_back({"recursive", {}, 0x1000, std::nullopt, "func"});
    auto result = analyzeCrossReferences(info, recursive);
    ASSERT_TRUE(result.ok) << result.error;
    ASSERT_EQ(result.functions.size(), 1u);
    EXPECT_TRUE(result.functions.front().recursive);

    const std::vector<uint8_t> indirect{0xFF, 0xD0, 0xC3};
    info = x86Info(indirect);
    info.symbols.items.push_back({"indirect", {}, 0x1000, std::nullopt, "func"});
    result = analyzeCrossReferences(info, indirect);
    ASSERT_TRUE(result.ok) << result.error;
    ASSERT_EQ(result.unresolvedIndirectCalls, 1u);
    const auto* call = findReference(result, XrefType::Call, 0x1000);
    ASSERT_NE(call, nullptr);
    EXPECT_FALSE(call->destinationAddress);
    EXPECT_EQ(call->confidence, XrefConfidence::Unresolved);
}

TEST(XREF, HandlesStrippedMetadataAndEnforcesConfiguredLimits) {
    if (!disassemblerCompiledIn()) GTEST_SKIP();
    std::vector<uint8_t> bytes{0x90, 0xC3};
    auto info = x86Info(bytes);
    const auto result = analyzeCrossReferences(info, bytes);
    ASSERT_TRUE(result.ok) << result.error;
    ASSERT_EQ(result.functions.size(), 1u);
    EXPECT_EQ(result.functions.front().candidate.evidence, FunctionEvidence::SectionStart);
    EXPECT_FALSE(result.functions.front().candidate.startConfirmed);

    std::vector<uint8_t> repeatedCalls(11, 0x90);
    repeatedCalls[0] = 0xE8;
    repeatedCalls[1] = 0xFB; repeatedCalls[2] = 0xFF; repeatedCalls[3] = 0xFF; repeatedCalls[4] = 0xFF;
    repeatedCalls[5] = 0xE8;
    repeatedCalls[6] = 0xF6; repeatedCalls[7] = 0xFF; repeatedCalls[8] = 0xFF; repeatedCalls[9] = 0xFF;
    repeatedCalls[10] = 0xC3;
    info = x86Info(repeatedCalls);
    XrefOptions options;
    options.maxReferences = 1;
    const auto limited = analyzeCrossReferences(info, repeatedCalls, nullptr, options);
    ASSERT_TRUE(limited.ok);
    EXPECT_LE(limited.references.size(), 1u);
    EXPECT_TRUE(limited.truncated);

    const auto mismatch = analyzeCrossReferences(info, std::span<const uint8_t>(bytes).first(1));
    EXPECT_FALSE(mismatch.ok);
    EXPECT_NE(mismatch.error.find("does not match"), std::string::npos);
}

TEST(XREF, ExportsRealReferencesAsJsonCsvAndBoundedDot) {
    if (!disassemblerCompiledIn()) GTEST_SKIP();
    const std::vector<uint8_t> bytes{0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3};
    auto info = x86Info(bytes);
    info.symbols.items.push_back({"entry", {}, 0x1000, std::nullopt, "func"});
    const auto result = analyzeCrossReferences(info, bytes);
    ASSERT_TRUE(result.ok);
    const auto parsed = Json::parse(renderXrefJson(result));
    ASSERT_TRUE(parsed.value.has_value()) << parsed.error;
    EXPECT_NE(renderXrefCsv(result).find("source_address,destination_address"), std::string::npos);
    const std::string dot = renderXrefDot(result);
    EXPECT_NE(dot.find("label=\"call\""), std::string::npos);
    EXPECT_NE(dot.find("source=0x1000"), std::string::npos);
    EXPECT_NE(dot.find("confidence=confirmed"), std::string::npos);
    EXPECT_NE(dot.find("Capstone-decoded direct call target"), std::string::npos);
    EXPECT_NE(renderXrefDot(result, 0).find("omitted"), std::string::npos);
}

TEST(XREF, BuildsLargeReferenceIndexesAndBoundsGraphExport) {
    if (!disassemblerCompiledIn()) GTEST_SKIP();
    std::vector<uint8_t> bytes(400 * 5 + 1);
    for (size_t i = 0; i < 400; ++i) {
        const size_t offset = i * 5;
        bytes[offset] = 0xE8;
        bytes[offset + 1] = 0xFB;
        bytes[offset + 2] = 0xFF;
        bytes[offset + 3] = 0xFF;
        bytes[offset + 4] = 0xFF;
    }
    bytes.back() = 0xC3;
    auto info = x86Info(bytes);
    info.symbols.items.push_back({"repeated_calls", {}, 0x1000, std::nullopt, "func"});
    const auto result = analyzeCrossReferences(info, bytes);
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_GE(result.references.size(), 400u);
    EXPECT_EQ(std::count_if(result.references.begin(), result.references.end(), [](const auto& reference) {
        return reference.type == XrefType::Call;
    }), 400);
    EXPECT_EQ(result.functions.front().outgoingCalls, 1u);

    XrefResult graphResult;
    for (uint64_t address = 0; address < 4; ++address) {
        XrefReference reference;
        reference.sourceAddress = 0x1000 + address;
        reference.destinationAddress = 0x2000 + address;
        reference.type = XrefType::Data;
        graphResult.references.push_back(reference);
    }
    const std::string dot = renderXrefDot(graphResult, 8, 2);
    EXPECT_NE(dot.find("some references omitted"), std::string::npos);
}

TEST(XREF, CancellationIsExplicit) {
    if (!disassemblerCompiledIn()) GTEST_SKIP();
    const std::vector<uint8_t> bytes{0x90, 0xC3};
    const auto result = analyzeCrossReferences(x86Info(bytes), bytes, nullptr, {},
                                               {}, [] { return true; });
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(result.cancelled);
}
