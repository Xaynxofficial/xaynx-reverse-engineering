#include <algorithm>

#include <gtest/gtest.h>

#include "xrl/static_analysis.hpp"

using namespace xrl;

namespace {

BinaryInfo baseInfo(size_t size = 4096) {
    BinaryInfo info;
    info.fileName = "fixture.bin";
    info.filePath = "fixture.bin";
    info.fileSize = size;
    info.sha256 = "0123456789abcdef";
    info.format = Format::ELF;
    info.formatName = "ELF";
    info.arch = Arch::X86_64;
    info.archName = "x86-64";
    info.bits = 64;
    info.sections.push_back({".text", {}, "section", 0x400000, size, 0, size,
                             0, true, false, true, true, true, 0.0, {}});
    return info;
}

}  // namespace

TEST(StaticAnalysis, FlagsWritableExecutableSectionWithRealRangeEvidence) {
    auto info = baseInfo();
    info.sections[0].writable = true;
    const std::vector<uint8_t> bytes(info.fileSize, 0x90);
    const auto result = analyzeStatic(info, bytes);
    ASSERT_TRUE(result.ok) << result.error;
    ASSERT_EQ(result.findings.size(), 1u);
    const auto& finding = result.findings.front();
    EXPECT_EQ(finding.ruleId, "XRL.MEM.001");
    EXPECT_EQ(finding.severity, StaticSeverity::High);
    EXPECT_EQ(finding.evidence.front().fileOffset, 0u);
    EXPECT_EQ(finding.evidence.front().virtualAddress, 0x400000u);
    EXPECT_TRUE(result.risk.inconclusive);
}

TEST(StaticAnalysis, CorrelatesIndependentPermissionAndImportFindingsWithoutExtraScore) {
    auto info = baseInfo();
    info.sections[0].writable = true;
    info.imports.state = Availability::Present;
    info.imports.items.push_back({"WriteProcessMemory", "kernel32.dll", std::nullopt, std::nullopt, "function"});
    const std::vector<uint8_t> bytes(info.fileSize, 0x90);
    const auto result = analyzeStatic(info, bytes);
    ASSERT_TRUE(result.ok) << result.error;
    ASSERT_EQ(result.correlations.size(), 1u);
    EXPECT_EQ(result.correlations.front().findingIds.size(), 2u);
    ASSERT_EQ(result.findings.size(), 3u);
    EXPECT_EQ(result.findings.back().category, StaticCategory::Correlation);
    const auto correlationScore = std::find_if(
        result.risk.contributions.begin(), result.risk.contributions.end(),
        [](const RiskContribution& contribution) {
            return contribution.findingId.find("XRL.CORR.001") == 0;
        });
    ASSERT_NE(correlationScore, result.risk.contributions.end());
    EXPECT_FALSE(correlationScore->counted);
}

TEST(StaticAnalysis, CorrelatesNetworkImportsWithUrlAndDomainIndicatorsCaseInsensitively) {
    auto info = baseInfo();
    info.imports.state = Availability::Present;
    info.imports.items.push_back({"connect", "libc.so", std::nullopt, std::nullopt, "function"});
    const std::vector<uint8_t> bytes(info.fileSize, 0);
    StringExtractionResult strings;
    strings.ok = true;
    strings.fileSize = info.fileSize;
    strings.sha256 = info.sha256;
    strings.strings.push_back({16, 20, StringEncoding::Ascii, "https://example.test/a",
                               {StringCategory::Url, StringCategory::Domain}});

    const auto result = analyzeStatic(info, bytes, &strings);
    ASSERT_TRUE(result.ok) << result.error;
    ASSERT_EQ(result.correlations.size(), 1u);
    EXPECT_EQ(result.correlations.front().id, "XRL.CORR.003");
}

TEST(StaticAnalysis, RejectsMismatchedInputAndMalformedEvidenceRanges) {
    auto info = baseInfo();
    const std::vector<uint8_t> shortFile(12);
    const auto mismatch = analyzeStatic(info, shortFile);
    EXPECT_FALSE(mismatch.ok);
    EXPECT_NE(mismatch.error.find("does not match"), std::string::npos);

    info.sections[0].boundsValid = false;
    const std::vector<uint8_t> bytes(info.fileSize, 0);
    const auto result = analyzeStatic(info, bytes);
    ASSERT_TRUE(result.ok) << result.error;
    ASSERT_FALSE(result.findings.empty());
    EXPECT_EQ(result.findings.front().ruleId, "XRL.STRUCT.001");
}

TEST(StaticAnalysis, UsesStringExplorerCategoriesAndValidatesStringOffsets) {
    auto info = baseInfo();
    std::vector<uint8_t> bytes(info.fileSize, 0);
    StringExtractionResult strings;
    strings.ok = true;
    strings.fileSize = info.fileSize;
    strings.sha256 = info.sha256;
    strings.strings.push_back({16, 20, StringEncoding::Ascii, "https://example.test/a",
                               {StringCategory::Url, StringCategory::Domain}});
    strings.strings.push_back({info.fileSize - 1, 10, StringEncoding::Ascii, "invalid",
                               {StringCategory::IPv4}});
    const auto result = analyzeStatic(info, bytes, &strings);
    ASSERT_TRUE(result.ok) << result.error;
    ASSERT_EQ(result.findings.size(), 2u);
    const auto url = std::find_if(result.findings.begin(), result.findings.end(), [](const StaticFinding& finding) {
        return finding.title.find("URL") != std::string::npos;
    });
    const auto domain = std::find_if(result.findings.begin(), result.findings.end(), [](const StaticFinding& finding) {
        return finding.title.find("Domain") != std::string::npos;
    });
    ASSERT_NE(url, result.findings.end()) << result.findings[0].title << " | " << result.findings[1].title;
    ASSERT_NE(domain, result.findings.end());
    EXPECT_EQ(url->evidence.front().fileOffset, 16u);
}

TEST(StaticAnalysis, ReportsValidatedHeatmapRegionsAndIgnoresOutOfFileBlocks) {
    auto info = baseInfo();
    const std::vector<uint8_t> bytes(info.fileSize, 0x90);
    EntropyAnalysisResult entropy;
    entropy.ok = true;
    entropy.fileSize = info.fileSize;
    entropy.sha256 = info.sha256;
    entropy.overallEntropy = 7.3;
    entropy.blocks.push_back({64, 256, 7.8});
    entropy.blocks.push_back({info.fileSize - 8, 64, 7.9});
    const auto result = analyzeStatic(info, bytes, nullptr, &entropy);
    ASSERT_TRUE(result.ok);
    const auto regions = std::find_if(result.findings.begin(), result.findings.end(),
                                      [](const StaticFinding& finding) {
                                          return finding.ruleId == "XRL.ENTROPY.003";
                                      });
    ASSERT_NE(regions, result.findings.end());
    EXPECT_EQ(regions->evidence.size(), 1u);
    EXPECT_EQ(regions->evidence.front().fileOffset, 64u);
    EXPECT_TRUE(result.risk.inconclusive);
}

TEST(StaticAnalysis, IgnoresOptionalResultsFromAnotherFile) {
    auto info = baseInfo();
    const std::vector<uint8_t> bytes(info.fileSize, 0);
    StringExtractionResult strings;
    strings.ok = true;
    strings.fileSize = info.fileSize;
    strings.sha256 = "different-file";
    strings.strings.push_back({16, 20, StringEncoding::Ascii, "https://example.test/a",
                               {StringCategory::Url}});
    EntropyAnalysisResult entropy;
    entropy.ok = true;
    entropy.fileSize = info.fileSize;
    entropy.sha256 = "different-file";
    entropy.overallEntropy = 8.0;

    const auto result = analyzeStatic(info, bytes, &strings, &entropy);
    ASSERT_TRUE(result.ok);
    EXPECT_TRUE(result.findings.empty());
    ASSERT_EQ(result.warnings.size(), 2u);
}

TEST(StaticAnalysis, IncludesPartialParserDiagnosticInsteadOfDiscardingSafeEvidence) {
    auto info = baseInfo();
    info.error = "truncated optional header";
    info.sections[0].writable = true;
    const std::vector<uint8_t> bytes(info.fileSize, 0);
    const auto result = analyzeStatic(info, bytes);
    ASSERT_TRUE(result.ok) << result.error;
    ASSERT_FALSE(result.warnings.empty());
    EXPECT_NE(result.warnings.front().find("truncated optional header"), std::string::npos);
    EXPECT_EQ(result.findings.front().ruleId, "XRL.STRUCT.000");
    EXPECT_TRUE(std::any_of(result.findings.begin(), result.findings.end(), [](const StaticFinding& finding) {
        return finding.ruleId == "XRL.MEM.001";
    }));
}

TEST(StaticAnalysis, ReportsRiskMethodAndEscapedHtmlAndJsonEvidence) {
    auto info = baseInfo();
    info.fileName = "<script>alert(1)</script>";
    info.sections[0].writable = true;
    const std::vector<uint8_t> bytes(info.fileSize, 0x90);
    const auto result = analyzeStatic(info, bytes);
    ASSERT_TRUE(result.ok);
    const std::string json = renderStaticJsonReport(result);
    const auto parsed = Json::parse(json);
    ASSERT_TRUE(parsed.value.has_value()) << parsed.error;
    ASSERT_NE(parsed.value->find("risk"), nullptr);
    EXPECT_NE(json.find("not a malware probability"), std::string::npos);
    const std::string html = renderStaticHtmlReport(result);
    EXPECT_EQ(html.find("<script>alert"), std::string::npos);
    EXPECT_NE(html.find("&lt;script&gt;"), std::string::npos);
    EXPECT_NE(html.find("Benign explanations"), std::string::npos);
}

TEST(StaticAnalysis, CancellationIsExplicit) {
    auto info = baseInfo();
    const std::vector<uint8_t> bytes(info.fileSize, 0);
    const auto result = analyzeStatic(info, bytes, nullptr, nullptr, nullptr, {},
                                      [] { return true; });
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(result.cancelled);
    EXPECT_EQ(result.error, "Static analysis cancelled.");
}
