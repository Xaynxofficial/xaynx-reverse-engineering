#include <gtest/gtest.h>

#include "fixtures.hpp"
#include "xrl/analyzer.hpp"
#include "xrl/disassembler.hpp"
#include "xrl/report.hpp"

using namespace xrl;

namespace {
Json reportOf(const BinaryInfo& info, const DisasmResult* d = nullptr, const GhidraResult* g = nullptr) {
    ReportInputs in;
    in.info = &info;
    in.disassembly = d;
    in.ghidra = g;
    in.generatedAtUtc = "2025-01-01T00:00:00Z";
    const auto text = renderJsonReport(in);
    const auto parsed = Json::parse(text);
    EXPECT_TRUE(parsed.value) << parsed.error;
    return parsed.value ? *parsed.value : Json();
}
}  // namespace

TEST(Report, JsonIsValidAndContainsExpectedFields) {
    auto info = analyzeBuffer(fixtures::makePE64());
    info.fileName = "fixture.exe";
    info.filePath = "/tmp/fixture.exe";
    const Json j = reportOf(info);
    ASSERT_TRUE(j.isObject());
    EXPECT_EQ(j.find("schema_version")->asString(), kReportSchemaVersion);
    EXPECT_EQ(j.find("generated_utc")->asString(), "2025-01-01T00:00:00Z");
    EXPECT_FALSE(j.find("executed")->asBool(true));
    EXPECT_EQ(j.find("file")->find("sha256")->asString(), info.sha256);
    EXPECT_EQ(j.find("file")->find("size_bytes")->asInt(), static_cast<int64_t>(info.fileSize));
    const Json* bin = j.find("binary");
    EXPECT_EQ(bin->find("format")->asString(), "PE");
    EXPECT_EQ(bin->find("architecture")->asString(), "x86-64");
    EXPECT_EQ(bin->find("bits")->asInt(), 64);
    EXPECT_EQ(bin->find("endianness")->asString(), "Little-endian");
    EXPECT_EQ(bin->find("entry_point")->asString(), "0x140001000");
    EXPECT_EQ(j.find("sections")->find("items")->size(), 2u);
    EXPECT_EQ(j.find("sections")->find("items")->items()[0].find("permissions")->asString(), "r-x");
    EXPECT_EQ(j.find("imports")->find("items")->items()[0].find("name")->asString(), "ExitProcess");
    EXPECT_EQ(j.find("exports")->find("items")->items()[0].find("name")->asString(), "my_export");
}
TEST(Report, UnavailableAndAbsentAreDistinguishedInJson) {
    auto info = analyzeBuffer(fixtures::makeELF());
    Json j = reportOf(info);
    EXPECT_EQ(j.find("symbols")->find("availability")->asString(), "absent (confirmed)");
    auto b = fixtures::makeELF();
    for (size_t k = 0; k < 8; ++k) b[40 + k] = 0;
    j = reportOf(analyzeBuffer(b));
    EXPECT_EQ(j.find("imports")->find("availability")->asString(), "unavailable (not parsed)");
}
TEST(Report, IncludesRelocationRecordsAndUnavailableValuesAsNull) {
    auto info = analyzeBuffer(fixtures::makePE64WithBaseRelocation());
    Json j = reportOf(info);
    ASSERT_EQ(j.find("relocations")->find("availability")->asString(), "present");
    ASSERT_EQ(j.find("relocations")->find("items")->size(), 1u);
    const Json& relocation = j.find("relocations")->find("items")->items().front();
    EXPECT_EQ(relocation.find("address")->asString(), "0x140001010");
    EXPECT_EQ(relocation.find("file_offset")->asInt(), 0x410);
    EXPECT_TRUE(relocation.find("symbol")->isNull());
    EXPECT_TRUE(relocation.find("target_address")->isNull());

    info.relocations.state = Availability::NotParsed;
    info.relocations.items.clear();
    j = reportOf(info);
    EXPECT_EQ(j.find("relocations")->find("availability")->asString(), "unavailable (not parsed)");
}
TEST(Report, FailedAnalysisStillProducesValidJsonWithError) {
    fixtures::Bytes junk(64, 0x55);
    const auto info = analyzeBuffer(junk);
    const Json j = reportOf(info);
    EXPECT_FALSE(j.find("status")->find("parsed_without_error")->asBool(true));
    EXPECT_FALSE(j.find("status")->find("format_recognised")->asBool(true));
    EXPECT_FALSE(j.find("status")->find("error")->asString().empty());
}
TEST(Report, HostileSymbolNamesStillYieldValidJson) {
    BinaryInfo info;
    info.error = "x";
    info.imports.state = Availability::Present;
    info.imports.items.push_back({std::string("evil\"\\\n\x01\xFF\xC0name"), "lib\xFE", std::nullopt, std::nullopt, "func"});
    const Json j = reportOf(info);
    EXPECT_EQ(j.find("imports")->find("items")->size(), 1u);
}
TEST(Report, DisassemblyAndGhidraSectionsReflectInputs) {
    auto info = analyzeBuffer(fixtures::makeELF());
    Json j = reportOf(info);
    EXPECT_FALSE(j.find("disassembly")->find("available")->asBool(true));
    EXPECT_FALSE(j.find("ghidra")->find("available")->asBool(true));

    DisasmResult d;
    d.ok = true;
    d.startAddress = 0x401000;
    Instruction ins;
    ins.address = 0x401000;
    ins.bytes = {0x55};
    ins.mnemonic = "push";
    ins.operands = "rbp";
    d.instructions.push_back(ins);
    GhidraResult g;
    g.ok = true;
    g.ghidraVersion = "11.0";
    g.functions.push_back({"entry", 0x401000, 6, "void entry(void)", false, false, true, "void entry(void) {}"});
    j = reportOf(info, &d, &g);
    EXPECT_TRUE(j.find("disassembly")->find("available")->asBool());
    EXPECT_EQ(j.find("disassembly")->find("instructions")->items()[0].find("mnemonic")->asString(), "push");
    EXPECT_TRUE(j.find("ghidra")->find("available")->asBool());
    EXPECT_EQ(j.find("ghidra")->find("functions")->items()[0].find("decompiled")->asString(), "void entry(void) {}");
}
TEST(Report, FailedDisassemblyIsNotReportedAsAvailable) {
    auto info = analyzeBuffer(fixtures::makeELF());
    DisasmResult d;  // ok == false
    d.error = "boom";
    const Json j = reportOf(info, &d);
    EXPECT_FALSE(j.find("disassembly")->find("available")->asBool(true));
}
TEST(Report, TextReportLabelsHeuristicsAndStatesNotExecuted) {
    auto b = fixtures::makePE64();
    b[0x84 + 20 + 240 + 36 + 3] = 0xE0;
    const auto info = analyzeBuffer(b);
    ReportInputs in;
    in.info = &info;
    in.generatedAtUtc = "2025-01-01T00:00:00Z";
    const auto text = renderTextReport(in);
    EXPECT_NE(text.find("not executed"), std::string::npos);
    EXPECT_NE(text.find("[heuristic]"), std::string::npos);
    EXPECT_NE(text.find(info.sha256), std::string::npos);
    EXPECT_NE(text.find("ExitProcess"), std::string::npos);
    EXPECT_NE(text.find("Ghidra analysis was not run"), std::string::npos);
    EXPECT_NE(text.find("not verdicts"), std::string::npos);
}
TEST(Report, ListCapMarksTruncation) {
    BinaryInfo info;
    info.imports.state = Availability::Present;
    for (int i = 0; i < 10; ++i) info.imports.items.push_back({"f" + std::to_string(i), "", std::nullopt, std::nullopt, "func"});
    ReportInputs in;
    in.info = &info;
    in.maxListedItems = 3;
    const auto j = Json::parse(renderJsonReport(in));
    ASSERT_TRUE(j.value);
    EXPECT_EQ(j.value->find("imports")->find("items")->size(), 3u);
    EXPECT_TRUE(j.value->find("imports")->find("truncated")->asBool());
    EXPECT_EQ(j.value->find("imports")->find("count")->asInt(), 10);
}
