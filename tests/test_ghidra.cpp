#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>

#include "xrl/ghidra.hpp"

using namespace xrl;
namespace fs = std::filesystem;

namespace {
struct FakeGhidra {
    fs::path root;
    FakeGhidra() {
        root = fs::temp_directory_path() / "xrl_fake_ghidra";
        fs::create_directories(root / "support");
        fs::create_directories(root / "Ghidra");
#ifdef _WIN32
        std::ofstream(root / "support" / "analyzeHeadless.bat") << "rem fake";
#else
        std::ofstream(root / "support" / "analyzeHeadless") << "#!/bin/sh\n";
#endif
        std::ofstream(root / "Ghidra" / "application.properties") << "application.name=Ghidra\napplication.version=11.2.1\n";
    }
    ~FakeGhidra() { std::error_code ec; fs::remove_all(root, ec); }
};
}  // namespace

TEST(Ghidra, ValidatesInstallLayoutWithoutRunningIt) {
    FakeGhidra g;
    const auto inst = validateGhidraInstall(g.root);
    EXPECT_TRUE(inst.valid) << inst.error;
    EXPECT_EQ(inst.version, "11.2.1");
}
TEST(Ghidra, RejectsMissingOrWrongDirectory) {
    EXPECT_FALSE(validateGhidraInstall("/definitely/not/here").valid);
    EXPECT_FALSE(validateGhidraInstall("").valid);
    const auto tmp = validateGhidraInstall(fs::temp_directory_path());
    EXPECT_FALSE(tmp.valid);
    EXPECT_FALSE(tmp.error.empty());
}
TEST(Ghidra, BuildsHeadlessCommandWithExplicitArguments) {
    FakeGhidra g;
    const auto inst = validateGhidraInstall(g.root);
    GhidraOptions opts;
    opts.decompile = true;
    opts.maxDecompiled = 7;
    const auto cmd = buildGhidraCommand(inst, "/tmp/sample.bin", "/tmp/work", "/tmp/scripts", opts);
    EXPECT_EQ(cmd.program, inst.headless);
    auto has = [&](const std::string& s) { return std::find(cmd.args.begin(), cmd.args.end(), s) != cmd.args.end(); };
    EXPECT_TRUE(has("-import"));
    EXPECT_TRUE(has("-postScript"));
    EXPECT_TRUE(has("XrlExport.java"));
    EXPECT_TRUE(has("-deleteProject"));
    EXPECT_TRUE(has("7"));
    EXPECT_TRUE(has("1"));
    EXPECT_EQ(cmd.args[0], cmd.projectDir);
}
TEST(Ghidra, ParsesRealisticScriptOutput) {
    const std::string json = R"JSON({
      "ghidra_version": "11.2.1", "language": "x86:LE:64:default", "compiler": "gcc", "image_base": "0x100000",
      "total_functions": 2,
      "functions": [
        {"name": "entry", "entry": "0x101000", "size": 42, "signature": "void entry(void)", "external": false, "thunk": false,
         "decompiled": "void entry(void)\n{\n  return;\n}\n"},
        {"name": "printf", "entry": "0x500000", "size": 1, "signature": "int printf(char *,...)", "external": true, "thunk": false}
      ]})JSON";
    const auto r = parseGhidraOutput(json);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.ghidraVersion, "11.2.1");
    EXPECT_EQ(r.language, "x86:LE:64:default");
    ASSERT_EQ(r.functions.size(), 2u);
    EXPECT_EQ(r.functions[0].entry, 0x101000u);
    EXPECT_TRUE(r.functions[0].hasDecompilation);
    EXPECT_NE(r.functions[0].decompiled.find("return;"), std::string::npos);
    EXPECT_FALSE(r.functions[1].hasDecompilation);
    EXPECT_TRUE(r.functions[1].external);
}
TEST(Ghidra, RejectsMalformedOutput) {
    EXPECT_FALSE(parseGhidraOutput("").ok);
    EXPECT_FALSE(parseGhidraOutput("not json").ok);
    EXPECT_FALSE(parseGhidraOutput("[1,2]").ok);
    EXPECT_FALSE(parseGhidraOutput("{\"no_functions\": 1}").ok);
    EXPECT_FALSE(parseGhidraOutput("{\"functions\": [").ok);
}
TEST(Ghidra, ToleratesBadFunctionEntries) {
    const auto r = parseGhidraOutput(R"JSON({"functions": [1, "x", {"name": "ok", "entry": "zzz", "size": -5}]})JSON");
    ASSERT_TRUE(r.ok);
    ASSERT_EQ(r.functions.size(), 1u);
    EXPECT_EQ(r.functions[0].entry, 0u);
    EXPECT_EQ(r.functions[0].size, 0u);
}
