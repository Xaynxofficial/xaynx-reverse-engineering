#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "fixtures.hpp"
#include "xrl/analyzer.hpp"
#include "xrl/byte_reader.hpp"
#include "xrl/sha256.hpp"

using namespace xrl;
namespace fs = std::filesystem;

namespace {
struct TempFile {
    fs::path path;
    explicit TempFile(const std::string& name, const fixtures::Bytes& data) {
        path = fs::temp_directory_path() / ("xrl_test_" + name);
        std::ofstream(path, std::ios::binary).write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    ~TempFile() { std::error_code ec; fs::remove(path, ec); }
};
}  // namespace

TEST(Analyzer, EmptyBuffer) {
    const auto info = analyzeBuffer({});
    EXPECT_FALSE(info.ok());
    EXPECT_NE(info.error.find("empty"), std::string::npos);
    EXPECT_EQ(info.format, Format::Unknown);
}
TEST(Analyzer, InvalidMagicIsUnsupportedButHashed) {
    fixtures::Bytes b(512, 0x41);
    const auto info = analyzeBuffer(b);
    EXPECT_FALSE(info.ok());
    EXPECT_FALSE(info.recognized());
    EXPECT_EQ(info.sha256.size(), 64u);
    EXPECT_EQ(info.sha256, Sha256::hexDigest(b));
    EXPECT_NE(info.error.find("Unsupported"), std::string::npos);
}
TEST(Analyzer, ShortFilesNeverCrash) {
    const auto pe = fixtures::makePE64();
    const auto elf = fixtures::makeELF();
    const auto macho = fixtures::makeMachO64();
    for (const auto* full : {&pe, &elf, &macho})
        for (size_t n = 0; n < full->size(); n += 7) {
            fixtures::Bytes cut(full->begin(), full->begin() + static_cast<long>(n));
            (void)analyzeBuffer(cut);  // must not throw, crash or hang
        }
    SUCCEED();
}
TEST(Analyzer, SingleByteCorruptionNeverCrashes) {
    for (const auto& base : {fixtures::makePE64(), fixtures::makeELF(), fixtures::makeMachO64()}) {
        for (size_t i = 0; i < base.size(); i += 3) {
            auto b = base;
            b[i] ^= 0xFF;
            (void)analyzeBuffer(b);
            b[i] = 0xFF;
            (void)analyzeBuffer(b);
        }
    }
    SUCCEED();
}
TEST(Analyzer, OversizedBufferRejectedBeforeParsing) {
    Limits lim;
    lim.maxFileSize = 100;
    const auto info = analyzeBuffer(fixtures::makeELF(), lim);
    EXPECT_FALSE(info.ok());
    EXPECT_NE(info.error.find("exceeds"), std::string::npos);
    EXPECT_TRUE(info.sha256.empty());
}
TEST(Analyzer, OversizedFileIsNotRead) {
    TempFile f("oversized.bin", fixtures::makeELF());
    Limits lim;
    lim.maxFileSize = 64;
    const auto res = analyzeFile(f.path, lim);
    EXPECT_FALSE(res.info.ok());
    EXPECT_EQ(res.data, nullptr);
    EXPECT_NE(res.info.error.find("exceeds"), std::string::npos);
    EXPECT_GT(res.info.fileSize, 64u);
}
TEST(Analyzer, FileRoundTrip) {
    const auto pe = fixtures::makePE64();
    TempFile f("pe.exe", pe);
    const auto res = analyzeFile(f.path);
    ASSERT_TRUE(res.info.ok()) << res.info.error;
    ASSERT_NE(res.data, nullptr);
    EXPECT_EQ(res.info.fileSize, pe.size());
    EXPECT_EQ(res.info.sha256, Sha256::hexDigest(pe));
    EXPECT_EQ(res.info.fileName, "xrl_test_pe.exe");
}
TEST(Analyzer, EmptyFileOnDisk) {
    TempFile f("empty.bin", {});
    const auto res = analyzeFile(f.path);
    EXPECT_FALSE(res.info.ok());
}
TEST(Analyzer, MissingFileAndDirectory) {
    EXPECT_FALSE(analyzeFile(fs::temp_directory_path() / "xrl_does_not_exist_12345").info.ok());
    EXPECT_FALSE(analyzeFile(fs::temp_directory_path()).info.ok());
}
TEST(Analyzer, ProgressIsReportedMonotonically) {
    int last = -1;
    bool sawDone = false;
    analyzeBuffer(fixtures::makeELF(), {}, [&](int pct, const std::string&) {
        EXPECT_GE(pct, last);
        last = pct;
        sawDone = sawDone || pct == 100;
    });
    EXPECT_TRUE(sawDone);
}

// Heuristics are observations, never verdicts.
TEST(Heuristics, WritableExecutableSectionIsFlagged) {
    auto b = fixtures::makePE64();
    const size_t o = 0x84 + 20 + 240 + 36;  // .text characteristics
    b[o + 3] = 0xE0;                        // R|W|X
    const auto info = analyzeBuffer(b);
    bool found = false;
    for (const auto& f : info.findings) found = found || f.title.find("Writable and executable") != std::string::npos;
    EXPECT_TRUE(found);
}
TEST(Heuristics, CleanFixtureHasNoAccusatoryWording) {
    const auto info = analyzeBuffer(fixtures::makePE64());
    for (const auto& f : info.findings) {
        EXPECT_EQ(f.title.find("malicious"), std::string::npos);
        EXPECT_EQ(f.title.find("malware"), std::string::npos);
    }
}
TEST(Heuristics, ProcessApiImportIsInformationalOnly) {
    // Replace ExitProcess (11 chars) by WriteProcessMemory-like name that fits: reuse 11-char "VirtualAlloc" is longer; use direct check via BinaryInfo.
    BinaryInfo info;
    info.format = Format::PE;
    info.imports.state = Availability::Present;
    info.imports.items.push_back({"WriteProcessMemory", "kernel32.dll", std::nullopt, std::nullopt, "func"});
    runHeuristics(info);
    ASSERT_EQ(info.findings.size(), 1u);
    EXPECT_NE(info.findings[0].detail.find("not evidence"), std::string::npos);
}

TEST(Reader, BoundsChecks) {
    const std::vector<uint8_t> d = {1, 2, 3, 4};
    Reader r(d, true);
    EXPECT_EQ(r.u32(0), 0x04030201u);
    EXPECT_THROW(r.u32(1), ParseError);
    EXPECT_THROW(r.u8(4), ParseError);
    EXPECT_THROW(r.u8(UINT64_MAX), ParseError);
    EXPECT_THROW(r.bytes(UINT64_MAX - 1, 4), ParseError);  // off + len overflows
    EXPECT_FALSE(r.inRange(2, UINT64_MAX));
    EXPECT_TRUE(r.inRange(4, 0));
    Reader be(d, false);
    EXPECT_EQ(be.u16(0), 0x0102u);
}
TEST(Reader, CStringIsBoundedAndSanitised) {
    const std::vector<uint8_t> d = {'a', 'b', 0x01, 'c'};  // no NUL terminator
    Reader r(d);
    EXPECT_EQ(r.cstring(0), "ab?c");
    EXPECT_EQ(r.cstring(0, 2), "ab");
    EXPECT_THROW(r.cstring(5), ParseError);
}

