#include <gtest/gtest.h>

#include "fixtures.hpp"
#include "xrl/analyzer.hpp"
#include "xrl/disassembler.hpp"

using namespace xrl;

TEST(Disassembly, StartPointsComeFromFileMetadata) {
    const auto info = analyzeBuffer(fixtures::makeELF());
    const auto pts = knownStartPoints(info);
    ASSERT_GE(pts.size(), 2u);
    EXPECT_EQ(pts[0].fileOffset, 0x100u);  // entry point 0x401000 -> .text file offset
    EXPECT_EQ(pts[0].address, 0x401000u);
}

TEST(Disassembly, UnsupportedArchitectureFailsCleanly) {
    BinaryInfo info;
    info.arch = Arch::Other;
    info.bits = 64;
    const std::vector<uint8_t> data(64, 0x90);
    const auto r = disassemble(info, data, {});
    EXPECT_FALSE(r.ok);
    EXPECT_FALSE(r.error.empty());
    EXPECT_FALSE(disassemblySupported(info));
}

TEST(Disassembly, OffsetOutsideFileIsRejected) {
    const auto data = fixtures::makeELF();
    const auto info = analyzeBuffer(data);
    DisasmRequest req;
    req.fileOffset = data.size();
    EXPECT_FALSE(disassemble(info, data, req).ok);
    req.fileOffset = UINT64_MAX;
    EXPECT_FALSE(disassemble(info, data, req).ok);
}

#ifdef XRL_HAS_CAPSTONE
TEST(Disassembly, DecodesKnownX64Bytes) {
    const auto data = fixtures::makeELF();
    const auto info = analyzeBuffer(data);
    DisasmRequest req;
    req.fileOffset = 0x100;
    req.maxBytes = fixtures::kCode.size();
    const auto r = disassemble(info, data, req);
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_EQ(r.instructions.size(), 4u);
    EXPECT_EQ(r.instructions[0].mnemonic, "push");
    EXPECT_EQ(r.instructions[0].operands, "rbp");
    EXPECT_EQ(r.instructions[0].address, 0x401000u);
    EXPECT_EQ(r.instructions[1].mnemonic, "mov");
    EXPECT_EQ(r.instructions[1].operands, "rbp, rsp");
    EXPECT_EQ(r.instructions[1].address, 0x401001u);
    EXPECT_EQ(r.instructions[1].bytes, (std::vector<uint8_t>{0x48, 0x89, 0xE5}));
    EXPECT_EQ(r.instructions[3].mnemonic, "ret");
    EXPECT_FALSE(r.addressIsFileOffset);
}
TEST(Disassembly, WorksOnPeAndMachOFixtures) {
    for (const auto& data : {fixtures::makePE64(), fixtures::makeMachO64()}) {
        const auto info = analyzeBuffer(data);
        const auto pts = knownStartPoints(info);
        ASSERT_FALSE(pts.empty());
        DisasmRequest req;
        req.fileOffset = pts[0].fileOffset;
        req.maxBytes = fixtures::kCode.size();
        const auto r = disassemble(info, data, req);
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(r.instructions.front().mnemonic, "push");
        EXPECT_EQ(r.instructions.front().address, pts[0].address);
    }
}
TEST(Disassembly, UndecodableBytesBecomeByteEntries) {
    auto data = fixtures::makeELF();
    data[0x100] = 0x06;  // invalid in 64-bit mode
    const auto info = analyzeBuffer(data);
    DisasmRequest req;
    req.fileOffset = 0x100;
    req.maxBytes = 6;
    const auto r = disassemble(info, data, req);
    ASSERT_TRUE(r.ok);
    EXPECT_FALSE(r.instructions[0].valid);
    EXPECT_EQ(r.instructions[0].mnemonic, ".byte");
    EXPECT_GT(r.instructions.size(), 1u);
}
TEST(Disassembly, InstructionAndByteLimitsAreHonoured) {
    const auto data = fixtures::makeELF();
    const auto info = analyzeBuffer(data);
    DisasmRequest req;
    req.fileOffset = 0x100;
    req.maxInstructions = 2;
    EXPECT_EQ(disassemble(info, data, req).instructions.size(), 2u);
    req.maxInstructions = 100;
    req.maxBytes = 0;
    EXPECT_TRUE(disassemble(info, data, req).instructions.empty());
}
TEST(Disassembly, OffsetOutsideSectionsUsesFileOffsetsAndSaysSo) {
    const auto data = fixtures::makeELF();
    const auto info = analyzeBuffer(data);
    DisasmRequest req;
    req.fileOffset = 0x0;
    req.maxBytes = 16;
    const auto r = disassemble(info, data, req);
    ASSERT_TRUE(r.ok);
    EXPECT_TRUE(r.addressIsFileOffset);
    EXPECT_FALSE(r.note.empty());
}
TEST(Disassembly, ReadNeverCrossesEndOfFile) {
    const auto data = fixtures::makeELF();
    const auto info = analyzeBuffer(data);
    DisasmRequest req;
    req.fileOffset = data.size() - 3;
    req.maxBytes = 1'000'000;
    req.maxInstructions = 1000;
    const auto r = disassemble(info, data, req);
    ASSERT_TRUE(r.ok);
    uint64_t total = 0;
    for (const auto& i : r.instructions) total += i.bytes.size();
    EXPECT_LE(total, 3u);
}
#else
TEST(Disassembly, ReportsMissingCapstone) {
    const auto data = fixtures::makeELF();
    const auto info = analyzeBuffer(data);
    EXPECT_FALSE(disassemble(info, data, {}).ok);
}
#endif

