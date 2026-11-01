#include <gtest/gtest.h>

#include <algorithm>

#include "fixtures.hpp"
#include "xrl/analyzer.hpp"

using namespace xrl;
using namespace fixtures;

namespace {
const Section* findSection(const BinaryInfo& i, const std::string& n) {
    for (const auto& s : i.sections) if (s.name == n) return &s;
    return nullptr;
}
bool hasSymbol(const Category<Symbol>& c, const std::string& n) {
    return std::any_of(c.items.begin(), c.items.end(), [&](const Symbol& s) { return s.name == n; });
}
}  // namespace

// ----------------------------------------------------------------- PE
TEST(PE, ParsesValidFixture) {
    const auto info = analyzeBuffer(makePE64());
    ASSERT_TRUE(info.ok()) << info.error;
    EXPECT_EQ(info.format, Format::PE);
    EXPECT_EQ(info.arch, Arch::X86_64);
    EXPECT_EQ(info.bits, 64);
    EXPECT_EQ(info.endian, Endian::Little);
    ASSERT_TRUE(info.entryPoint);
    EXPECT_EQ(*info.entryPoint, 0x140001000u);
    ASSERT_EQ(info.sections.size(), 2u);
    const auto* text = findSection(info, ".text");
    ASSERT_TRUE(text);
    EXPECT_TRUE(text->executable);
    EXPECT_FALSE(text->writable);
    EXPECT_EQ(text->fileOffset, 0x400u);
    EXPECT_TRUE(text->entropy.has_value());
}
TEST(PE, ParsesImportsAndExports) {
    const auto info = analyzeBuffer(makePE64());
    ASSERT_TRUE(info.ok()) << info.error;
    EXPECT_EQ(info.imports.state, Availability::Present);
    ASSERT_EQ(info.imports.items.size(), 1u);
    EXPECT_EQ(info.imports.items[0].name, "ExitProcess");
    EXPECT_EQ(info.imports.items[0].library, "kernel32.dll");
    ASSERT_EQ(info.libraries.items.size(), 1u);
    EXPECT_EQ(info.libraries.items[0], "kernel32.dll");
    EXPECT_EQ(info.exports.state, Availability::Present);
    ASSERT_EQ(info.exports.items.size(), 1u);
    EXPECT_EQ(info.exports.items[0].name, "my_export");
    EXPECT_EQ(info.exports.items[0].address.value_or(0), 0x140001000u);
}
TEST(PE, ParsesBaseRelocationsAndCodeViewIdentity) {
    const auto relocInfo = analyzeBuffer(makePE64WithBaseRelocation());
    ASSERT_TRUE(relocInfo.ok()) << relocInfo.error;
    ASSERT_EQ(relocInfo.relocations.state, Availability::Present);
    ASSERT_EQ(relocInfo.relocations.items.size(), 1u);
    EXPECT_EQ(relocInfo.relocations.items[0].address, 0x140001010u);
    EXPECT_EQ(relocInfo.relocations.items[0].fileOffset, 0x410u);
    EXPECT_EQ(relocInfo.relocations.items[0].typeName, "DIR64");
    EXPECT_EQ(relocInfo.relocations.items[0].source, "PE base relocation directory");

    const auto debugInfo = analyzeBuffer(makePE64WithCodeView());
    ASSERT_TRUE(debugInfo.ok()) << debugInfo.error;
    const auto metadataValue = [&](const std::string& key) -> std::string {
        const auto found = std::find_if(debugInfo.metadata.begin(), debugInfo.metadata.end(),
                                        [&](const auto& entry) { return entry.first == key; });
        return found == debugInfo.metadata.end() ? std::string{} : found->second;
    };
    EXPECT_EQ(metadataValue("CodeView PDB path"), "test.pdb");
    EXPECT_EQ(metadataValue("CodeView age"), "2");
    EXPECT_EQ(metadataValue("External debug symbols"), "PDB referenced; symbols are not loaded from disk");
    EXPECT_FALSE(metadataValue("CodeView GUID").empty());
}
TEST(PE, ParsesCoffSymbolAndSectionRelocation) {
    const auto info = analyzeBuffer(makePE64WithCoffRelocation());
    ASSERT_TRUE(info.ok()) << info.error;
    ASSERT_TRUE(hasSymbol(info.symbols, "target"));
    ASSERT_EQ(info.relocations.items.size(), 1u);
    const auto& relocation = info.relocations.items.front();
    EXPECT_EQ(relocation.address, 0x140001010u);
    EXPECT_EQ(relocation.fileOffset, 0x410u);
    EXPECT_EQ(relocation.symbolName, "target");
    EXPECT_EQ(relocation.targetAddress, 0x140001020u);
    EXPECT_EQ(relocation.typeName, "COFF relocation 0x0004");
}
TEST(PE, AbsentVersusUnavailable) {
    auto b = makePE64();
    // zero both directories -> imports/exports confirmed absent
    for (size_t o : {size_t{0x84 + 20 + 112}, size_t{0x84 + 20 + 112 + 8}})
        for (size_t k = 0; k < 8; ++k) b[o + k] = 0;
    const auto info = analyzeBuffer(b);
    ASSERT_TRUE(info.ok()) << info.error;
    EXPECT_EQ(info.imports.state, Availability::Absent);
    EXPECT_EQ(info.exports.state, Availability::Absent);
    // COFF symbol table is referenced as absent here, but a non-zero pointer must not be called "absent"
    b[0x84 + 8] = 0x10;
    EXPECT_EQ(analyzeBuffer(b).symbols.state, Availability::NotParsed);
}
TEST(PE, MzWithoutPeSignature) {
    Bytes b(256, 0);
    b[0] = 'M'; b[1] = 'Z';
    const auto info = analyzeBuffer(b);
    EXPECT_FALSE(info.ok());
    EXPECT_EQ(info.format, Format::PE);
    EXPECT_NE(info.error.find("PE"), std::string::npos);
}
TEST(PE, LfanewOutOfRange) {
    auto b = makePE64();
    b[0x3C] = 0xFF; b[0x3D] = 0xFF; b[0x3E] = 0xFF; b[0x3F] = 0xFF;
    EXPECT_FALSE(analyzeBuffer(b).ok());
}
TEST(PE, TruncatedInsideSectionTable) {
    auto b = makePE64();
    b.resize(0x84 + 20 + 240 + 40 + 10);  // cut inside the 2nd section header
    const auto info = analyzeBuffer(b);
    EXPECT_FALSE(info.ok());
    EXPECT_NE(info.error.find("Truncated"), std::string::npos) << info.error;
}
TEST(PE, TruncatedBelowDosHeader) {
    Bytes b = {'M', 'Z', 0, 0};
    const auto info = analyzeBuffer(b);
    EXPECT_FALSE(info.ok());
    EXPECT_EQ(info.format, Format::PE);
}
TEST(PE, SectionRawDataBeyondEndOfFileIsFlaggedNotRead) {
    auto b = makePE64();
    // .text SizeOfRawData -> huge
    const size_t o = 0x84 + 20 + 240;
    b[o + 16] = 0xFF; b[o + 17] = 0xFF; b[o + 18] = 0xFF; b[o + 19] = 0x7F;
    const auto info = analyzeBuffer(b);
    const auto* text = findSection(info, ".text");
    ASSERT_TRUE(text);
    EXPECT_FALSE(text->boundsValid);
    EXPECT_FALSE(text->entropy.has_value());
    EXPECT_FALSE(info.warnings.empty());
}
TEST(PE, ImportRvaPointingOutsideFileKeepsPartialResults) {
    auto b = makePE64();
    const size_t opt = 0x84 + 20;
    b[opt + 112 + 8 + 2] = 0xFF;  // import dir RVA -> 0xFF2000
    const auto info = analyzeBuffer(b);
    EXPECT_TRUE(info.imports.items.empty());
    EXPECT_FALSE(info.warnings.empty());
    EXPECT_EQ(info.sections.size(), 2u);  // sections still available
}
TEST(PE, UnsupportedOptionalHeaderMagic) {
    auto b = makePE64();
    b[0x84 + 20] = 0x07; b[0x84 + 21] = 0x01;
    EXPECT_FALSE(analyzeBuffer(b).ok());
}
TEST(PE, UnknownMachineIsReportedAsOther) {
    auto b = makePE64();
    b[0x84] = 0x34; b[0x85] = 0x12;
    const auto info = analyzeBuffer(b);
    EXPECT_EQ(info.arch, Arch::Other);
}
TEST(PE, ExcessiveSectionCountRejected) {
    auto b = makePE64();
    b[0x86] = 0xFF; b[0x87] = 0xFF;  // 65535 sections
    EXPECT_FALSE(analyzeBuffer(b).ok());
}

// ----------------------------------------------------------------- ELF
TEST(ELF, ParsesValid64LittleEndian) {
    const auto info = analyzeBuffer(makeELF());
    ASSERT_TRUE(info.ok()) << info.error;
    EXPECT_EQ(info.format, Format::ELF);
    EXPECT_EQ(info.arch, Arch::X86_64);
    EXPECT_EQ(info.bits, 64);
    EXPECT_EQ(info.endian, Endian::Little);
    EXPECT_EQ(info.entryPoint.value_or(0), 0x401000u);
    const auto* text = findSection(info, ".text");
    ASSERT_TRUE(text);
    EXPECT_TRUE(text->executable);
    EXPECT_EQ(text->fileOffset, 0x100u);
    EXPECT_TRUE(findSection(info, ".dynsym"));
    EXPECT_TRUE(hasSymbol(info.imports, "puts"));
    EXPECT_TRUE(hasSymbol(info.exports, "my_func"));
    EXPECT_FALSE(hasSymbol(info.exports, "puts"));
    ASSERT_EQ(info.libraries.items.size(), 1u);
    EXPECT_EQ(info.libraries.items[0], "libc.so.6");
    EXPECT_EQ(info.symbols.state, Availability::Absent);  // no .symtab in fixture: stripped
}
TEST(ELF, ParsesValid32BitBigEndian) {
    const auto info = analyzeBuffer(makeELF(false, true, 20));  // PowerPC
    ASSERT_TRUE(info.ok()) << info.error;
    EXPECT_EQ(info.bits, 32);
    EXPECT_EQ(info.endian, Endian::Big);
    EXPECT_EQ(info.arch, Arch::PowerPC);
    EXPECT_TRUE(hasSymbol(info.exports, "my_func"));
    EXPECT_EQ(info.libraries.items.size(), 1u);
}
TEST(ELF, ParsesRelaSymbolAndFileOffsetMapping) {
    auto b = makeELF();
    b.resize(0x200 + 7 * 64);
    Writer w{b};
    constexpr size_t shoff = 0x200;
    constexpr size_t relOffset = 0x1D0;
    w.u16(60, 7);
    w.u64(relOffset, 0x401002);
    w.u64(relOffset + 8, (uint64_t{1} << 32) | 2);
    w.u64(relOffset + 16, static_cast<uint64_t>(-4));
    const size_t header = shoff + 6 * 64;
    w.u32(header + 4, 4);       // SHT_RELA
    w.u64(header + 24, relOffset);
    w.u64(header + 32, 24);
    w.u32(header + 40, 3);      // linked .dynsym
    w.u32(header + 44, 1);      // relocation applies to .text
    w.u64(header + 56, 24);

    const auto info = analyzeBuffer(b);
    ASSERT_TRUE(info.ok()) << info.error;
    ASSERT_EQ(info.relocations.state, Availability::Present);
    ASSERT_EQ(info.relocations.items.size(), 1u);
    const auto& relocation = info.relocations.items.front();
    EXPECT_EQ(relocation.address, 0x401002u);
    EXPECT_EQ(relocation.fileOffset, 0x102u);
    EXPECT_EQ(relocation.symbolName, "puts");
    EXPECT_EQ(relocation.addend, -4);
    EXPECT_FALSE(relocation.targetAddress.has_value());
}
TEST(ELF, ParsesRelWithoutInventingAnAddend) {
    auto b = makeELF();
    b.resize(0x200 + 7 * 64);
    Writer w{b};
    constexpr size_t shoff = 0x200;
    constexpr size_t relOffset = 0x1D0;
    w.u16(60, 7);
    w.u64(relOffset, 0x401002);
    w.u64(relOffset + 8, (uint64_t{1} << 32) | 2);
    const size_t header = shoff + 6 * 64;
    w.u32(header + 4, 9);       // SHT_REL
    w.u64(header + 24, relOffset);
    w.u64(header + 32, 16);
    w.u32(header + 40, 3);
    w.u32(header + 44, 1);
    w.u64(header + 56, 16);

    const auto info = analyzeBuffer(b);
    ASSERT_TRUE(info.ok()) << info.error;
    ASSERT_EQ(info.relocations.items.size(), 1u);
    EXPECT_EQ(info.relocations.items.front().symbolName, "puts");
    EXPECT_EQ(info.relocations.items.front().fileOffset, 0x102u);
    EXPECT_FALSE(info.relocations.items.front().addend.has_value());
}
TEST(ELF, InvalidRelocationSymbolTableLinkIsNotReportedAsAbsent) {
    auto b = makeELF();
    b.resize(0x200 + 7 * 64);
    Writer w{b};
    constexpr size_t shoff = 0x200;
    constexpr size_t relOffset = 0x1D0;
    w.u16(60, 7);
    w.u64(relOffset, 0x401002);
    w.u64(relOffset + 8, (uint64_t{1} << 32) | 2);
    w.u32(shoff + 6 * 64 + 4, 4);  // SHT_RELA
    w.u64(shoff + 6 * 64 + 24, relOffset);
    w.u64(shoff + 6 * 64 + 32, 24);
    w.u32(shoff + 6 * 64 + 40, 0xFF);
    w.u32(shoff + 6 * 64 + 44, 1);
    w.u64(shoff + 6 * 64 + 56, 24);

    const auto info = analyzeBuffer(b);
    EXPECT_TRUE(info.ok()) << info.error;
    EXPECT_EQ(info.relocations.state, Availability::NotParsed);
    EXPECT_FALSE(info.warnings.empty());
}
TEST(ELF, Valid32BitLittleEndianAndUnsupportedMachine) {
    auto info = analyzeBuffer(makeELF(false, false, 3));
    ASSERT_TRUE(info.ok()) << info.error;
    EXPECT_EQ(info.arch, Arch::X86);
    info = analyzeBuffer(makeELF(true, false, 0x1234));
    EXPECT_TRUE(info.ok());
    EXPECT_EQ(info.arch, Arch::Other);
}
TEST(ELF, BadClassAndDataBytes) {
    auto b = makeELF(); b[4] = 7;
    EXPECT_FALSE(analyzeBuffer(b).ok());
    b = makeELF(); b[5] = 9;
    EXPECT_FALSE(analyzeBuffer(b).ok());
}
TEST(ELF, TruncatedHeader) {
    auto b = makeELF(); b.resize(40);
    const auto info = analyzeBuffer(b);
    EXPECT_FALSE(info.ok());
    EXPECT_EQ(info.format, Format::ELF);
}
TEST(ELF, SectionTableBeyondEndOfFile) {
    auto b = makeELF();
    b.resize(0x200 + 64 * 3);  // table claims 6 entries
    const auto info = analyzeBuffer(b);
    EXPECT_FALSE(info.ok());
    EXPECT_NE(info.error.find("outside the file"), std::string::npos) << info.error;
}
TEST(ELF, SectionDataBeyondEndOfFile) {
    auto b = makeELF();
    const size_t o = 0x200 + 64 * 1;  // .text header
    b[o + 32] = 0xFF; b[o + 33] = 0xFF; b[o + 34] = 0xFF; b[o + 35] = 0x0F;  // sh_size huge
    const auto info = analyzeBuffer(b);
    const auto* text = findSection(info, ".text");
    ASSERT_TRUE(text);
    EXPECT_FALSE(text->boundsValid);
    EXPECT_FALSE(text->entropy.has_value());
}
TEST(ELF, SectionOffsetNearUint64MaxDoesNotOverflow) {
    auto b = makeELF();
    const size_t o = 0x200 + 64 * 1;
    for (size_t k = 0; k < 8; ++k) b[o + 24 + k] = 0xFF;     // sh_offset = 2^64-1
    for (size_t k = 0; k < 8; ++k) b[o + 32 + k] = 0x10;     // sh_size
    const auto info = analyzeBuffer(b);
    const auto* text = findSection(info, ".text");
    ASSERT_TRUE(text);
    EXPECT_FALSE(text->boundsValid);
}
TEST(ELF, StringIndexOutOfRangeGivesPlaceholder) {
    auto b = makeELF();
    const size_t o = 0x200 + 64 * 1;
    b[o] = 0xFF; b[o + 1] = 0xFF;  // sh_name past table end
    const auto info = analyzeBuffer(b);
    ASSERT_TRUE(info.ok()) << info.error;
    EXPECT_EQ(info.sections[0].name, "<invalid>");
}
TEST(ELF, ShstrndxOutOfRange) {
    auto b = makeELF(); b[62] = 0x40;
    EXPECT_FALSE(analyzeBuffer(b).ok());
}
TEST(ELF, NoSectionHeadersMeansUnavailableNotAbsent) {
    auto b = makeELF();
    for (size_t k = 0; k < 8; ++k) b[40 + k] = 0;  // e_shoff = 0
    const auto info = analyzeBuffer(b);
    EXPECT_TRUE(info.ok());
    EXPECT_FALSE(info.sectionsParsed);
    EXPECT_EQ(info.imports.state, Availability::NotParsed);
    EXPECT_EQ(info.exports.state, Availability::NotParsed);
    EXPECT_EQ(info.libraries.state, Availability::NotParsed);
}
TEST(ELF, DynsymWithBadLinkIsReportedNotCrashed) {
    auto b = makeELF();
    const size_t o = 0x200 + 64 * 3;
    b[o + 40] = 0xEE;  // sh_link -> nonexistent
    const auto info = analyzeBuffer(b);
    EXPECT_TRUE(info.ok());
    EXPECT_FALSE(info.warnings.empty());
}

// ----------------------------------------------------------------- Mach-O
TEST(MachO, ParsesValid64) {
    const auto info = analyzeBuffer(makeMachO64());
    ASSERT_TRUE(info.ok()) << info.error;
    EXPECT_EQ(info.format, Format::MachO);
    EXPECT_EQ(info.arch, Arch::X86_64);
    EXPECT_EQ(info.bits, 64);
    EXPECT_EQ(info.endian, Endian::Little);
    EXPECT_EQ(info.entryPoint.value_or(0), 0x100000200u);
    const auto* text = findSection(info, "__text");
    ASSERT_TRUE(text);
    EXPECT_EQ(text->segment, "__TEXT");
    EXPECT_TRUE(text->executable);
    EXPECT_EQ(text->fileOffset, 0x200u);
    ASSERT_EQ(info.libraries.items.size(), 1u);
    EXPECT_EQ(info.libraries.items[0], "/usr/lib/libSystem.B.dylib");
    ASSERT_TRUE(hasSymbol(info.imports, "_printf"));
    EXPECT_EQ(info.imports.items[0].library, "/usr/lib/libSystem.B.dylib");
    EXPECT_TRUE(hasSymbol(info.exports, "_main"));
}
TEST(MachO, ParsesSectionRelocationAndMapsExternalSymbol) {
    auto b = makeMachO64();
    Writer w{b};
    w.u32(160, 0x380);  // __text relocation table offset
    w.u32(164, 1);
    w.u32(0x380, 0x2);
    w.u32(0x384, 1 | (1u << 27));  // external relocation to nlist symbol 1

    const auto info = analyzeBuffer(b);
    ASSERT_TRUE(info.ok()) << info.error;
    ASSERT_EQ(info.relocations.state, Availability::Present);
    ASSERT_EQ(info.relocations.items.size(), 1u);
    EXPECT_EQ(info.relocations.items[0].address, 0x100000202u);
    EXPECT_EQ(info.relocations.items[0].fileOffset, 0x202u);
    EXPECT_EQ(info.relocations.items[0].symbolName, "_main");
    EXPECT_EQ(info.relocations.items[0].targetAddress, 0x100000200u);
}
TEST(MachO, InvalidSectionRelocationTableIsUnavailable) {
    auto b = makeMachO64();
    Writer w{b};
    w.u32(160, 0x500);
    w.u32(164, 1);
    const auto info = analyzeBuffer(b);
    EXPECT_EQ(info.relocations.state, Availability::NotParsed);
    EXPECT_FALSE(info.warnings.empty());
}
TEST(MachO, ArmAndUnsupportedCpuTypes) {
    EXPECT_EQ(analyzeBuffer(makeMachO64(0x0100000C)).arch, Arch::Arm64);
    const auto weird = analyzeBuffer(makeMachO64(0x00ABCDEF));
    EXPECT_TRUE(weird.ok());
    EXPECT_EQ(weird.arch, Arch::Other);
}
TEST(MachO, UniversalBinaryAnalysesSliceWithAbsoluteOffsets) {
    const auto info = analyzeBuffer(makeFat(makeMachO64()));
    ASSERT_TRUE(info.ok()) << info.error;
    const auto* text = findSection(info, "__text");
    ASSERT_TRUE(text);
    EXPECT_EQ(text->fileOffset, 0x1000u + 0x200u);  // absolute within the fat file
    EXPECT_TRUE(text->boundsValid);
}
TEST(MachO, UniversalSliceOutsideFile) {
    auto fat = makeFat(makeMachO64());
    fat.resize(0x800);
    const auto info = analyzeBuffer(fat);
    EXPECT_FALSE(info.ok());
}
TEST(MachO, JavaClassHeaderIsNotMistakenForUniversal) {
    Bytes b = {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34, 0, 0, 0, 0};
    const auto info = analyzeBuffer(b);
    EXPECT_FALSE(info.ok());
    EXPECT_NE(info.error.find("Java"), std::string::npos);
}
TEST(MachO, TruncatedLoadCommands) {
    auto b = makeMachO64();
    b.resize(100);
    const auto info = analyzeBuffer(b);
    EXPECT_FALSE(info.ok());
    EXPECT_EQ(info.format, Format::MachO);
}
TEST(MachO, InvalidCmdsize) {
    auto b = makeMachO64();
    b[32 + 4] = 0x02; b[32 + 5] = 0; b[32 + 6] = 0; b[32 + 7] = 0;  // cmdsize 2
    EXPECT_FALSE(analyzeBuffer(b).ok());
}
TEST(MachO, HugeNcmdsRejected) {
    auto b = makeMachO64();
    b[16] = 0xFF; b[17] = 0xFF; b[18] = 0xFF; b[19] = 0x7F;
    EXPECT_FALSE(analyzeBuffer(b).ok());
}
TEST(MachO, SymtabOutOfBounds) {
    auto b = makeMachO64();
    const size_t symtab = 32 + 152 + 56;
    b[symtab + 9] = 0xFF; b[symtab + 10] = 0xFF;  // symoff huge
    EXPECT_FALSE(analyzeBuffer(b).ok());
}
TEST(MachO, SectionOffsetBeyondFileIsFlagged) {
    auto b = makeMachO64();
    const size_t sec = 32 + 72;
    b[sec + 48] = 0xFF; b[sec + 49] = 0xFF; b[sec + 50] = 0xFF; b[sec + 51] = 0x7F;
    const auto info = analyzeBuffer(b);
    const auto* text = findSection(info, "__text");
    ASSERT_TRUE(text);
    EXPECT_FALSE(text->boundsValid);
}
TEST(MachO, BigEndian32BitHeader) {
    // Minimal big-endian 32-bit PowerPC header with zero load commands.
    Bytes b(28, 0);
    Writer w{b, true};
    w.u32(0, 0xFEEDFACE); w.u32(4, 18); w.u32(12, 2);
    const auto info = analyzeBuffer(b);
    ASSERT_TRUE(info.ok()) << info.error;
    EXPECT_EQ(info.endian, Endian::Big);
    EXPECT_EQ(info.arch, Arch::PowerPC);
    EXPECT_EQ(info.bits, 32);
}
