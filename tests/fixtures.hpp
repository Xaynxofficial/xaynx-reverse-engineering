#pragma once
// Synthetic, hand-assembled minimal binaries used as test fixtures. They contain no real
// program or malware: only headers plus a few bytes of x86-64 code (push rbp; mov rbp,rsp; pop rbp; ret).
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace fixtures {

using Bytes = std::vector<uint8_t>;

struct Writer {
    Bytes& b;
    bool be = false;
    void ensure(size_t n) { if (b.size() < n) b.resize(n, 0); }
    void put(size_t off, uint64_t v, int size) {
        ensure(off + static_cast<size_t>(size));
        for (int i = 0; i < size; ++i) {
            const int shift = be ? (size - 1 - i) : i;
            b[off + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * shift));
        }
    }
    void u8(size_t o, uint64_t v) { put(o, v, 1); }
    void u16(size_t o, uint64_t v) { put(o, v, 2); }
    void u32(size_t o, uint64_t v) { put(o, v, 4); }
    void u64(size_t o, uint64_t v) { put(o, v, 8); }
    void str(size_t o, const std::string& s) {
        ensure(o + s.size() + 1);
        std::memcpy(&b[o], s.c_str(), s.size() + 1);
    }
    void raw(size_t o, const Bytes& d) {
        ensure(o + d.size());
        std::memcpy(&b[o], d.data(), d.size());
    }
};

inline const Bytes kCode = {0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3};

// ------------------------------------------------------------------ PE32+
// One .text section (RVA 0x1000) and one .rdata (RVA 0x2000) holding an import table
// (kernel32.dll!ExitProcess) and an export table ("my_export").
inline Bytes makePE64() {
    Bytes b;
    Writer w{b};
    w.u8(0, 'M'); w.u8(1, 'Z');
    w.u32(0x3C, 0x80);
    w.u32(0x80, 0x00004550);                 // PE\0\0
    const size_t coff = 0x84;
    w.u16(coff, 0x8664);                     // AMD64
    w.u16(coff + 2, 2);                      // sections
    w.u32(coff + 4, 0x5F000000);
    w.u16(coff + 16, 240);                   // SizeOfOptionalHeader
    w.u16(coff + 18, 0x0022);                // EXECUTABLE | LARGE_ADDRESS_AWARE
    const size_t opt = coff + 20;
    w.u16(opt, 0x20B);
    w.u32(opt + 16, 0x1000);                 // entry RVA
    w.u64(opt + 24, 0x140000000);            // image base
    w.u32(opt + 60, 0x400);                  // size of headers
    w.u16(opt + 68, 3);                      // console
    w.u32(opt + 108, 16);                    // data directories
    w.u32(opt + 112 + 0 * 8, 0x2100);        // export dir
    w.u32(opt + 112 + 0 * 8 + 4, 0x80);
    w.u32(opt + 112 + 1 * 8, 0x2000);        // import dir
    w.u32(opt + 112 + 1 * 8 + 4, 0x28);
    const size_t sec = opt + 240;
    auto section = [&](size_t i, const char* name, uint32_t vsize, uint32_t va, uint32_t rawSize, uint32_t rawPtr, uint32_t ch) {
        const size_t o = sec + i * 40;
        for (size_t k = 0; k < 8 && name[k]; ++k) w.u8(o + k, static_cast<uint8_t>(name[k]));
        w.u32(o + 8, vsize); w.u32(o + 12, va); w.u32(o + 16, rawSize); w.u32(o + 20, rawPtr); w.u32(o + 36, ch);
    };
    section(0, ".text", 0x200, 0x1000, 0x200, 0x400, 0x60000020);
    section(1, ".rdata", 0x400, 0x2000, 0x400, 0x600, 0x40000040);
    w.raw(0x400, kCode);
    // .rdata raw 0x600 <-> RVA 0x2000
    auto R = [](uint32_t rva) { return static_cast<size_t>(0x600 + (rva - 0x2000)); };
    w.u32(R(0x2000) + 0, 0x2040);            // OriginalFirstThunk
    w.u32(R(0x2000) + 12, 0x2080);           // Name
    w.u32(R(0x2000) + 16, 0x2040);           // FirstThunk
    w.u64(R(0x2040), 0x2060);                // thunk -> hint/name
    w.u16(R(0x2060), 0);
    w.str(R(0x2062), "ExitProcess");
    w.str(R(0x2080), "kernel32.dll");
    w.u32(R(0x2100) + 12, 0x2170);           // export module name
    w.u32(R(0x2100) + 16, 1);                // ordinal base
    w.u32(R(0x2100) + 20, 1);                // functions
    w.u32(R(0x2100) + 24, 1);                // names
    w.u32(R(0x2100) + 28, 0x2130);
    w.u32(R(0x2100) + 32, 0x2138);
    w.u32(R(0x2100) + 36, 0x2140);
    w.u32(R(0x2130), 0x1000);                // function RVA
    w.u32(R(0x2138), 0x2150);                // name RVA
    w.u16(R(0x2140), 0);
    w.str(R(0x2150), "my_export");
    w.str(R(0x2170), "fixture.dll");
    w.ensure(0xA00);
    return b;
}

inline Bytes makePE64WithCodeView() {
    Bytes b = makePE64();
    Writer w{b};
    constexpr size_t optionalHeader = 0x98;
    constexpr size_t dataDirectoryOffset = optionalHeader + 112;
    w.u32(dataDirectoryOffset + 6 * 8, 0x2200);
    w.u32(dataDirectoryOffset + 6 * 8 + 4, 28);
    const size_t debugDirectory = 0x800;
    w.u32(debugDirectory + 12, 2);
    w.u32(debugDirectory + 16, 33);
    w.u32(debugDirectory + 20, 0x2240);
    w.u32(debugDirectory + 24, 0x840);
    w.u32(0x840, 0x53445352);
    for (size_t i = 0; i < 16; ++i) w.u8(0x844 + i, i);
    w.u32(0x854, 2);
    w.str(0x858, "test.pdb");
    return b;
}

inline Bytes makePE64WithBaseRelocation() {
    Bytes b = makePE64();
    Writer w{b};
    constexpr size_t optionalHeader = 0x98;
    constexpr size_t dataDirectoryOffset = optionalHeader + 112;
    w.u32(dataDirectoryOffset + 5 * 8, 0x2200);
    w.u32(dataDirectoryOffset + 5 * 8 + 4, 12);
    w.u32(0x800, 0x1000);
    w.u32(0x804, 12);
    w.u16(0x808, 0xA010);
    w.u16(0x80A, 0);
    return b;
}

inline Bytes makePE64WithCoffRelocation() {
    Bytes b = makePE64();
    Writer w{b};
    constexpr size_t coffHeader = 0x84;
    constexpr size_t textSectionHeader = 0x188;
    constexpr size_t symbolTable = 0xA00;
    constexpr size_t relocationTable = 0xA20;
    w.u32(coffHeader + 8, symbolTable);
    w.u32(coffHeader + 12, 1);
    w.u32(textSectionHeader + 24, relocationTable);
    w.u16(textSectionHeader + 32, 1);
    w.str(symbolTable, "target");
    w.u32(symbolTable + 8, 0x20);
    w.u16(symbolTable + 12, 1);
    w.u16(symbolTable + 14, 0x20);
    w.u8(symbolTable + 16, 2);
    w.u32(symbolTable + 18, 4);  // empty COFF string table
    w.u32(relocationTable, 0x10);
    w.u32(relocationTable + 4, 0);
    w.u16(relocationTable + 8, 4);  // IMAGE_REL_AMD64_REL32
    w.ensure(relocationTable + 10);
    return b;
}

// ------------------------------------------------------------------ ELF
// Sections: null, .text, .dynstr, .dynsym (puts undefined, my_func defined), .dynamic (NEEDED libc.so.6), .shstrtab
inline Bytes makeELF(bool is64 = true, bool bigEndian = false, uint16_t machine = 62) {
    Bytes b;
    Writer w{b, bigEndian};
    w.u8(0, 0x7F); w.u8(1, 'E'); w.u8(2, 'L'); w.u8(3, 'F');
    w.u8(4, is64 ? 2 : 1); w.u8(5, bigEndian ? 2 : 1); w.u8(6, 1);
    const size_t ehsize = is64 ? 64 : 52;
    const size_t shentsize = is64 ? 64 : 40, symsz = is64 ? 24 : 16, dynsz = is64 ? 16 : 8;
    const uint64_t textAddr = 0x401000;

    const size_t textOff = 0x100;
    w.raw(textOff, kCode);
    const std::string dynstr = std::string("\0libc.so.6\0puts\0my_func\0", 24);
    const size_t dynstrOff = 0x120;
    w.raw(dynstrOff, Bytes(dynstr.begin(), dynstr.end()));
    const size_t dynsymOff = 0x140;
    auto sym = [&](size_t i, uint32_t name, uint8_t info, uint16_t shndx, uint64_t value) {
        const size_t o = dynsymOff + i * symsz;
        if (is64) { w.u32(o, name); w.u8(o + 4, info); w.u16(o + 6, shndx); w.u64(o + 8, value); }
        else { w.u32(o, name); w.u32(o + 4, value); w.u8(o + 12, info); w.u16(o + 14, shndx); }
    };
    sym(1, 11, 0x12, 0, 0);                    // puts: GLOBAL FUNC, undefined
    sym(2, 16, 0x12, 1, textAddr);             // my_func: GLOBAL FUNC in section 1
    const size_t dynamicOff = 0x180;
    if (is64) { w.u64(dynamicOff, 1); w.u64(dynamicOff + 8, 1); w.u64(dynamicOff + 16, 0); w.u64(dynamicOff + 24, 0); }
    else { w.u32(dynamicOff, 1); w.u32(dynamicOff + 4, 1); w.u32(dynamicOff + 8, 0); w.u32(dynamicOff + 12, 0); }
    const std::string shstr = std::string("\0.text\0.dynstr\0.dynsym\0.dynamic\0.shstrtab\0", 42);
    const size_t shstrOff = 0x1A0;
    w.raw(shstrOff, Bytes(shstr.begin(), shstr.end()));
    const size_t shoff = 0x200;
    const uint16_t shnum = 6;

    auto shdr = [&](size_t i, uint32_t name, uint32_t type, uint64_t flags, uint64_t addr,
                    uint64_t off, uint64_t size, uint32_t link, uint64_t entsize, uint32_t info = 0) {
        const size_t o = shoff + i * shentsize;
        w.u32(o, name); w.u32(o + 4, type);
        if (is64) {
            w.u64(o + 8, flags); w.u64(o + 16, addr); w.u64(o + 24, off); w.u64(o + 32, size);
            w.u32(o + 40, link); w.u32(o + 44, info); w.u64(o + 56, entsize);
        } else {
            w.u32(o + 8, flags); w.u32(o + 12, addr); w.u32(o + 16, off); w.u32(o + 20, size);
            w.u32(o + 24, link); w.u32(o + 28, info); w.u32(o + 36, entsize);
        }
    };
    shdr(0, 0, 0, 0, 0, 0, 0, 0, 0);
    shdr(1, 1, 1, 6, textAddr, textOff, kCode.size(), 0, 0);              // .text PROGBITS AX
    shdr(2, 7, 3, 2, 0, dynstrOff, dynstr.size(), 0, 0);                  // .dynstr STRTAB
    shdr(3, 15, 11, 2, 0, dynsymOff, 3 * symsz, 2, symsz);                // .dynsym -> .dynstr
    shdr(4, 23, 6, 3, 0, dynamicOff, 2 * dynsz, 2, dynsz);                // .dynamic -> .dynstr
    shdr(5, 32, 3, 0, 0, shstrOff, shstr.size(), 0, 0);                   // .shstrtab

    // ELF header
    w.u16(16, 2);                              // ET_EXEC
    w.u16(18, machine);
    w.u32(20, 1);
    if (is64) {
        w.u64(24, textAddr); w.u64(32, 0); w.u64(40, shoff);
        w.u16(52, ehsize); w.u16(54, 56); w.u16(56, 0); w.u16(58, shentsize); w.u16(60, shnum); w.u16(62, 5);
    } else {
        w.u32(24, textAddr); w.u32(28, 0); w.u32(32, shoff);
        w.u16(40, ehsize); w.u16(42, 32); w.u16(44, 0); w.u16(46, shentsize); w.u16(48, shnum); w.u16(50, 5);
    }
    w.ensure(shoff + shnum * shentsize);
    return b;
}

// ------------------------------------------------------------------ Mach-O 64 (little-endian, x86-64)
inline Bytes makeMachO64(uint32_t cputype = 0x01000007) {
    Bytes b;
    Writer w{b};
    w.u32(0, 0xFEEDFACF);                      // stored LE => bytes CF FA ED FE
    w.u32(4, cputype); w.u32(8, 3); w.u32(12, 2);  // MH_EXECUTE
    w.u32(16, 4);                              // ncmds
    const size_t segSize = 72 + 80, dylibSize = 56, symtabSize = 24, mainSize = 24;
    w.u32(20, segSize + dylibSize + symtabSize + mainSize);
    size_t o = 32;
    // LC_SEGMENT_64 __TEXT + __text
    w.u32(o, 0x19); w.u32(o + 4, segSize); w.str(o + 8, "__TEXT");
    w.u64(o + 24, 0x100000000); w.u64(o + 32, 0x1000); w.u64(o + 40, 0); w.u64(o + 48, 0x400);
    w.u32(o + 56, 5); w.u32(o + 60, 5); w.u32(o + 64, 1);
    w.str(o + 72, "__text"); w.str(o + 72 + 16, "__TEXT");
    w.u64(o + 72 + 32, 0x100000200); w.u64(o + 72 + 40, kCode.size()); w.u32(o + 72 + 48, 0x200);
    o += segSize;
    // LC_LOAD_DYLIB
    w.u32(o, 0xC); w.u32(o + 4, dylibSize); w.u32(o + 8, 24);
    w.str(o + 24, "/usr/lib/libSystem.B.dylib");
    o += dylibSize;
    // LC_SYMTAB
    w.u32(o, 0x2); w.u32(o + 4, symtabSize);
    w.u32(o + 8, 0x300); w.u32(o + 12, 2); w.u32(o + 16, 0x340); w.u32(o + 20, 16);
    o += symtabSize;
    // LC_MAIN
    w.u32(o, 0x80000028); w.u32(o + 4, mainSize); w.u64(o + 8, 0x200);
    w.raw(0x200, kCode);
    // nlist_64: _printf (undefined external, lib ordinal 1), _main (defined external in section 1)
    w.u32(0x300, 1); w.u8(0x304, 0x01); w.u8(0x305, 0); w.u16(0x306, 0x0100); w.u64(0x308, 0);
    w.u32(0x310, 9); w.u8(0x314, 0x0F); w.u8(0x315, 1); w.u16(0x316, 0); w.u64(0x318, 0x100000200);
    w.str(0x341, "_printf"); w.str(0x349, "_main");
    w.ensure(0x400);
    return b;
}

// Wrap a thin Mach-O into a one-slice universal binary.
inline Bytes makeFat(const Bytes& thin, uint32_t cputype = 0x01000007) {
    Bytes b;
    Writer w{b, true};
    w.u32(0, 0xCAFEBABE); w.u32(4, 1);
    w.u32(8, cputype); w.u32(12, 3); w.u32(16, 0x1000); w.u32(20, thin.size()); w.u32(24, 12);
    w.raw(0x1000, thin);
    return b;
}

}  // namespace fixtures
