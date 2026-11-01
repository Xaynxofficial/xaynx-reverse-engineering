#include <algorithm>

#include "xrl/formats.hpp"

namespace xrl {
namespace {

struct ElfMachine {
    Arch arch;
    const char* name;
};

ElfMachine machineInfo(uint16_t m) {
    switch (m) {
        case 3: return {Arch::X86, "x86 (Intel 80386)"};
        case 62: return {Arch::X86_64, "x86-64 (AMD64)"};
        case 40: return {Arch::Arm, "ARM"};
        case 183: return {Arch::Arm64, "ARM64 (AArch64)"};
        case 8: case 10: return {Arch::Mips, "MIPS"};
        case 20: return {Arch::PowerPC, "PowerPC"};
        case 21: return {Arch::PowerPC, "PowerPC 64"};
        case 243: return {Arch::RiscV, "RISC-V"};
        case 0: return {Arch::Unknown, "None"};
        default: return {Arch::Other, "Unrecognised e_machine"};
    }
}

const char* typeName(uint16_t t) {
    switch (t) {
        case 1: return "Relocatable object (ET_REL)";
        case 2: return "Executable (ET_EXEC)";
        case 3: return "Shared object / PIE executable (ET_DYN)";
        case 4: return "Core dump (ET_CORE)";
        default: return "Unknown ELF type";
    }
}

constexpr uint32_t SHT_SYMTAB = 2, SHT_STRTAB = 3, SHT_RELA = 4, SHT_DYNAMIC = 6,
                   SHT_NOBITS = 8, SHT_REL = 9, SHT_DYNSYM = 11;
constexpr uint64_t SHF_WRITE = 1, SHF_ALLOC = 2, SHF_EXEC = 4;

struct Shdr {
    uint32_t name = 0, type = 0, link = 0, info = 0;
    uint64_t flags = 0, addr = 0, offset = 0, size = 0, entsize = 0;
};

const char* symType(uint8_t t) {
    switch (t) {
        case 0: return "notype";
        case 1: return "object";
        case 2: return "func";
        case 3: return "section";
        case 4: return "file";
        case 5: return "common";
        case 6: return "tls";
        case 10: return "gnu_ifunc";
        default: return "other";
    }
}

}  // namespace

void parseELF(std::span<const uint8_t> data, BinaryInfo& info, const Limits& lim) {
    info.format = Format::ELF;
    info.formatName = "ELF";
    if (data.size() < 20) throw ParseError("File too small for an ELF identification header");

    const uint8_t cls = data[4], dataEnc = data[5];
    if (cls != 1 && cls != 2) throw ParseError("Invalid ELF class byte " + hex(cls, 2));
    if (dataEnc != 1 && dataEnc != 2) throw ParseError("Invalid ELF data-encoding byte " + hex(dataEnc, 2));
    const bool is64 = cls == 2;
    info.bits = is64 ? 64 : 32;
    info.endian = dataEnc == 1 ? Endian::Little : Endian::Big;
    info.formatName = is64 ? "ELF64" : "ELF32";

    Reader r(data, dataEnc == 1);
    const uint64_t ehsize = is64 ? 64 : 52;
    if (data.size() < ehsize) throw ParseError("Truncated ELF header (need " + std::to_string(ehsize) + " bytes)");

    const uint16_t type = r.u16(16, "e_type");
    const uint16_t machine = r.u16(18, "e_machine");
    auto word = [&](uint64_t off, const char* w) { return is64 ? r.u64(off, w) : uint64_t{r.u32(off, w)}; };
    const uint64_t entry = word(24, "e_entry");
    const uint64_t phoff = word(is64 ? 32 : 28, "e_phoff");
    const uint64_t shoff = word(is64 ? 40 : 32, "e_shoff");
    const uint16_t phentsize = r.u16(is64 ? 54 : 42, "e_phentsize");
    const uint16_t phnum = r.u16(is64 ? 56 : 44, "e_phnum");
    const uint16_t shentsize = r.u16(is64 ? 58 : 46, "e_shentsize");
    uint64_t shnum = r.u16(is64 ? 60 : 48, "e_shnum");
    uint64_t shstrndx = r.u16(is64 ? 62 : 50, "e_shstrndx");

    const auto mi = machineInfo(machine);
    info.arch = mi.arch;
    info.archName = mi.name;
    info.fileType = typeName(type);
    if (entry != 0) info.entryPoint = entry;
    info.addMeta("e_machine", std::to_string(machine));
    info.addMeta("OS/ABI", std::to_string(data[7]));

    // ---- program headers (informational: interpreter)
    if (phnum > 0 && phoff != 0) {
        const uint64_t need = uint64_t{phnum} * phentsize;
        if (phentsize < (is64 ? 56u : 32u) || !r.inRange(phoff, need)) {
            info.warnings.push_back("Program header table is invalid or out of bounds; skipped.");
        } else {
            for (uint16_t i = 0; i < phnum; ++i) {
                const uint64_t o = phoff + uint64_t{i} * phentsize;
                if (r.u32(o, "p_type") != 3) continue;  // PT_INTERP
                const uint64_t off = is64 ? r.u64(o + 8, "p_offset") : r.u32(o + 4, "p_offset");
                const uint64_t sz = is64 ? r.u64(o + 32, "p_filesz") : r.u32(o + 16, "p_filesz");
                if (r.inRange(off, std::min<uint64_t>(sz, 1)))
                    info.addMeta("Interpreter", r.cstring(off, static_cast<size_t>(std::min<uint64_t>(sz, lim.maxStringLength))));
            }
        }
    }

    // ---- section headers
    if (shoff == 0) {
        info.sectionsParsed = false;
        const std::string n = "No section header table (stripped or minimal file); section-based data is unavailable.";
        info.imports.note = info.exports.note = info.libraries.note = info.symbols.note = n;
        info.warnings.push_back(n);
        return;
    }
    if (shentsize < (is64 ? 64u : 40u)) throw ParseError("e_shentsize (" + std::to_string(shentsize) + ") smaller than the section header structure");
    auto readShdr = [&](uint64_t idx) {
        const uint64_t o = shoff + idx * shentsize;
        Shdr h;
        h.name = r.u32(o, "sh_name");
        h.type = r.u32(o + 4, "sh_type");
        if (is64) {
            h.flags = r.u64(o + 8, "sh_flags");
            h.addr = r.u64(o + 16, "sh_addr");
            h.offset = r.u64(o + 24, "sh_offset");
            h.size = r.u64(o + 32, "sh_size");
            h.link = r.u32(o + 40, "sh_link");
            h.info = r.u32(o + 44, "sh_info");
            h.entsize = r.u64(o + 56, "sh_entsize");
        } else {
            h.flags = r.u32(o + 8, "sh_flags");
            h.addr = r.u32(o + 12, "sh_addr");
            h.offset = r.u32(o + 16, "sh_offset");
            h.size = r.u32(o + 20, "sh_size");
            h.link = r.u32(o + 24, "sh_link");
            h.info = r.u32(o + 28, "sh_info");
            h.entsize = r.u32(o + 36, "sh_entsize");
        }
        return h;
    };
    r.require(shoff, shentsize, "first section header");
    if (shnum == 0 || shstrndx == 0xFFFF) {  // extended numbering
        const Shdr h0 = readShdr(0);
        if (shnum == 0) shnum = h0.size;
        if (shstrndx == 0xFFFF) shstrndx = h0.link;
    }
    if (shnum == 0) throw ParseError("e_shoff is set but the section count is zero");
    if (shnum > lim.maxSections) throw ParseError("Section count " + std::to_string(shnum) + " exceeds limit");
    if (shnum > (r.size() - std::min(shoff, r.size())) / shentsize)
        throw ParseError("Section header table (offset " + hex(shoff) + ", " + std::to_string(shnum) +
                         " entries) lies outside the file; the file is truncated or corrupt");
    if (shstrndx >= shnum) throw ParseError("e_shstrndx " + std::to_string(shstrndx) + " out of range");

    std::vector<Shdr> hdrs;
    hdrs.reserve(static_cast<size_t>(shnum));
    for (uint64_t i = 0; i < shnum; ++i) hdrs.push_back(readShdr(i));

    const Shdr& shstr = hdrs[static_cast<size_t>(shstrndx)];
    const bool shstrOk = r.inRange(shstr.offset, shstr.size);
    if (!shstrOk) info.warnings.push_back("Section name string table is out of bounds; names unavailable.");
    auto strAt = [&](const Shdr& tab, uint64_t idx) -> std::string {
        if (!r.inRange(tab.offset, tab.size) || idx >= tab.size) return "<invalid>";
        return r.cstring(tab.offset + idx, static_cast<size_t>(std::min<uint64_t>(lim.maxStringLength, tab.size - idx)));
    };

    for (size_t i = 0; i < hdrs.size(); ++i) {
        const Shdr& h = hdrs[i];
        if (i == 0 && h.type == 0) continue;  // SHN_UNDEF null section
        Section s;
        s.name = shstrOk ? strAt(shstr, h.name) : "<unnamed>";
        s.virtualAddress = h.addr;
        s.virtualSize = h.size;
        s.fileOffset = h.offset;
        s.fileSize = h.type == SHT_NOBITS ? 0 : h.size;
        s.flags = static_cast<uint32_t>(h.flags);
        s.readable = h.flags & SHF_ALLOC;
        s.writable = h.flags & SHF_WRITE;
        s.executable = h.flags & SHF_EXEC;
        s.hasFileData = h.type != SHT_NOBITS && h.size != 0 && h.type != 0;
        if (!(h.flags & SHF_ALLOC)) s.note = "not loaded into memory";
        info.sections.push_back(std::move(s));
    }
    info.sectionsParsed = true;

    // ---- symbol tables
    auto readSyms = [&](const Shdr& tab, bool dynamic) {
        if (tab.link >= hdrs.size()) { info.warnings.push_back("Symbol table has invalid sh_link; skipped."); return; }
        const Shdr& str = hdrs[tab.link];
        const uint64_t symSize = is64 ? 24 : 16;
        if (!r.inRange(tab.offset, tab.size)) { info.warnings.push_back("Symbol table lies outside the file; skipped."); return; }
        uint64_t count = tab.size / symSize;
        if (count > lim.maxSymbols) {
            count = lim.maxSymbols;
            info.warnings.push_back("Symbol count capped at " + std::to_string(lim.maxSymbols) + "; list truncated.");
        }
        for (uint64_t i = 1; i < count; ++i) {
            const uint64_t o = tab.offset + i * symSize;
            const uint32_t nameIdx = r.u32(o, "st_name");
            uint8_t infoB;
            uint16_t shndx;
            uint64_t value;
            if (is64) { infoB = r.u8(o + 4); shndx = r.u16(o + 6); value = r.u64(o + 8); }
            else { value = r.u32(o + 4); infoB = r.u8(o + 12); shndx = r.u16(o + 14); }
            const std::string name = strAt(str, nameIdx);
            if (name.empty()) continue;
            Symbol sym;
            sym.name = name;
            sym.type = symType(infoB & 0xF);
            const uint8_t bind = infoB >> 4;
            if (shndx != 0) sym.address = value;
            if (dynamic) {
                if (shndx == 0) info.imports.items.push_back(sym);
                else if (bind == 1 || bind == 2) info.exports.items.push_back(sym);
            } else {
                info.symbols.items.push_back(std::move(sym));
            }
        }
    };

    bool haveDynsym = false, haveSymtab = false;
    for (const Shdr& h : hdrs) {
        try {
            if (h.type == SHT_DYNSYM && !haveDynsym) { haveDynsym = true; readSyms(h, true); }
            else if (h.type == SHT_SYMTAB && !haveSymtab) { haveSymtab = true; readSyms(h, false); }
        } catch (const ParseError& e) {
            info.warnings.push_back(std::string("Symbol table parsing stopped: ") + e.what());
        }
    }
    info.imports.state = info.exports.state = haveDynsym ? Availability::Present : Availability::Absent;
    if (!haveDynsym) info.imports.note = info.exports.note = "No .dynsym section (statically linked or no dynamic symbols).";
    else info.imports.note = "ELF imports are undefined dynamic symbols; the providing library is not resolved.";
    info.symbols.state = haveSymtab ? Availability::Present : Availability::Absent;
    if (!haveSymtab) info.symbols.note = "No .symtab section (binary is stripped).";

    // ---- relocation sections
    info.relocations.state = Availability::Absent;
    info.relocations.note = "No relocation sections were found.";
    const uint64_t relEntSize = is64 ? 16 : 8;
    const uint64_t relaEntSize = is64 ? 24 : 12;
    for (const Shdr& relocSection : hdrs) {
        if (relocSection.type != SHT_REL && relocSection.type != SHT_RELA) continue;
        if (info.relocations.items.size() >= lim.maxSymbols) {
            info.warnings.push_back("ELF relocation count capped; remaining records were not parsed.");
            break;
        }
        info.relocations.state = Availability::Present;
        info.relocations.note.clear();
        const bool withAddend = relocSection.type == SHT_RELA;
        const uint64_t entrySize = withAddend ? relaEntSize : relEntSize;
        if (!r.inRange(relocSection.offset, relocSection.size)) {
            info.relocations.state = Availability::NotParsed;
            info.warnings.push_back("ELF relocation section is outside the file.");
            continue;
        }
        if (relocSection.entsize && relocSection.entsize < entrySize) {
            info.relocations.state = Availability::NotParsed;
            info.warnings.push_back("ELF relocation entry size is smaller than the ABI record.");
            continue;
        }
        const uint64_t stride = relocSection.entsize ? relocSection.entsize : entrySize;
        if (relocSection.size % stride != 0) {
            info.warnings.push_back("ELF relocation section has a partial trailing record.");
        }
        const uint64_t count = relocSection.size / stride;
        if (relocSection.link >= hdrs.size()) {
            info.relocations.state = Availability::NotParsed;
            info.warnings.push_back("ELF relocation section has an invalid symbol-table link.");
            continue;
        }
        const Shdr& symtab = hdrs[relocSection.link];
        if (symtab.type != SHT_SYMTAB && symtab.type != SHT_DYNSYM) {
            info.relocations.state = Availability::NotParsed;
            info.warnings.push_back("ELF relocation section is not linked to a symbol table.");
            continue;
        }
        const uint64_t symbolSize = is64 ? 24 : 16;
        const Shdr* symbolStrings = symtab.link < hdrs.size() && hdrs[symtab.link].type == SHT_STRTAB
                                        ? &hdrs[symtab.link]
                                        : nullptr;
        for (uint64_t i = 0; i < count; ++i) {
            if (info.relocations.items.size() >= lim.maxSymbols) break;
            const uint64_t offset = relocSection.offset + i * stride;
            const uint64_t location = word(offset, "Relocation offset");
            const uint64_t rawInfo = word(offset + (is64 ? 8 : 4), "Relocation info");
            const uint64_t symbolIndex = is64 ? rawInfo >> 32 : rawInfo >> 8;
            const uint32_t relocationType = static_cast<uint32_t>(is64 ? rawInfo & 0xFFFFFFFFu : rawInfo & 0xFFu);
            Relocation relocation;
            relocation.address = location;
            relocation.type = relocationType;
            relocation.typeName = "ELF relocation " + std::to_string(relocationType);
            relocation.source = withAddend ? "ELF SHT_RELA section" : "ELF SHT_REL section";
            if (withAddend) {
                if (is64) relocation.addend = static_cast<int64_t>(r.u64(offset + 16, "Relocation addend"));
                else relocation.addend = static_cast<int32_t>(r.u32(offset + 8, "Relocation addend"));
            }
            if (relocSection.info < hdrs.size()) {
                const Shdr& targetSection = hdrs[relocSection.info];
                if (type == 1) {
                    if (location < targetSection.size && targetSection.offset <= data.size() &&
                        location < data.size() - targetSection.offset)
                        relocation.fileOffset = targetSection.offset + location;
                    if (targetSection.addr <= UINT64_MAX - location)
                        relocation.address = targetSection.addr + location;
                } else {
                    const uint64_t targetAddress = location;
                    for (const auto& section : info.sections) {
                        if (section.hasFileData && targetAddress >= section.virtualAddress &&
                            targetAddress - section.virtualAddress < section.fileSize) {
                            relocation.fileOffset = section.fileOffset + targetAddress - section.virtualAddress;
                            break;
                        }
                    }
                }
            }
            if (symbolIndex > 0 && symbolStrings && symbolSize &&
                symbolIndex < symtab.size / symbolSize &&
                r.inRange(symtab.offset + symbolIndex * symbolSize, symbolSize)) {
                const uint64_t symbolOffset = symtab.offset + symbolIndex * symbolSize;
                const uint32_t nameIndex = r.u32(symbolOffset, "Relocation symbol name");
                relocation.symbolName = strAt(*symbolStrings, nameIndex);
                const uint16_t symbolSection = r.u16(symbolOffset + (is64 ? 6 : 14), "Relocation symbol section");
                const uint64_t symbolValue = is64 ? r.u64(symbolOffset + 8, "Relocation symbol value")
                                                   : r.u32(symbolOffset + 4, "Relocation symbol value");
                if (symbolSection != 0 && type != 1) relocation.targetAddress = symbolValue;
            }
            info.relocations.items.push_back(std::move(relocation));
        }
    }

    // ---- debug information identifiers and companion-file references
    for (size_t sectionIndex = 0; sectionIndex < hdrs.size(); ++sectionIndex) {
        const Shdr& header = hdrs[sectionIndex];
        const std::string name = shstrOk ? strAt(shstr, header.name) : std::string{};
        if (name == ".gnu_debuglink" && r.inRange(header.offset, header.size) && header.size > 4) {
            const std::string path = r.cstring(header.offset, static_cast<size_t>(
                std::min<uint64_t>(header.size, lim.maxStringLength)));
            if (!path.empty()) info.addMeta("GNU debuglink", path);
        } else if (name == ".debug_info" || name == ".zdebug_info" || name == ".debug_line" ||
                   name == ".debug_abbrev") {
            info.addMeta("Embedded debug information", "DWARF sections present; full DWARF decoding is not implemented");
        }
    }
    if (shstrOk) {
        for (const Shdr& header : hdrs) {
            if (header.type != 7 || !r.inRange(header.offset, header.size) || header.size < 12) continue;
            uint64_t noteOffset = header.offset;
            const uint64_t noteEnd = header.offset + header.size;
            while (noteOffset + 12 <= noteEnd) {
                const uint32_t nameSize = r.u32(noteOffset, "ELF note name size");
                const uint32_t descSize = r.u32(noteOffset + 4, "ELF note description size");
                const uint32_t noteType = r.u32(noteOffset + 8, "ELF note type");
                const uint64_t paddedName = (uint64_t{nameSize} + 3) & ~uint64_t{3};
                const uint64_t paddedDesc = (uint64_t{descSize} + 3) & ~uint64_t{3};
                if (paddedName > noteEnd - noteOffset - 12 ||
                    paddedDesc > noteEnd - noteOffset - 12 - paddedName) break;
                const uint64_t nameOffset = noteOffset + 12;
                const uint64_t descOffset = nameOffset + paddedName;
                const std::string noteName = nameSize ? r.cstring(nameOffset, nameSize) : std::string{};
                if (noteType == 3 && noteName == "GNU" && descSize > 0) {
                    info.addMeta("GNU build ID", hexBytes(r.bytes(descOffset, descSize)));
                    break;
                }
                noteOffset = descOffset + paddedDesc;
            }
        }
    }

    // ---- dynamic: DT_NEEDED etc.
    bool haveDynamic = false;
    for (const Shdr& h : hdrs) {
        if (h.type != SHT_DYNAMIC || haveDynamic) continue;
        haveDynamic = true;
        try {
            if (h.link >= hdrs.size()) throw ParseError("invalid sh_link in .dynamic");
            const Shdr& str = hdrs[h.link];
            const uint64_t esz = is64 ? 16 : 8;
            r.require(h.offset, h.size, ".dynamic");
            for (uint64_t i = 0; i < std::min<uint64_t>(h.size / esz, 4096); ++i) {
                const uint64_t o = h.offset + i * esz;
                const uint64_t tag = is64 ? r.u64(o) : r.u32(o);
                const uint64_t val = is64 ? r.u64(o + 8) : r.u32(o + 4);
                if (tag == 0) break;
                if (tag == 1) info.libraries.items.push_back(strAt(str, val));
                else if (tag == 14) info.addMeta("SONAME", strAt(str, val));
                else if (tag == 15) info.addMeta("RPATH", strAt(str, val));
                else if (tag == 29) info.addMeta("RUNPATH", strAt(str, val));
            }
            info.libraries.state = Availability::Present;
        } catch (const ParseError& e) {
            info.warnings.push_back(std::string(".dynamic parsing stopped: ") + e.what());
            info.libraries.state = Availability::NotParsed;
            info.libraries.note = "Partial/failed: see warnings.";
        }
    }
    if (!haveDynamic) {
        info.libraries.state = Availability::Absent;
        info.libraries.note = "No .dynamic section (statically linked or not a dynamically-linked object).";
    }
}

}  // namespace xrl
