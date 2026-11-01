#include <algorithm>

#include "xrl/formats.hpp"

namespace xrl {
namespace {

struct Cpu {
    Arch arch;
    const char* name;
    int bits;
};

Cpu cpuInfo(uint32_t t) {
    switch (t) {
        case 7: return {Arch::X86, "x86 (i386)", 32};
        case 0x01000007: return {Arch::X86_64, "x86-64", 64};
        case 12: return {Arch::Arm, "ARM", 32};
        case 0x0100000C: return {Arch::Arm64, "ARM64", 64};
        case 0x0200000C: return {Arch::Other, "ARM64_32", 32};
        case 18: return {Arch::PowerPC, "PowerPC", 32};
        case 0x01000012: return {Arch::PowerPC, "PowerPC 64", 64};
        default: return {Arch::Other, "Unrecognised cputype", 0};
    }
}

const char* fileTypeName(uint32_t t) {
    switch (t) {
        case 1: return "Relocatable object (MH_OBJECT)";
        case 2: return "Executable (MH_EXECUTE)";
        case 3: return "Fixed VM library (MH_FVMLIB)";
        case 4: return "Core file (MH_CORE)";
        case 5: return "Preloaded executable (MH_PRELOAD)";
        case 6: return "Dynamic library (MH_DYLIB)";
        case 7: return "Dynamic linker (MH_DYLINKER)";
        case 8: return "Bundle (MH_BUNDLE)";
        case 9: return "Dylib stub (MH_DYLIB_STUB)";
        case 10: return "Debug symbols (MH_DSYM)";
        case 11: return "Kernel extension (MH_KEXT_BUNDLE)";
        default: return "Unknown Mach-O file type";
    }
}

constexpr uint32_t LC_SEGMENT = 0x1, LC_SYMTAB = 0x2, LC_LOAD_DYLIB = 0xC, LC_ID_DYLIB = 0xD,
                   LC_LOAD_WEAK_DYLIB = 0x80000018, LC_SEGMENT_64 = 0x19, LC_UUID = 0x1B,
                   LC_CODE_SIGNATURE = 0x1D, LC_REEXPORT_DYLIB = 0x8000001F, LC_LAZY_LOAD_DYLIB = 0x20,
                   LC_ENCRYPTION_INFO = 0x21, LC_ENCRYPTION_INFO_64 = 0x2C,
                   LC_LOAD_UPWARD_DYLIB = 0x80000023, LC_MAIN = 0x80000028;

bool isDylibCmd(uint32_t c) {
    return c == LC_LOAD_DYLIB || c == LC_LOAD_WEAK_DYLIB || c == LC_REEXPORT_DYLIB ||
           c == LC_LAZY_LOAD_DYLIB || c == LC_LOAD_UPWARD_DYLIB;
}

void parseSlice(std::span<const uint8_t> whole, uint64_t sliceOff, uint64_t sliceSize, BinaryInfo& info,
                const Limits& lim) {
    const auto slice = whole.subspan(static_cast<size_t>(sliceOff), static_cast<size_t>(sliceSize));
    if (slice.size() < 28) throw ParseError("Mach-O slice too small for a header");
    // Magic as stored: bytes FE ED FA CE/CF => big-endian file; CE FA ED FE / CF FA ED FE => little-endian.
    const uint32_t beMagic = (uint32_t{slice[0]} << 24) | (uint32_t{slice[1]} << 16) | (uint32_t{slice[2]} << 8) | slice[3];
    bool le, is64;
    switch (beMagic) {
        case 0xFEEDFACE: le = false; is64 = false; break;
        case 0xFEEDFACF: le = false; is64 = true; break;
        case 0xCEFAEDFE: le = true; is64 = false; break;
        case 0xCFFAEDFE: le = true; is64 = true; break;
        default: throw ParseError("Invalid Mach-O magic " + hex(beMagic, 8) + " in slice");
    }
    Reader r(slice, le);
    info.endian = le ? Endian::Little : Endian::Big;
    info.bits = is64 ? 64 : 32;
    const uint64_t hdrSize = is64 ? 32 : 28;
    r.require(0, hdrSize, "Mach-O header");

    const uint32_t cputype = r.u32(4, "cputype");
    const uint32_t cpusub = r.u32(8, "cpusubtype");
    const uint32_t filetype = r.u32(12, "filetype");
    const uint32_t ncmds = r.u32(16, "ncmds");
    const uint32_t sizeofcmds = r.u32(20, "sizeofcmds");
    const uint32_t flags = r.u32(24, "flags");
    const Cpu cpu = cpuInfo(cputype);
    info.arch = cpu.arch;
    info.archName = cpu.name;
    info.fileType = fileTypeName(filetype);
    info.formatName = is64 ? "Mach-O 64-bit" : "Mach-O 32-bit";
    info.addMeta("CPU type", hex(cputype, 8));
    info.addMeta("CPU subtype", hex(cpusub & 0x00FFFFFF, 0));
    info.addMeta("Mach-O flags", hex(flags, 8));

    if (ncmds > lim.maxLoadCommands) throw ParseError("Load command count " + std::to_string(ncmds) + " exceeds limit");
    r.require(hdrSize, sizeofcmds, "load commands");

    uint64_t off = hdrSize;
    const uint64_t cmdsEnd = hdrSize + sizeofcmds;
    std::vector<std::string> dylibs;  // ordinal order
    uint64_t symoff = 0, nsyms = 0, stroff = 0, strsize = 0;
    struct MachRelocations {
        uint32_t offset = 0;
        uint32_t count = 0;
        uint64_t address = 0;
        uint64_t fileOffset = 0;
        uint64_t fileSize = 0;
    };
    std::vector<MachRelocations> relocationTables;
    bool haveSymtab = false;
    std::optional<uint64_t> entryOff;
    bool codeSig = false;

    for (uint32_t i = 0; i < ncmds; ++i) {
        if (off + 8 > cmdsEnd) throw ParseError("Load command " + std::to_string(i) + " begins outside the load-command area");
        const uint32_t cmd = r.u32(off, "cmd");
        const uint32_t cmdsize = r.u32(off + 4, "cmdsize");
        if (cmdsize < 8 || cmdsize > cmdsEnd - off)
            throw ParseError("Load command " + std::to_string(i) + " has invalid cmdsize " + std::to_string(cmdsize));

        if (cmd == LC_SEGMENT || cmd == LC_SEGMENT_64) {
            const bool seg64 = cmd == LC_SEGMENT_64;
            const uint32_t segSize = seg64 ? 72 : 56, secSize = seg64 ? 80 : 68;
            if (cmdsize < segSize) throw ParseError("Segment command too small");
            const std::string segname = r.fixedString(off + 8, 16);
            const uint64_t vmaddr = seg64 ? r.u64(off + 24) : r.u32(off + 24);
            const uint64_t vmsize = seg64 ? r.u64(off + 32) : r.u32(off + 28);
            const uint64_t fileoff = seg64 ? r.u64(off + 40) : r.u32(off + 32);
            const uint64_t filesize = seg64 ? r.u64(off + 48) : r.u32(off + 36);
            const uint32_t maxprot = r.u32(off + (seg64 ? 56 : 40));
            const uint32_t initprot = r.u32(off + (seg64 ? 60 : 44));
            const uint32_t nsects = r.u32(off + (seg64 ? 64 : 48));
            (void)maxprot;
            if (info.sections.size() + nsects + 1 > lim.maxSections) throw ParseError("Section count exceeds limit");

            Section seg;
            seg.kind = "segment";
            seg.name = segname;
            seg.segment = segname;
            seg.virtualAddress = vmaddr;
            seg.virtualSize = vmsize;
            seg.fileOffset = sliceOff + fileoff;
            seg.fileSize = filesize;
            seg.flags = initprot;
            seg.readable = initprot & 1;
            seg.writable = initprot & 2;
            seg.executable = initprot & 4;
            seg.hasFileData = false;  // segments are listed for permissions; address translation uses sections
            if (filesize > sliceSize || fileoff > sliceSize - std::min(filesize, sliceSize)) seg.boundsValid = false;
            info.sections.push_back(seg);

            if (uint64_t{nsects} * secSize > cmdsize - segSize) throw ParseError("Segment declares more sections than its command can hold");
            for (uint32_t s = 0; s < nsects; ++s) {
                const uint64_t o = off + segSize + uint64_t{s} * secSize;
                Section sec;
                sec.name = r.fixedString(o, 16);
                sec.segment = r.fixedString(o + 16, 16);
                uint32_t secOff, secFlags;
                uint32_t relocOff, relocCount;
                if (seg64) {
                    sec.virtualAddress = r.u64(o + 32);
                    sec.virtualSize = r.u64(o + 40);
                    secOff = r.u32(o + 48);
                    relocOff = r.u32(o + 56);
                    relocCount = r.u32(o + 60);
                    secFlags = r.u32(o + 64);
                } else {
                    sec.virtualAddress = r.u32(o + 32);
                    sec.virtualSize = r.u32(o + 36);
                    secOff = r.u32(o + 40);
                    relocOff = r.u32(o + 48);
                    relocCount = r.u32(o + 52);
                    secFlags = r.u32(o + 56);
                }
                const uint32_t stype = secFlags & 0xFF;
                const bool zerofill = stype == 0x1 || stype == 0xC || stype == 0x12;
                sec.flags = secFlags;
                sec.readable = initprot & 1;
                sec.writable = initprot & 2;
                sec.executable = initprot & 4;
                sec.fileOffset = sliceOff + secOff;
                sec.fileSize = zerofill ? 0 : sec.virtualSize;
                sec.hasFileData = !zerofill && sec.virtualSize != 0 && secOff != 0;
                if (zerofill) sec.note = "zero-fill (no file data)";
                if (sec.hasFileData && (sec.fileSize > sliceSize || secOff > sliceSize - sec.fileSize))
                    sec.boundsValid = false;
                if (relocCount)
                    relocationTables.push_back({relocOff, relocCount, sec.virtualAddress,
                                                sliceOff + secOff, sec.fileSize});
                info.sections.push_back(std::move(sec));
            }
        } else if (isDylibCmd(cmd)) {
            if (cmdsize < 24) throw ParseError("Dylib command too small");
            const uint32_t nameOff = r.u32(off + 8, "dylib name offset");
            if (nameOff >= cmdsize) throw ParseError("Dylib name offset out of command bounds");
            dylibs.push_back(r.cstring(off + nameOff, std::min<size_t>(lim.maxStringLength, cmdsize - nameOff)));
        } else if (cmd == LC_ID_DYLIB && cmdsize >= 24) {
            const uint32_t nameOff = r.u32(off + 8);
            if (nameOff < cmdsize) info.addMeta("Install name", r.cstring(off + nameOff, std::min<size_t>(lim.maxStringLength, cmdsize - nameOff)));
        } else if (cmd == LC_SYMTAB) {
            if (cmdsize < 24) throw ParseError("LC_SYMTAB too small");
            symoff = r.u32(off + 8); nsyms = r.u32(off + 12);
            stroff = r.u32(off + 16); strsize = r.u32(off + 20);
            haveSymtab = true;
        } else if (cmd == LC_MAIN && cmdsize >= 16) {
            entryOff = r.u64(off + 8);
        } else if (cmd == LC_UUID && cmdsize >= 24) {
            info.addMeta("UUID", hexBytes(r.bytes(off + 8, 16)));
        } else if (cmd == LC_CODE_SIGNATURE) {
            codeSig = true;
        } else if ((cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) && cmdsize >= 20) {
            if (r.u32(off + 16) != 0)
                info.warnings.push_back("LC_ENCRYPTION_INFO reports an encrypted segment; code bytes are not meaningful until decrypted.");
        }
        off += cmdsize;
    }
    info.sectionsParsed = true;
    info.addMeta("Code signature", codeSig ? "load command present (signature not verified)" : "no LC_CODE_SIGNATURE");

    info.libraries.items = dylibs;
    info.libraries.state = Availability::Present;
    if (dylibs.empty()) { info.libraries.state = Availability::Absent; info.libraries.note = "No dylib load commands."; }

    if (entryOff && *entryOff < sliceSize) {
        if (auto va = info.fileOffsetToVirtual(sliceOff + *entryOff)) info.entryPoint = *va;
    }

    // ---- symbol table
    if (!haveSymtab) {
        info.symbols.state = info.imports.state = info.exports.state = Availability::Absent;
        info.symbols.note = info.imports.note = info.exports.note = "No LC_SYMTAB load command.";
    }
    std::vector<std::string> nlistNames;
    std::vector<std::optional<uint64_t>> nlistAddresses;
    if (haveSymtab) {
        info.symbols.state = info.imports.state = info.exports.state = Availability::Present;
        info.imports.note = "Imports are undefined external symbols from LC_SYMTAB. Binaries using only chained fixups without symbol entries would not list them.";
        const uint64_t entSize = is64 ? 16 : 12;
        r.require(symoff, nsyms * entSize > UINT64_MAX / 2 ? UINT64_MAX : nsyms * entSize, "symbol table");
        r.require(stroff, strsize, "string table");
        uint64_t count = nsyms;
        if (count > lim.maxSymbols) {
            count = lim.maxSymbols;
            info.warnings.push_back("Symbol count capped at " + std::to_string(lim.maxSymbols) + "; list truncated.");
        }
        nlistNames.resize(static_cast<size_t>(count));
        nlistAddresses.resize(static_cast<size_t>(count));
        for (uint64_t i = 0; i < count; ++i) {
            const uint64_t o = symoff + i * entSize;
            const uint32_t strx = r.u32(o);
            const uint8_t ntype = r.u8(o + 4);
            const uint16_t ndesc = r.u16(o + 6);
            const uint64_t value = is64 ? r.u64(o + 8) : r.u32(o + 8);
            if (ntype & 0xE0) continue;  // N_STAB debug entries
            if (strx == 0 || strx >= strsize) continue;
            Symbol sym;
            sym.name = r.cstring(stroff + strx, static_cast<size_t>(std::min<uint64_t>(lim.maxStringLength, strsize - strx)));
            if (sym.name.empty()) continue;
            nlistNames[static_cast<size_t>(i)] = sym.name;
            const uint8_t t = ntype & 0x0E;
            const bool ext = ntype & 0x01;
            if (t == 0x0E) {
                sym.address = value;
                nlistAddresses[static_cast<size_t>(i)] = value;
                sym.type = "defined";
            }
            else if (t == 0x00) sym.type = value ? "common" : "undefined";
            else if (t == 0x0A) sym.type = "indirect";
            else sym.type = "other";
            if (ext && t == 0 && value == 0) {
                const uint32_t ord = (ndesc >> 8) & 0xFF;
                Symbol imp = sym;
                if (ord >= 1 && ord <= dylibs.size()) { imp.library = dylibs[ord - 1]; imp.ordinal = ord; }
                else if (ord == 0xFE) imp.library = "(flat/dynamic lookup)";
                info.imports.items.push_back(std::move(imp));
            } else if (ext && t == 0x0E && !(ntype & 0x10)) {
                info.exports.items.push_back(sym);
            }
            info.symbols.items.push_back(std::move(sym));
        }
    }
    info.relocations.state = relocationTables.empty() ? Availability::Absent : Availability::Present;
    info.relocations.note = relocationTables.empty() ? "No section relocation records were found." : "";
    size_t relocationCount = 0;
    for (const auto& table : relocationTables) {
        if (table.count > lim.maxSymbols - std::min(lim.maxSymbols, relocationCount)) {
            info.warnings.push_back("Mach-O relocation count capped; remaining records were not parsed.");
        }
        const uint32_t count = static_cast<uint32_t>(
            std::min<size_t>(table.count, lim.maxSymbols - std::min(lim.maxSymbols, relocationCount)));
        if (!r.inRange(table.offset, uint64_t{count} * 8)) {
            info.relocations.state = Availability::NotParsed;
            info.warnings.push_back("Mach-O relocation table is outside the slice; skipped.");
            continue;
        }
        for (uint32_t i = 0; i < count; ++i) {
            const uint64_t entry = uint64_t{table.offset} + uint64_t{i} * 8;
            const int32_t relative = static_cast<int32_t>(r.u32(entry, "Relocation address"));
            const uint32_t rawInfo = r.u32(entry + 4, "Relocation info");
            if (relative < 0) continue;
            const uint64_t rel = static_cast<uint32_t>(relative);
            if (table.address > UINT64_MAX - rel) {
                info.warnings.push_back("A Mach-O relocation address overflows the virtual address range.");
                continue;
            }
            Relocation relocation;
            relocation.address = table.address + rel;
            if (rel < table.fileSize && table.fileOffset <= whole.size() &&
                rel < whole.size() - table.fileOffset)
                relocation.fileOffset = table.fileOffset + rel;
            relocation.type = rawInfo >> 28;
            relocation.typeName = "Mach-O relocation " + std::to_string(relocation.type);
            relocation.source = "Mach-O section relocation";
            const bool external = ((rawInfo >> 27) & 1u) != 0;
            const uint32_t symbolIndex = rawInfo & 0x00FFFFFFu;
            if (external && symbolIndex < nlistNames.size()) {
                relocation.symbolName = nlistNames[symbolIndex];
                if (symbolIndex < nlistAddresses.size())
                    relocation.targetAddress = nlistAddresses[symbolIndex];
            }
            info.relocations.items.push_back(std::move(relocation));
            ++relocationCount;
        }
    }
}

}  // namespace

void parseMachO(std::span<const uint8_t> data, BinaryInfo& info, const Limits& lim) {
    info.format = Format::MachO;
    info.formatName = "Mach-O";
    if (data.size() < 8) throw ParseError("File too small for a Mach-O header");
    const uint32_t beMagic = (uint32_t{data[0]} << 24) | (uint32_t{data[1]} << 16) | (uint32_t{data[2]} << 8) | data[3];

    if (beMagic != 0xCAFEBABE && beMagic != 0xCAFEBABF) {
        parseSlice(data, 0, data.size(), info, lim);
        return;
    }

    // Universal ("fat") binary. Headers are always big-endian.
    const bool fat64 = beMagic == 0xCAFEBABF;
    Reader r(data, false);
    const uint32_t narch = r.u32(4, "nfat_arch");
    if (narch == 0 || narch > 32)
        throw ParseError("0xCAFEBABE header with implausible architecture count " + std::to_string(narch) +
                         " (this may be a Java class file, not a universal Mach-O)");
    const uint64_t entSize = fat64 ? 32 : 20;
    r.require(8, uint64_t{narch} * entSize, "fat_arch table");

    struct Slice { uint32_t cpu; uint64_t off, size; };
    std::vector<Slice> slices;
    std::string archList;
    for (uint32_t i = 0; i < narch; ++i) {
        const uint64_t o = 8 + uint64_t{i} * entSize;
        Slice s{r.u32(o), fat64 ? r.u64(o + 8) : r.u32(o + 8), fat64 ? r.u64(o + 16) : r.u32(o + 12)};
        archList += (archList.empty() ? "" : ", ") + std::string(cpuInfo(s.cpu).name);
        if (!r.inRange(s.off, s.size)) {
            info.warnings.push_back("Universal binary slice " + std::to_string(i) + " (" + cpuInfo(s.cpu).name +
                                    ") lies outside the file; skipped.");
            continue;
        }
        slices.push_back(s);
    }
    info.addMeta("Universal binary slices", archList);
    if (slices.empty()) throw ParseError("No universal-binary slice lies within the file");
    info.addMeta("Analysed slice", std::string(cpuInfo(slices[0].cpu).name) + " at offset " + hex(slices[0].off) +
                                       (narch > 1 ? " (first slice; other slices are not analysed)" : ""));
    parseSlice(data, slices[0].off, slices[0].size, info, lim);
}

}  // namespace xrl
