#include <algorithm>
#include <unordered_set>

#include "xrl/formats.hpp"

namespace xrl {
namespace {

constexpr uint32_t kScnExec = 0x20000000, kScnRead = 0x40000000, kScnWrite = 0x80000000;

struct MachineInfo {
    Arch arch;
    const char* name;
    bool thumb;
};

MachineInfo machineInfo(uint16_t m, bool is64) {
    switch (m) {
        case 0x14c: return {Arch::X86, "x86 (i386)", false};
        case 0x8664: return {Arch::X86_64, "x86-64 (AMD64)", false};
        case 0x1c0: return {Arch::Arm, "ARM", false};
        case 0x1c4: return {Arch::Arm, "ARM Thumb-2 (ARMNT)", true};
        case 0xaa64: return {Arch::Arm64, "ARM64", false};
        case 0x166: case 0x266: case 0x366: case 0x466: return {Arch::Mips, "MIPS", false};
        case 0x1f0: case 0x1f1: return {Arch::PowerPC, "PowerPC", false};
        case 0x5032: return {Arch::RiscV, "RISC-V 32", false};
        case 0x5064: return {Arch::RiscV, "RISC-V 64", false};
        case 0x200: return {Arch::Other, "Intel Itanium (IA-64)", false};
        default: (void)is64; return {Arch::Other, "Unrecognised machine", false};
    }
}

std::string subsystemName(uint16_t s) {
    switch (s) {
        case 1: return "Native";
        case 2: return "Windows GUI";
        case 3: return "Windows console";
        case 5: return "OS/2 console";
        case 7: return "POSIX console";
        case 9: return "Windows CE";
        case 10: return "EFI application";
        case 11: return "EFI boot service driver";
        case 12: return "EFI runtime driver";
        case 14: return "Xbox";
        case 16: return "Windows boot application";
        default: return "Unknown (" + std::to_string(s) + ")";
    }
}

}  // namespace

void parsePE(std::span<const uint8_t> data, BinaryInfo& info, const Limits& lim) {
    Reader r(data, true);
    info.format = Format::PE;
    info.formatName = "PE (Portable Executable)";
    info.endian = Endian::Little;

    if (data.size() < 64) throw ParseError("File is too small to contain a DOS header (64 bytes)");
    const uint32_t lfanew = r.u32(0x3C, "e_lfanew");
    if (!r.inRange(lfanew, 4) || r.u32(lfanew, "PE signature") != 0x00004550) {
        info.fileType = "DOS/legacy executable (no PE signature)";
        throw ParseError("'MZ' header found but no valid 'PE\\0\\0' signature at e_lfanew " + hex(lfanew) +
                         ". The file is truncated or a legacy (DOS/NE/LE) executable, which is not supported.");
    }
    const uint64_t coff = uint64_t{lfanew} + 4;
    const uint16_t machine = r.u16(coff, "COFF machine");
    const uint16_t nsec = r.u16(coff + 2, "NumberOfSections");
    const uint32_t timestamp = r.u32(coff + 4, "TimeDateStamp");
    const uint32_t symPtr = r.u32(coff + 8, "PointerToSymbolTable");
    const uint32_t symCount = r.u32(coff + 12, "NumberOfSymbols");
    const uint16_t optSize = r.u16(coff + 16, "SizeOfOptionalHeader");
    const uint16_t chars = r.u16(coff + 18, "Characteristics");
    const uint64_t opt = coff + 20;

    info.addMeta("Machine", hex(machine, 4));
    info.addMeta("Timestamp (header, unverified)", std::to_string(timestamp));
    info.addMeta("COFF characteristics", hex(chars, 4));

    if (optSize < 2) throw ParseError("Missing optional header; not a loadable PE image");
    const uint16_t magic = r.u16(opt, "optional header magic");
    bool is64;
    if (magic == 0x10B) is64 = false;
    else if (magic == 0x20B) is64 = true;
    else throw ParseError("Unsupported optional header magic " + hex(magic, 4) + " (expected 0x10b or 0x20b)");

    const auto mi = machineInfo(machine, is64);
    info.arch = mi.arch;
    info.archName = mi.name;
    info.armThumb = mi.thumb;
    info.bits = is64 ? 64 : 32;
    info.fileType = (chars & 0x2000) ? "Dynamic-link library" : (chars & 0x0002) ? "Executable image" : "PE image";
    info.addMeta("PE format", is64 ? "PE32+" : "PE32");

    const uint64_t minOpt = is64 ? 112 : 96;
    if (optSize < minOpt) throw ParseError("SizeOfOptionalHeader (" + std::to_string(optSize) + ") too small for a " +
                                           (is64 ? "PE32+" : "PE32") + " header");
    const uint32_t entryRva = r.u32(opt + 16, "AddressOfEntryPoint");
    const uint64_t imageBase = is64 ? r.u64(opt + 24, "ImageBase") : r.u32(opt + 28, "ImageBase");
    const uint32_t headersSize = r.u32(opt + 60, "SizeOfHeaders");
    const uint16_t subsystem = r.u16(opt + 68, "Subsystem");
    const uint32_t nDirs = r.u32(opt + (is64 ? 108 : 92), "NumberOfRvaAndSizes");
    info.addMeta("Image base", hex(imageBase));
    info.addMeta("Subsystem", subsystemName(subsystem));
    info.addMeta("Entry point RVA", hex(entryRva));
    if (entryRva != 0) info.entryPoint = imageBase + entryRva;

    const uint64_t dirBase = opt + minOpt;
    auto dirEntry = [&](uint32_t idx) -> std::pair<uint32_t, uint32_t> {
        if (idx >= nDirs || uint64_t{idx} * 8 + 8 > optSize - minOpt) return {0, 0};
        return {r.u32(dirBase + idx * 8, "data directory"), r.u32(dirBase + idx * 8 + 4, "data directory")};
    };

    // ---- sections
    if (nsec > lim.maxSections) throw ParseError("NumberOfSections (" + std::to_string(nsec) + ") exceeds limit");
    const uint64_t secTable = opt + optSize;
    r.require(secTable, uint64_t{nsec} * 40, "section table");
    struct CoffRelocations { uint32_t offset = 0; uint16_t count = 0; };
    std::vector<CoffRelocations> coffRelocations;
    coffRelocations.reserve(nsec);
    for (uint16_t i = 0; i < nsec; ++i) {
        const uint64_t o = secTable + uint64_t{i} * 40;
        Section s;
        s.name = r.fixedString(o, 8);
        s.virtualSize = r.u32(o + 8, "VirtualSize");
        s.virtualAddress = r.u32(o + 12, "VirtualAddress");
        s.fileSize = r.u32(o + 16, "SizeOfRawData");
        s.fileOffset = r.u32(o + 20, "PointerToRawData");
        s.flags = r.u32(o + 36, "Characteristics");
        s.readable = s.flags & kScnRead;
        s.writable = s.flags & kScnWrite;
        s.executable = s.flags & kScnExec;
        s.hasFileData = s.fileSize != 0 && s.fileOffset != 0;
        if (s.fileSize != 0 && s.fileOffset == 0) s.note = "raw size set but raw pointer is 0";
        coffRelocations.push_back({r.u32(o + 24, "PointerToRelocations"),
                                   r.u16(o + 32, "NumberOfRelocations")});
        info.sections.push_back(std::move(s));
    }
    info.sectionsParsed = true;

    auto rvaToOff = [&](uint64_t rva) -> std::optional<uint64_t> {
        if (rva < headersSize) return rva;
        for (const auto& s : info.sections) {
            if (!s.hasFileData) continue;
            const uint64_t extent = std::max<uint64_t>(s.virtualSize, s.fileSize);
            if (rva >= s.virtualAddress && rva - s.virtualAddress < extent && rva - s.virtualAddress < s.fileSize)
                return s.fileOffset + (rva - s.virtualAddress);
        }
        return std::nullopt;
    };

    // ---- COFF symbols
    std::vector<Symbol> coffSymbols;
    if (symPtr == 0 && symCount == 0) {
        info.symbols.state = Availability::Absent;
        info.symbols.note = "No COFF symbol table (typical for release builds; debug info may live in a separate PDB).";
    } else {
        info.symbols.state = Availability::Present;
        const uint64_t tableSize = uint64_t{symCount} * 18;
        try {
            r.require(symPtr, tableSize, "COFF symbol table");
            const uint64_t stringTable = uint64_t{symPtr} + tableSize;
            const uint32_t stringTableSize = r.u32(stringTable, "COFF string table size");
            if (stringTableSize < 4) throw ParseError("Invalid COFF string table size");
            r.require(stringTable, stringTableSize, "COFF string table");
            coffSymbols.resize(symCount);
            uint32_t index = 0;
            while (index < symCount && info.symbols.items.size() < lim.maxSymbols) {
                const uint64_t offset = uint64_t{symPtr} + uint64_t{index} * 18;
                const uint32_t nameZero = r.u32(offset, "COFF symbol name");
                const uint32_t nameOffset = r.u32(offset + 4, "COFF long symbol name");
                Symbol symbol;
                if (nameZero == 0) {
                    if (nameOffset < 4 || nameOffset >= stringTableSize)
                        throw ParseError("COFF symbol name offset is out of range");
                    symbol.name = r.cstring(stringTable + nameOffset,
                                            std::min<size_t>(lim.maxStringLength, stringTableSize - nameOffset));
                } else {
                    symbol.name = r.fixedString(offset, 8);
                }
                const uint32_t value = r.u32(offset + 8, "COFF symbol value");
                const int16_t sectionNumber = static_cast<int16_t>(r.u16(offset + 12, "COFF section number"));
                const uint16_t type = r.u16(offset + 14, "COFF symbol type");
                const uint8_t auxCount = r.u8(offset + 17, "COFF auxiliary count");
                symbol.type = (type & 0x20) ? "func" : "object";
                if (sectionNumber > 0 && static_cast<size_t>(sectionNumber) <= info.sections.size()) {
                    const auto& section = info.sections[static_cast<size_t>(sectionNumber - 1)];
                    if (value <= std::max(section.virtualSize, section.fileSize))
                        symbol.address = imageBase + section.virtualAddress + value;
                }
                coffSymbols[index] = symbol;
                if (!symbol.name.empty()) info.symbols.items.push_back(std::move(symbol));
                if (auxCount > symCount - index - 1) throw ParseError("COFF auxiliary symbol count exceeds the table");
                index += 1 + auxCount;
            }
            if (index < symCount)
                info.warnings.push_back("COFF symbol count capped; symbol list truncated.");
        } catch (const ParseError& e) {
            info.symbols.state = Availability::NotParsed;
            info.symbols.note = "COFF symbol table could not be fully parsed.";
            info.warnings.push_back(std::string("COFF symbol parsing stopped: ") + e.what());
            coffSymbols.clear();
        }
    }
    info.relocations.state = Availability::Absent;
    info.relocations.note = "No relocation records were found.";
    for (size_t sectionIndex = 0; sectionIndex < coffRelocations.size(); ++sectionIndex) {
        const auto [relocOffset, relocCount] = coffRelocations[sectionIndex];
        if (relocCount == 0) continue;
        if (relocOffset == 0 || !r.inRange(relocOffset, uint64_t{relocCount} * 10)) {
            info.warnings.push_back("A COFF section relocation table is invalid or out of bounds.");
            info.relocations.state = Availability::NotParsed;
            continue;
        }
        info.relocations.state = Availability::Present;
        const auto& section = info.sections[sectionIndex];
        for (uint16_t i = 0; i < relocCount; ++i) {
            const uint64_t entry = uint64_t{relocOffset} + uint64_t{i} * 10;
            const uint32_t relative = r.u32(entry, "COFF relocation address");
            const uint32_t symbolIndex = r.u32(entry + 4, "COFF relocation symbol index");
            Relocation relocation;
            if (imageBase > UINT64_MAX - section.virtualAddress ||
                imageBase + section.virtualAddress > UINT64_MAX - relative) {
                info.warnings.push_back("A COFF relocation address overflows the virtual address range.");
                continue;
            }
            relocation.address = imageBase + section.virtualAddress + relative;
            if (relative < section.fileSize && section.fileOffset <= data.size() &&
                relative < data.size() - section.fileOffset)
                relocation.fileOffset = section.fileOffset + relative;
            relocation.type = r.u16(entry + 8, "COFF relocation type");
            relocation.typeName = "COFF relocation " + hex(relocation.type, 4);
            relocation.source = "COFF section relocation";
            if (symbolIndex < coffSymbols.size()) {
                relocation.symbolName = coffSymbols[symbolIndex].name;
                relocation.targetAddress = coffSymbols[symbolIndex].address;
            }
            info.relocations.items.push_back(std::move(relocation));
        }
    }

    // ---- imports
    auto [impRva, impSize] = dirEntry(1);
    auto [delayRva, delaySize] = dirEntry(13);
    if (impRva == 0 || impSize == 0) {
        info.imports.state = Availability::Absent;
        info.libraries.state = Availability::Absent;
        info.imports.note = info.libraries.note = "No import directory in the data directory table.";
    } else {
        info.imports.state = info.libraries.state = Availability::Present;
        try {
            uint64_t desc = 0;
            for (size_t n = 0;; ++n) {
                if (n >= lim.maxImportDlls) { info.warnings.push_back("Import descriptor limit reached; list truncated."); break; }
                const auto off = rvaToOff(uint64_t{impRva} + n * 20);
                if (!off) throw ParseError("Import directory RVA " + hex(impRva) + " does not map to file data");
                desc = *off;
                const uint32_t oft = r.u32(desc, "OriginalFirstThunk");
                const uint32_t nameRva = r.u32(desc + 12, "import Name");
                const uint32_t ft = r.u32(desc + 16, "FirstThunk");
                if (oft == 0 && nameRva == 0 && ft == 0) break;
                const auto nameOff = rvaToOff(nameRva);
                if (!nameOff) throw ParseError("Import DLL name RVA " + hex(nameRva) + " is unmapped");
                const std::string dll = r.cstring(*nameOff, lim.maxStringLength);
                info.libraries.items.push_back(dll);
                const uint32_t thunkRva = oft ? oft : ft;
                const size_t step = is64 ? 8 : 4;
                for (size_t t = 0; t < 65536; ++t) {
                    const auto tOff = rvaToOff(uint64_t{thunkRva} + t * step);
                    if (!tOff) { info.warnings.push_back("Import thunk table of " + dll + " leaves mapped data"); break; }
                    const uint64_t entry = is64 ? r.u64(*tOff, "thunk") : r.u32(*tOff, "thunk");
                    if (entry == 0) break;
                    if (info.imports.items.size() >= lim.maxSymbols) break;
                    Symbol sym;
                    sym.library = dll;
                    sym.type = "func";
                    const uint64_t ordFlag = is64 ? (1ull << 63) : (1ull << 31);
                    if (entry & ordFlag) {
                        sym.ordinal = static_cast<uint32_t>(entry & 0xFFFF);
                        sym.name = "#" + std::to_string(*sym.ordinal);
                    } else {
                        const auto hn = rvaToOff(entry & 0x7FFFFFFF);
                        if (!hn) { info.warnings.push_back("Import-by-name RVA " + hex(entry) + " unmapped"); continue; }
                        sym.name = r.cstring(*hn + 2, lim.maxStringLength);
                    }
                    info.imports.items.push_back(std::move(sym));
                }
            }
        } catch (const ParseError& e) {
            info.warnings.push_back(std::string("Import table parsing stopped early: ") + e.what());
            info.imports.note = info.libraries.note = "Partial: parsing stopped early (see warnings).";
        }
    }
    if (delayRva != 0 && delaySize != 0) {
        const std::string n = "A delay-load import directory exists but delay-load imports are not parsed.";
        info.imports.note += (info.imports.note.empty() ? "" : " ") + n;
        info.libraries.note += (info.libraries.note.empty() ? "" : " ") + n;
        if (info.imports.state == Availability::Absent) info.imports.state = Availability::NotParsed;
        if (info.libraries.state == Availability::Absent) info.libraries.state = Availability::NotParsed;
    }

    // ---- exports
    auto [expRva, expSize] = dirEntry(0);
    if (expRva == 0 || expSize == 0) {
        info.exports.state = Availability::Absent;
        info.exports.note = "No export directory in the data directory table.";
    } else {
        info.exports.state = Availability::Present;
        try {
            const auto eo = rvaToOff(expRva);
            if (!eo) throw ParseError("Export directory RVA " + hex(expRva) + " unmapped");
            const uint32_t nameRva = r.u32(*eo + 12, "export DLL name");
            const uint32_t base = r.u32(*eo + 16, "export Base");
            const uint32_t nFuncs = r.u32(*eo + 20, "NumberOfFunctions");
            const uint32_t nNames = r.u32(*eo + 24, "NumberOfNames");
            const uint32_t funcsRva = r.u32(*eo + 28, "AddressOfFunctions");
            const uint32_t namesRva = r.u32(*eo + 32, "AddressOfNames");
            const uint32_t ordsRva = r.u32(*eo + 36, "AddressOfNameOrdinals");
            if (nFuncs > 65536 || nNames > 65536) throw ParseError("Export counts exceed sanity limit (65536)");
            if (const auto no = rvaToOff(nameRva)) info.addMeta("Export module name", r.cstring(*no, lim.maxStringLength));

            auto funcRva = [&](uint32_t idx) -> uint32_t {
                const auto o = rvaToOff(uint64_t{funcsRva} + uint64_t{idx} * 4);
                if (!o) throw ParseError("Export address table unmapped");
                return r.u32(*o, "export function RVA");
            };
            auto makeSym = [&](std::string name, uint32_t idx) {
                Symbol s;
                s.name = std::move(name);
                s.ordinal = base + idx;
                const uint32_t frva = funcRva(idx);
                const bool fwd = frva >= expRva && frva - expRva < expSize;
                s.type = fwd ? "forwarder" : "func/data";
                if (fwd) {
                    if (const auto fo = rvaToOff(frva)) s.library = "-> " + r.cstring(*fo, lim.maxStringLength);
                } else {
                    s.address = imageBase + frva;
                }
                return s;
            };
            std::unordered_set<uint32_t> named;
            for (uint32_t i = 0; i < nNames && info.exports.items.size() < lim.maxSymbols; ++i) {
                const auto no = rvaToOff(uint64_t{namesRva} + uint64_t{i} * 4);
                const auto oo = rvaToOff(uint64_t{ordsRva} + uint64_t{i} * 2);
                if (!no || !oo) throw ParseError("Export name tables unmapped");
                const uint32_t ordIdx = r.u16(*oo, "export ordinal");
                if (ordIdx >= nFuncs) { info.warnings.push_back("Export ordinal index out of range; entry skipped"); continue; }
                const auto so = rvaToOff(r.u32(*no, "export name RVA"));
                if (!so) { info.warnings.push_back("Export name RVA unmapped; entry skipped"); continue; }
                named.insert(ordIdx);
                info.exports.items.push_back(makeSym(r.cstring(*so, lim.maxStringLength), ordIdx));
            }
            for (uint32_t i = 0; i < nFuncs && info.exports.items.size() < lim.maxSymbols; ++i) {
                if (named.count(i) || funcRva(i) == 0) continue;
                info.exports.items.push_back(makeSym("#" + std::to_string(base + i), i));
            }
        } catch (const ParseError& e) {
            info.warnings.push_back(std::string("Export table parsing stopped early: ") + e.what());
            info.exports.note = "Partial: parsing stopped early (see warnings).";
        }
    }

    // ---- image base relocations
    const auto [relocRva, relocSize] = dirEntry(5);
    if (relocRva != 0 && relocSize != 0) {
        const auto start = rvaToOff(relocRva);
        if (!start) {
            info.relocations.state = Availability::NotParsed;
            info.relocations.note = "Base relocation directory is unmapped.";
            info.warnings.push_back("PE base relocation directory is unmapped.");
        } else {
            info.relocations.state = Availability::Present;
            info.relocations.note.clear();
            uint64_t cursor = 0;
            while (cursor < relocSize) {
                if (!r.inRange(*start + cursor, 8)) {
                    info.relocations.state = Availability::NotParsed;
                    info.warnings.push_back("PE base relocation block header is truncated.");
                    break;
                }
                const uint32_t pageRva = r.u32(*start + cursor, "Relocation page RVA");
                const uint32_t blockSize = r.u32(*start + cursor + 4, "Relocation block size");
                if (blockSize < 8 || blockSize > relocSize - cursor || (blockSize & 1u) != 0) {
                    info.relocations.state = Availability::NotParsed;
                    info.warnings.push_back("PE base relocation block has an invalid size.");
                    break;
                }
                const uint32_t entryCount = (blockSize - 8) / 2;
                for (uint32_t i = 0; i < entryCount; ++i) {
                    if (info.relocations.items.size() >= lim.maxSymbols) {
                        info.warnings.push_back("PE relocation count capped; remaining records were not parsed.");
                        break;
                    }
                    const uint16_t item = r.u16(*start + cursor + 8 + uint64_t{i} * 2, "Relocation entry");
                    const uint32_t type = item >> 12;
                    if (type == 0) continue;
                    const uint64_t targetRva = uint64_t{pageRva} + (item & 0x0FFF);
                    if (targetRva > UINT32_MAX) continue;
                    if (imageBase > UINT64_MAX - targetRva) {
                        info.warnings.push_back("A PE base relocation address overflows the virtual address range.");
                        continue;
                    }
                    Relocation relocation;
                    relocation.address = imageBase + targetRva;
                    relocation.fileOffset = rvaToOff(targetRva);
                    relocation.type = type;
                    switch (type) {
                        case 1: relocation.typeName = "HIGH"; break;
                        case 2: relocation.typeName = "LOW"; break;
                        case 3: relocation.typeName = "HIGHLOW"; break;
                        case 4: relocation.typeName = "HIGHADJ"; break;
                        case 10: relocation.typeName = "DIR64"; break;
                        default: relocation.typeName = "PE base relocation " + std::to_string(type); break;
                    }
                    relocation.source = "PE base relocation directory";
                    info.relocations.items.push_back(std::move(relocation));
                }
                cursor += blockSize;
                if (info.relocations.items.size() >= lim.maxSymbols) break;
            }
        }
    }

    // ---- CodeView/PDB identity in the PE debug directory
    const auto [debugRva, debugSize] = dirEntry(6);
    if (debugRva != 0 && debugSize >= 28) {
        try {
            const auto directoryOffset = rvaToOff(debugRva);
            if (!directoryOffset) throw ParseError("Debug directory RVA is unmapped");
            const uint32_t entries = std::min<uint32_t>(debugSize / 28, 4096);
            for (uint32_t i = 0; i < entries; ++i) {
                const uint64_t entry = *directoryOffset + uint64_t{i} * 28;
                if (!r.inRange(entry, 28)) throw ParseError("Debug directory is truncated");
                if (r.u32(entry + 12, "Debug type") != 2) continue;
                const uint32_t dataSize = r.u32(entry + 16, "CodeView data size");
                const uint32_t dataRva = r.u32(entry + 20, "CodeView data RVA");
                const uint32_t dataPointer = r.u32(entry + 24, "CodeView data pointer");
                uint64_t cvOffset = dataPointer;
                if (!r.inRange(cvOffset, dataSize)) {
                    const auto mapped = rvaToOff(dataRva);
                    if (!mapped) continue;
                    cvOffset = *mapped;
                }
                if (dataSize < 24 || !r.inRange(cvOffset, dataSize) ||
                    r.u32(cvOffset, "CodeView signature") != 0x53445352) continue;
                const std::string guid = hexBytes(r.bytes(cvOffset + 4, 16));
                const uint32_t age = r.u32(cvOffset + 20, "CodeView age");
                const std::string pdbPath = r.cstring(cvOffset + 24,
                    std::min<size_t>(lim.maxStringLength, dataSize - 24));
                info.addMeta("CodeView PDB path", pdbPath);
                info.addMeta("CodeView GUID", guid);
                info.addMeta("CodeView age", std::to_string(age));
                info.addMeta("External debug symbols", "PDB referenced; symbols are not loaded from disk");
                break;
            }
        } catch (const ParseError& e) {
            info.warnings.push_back(std::string("PE debug directory parsing stopped: ") + e.what());
        }
    }
}

}  // namespace xrl
