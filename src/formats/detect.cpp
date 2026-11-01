#include "xrl/analyzer.hpp"
#include "xrl/formats.hpp"

#include <algorithm>

namespace xrl {

Format detectFormat(std::span<const uint8_t> d) {
    if (d.size() >= 2 && d[0] == 'M' && d[1] == 'Z') return Format::PE;
    if (d.size() >= 4 && d[0] == 0x7F && d[1] == 'E' && d[2] == 'L' && d[3] == 'F') return Format::ELF;
    if (d.size() >= 4) {
        const uint32_t be = (uint32_t{d[0]} << 24) | (uint32_t{d[1]} << 16) | (uint32_t{d[2]} << 8) | d[3];
        const uint32_t le = (uint32_t{d[3]} << 24) | (uint32_t{d[2]} << 16) | (uint32_t{d[1]} << 8) | d[0];
        switch (be) {
            case 0xCAFEBABE: case 0xCAFEBABF:  // fat (validated later; Java class files share 0xCAFEBABE)
            case 0xFEEDFACE: case 0xFEEDFACF: case 0xCEFAEDFE: case 0xCFFAEDFE:
                return Format::MachO;
            default: break;
        }
        if (le == 0xFEEDFACE || le == 0xFEEDFACF) return Format::MachO;
    }
    return Format::Unknown;
}

const char* toString(Format f) {
    switch (f) {
        case Format::PE: return "PE";
        case Format::ELF: return "ELF";
        case Format::MachO: return "Mach-O";
        default: return "Unknown";
    }
}
const char* toString(Arch a) {
    switch (a) {
        case Arch::X86: return "x86";
        case Arch::X86_64: return "x86-64";
        case Arch::Arm: return "ARM";
        case Arch::Arm64: return "ARM64";
        case Arch::Mips: return "MIPS";
        case Arch::PowerPC: return "PowerPC";
        case Arch::RiscV: return "RISC-V";
        case Arch::Other: return "Other";
        default: return "Unknown";
    }
}
const char* toString(Endian e) {
    switch (e) {
        case Endian::Little: return "Little-endian";
        case Endian::Big: return "Big-endian";
        default: return "Unknown";
    }
}
const char* toString(Availability a) {
    switch (a) {
        case Availability::Present: return "present";
        case Availability::Absent: return "absent (confirmed)";
        default: return "unavailable (not parsed)";
    }
}

std::optional<uint64_t> BinaryInfo::virtualToFileOffset(uint64_t va) const {
    for (const auto& s : sections) {
        if (!s.hasFileData || !s.boundsValid) continue;
        const uint64_t span = std::min(s.virtualSize ? s.virtualSize : s.fileSize, s.fileSize);
        if (va >= s.virtualAddress && va - s.virtualAddress < span) return s.fileOffset + (va - s.virtualAddress);
    }
    return std::nullopt;
}

std::optional<uint64_t> BinaryInfo::fileOffsetToVirtual(uint64_t off) const {
    for (const auto& s : sections) {
        if (!s.hasFileData || !s.boundsValid || s.fileSize == 0) continue;
        if (off >= s.fileOffset && off - s.fileOffset < s.fileSize) return s.virtualAddress + (off - s.fileOffset);
    }
    return std::nullopt;
}

}  // namespace xrl
