#pragma once
// Data model produced by the analysis engine. Independent of any GUI toolkit.
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace xrl {

enum class Format { Unknown, PE, ELF, MachO };
enum class Arch { Unknown, X86, X86_64, Arm, Arm64, Mips, PowerPC, RiscV, Other };
enum class Endian { Unknown, Little, Big };

// Whether a category of information could be determined for this file.
//   NotParsed - we could not (or did not) determine it. This is NOT a statement of absence.
//   Absent    - the file structure was read and confirms that the data does not exist.
//   Present   - parsed; items may be listed.
enum class Availability { NotParsed, Absent, Present };

struct Section {
    std::string name;
    std::string segment;          // Mach-O segment name; empty otherwise
    std::string kind = "section"; // "section" or "segment"
    uint64_t virtualAddress = 0;
    uint64_t virtualSize = 0;
    uint64_t fileOffset = 0;      // absolute offset within the analysed file
    uint64_t fileSize = 0;        // bytes occupied in the file (0 for zero-fill / NOBITS)
    uint32_t flags = 0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool hasFileData = false;     // false for BSS-like sections
    bool boundsValid = true;      // false when [fileOffset, fileOffset+fileSize) exceeds the file
    std::optional<double> entropy;  // only for sections that are in-bounds and non-empty
    std::string note;
};

struct Symbol {
    std::string name;
    std::string library;          // providing library when known
    std::optional<uint64_t> address;
    std::optional<uint32_t> ordinal;
    std::string type;             // e.g. "func", "object", "forwarder"
};

struct Relocation {
    uint64_t address = 0;
    std::optional<uint64_t> fileOffset;
    uint32_t type = 0;
    std::string typeName;
    std::string symbolName;
    std::optional<int64_t> addend;
    std::optional<uint64_t> targetAddress;
    std::string source;
};

template <class T>
struct Category {
    Availability state = Availability::NotParsed;
    std::string note;             // explains NotParsed / partial results
    std::vector<T> items;
};

struct Finding {
    std::string title;
    std::string detail;
    // Every finding is heuristic by construction. Wording must stay non-accusatory.
};

struct BinaryInfo {
    // File
    std::string filePath;
    std::string fileName;
    uint64_t fileSize = 0;
    std::string sha256;           // empty when the file was not read

    // Format
    Format format = Format::Unknown;
    std::string formatName = "Unknown";
    std::string fileType;         // executable / shared library / object ...
    Arch arch = Arch::Unknown;
    std::string archName = "Unknown";
    int bits = 0;                 // 0 = unknown
    Endian endian = Endian::Unknown;
    bool armThumb = false;        // ARM code is Thumb-only (PE ARMNT)
    std::optional<uint64_t> entryPoint;  // virtual address

    std::vector<std::pair<std::string, std::string>> metadata;

    std::vector<Section> sections;
    bool sectionsParsed = false;
    Category<Symbol> imports;
    Category<Symbol> exports;
    Category<std::string> libraries;
    Category<Symbol> symbols;
    Category<Relocation> relocations;

    std::vector<std::string> warnings;
    std::vector<Finding> findings;  // heuristic observations
    std::string error;            // non-empty when parsing failed (possibly after partial results)

    bool recognized() const { return format != Format::Unknown; }
    bool ok() const { return error.empty(); }
    void addMeta(std::string k, std::string v) { metadata.emplace_back(std::move(k), std::move(v)); }

    // Address translation based on parsed sections. nullopt when unmapped.
    std::optional<uint64_t> virtualToFileOffset(uint64_t va) const;
    std::optional<uint64_t> fileOffsetToVirtual(uint64_t off) const;
};

const char* toString(Format f);
const char* toString(Arch a);
const char* toString(Endian e);
const char* toString(Availability a);

}  // namespace xrl
