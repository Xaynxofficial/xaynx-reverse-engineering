#pragma once
// Linear-sweep disassembly through Capstone (if compiled in).
//
// LIMITATION: this performs linear disassembly from a caller-chosen start address.
// It does NOT discover functions, recover control flow, resolve data-vs-code ambiguity or
// decompile. Known start points (entry point, exported symbols, ELF/Mach-O symbols with
// addresses) come from the file's own metadata and are not inferred.
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "xrl/types.hpp"

namespace xrl {

enum class InstructionFlow { None, ConditionalBranch, UnconditionalBranch, Call, Return, IndirectBranch, IndirectCall };

struct Instruction {
    uint64_t address = 0;
    uint64_t fileOffset = 0;
    std::vector<uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    bool valid = true;  // false for bytes that Capstone could not decode (shown as ".byte")
    InstructionFlow flow = InstructionFlow::None;
    std::optional<uint64_t> flowTarget;
    std::vector<uint64_t> dataTargets;
};

struct DisasmRequest {
    uint64_t fileOffset = 0;
    uint64_t maxBytes = 4096;
    size_t maxInstructions = 2000;
};

struct DisasmResult {
    bool ok = false;
    std::string error;
    std::string note;  // e.g. mode assumptions
    uint64_t startOffset = 0;
    uint64_t startAddress = 0;
    bool addressIsFileOffset = false;  // true when the offset is outside any mapped section
    std::vector<Instruction> instructions;
};

struct StartPoint {
    std::string label;
    uint64_t fileOffset;
    uint64_t address;
};

bool disassemblerCompiledIn();
std::string disassemblerVersion();  // "unavailable" if Capstone is not compiled in
bool disassemblySupported(const BinaryInfo& info);

// Start points that exist in the file's metadata: entry point, executable sections, exports with addresses.
std::vector<StartPoint> knownStartPoints(const BinaryInfo& info, size_t maxExports = 500);

DisasmResult disassemble(const BinaryInfo& info, std::span<const uint8_t> fileData, const DisasmRequest& req);

}  // namespace xrl
