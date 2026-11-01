#pragma once
#include <string>

#include "xrl/disassembler.hpp"
#include "xrl/ghidra.hpp"
#include "xrl/json.hpp"
#include "xrl/types.hpp"

namespace xrl {

inline constexpr const char* kReportSchemaVersion = "1.0";

struct ReportInputs {
    const BinaryInfo* info = nullptr;
    const DisasmResult* disassembly = nullptr;  // optional: last disassembly listing the user produced
    const GhidraResult* ghidra = nullptr;       // optional: only present if the user ran Ghidra
    std::string generatedAtUtc;                 // empty -> now
    size_t maxDisasmInstructions = 5000;
    size_t maxListedItems = 5000;               // cap on imports/exports/symbols in the report
};

Json buildJsonReport(const ReportInputs& in);
std::string renderJsonReport(const ReportInputs& in);
std::string renderTextReport(const ReportInputs& in);

}  // namespace xrl

