#include "xrl/report.hpp"

#include <algorithm>
#include <cstdio>
#include <sstream>

#include "xrl/util.hpp"

namespace xrl {
namespace {

const char* kDisclaimer =
    "Findings are heuristic observations from static analysis. They are not verdicts: a finding "
    "alone does not establish that a file is malicious or benign. The file was never executed.";

Json symbolJson(const Symbol& s) {
    Json j = Json::object();
    j.set("name", s.name);
    if (!s.library.empty()) j.set("library", s.library);
    if (s.address) j.set("address", hex(*s.address));
    if (s.ordinal) j.set("ordinal", static_cast<int64_t>(*s.ordinal));
    if (!s.type.empty()) j.set("type", s.type);
    return j;
}

Json symbolCategory(const Category<Symbol>& c, size_t cap) {
    Json j = Json::object();
    j.set("availability", toString(c.state));
    if (!c.note.empty()) j.set("note", c.note);
    j.set("count", static_cast<int64_t>(c.items.size()));
    Json items = Json::array();
    for (size_t i = 0; i < c.items.size() && i < cap; ++i) items.push(symbolJson(c.items[i]));
    j.set("items", std::move(items));
    j.set("truncated", c.items.size() > cap);
    return j;
}

Json relocationCategory(const Category<Relocation>& c, size_t cap) {
    Json j = Json::object();
    j.set("availability", toString(c.state));
    if (!c.note.empty()) j.set("note", c.note);
    j.set("count", static_cast<int64_t>(c.items.size()));
    Json items = Json::array();
    for (size_t i = 0; i < c.items.size() && i < cap; ++i) {
        const auto& relocation = c.items[i];
        Json item = Json::object();
        item.set("address", hex(relocation.address));
        item.set("file_offset", relocation.fileOffset ? Json(*relocation.fileOffset) : Json(nullptr));
        item.set("type", static_cast<int64_t>(relocation.type));
        item.set("type_name", relocation.typeName);
        item.set("symbol", relocation.symbolName.empty() ? Json(nullptr) : Json(relocation.symbolName));
        item.set("addend", relocation.addend ? Json(*relocation.addend) : Json(nullptr));
        item.set("target_address", relocation.targetAddress ? Json(hex(*relocation.targetAddress)) : Json(nullptr));
        item.set("source", relocation.source);
        items.push(std::move(item));
    }
    j.set("items", std::move(items));
    j.set("truncated", c.items.size() > cap);
    return j;
}

}  // namespace

Json buildJsonReport(const ReportInputs& in) {
    const BinaryInfo& i = *in.info;
    Json root = Json::object();
    root.set("schema_version", kReportSchemaVersion);
    Json tool = Json::object();
    tool.set("name", "Xaynx Reverse Lab");
    tool.set("version", XRL_VERSION);
    root.set("tool", std::move(tool));
    root.set("generated_utc", in.generatedAtUtc.empty() ? utcNowIso8601() : in.generatedAtUtc);
    root.set("executed", false);  // the analysed file is never run
    root.set("disclaimer", kDisclaimer);

    Json file = Json::object();
    file.set("name", i.fileName);
    file.set("path", i.filePath);
    file.set("size_bytes", i.fileSize);
    if (!i.sha256.empty()) file.set("sha256", i.sha256);
    else file.set("sha256", nullptr);
    root.set("file", std::move(file));

    Json status = Json::object();
    status.set("parsed_without_error", i.ok());
    status.set("format_recognised", i.recognized());
    if (!i.error.empty()) status.set("error", i.error);
    root.set("status", std::move(status));

    Json fmt = Json::object();
    fmt.set("format", toString(i.format));
    fmt.set("description", i.formatName);
    fmt.set("file_type", i.fileType);
    fmt.set("architecture", toString(i.arch));
    fmt.set("architecture_detail", i.archName);
    fmt.set("bits", i.bits == 0 ? Json(nullptr) : Json(i.bits));
    fmt.set("endianness", toString(i.endian));
    fmt.set("entry_point", i.entryPoint ? Json(hex(*i.entryPoint)) : Json(nullptr));
    Json meta = Json::object();
    for (const auto& [k, v] : i.metadata) meta.set(k, v);
    fmt.set("metadata", std::move(meta));
    root.set("binary", std::move(fmt));

    Json secs = Json::object();
    secs.set("availability", i.sectionsParsed ? "present" : "unavailable (not parsed)");
    Json list = Json::array();
    for (const auto& s : i.sections) {
        Json j = Json::object();
        j.set("name", s.name);
        j.set("kind", s.kind);
        if (!s.segment.empty()) j.set("segment", s.segment);
        j.set("virtual_address", hex(s.virtualAddress));
        j.set("virtual_size", s.virtualSize);
        j.set("file_offset", s.fileOffset);
        j.set("file_size", s.fileSize);
        std::string perms = std::string(s.readable ? "r" : "-") + (s.writable ? "w" : "-") + (s.executable ? "x" : "-");
        j.set("permissions", perms);
        j.set("bounds_valid", s.boundsValid);
        j.set("entropy", s.entropy ? Json(*s.entropy) : Json(nullptr));
        if (!s.note.empty()) j.set("note", s.note);
        list.push(std::move(j));
    }
    secs.set("items", std::move(list));
    root.set("sections", std::move(secs));

    root.set("imports", symbolCategory(i.imports, in.maxListedItems));
    root.set("exports", symbolCategory(i.exports, in.maxListedItems));
    root.set("symbols", symbolCategory(i.symbols, in.maxListedItems));
    root.set("relocations", relocationCategory(i.relocations, in.maxListedItems));
    Json libs = Json::object();
    libs.set("availability", toString(i.libraries.state));
    if (!i.libraries.note.empty()) libs.set("note", i.libraries.note);
    Json ll = Json::array();
    for (const auto& l : i.libraries.items) ll.push(l);
    libs.set("items", std::move(ll));
    root.set("libraries", std::move(libs));

    Json warns = Json::array();
    for (const auto& w : i.warnings) warns.push(w);
    root.set("warnings", std::move(warns));

    Json finds = Json::array();
    for (const auto& f : i.findings) {
        Json j = Json::object();
        j.set("title", f.title);
        j.set("detail", f.detail);
        j.set("confidence", "heuristic");
        finds.push(std::move(j));
    }
    root.set("heuristic_findings", std::move(finds));

    Json dis = Json::object();
    if (in.disassembly && in.disassembly->ok) {
        const auto& d = *in.disassembly;
        dis.set("available", true);
        dis.set("engine", disassemblerVersion());
        dis.set("method", "linear sweep from a user-selected start offset; no function discovery");
        dis.set("start_offset", d.startOffset);
        dis.set("start_address", hex(d.startAddress));
        dis.set("addresses_are_file_offsets", d.addressIsFileOffset);
        if (!d.note.empty()) dis.set("note", d.note);
        Json insns = Json::array();
        for (size_t k = 0; k < d.instructions.size() && k < in.maxDisasmInstructions; ++k) {
            const auto& ins = d.instructions[k];
            Json j = Json::object();
            j.set("address", hex(ins.address));
            j.set("bytes", hexBytes(ins.bytes));
            j.set("mnemonic", ins.mnemonic);
            j.set("operands", ins.operands);
            j.set("decoded", ins.valid);
            insns.push(std::move(j));
        }
        dis.set("instruction_count", static_cast<int64_t>(d.instructions.size()));
        dis.set("instructions", std::move(insns));
        dis.set("truncated", d.instructions.size() > in.maxDisasmInstructions);
    } else {
        dis.set("available", false);
        dis.set("reason", "No disassembly was requested for this report.");
    }
    root.set("disassembly", std::move(dis));

    Json gh = Json::object();
    if (in.ghidra && in.ghidra->ok) {
        const auto& g = *in.ghidra;
        gh.set("available", true);
        gh.set("ghidra_version", g.ghidraVersion);
        gh.set("language", g.language);
        gh.set("compiler", g.compiler);
        gh.set("image_base", g.imageBase);
        gh.set("total_functions", static_cast<int64_t>(g.totalFunctions));
        Json fl = Json::array();
        for (const auto& f : g.functions) {
            Json j = Json::object();
            j.set("name", f.name);
            j.set("entry", hex(f.entry));
            j.set("size", f.size);
            j.set("signature", f.signature);
            j.set("external", f.external);
            j.set("thunk", f.thunk);
            if (f.hasDecompilation) j.set("decompiled", f.decompiled);
            fl.push(std::move(j));
        }
        gh.set("functions", std::move(fl));
    } else {
        gh.set("available", false);
        gh.set("reason", "Ghidra analysis was not run (optional, user-initiated).");
    }
    root.set("ghidra", std::move(gh));
    return root;
}

std::string renderJsonReport(const ReportInputs& in) { return buildJsonReport(in).dump(2) + "\n"; }

std::string renderTextReport(const ReportInputs& in) {
    const BinaryInfo& i = *in.info;
    std::ostringstream o;
    auto rule = [&](const char* title) { o << "\n== " << title << " ==\n"; };
    auto perms = [](const Section& s) {
        return std::string(s.readable ? "r" : "-") + (s.writable ? "w" : "-") + (s.executable ? "x" : "-");
    };

    o << "Xaynx Reverse Lab " << XRL_VERSION << " - static analysis report\n";
    o << "Generated (UTC): " << (in.generatedAtUtc.empty() ? utcNowIso8601() : in.generatedAtUtc) << "\n";
    o << "The analysed file was not executed.\n" << kDisclaimer << "\n";

    rule("File");
    o << "Name:    " << i.fileName << "\nPath:    " << i.filePath << "\nSize:    " << humanSize(i.fileSize) << "\n";
    o << "SHA-256: " << (i.sha256.empty() ? "(not computed)" : i.sha256) << "\n";
    if (!i.error.empty()) o << "\nERROR: " << i.error << "\n";

    rule("Binary");
    o << "Format:       " << i.formatName << "\nType:         " << (i.fileType.empty() ? "(unknown)" : i.fileType)
      << "\nArchitecture: " << i.archName << "\nBitness:      " << (i.bits ? std::to_string(i.bits) + "-bit" : "unknown")
      << "\nEndianness:   " << toString(i.endian) << "\nEntry point:  " << (i.entryPoint ? hex(*i.entryPoint) : "(none / unknown)") << "\n";
    for (const auto& [k, v] : i.metadata) o << k << ": " << v << "\n";

    rule("Sections");
    if (!i.sectionsParsed) o << "Unavailable: section information could not be parsed.\n";
    for (const auto& s : i.sections) {
        char line[256];
        std::snprintf(line, sizeof line, "%-10s %-20s va=%-18s vsize=%-10llu foff=%-12s fsize=%-10llu %s",
                      s.kind.c_str(), s.name.c_str(), hex(s.virtualAddress).c_str(),
                      static_cast<unsigned long long>(s.virtualSize), hex(s.fileOffset).c_str(),
                      static_cast<unsigned long long>(s.fileSize), perms(s).c_str());
        o << line;
        if (s.entropy) { std::snprintf(line, sizeof line, " entropy=%.2f", *s.entropy); o << line; }
        if (!s.note.empty()) o << "  [" << s.note << "]";
        o << "\n";
    }

    auto symSection = [&](const char* title, const Category<Symbol>& c) {
        rule(title);
        o << "Status: " << toString(c.state) << " (" << c.items.size() << " entries)\n";
        if (!c.note.empty()) o << "Note: " << c.note << "\n";
        for (size_t k = 0; k < c.items.size() && k < in.maxListedItems; ++k) {
            const auto& s = c.items[k];
            o << "  " << s.name;
            if (!s.library.empty()) o << "  <" << s.library << ">";
            if (s.address) o << "  @" << hex(*s.address);
            o << "\n";
        }
        if (c.items.size() > in.maxListedItems) o << "  ... list truncated at " << in.maxListedItems << " entries\n";
    };
    rule("Linked libraries");
    o << "Status: " << toString(i.libraries.state) << "\n";
    if (!i.libraries.note.empty()) o << "Note: " << i.libraries.note << "\n";
    for (const auto& l : i.libraries.items) o << "  " << l << "\n";
    symSection("Imports", i.imports);
    symSection("Exports", i.exports);
    symSection("Symbols", i.symbols);
    rule("Relocations");
    o << "Status: " << toString(i.relocations.state) << " (" << i.relocations.items.size() << " entries)\n";
    if (!i.relocations.note.empty()) o << "Note: " << i.relocations.note << "\n";
    for (size_t k = 0; k < i.relocations.items.size() && k < in.maxListedItems; ++k) {
        const auto& relocation = i.relocations.items[k];
        o << "  " << hex(relocation.address) << "  " << relocation.typeName;
        if (relocation.fileOffset) o << "  file-offset=" << hex(*relocation.fileOffset);
        if (!relocation.symbolName.empty()) o << "  symbol=" << relocation.symbolName;
        if (relocation.targetAddress) o << "  target=" << hex(*relocation.targetAddress);
        o << "  source=" << relocation.source << "\n";
    }
    if (i.relocations.items.size() > in.maxListedItems)
        o << "  ... list truncated at " << in.maxListedItems << " entries\n";

    rule("Warnings");
    if (i.warnings.empty()) o << "None.\n";
    for (const auto& w : i.warnings) o << "- " << w << "\n";

    rule("Heuristic findings (unverified)");
    if (i.findings.empty()) o << "No heuristic observations were triggered. This does not prove the file is benign.\n";
    for (const auto& f : i.findings) o << "- [heuristic] " << f.title << "\n    " << f.detail << "\n";

    rule("Disassembly");
    if (in.disassembly && in.disassembly->ok) {
        const auto& d = *in.disassembly;
        o << "Engine: " << disassemblerVersion() << "; linear sweep from " << hex(d.startAddress)
          << " (no function discovery).\n";
        if (!d.note.empty()) o << "Note: " << d.note << "\n";
        for (size_t k = 0; k < d.instructions.size() && k < in.maxDisasmInstructions; ++k) {
            const auto& ins = d.instructions[k];
            char addr[24];
            std::snprintf(addr, sizeof addr, "%016llx", static_cast<unsigned long long>(ins.address));
            o << addr << "  " << hexBytes(ins.bytes);
            for (size_t pad = ins.bytes.size() * 2; pad < 32; ++pad) o << ' ';
            o << "  " << ins.mnemonic << (ins.operands.empty() ? "" : " ") << ins.operands << "\n";
        }
        if (d.instructions.size() > in.maxDisasmInstructions) o << "... truncated\n";
    } else {
        o << "No disassembly was requested for this report.\n";
    }

    rule("Ghidra");
    if (in.ghidra && in.ghidra->ok) {
        const auto& g = *in.ghidra;
        o << "Ghidra " << g.ghidraVersion << ", language " << g.language << ", compiler " << g.compiler
          << "\nFunctions reported by Ghidra: " << g.totalFunctions << "\n";
        for (const auto& f : g.functions) {
            o << "  " << hex(f.entry) << "  " << f.name << "  size=" << f.size << (f.external ? "  [external]" : "")
              << (f.thunk ? "  [thunk]" : "") << "\n";
            if (f.hasDecompilation) o << "    --- Ghidra decompiler output ---\n" << f.decompiled << "\n";
        }
    } else {
        o << "Ghidra analysis was not run (optional, user-initiated).\n";
    }
    return o.str();
}

}  // namespace xrl
