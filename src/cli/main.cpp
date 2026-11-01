// xrl-cli: headless front-end to the analysis and comparison engine. Never executes the target file.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

#include "xrl/analyzer.hpp"
#include "xrl/diff.hpp"
#include "xrl/disassembler.hpp"
#include "xrl/report.hpp"
#include "xrl/util.hpp"

namespace {
void usage() {
    std::puts(
        "Usage:\n"
        "  Single file analysis:\n"
        "    xrl-cli <file> [--json [out.json]] [--text [out.txt]] [--disasm [start]] [--count N]\n"
        "      --json        write the JSON report (stdout if no path given)\n"
        "      --text        write the plain-text report (default when no format is chosen)\n"
        "      --disasm      include linear disassembly from entry point or file offset (0x.. / decimal)\n"
        "      --count N     instructions to disassemble (default 100)\n"
        "\n"
        "  Binary comparison / diff:\n"
        "    xrl-cli --diff <fileA> <fileB> [--json [out.json]] [--text [out.txt]]\n"
        "      --json        write the structured JSON diff report\n"
        "      --text        write the human-readable diff summary (default)\n");
}
}  // namespace

int main(int argc, char** argv) {
    if (argc < 2 || !std::strcmp(argv[1], "--help") || !std::strcmp(argv[1], "-h")) {
        usage();
        return argc < 2 ? 2 : 0;
    }

    auto emit = [](const std::string& content, const std::string& path) {
        if (path.empty()) { std::cout << content; return true; }
        std::ofstream f(path, std::ios::binary);
        if (!f) { std::fprintf(stderr, "Cannot write %s\n", path.c_str()); return false; }
        f << content;
        return true;
    };

    // Mode: --diff <fileA> <fileB>
    if (!std::strcmp(argv[1], "--diff")) {
        if (argc < 4) {
            std::fprintf(stderr, "Error: --diff requires two file paths: xrl-cli --diff <fileA> <fileB>\n");
            usage();
            return 2;
        }
        const std::string pathA = argv[2];
        const std::string pathB = argv[3];
        bool wantJson = false, wantText = false;
        std::string jsonOut, textOut;
        for (int i = 4; i < argc; ++i) {
            const std::string a = argv[i];
            auto optArg = [&](std::string& dst) {
                if (i + 1 < argc && argv[i + 1][0] != '-') dst = argv[++i];
            };
            if (a == "--json") { wantJson = true; optArg(jsonOut); }
            else if (a == "--text") { wantText = true; optArg(textOut); }
            else { std::fprintf(stderr, "Unknown argument: %s\n", a.c_str()); usage(); return 2; }
        }
        if (!wantJson && !wantText) wantText = true;

        const auto diffRes = xrl::compareFiles(pathA, pathB);
        if (!diffRes.ok) {
            std::fprintf(stderr, "Diff error: %s\n", diffRes.error.c_str());
            return 1;
        }

        bool ok = true;
        if (wantText) ok &= emit(xrl::renderDiffTextReport(diffRes), textOut);
        if (wantJson) ok &= emit(xrl::renderDiffJsonReport(diffRes), jsonOut);
        if (!ok) return 3;
        return diffRes.summary.identical ? 0 : 1;
    }

    // Single file mode
    const std::string path = argv[1];
    bool wantJson = false, wantText = false, wantDisasm = false;
    std::string jsonOut, textOut, disasmStart;
    size_t count = 100;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        auto optArg = [&](std::string& dst) {
            if (i + 1 < argc && argv[i + 1][0] != '-') dst = argv[++i];
        };
        if (a == "--json") { wantJson = true; optArg(jsonOut); }
        else if (a == "--text") { wantText = true; optArg(textOut); }
        else if (a == "--disasm") { wantDisasm = true; optArg(disasmStart); }
        else if (a == "--count") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Missing instruction count after --count.\n");
                return 2;
            }
            const auto parsedCount = xrl::parseNumber(argv[++i]);
            if (!parsedCount || *parsedCount == 0 || *parsedCount > 100'000) {
                std::fprintf(stderr, "Invalid instruction count. Use a decimal value from 1 to 100000.\n");
                return 2;
            }
            count = static_cast<size_t>(*parsedCount);
        }
        else { std::fprintf(stderr, "Unknown argument: %s\n", a.c_str()); usage(); return 2; }
    }
    if (!wantJson && !wantText) wantText = true;

    auto res = xrl::analyzeFile(path);
    xrl::DisasmResult dis;
    if (wantDisasm && res.data) {
        xrl::DisasmRequest req;
        req.maxInstructions = count;
        req.maxBytes = count * 16;
        bool haveStart = false;
        if (!disasmStart.empty()) {
            const auto n = xrl::parseNumber(disasmStart);
            if (!n) { std::fprintf(stderr, "Invalid disassembly start: %s\n", disasmStart.c_str()); return 2; }
            req.fileOffset = *n;
            haveStart = true;
        } else if (res.info.entryPoint) {
            if (auto off = res.info.virtualToFileOffset(*res.info.entryPoint)) { req.fileOffset = *off; haveStart = true; }
        }
        if (haveStart) {
            dis = xrl::disassemble(res.info, *res.data, req);
            if (!dis.ok) std::fprintf(stderr, "Disassembly: %s\n", dis.error.c_str());
        } else {
            std::fprintf(stderr, "Disassembly: no entry point mapped to file data; pass an explicit offset.\n");
        }
    }

    xrl::ReportInputs in;
    in.info = &res.info;
    in.disassembly = wantDisasm ? &dis : nullptr;

    bool ok = true;
    if (wantText) ok &= emit(xrl::renderTextReport(in), textOut);
    if (wantJson) ok &= emit(xrl::renderJsonReport(in), jsonOut);
    if (!ok) return 3;
    return res.info.ok() ? 0 : 1;
}
