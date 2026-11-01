#include <algorithm>
#include <cstdio>
#include <set>

#include "xrl/analyzer.hpp"
#include "xrl/util.hpp"

namespace xrl {

// All findings here are heuristics, worded as observations. None of them is evidence of
// malicious intent on its own: packers, installers, JIT-style code and ordinary
// system tools trigger each of them routinely.
void runHeuristics(BinaryInfo& info) {
    for (const auto& s : info.sections) {
        if (s.kind == "section" || s.kind == "segment") {
            if (s.writable && s.executable)
                info.findings.push_back({"Writable and executable " + s.kind + ": " + s.name,
                                         "The " + s.kind + " is mapped both writable and executable. This is common in "
                                         "packed or self-modifying code but also in some legitimate runtimes and old toolchains."});
        }
        if (!s.boundsValid)
            info.findings.push_back({"Section extends past end of file: " + s.name,
                                     "Header metadata and file size disagree. This may indicate truncation, "
                                     "corruption, or data appended/stripped after the header was written."});
        if (s.entropy && *s.entropy >= 7.2 && s.fileSize >= 4096) {
            char buf[32];
            std::snprintf(buf, sizeof buf, "%.2f", *s.entropy);
            info.findings.push_back({std::string("High entropy section: ") + s.name,
                                     std::string("Shannon entropy ") + buf + " bits/byte over " + std::to_string(s.fileSize) +
                                         " bytes. High entropy suggests compressed or encrypted content; this is also "
                                         "typical of embedded resources and compressed assets. Not a verdict."});
        }
    }

    if (info.entryPoint && info.sectionsParsed && !info.sections.empty()) {
        bool inExec = false, mapped = false;
        for (const auto& s : info.sections) {
            if (s.kind != "section") continue;
            const uint64_t ext = std::max(s.virtualSize, s.fileSize);
            if (*info.entryPoint >= s.virtualAddress && *info.entryPoint - s.virtualAddress < ext) {
                mapped = true;
                inExec = inExec || s.executable;
            }
        }
        if (!mapped)
            info.findings.push_back({"Entry point not inside any listed section",
                                     "The entry address " + hex(*info.entryPoint) +
                                         " is not covered by the parsed section table. Possible with packers, "
                                         "stripped section tables, or unusual loaders."});
        else if (!inExec)
            info.findings.push_back({"Entry point is in a non-executable section",
                                     "Entry address " + hex(*info.entryPoint) + " lies in a section without the execute permission flag."});
    }

    if (info.format == Format::PE && info.imports.state == Availability::Present) {
        static const std::set<std::string> kApis = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                                                    "SetWindowsHookExA", "SetWindowsHookExW", "NtUnmapViewOfSection"};
        std::string hits;
        std::set<std::string> seen;
        for (const auto& i : info.imports.items)
            if (kApis.count(i.name) && seen.insert(i.name).second) hits += (hits.empty() ? "" : ", ") + i.name;
        if (!hits.empty())
            info.findings.push_back({"Imports of process-manipulation APIs: " + hits,
                                     "These APIs are used by debuggers, accessibility tools, anti-cheat, security software and "
                                     "installers as well as by hostile code. Importing them is not evidence of malicious behaviour."});
    }

    if (info.imports.state == Availability::Present && info.imports.items.empty() && info.format == Format::PE &&
        !info.sections.empty())
        info.findings.push_back({"Import directory is present but lists no functions",
                                 "Some packers resolve imports at runtime; some tiny or freestanding programs legitimately import nothing."});
}

}  // namespace xrl
