#pragma once
// Optional Ghidra integration. Ghidra is never required: nothing here runs unless the caller
// explicitly builds and executes the headless command.
//
// Mechanism: `analyzeHeadless <projectDir> <name> -import <file> -scriptPath <dir>
//             -postScript XrlExport.java <out.json> <decompile 0|1> <max> -deleteProject`
// The script (ghidra_scripts/XrlExport.java) writes JSON that parseGhidraOutput() reads.
// Everything reported comes from that real output; nothing is synthesised.
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace xrl {

struct GhidraInstall {
    bool valid = false;
    std::string root;      // Ghidra installation directory
    std::string headless;  // path to analyzeHeadless(.bat)
    std::string version;   // from application.properties if readable
    std::string error;     // why validation failed
};

// Checks that `dir` is a Ghidra install containing support/analyzeHeadless(.bat).
// Only inspects the file system; does not start Ghidra.
GhidraInstall validateGhidraInstall(const std::filesystem::path& dir);

// Looks at GHIDRA_INSTALL_DIR and common install locations. Returns valid installs only.
std::vector<GhidraInstall> detectGhidra();

struct GhidraOptions {
    bool decompile = false;
    int maxDecompiled = 50;
    int analysisTimeoutSeconds = 600;
};

struct GhidraCommand {
    std::string program;
    std::vector<std::string> args;
    std::string outputJson;
    std::string projectDir;
};

// Builds (does not run) the headless command. `workDir` must be an existing writable directory
// in which a temporary project and the output file are created.
GhidraCommand buildGhidraCommand(const GhidraInstall& install, const std::filesystem::path& binary,
                                 const std::filesystem::path& workDir, const std::filesystem::path& scriptDir,
                                 const GhidraOptions& opts);

// Directory containing XrlExport.java (next to the executable, build tree, or source tree).
std::filesystem::path findGhidraScriptDir(const std::filesystem::path& executableDir);

struct GhidraFunction {
    std::string name;
    uint64_t entry = 0;
    uint64_t size = 0;
    std::string signature;
    bool external = false;
    bool thunk = false;
    bool hasDecompilation = false;
    std::string decompiled;  // real Ghidra decompiler output
};

struct GhidraResult {
    bool ok = false;
    std::string error;
    std::string ghidraVersion, language, compiler, imageBase;
    size_t totalFunctions = 0;
    std::vector<GhidraFunction> functions;
    std::string log;  // stdout/stderr tail captured by the runner (optional)
};

GhidraResult parseGhidraOutput(const std::string& jsonText);

}  // namespace xrl

