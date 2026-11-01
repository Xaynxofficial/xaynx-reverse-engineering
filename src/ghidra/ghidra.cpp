#include "xrl/ghidra.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>

#include "xrl/json.hpp"
#include "xrl/util.hpp"

namespace fs = std::filesystem;

namespace xrl {

GhidraInstall validateGhidraInstall(const fs::path& dir) {
    GhidraInstall g;
    std::error_code ec;
    if (dir.empty() || !fs::is_directory(dir, ec)) {
        g.error = "Not a directory.";
        return g;
    }
#ifdef _WIN32
    const fs::path hl = dir / "support" / "analyzeHeadless.bat";
#else
    const fs::path hl = dir / "support" / "analyzeHeadless";
#endif
    if (!fs::is_regular_file(hl, ec)) {
        g.error = "support/analyzeHeadless was not found. Select the Ghidra root directory (the one containing 'ghidraRun').";
        return g;
    }
    g.valid = true;
    g.root = pathUtf8(dir);
    g.headless = pathUtf8(hl);
    std::ifstream props(dir / "Ghidra" / "application.properties");
    for (std::string line; std::getline(props, line);) {
        const std::string key = "application.version=";
        if (line.rfind(key, 0) == 0) {
            g.version = sanitizeText(line.substr(key.size()));
            while (!g.version.empty() && (g.version.back() == '\r' || g.version.back() == ' ')) g.version.pop_back();
        }
    }
    return g;
}

std::vector<GhidraInstall> detectGhidra() {
    std::vector<fs::path> roots;
    std::error_code ec;
    if (const char* env = std::getenv("GHIDRA_INSTALL_DIR")) roots.emplace_back(env);

    auto scan = [&](const fs::path& parent) {
        if (!fs::is_directory(parent, ec)) return;
        for (const auto& e : fs::directory_iterator(parent, fs::directory_options::skip_permission_denied, ec)) {
            const auto name = e.path().filename().string();
            if (name.rfind("ghidra", 0) == 0 || name.rfind("Ghidra", 0) == 0) roots.push_back(e.path());
        }
    };
    auto home = [&]() -> fs::path {
#ifdef _WIN32
        const char* h = std::getenv("USERPROFILE");
#else
        const char* h = std::getenv("HOME");
#endif
        return h ? fs::path(h) : fs::path();
    }();

#ifdef _WIN32
    for (const char* p : {"C:\\", "C:\\Program Files", "C:\\Program Files (x86)", "C:\\tools"}) scan(p);
#else
    for (const char* p : {"/Applications", "/opt", "/usr/local", "/usr/share"}) scan(p);
    scan("/opt/homebrew/Caskroom/ghidra");
    scan("/opt/homebrew/opt");
    scan("/usr/local/Caskroom/ghidra");
#endif
    if (!home.empty()) {
        scan(home);
        scan(home / "Downloads");
        scan(home / "tools");
    }
    // Homebrew cask layout: Caskroom/ghidra/<version>/ghidra_<version>_PUBLIC
    for (const char* cask : {"/opt/homebrew/Caskroom/ghidra", "/usr/local/Caskroom/ghidra"}) {
        if (!fs::is_directory(cask, ec)) continue;
        for (const auto& v : fs::directory_iterator(cask, fs::directory_options::skip_permission_denied, ec))
            scan(v.path());
    }

    std::vector<GhidraInstall> found;
    for (const auto& r : roots) {
        auto g = validateGhidraInstall(r);
        if (!g.valid) {
            // Some distributions nest the real root one level down (e.g. /opt/homebrew/opt/ghidra/libexec).
            g = validateGhidraInstall(r / "libexec");
            if (!g.valid) continue;
        }
        bool dup = false;
        for (const auto& f : found) dup = dup || f.root == g.root;
        if (!dup) found.push_back(std::move(g));
    }
    return found;
}

GhidraCommand buildGhidraCommand(const GhidraInstall& install, const fs::path& binary, const fs::path& workDir,
                                 const fs::path& scriptDir, const GhidraOptions& opts) {
    GhidraCommand c;
    c.program = install.headless;
    c.projectDir = pathUtf8(workDir / "project");
    c.outputJson = pathUtf8(workDir / "xrl_ghidra_output.json");
    c.args = {c.projectDir, "xrl_project",  // Ghidra creates the project directory if needed
              "-import", pathUtf8(binary),
              "-scriptPath", pathUtf8(scriptDir),
              "-postScript", "XrlExport.java", c.outputJson, opts.decompile ? "1" : "0", std::to_string(opts.maxDecompiled),
              "-analysisTimeoutPerFile", std::to_string(opts.analysisTimeoutSeconds),
              "-deleteProject"};
    return c;
}

fs::path findGhidraScriptDir(const fs::path& exeDir) {
    std::error_code ec;
    std::vector<fs::path> candidates = {exeDir / "ghidra_scripts", exeDir.parent_path() / "ghidra_scripts",
                                        exeDir.parent_path().parent_path() / "ghidra_scripts",
                                        exeDir.parent_path() / "Resources" / "ghidra_scripts"};
#ifdef XRL_SOURCE_SCRIPT_DIR
    candidates.emplace_back(XRL_SOURCE_SCRIPT_DIR);
#endif
    for (const auto& c : candidates)
        if (fs::is_regular_file(c / "XrlExport.java", ec)) return c;
    return {};
}

GhidraResult parseGhidraOutput(const std::string& text) {
    GhidraResult r;
    const auto parsed = Json::parse(text);
    if (!parsed.value) {
        r.error = "Ghidra output is not valid JSON: " + parsed.error;
        return r;
    }
    const Json& root = *parsed.value;
    if (!root.isObject()) { r.error = "Ghidra output has an unexpected structure (root is not an object)."; return r; }
    const Json* fns = root.find("functions");
    if (!fns || !fns->isArray()) { r.error = "Ghidra output has no 'functions' array."; return r; }

    auto str = [&](const Json& o, const char* k) {
        const Json* v = o.find(k);
        return v && v->isString() ? v->asString() : std::string();
    };
    r.ghidraVersion = str(root, "ghidra_version");
    r.language = str(root, "language");
    r.compiler = str(root, "compiler");
    r.imageBase = str(root, "image_base");
    if (const Json* t = root.find("total_functions")) r.totalFunctions = static_cast<size_t>(t->asInt());
    else r.totalFunctions = fns->size();

    for (const Json& f : fns->items()) {
        if (!f.isObject()) continue;
        GhidraFunction g;
        g.name = str(f, "name");
        if (auto addr = parseNumber(str(f, "entry"), true)) g.entry = *addr;
        if (const Json* s = f.find("size")) g.size = static_cast<uint64_t>(std::max<int64_t>(0, s->asInt()));
        g.signature = str(f, "signature");
        if (const Json* e = f.find("external")) g.external = e->asBool();
        if (const Json* t = f.find("thunk")) g.thunk = t->asBool();
        if (const Json* d = f.find("decompiled"); d && d->isString()) {
            g.hasDecompilation = true;
            g.decompiled = d->asString();
        }
        r.functions.push_back(std::move(g));
    }
    r.ok = true;
    return r;
}

}  // namespace xrl
