#include <fstream>
#include <system_error>

#include "xrl/analyzer.hpp"
#include "xrl/formats.hpp"
#include "xrl/sha256.hpp"
#include "xrl/util.hpp"

namespace xrl {
namespace {

void report(const ProgressFn& p, int pct, const char* stage) {
    if (p) p(pct, stage);
}

// Section bounds validation and entropy (entropy only for in-bounds sections).
void finalizeSections(std::span<const uint8_t> data, BinaryInfo& info) {
    for (auto& s : info.sections) {
        if (!s.hasFileData) continue;
        const bool inRange = s.fileOffset <= data.size() && s.fileSize <= data.size() - s.fileOffset;
        if (!inRange) {
            s.boundsValid = false;
            s.note += (s.note.empty() ? "" : "; ") + std::string("file range exceeds file size");
            info.warnings.push_back("Section '" + s.name + "' (offset " + hex(s.fileOffset) + ", size " +
                                    std::to_string(s.fileSize) + ") extends beyond the end of the file.");
            continue;
        }
        if (s.kind == "section" && s.fileSize > 0)
            s.entropy = shannonEntropy(data.subspan(static_cast<size_t>(s.fileOffset), static_cast<size_t>(s.fileSize)));
    }
}

}  // namespace

BinaryInfo analyzeBuffer(std::span<const uint8_t> data, const Limits& limits, const ProgressFn& progress) {
    BinaryInfo info;
    info.fileSize = data.size();
    if (data.empty()) {
        info.error = "File is empty (0 bytes).";
        return info;
    }
    if (data.size() > limits.maxFileSize) {
        info.error = "File size " + humanSize(data.size()) + " exceeds the configured limit of " +
                     humanSize(limits.maxFileSize) + ". Analysis was not performed.";
        return info;
    }

    report(progress, 10, "Computing SHA-256");
    info.sha256 = Sha256::hexDigest(data);

    report(progress, 40, "Identifying format");
    const Format fmt = detectFormat(data);
    if (fmt == Format::Unknown) {
        info.error = "Unsupported or unrecognised file format (no PE, ELF or Mach-O magic bytes).";
        return info;
    }

    report(progress, 55, "Parsing structure");
    try {
        switch (fmt) {
            case Format::PE: parsePE(data, info, limits); break;
            case Format::ELF: parseELF(data, info, limits); break;
            case Format::MachO: parseMachO(data, info, limits); break;
            default: break;
        }
    } catch (const ParseError& e) {
        info.error = e.what();
    } catch (const std::exception& e) {  // defensive: e.g. std::bad_alloc
        info.error = std::string("Internal error while parsing: ") + e.what();
    }
    if (info.format == Format::Unknown) info.format = fmt;

    report(progress, 85, "Section analysis");
    try {
        finalizeSections(data, info);
        runHeuristics(info);
    } catch (const std::exception& e) {
        info.warnings.push_back(std::string("Post-processing failed: ") + e.what());
    }
    report(progress, 100, "Done");
    return info;
}

AnalysisResult analyzeFile(const std::filesystem::path& path, const Limits& limits, const ProgressFn& progress) {
    AnalysisResult res;
    res.info.filePath = pathUtf8(path);
    res.info.fileName = pathUtf8(path.filename());

    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) {
        res.info.error = ec ? "Cannot access file: " + ec.message() : "Not a regular file.";
        return res;
    }
    const uint64_t size = std::filesystem::file_size(path, ec);
    if (ec) {
        res.info.error = "Cannot determine file size: " + ec.message();
        return res;
    }
    res.info.fileSize = size;
    if (size > limits.maxFileSize) {
        res.info.error = "File size " + humanSize(size) + " exceeds the configured limit of " +
                         humanSize(limits.maxFileSize) + ". The file was not read.";
        return res;
    }

    report(progress, 2, "Reading file");
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        res.info.error = "Cannot open file for reading.";
        return res;
    }
    auto buf = std::make_shared<std::vector<uint8_t>>();
    try {
        buf->resize(static_cast<size_t>(size));
    } catch (const std::bad_alloc&) {
        res.info.error = "Not enough memory to load the file.";
        return res;
    }
    in.read(reinterpret_cast<char*>(buf->data()), static_cast<std::streamsize>(size));
    if (static_cast<uint64_t>(in.gcount()) != size) {
        res.info.error = "Short read: the file changed or could not be fully read.";
        return res;
    }

    BinaryInfo parsed = analyzeBuffer(*buf, limits, progress);
    parsed.filePath = res.info.filePath;
    parsed.fileName = res.info.fileName;
    res.info = std::move(parsed);
    res.data = std::move(buf);
    return res;
}

}  // namespace xrl
