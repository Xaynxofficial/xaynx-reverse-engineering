#include "xrl/diff.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "xrl/sha256.hpp"
#include "xrl/util.hpp"

namespace xrl {

const char* toString(DiffKind kind) {
    switch (kind) {
        case DiffKind::Equal: return "Equal";
        case DiffKind::Modified: return "Modified";
        case DiffKind::Inserted: return "Inserted";
        case DiffKind::Deleted: return "Deleted";
    }
    return "Unknown";
}

const char* toString(MetadataChangeType type) {
    switch (type) {
        case MetadataChangeType::Added: return "Added";
        case MetadataChangeType::Removed: return "Removed";
        case MetadataChangeType::Modified: return "Modified";
    }
    return "Unknown";
}

namespace {

constexpr size_t kBlockSize = 48;
constexpr size_t kMaxCoalesceGap = 8;
constexpr size_t kChunkSize = 64 * 1024;
constexpr size_t kMaxHashOccurrences = 4;
constexpr int kMaxRecursionDepth = 16;

uint64_t hashBlock(const uint8_t* p, size_t len) {
    // FNV-1a 64-bit hash
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

// Find the longest common block match between subA and subB
struct BlockMatch {
    size_t offA = 0;
    size_t offB = 0;
    size_t length = 0;
};

BlockMatch findLongestMatch(std::span<const uint8_t> subA, std::span<const uint8_t> subB) {
    BlockMatch best;
    if (subA.size() < kBlockSize || subB.size() < kBlockSize) return best;

    // Index blocks of subA (skipping overly repetitive hashes)
    std::unordered_map<uint64_t, std::vector<size_t>> indexA;
    const size_t step = kBlockSize;
    for (size_t i = 0; i + kBlockSize <= subA.size(); i += step) {
        const uint64_t h = hashBlock(subA.data() + i, kBlockSize);
        auto& list = indexA[h];
        if (list.size() < kMaxHashOccurrences) {
            list.push_back(i);
        }
    }

    // Search matches from subB
    for (size_t j = 0; j + kBlockSize <= subB.size(); j += step) {
        const uint64_t h = hashBlock(subB.data() + j, kBlockSize);
        auto it = indexA.find(h);
        if (it == indexA.end() || it->second.size() >= kMaxHashOccurrences) continue;

        for (size_t i : it->second) {
            if (std::memcmp(subA.data() + i, subB.data() + j, kBlockSize) != 0) continue;

            size_t matchLen = kBlockSize;
            while (i + matchLen < subA.size() && j + matchLen < subB.size() &&
                   subA[i + matchLen] == subB[j + matchLen]) {
                ++matchLen;
            }

            size_t backLen = 0;
            while (i > backLen && j > backLen &&
                   subA[i - 1 - backLen] == subB[j - 1 - backLen]) {
                ++backLen;
            }

            const size_t totalLen = matchLen + backLen;
            const size_t startA = i - backLen;
            const size_t startB = j - backLen;

            if (totalLen > best.length) {
                best.offA = startA;
                best.offB = startB;
                best.length = totalLen;
            }
        }
        if (best.length >= 2048) break; // Strong anchor found
    }
    return best;
}

// Recursive anchor-based diff for differing middle regions
void diffSubregions(std::span<const uint8_t> a, uint64_t baseA,
                    std::span<const uint8_t> b, uint64_t baseB,
                    std::vector<ByteDiffRange>& out,
                    const CancelFn& shouldCancel,
                    int depth = 0) {
    if (shouldCancel && shouldCancel()) return;
    if (a.empty() && b.empty()) return;

    if (a.empty()) {
        out.push_back({baseA, 0, baseB, b.size(), DiffKind::Inserted});
        return;
    }
    if (b.empty()) {
        out.push_back({baseA, a.size(), baseB, 0, DiffKind::Deleted});
        return;
    }

    if (depth >= kMaxRecursionDepth) {
        out.push_back({baseA, a.size(), baseB, b.size(), DiffKind::Modified});
        return;
    }

    // Search for a common block match
    BlockMatch match = findLongestMatch(a, b);
    if (match.length >= kBlockSize) {
        diffSubregions(a.subspan(0, match.offA), baseA,
                       b.subspan(0, match.offB), baseB,
                       out, shouldCancel, depth + 1);

        const size_t afterA = match.offA + match.length;
        const size_t afterB = match.offB + match.length;
        diffSubregions(a.subspan(afterA), baseA + afterA,
                       b.subspan(afterB), baseB + afterB,
                       out, shouldCancel, depth + 1);
    } else {
        out.push_back({baseA, a.size(), baseB, b.size(), DiffKind::Modified});
    }
}

// Linear scan for same-length spans
void diffEqualLength(std::span<const uint8_t> a, uint64_t baseA,
                     std::span<const uint8_t> b, uint64_t baseB,
                     std::vector<ByteDiffRange>& out,
                     const CancelFn& shouldCancel) {
    const size_t n = a.size();
    size_t i = 0;
    while (i < n) {
        if (shouldCancel && shouldCancel()) return;
        if (a[i] == b[i]) {
            ++i;
            continue;
        }

        const size_t start = i;
        size_t lastDiff = i;
        ++i;
        while (i < n) {
            if (a[i] != b[i]) {
                lastDiff = i;
            } else if (i - lastDiff > kMaxCoalesceGap) {
                break;
            }
            ++i;
        }

        const size_t diffLen = lastDiff - start + 1;
        out.push_back({baseA + start, diffLen, baseB + start, diffLen, DiffKind::Modified});
        i = lastDiff + 1;
    }
}

}  // namespace

std::vector<ByteDiffRange> computeByteDiff(std::span<const uint8_t> dataA,
                                           std::span<const uint8_t> dataB,
                                           const ProgressFn& progress,
                                           const CancelFn& shouldCancel) {
    std::vector<ByteDiffRange> out;
    const uint64_t sizeA = dataA.size();
    const uint64_t sizeB = dataB.size();

    if (progress) progress(10, "Comparing common prefixes");
    if (shouldCancel && shouldCancel()) return out;

    if (sizeA == 0 && sizeB == 0) return out;
    if (sizeA == 0) {
        out.push_back({0, 0, 0, sizeB, DiffKind::Inserted});
        return out;
    }
    if (sizeB == 0) {
        out.push_back({0, sizeA, 0, 0, DiffKind::Deleted});
        return out;
    }

    // 1. Common prefix
    size_t prefix = 0;
    const size_t minSize = static_cast<size_t>(std::min(sizeA, sizeB));
    while (prefix < minSize && dataA[prefix] == dataB[prefix]) {
        ++prefix;
    }

    if (prefix == sizeA && prefix == sizeB) {
        // Files are 100% identical
        if (progress) progress(100, "Done");
        return out;
    }

    // 2. Common suffix
    size_t suffix = 0;
    while (suffix + prefix < sizeA && suffix + prefix < sizeB &&
           dataA[sizeA - 1 - suffix] == dataB[sizeB - 1 - suffix]) {
        ++suffix;
    }

    const size_t midLenA = static_cast<size_t>(sizeA) - prefix - suffix;
    const size_t midLenB = static_cast<size_t>(sizeB) - prefix - suffix;

    if (progress) progress(30, "Analyzing differing byte spans");

    auto midA = dataA.subspan(prefix, midLenA);
    auto midB = dataB.subspan(prefix, midLenB);

    if (midLenA == 0 && midLenB > 0) {
        out.push_back({prefix, 0, prefix, midLenB, DiffKind::Inserted});
    } else if (midLenB == 0 && midLenA > 0) {
        out.push_back({prefix, midLenA, prefix, 0, DiffKind::Deleted});
    } else if (midLenA == midLenB) {
        diffEqualLength(midA, prefix, midB, prefix, out, shouldCancel);
    } else {
        diffSubregions(midA, prefix, midB, prefix, out, shouldCancel);
    }

    // Sort by offset
    std::sort(out.begin(), out.end(), [](const ByteDiffRange& l, const ByteDiffRange& r) {
        return l.offsetA < r.offsetA || (l.offsetA == r.offsetA && l.offsetB < r.offsetB);
    });

    if (progress) progress(100, "Done");
    return out;
}

std::vector<ByteDiffRange> computeFileByteDiff(const std::filesystem::path& pathA,
                                               const std::filesystem::path& pathB,
                                               uint64_t sizeA,
                                               uint64_t sizeB,
                                               const ProgressFn& progress,
                                               const CancelFn& shouldCancel,
                                               std::string* error) {
    if (error) error->clear();
    auto fail = [&](const char* message) {
        if (error) *error = message;
        return std::vector<ByteDiffRange>{};
    };

    std::error_code initialSizeErrorA, initialSizeErrorB;
    const uint64_t initialSizeA = std::filesystem::file_size(pathA, initialSizeErrorA);
    const uint64_t initialSizeB = std::filesystem::file_size(pathB, initialSizeErrorB);
    if (initialSizeErrorA || initialSizeErrorB) return fail("Cannot determine file size for byte comparison.");
    if (initialSizeA != sizeA || initialSizeB != sizeB) return fail("A file changed size before comparison.");
    if (sizeA == 0 && sizeB == 0) return {};
    if (sizeA == 0) return {{0, 0, 0, sizeB, DiffKind::Inserted}};
    if (sizeB == 0) return {{0, sizeA, 0, 0, DiffKind::Deleted}};

    // If both files are small enough to buffer safely (<= 32 MiB each), in-memory diff is faster
    constexpr uint64_t kMaxBufferDiff = 32ull * 1024 * 1024;
    if (sizeA <= kMaxBufferDiff && sizeB <= kMaxBufferDiff) {
        std::vector<uint8_t> bufA(static_cast<size_t>(sizeA));
        std::vector<uint8_t> bufB(static_cast<size_t>(sizeB));

        std::ifstream inA(pathA, std::ios::binary);
        std::ifstream inB(pathB, std::ios::binary);
        if (!inA || !inB) return fail("Cannot open files for byte comparison.");

        inA.read(reinterpret_cast<char*>(bufA.data()), static_cast<std::streamsize>(sizeA));
        inB.read(reinterpret_cast<char*>(bufB.data()), static_cast<std::streamsize>(sizeB));
        if (static_cast<uint64_t>(inA.gcount()) != sizeA ||
            static_cast<uint64_t>(inB.gcount()) != sizeB) {
            return fail("Short read: a file changed or could not be fully read during comparison.");
        }
        std::error_code sizeErrorA, sizeErrorB;
        if (std::filesystem::file_size(pathA, sizeErrorA) != sizeA ||
            std::filesystem::file_size(pathB, sizeErrorB) != sizeB || sizeErrorA || sizeErrorB) {
            return fail("A file changed size during comparison.");
        }
        return computeByteDiff(bufA, bufB, progress, shouldCancel);
    }

    // For large files of equal size, stream chunks linearly in O(1) memory
    if (sizeA == sizeB) {
        std::ifstream inA(pathA, std::ios::binary);
        std::ifstream inB(pathB, std::ios::binary);
        if (!inA || !inB) return fail("Cannot open files for byte comparison.");

        std::vector<uint8_t> chunkA(kChunkSize);
        std::vector<uint8_t> chunkB(kChunkSize);
        std::vector<ByteDiffRange> out;

        uint64_t processed = 0;
        while (processed < sizeA) {
            if (shouldCancel && shouldCancel()) return fail("File comparison cancelled.");
            const size_t toRead = static_cast<size_t>(std::min<uint64_t>(kChunkSize, sizeA - processed));
            inA.read(reinterpret_cast<char*>(chunkA.data()), static_cast<std::streamsize>(toRead));
            inB.read(reinterpret_cast<char*>(chunkB.data()), static_cast<std::streamsize>(toRead));
            if (static_cast<size_t>(inA.gcount()) != toRead ||
                static_cast<size_t>(inB.gcount()) != toRead) {
                return fail("Short read: a file changed or could not be fully read during comparison.");
            }

            diffEqualLength({chunkA.data(), toRead}, processed,
                            {chunkB.data(), toRead}, processed,
                            out, shouldCancel);

            processed += toRead;
            if (progress && sizeA > 0) {
                const int pct = static_cast<int>(
                    (static_cast<long double>(processed) * 100.0L) / static_cast<long double>(sizeA));
                progress(pct, "Streaming chunk comparison");
            }
        }
        std::error_code sizeErrorA, sizeErrorB;
        const uint64_t finalSizeA = std::filesystem::file_size(pathA, sizeErrorA);
        const uint64_t finalSizeB = std::filesystem::file_size(pathB, sizeErrorB);
        if (sizeErrorA || sizeErrorB || finalSizeA != sizeA || finalSizeB != sizeB) {
            return fail("A file changed size during comparison.");
        }
        if (inA.bad() || inB.bad()) return fail("An I/O error occurred during byte comparison.");
        return out;
    }

    // For large unequal files compare the common offset-aligned range in bounded chunks,
    // then report the unmatched tail without pretending the unread bytes were compared.
    std::ifstream inA(pathA, std::ios::binary);
    std::ifstream inB(pathB, std::ios::binary);
    if (!inA || !inB) return fail("Cannot open files for byte comparison.");

    std::vector<uint8_t> chunkA(kChunkSize);
    std::vector<uint8_t> chunkB(kChunkSize);
    std::vector<ByteDiffRange> out;
    const uint64_t commonSize = std::min(sizeA, sizeB);
    uint64_t processed = 0;
    while (processed < commonSize) {
        if (shouldCancel && shouldCancel()) return fail("File comparison cancelled.");
        const size_t toRead = static_cast<size_t>(std::min<uint64_t>(kChunkSize, commonSize - processed));
        inA.read(reinterpret_cast<char*>(chunkA.data()), static_cast<std::streamsize>(toRead));
        inB.read(reinterpret_cast<char*>(chunkB.data()), static_cast<std::streamsize>(toRead));
        if (static_cast<size_t>(inA.gcount()) != toRead ||
            static_cast<size_t>(inB.gcount()) != toRead) {
            return fail("Short read: a file changed or could not be fully read during comparison.");
        }
        diffEqualLength({chunkA.data(), toRead}, processed,
                        {chunkB.data(), toRead}, processed, out, shouldCancel);
        if (shouldCancel && shouldCancel()) return fail("File comparison cancelled.");
        processed += toRead;
        if (progress) {
            const int pct = static_cast<int>(
                (static_cast<long double>(processed) * 100.0L) / static_cast<long double>(commonSize));
            progress(pct, "Streaming unequal-size comparison");
        }
    }

    if (sizeA > commonSize) out.push_back({commonSize, sizeA - commonSize, commonSize, 0, DiffKind::Deleted});
    if (sizeB > commonSize) out.push_back({commonSize, 0, commonSize, sizeB - commonSize, DiffKind::Inserted});
    std::error_code sizeErrorA, sizeErrorB;
    const uint64_t finalSizeA = std::filesystem::file_size(pathA, sizeErrorA);
    const uint64_t finalSizeB = std::filesystem::file_size(pathB, sizeErrorB);
    if (sizeErrorA || sizeErrorB || finalSizeA != sizeA || finalSizeB != sizeB) {
        return fail("A file changed size during comparison.");
    }
    if (inA.bad() || inB.bad()) return fail("An I/O error occurred during byte comparison.");
    return out;
}

// ---------------------------------------------------------------------------- Metadata
std::vector<MetadataDiffItem> compareMetadata(const BinaryInfo& a, const BinaryInfo& b) {
    std::vector<MetadataDiffItem> out;

    auto add = [&](std::string cat, std::string key, MetadataChangeType ch,
                   std::string oldV, std::string newV,
                   std::optional<uint64_t> offA = std::nullopt,
                   std::optional<uint64_t> offB = std::nullopt,
                   std::string note = {}) {
        out.push_back({std::move(cat), std::move(key), ch, std::move(oldV), std::move(newV), offA, offB, std::move(note)});
    };

    // 1. Container and Architecture
    if (a.format != b.format) {
        add("Header", "Format", MetadataChangeType::Modified, a.formatName, b.formatName);
    }
    if (a.arch != b.arch || a.archName != b.archName) {
        add("Header", "Architecture", MetadataChangeType::Modified, a.archName, b.archName);
    }
    if (a.bits != b.bits) {
        add("Header", "Bitness", MetadataChangeType::Modified,
            a.bits ? std::to_string(a.bits) + "-bit" : "unknown",
            b.bits ? std::to_string(b.bits) + "-bit" : "unknown");
    }
    if (a.endian != b.endian) {
        add("Header", "Endianness", MetadataChangeType::Modified, toString(a.endian), toString(b.endian));
    }
    if (a.entryPoint != b.entryPoint) {
        add("Header", "Entry point", MetadataChangeType::Modified,
            a.entryPoint ? hex(*a.entryPoint) : "(none)",
            b.entryPoint ? hex(*b.entryPoint) : "(none)",
            a.entryPoint ? a.virtualToFileOffset(*a.entryPoint) : std::nullopt,
            b.entryPoint ? b.virtualToFileOffset(*b.entryPoint) : std::nullopt);
    }

    // 2. Sections
    if (a.sectionsParsed || b.sectionsParsed) {
        std::unordered_map<std::string, const Section*> mapA;
        for (const auto& s : a.sections) {
            const std::string k = s.segment.empty() ? s.name : s.segment + "/" + s.name;
            mapA[k] = &s;
        }

        std::unordered_set<std::string> seenB;
        for (const auto& sB : b.sections) {
            const std::string k = sB.segment.empty() ? sB.name : sB.segment + "/" + sB.name;
            seenB.insert(k);
            auto itA = mapA.find(k);
            if (itA == mapA.end()) {
                add("Section", k, MetadataChangeType::Added, "(absent)",
                    "VA " + hex(sB.virtualAddress) + ", size " + std::to_string(sB.fileSize),
                    std::nullopt, sB.fileOffset);
            } else {
                const auto& sA = *itA->second;
                std::string changes;
                if (sA.virtualSize != sB.virtualSize || sA.fileSize != sB.fileSize) {
                    changes += "size: " + std::to_string(sA.fileSize) + " -> " + std::to_string(sB.fileSize) + "; ";
                }
                if (sA.virtualAddress != sB.virtualAddress) {
                    changes += "VA: " + hex(sA.virtualAddress) + " -> " + hex(sB.virtualAddress) + "; ";
                }
                const auto permStr = [](const Section& s) {
                    return std::string(s.readable ? "r" : "-") + (s.writable ? "w" : "-") + (s.executable ? "x" : "-");
                };
                if (permStr(sA) != permStr(sB)) {
                    changes += "perms: " + permStr(sA) + " -> " + permStr(sB) + "; ";
                }
                if (sA.entropy && sB.entropy && std::abs(*sA.entropy - *sB.entropy) >= 0.1) {
                    char ebuf[64];
                    std::snprintf(ebuf, sizeof ebuf, "entropy: %.2f -> %.2f; ", *sA.entropy, *sB.entropy);
                    changes += ebuf;
                }
                if (!changes.empty()) {
                    add("Section", k, MetadataChangeType::Modified, permStr(sA), permStr(sB),
                        sA.fileOffset, sB.fileOffset, changes);
                }
            }
        }
        for (const auto& [k, pA] : mapA) {
            if (!seenB.count(k)) {
                add("Section", k, MetadataChangeType::Removed,
                    "VA " + hex(pA->virtualAddress) + ", size " + std::to_string(pA->fileSize),
                    "(removed)", pA->fileOffset, std::nullopt);
            }
        }
    }

    // 3. Imports
    if (a.imports.state == Availability::Present || b.imports.state == Availability::Present) {
        std::unordered_set<std::string> impA, impB;
        for (const auto& i : a.imports.items) impA.insert(i.library.empty() ? i.name : i.library + "!" + i.name);
        for (const auto& i : b.imports.items) impB.insert(i.library.empty() ? i.name : i.library + "!" + i.name);

        for (const auto& i : impB) {
            if (!impA.count(i)) add("Import", i, MetadataChangeType::Added, "(none)", i);
        }
        for (const auto& i : impA) {
            if (!impB.count(i)) add("Import", i, MetadataChangeType::Removed, i, "(removed)");
        }
    } else if (a.imports.state != b.imports.state) {
        add("Import", "Availability", MetadataChangeType::Modified, toString(a.imports.state), toString(b.imports.state));
    }

    // 4. Exports
    if (a.exports.state == Availability::Present || b.exports.state == Availability::Present) {
        std::unordered_map<std::string, const Symbol*> expA;
        for (const auto& e : a.exports.items) expA[e.name] = &e;

        std::unordered_set<std::string> seenExpB;
        for (const auto& eB : b.exports.items) {
            seenExpB.insert(eB.name);
            auto itA = expA.find(eB.name);
            if (itA == expA.end()) {
                add("Export", eB.name, MetadataChangeType::Added, "(none)",
                    eB.address ? hex(*eB.address) : eB.type, std::nullopt,
                    eB.address ? b.virtualToFileOffset(*eB.address) : std::nullopt);
            } else {
                const auto& eA = *itA->second;
                if (eA.address != eB.address) {
                    add("Export", eB.name, MetadataChangeType::Modified,
                        eA.address ? hex(*eA.address) : "(unmapped)",
                        eB.address ? hex(*eB.address) : "(unmapped)",
                        eA.address ? a.virtualToFileOffset(*eA.address) : std::nullopt,
                        eB.address ? b.virtualToFileOffset(*eB.address) : std::nullopt);
                }
            }
        }
        for (const auto& [name, eA] : expA) {
            if (!seenExpB.count(name)) {
                add("Export", name, MetadataChangeType::Removed,
                    eA->address ? hex(*eA->address) : eA->type, "(removed)",
                    eA->address ? a.virtualToFileOffset(*eA->address) : std::nullopt, std::nullopt);
            }
        }
    } else if (a.exports.state != b.exports.state) {
        add("Export", "Availability", MetadataChangeType::Modified, toString(a.exports.state), toString(b.exports.state));
    }

    // 5. Libraries
    if (a.libraries.state == Availability::Present || b.libraries.state == Availability::Present) {
        std::unordered_set<std::string> libA(a.libraries.items.begin(), a.libraries.items.end());
        std::unordered_set<std::string> libB(b.libraries.items.begin(), b.libraries.items.end());
        for (const auto& l : libB) if (!libA.count(l)) add("Library", l, MetadataChangeType::Added, "(none)", l);
        for (const auto& l : libA) if (!libB.count(l)) add("Library", l, MetadataChangeType::Removed, l, "(removed)");
    }

    return out;
}

// ---------------------------------------------------------------------------- Pipeline
BinaryDiffResult compareFiles(const std::filesystem::path& pathA,
                              const std::filesystem::path& pathB,
                              const Limits& limits,
                              const ProgressFn& progress,
                              const CancelFn& shouldCancel) {
    BinaryDiffResult res;

    if (progress) progress(5, "Analyzing baseline file");
    auto anaA = analyzeFile(pathA, limits, progress);
    if (shouldCancel && shouldCancel()) return res;

    if (progress) progress(25, "Analyzing comparison file");
    auto anaB = analyzeFile(pathB, limits, progress);
    if (shouldCancel && shouldCancel()) return res;

    res.infoA = std::move(anaA.info);
    res.infoB = std::move(anaB.info);

    if (!anaA.data && res.infoA.fileSize <= limits.maxFileSize) {
        res.error = "Baseline file error: " + res.infoA.error;
        return res;
    }
    if (!anaB.data && res.infoB.fileSize <= limits.maxFileSize) {
        res.error = "Comparison file error: " + res.infoB.error;
        return res;
    }

    if (anaA.data && anaB.data) {
        return compareBuffers(*anaA.data, *anaB.data, res.infoA, res.infoB, progress, shouldCancel);
    }

    // Compute disk-based byte diff
    if (progress) progress(50, "Computing byte differences");
    std::string diffError;
    res.byteDiffs = computeFileByteDiff(pathA, pathB, res.infoA.fileSize, res.infoB.fileSize,
                                        progress, shouldCancel, &diffError);
    if (!diffError.empty()) {
        res.error = std::move(diffError);
        return res;
    }
    if (shouldCancel && shouldCancel()) {
        res.error = "File comparison cancelled.";
        return res;
    }
    if (progress) progress(85, "Comparing metadata structures");
    res.metadataDiffs = compareMetadata(res.infoA, res.infoB);

    // Summary
    res.summary.totalDiffRegions = res.byteDiffs.size();
    for (const auto& d : res.byteDiffs) {
        switch (d.kind) {
            case DiffKind::Modified: res.summary.totalModifiedBytes += std::max(d.sizeA, d.sizeB); break;
            case DiffKind::Inserted: res.summary.totalInsertedBytes += d.sizeB; break;
            case DiffKind::Deleted: res.summary.totalDeletedBytes += d.sizeA; break;
            default: break;
        }
    }
    for (const auto& m : res.metadataDiffs) {
        switch (m.change) {
            case MetadataChangeType::Added: res.summary.addedMetadataCount++; break;
            case MetadataChangeType::Removed: res.summary.removedMetadataCount++; break;
            case MetadataChangeType::Modified: res.summary.modifiedMetadataCount++; break;
        }
    }
    res.summary.identical = (res.byteDiffs.empty() && res.metadataDiffs.empty() &&
                             res.infoA.sha256 == res.infoB.sha256 && res.infoA.fileSize == res.infoB.fileSize);
    res.ok = true;
    if (progress) progress(100, "Comparison complete");
    return res;
}

BinaryDiffResult compareBuffers(std::span<const uint8_t> dataA,
                                std::span<const uint8_t> dataB,
                                const BinaryInfo& infoA,
                                const BinaryInfo& infoB,
                                const ProgressFn& progress,
                                const CancelFn& shouldCancel) {
    BinaryDiffResult res;
    res.infoA = infoA;
    res.infoB = infoB;

    if (progress) progress(40, "Computing byte diffs");
    res.byteDiffs = computeByteDiff(dataA, dataB, progress, shouldCancel);
    if (shouldCancel && shouldCancel()) return res;

    if (progress) progress(85, "Comparing metadata");
    res.metadataDiffs = compareMetadata(infoA, infoB);

    res.summary.totalDiffRegions = res.byteDiffs.size();
    for (const auto& d : res.byteDiffs) {
        switch (d.kind) {
            case DiffKind::Modified: res.summary.totalModifiedBytes += std::max(d.sizeA, d.sizeB); break;
            case DiffKind::Inserted: res.summary.totalInsertedBytes += d.sizeB; break;
            case DiffKind::Deleted: res.summary.totalDeletedBytes += d.sizeA; break;
            default: break;
        }
    }
    for (const auto& m : res.metadataDiffs) {
        switch (m.change) {
            case MetadataChangeType::Added: res.summary.addedMetadataCount++; break;
            case MetadataChangeType::Removed: res.summary.removedMetadataCount++; break;
            case MetadataChangeType::Modified: res.summary.modifiedMetadataCount++; break;
        }
    }
    res.summary.identical = (res.byteDiffs.empty() && res.metadataDiffs.empty() &&
                             infoA.sha256 == infoB.sha256 && dataA.size() == dataB.size());
    res.ok = true;
    if (progress) progress(100, "Comparison complete");
    return res;
}

// ---------------------------------------------------------------------------- Reports
Json buildDiffJsonReport(const BinaryDiffResult& diff) {
    Json root = Json::object();
    root.set("schema_version", "1.0");
    Json tool = Json::object();
    tool.set("name", "Xaynx Reverse Lab");
    tool.set("version", XRL_VERSION);
    tool.set("component", "Binary Diff & Comparison Engine");
    root.set("tool", std::move(tool));
    root.set("generated_utc", utcNowIso8601());

    auto fileObj = [](const BinaryInfo& info) {
        Json f = Json::object();
        f.set("name", info.fileName);
        f.set("path", info.filePath);
        f.set("size_bytes", info.fileSize);
        f.set("sha256", info.sha256.empty() ? Json(nullptr) : Json(info.sha256));
        f.set("format", info.formatName);
        f.set("architecture", info.archName);
        f.set("bits", info.bits ? Json(info.bits) : Json(nullptr));
        f.set("entry_point", info.entryPoint ? Json(hex(*info.entryPoint)) : Json(nullptr));
        return f;
    };
    root.set("baseline", fileObj(diff.infoA));
    root.set("comparison", fileObj(diff.infoB));

    Json sum = Json::object();
    sum.set("identical", diff.summary.identical);
    sum.set("total_diff_regions", static_cast<int64_t>(diff.summary.totalDiffRegions));
    sum.set("total_modified_bytes", static_cast<int64_t>(diff.summary.totalModifiedBytes));
    sum.set("total_inserted_bytes", static_cast<int64_t>(diff.summary.totalInsertedBytes));
    sum.set("total_deleted_bytes", static_cast<int64_t>(diff.summary.totalDeletedBytes));
    sum.set("added_metadata_count", static_cast<int64_t>(diff.summary.addedMetadataCount));
    sum.set("removed_metadata_count", static_cast<int64_t>(diff.summary.removedMetadataCount));
    sum.set("modified_metadata_count", static_cast<int64_t>(diff.summary.modifiedMetadataCount));
    root.set("summary", std::move(sum));

    Json byteArr = Json::array();
    for (const auto& b : diff.byteDiffs) {
        Json j = Json::object();
        j.set("offset_a", hex(b.offsetA));
        j.set("size_a", b.sizeA);
        j.set("offset_b", hex(b.offsetB));
        j.set("size_b", b.sizeB);
        j.set("kind", toString(b.kind));
        byteArr.push(std::move(j));
    }
    root.set("byte_differences", std::move(byteArr));

    Json metaArr = Json::array();
    for (const auto& m : diff.metadataDiffs) {
        Json j = Json::object();
        j.set("category", m.category);
        j.set("key", m.key);
        j.set("change", toString(m.change));
        j.set("old_value", m.oldValue);
        j.set("new_value", m.newValue);
        if (m.offsetA) j.set("offset_a", hex(*m.offsetA));
        if (m.offsetB) j.set("offset_b", hex(*m.offsetB));
        if (!m.note.empty()) j.set("note", m.note);
        metaArr.push(std::move(j));
    }
    root.set("metadata_differences", std::move(metaArr));
    return root;
}

std::string renderDiffJsonReport(const BinaryDiffResult& diff) {
    return buildDiffJsonReport(diff).dump(2) + "\n";
}

std::string renderDiffTextReport(const BinaryDiffResult& diff) {
    std::ostringstream o;
    o << "Xaynx Reverse Lab " << XRL_VERSION << " - Binary Comparison Report\n";
    o << "Generated (UTC): " << utcNowIso8601() << "\n\n";

    o << "== Baseline File (A) ==\n";
    o << "Name:    " << diff.infoA.fileName << "\nPath:    " << diff.infoA.filePath << "\n";
    o << "Size:    " << humanSize(diff.infoA.fileSize) << "\nSHA-256: " << diff.infoA.sha256 << "\n";
    o << "Format:  " << diff.infoA.formatName << " (" << diff.infoA.archName << ")\n\n";

    o << "== Comparison File (B) ==\n";
    o << "Name:    " << diff.infoB.fileName << "\nPath:    " << diff.infoB.filePath << "\n";
    o << "Size:    " << humanSize(diff.infoB.fileSize) << "\nSHA-256: " << diff.infoB.sha256 << "\n";
    o << "Format:  " << diff.infoB.formatName << " (" << diff.infoB.archName << ")\n\n";

    o << "== Summary ==\n";
    o << "Result:             " << (diff.summary.identical ? "IDENTICAL" : "DIFFERENT") << "\n";
    o << "Diff regions:       " << diff.summary.totalDiffRegions << "\n";
    o << "Modified bytes:     " << diff.summary.totalModifiedBytes << "\n";
    o << "Inserted bytes:     " << diff.summary.totalInsertedBytes << "\n";
    o << "Deleted bytes:      " << diff.summary.totalDeletedBytes << "\n";
    o << "Metadata changes:   " << (diff.summary.addedMetadataCount + diff.summary.removedMetadataCount + diff.summary.modifiedMetadataCount) << "\n\n";

    o << "== Byte Differences (" << diff.byteDiffs.size() << " regions) ==\n";
    for (size_t i = 0; i < std::min<size_t>(diff.byteDiffs.size(), 500); ++i) {
        const auto& d = diff.byteDiffs[i];
        o << "  [" << toString(d.kind) << "] ";
        o << "A:" << hex(d.offsetA) << " (+" << d.sizeA << ") <-> ";
        o << "B:" << hex(d.offsetB) << " (+" << d.sizeB << ")\n";
    }
    if (diff.byteDiffs.size() > 500) {
        o << "  ... truncated at 500 regions\n";
    }
    o << "\n";

    o << "== Metadata Differences (" << diff.metadataDiffs.size() << " changes) ==\n";
    for (const auto& m : diff.metadataDiffs) {
        o << "  [" << m.category << "] " << m.key << " (" << toString(m.change) << ")\n";
        o << "      Old: " << m.oldValue << "\n";
        o << "      New: " << m.newValue << "\n";
        if (m.offsetA || m.offsetB) {
            o << "      Offsets: ";
            if (m.offsetA) o << "A=" << hex(*m.offsetA) << " ";
            if (m.offsetB) o << "B=" << hex(*m.offsetB);
            o << "\n";
        }
        if (!m.note.empty()) o << "      Note: " << m.note << "\n";
    }
    return o.str();
}

}  // namespace xrl
