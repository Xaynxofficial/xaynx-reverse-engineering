#pragma once
// Small helpers shared across the core library.
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace xrl {

// "0x" + lowercase hex, zero padded to at least `width` digits.
std::string hex(uint64_t value, int width = 0);

// Lowercase hex dump without separators.
std::string hexBytes(std::span<const uint8_t> bytes);

// Shannon entropy in bits per byte (0..8). Empty input yields 0.
double shannonEntropy(std::span<const uint8_t> bytes);

// Human readable size, e.g. "1.50 MiB (1572864 bytes)".
std::string humanSize(uint64_t bytes);

// Parses "0x1F", "1f" (hex only with prefix or letters), or decimal text.
// Returns nullopt on empty input, junk characters, or overflow of uint64_t.
// Plain digit strings are decimal unless `defaultHex` is true.
std::optional<uint64_t> parseNumber(std::string_view text, bool defaultHex = false);

// Replaces control characters (which may come from hostile binaries) with '?'.
std::string sanitizeText(std::string_view s);

// UTF-8 representation of a path (std::filesystem::path::string() is lossy on Windows).
std::string pathUtf8(const std::filesystem::path& p);

// Current UTC time in ISO-8601 form.
std::string utcNowIso8601();

}  // namespace xrl
