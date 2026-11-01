#pragma once
// Per-format parsers. Each throws xrl::ParseError on fatal structural problems; whatever was
// parsed up to that point remains in `info`, so callers can still show partial results.
#include <span>

#include "xrl/analyzer.hpp"
#include "xrl/byte_reader.hpp"
#include "xrl/types.hpp"

namespace xrl {

void parsePE(std::span<const uint8_t> data, BinaryInfo& info, const Limits& limits);
void parseELF(std::span<const uint8_t> data, BinaryInfo& info, const Limits& limits);
void parseMachO(std::span<const uint8_t> data, BinaryInfo& info, const Limits& limits);

}  // namespace xrl

