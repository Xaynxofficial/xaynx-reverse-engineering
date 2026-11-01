#pragma once
// Self-contained SHA-256 (FIPS 180-4). Verified against published test vectors in tests/.
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace xrl {

class Sha256 {
public:
    Sha256();
    void update(std::span<const uint8_t> data);
    std::array<uint8_t, 32> finish();  // the object must not be reused afterwards

    static std::string hexDigest(std::span<const uint8_t> data);

private:
    void block(const uint8_t* p);
    std::array<uint32_t, 8> h_;
    std::array<uint8_t, 64> buf_{};
    size_t bufLen_ = 0;
    uint64_t totalLen_ = 0;
};

}  // namespace xrl

