#include <gtest/gtest.h>

#include <string>

#include "xrl/sha256.hpp"
#include "xrl/util.hpp"

using namespace xrl;

static std::string sha(const std::string& s) {
    return Sha256::hexDigest({reinterpret_cast<const uint8_t*>(s.data()), s.size()});
}

TEST(Sha256, EmptyInput) {
    EXPECT_EQ(sha(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}
TEST(Sha256, Abc) {
    EXPECT_EQ(sha("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}
TEST(Sha256, TwoBlockVector) {
    EXPECT_EQ(sha("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}
TEST(Sha256, MillionAsStreamedInOddChunks) {
    Sha256 s;
    const std::string chunk(997, 'a');
    size_t total = 0;
    while (total + chunk.size() <= 1'000'000) {
        s.update({reinterpret_cast<const uint8_t*>(chunk.data()), chunk.size()});
        total += chunk.size();
    }
    const std::string rest(1'000'000 - total, 'a');
    s.update({reinterpret_cast<const uint8_t*>(rest.data()), rest.size()});
    EXPECT_EQ(hexBytes(s.finish()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(Util, ParseNumberVariants) {
    EXPECT_EQ(parseNumber("0x1F"), 0x1Fu);
    EXPECT_EQ(parseNumber("  42 "), 42u);
    EXPECT_EQ(parseNumber("1f", true), 0x1Fu);
    EXPECT_EQ(parseNumber("401000h"), 0x401000u);
    EXPECT_EQ(parseNumber("0xFFFFFFFFFFFFFFFF"), UINT64_MAX);
}
TEST(Util, ParseNumberRejectsBadInput) {
    EXPECT_FALSE(parseNumber(""));
    EXPECT_FALSE(parseNumber("0x"));
    EXPECT_FALSE(parseNumber("12ab"));              // hex digits in a decimal string
    EXPECT_FALSE(parseNumber("-1"));
    EXPECT_FALSE(parseNumber("0x1FFFFFFFFFFFFFFFF"));  // overflow of uint64
    EXPECT_FALSE(parseNumber("18446744073709551616"));
}
TEST(Util, EntropyBounds) {
    std::vector<uint8_t> zeros(1024, 0);
    EXPECT_DOUBLE_EQ(shannonEntropy(zeros), 0.0);
    std::vector<uint8_t> all;
    for (int r = 0; r < 4; ++r) for (int i = 0; i < 256; ++i) all.push_back(static_cast<uint8_t>(i));
    EXPECT_NEAR(shannonEntropy(all), 8.0, 1e-9);
    EXPECT_DOUBLE_EQ(shannonEntropy({}), 0.0);
}
TEST(Util, HexFormatting) {
    EXPECT_EQ(hex(0), "0x0");
    EXPECT_EQ(hex(255, 4), "0x00ff");
    EXPECT_EQ(sanitizeText(std::string("a\x01" "b\n")), "a?b?");
}

