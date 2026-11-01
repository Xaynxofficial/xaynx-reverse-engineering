#include <gtest/gtest.h>

#include <limits>

#include "xrl/json.hpp"

using namespace xrl;

TEST(Json, RoundTripPreservesStructure) {
    Json o = Json::object();
    o.set("s", "he said \"hi\"\n\t\\");
    o.set("i", int64_t{-42});
    o.set("d", 1.5);
    o.set("b", true);
    o.set("n", nullptr);
    Json a = Json::array();
    a.push(1); a.push("x"); a.push(Json::object());
    o.set("a", std::move(a));

    for (int indent : {-1, 2}) {
        const auto r = Json::parse(o.dump(indent));
        ASSERT_TRUE(r.value) << r.error;
        EXPECT_EQ(r.value->find("s")->asString(), "he said \"hi\"\n\t\\");
        EXPECT_EQ(r.value->find("i")->asInt(), -42);
        EXPECT_DOUBLE_EQ(r.value->find("d")->asDouble(), 1.5);
        EXPECT_TRUE(r.value->find("b")->asBool());
        EXPECT_TRUE(r.value->find("n")->isNull());
        EXPECT_EQ(r.value->find("a")->size(), 3u);
    }
}

TEST(Json, InvalidUtf8IsReplacedSoOutputStaysValid) {
    Json o = Json::object();
    o.set("name", std::string("ok\xFF\xC3\x28-end"));  // 0xFF and a broken 2-byte sequence
    const auto text = o.dump();
    const auto r = Json::parse(text);
    ASSERT_TRUE(r.value) << r.error;
    const std::string v = r.value->find("name")->asString();
    EXPECT_NE(v.find("\xEF\xBF\xBD"), std::string::npos);
    EXPECT_EQ(v.substr(0, 2), "ok");
}

TEST(Json, ControlCharactersAreEscaped) {
    const std::string text = Json(std::string("a\x01" "b")).dump(-1);
    EXPECT_EQ(text, "\"a\\u0001b\"");
}

TEST(Json, NonFiniteDoublesBecomeNull) {
    EXPECT_EQ(Json(std::numeric_limits<double>::infinity()).dump(-1), "null");
}

TEST(Json, LargeUnsignedFallsBackToDouble) {
    EXPECT_EQ(Json(uint64_t{5}).dump(-1), "5");
    EXPECT_EQ(Json(UINT64_MAX).type(), Json::Type::Double);
}

TEST(Json, ParserRejectsMalformedInput) {
    for (const char* bad : {"", "{", "[1,]", "{\"a\":}", "{'a':1}", "[1 2]", "01", "\"abc", "tru", "{\"a\":1} x",
                            "\"\\ud800\"", "[\"\x01\"]", "{\"a\" 1}", "1e", "-"}) {
        const auto r = Json::parse(bad);
        EXPECT_FALSE(r.value) << "accepted: " << bad;
        EXPECT_FALSE(r.error.empty());
    }
}

TEST(Json, ParserRejectsExcessiveNesting) {
    const std::string deep(1000, '[');
    EXPECT_FALSE(Json::parse(deep + std::string(1000, ']')).value);
}

TEST(Json, ParsesUnicodeEscapesAndSurrogates) {
    const auto r = Json::parse("\"\\u00e9\\ud83d\\ude00\"");
    ASSERT_TRUE(r.value);
    EXPECT_EQ(r.value->asString(), "\xC3\xA9\xF0\x9F\x98\x80");
}
