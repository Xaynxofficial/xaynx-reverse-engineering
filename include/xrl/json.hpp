#pragma once
// Minimal JSON value, serializer and strict parser (RFC 8259 subset: no comments, depth-limited).
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace xrl {

class Json;
struct JsonParseResult;

class Json {
public:
    enum class Type { Null, Bool, Int, Double, String, Array, Object };

    Json() = default;
    Json(std::nullptr_t) {}
    Json(bool v) : type_(Type::Bool), b_(v) {}
    Json(int v) : type_(Type::Int), i_(v) {}
    Json(int64_t v) : type_(Type::Int), i_(v) {}
    Json(uint64_t v);  // values above INT64_MAX are stored as double (lossy); prefer hex strings for addresses
    Json(double v) : type_(Type::Double), d_(v) {}
    Json(const char* v) : type_(Type::String), s_(v) {}
    Json(std::string v) : type_(Type::String), s_(std::move(v)) {}

    static Json array() { Json j; j.type_ = Type::Array; return j; }
    static Json object() { Json j; j.type_ = Type::Object; return j; }

    Type type() const { return type_; }
    bool isNull() const { return type_ == Type::Null; }
    bool isObject() const { return type_ == Type::Object; }
    bool isArray() const { return type_ == Type::Array; }
    bool isString() const { return type_ == Type::String; }
    bool isNumber() const { return type_ == Type::Int || type_ == Type::Double; }

    bool asBool(bool def = false) const { return type_ == Type::Bool ? b_ : def; }
    int64_t asInt(int64_t def = 0) const;
    double asDouble(double def = 0) const;
    const std::string& asString() const { return s_; }  // empty if not a string

    // Array / object building
    Json& push(Json v);
    Json& set(std::string key, Json v);  // appends; does not de-duplicate

    // Access
    const std::vector<Json>& items() const { return arr_; }
    const std::vector<std::pair<std::string, Json>>& members() const { return obj_; }
    const Json* find(std::string_view key) const;  // nullptr when missing / not an object
    size_t size() const { return type_ == Type::Array ? arr_.size() : obj_.size(); }

    // indent < 0 -> compact
    std::string dump(int indent = 2) const;

    using ParseResult = struct JsonParseResult;
    static ParseResult parse(std::string_view text);

private:
    void dumpTo(std::string& out, int indent, int depth) const;

    Type type_ = Type::Null;
    bool b_ = false;
    int64_t i_ = 0;
    double d_ = 0;
    std::string s_;
    std::vector<Json> arr_;
    std::vector<std::pair<std::string, Json>> obj_;
};

struct JsonParseResult {
    std::optional<Json> value;
    std::string error;
};

}  // namespace xrl
