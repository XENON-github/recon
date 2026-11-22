// Small strict JSON (RFC 8259) parser for reading scan baselines. No dependencies, no exceptions,
// bounded recursion depth, validates UTF-8, rejects trailing garbage and control characters.
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace recon::json {

class Value {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    [[nodiscard]] Type type() const noexcept { return type_; }
    [[nodiscard]] bool is_object() const noexcept { return type_ == Type::Object; }
    [[nodiscard]] bool is_array() const noexcept { return type_ == Type::Array; }
    [[nodiscard]] bool is_string() const noexcept { return type_ == Type::String; }
    [[nodiscard]] bool is_number() const noexcept { return type_ == Type::Number; }

    [[nodiscard]] bool as_bool(bool def = false) const noexcept { return type_ == Type::Bool ? bool_ : def; }
    [[nodiscard]] double as_number(double def = 0.0) const noexcept { return type_ == Type::Number ? num_ : def; }
    [[nodiscard]] const std::string& as_string() const noexcept { return type_ == Type::String ? str_ : empty_; }
    [[nodiscard]] const std::vector<Value>& items() const noexcept { return type_ == Type::Array ? vals_ : no_vals_; }
    [[nodiscard]] std::size_t size() const noexcept { return vals_.size(); }
    // Object member lookup; first match wins. Returns nullptr when absent or not an object.
    [[nodiscard]] const Value* find(std::string_view key) const noexcept;

    static Value make_bool(bool b) { Value v; v.type_ = Type::Bool; v.bool_ = b; return v; }
    static Value make_number(double d) { Value v; v.type_ = Type::Number; v.num_ = d; return v; }
    static Value make_string(std::string s) { Value v; v.type_ = Type::String; v.str_ = std::move(s); return v; }
    static Value make_array() { Value v; v.type_ = Type::Array; return v; }
    static Value make_object() { Value v; v.type_ = Type::Object; return v; }
    void push(Value v) { vals_.push_back(std::move(v)); }
    void set(std::string key, Value v) { keys_.push_back(std::move(key)); vals_.push_back(std::move(v)); }

private:
    Type type_ = Type::Null;
    bool bool_ = false;
    double num_ = 0.0;
    std::string str_;
    std::vector<std::string> keys_;  // objects: keys_[i] <-> vals_[i]
    std::vector<Value> vals_;        // arrays and object values
    static const std::string empty_;
    static const std::vector<Value> no_vals_;
};

struct ParseResult {
    std::optional<Value> value;
    std::string error;       // empty on success
    std::size_t offset = 0;  // byte offset of the error
};

// Parses a complete document. Hostile input is bounded two ways: `max_depth` limits nesting (stack),
// `max_nodes` limits the total number of values (memory): a 64 MiB file of `[1,1,1,...]` would
// otherwise expand into gigabytes of Value objects. The default allows ~50k open ports.
ParseResult parse(std::string_view text, std::size_t max_depth = 64, std::size_t max_nodes = 1000000);

}  // namespace recon::json
