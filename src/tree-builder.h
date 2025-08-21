
#pragma once

#include <epan/dissectors/packet-tcp.h>
#include <epan/proto_data.h>
#include <wireshark.h>

#include <hilti/rt/type-info.h>

namespace spicy::wireshark {

struct Conversation;
struct Dissector;
struct Endpoint;
struct HeaderField;
struct Packet;

namespace data {

struct Struct;
struct Tuple;
struct Value;
struct Vector;

struct Boxed : std::vector<Value> {
    Boxed(Value value);
    const auto& value() const;
};

struct Error {
    Error(std::string ei_name, std::string message) : ei_name(std::move(ei_name)), message(std::move(message)) {}
    std::string ei_name;
    std::string message;
};

struct Map : std::map<Value, Value> {
    using std::map<Value, Value>::map;
};

struct Set : std::set<Value> {
    using std::set<Value>::set;
};

struct Struct : std::vector<Value> {
    using std::vector<Value>::vector;
};

struct Tuple : std::vector<Value> {
    using std::vector<Value>::vector;
};

struct Vector : std::vector<Value> {
    using std::vector<Value>::vector;
};

struct Value {
    using value_type = std::variant<std::monostate, std::string, uint64_t, int64_t, double, bool, hilti::rt::Address,
                                    hilti::rt::Port, Boxed, Map, Set, Struct, Tuple, Vector, Error>;

    Value(value_type value, const hilti::rt::TypeInfo* type, std::string as_string,
          std::optional<std::string> field_name, std::optional<uint64_t> begin, std::optional<uint64_t> end)
        : value(std::move(value)),
          type(type),
          as_string(std::move(as_string)),
          field_name(std::move(field_name)),
          begin(begin),
          end(end) {}

    Value() = delete;
    Value(const Value& other) = default;
    Value(Value&& other) = default;
    ~Value() = default;

    Value& operator=(const Value& other) = default;
    Value& operator=(Value&& other) = default;

    value_type value;
    const hilti::rt::TypeInfo* type = nullptr;
    std::string as_string;
    std::optional<std::string> field_name;
    std::optional<uint64_t> begin;
    std::optional<uint64_t> end;

    operator bool() const { return value.index() > 0; }
};

inline bool operator<(const Value& a, const Value& b) { return a.as_string < b.as_string; }

inline Boxed::Boxed(Value value) { push_back(std::move(value)); }

inline const auto& Boxed::value() const {
    assert(! empty());
    return front();
}

inline Value error(std::string ei_name, const std::string& message) {
    return {data::Error(std::move(ei_name), message), &hilti::rt::type_info::error, message, {}, {}, {}};
}

} // namespace data

extern void registerHeaderFieldForStruct(Dissector* dissector, const hilti::rt::TypeInfo* type, int level = 0);
extern void registerStaticHeaderFields(Dissector* dissector);
extern void registerStaticExpertItems(Dissector* dissector);

extern data::Value hiltiValueToDataValue(Packet* packet, const hilti::rt::type_info::Value& v,
                                         const std::optional<std::string>& field_name = {},
                                         std::optional<hilti::rt::integer::safe<uint64_t>> begin = {},
                                         std::optional<hilti::rt::integer::safe<uint64_t>> end = {});

extern void createProtocolTree(const Packet& packet, proto_tree* tree, const data::Value& value);

} // namespace spicy::wireshark
