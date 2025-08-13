
#pragma once

#include <autogen/wireshark.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <wsutil/filesystem.h>
#include <wsutil/wslog.h>

#include <hilti/rt/types/enum.h>

#include <spicy/rt/parser.h>

#include "tree-builder.h"
#include "util.h"

namespace spicy::wireshark {

// Logs messages to the info or debug stream, depending on indentation level, both invisible to user by default.
#define spicy_info(...)                                                                                               \
    ::spicy::wireshark::log_full("Spicy", LOG_LEVEL_INFO, "", NULL, -1, NULL,   \
                                 __VA_ARGS__);

#define spicy_debug(...)                                                                                               \
    ::spicy::wireshark::log_full("Spicy", LOG_LEVEL_DEBUG, "  * ", NULL, -1, NULL,   \
                                 __VA_ARGS__);

// Logs messages to noisy debug stream, invisible to user by default.
#define spicy_noisy(...) ::spicy::wireshark::log_full("Spicy", LOG_LEVEL_NOISY, "    - ", NULL, -1, NULL, __VA_ARGS__);

// Logs message to warning stream, visible to user by default.
#define spicy_warning(...) ws_log_full("Spicy", LOG_LEVEL_WARNING, NULL, -2, NULL, __VA_ARGS__);

// Logs message to critical stream, continues execution.
#define spicy_critical(...) ws_log_full("Spicy", LOG_LEVEL_CRITICAL, NULL, -3, NULL, __VA_ARGS__);

// Logs message to error stream and aborts execution immediately.
#define spicy_fatal_error(...) ws_log_full("Spicy", LOG_LEVEL_ERROR, NULL, -1, NULL, __VA_ARGS__);

// Logs message as internal error to error stream and aborts execution immediately.
#define spicy_internal_error(...)                                                                                      \
    ::spicy::wireshark::log_full("Spicy", LOG_LEVEL_ERROR, "[internal error] ", NULL, -1, NULL, __VA_ARGS__);

extern void log_full(const char* domain, enum ws_log_level level, std::string prefix, const char* file, long line,
                     const char* func, const char* format, ...) G_GNUC_PRINTF(7, 8);

using Mode = ::__hlt::Wireshark::Mode;

struct HeaderField {
    std::string field_name;
    std::string filter_name;
    std::string description;
    bool is_subtree = false;

    // For header fields.
    int* hf_index = nullptr;
    hf_register_info* hf_ri = nullptr;

    std::vector<val64_string> enum_values;

    // For subtree fields.
    int ett = -1;

    bool isSubtree() const { return is_subtree; }

    hf_register_info __hf_ri;
};

struct ExpertField {
    std::string name;
    int group = PI_COMMENT;
    int severity = PI_NOTE;
    std::string summary;

    expert_field* expert_field_ = nullptr;
    ei_register_info* ei_ri = nullptr;

    ei_register_info __ei_ri;
};

struct Dissector {
    // Fields provided by the developer of the dissector.

    std::string name;
    Mode mode;
    std::string short_name;
    std::string filter_name;
    const ::hilti::rt::TypeInfo* parser_orig_type = nullptr;
    const ::hilti::rt::TypeInfo* parser_resp_type = nullptr;
    hilti::rt::Set<::hilti::rt::Port> ports;

    // Fields set internally by the plugin.

    const ::spicy::rt::Parser* parser_orig = nullptr;
    const ::spicy::rt::Parser* parser_resp = nullptr;
    int protocol = -1;
    expert_module_t* expert_protocol = nullptr;
    dissector_handle_t handle = nullptr;

    // "Static" storage for registration with Wireshark.
    std::map<std::string, std::map<std::string, HeaderField>> header_fields; // indexed by filter name
    std::map<std::string, ExpertField> expert_fields;                        // indexed by name

    // Arrays that we register with Wireshark. Note that these must not resize
    // after registration has been performed.
    std::vector<hf_register_info> hf_register_infos;
    std::vector<int*> etts;
    std::vector<ei_register_info> ei_register_infos;
};

struct Endpoint {
    address addr;
    uint32_t port = 0;
    bool is_originator = false;
    const hilti::rt::TypeInfo* parser_type = nullptr;

    hilti::rt::ValueReference<hilti::rt::Stream> stream;
    std::optional<hilti::rt::Resumable> resumable;
    hilti::rt::ValueReference<spicy::rt::ParsedUnit> unit;
    std::set<uint32_t> unit_packets; // packets that have contributed to current unit
    uint64_t tvb_begin = 0; // tvb's start inside the global stream
    uint64_t tvb_offset = 0; // offset of current packet inside the tvb
    bool display_called =
        false; // set to true wireshark::display() is called from Spicy code anytime during the lifetime of the stream

    std::map<uint32_t, std::string> packet_info; // string to prefix the column info with, indexed by packet number

    util::StaticStorage<data::Value> values;

    void reinit(const char* data = nullptr, size_t size = 0) {
        if ( data ) {
            assert(size);
            stream = hilti::rt::Stream(data, size);
        }
        else
            stream = hilti::rt::Stream();

        resumable.reset();
        unit = spicy::rt::ParsedUnit();
        unit_packets.clear();
        tvb_begin = 0;
        tvb_offset = 0;
        display_called = false;
        packet_info.clear();
    }

    bool isActive() const { return resumable.has_value() && ! *resumable; }

    Endpoint(const address& addr, uint32_t port, bool is_originator, const hilti::rt::TypeInfo* parser_type)
        : port(port), is_originator(is_originator), parser_type(parser_type) {
        copy_address_wmem(wmem_file_scope(), &this->addr, &addr);
    }

    ~Endpoint() { free_address_wmem(wmem_file_scope(), &addr); }

    Endpoint(const Endpoint& other)
        : port(other.port), is_originator(other.is_originator), parser_type(other.parser_type) {
        copy_address_wmem(wmem_file_scope(), &addr, &other.addr);
    }

    Endpoint& operator=(const Endpoint& other) {
        if ( this != &other ) {
            free_address_wmem(wmem_file_scope(), &addr);
            copy_address_wmem(wmem_file_scope(), &addr, &other.addr);
            port = other.port;
            is_originator = other.is_originator;
            parser_type = other.parser_type;
        }

        return *this;
    }
};

struct Conversation {
    std::optional<Endpoint> originator;
    std::optional<Endpoint> responder;
};

struct Packet {
    Packet(spicy::wireshark::Dissector* dissector, spicy::wireshark::Conversation* conversation, Endpoint* endpoint,
           proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo)
        : dissector(dissector), conversation(conversation), endpoint(endpoint), tvb(tvb), pinfo(pinfo) {}

    void record(data::Value&& value);
    void record(const hilti::rt::type_info::Value& value);

    spicy::wireshark::Dissector* dissector;
    spicy::wireshark::Conversation* conversation;
    Endpoint* endpoint;
    tvbuff_t* tvb;
    packet_info* pinfo;
    const hilti::rt::TypeInfo* recorded_unit = nullptr; // set when record() is called
};

extern std::optional<Packet> CurrentPacket;
extern std::vector<hilti::rt::Library> HLTOs;
extern std::vector<Dissector> Dissectors; // filled by register_dissector()

} // namespace spicy::wireshark
