#include "plugin.h"

#include "hilti/rt/util.h"
#include "spicy/rt/parsed-unit.h"
#include "tree-builder.h"
#include "util.h"
#define WS_BUILD_DLL
#include <dlfcn.h>
#include <epan/addr_resolv.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/proto_data.h>
#include <wireshark.h>
#include <wsutil/filesystem.h>
#include <wsutil/wslog.h>

#include <hilti/rt/libhilti.h>

#include <spicy/rt/libspicy.h>

#include "plugin-config.h"

extern "C" WS_DLL_PUBLIC_DEF void plugin_register();

using namespace spicy::wireshark;

std::optional<Packet> spicy::wireshark::CurrentPacket;
std::vector<hilti::rt::Library> spicy::wireshark::HLTOs;
std::vector<Dissector> spicy::wireshark::Dissectors;

static std::string log_frame_prefix(const Packet& packet) {
    return hilti::rt::fmt("frame #%u, %s", packet.pinfo->num,
                          (packet.endpoint->is_originator ? "originator" : "responder"));
}

void Packet::record(data::Value&& value) {
    if ( ! value )
        return;

    spicy_info("%s: recording Spicy value '%s'", log_frame_prefix(*this).c_str(), value.as_string.c_str());
    auto* wsv = endpoint->values.store(std::move(value));
    p_add_proto_data(wmem_file_scope(), pinfo, dissector->protocol, 0, wsv);
    recorded_unit = value.type;
}

void Packet::record(const hilti::rt::type_info::Value& value) { record(hiltiValueToDataValue(this, value, {})); }

// Make sure core runtime libraries are RTLD_GLOBAL, so HLTO modules can
// resolve their symbols regardless of how the plugin itself was loaded.
static void makePluginSymbolsGlobal() {
    static auto promote_library = [](const char* name, void* sym) {
        Dl_info info;
        if ( dladdr(sym, &info) && info.dli_fname ) {
            void* h = dlopen(info.dli_fname, RTLD_NOLOAD | RTLD_GLOBAL);

            if ( ! h )
                h = dlopen(info.dli_fname, RTLD_LAZY | RTLD_GLOBAL);

            if ( ! h )
                spicy_fatal_error("could not promote %s (%s) to RTLD_GLOBAL: %s", name, info.dli_fname,
                                  dlerror());
        }
        else
            spicy_warning("could not resolve shared object for %s", name);
    };

    promote_library("libhilti", (void*)&hilti::rt::init);
    promote_library("libspicy", (void*)&spicy::rt::init);
}

void spicy::wireshark::log_full(const char* domain, enum ws_log_level level, std::string prefix, const char* file,
                                long line, const char* func, const char* format, ...) {
    std::string format_ext = prefix + format;

    va_list ap;
    va_start(ap, format);
    ws_logv_full(domain, level, file, line, func, format_ext.c_str(), ap);
    va_end(ap);
}


static void searchPathForHLTOs(const hilti::rt::filesystem::path& path) {
    spicy_info("searching '%s' for HLTO modules", path.c_str());

    std::error_code ec;
    auto it = hilti::rt::filesystem::directory_iterator(path, ec);
    if ( ec )
        return;

    while ( it != hilti::rt::filesystem::directory_iterator() ) {
        if ( const auto& path = it->path(); path.extension() == ".hlto" && it->is_regular_file() ) {
            try {
                spicy_debug("loading %s", path.c_str());

                HLTOs.emplace_back(hilti::rt::Library(path));
                if ( auto load = HLTOs.back().open(); ! load )
                    spicy_critical("could not open HLTO module '%s': %s", path.c_str(),
                                   load.error().description().c_str());

            } catch ( const ::hilti::rt::UsageError& e ) {
                spicy_critical("error loading HLTO module '%s': %s", path.c_str(), e.what());
            }
        }

        if ( it.increment(ec); ec ) {
            spicy_warning("error iterating through '%s', skipping any remaining files: %s", path.c_str(),
                          ec.message().c_str());
            break;
        }
    }
}

static void discoverHLTOs() {
    if ( auto paths = hilti::rt::getenv("WIRESHARK_SPICY_MODULE_PATH"); paths && paths->size() )
        // Search custom paths for HLTO modules.
        for ( const auto& path :
              hilti::rt::transform(hilti::rt::split(*paths, ":"), [](const auto& d) { return hilti::rt::trim(d); }) ) {
            std::error_code ec;
            if ( auto is_dir = hilti::rt::filesystem::is_directory(path, ec); ec || ! is_dir ) {
                spicy_debug("directory '%s' cannot be read, skipping", std::string(path).c_str());
                continue;
            }

            searchPathForHLTOs(path);
        }
    else {
        // Search Wireshark's plugin directories for HLTO modules.
        if ( const auto* plugin_dir = get_plugins_dir_with_version() )
            searchPathForHLTOs(hilti::rt::filesystem::path(plugin_dir) / "spicy");

        if ( const auto* plugin_dir = get_plugins_pers_dir_with_version() )
            searchPathForHLTOs(hilti::rt::filesystem::path(plugin_dir) / "spicy");
    }
}

static Conversation* getConversation(packet_info* pinfo, int protocol) {
    auto* wsconv = find_or_create_conversation(pinfo);
    assert(wsconv);

    Conversation* conversation = reinterpret_cast<Conversation*>(conversation_get_proto_data(wsconv, protocol));

    if ( ! conversation ) {
        conversation = wmem_new0(wmem_file_scope(), Conversation);
        new (conversation) Conversation;
        conversation_add_proto_data(wsconv, protocol, conversation);
        // TODO: Is the allocated memory freed by Wireshark?
    }

    return conversation;
}

static const spicy::rt::ParsedUnit* dissectParse(Packet* packet, void* data) {
    auto* parser = packet->endpoint->is_originator ? packet->dissector->parser_orig : packet->dissector->parser_resp;
    if ( ! parser ) {
        spicy_debug("no parser specified for this direction, skipping");
        packet->endpoint->stream->freeze(); // skip further parsing
        return nullptr;
    }

    spicy_info("%s: parsing with %s", log_frame_prefix(*packet).c_str(), parser->type_info->display);

    auto tvb_size = (uint64_t)tvb_reported_length(packet->tvb);
    if ( tvb_size == 0 )
        return nullptr;

    auto segment_size = (uint64_t)tvb_reported_length_remaining(packet->tvb, packet->endpoint->tvb_offset);

    // Need to copy data from the tvb to a buffer, so that we can pass it to Spicy.
    auto* buffer =
        static_cast<char*>(alloca(segment_size + 1)); // +1 for null-termination by tvb_get_raw_bytes_as_string
    tvb_get_raw_bytes_as_string(packet->tvb, packet->endpoint->tvb_offset, buffer, segment_size + 1);

    // Prepare the stream for (continuing) parsing.
    switch ( packet->dissector->mode.value() ) {
        case Mode::Packet: {
            spicy_debug("new PDU in packet mode");
            assert(! packet->endpoint->isActive());

            packet->endpoint->reinit(buffer, segment_size);
            packet->endpoint->stream->freeze();
            break;
        }

        case Mode::Stream: {
            spicy_debug("new data in stream mode");
            packet->endpoint->stream->append(buffer, segment_size);

            if ( packet->pinfo->ptype == PT_TCP ) {
                // We'll see FIN/RST flags only if their packets come with
                // payload, otherwise Wireshark doesn't feed them to the
                // dissector. That means that while we still use them as
                // heuristic to determine the end of a stream, we can not rely
                // on this freeze to happen due to that limitation.
                assert(data);
                if ( auto* tcpinfo = static_cast<struct tcpinfo*>(data); tcpinfo->flags & (TH_FIN | TH_RST) ) {
                    spicy_debug("FIN/RST indicates end of stream");
                    packet->endpoint->stream->freeze();
                }
            }

            break;
        }
    }

    spicy_debug("segment-size=%" PRIu64 " tvb-size=%" PRIu64 " tvb-begin=%" PRIu64 " tvb-offset=%" PRIu64
                " stream-end-offset=%" PRIu64 " stream-frozen=%s",
                segment_size, tvb_size, packet->endpoint->tvb_begin, packet->endpoint->tvb_offset,
                packet->endpoint->stream->endOffset().Ref(), packet->endpoint->stream->isFrozen() ? "yes" : "no");

    spicy_debug("segment: size=%" PRIu64 " content=|%s|", segment_size, hilti::rt::escapeBytes(buffer).c_str());

    switch ( packet->dissector->mode.value() ) {
        case Mode::Packet: {
            try {
                packet->endpoint->resumable =
                    (*parser->parse3)(packet->endpoint->unit, packet->endpoint->stream, {}, {});
            } catch ( const spicy::rt::ParseError& e ) {
                packet->record(data::error("spicy.error.parse", hilti::rt::fmt("Protocol error: %s", e.what())));
                return nullptr;
            }

            auto display_type = util::stripScope(packet->endpoint->unit->value().type().display);
            packet->endpoint->packet_info[packet->pinfo->num] = display_type;

            return packet->endpoint->unit.get();
        }

        case Mode::Stream: {
            if ( packet->endpoint->stream->isFrozen() ) {
                spicy_debug("stream already finished, skipping parsing");
                return nullptr;
            }

            try {
                if ( ! packet->endpoint->isActive() )
                    // initial segment
                    packet->endpoint->resumable =
                        (*parser->parse3)(packet->endpoint->unit, packet->endpoint->stream, {}, {});
                else
                    // resuming after more data
                    packet->endpoint->resumable->resume();
            } catch ( const spicy::rt::ParseError& e ) {
                packet->record(data::error("spicy.error.parse", hilti::rt::fmt("Protocol error: %s", e.what())));
                packet->endpoint->stream->freeze(); // skip further parsing
                return nullptr;
            }

            if ( ! packet->recorded_unit ) {
                packet->endpoint->unit_packets.insert(packet->pinfo->num);
            }
            else {
                auto display_type = util::stripScope(packet->recorded_unit->display);
                packet->endpoint->packet_info[packet->pinfo->num] = display_type;

                for ( auto num : packet->endpoint->unit_packets )
                    // TODO: These aren't showing up currently, looks like Wireshark is prioritizing TCP?
                    packet->endpoint->packet_info[num] = hilti::rt::fmt("%s (partial)", display_type);
            }

            if ( ! packet->endpoint->isActive() ) {
                // Mark stream as done, so that we won't try to parse more data.
                spicy_debug("reached end of Spicy unit");
                packet->endpoint->stream->freeze();
            }

            if ( packet->endpoint->stream->isFrozen() ) {
                // Done parsing, with a unit to return.
                spicy_debug("stream parsing finished");
                return packet->endpoint->unit.get();
            }
            else {
                spicy_debug("stream parsing ran out of data, waiting for more");
                packet->endpoint->tvb_offset += segment_size;

                // When record() was called during parsing, we consider that
                // as end-of-PDU and don't request more data from the reassembler.
                // That way Wireshark will stop tracking future packets as
                // belonging to the current PDU. This will probably not work 100%
                // correctly in case of multiple PDUs being part of the same
                // packet, but let's see if it is good enough ...
                if ( ! packet->recorded_unit ) {
                    spicy_debug("continuing PDU");
                    packet->pinfo->desegment_offset = 0;
                    packet->pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                }
                else {
                    spicy_debug("signaling end of PDU (%s)", packet->recorded_unit->display);
                    packet->endpoint->tvb_offset = 0; // we'll be getting a new tvb
                    packet->endpoint->tvb_begin = packet->endpoint->stream->endOffset();
                }

                return nullptr;
            }
        }

        case Mode::Undef: spicy_internal_error("undefined dissector mode"); ;
    }

    hilti::rt::cannot_be_reached();
}

static void dissectDisplay(const Packet& packet, proto_tree* tree, const data::Value& value) {
    spicy_info("%s: displaying value", log_frame_prefix(packet).c_str());
    spicy_debug("display value of type `%s`: '%s'", value.type->display, value.as_string.c_str());

    if ( ! value ) {
        spicy_debug("no value to display");
        return;
    }

    createProtocolTree(packet, tree, value);
}

static bool sameEndpoint(const Endpoint& endpoint, const address& addr, guint32 port, port_type ptype) {
    if ( ptype == PT_TCP || ptype == PT_UDP )
        return addresses_equal(&endpoint.addr, &addr) && endpoint.port == port;
    else
        return addresses_equal(&endpoint.addr, &addr) && endpoint.port == 0;
}

static bool isReservedPort(guint32 port, port_type /* ptype */) { return port < 1024; }

static bool isWellKnownPort(guint32 port, port_type ptype) { return try_serv_name_lookup(ptype, port); }

// This is a heuristic to determine which endpoint send the current packet.
static Endpoint* getOrSetEndpoint(Dissector* dissector, Conversation* conversation, packet_info* pinfo) {
    if ( conversation->originator && sameEndpoint(*conversation->originator, pinfo->src, pinfo->srcport, pinfo->ptype) )
        return &*conversation->originator;

    if ( conversation->responder && sameEndpoint(*conversation->responder, pinfo->src, pinfo->srcport, pinfo->ptype) )
        return &*conversation->responder;

    if ( conversation->originator ) {
        // Must be first packet of responder side.
        assert(! conversation->responder);
        conversation->responder = Endpoint(pinfo->src, pinfo->srcport, false, dissector->parser_resp_type);
        return &*conversation->responder;
    }
    else {
        if ( conversation->responder ) {
            // Must be first packet of originator side.
            conversation->originator = Endpoint(pinfo->src, pinfo->srcport, true, dissector->parser_orig_type);
            return &*conversation->originator;
        }

        if ( pinfo->ptype == PT_TCP || pinfo->ptype == PT_UDP ) {
            if ( (isWellKnownPort(pinfo->srcport, pinfo->ptype) && ! isWellKnownPort(pinfo->destport, pinfo->ptype)) ||
                 (isReservedPort(pinfo->srcport, pinfo->ptype) && ! isReservedPort(pinfo->destport, pinfo->ptype)) ) {
                // Flip direction.
                conversation->responder = Endpoint(pinfo->src, pinfo->srcport, false, dissector->parser_orig_type);
                return &*conversation->responder;
            }
        }
    }

    // Must be the first packet for this conversation. We assume it to be from
    // the originator.
    assert(! conversation->originator);
    assert(! conversation->responder);

    conversation->originator = Endpoint(pinfo->src, pinfo->srcport, true, dissector->parser_orig_type);
    return &*conversation->originator;
}

static void registerHeaderFields(spicy::wireshark::Dissector* dissector) {
    registerStaticHeaderFields(dissector);

    if ( dissector->parser_orig_type )
        registerHeaderFieldForStruct(dissector, dissector->parser_orig_type);

    if ( dissector->parser_resp_type )
        registerHeaderFieldForStruct(dissector, dissector->parser_resp_type);

    dissector->hf_register_infos.reserve(dissector->header_fields.size());
    dissector->etts.reserve(dissector->header_fields.size());

    for ( auto& [filter_name, hfs] : dissector->header_fields ) {
        for ( auto& [tag, hf] : hfs ) {
            dissector->hf_register_infos.push_back(hf.__hf_ri);
            hf.hf_ri = &dissector->hf_register_infos.back();
        }
    }

    spicy_info("registering subtrees with Wireshark");

    for ( auto& [filter_name, hfs] : dissector->header_fields ) {
        for ( auto& [tag, hf] : hfs ) {
            if ( hf.isSubtree() ) {
                spicy_debug("%s (name '%s')", hf.hf_ri->hfinfo.abbrev, hf.hf_ri->hfinfo.name);
                dissector->etts.push_back(&hf.ett);
            }
        }
    }

    spicy_info("registering header fields with Wireshark");

    for ( auto& [filter_name, hfs] : dissector->header_fields ) {
        for ( auto& [tag, hf] : hfs ) {
            if ( ! hf.isSubtree() )
                spicy_debug("%s (name '%s', type '%s')", hf.hf_ri->hfinfo.abbrev, hf.hf_ri->hfinfo.name,
                            ftype_pretty_name(hf.hf_ri->hfinfo.type));
        }
    }

    proto_register_field_array(dissector->protocol, dissector->hf_register_infos.data(),
                               dissector->hf_register_infos.size());
    proto_register_subtree_array(dissector->etts.data(), dissector->etts.size());
}

static void registerExpertItems(spicy::wireshark::Dissector* dissector) {
    registerStaticExpertItems(dissector);

    dissector->ei_register_infos.reserve(dissector->expert_fields.size());

    for ( auto& [name, efs] : dissector->expert_fields ) {
        dissector->ei_register_infos.push_back(efs.__ei_ri);
        efs.ei_ri = &dissector->ei_register_infos.back();
    }

    spicy_info("registering expert items with Wireshark");

    for ( auto& [name, efi] : dissector->expert_fields )
        spicy_debug("%s (%s)", efi.__ei_ri.eiinfo.name, efi.__ei_ri.eiinfo.summary);

    expert_register_field_array(dissector->expert_protocol, dissector->ei_register_infos.data(),
                                dissector->ei_register_infos.size());
}

static void proto_register_spicy() {
    for ( auto& d : Dissectors ) {
        spicy_info("registering protocol '%s' (%s/%s) with Wireshark", d.name.c_str(), d.short_name.c_str(),
                   d.filter_name.c_str());

        if ( d.parser_orig_type ) {
            if ( auto parser = spicy::rt::lookupParser(d.parser_orig_type->display) )
                d.parser_orig = *parser;
            else
                spicy_internal_error("could not find parser for '%s'", d.parser_orig_type->display);
        }

        if ( d.parser_resp_type ) {
            if ( auto parser = spicy::rt::lookupParser(d.parser_resp_type->display) )
                d.parser_resp = *parser;
            else
                spicy_internal_error("could not find parser for '%s'", d.parser_resp_type->display);
        }

        bool uniquify = false;

        if ( proto_name_already_registered(d.name.c_str()) ) {
            spicy_debug("protocol '%s' already exists", d.name.c_str());
            uniquify = true;
        }
        else if ( proto_get_id_by_short_name(d.short_name.c_str()) != -1 ) {
            spicy_debug("protocol with short name '%s' already exists", d.short_name.c_str());
            uniquify = true;
        }
        else if ( proto_get_id_by_filter_name(d.filter_name.c_str()) != -1 ) {
            spicy_debug("protocol with filter name '%s' already exists", d.filter_name.c_str());
            uniquify = true;
        }

        if ( uniquify ) {
            d.name += " [Spicy]";
            d.short_name = "spicy_" + d.short_name;
            d.filter_name = "spicy_" + d.filter_name;
            spicy_info("renaming protocol to '%s' (%s/%s)", d.name.c_str(), d.short_name.c_str(),
                       d.filter_name.c_str());
        }

        d.protocol = proto_register_protocol(d.name.c_str(), d.short_name.c_str(), d.filter_name.c_str());
        assert(d.protocol > 0);

        d.expert_protocol = expert_register_protocol(d.protocol);

        registerHeaderFields(&d);
        registerExpertItems(&d);
    }
}

static int proto_dissect_spicy(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data, void* user) {
    auto* dissector = reinterpret_cast<Dissector*>(user);
    auto* conversation = getConversation(pinfo, dissector->protocol);
    auto* endpoint = getOrSetEndpoint(dissector, conversation, pinfo);

    CurrentPacket = Packet(dissector, conversation, endpoint, tree, tvb, pinfo);
    hilti::rt::scope_exit cleanup([&]() { CurrentPacket.reset(); });

    switch ( dissector->mode.value() ) {
        case Mode::Packet:
            spicy_info("%s: %s, packet mode", log_frame_prefix(*CurrentPacket).c_str(),
                       (! PINFO_FD_VISITED(pinfo) ? "first pass of frame" : "revisiting frame"));
            break;

        case Mode::Stream: {
            std::string addl;

            if ( ! PINFO_FD_VISITED(pinfo) )
                addl = hilti::rt::fmt(", %s frame in stream mode", (endpoint->isActive() ? "continuation" : "initial"));

            spicy_info("%s: %s%s", log_frame_prefix(*CurrentPacket).c_str(),
                       (! PINFO_FD_VISITED(pinfo) ? "first pass of frame" : "revisiting frame"), addl.c_str());
            break;
        }
    }

    spicy_debug("conversation=%p tree=%p", conversation, tree);

    if ( ! PINFO_FD_VISITED(pinfo) ) {
        try {
            auto unit = dissectParse(&*CurrentPacket, data);

            if ( unit && endpoint->stream->isFrozen() && ! endpoint->display_called )
                CurrentPacket->record(unit->value());
        } catch ( const hilti::rt::RuntimeError& e ) {
            CurrentPacket->record(data::error("spicy.error.parse", e.what()));
        }
    }

    auto value = static_cast<const data::Value*>(p_get_proto_data(wmem_file_scope(), pinfo, dissector->protocol, 0));

    col_set_str(pinfo->cinfo, COL_PROTOCOL, dissector->short_name.c_str());

    std::string info_column;

    if ( auto info = endpoint->packet_info.find(pinfo->num); info != endpoint->packet_info.end() )
        info_column = info->second;

    if ( value ) {
        if ( info_column.empty() )
            info_column = value->as_string;
        else
            info_column = hilti::rt::fmt("%s: %s", info_column, value->as_string);
    }

    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", info_column.c_str());

    if ( value && tree )
        dissectDisplay(*CurrentPacket, tree, *value);

    return tvb_captured_length(tvb);
}

static void proto_reg_handoff_spicy() {
    for ( auto& d : Dissectors ) {
        spicy_info("registering dissector '%s' with Wireshark", d.name.c_str());

        d.handle = register_dissector_with_data(d.short_name.c_str(), proto_dissect_spicy, d.protocol, &d);

        for ( const auto& port : d.ports ) {
            switch ( port.protocol().value() ) {
                case hilti::rt::Protocol::TCP:
                    spicy_debug("on TCP port %" PRIu16, port.port());
                    dissector_add_uint("tcp.port", port.port(), d.handle);
                    break;

                case hilti::rt::Protocol::UDP:
                    spicy_debug("on UDP port %" PRIu16, port.port());
                    dissector_add_uint("udp.port", port.port(), d.handle);
                    break;

                default:
                    spicy_warning("dissector '%s': unsupported protocol for port %" PRIu16, d.name.c_str(),
                                  port.port());
                    break;
            }
        }
    }
}

////////// Wireshark entry points

extern "C" {
extern WS_DLL_PUBLIC_DEF const gchar plugin_version[] = PLUGIN_VERSION_NUMBER;
extern WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
extern WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC_DEF void plugin_register() {
    makePluginSymbolsGlobal();

    discoverHLTOs();

    hilti::rt::init();
    spicy::rt::init();

    static proto_plugin plugin_spicy;
    plugin_spicy.register_protoinfo = proto_register_spicy;
    plugin_spicy.register_handoff = proto_reg_handoff_spicy;
    proto_register_plugin(&plugin_spicy);
}
}

////////// Implementations of wireshark.spicy runtime functions

namespace spicy_wireshark {

WS_DLL_PUBLIC_DEF void register_dissector(const __hlt::Wireshark::Dissector& d) {
    if ( d.name.empty() ) {
        spicy_critical("register_dissector: missing name for Spicy dissector, skipping registration");
        return;
    }

    if ( d.short_name.empty() ) {
        spicy_critical("register_dissector: missing short name for Spicy dissector, skipping registration");
        return;
    }

    const hilti::rt::TypeInfo* parser_orig_type = nullptr;
    const hilti::rt::TypeInfo* parser_resp_type = nullptr;

    if ( d.parser_orig )
        parser_orig_type = *d.parser_orig;

    if ( d.parser_resp )
        parser_resp_type = *d.parser_resp;

    if ( d.parser ) {
        if ( ! parser_orig_type )
            parser_orig_type = *d.parser;

        if ( ! parser_resp_type )
            parser_resp_type = *d.parser;
    }

    if ( ! (parser_orig_type || parser_resp_type) ) {
        spicy_critical("register_dissector: missing parser type for dissector '%s', skipping registration",
                       d.name.c_str());
        return;
    }

    auto dissector = Dissector{.name = d.name,
                               .mode = d.mode,
                               .short_name = d.short_name,
                               .filter_name = (d.filter_name ? *d.filter_name : d.short_name),
                               .parser_orig_type = parser_orig_type,
                               .parser_resp_type = parser_resp_type,
                               .ports = d.ports};

    spicy_debug("registering Spicy dissector '%s' with plugin (orig parser '%s', resp parser '%s')",
                dissector.short_name.c_str(),
                (dissector.parser_orig_type ? dissector.parser_orig_type->display : "(none)"),
                (dissector.parser_resp_type ? dissector.parser_resp_type->display : "(none)"));

    Dissectors.emplace_back(std::move(dissector));
}


WS_DLL_PUBLIC_DEF void display(const void* unit_, const hilti::rt::TypeInfo* type) {
    hilti::rt::type_info::Value value(unit_, type);

    if ( type->tag == hilti::rt::TypeInfo::ValueReference )
        // Dereference to get the actual value.
        value = type->value_reference->value(value);


    if ( value.type().tag != hilti::rt::TypeInfo::Struct ) {
        spicy_warning("Wireshark::display: value must be a struct, got '%s'; ignoring request to display",
                      value.type().display);
        CurrentPacket->endpoint->display_called = true;
        return;
    }

    // TODO: Check that it's a struct that we know through through our filter names.

    if ( ! CurrentPacket )
        spicy_warning("Wireshark::display: no current packet to display value '%s' with", value.type().display);

    try {
        CurrentPacket->endpoint->display_called = true;
        CurrentPacket->record(std::move(value));
    } catch ( const hilti::rt::RuntimeError& e ) {
        spicy_warning("Wireshark::display: could not record value '%s': %s", value.type().display, e.what());
    }
}

} // namespace spicy_wireshark
