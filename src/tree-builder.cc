
#include "tree-builder.h"

#include <alloca.h>
#include <epan/to_str.h>

#include <cctype>

#include <hilti/rt/util.h>

#include "plugin.h"
#include "util.h"

using namespace hilti::rt;
using namespace spicy::wireshark;

util::StaticStorage<int> hf_indices;
util::StaticStorage<expert_field> ei_expert_fields;

static HeaderField* _allocateHeaderField(Dissector* dissector, const std::string& field_name,
                                         const std::string& filter_name, const std::string& tag, bool is_subtree,
                                         enum ftenum ftype, int display, const void* strings, uint64_t bitmask) {
    auto& hfs = dissector->header_fields[filter_name];
    if ( auto i = hfs.find(tag); i != hfs.end() )
        return &i->second; // already registered.

    HeaderField* hf = &dissector->header_fields[filter_name][tag];

    hf->field_name = field_name;
    hf->filter_name = filter_name;
    hf->description = ""; // TODO: Make docstring available in the type info.
    hf->is_subtree = is_subtree;
    hf->hf_index = hf_indices.store(0);

    hf->__hf_ri = {hf->hf_index,
                   {hf->field_name.c_str(), hf->filter_name.c_str(), ftype, display, strings, bitmask,
                    hf->description.c_str(), HFILL}},
    hf->hf_ri = &hf->__hf_ri;

    return hf;
};

static ExpertField* _registerExpertItem(Dissector* dissector, const std::string& name, int group, int severity,
                                        const std::string& summary) {
    auto* ef = &dissector->expert_fields[name];
    ef->name = name;
    ef->group = group;
    ef->severity = severity;
    ef->summary = summary;
    ef->expert_field_ = ei_expert_fields.store(EI_INIT);

    ef->__ei_ri = {ef->expert_field_, {ef->name.c_str(), ef->group, ef->severity, ef->summary.c_str(), EXPFILL}};
    ef->ei_ri = &ef->__ei_ri;

    return ef;
}


static void _registerHeaderField(Dissector* dissector, const std::string& field_name, const std::string& filter_name,
                                 const hilti::rt::TypeInfo* type, int level);

static void _registerHeaderField(Dissector* dissector, const std::string& field_name, const std::string& filter_name,
                                 const std::string& tag, const hilti::rt::TypeInfo* type, int level) {
    auto add_subtree = [&](std::string tree_filter_name = "", std::string tree_field_name = "") {
        if ( tree_filter_name.empty() )
            tree_filter_name = filter_name;

        if ( tree_field_name.empty() )
            tree_field_name = field_name;

        return _allocateHeaderField(dissector, tree_field_name, tree_filter_name, tag, true, FT_STRING, BASE_NONE,
                                    nullptr, 0);
    };

    auto add_header_field = [&](enum ftenum ftype, int display, std::string tag = "", const void* strings = nullptr,
                                uint64_t bitmask = 0) {
        return _allocateHeaderField(dissector, field_name, filter_name, tag, false, ftype, display, strings, bitmask);
    };

    auto add_header_fields_for_bitfield = [&](const hilti::rt::type_info::Bitfield* bitfield,
                                              const std::string& filter_prefix) {
        for ( const auto& bits : bitfield->bits() ) {
            std::string bits_name = bits.name;
            std::string bits_filter_name = fmt("%s.%s", filter_prefix, util::toLower(bits_name));

            enum ftenum fte = FT_NONE;
            switch ( bitfield->width() ) {
                case 8: {
                    fte = FT_UINT8;
                    break;
                }
                case 16: {
                    fte = FT_UINT16;
                    break;
                }
                case 32: {
                    fte = FT_UINT32;
                    break;
                }
                case 64: {
                    fte = FT_UINT64;
                    break;
                }
                default:
                    spicy_fatal_error("add_header_fields_for_bitfield: unsupported bitfield width %d",
                                      bitfield->width());
            }

            _allocateHeaderField(dissector, bits_name, bits_filter_name, "", false, fte, BASE_DEC, nullptr, 0);
        }
    };

    assert(level == 0 || ! filter_name.empty());

    switch ( type->tag ) {
        case TypeInfo::Address:
            add_header_field(FT_IPv4, BASE_NONE, "ipv4");
            add_header_field(FT_IPv6, BASE_NONE, "ipv6");
            break;

        case TypeInfo::Bitfield:
            add_subtree();
            add_header_fields_for_bitfield(type->bitfield, filter_name);
            break;

        case TypeInfo::Bool: add_header_field(FT_BOOLEAN, BASE_NONE); break;

        case TypeInfo::Bytes: add_header_field(FT_BYTES, BASE_NONE); break;

        case TypeInfo::Enum: {
            auto* hf = add_header_field(FT_UINT64, BASE_VAL64_STRING);

            for ( const auto& label : type->enum_->labels() ) {
                if ( label.value >= 0 )
                    hf->enum_values.emplace_back(val64_string{static_cast<uint64_t>(label.value), label.name.c_str()});
                else
                    hf->enum_values.emplace_back(val64_string{UINT64_MAX, label.name.c_str()});
            }

            hf->enum_values.emplace_back(val64_string{0, NULL});

            hf->hf_ri->hfinfo.strings = VALS64(hf->enum_values.data());
            break;
        }

        case TypeInfo::Interval: add_header_field(FT_RELATIVE_TIME, BASE_NONE); break;

        case TypeInfo::Map:
            add_subtree(filter_name + ".display");

            _registerHeaderField(dissector, "key", filter_name + ".key", type->map->keyType(), level + 1);
            _registerHeaderField(dissector, "value", filter_name + ".value", type->map->valueType(), level + 1);
            break;

        case TypeInfo::Optional:
            _registerHeaderField(dissector, field_name, filter_name, type->optional->valueType(), level);
            break;

        case TypeInfo::Port: add_header_field(FT_UINT16, BASE_DEC); break;

        case TypeInfo::SignedInteger_int8: add_header_field(FT_INT8, BASE_DEC); break;

        case TypeInfo::SignedInteger_int16: add_header_field(FT_INT16, BASE_DEC); break;

        case TypeInfo::SignedInteger_int32: add_header_field(FT_INT32, BASE_DEC); break;

        case TypeInfo::SignedInteger_int64: add_header_field(FT_INT64, BASE_DEC); break;

        case TypeInfo::Time: add_header_field(FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL); break;

        case TypeInfo::Real: add_header_field(FT_DOUBLE, BASE_NONE); break;

        case TypeInfo::Set:
            add_subtree(filter_name + ".display");
            _registerHeaderField(dissector, "element", filter_name, type->set->dereferencedType(), level);
            break;

        case TypeInfo::String: add_header_field(FT_STRING, BASE_NONE); break;

        case TypeInfo::StrongReference:
            _registerHeaderField(dissector, field_name, filter_name, type->strong_reference->valueType(), level);
            break;

        case TypeInfo::Struct: {
            auto struct_type_name = util::stripScope(type->display);
            auto struct_filter_name = util::toLower(fmt("%s.%s", dissector->short_name, struct_type_name));

            if ( level > 0 )
                // The top-level unit gets folder into the manually created root node.
                add_subtree(struct_filter_name);

            for ( const auto& field_ : type->struct_->fields() ) {
                const auto& field = field_.get();

                if ( field.isInternal() )
                    continue;

                if ( field.isAnonymous() ) {
                    if ( field.type->tag == TypeInfo::Bitfield )
                        // Special case: lift up anonymous bitfield to the struct level.
                        add_header_fields_for_bitfield(field.type->bitfield, struct_filter_name);
                    else if ( field.type->tag != TypeInfo::Vector )
                        // Skip all other anonymous fields.
                        continue;
                }

                auto hf_filter_name = fmt("%s.%s", struct_filter_name, util::toLower(field.name));
                _registerHeaderField(dissector, field.name, hf_filter_name, field.type, level + 1);
            }

            break;
        }

        case TypeInfo::Tuple:
            add_subtree();

            for ( const auto& [index, element] : hilti::rt::enumerate(type->tuple->elements()) ) {
                std::string name;
                std::string hf_filter_name;

                if ( ! element.name.empty() ) {
                    name = element.name;
                    hf_filter_name = fmt("%s.%s", filter_name, util::toLower(element.name));
                }
                else {
                    name = "<anon>";
                    hf_filter_name = fmt("%s.%u", filter_name, index);
                }

                _registerHeaderField(dissector, name, hf_filter_name, element.type, level + 1);
            }

            break;


        case TypeInfo::ValueReference:
            _registerHeaderField(dissector, field_name, filter_name, type->value_reference->valueType(), level);
            break;

        case TypeInfo::Vector:
            add_subtree(filter_name + ".display");

            _registerHeaderField(dissector, "element", filter_name, type->vector->dereferencedType(), level);
            break;

        case TypeInfo::Void:
            // Just skip, nothing to do.
            break;

        case TypeInfo::UnsignedInteger_uint8: add_header_field(FT_UINT8, BASE_DEC); break;

        case TypeInfo::UnsignedInteger_uint16: add_header_field(FT_UINT16, BASE_DEC); break;

        case TypeInfo::UnsignedInteger_uint32: add_header_field(FT_UINT32, BASE_DEC); break;

        case TypeInfo::UnsignedInteger_uint64: add_header_field(FT_UINT64, BASE_DEC); break;

        case TypeInfo::WeakReference:
            _registerHeaderField(dissector, field_name, filter_name, type->weak_reference->valueType(), level);
            break;

        case TypeInfo::Any:
        case TypeInfo::BytesIterator:
        case TypeInfo::Error:
        case TypeInfo::Exception:
        case TypeInfo::Function:
        case TypeInfo::Library:
        case TypeInfo::MapIterator:
        case TypeInfo::Network:
        case TypeInfo::Null:
        case TypeInfo::RegExp:
        case TypeInfo::Result:
        case TypeInfo::SetIterator:
        case TypeInfo::Stream:
        case TypeInfo::StreamIterator:
        case TypeInfo::StreamView:
        case TypeInfo::Undefined:
        case TypeInfo::Union:
        case TypeInfo::VectorIterator:
            // These types not currently supported by the plugin.,
            break;
    }
}

static void _registerHeaderField(Dissector* dissector, const std::string& field_name, const std::string& filter_name,
                                 const hilti::rt::TypeInfo* type, int level) {
    _registerHeaderField(dissector, field_name, filter_name, "", type, level);
}

static void _registerHeaderField(Dissector* dissector, const std::string& field_name, const std::string& filter_name,
                                 enum ftenum ftype, int display, const void* strings = nullptr, uint64_t bitmask = 0) {
    _allocateHeaderField(dissector, field_name, filter_name, "", false, ftype, display, strings, bitmask);
}

static std::pair<std::optional<uint64_t>, std::optional<uint64_t>> _streamOffsetsToTvbOffsets(
    const Packet* packet, const std::optional<hilti::rt::integer::safe<uint64_t>>& begin,
    const std::optional<hilti::rt::integer::safe<uint64_t>>& end) {
    if ( ! (begin && end) )
        return {std::nullopt, std::nullopt};

    std::optional<uint64_t> tvb_begin;
    std::optional<uint64_t> tvb_end;

    if ( *begin >= packet->endpoint->tvb_begin )
        tvb_begin = *begin - packet->endpoint->tvb_begin;
    else
        tvb_begin = 0;

    if ( *end >= packet->endpoint->tvb_begin )
        tvb_end = *end - packet->endpoint->tvb_begin;
    else
        tvb_end = 0;

    return {tvb_begin, tvb_end};
}

static data::Value _hiltiValueToDataValue(Packet* packet, const hilti::rt::type_info::Value& v,
                                          const std::optional<std::string>& field_name,
                                          std::optional<hilti::rt::integer::safe<uint64_t>> begin,
                                          std::optional<hilti::rt::integer::safe<uint64_t>> end) {
    auto [tvb_begin, tvb_end] = _streamOffsetsToTvbOffsets(packet, begin, end);

    const auto* type = &v.type();

    if ( ! v )
        return {{}, type, "<no value>", {}, tvb_begin, tvb_end};

    auto as_string = v.to_string();

    switch ( type->tag ) {
        case TypeInfo::Address: return {type->address->get(v), type, as_string, field_name, tvb_begin, tvb_end};

        case TypeInfo::Bitfield: {
            data::Vector result;

            for ( const auto& bits : type->bitfield->iterate(v) ) {
                auto bval = _hiltiValueToDataValue(packet, bits.second, bits.first.name, begin,
                                                   end); // yields optional<uint64>
                auto bval_deref = std::get<data::Boxed>(bval.value).value();
                result.emplace_back(std::move(bval_deref));
            }

            return {std::move(result), type, as_string, field_name, tvb_begin, tvb_end};
        }

        case TypeInfo::Bool: return {type->bool_->get(v), type, as_string, field_name, tvb_begin, tvb_end};

        case TypeInfo::Bytes: {
            return {type->bytes->get(v).str(), type, as_string, field_name, tvb_begin, tvb_end};
        }

        case TypeInfo::Enum: return {type->enum_->get(v).value, type, as_string, field_name, tvb_begin, tvb_end};

        case TypeInfo::Interval:
            return {type->interval->get(v).nanoseconds(), type, as_string, field_name, tvb_begin, tvb_end};

        case TypeInfo::Map: {
            data::Map result;

            for ( const auto& [key, value] : type->map->iterate(v) ) {
                auto kval = _hiltiValueToDataValue(packet, key, {}, {}, {});
                auto vval = _hiltiValueToDataValue(packet, value, {}, {}, {});
                result.emplace(std::move(kval), std::move(vval));
            }

            return {std::move(result), type, as_string, field_name, tvb_begin, tvb_end};
        }

        case TypeInfo::Optional: {
            const auto& value = type->optional->value(v);
            if ( value )
                return {data::Boxed(_hiltiValueToDataValue(packet, value, field_name, begin, end)),
                        type,
                        as_string,
                        field_name,
                        tvb_begin,
                        tvb_end};
            else
                return {data::Boxed(_hiltiValueToDataValue(packet, value, field_name, {}, {})),
                        type,
                        as_string,
                        field_name,
                        {},
                        {}};
        }

        case TypeInfo::Port:
            return {static_cast<uint64_t>(type->port->get(v).port()), type, as_string, field_name, tvb_begin, tvb_end};

        case TypeInfo::SignedInteger_int8:
            return {static_cast<int64_t>(type->signed_integer_int8->get(v)),
                    type,
                    as_string,
                    field_name,
                    tvb_begin,
                    tvb_end};

        case TypeInfo::SignedInteger_int16:
            return {static_cast<int64_t>(type->signed_integer_int16->get(v)),
                    type,
                    as_string,
                    field_name,
                    tvb_begin,
                    tvb_end};

        case TypeInfo::SignedInteger_int32:
            return {static_cast<int64_t>(type->signed_integer_int32->get(v)),
                    type,
                    as_string,
                    field_name,
                    tvb_begin,
                    tvb_end};

        case TypeInfo::SignedInteger_int64:
            return {type->signed_integer_int64->get(v), type, as_string, field_name, tvb_begin, tvb_end};

        case TypeInfo::Time: return {type->time->get(v).nanoseconds(), type, as_string, field_name, tvb_begin, tvb_end};

        case TypeInfo::Real: return {type->real->get(v), type, as_string, field_name, tvb_begin, tvb_end};

        case TypeInfo::Set: {
            data::Set result;

            for ( const auto& value : type->set->iterate(v) )
                result.emplace(_hiltiValueToDataValue(packet, value, {}, {}, {}));

            return {result, type, as_string, field_name, tvb_begin, tvb_end};
        }

        case TypeInfo::String: return {type->string->get(v), type, as_string, field_name, tvb_begin, tvb_end};

        case TypeInfo::StrongReference:
            return {data::Boxed(
                        _hiltiValueToDataValue(packet, type->strong_reference->value(v), field_name, begin, end)),
                    type,
                    as_string,
                    field_name,
                    tvb_begin,
                    tvb_end};

        case TypeInfo::Struct: {
            const auto* offsets = spicy::rt::get_offsets_for_unit(*type->struct_, v);

            const auto& get_offsets =
                [&](const std::string& id) -> std::pair<std::optional<hilti::rt::integer::safe<uint64_t>>,
                                                        std::optional<hilti::rt::integer::safe<uint64_t>>> {
                std::optional<hilti::rt::integer::safe<uint64_t>> begin, end;

                if ( offsets ) {
                    if ( const auto& x = offsets->get_optional(id) ) {
                        begin = hilti::rt::tuple::get<0>(*x);
                        if ( const auto& i = hilti::rt::tuple::get<1>(*x) )
                            end = *i;
                    }
                }

                if ( begin && end )
                    return std::make_pair(begin, end);
                else
                    return std::make_pair(std::nullopt, std::nullopt);
            };

            data::Struct result;

            for ( const auto& [index, field] : hilti::rt::enumerate(type->struct_->iterate(v)) ) {
                if ( ! field.second )
                    continue;

                if ( field.first.isInternal() )
                    continue;

                std::optional<std::string> fname;
                if ( ! field.first.isAnonymous() )
                    fname = field.first.name;

                const auto& [fbegin, fend] = get_offsets(field.first.name);
                result.emplace_back(_hiltiValueToDataValue(packet, field.second, fname, fbegin, fend));
            }

            const auto& [self_begin, self_end] = get_offsets("self");
            auto [tvb_struct_begin, tvb_struct_end] = _streamOffsetsToTvbOffsets(packet, self_begin, self_end);
            return {std::move(result), type, as_string, field_name, tvb_struct_begin, tvb_struct_end};
        }

        case TypeInfo::UnsignedInteger_uint8:
            return {static_cast<uint64_t>(type->unsigned_integer_uint8->get(v)),
                    type,
                    as_string,
                    field_name,
                    tvb_begin,
                    tvb_end};

        case TypeInfo::UnsignedInteger_uint16:
            return {static_cast<uint64_t>(type->unsigned_integer_uint16->get(v)),
                    type,
                    as_string,
                    field_name,
                    tvb_begin,
                    tvb_end};

        case TypeInfo::UnsignedInteger_uint32:
            return {static_cast<uint64_t>(type->unsigned_integer_uint32->get(v)),
                    type,
                    as_string,
                    field_name,
                    tvb_begin,
                    tvb_end};

        case TypeInfo::UnsignedInteger_uint64:
            return {type->unsigned_integer_uint64->get(v), type, as_string, field_name, tvb_begin, tvb_end};

        case TypeInfo::Tuple: {
            data::Tuple result;

            for ( const auto& element : type->tuple->iterate(v) ) {
                std::optional<std::string> ename;
                if ( ! element.first.name.empty() )
                    ename = element.first.name;

                result.emplace_back(_hiltiValueToDataValue(packet, element.second, ename, {}, {}));
            }

            return {std::move(result), type, as_string, field_name, tvb_begin, tvb_end};
        }

        case TypeInfo::ValueReference: {
            return {data::Boxed(
                        _hiltiValueToDataValue(packet, type->value_reference->value(v), field_name, begin, end)),
                    type,
                    as_string,
                    field_name,
                    tvb_begin,
                    tvb_end};
        }

        case TypeInfo::Vector: {
            data::Vector result;

            for ( const auto& value : type->vector->iterate(v) )
                result.emplace_back(_hiltiValueToDataValue(packet, value, {}, {}, {}));

            return {result, type, as_string, field_name, tvb_begin, tvb_end};
        }

        case TypeInfo::Void: return {{}, type, as_string, field_name, tvb_begin, tvb_end};

        case TypeInfo::WeakReference:
            return {data::Boxed(_hiltiValueToDataValue(packet, type->weak_reference->value(v), field_name, begin, end)),
                    type,
                    as_string,
                    field_name,
                    tvb_begin,
                    tvb_end};

        case TypeInfo::Any:
        case TypeInfo::BytesIterator:
        case TypeInfo::Error:
        case TypeInfo::Exception:
        case TypeInfo::Function:
        case TypeInfo::Library:
        case TypeInfo::MapIterator:
        case TypeInfo::Network:
        case TypeInfo::Null:
        case TypeInfo::RegExp:
        case TypeInfo::Result:
        case TypeInfo::SetIterator:
        case TypeInfo::Stream:
        case TypeInfo::StreamIterator:
        case TypeInfo::StreamView:
        case TypeInfo::Undefined:
        case TypeInfo::Union:
        case TypeInfo::VectorIterator:
            return {data::Error("spicy.error.unsupported",
                                fmt("Spicy type '%s' not supported for Wireshark data conversion", type->display)),
                    &hilti::rt::type_info::error,
                    as_string,
                    field_name,
                    {},
                    {}};
    }

    hilti::rt::cannot_be_reached();
}

static const HeaderField* _getHeaderField(Dissector* dissector, const std::string& filter_name, std::string tag) {
    auto i = dissector->header_fields.find(filter_name);
    if ( i == dissector->header_fields.end() )
        spicy_fatal_error("add_value_to_tree: header field '%s' not registered", filter_name.c_str());

    auto j = i->second.find(tag);
    if ( j == i->second.end() )
        spicy_fatal_error("add_value_to_tree: header field '%s' has no registered tag '%s'", filter_name.c_str(),
                          tag.c_str());

    return &j->second;
}

static void _addDataValueToTree(const Packet& packet, proto_tree* tree, proto_item* tree_item, const data::Value& v,
                                unsigned int level, const std::string& field_name, const std::string& filter_name) {
    auto get_header_field = [&](std::optional<std::string> filter_name_override = {}) {
        const auto* hf =
            _getHeaderField(packet.dissector, (filter_name_override ? *filter_name_override : filter_name), "");
        assert(! hf->isSubtree());
        return hf;
    };

    auto get_header_field_for_tag = [&](const std::string& tag = "",
                                        std::optional<std::string> filter_name_override = {}) {
        const auto* hf =
            _getHeaderField(packet.dissector, (filter_name_override ? *filter_name_override : filter_name), tag);
        assert(! hf->isSubtree());
        return hf;
    };

    auto get_subtree = [&](std::string tree_filter_name = "", const std::string& tag = "") {
        if ( tree_filter_name.empty() )
            tree_filter_name = filter_name;

        const auto* hf = _getHeaderField(packet.dissector, tree_filter_name, tag);
        assert(hf->isSubtree());
        return hf;
    };

    auto get_expert_item = [&](const std::string& name) {
        auto i = packet.dissector->expert_fields.find(name);
        if ( i == packet.dissector->expert_fields.end() )
            spicy_internal_error("add_value_to_tree: expert item '%s' not registered", name.c_str());

        return &i->second;
    };

    auto add_bitfield_to_tree = [&](proto_tree* tree, data::Value v, const std::string& filter_prefix, int start,
                                    int length) {
        for ( const auto& [bits, bvalue] : util::zip2(v.type->bitfield->bits(), std::get<data::Vector>(v.value)) ) {
            assert(bvalue.field_name);
            const std::string& bits_name = *bvalue.field_name;
            std::string bits_filter_name = fmt("%s.%s", filter_prefix, util::toLower(bits_name));
            const auto& hf = get_header_field(bits_filter_name);

            const auto& value = std::get<uint64_t>(bvalue.value);

            // Wireshark's API function for displaying bitfields as individual
            // bits read the value from the TVB, which doesn't work for us. So
            // just show them as integers for now.
            if ( v.type->bitfield->width() <= 32 )
                proto_tree_add_uint_format(tree, *hf->hf_index, packet.tvb, start, length, value, "%s: %" PRIu64,
                                           bits_name.c_str(), value);
            else
                proto_tree_add_uint64_format(tree, *hf->hf_index, packet.tvb, start, length, value, "%s: %" PRIu64,
                                             bits_name.c_str(), value);
        }
    };

    assert(level == 0 || ! filter_name.empty());

    if ( ! v )
        return;

    // We render our labels ourselves from the field_name passed in (not from
    // the ones registered). That allows us to deal with empty names. All
    // fields will prefix their textual representation with the `field_prefix`
    // we set here.
    std::string field_prefix;

    if ( ! field_name.empty() )
        field_prefix = fmt("%s: ", field_name);

    int start = 0;
    int length = 0;

    if ( v.begin && v.end ) {
        auto begin = *v.begin;
        auto end = *v.end; // end is exclusive
        if ( end >= begin ) {
            start = static_cast<int>(begin);
            length = static_cast<int>(end - begin);
            int cap = tvb_captured_length(packet.tvb);
            if ( start + length > cap )
                length = (cap > start) ? (cap - start) : 0;
        }
    }

    const auto* type = v.type;

    if ( ws_log_msg_is_active("Spicy", LOG_LEVEL_NOISY) ) {
        std::string data = "n/a";

        if ( length > 0 ) {
            auto* buffer = reinterpret_cast<char*>(alloca(length + 1));
            tvb_get_raw_bytes_as_string(packet.tvb, start, buffer, length + 1);
            data = hilti::rt::fmt("|%s|", hilti::rt::escapeBytes(buffer));
        }

        spicy_noisy("%s: type=%s offset=%d length=%d data=%s",
                    (filter_name.empty() ? "(no name)" : filter_name.c_str()), type->display, start, length,
                    data.c_str());
    }

    switch ( type->tag ) {
        case TypeInfo::Address: {
            const auto& addr = std::get<hilti::rt::Address>(v.value).asInAddr();

            if ( auto* v4 = std::get_if<struct in_addr>(&addr) ) {
                const auto& hf = get_header_field_for_tag("ipv4");
                proto_tree_add_ipv4_format(tree, *hf->hf_index, packet.tvb, start, length, v4->s_addr, "%s%s",
                                           field_prefix.c_str(), v.as_string.c_str());
            }
            else if ( auto* v6 = std::get_if<struct in6_addr>(&addr) ) {
                const auto& hf = get_header_field_for_tag("ipv6");
                proto_tree_add_ipv6_format(tree, *hf->hf_index, packet.tvb, start, length,
                                           reinterpret_cast<const ws_in6_addr*>(v6->s6_addr), "%s%s",
                                           field_prefix.c_str(), v.as_string.c_str());
            }
            else {
                auto ei = get_expert_item("spicy.error.unsupported");
                proto_tree_add_expert_format(tree, packet.pinfo, ei->expert_field_, packet.tvb, start, length,
                                             "%sunsupported address type", field_prefix.c_str());
            }

            break;
        }

        case TypeInfo::Bitfield: {
            auto* subtree = get_subtree(filter_name);
            auto ntree_item =
                proto_tree_add_string_format(tree, *subtree->hf_index, packet.tvb, start, length, v.as_string.c_str(),
                                             "%s%s", field_prefix.c_str(), v.as_string.c_str());
            auto* ntree = proto_item_add_subtree(ntree_item, subtree->ett);
            add_bitfield_to_tree(ntree, v, filter_name, start, length);
            break;
        }

        case TypeInfo::Bool: {
            const auto& hf = get_header_field();
            const auto& value = std::get<bool>(v.value);
            proto_tree_add_boolean_format(tree, *hf->hf_index, packet.tvb, start, length, value, "%s%s",
                                          field_prefix.c_str(), v.as_string.c_str());
            break;
        }

        case TypeInfo::Bytes: {
            const auto& hf = get_header_field();
            const auto& data = std::get<std::string>(v.value);

            // Note that length here must be the length of the actual data, not
            // just the normal offset information (which may not be set).
            // Otherwise, the JSON output will be broken, it apparently takes
            // this arguments as the length of the data. This is also true for
            // the other proto_add_bytes_*() functions, even when we provide
            // the formatting ourselves! (-V is fine either way, but -O json is
            // not.)
            auto txt = hilti::rt::to_string_for_print(data);
            proto_tree_add_bytes_format(tree, *hf->hf_index, packet.tvb, start, length,
                                        reinterpret_cast<const uint8_t*>(txt.c_str()), "%s%s", field_prefix.c_str(),
                                        txt.c_str());

            break;
        }

        case TypeInfo::Enum: {
            const auto& hf = get_header_field();
            auto label = util::stripScope(v.as_string);

            if ( auto value = std::get<int64_t>(v.value); value >= 0 )
                proto_tree_add_uint64_format(tree, *hf->hf_index, packet.tvb, start, length, value,
                                             "%s%s (0x%02" PRIx64 ")", field_prefix.c_str(), label.c_str(),
                                             static_cast<uint64_t>(value));
            else
                proto_tree_add_uint64_format(tree, *hf->hf_index, packet.tvb, start, length, value, "%s%s",
                                             field_prefix.c_str(), label.c_str());


            break;
        }

        case TypeInfo::Interval: {
            const auto& hf = get_header_field();
            nstime_t ns_time;
            ns_time.secs = std::get<int64_t>(v.value) / 1000000000;
            ns_time.nsecs = std::get<int64_t>(v.value) % 1000000000;

            proto_tree_add_time_format(tree, *hf->hf_index, packet.tvb, start, length, &ns_time, "%s%s",
                                       field_prefix.c_str(), rel_time_to_str(wmem_file_scope(), &ns_time));
            break;
        }

        case TypeInfo::Map: {
            auto* subtree = get_subtree(filter_name + ".display");

            auto ntree_item =
                proto_tree_add_string_format(tree, *subtree->hf_index, packet.tvb, start, length, v.as_string.c_str(),
                                             "%s%s", field_prefix.c_str(), v.as_string.c_str());

            auto* ntree = proto_item_add_subtree(ntree_item, subtree->ett);

            for ( const auto& [key, value] : std::get<data::Map>(v.value) ) {
                _addDataValueToTree(packet, ntree, ntree_item, key, level + 1, "key", filter_name + ".key");
                _addDataValueToTree(packet, ntree, ntree_item, value, level + 1, "value", filter_name + ".value");
            }

            break;
        }

        case TypeInfo::Optional: {
            if ( const auto& optional = std::get<data::Boxed>(v.value).value() )
                _addDataValueToTree(packet, tree, tree_item, optional, level, field_name, filter_name);
            else {
                const auto& hf = get_header_field();
                proto_tree_add_string_format(tree, *hf->hf_index, packet.tvb, start, length, nullptr, "%s(not set)",
                                             field_prefix.c_str());
            }

            break;
        }

        case TypeInfo::Port: {
            const auto& hf = get_header_field();
            auto value = static_cast<uint16_t>(std::get<uint64_t>(v.value));
            proto_tree_add_uint_format(tree, *hf->hf_index, packet.tvb, start, length, value, "%s%" PRIu16,
                                       field_prefix.c_str(), value);
            break;
        }

        case TypeInfo::SignedInteger_int8:
        case TypeInfo::SignedInteger_int16:
        case TypeInfo::SignedInteger_int32: {
            const auto& hf = get_header_field();
            auto value = static_cast<int32_t>(std::get<int64_t>(v.value));
            proto_tree_add_int_format(tree, *hf->hf_index, packet.tvb, start, length, value, "%s%" PRId32,
                                      field_prefix.c_str(), value);
            break;
        }

        case TypeInfo::SignedInteger_int64: {
            const auto& hf = get_header_field();
            auto value = std::get<int64_t>(v.value);
            proto_tree_add_int64_format(tree, *hf->hf_index, packet.tvb, start, length, value, "%s%" PRId64,
                                        field_prefix.c_str(), value);
            break;
        }

        case TypeInfo::Time: {
            const auto& hf = get_header_field();
            nstime_t ns_time;
            ns_time.secs = std::get<uint64_t>(v.value) / 1000000000;
            ns_time.nsecs = std::get<uint64_t>(v.value) % 1000000000;

            proto_tree_add_time_format(tree, *hf->hf_index, packet.tvb, start, length, &ns_time, "%s%s",
                                       field_prefix.c_str(),
                                       abs_time_to_str_ex(wmem_file_scope(), &ns_time,
                                                          ABSOLUTE_TIME_LOCAL, // hf->..->display isn't correct here
                                                                               // for some reason?
                                                          ABS_TIME_TO_STR_SHOW_ZONE));
            break;
        }

        case TypeInfo::Real: {
            const auto& hf = get_header_field();
            auto value = std::get<double>(v.value);
            proto_tree_add_double_format(tree, *hf->hf_index, packet.tvb, start, length, value, "%s%.6f",
                                         field_prefix.c_str(), value);
            break;
        }

        case TypeInfo::Set: {
            auto* subtree = get_subtree(filter_name + ".display");
            auto ntree_item =
                proto_tree_add_string_format(tree, *subtree->hf_index, packet.tvb, start, length, v.as_string.c_str(),
                                             "%s%s", field_prefix.c_str(), v.as_string.c_str());
            auto* ntree = proto_item_add_subtree(ntree_item, subtree->ett);

            for ( const auto& value : std::get<data::Set>(v.value) )
                _addDataValueToTree(packet, ntree, ntree_item, value, level + 1, "", filter_name);

            break;
        }

        case TypeInfo::String: {
            const auto& hf = get_header_field();
            const auto& data = hilti::rt::to_string_for_print(std::get<std::string>(v.value));

            proto_tree_add_string_format(tree, *hf->hf_index, packet.tvb, start, length, field_prefix.c_str(), "%s%s",
                                         field_prefix.c_str(), data.c_str());
            break;
        }

        case TypeInfo::StrongReference: {
            auto value = std::get<data::Boxed>(v.value).value();
            _addDataValueToTree(packet, tree, tree_item, value, level, field_name, filter_name);
            break;
        }

        case TypeInfo::Struct: {
            auto struct_type_name = util::stripScope(v.type->display);
            auto struct_filter_name = util::toLower(fmt("%s.%s", packet.dissector->short_name, struct_type_name));

            auto description = hilti::rt::fmt("%s", v.as_string);
            if ( description.size() > 100 )
                description = hilti::rt::fmt("%s …", hilti::rt::to_string_for_print(description).substr(0, 100));

            auto* ntree = tree;
            auto* ntree_item = tree_item;

            if ( level == 0 ) {
                proto_item_append_text(tree_item, ", %s", struct_type_name.c_str());

                if ( ! description.empty() )
                    proto_item_append_text(tree_item, ": %s", description.c_str());
            }
            else {
                auto* subtree = get_subtree(struct_filter_name);
                ntree_item = proto_tree_add_string_format(tree, *subtree->hf_index, packet.tvb, start, length,
                                                          description.c_str(), "%s%s", field_prefix.c_str(),
                                                          description.c_str());
                ntree = proto_item_add_subtree(ntree_item, subtree->ett);
            }

            for ( const auto& fvalue : std::get<data::Struct>(v.value) ) {
                std::string fname;

                if ( ! fvalue.field_name ) {
                    if ( fvalue.type->tag == TypeInfo::Bitfield )
                        add_bitfield_to_tree(tree, fvalue, struct_filter_name, start, length);

                    continue; // ignore all other anonymous fields
                }
                else
                    fname = util::toLower(*fvalue.field_name);

                auto hf_filter_name = fmt("%s.%s", struct_filter_name, fname);
                if ( fvalue )
                    _addDataValueToTree(packet, ntree, ntree_item, fvalue, level + 1, fname, hf_filter_name);
                else {
                    // We don't show unset fields. Not sure if that's generally
                    // the right choice, but it's also technically
                    // easier/nicer: to show an "<unset>" note, we'd have to
                    // register a separate FT_STRING field, which, it turns
                    // out, would show up in the JSON output even if the the
                    // field is set.
                }
            }

            break;
        }

        case TypeInfo::Tuple: {
            auto* subtree = get_subtree();
            auto ntree_item =
                proto_tree_add_string_format(tree, *subtree->hf_index, packet.tvb, start, length, v.as_string.c_str(),
                                             "%s%s", field_prefix.c_str(), v.as_string.c_str());
            auto* ntree = proto_item_add_subtree(ntree_item, subtree->ett);

            for ( const auto& [index, evalue] : hilti::rt::enumerate(std::get<data::Tuple>(v.value)) ) {
                if ( ! evalue )
                    // We don't show unset values. Not sure if that's generally
                    // the right choice, but it's also technically
                    // easier/nicer: to show an "<unset>" note, we'd have to
                    // register a separate FT_STRING field.
                    continue;

                std::string id;
                std::string hf_filter_name;

                if ( evalue.field_name ) {
                    id = *evalue.field_name;
                    hf_filter_name = fmt("%s.%s", filter_name, util::toLower(*evalue.field_name));
                }
                else
                    hf_filter_name = fmt("%s.%u", filter_name, index);

                _addDataValueToTree(packet, ntree, ntree_item, evalue, level + 1, id, hf_filter_name);
            }

            break;
        }

        case TypeInfo::ValueReference: {
            auto value = std::get<data::Boxed>(v.value).value();
            _addDataValueToTree(packet, tree, tree_item, value, level, field_name, filter_name);
            break;
        }

        case TypeInfo::Vector: {
            auto* subtree = get_subtree(filter_name + ".display");
            auto ntree_item =
                proto_tree_add_string_format(tree, *subtree->hf_index, packet.tvb, start, length, v.as_string.c_str(),
                                             "%s%s", field_prefix.c_str(), v.as_string.c_str());
            auto* ntree = proto_item_add_subtree(ntree_item, subtree->ett);

            for ( const auto& value : std::get<data::Vector>(v.value) )
                _addDataValueToTree(packet, ntree, ntree_item, value, level + 1, "", filter_name);

            break;
        }

        case TypeInfo::Void: {
            // Just skip, nothing to do.
            break;
        }

        case TypeInfo::UnsignedInteger_uint8:
        case TypeInfo::UnsignedInteger_uint16:
        case TypeInfo::UnsignedInteger_uint32: {
            const auto& hf = get_header_field();
            auto value = static_cast<uint32_t>(std::get<uint64_t>(v.value));
            proto_tree_add_uint_format(tree, *hf->hf_index, packet.tvb, start, length, value, "%s%" PRIu32,
                                       field_prefix.c_str(), value);
            break;
        }

        case TypeInfo::UnsignedInteger_uint64: {
            const auto& hf = get_header_field();
            auto value = std::get<uint64_t>(v.value);
            proto_tree_add_uint64_format(tree, *hf->hf_index, packet.tvb, start, length, value, "%s%" PRIu64,
                                         field_prefix.c_str(), value);
            break;
        }

        case TypeInfo::WeakReference: {
            auto value = std::get<data::Boxed>(v.value).value();
            _addDataValueToTree(packet, tree, tree_item, value, level, field_name, filter_name);
            break;
        }

        case TypeInfo::Error: {
            auto value = std::get<data::Error>(v.value);
            auto ei = get_expert_item(value.ei_name);
            proto_tree_add_expert_format(tree, packet.pinfo, ei->expert_field_, packet.tvb, start, length, "%s%s",
                                         field_prefix.c_str(), value.message.c_str());
            break;
        }

        case TypeInfo::Any:
        case TypeInfo::BytesIterator:
        case TypeInfo::Exception:
        case TypeInfo::Function:
        case TypeInfo::Library:
        case TypeInfo::MapIterator:
        case TypeInfo::Network:
        case TypeInfo::Null:
        case TypeInfo::RegExp:
        case TypeInfo::Result:
        case TypeInfo::SetIterator:
        case TypeInfo::Stream:
        case TypeInfo::StreamIterator:
        case TypeInfo::StreamView:
        case TypeInfo::Undefined:
        case TypeInfo::Union:
        case TypeInfo::VectorIterator:
            // Data conversion should never produce any unsupported types (it'll create an `Error` if encountered).
            hilti::rt::cannot_be_reached();
    }
}

void spicy::wireshark::registerStaticHeaderFields(Dissector* dissector) {
    _registerHeaderField(dissector, "TODO", "__spicy.todo", FT_STRING,
                         BASE_NONE); // TODO: Remove this once no longer needed

    _allocateHeaderField(dissector, dissector->short_name, dissector->short_name, "", true, FT_STRING, BASE_NONE,
                         nullptr, 0);
}

void spicy::wireshark::registerStaticExpertItems(spicy::wireshark::Dissector* dissector) {
    // Note: We currently don't support Spicy code creating its own expert items, so
    // we just register a few static ones here.
    _registerExpertItem(dissector, "spicy.error.parse", PI_MALFORMED, PI_WARN, "Protocol parse error");
    _registerExpertItem(dissector, "spicy.error.unsupported", PI_UNDECODED, PI_WARN, "Unsupported Spicy feature");
}

void spicy::wireshark::registerHeaderFieldForStruct(Dissector* dissector, const hilti::rt::TypeInfo* type, int level) {
    assert(type->tag == hilti::rt::TypeInfo::Struct);
    _registerHeaderField(dissector, "", "", "", type, level); // field and filter names not needed for struct
}

data::Value spicy::wireshark::hiltiValueToDataValue(Packet* packet, const hilti::rt::type_info::Value& v,
                                                    const std::optional<std::string>& field_name,
                                                    std::optional<hilti::rt::integer::safe<uint64_t>> begin,
                                                    std::optional<hilti::rt::integer::safe<uint64_t>> end) {
    return _hiltiValueToDataValue(packet, v, field_name, begin, end);
}

void spicy::wireshark::createProtocolTree(const Packet& packet, proto_tree* tree, const data::Value& value) {
    assert(value);
    assert(value.type->tag == hilti::rt::TypeInfo::Error || value.type->tag == hilti::rt::TypeInfo::Struct);

    const auto* subtree = _getHeaderField(packet.dissector, packet.dissector->short_name, "");
    auto root_item = proto_tree_add_string_format(tree, *subtree->hf_index, packet.tvb, 0, 0, nullptr, "%s",
                                                  packet.dissector->name.c_str());
    auto* root_tree = proto_item_add_subtree(root_item, subtree->ett);

    _addDataValueToTree(packet, root_tree, root_item, value, 0, "", "");
}
