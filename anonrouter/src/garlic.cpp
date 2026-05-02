#include "garlic.hpp"
#include <cbor.h>
#include <cstring>

// CBOR garlic_blob layout (array per clove):
//   [ type:uint, channel_id:bstr(16), has_frag:bool,
//     [clove_id, idx, total] or null,
//     payload:bstr ]

namespace sw::anonrouter {

static cbor_item_t* encode_clove(const Clove& c) {
    cbor_item_t* arr = cbor_new_definite_array(5);

    cbor_array_push(arr, cbor_build_uint64(static_cast<uint64_t>(c.type)));

    cbor_item_t* cid = cbor_build_bytestring(
        reinterpret_cast<const unsigned char*>(c.channel_id.data()),
        c.channel_id.size());
    cbor_array_push(arr, cid);

    cbor_array_push(arr, cbor_build_bool(c.frag.has_value()));

    if (c.frag) {
        cbor_item_t* fi = cbor_new_definite_array(3);
        cbor_array_push(fi, cbor_build_uint64(c.frag->clove_id));
        cbor_array_push(fi, cbor_build_uint64(c.frag->idx));
        cbor_array_push(fi, cbor_build_uint64(c.frag->total));
        cbor_array_push(arr, fi);
    } else {
        cbor_array_push(arr, cbor_new_null());
    }

    cbor_item_t* pl = cbor_build_bytestring(
        reinterpret_cast<const unsigned char*>(c.payload.data()),
        c.payload.size());
    cbor_array_push(arr, pl);

    return arr;
}

Bytes garlic_encode(const std::vector<Clove>& cloves) {
    cbor_item_t* root = cbor_new_definite_array(cloves.size());
    for (auto& c : cloves)
        cbor_array_push(root, encode_clove(c));

    uint8_t* buf = nullptr;
    size_t   len = 0;
    cbor_serialize_alloc(root, &buf, &len);
    cbor_decref(&root);

    if (!buf) return {};
    Bytes out(buf, buf + len);
    free(buf);
    return out;
}

std::vector<Clove> garlic_decode(ByteSpan blob) {
    std::vector<Clove> out;
    struct cbor_load_result res{};
    cbor_item_t* root = cbor_load(
        reinterpret_cast<const unsigned char*>(blob.data()), blob.size(), &res);
    if (!root || res.error.code != CBOR_ERR_NONE) {
        if (root) cbor_decref(&root);
        return {};
    }
    if (!cbor_isa_array(root)) { cbor_decref(&root); return {}; }

    size_t n = cbor_array_size(root);
    out.reserve(n);
    cbor_item_t** items = cbor_array_handle(root);
    for (size_t i = 0; i < n; ++i) {
        cbor_item_t* cv = items[i];
        if (!cbor_isa_array(cv) || cbor_array_size(cv) < 5) continue;
        cbor_item_t** f = cbor_array_handle(cv);

        Clove c;
        c.type = static_cast<CloveType>(cbor_get_uint64(f[0]));

        if (cbor_isa_bytestring(f[1]) && cbor_bytestring_length(f[1]) == 16)
            std::memcpy(c.channel_id.data(), cbor_bytestring_handle(f[1]), 16);

        bool has_frag = cbor_is_bool(f[2]) && cbor_get_bool(f[2]);
        if (has_frag && cbor_isa_array(f[3]) && cbor_array_size(f[3]) == 3) {
            cbor_item_t** ff = cbor_array_handle(f[3]);
            FragInfo fi;
            fi.clove_id = static_cast<uint32_t>(cbor_get_uint64(ff[0]));
            fi.idx      = static_cast<uint16_t>(cbor_get_uint64(ff[1]));
            fi.total    = static_cast<uint16_t>(cbor_get_uint64(ff[2]));
            c.frag = fi;
        }

        if (cbor_isa_bytestring(f[4])) {
            auto* h = cbor_bytestring_handle(f[4]);
            c.payload.assign(h, h + cbor_bytestring_length(f[4]));
        }
        out.push_back(std::move(c));
    }
    cbor_decref(&root);
    return out;
}

} // namespace sw::anonrouter
