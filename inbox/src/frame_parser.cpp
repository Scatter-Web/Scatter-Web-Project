#include "frame_parser.hpp"
#include <cbor.h>
#include <iomanip>
#include <sstream>
#include <cstring>

namespace sw::inbox {

static std::string bytes_to_hex(const uint8_t* d, size_t n) {
    std::ostringstream ss;
    for (size_t i = 0; i < n; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)d[i];
    return ss.str();
}

bool parse_frame_header(ByteSpan delivery_frame, FrameHeader& out) {
    struct cbor_load_result res{};
    cbor_item_t* root = cbor_load(
        reinterpret_cast<const unsigned char*>(delivery_frame.data()),
        delivery_frame.size(), &res);
    if (!root || res.error.code != CBOR_ERR_NONE) {
        if (root) cbor_decref(&root);
        return false;
    }
    if (!cbor_isa_map(root)) { cbor_decref(&root); return false; }

    for (size_t i = 0; i < cbor_map_size(root); ++i) {
        auto p = cbor_map_handle(root)[i];
        if (!cbor_isa_string(p.key)) continue;
        std::string k(reinterpret_cast<char*>(cbor_string_handle(p.key)),
                      cbor_string_length(p.key));

        if (k == "message_id" && cbor_isa_bytestring(p.value)
                && cbor_bytestring_length(p.value) == 16) {
            out.message_id = bytes_to_hex(cbor_bytestring_handle(p.value), 16);
        } else if (k == "sender_id" && cbor_isa_bytestring(p.value)
                && cbor_bytestring_length(p.value) == 32) {
            out.sender_id = bytes_to_hex(cbor_bytestring_handle(p.value), 32);
        } else if (k == "persistence" && cbor_isa_string(p.value)) {
            out.persistence.assign(
                reinterpret_cast<char*>(cbor_string_handle(p.value)),
                cbor_string_length(p.value));
        }
    }
    cbor_decref(&root);
    return !out.message_id.empty() && !out.sender_id.empty();
}

} // namespace sw::inbox
