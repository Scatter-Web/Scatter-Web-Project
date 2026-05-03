#include <sw/ipc/codec.hpp>
#include <cbor.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <stdexcept>

namespace sw::ipc {

// ── CborValue ────────────────────────────────────────────────────────────────

CborValue::CborValue() : data_(std::monostate{}) {}

CborValue CborValue::null_val()                { CborValue v; return v; }
CborValue CborValue::from_bool(bool b)         { CborValue v; v.data_ = b;  return v; }
CborValue CborValue::from_uint(uint64_t u)     { CborValue v; v.data_ = u;  return v; }
CborValue CborValue::from_int(int64_t i)       { CborValue v; v.data_ = i;  return v; }
CborValue CborValue::from_string(std::string s){ CborValue v; v.data_ = std::move(s); return v; }
CborValue CborValue::from_bytes(Bytes b)       { CborValue v; v.data_ = std::move(b); return v; }
CborValue CborValue::from_array(CborArray arr) {
    CborValue v;
    v.data_ = std::make_shared<CborArray>(std::move(arr));
    return v;
}
CborValue CborValue::from_map(CborMap map) {
    CborValue v;
    v.data_ = std::make_shared<CborMap>(std::move(map));
    return v;
}

bool CborValue::is_null()   const noexcept { return std::holds_alternative<std::monostate>(data_); }
bool CborValue::is_bool()   const noexcept { return std::holds_alternative<bool>(data_); }
bool CborValue::is_uint()   const noexcept { return std::holds_alternative<uint64_t>(data_); }
bool CborValue::is_int()    const noexcept { return std::holds_alternative<int64_t>(data_); }
bool CborValue::is_string() const noexcept { return std::holds_alternative<std::string>(data_); }
bool CborValue::is_bytes()  const noexcept { return std::holds_alternative<Bytes>(data_); }
bool CborValue::is_array()  const noexcept { return std::holds_alternative<std::shared_ptr<CborArray>>(data_); }
bool CborValue::is_map()    const noexcept { return std::holds_alternative<std::shared_ptr<CborMap>>(data_); }

bool               CborValue::as_bool()   const { return std::get<bool>(data_); }
uint64_t           CborValue::as_uint()   const { return std::get<uint64_t>(data_); }
int64_t            CborValue::as_int()    const { return std::get<int64_t>(data_); }
const std::string& CborValue::as_string() const { return std::get<std::string>(data_); }
const Bytes&       CborValue::as_bytes()  const { return std::get<Bytes>(data_); }
const CborArray&   CborValue::as_array()  const { return *std::get<std::shared_ptr<CborArray>>(data_); }
CborArray&         CborValue::as_array()        { return *std::get<std::shared_ptr<CborArray>>(data_); }
const CborMap&     CborValue::as_map()    const { return *std::get<std::shared_ptr<CborMap>>(data_); }
CborMap&           CborValue::as_map()          { return *std::get<std::shared_ptr<CborMap>>(data_); }

// ── CBOR item <-> CborValue ──────────────────────────────────────────────────

namespace {

// Forward declaration for recursive use.
CborValue item_to_value(cbor_item_t* item);
cbor_item_t* value_to_item(const CborValue& v);

// cbor_get_uint64 reads 8 bytes from the item's union regardless of the actual
// encoded width. For width < 64 bits, the high bytes are uninitialized.
// Always use the width-appropriate getter and zero-extend to uint64.
static uint64_t safe_get_uint(const cbor_item_t* item) {
    switch (cbor_int_get_width(item)) {
        case CBOR_INT_8:  return cbor_get_uint8(item);
        case CBOR_INT_16: return cbor_get_uint16(item);
        case CBOR_INT_32: return cbor_get_uint32(item);
        case CBOR_INT_64: return cbor_get_uint64(item);
    }
    return 0;
}

CborValue item_to_value(cbor_item_t* item) {
    if (!item) return CborValue::null_val();

    if (cbor_isa_uint(item))
        return CborValue::from_uint(safe_get_uint(item));

    if (cbor_isa_negint(item))
        return CborValue::from_int(-1 - static_cast<int64_t>(safe_get_uint(item)));

    if (cbor_isa_bytestring(item)) {
        Bytes b(cbor_bytestring_handle(item),
                cbor_bytestring_handle(item) + cbor_bytestring_length(item));
        return CborValue::from_bytes(std::move(b));
    }

    if (cbor_isa_string(item)) {
        return CborValue::from_string(
            std::string(reinterpret_cast<const char*>(cbor_string_handle(item)),
                        cbor_string_length(item)));
    }

    if (cbor_isa_array(item)) {
        CborArray arr;
        size_t len = cbor_array_size(item);
        auto handle = cbor_array_handle(item);
        arr.reserve(len);
        for (size_t i = 0; i < len; ++i)
            arr.push_back(item_to_value(handle[i]));
        return CborValue::from_array(std::move(arr));
    }

    if (cbor_isa_map(item)) {
        CborMap map;
        size_t len = cbor_map_size(item);
        auto pairs = cbor_map_handle(item);
        for (size_t i = 0; i < len; ++i) {
            if (!cbor_isa_string(pairs[i].key))
                throw std::runtime_error("CBOR map key must be text string");
            std::string key(reinterpret_cast<const char*>(cbor_string_handle(pairs[i].key)),
                            cbor_string_length(pairs[i].key));
            map[std::move(key)] = item_to_value(pairs[i].value);
        }
        return CborValue::from_map(std::move(map));
    }

    if (cbor_is_bool(item))
        return CborValue::from_bool(cbor_get_bool(item));

    if (cbor_is_null(item))
        return CborValue::null_val();

    throw std::runtime_error("Unsupported CBOR type");
}

cbor_item_t* value_to_item(const CborValue& v) {
    if (v.is_null())   return cbor_new_null();
    if (v.is_bool())   return cbor_build_bool(v.as_bool());
    if (v.is_uint())   return cbor_build_uint64(v.as_uint());
    if (v.is_int()) {
        int64_t i = v.as_int();
        if (i >= 0) return cbor_build_uint64(static_cast<uint64_t>(i));
        return cbor_build_negint64(static_cast<uint64_t>(-1 - i));
    }
    if (v.is_string()) {
        return cbor_build_string(v.as_string().c_str());
    }
    if (v.is_bytes()) {
        const auto& b = v.as_bytes();
        return cbor_build_bytestring(b.data(), b.size());
    }
    if (v.is_array()) {
        const auto& arr = v.as_array();
        cbor_item_t* item = cbor_new_definite_array(arr.size());
        for (auto& elem : arr) {
            cbor_item_t* child = value_to_item(elem);
            cbor_array_push(item, child);
            cbor_decref(&child);
        }
        return item;
    }
    if (v.is_map()) {
        const auto& map = v.as_map();
        cbor_item_t* item = cbor_new_definite_map(map.size());
        for (auto& [k, val] : map) {
            cbor_item_t* kitem = cbor_build_string(k.c_str());
            cbor_item_t* vitem = value_to_item(val);
            cbor_map_add(item, {kitem, vitem});
            cbor_decref(&kitem);
            cbor_decref(&vitem);
        }
        return item;
    }
    throw std::runtime_error("value_to_item: unhandled variant");
}

Bytes serialize_item(cbor_item_t* item) {
    unsigned char* buf = nullptr;
    size_t buf_size    = 0;
    size_t written     = cbor_serialize_alloc(item, &buf, &buf_size);
    Bytes out(buf, buf + written);
    free(buf);
    return out;
}

cbor_item_t* map_to_item(const CborMap& map) {
    cbor_item_t* item = cbor_new_definite_map(map.size());
    for (auto& [k, v] : map) {
        cbor_item_t* kitem = cbor_build_string(k.c_str());
        cbor_item_t* vitem = value_to_item(v);
        cbor_map_add(item, {kitem, vitem});
        cbor_decref(&kitem);
        cbor_decref(&vitem);
    }
    return item;
}

CborMap parse_top_map(ByteSpan data) {
    struct cbor_load_result res{};
    cbor_item_t* root = cbor_load(data.data(), data.size(), &res);
    if (!root || res.error.code != CBOR_ERR_NONE)
        throw std::runtime_error("CBOR parse error");
    if (!cbor_isa_map(root)) {
        cbor_decref(&root);
        throw std::runtime_error("Expected top-level CBOR map");
    }
    CborValue v = item_to_value(root);
    cbor_decref(&root);
    return v.as_map();
}

std::string require_string(const CborMap& m, const std::string& key) {
    auto it = m.find(key);
    if (it == m.end() || !it->second.is_string())
        throw std::runtime_error("Missing/invalid field: " + key);
    return it->second.as_string();
}

uint64_t require_uint(const CborMap& m, const std::string& key) {
    auto it = m.find(key);
    if (it == m.end() || !it->second.is_uint())
        throw std::runtime_error("Missing/invalid field: " + key);
    return it->second.as_uint();
}

} // namespace

// ── Encode ───────────────────────────────────────────────────────────────────

Bytes encode_request(const Request& req) {
    CborMap m;
    m["id"]     = CborValue::from_uint(req.id);
    m["caller"] = CborValue::from_string(req.caller);
    m["method"] = CborValue::from_string(req.method);
    m["params"] = CborValue::from_map(req.params);
    cbor_item_t* item = map_to_item(m);
    Bytes out = serialize_item(item);
    cbor_decref(&item);
    return out;
}

Bytes encode_response(const Response& resp) {
    CborMap m;
    m["id"] = CborValue::from_uint(resp.id);
    m["ok"] = CborValue::from_bool(resp.ok);
    if (resp.ok) {
        m["result"] = CborValue::from_map(resp.result);
    } else {
        CborMap err;
        err["code"]    = CborValue::from_uint(static_cast<uint64_t>(resp.error.code));
        err["message"] = CborValue::from_string(resp.error.message);
        m["error"] = CborValue::from_map(std::move(err));
    }
    cbor_item_t* item = map_to_item(m);
    Bytes out = serialize_item(item);
    cbor_decref(&item);
    return out;
}

Bytes encode_push(const Push& push) {
    CborMap m;
    m["event"]   = CborValue::from_string(push.event);
    m["payload"] = CborValue::from_map(push.payload);
    cbor_item_t* item = map_to_item(m);
    Bytes out = serialize_item(item);
    cbor_decref(&item);
    return out;
}

// ── Detect / Decode ──────────────────────────────────────────────────────────

MsgType detect(ByteSpan data) {
    try {
        CborMap m = parse_top_map(data);
        if (m.count("method")) return MsgType::Request;
        if (m.count("ok"))     return MsgType::Response;
        if (m.count("event"))  return MsgType::Push;
    } catch (...) {}
    return MsgType::Unknown;
}

Request decode_request(ByteSpan data) {
    CborMap m = parse_top_map(data);
    Request req;
    req.id     = require_uint(m, "id");
    req.caller = require_string(m, "caller");
    req.method = require_string(m, "method");
    auto pit = m.find("params");
    if (pit != m.end() && pit->second.is_map())
        req.params = pit->second.as_map();
    return req;
}

Response decode_response(ByteSpan data) {
    CborMap m = parse_top_map(data);
    Response resp;
    resp.id = require_uint(m, "id");
    auto ok_it = m.find("ok");
    if (ok_it == m.end() || !ok_it->second.is_bool())
        throw std::runtime_error("Response missing 'ok' bool");
    resp.ok = ok_it->second.as_bool();

    if (resp.ok) {
        auto rit = m.find("result");
        if (rit != m.end() && rit->second.is_map())
            resp.result = rit->second.as_map();
    } else {
        auto eit = m.find("error");
        if (eit != m.end() && eit->second.is_map()) {
            const auto& em = eit->second.as_map();
            auto cit = em.find("code");
            if (cit != em.end()) {
                if (cit->second.is_uint())
                    resp.error.code = static_cast<int>(cit->second.as_uint());
                else if (cit->second.is_int())
                    resp.error.code = static_cast<int>(cit->second.as_int());
            }
            auto mit = em.find("message");
            if (mit != em.end() && mit->second.is_string())
                resp.error.message = mit->second.as_string();
        }
    }
    return resp;
}

Push decode_push(ByteSpan data) {
    CborMap m = parse_top_map(data);
    Push push;
    push.event = require_string(m, "event");
    auto pit = m.find("payload");
    if (pit != m.end() && pit->second.is_map())
        push.payload = pit->second.as_map();
    return push;
}

// ── Framing ──────────────────────────────────────────────────────────────────

Bytes frame(const Bytes& payload) {
    uint32_t len = htonl(static_cast<uint32_t>(payload.size()));
    Bytes out(4 + payload.size());
    std::memcpy(out.data(), &len, 4);
    std::memcpy(out.data() + 4, payload.data(), payload.size());
    return out;
}

static bool read_exact(int fd, uint8_t* buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = ::read(fd, buf + done, n - done);
        if (r <= 0) return false;
        done += static_cast<size_t>(r);
    }
    return true;
}

Bytes read_frame(int fd) {
    uint8_t hdr[4];
    if (!read_exact(fd, hdr, 4)) return {};
    uint32_t len;
    std::memcpy(&len, hdr, 4);
    len = ntohl(len);
    if (len == 0 || len > 64 * 1024 * 1024)
        throw std::runtime_error("read_frame: invalid length " + std::to_string(len));
    Bytes payload(len);
    if (!read_exact(fd, payload.data(), len)) return {};
    return payload;
}

void write_frame(int fd, const Bytes& payload) {
    Bytes framed = frame(payload);
    size_t done  = 0;
    while (done < framed.size()) {
        ssize_t w = ::write(fd, framed.data() + done, framed.size() - done);
        if (w < 0) throw std::runtime_error("write_frame: write failed");
        done += static_cast<size_t>(w);
    }
}

} // namespace sw::ipc
