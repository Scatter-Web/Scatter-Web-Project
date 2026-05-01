#pragma once
#include <sw/types.hpp>
#include <map>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace sw::ipc {

// Forward-declare for recursive value type.
class CborValue;
using CborArray = std::vector<CborValue>;
using CborMap   = std::map<std::string, CborValue>;

// Dynamic CBOR value. Compound types (array/map) are heap-allocated so that
// CborValue remains a fixed-size type despite being recursive.
class CborValue {
public:
    CborValue();           // null
    ~CborValue() = default;
    CborValue(const CborValue&) = default;
    CborValue& operator=(const CborValue&) = default;
    CborValue(CborValue&&) noexcept = default;
    CborValue& operator=(CborValue&&) noexcept = default;

    // Named constructors
    static CborValue null_val();
    static CborValue from_bool(bool b);
    static CborValue from_uint(uint64_t u);
    static CborValue from_int(int64_t i);
    static CborValue from_string(std::string s);
    static CborValue from_bytes(Bytes b);
    static CborValue from_array(CborArray arr);
    static CborValue from_map(CborMap map);

    // Type predicates
    bool is_null()   const noexcept;
    bool is_bool()   const noexcept;
    bool is_uint()   const noexcept;
    bool is_int()    const noexcept;
    bool is_string() const noexcept;
    bool is_bytes()  const noexcept;
    bool is_array()  const noexcept;
    bool is_map()    const noexcept;

    // Typed accessors — throw std::bad_variant_access on type mismatch.
    bool                as_bool()   const;
    uint64_t            as_uint()   const;
    int64_t             as_int()    const;
    const std::string&  as_string() const;
    const Bytes&        as_bytes()  const;
    const CborArray&    as_array()  const;
    CborArray&          as_array();
    const CborMap&      as_map()    const;
    CborMap&            as_map();

private:
    // shared_ptr for CborArray/CborMap so the variant stays fixed-size
    // while CborValue is still being defined.
    std::variant<
        std::monostate,
        bool,
        uint64_t,
        int64_t,
        std::string,
        Bytes,
        std::shared_ptr<CborArray>,
        std::shared_ptr<CborMap>
    > data_;
};

// ── IPC envelope types ────────────────────────────────────────────────────────

struct Request {
    uint64_t   id;
    std::string caller;
    std::string method;
    CborMap    params;
};

struct Response {
    uint64_t   id;
    bool       ok;
    CborMap    result;
    struct { int code = 0; std::string message; } error;
};

struct Push {
    std::string event;
    CborMap     payload;
};

// ── Encode ────────────────────────────────────────────────────────────────────

Bytes encode_request(const Request& req);
Bytes encode_response(const Response& resp);
Bytes encode_push(const Push& push);

// ── Decode ────────────────────────────────────────────────────────────────────

// Inspect the "method"/"ok"/"event" key to pick the right decoder.
enum class MsgType { Request, Response, Push, Unknown };
MsgType detect(ByteSpan data);

Request  decode_request(ByteSpan data);
Response decode_response(ByteSpan data);
Push     decode_push(ByteSpan data);

// ── Length-prefixed framing (4-byte big-endian uint32 + payload) ──────────────

// Prepend a 4-byte length header.
Bytes frame(const Bytes& payload);

// Read exactly one framed message from fd (blocking). Returns empty on EOF.
Bytes read_frame(int fd);

// Write one framed message to fd.
void write_frame(int fd, const Bytes& payload);

} // namespace sw::ipc
