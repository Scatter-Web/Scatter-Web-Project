#include <sw/ipc/codec.hpp>
#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <cstring>

using namespace sw::ipc;

TEST(CborValue, NullDefault) {
    CborValue v;
    EXPECT_TRUE(v.is_null());
    EXPECT_FALSE(v.is_bool());
}

TEST(CborValue, UintRoundTrip) {
    auto v = CborValue::from_uint(42);
    EXPECT_TRUE(v.is_uint());
    EXPECT_EQ(v.as_uint(), 42u);
}

TEST(CborValue, StringRoundTrip) {
    auto v = CborValue::from_string("hello");
    EXPECT_TRUE(v.is_string());
    EXPECT_EQ(v.as_string(), "hello");
}

TEST(CborValue, BytesRoundTrip) {
    sw::Bytes b = {1, 2, 3};
    auto v = CborValue::from_bytes(b);
    EXPECT_TRUE(v.is_bytes());
    EXPECT_EQ(v.as_bytes(), b);
}

TEST(CborValue, MapRoundTrip) {
    CborMap m;
    m["x"] = CborValue::from_uint(7);
    m["y"] = CborValue::from_string("hi");
    auto v = CborValue::from_map(m);
    EXPECT_TRUE(v.is_map());
    EXPECT_EQ(v.as_map().at("x").as_uint(), 7u);
    EXPECT_EQ(v.as_map().at("y").as_string(), "hi");
}

TEST(CborValue, NestedMapRoundTrip) {
    CborMap inner;
    inner["k"] = CborValue::from_bool(true);
    CborMap outer;
    outer["inner"] = CborValue::from_map(std::move(inner));
    auto v = CborValue::from_map(std::move(outer));
    EXPECT_TRUE(v.as_map().at("inner").as_map().at("k").as_bool());
}

TEST(Request, EncodeDecodeRoundTrip) {
    Request req;
    req.id     = 99;
    req.caller = "ui";
    req.method = "messages.send";
    req.params["text"] = CborValue::from_string("hey");
    req.params["id"]   = CborValue::from_uint(1);

    auto encoded = encode_request(req);
    EXPECT_FALSE(encoded.empty());
    auto decoded = decode_request(encoded);

    EXPECT_EQ(decoded.id,     req.id);
    EXPECT_EQ(decoded.caller, req.caller);
    EXPECT_EQ(decoded.method, req.method);
    EXPECT_EQ(decoded.params.at("text").as_string(), "hey");
    EXPECT_EQ(decoded.params.at("id").as_uint(),     1u);
}

TEST(Response, SuccessEncodeDecodeRoundTrip) {
    Response resp;
    resp.id = 99;
    resp.ok = true;
    resp.result["status"] = CborValue::from_string("ok");

    auto encoded = encode_response(resp);
    auto decoded = decode_response(encoded);

    EXPECT_EQ(decoded.id, 99u);
    EXPECT_TRUE(decoded.ok);
    EXPECT_EQ(decoded.result.at("status").as_string(), "ok");
}

TEST(Response, ErrorEncodeDecodeRoundTrip) {
    Response resp;
    resp.id            = 7;
    resp.ok            = false;
    resp.error.code    = 404;
    resp.error.message = "not found";

    auto encoded = encode_response(resp);
    auto decoded = decode_response(encoded);

    EXPECT_EQ(decoded.id, 7u);
    EXPECT_FALSE(decoded.ok);
    EXPECT_EQ(decoded.error.code,    404);
    EXPECT_EQ(decoded.error.message, "not found");
}

TEST(Push, EncodeDecodeRoundTrip) {
    Push push;
    push.event             = "message.received";
    push.payload["msg_id"] = CborValue::from_bytes({0xDE, 0xAD});

    auto encoded = encode_push(push);
    auto decoded = decode_push(encoded);

    EXPECT_EQ(decoded.event, "message.received");
    sw::Bytes expected = {0xDE, 0xAD};
    EXPECT_EQ(decoded.payload.at("msg_id").as_bytes(), expected);
}

TEST(Framing, FrameUnframe) {
    sw::Bytes payload = {1, 2, 3, 4, 5};
    sw::Bytes framed  = frame(payload);
    EXPECT_EQ(framed.size(), 4 + payload.size());

    // Check length header.
    uint32_t len_be;
    std::memcpy(&len_be, framed.data(), 4);
    uint32_t len = ntohl(len_be);
    EXPECT_EQ(len, payload.size());
}

TEST(Detect, DetectsRequestResponsePush) {
    Request req{1, "ui", "foo", {}};
    EXPECT_EQ(detect(encode_request(req)), MsgType::Request);

    Response resp{1, true, {}, {}};
    EXPECT_EQ(detect(encode_response(resp)), MsgType::Response);

    Push push{"ev", {}};
    EXPECT_EQ(detect(encode_push(push)), MsgType::Push);
}
