#include <sw/crypto/kdf.hpp>
#include <gtest/gtest.h>
#include <sodium.h>

using namespace sw::crypto;

TEST(Kdf, Sha3256Deterministic) {
    const sw::Bytes data = {1, 2, 3, 4};
    auto h1 = sha3_256(data);
    auto h2 = sha3_256(data);
    EXPECT_EQ(h1, h2);
    EXPECT_EQ(h1.size(), 32u);
}

TEST(Kdf, Sha3256DifferentInputsDifferentOutputs) {
    auto h1 = sha3_256(sw::Bytes{1, 2, 3});
    auto h2 = sha3_256(sw::Bytes{1, 2, 4});
    EXPECT_NE(h1, h2);
}

TEST(Kdf, Sha3256MultiPartEquivalent) {
    const sw::Bytes a = {1, 2};
    const sw::Bytes b = {3, 4};
    sw::Bytes combined = {1, 2, 3, 4};
    auto h_split    = sha3_256({sw::ByteSpan{a}, sw::ByteSpan{b}});
    auto h_combined = sha3_256(combined);
    EXPECT_EQ(h_split, h_combined);
}

TEST(Kdf, Shake256Deterministic) {
    const sw::Bytes data = {0xAB, 0xCD};
    auto out1 = shake256(data, 64);
    auto out2 = shake256(data, 64);
    EXPECT_EQ(out1, out2);
    EXPECT_EQ(out1.size(), 64u);
}

TEST(Kdf, Shake256VaryingLength) {
    const sw::Bytes data = {1};
    auto out32 = shake256(data, 32);
    auto out64 = shake256(data, 64);
    EXPECT_EQ(out32.size(), 32u);
    EXPECT_EQ(out64.size(), 64u);
    // First 32 bytes of 64-byte output should match 32-byte output.
    EXPECT_TRUE(std::equal(out32.begin(), out32.end(), out64.begin()));
}

TEST(Kdf, Shake256_32ConvenienceWrapper) {
    const sw::Bytes data = {5, 6, 7};
    auto key = shake256_32(data);
    EXPECT_EQ(key.size(), 32u);
    auto full = shake256(data, 32);
    sw::Key32 expected;
    std::copy(full.begin(), full.end(), expected.begin());
    EXPECT_EQ(key, expected);
}

TEST(Kdf, HmacSha3256Deterministic) {
    const sw::Key32 key{};
    const sw::Bytes data = {1, 2, 3};
    auto h1 = hmac_sha3_256(key, data);
    auto h2 = hmac_sha3_256(key, data);
    EXPECT_EQ(h1, h2);
    EXPECT_EQ(h1.size(), 32u);
}

TEST(Kdf, HmacSha3256DifferentKeysDifferentOutputs) {
    sw::Key32 k1{}, k2{};
    k2[0] = 1;
    const sw::Bytes data = {1};
    EXPECT_NE(hmac_sha3_256(k1, data), hmac_sha3_256(k2, data));
}

TEST(Kdf, Argon2idProducesKey) {
    // salt must be crypto_pwhash_SALTBYTES (16 bytes).
    std::vector<uint8_t> salt(crypto_pwhash_SALTBYTES, 0xAA);
    auto key = argon2id("testpassword", salt);
    EXPECT_EQ(key.size(), 32u);
    // Same inputs → same output.
    auto key2 = argon2id("testpassword", salt);
    EXPECT_EQ(key, key2);
    // Different passphrase → different output.
    auto key3 = argon2id("otherpassword", salt);
    EXPECT_NE(key, key3);
}
