#include <sw/crypto/aes_gcm.hpp>
#include <gtest/gtest.h>

using namespace sw::crypto;

namespace {
AesKey make_key() {
    AesKey k{};
    for (size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(i);
    return k;
}
} // namespace

TEST(AesGcm, EncryptDecryptRoundTrip) {
    auto key = make_key();
    const sw::Bytes pt = {1, 2, 3, 4, 5, 6, 7, 8};
    auto enc = aes_encrypt(key, pt);
    auto dec = aes_decrypt(key, enc.nonce, enc.ciphertext, enc.tag);
    EXPECT_EQ(dec, pt);
}

TEST(AesGcm, EncryptEmptyPlaintext) {
    auto key = make_key();
    auto enc = aes_encrypt(key, {});
    EXPECT_TRUE(enc.ciphertext.empty());
    auto dec = aes_decrypt(key, enc.nonce, enc.ciphertext, enc.tag);
    EXPECT_TRUE(dec.empty());
}

TEST(AesGcm, WithAdditionalData) {
    auto key = make_key();
    const sw::Bytes pt = {0xAB, 0xCD};
    const sw::Bytes ad = {0x01, 0x02, 0x03};
    auto enc = aes_encrypt(key, pt, ad);
    auto dec = aes_decrypt(key, enc.nonce, enc.ciphertext, enc.tag, ad);
    EXPECT_EQ(dec, pt);
}

TEST(AesGcm, WrongAdFails) {
    auto key = make_key();
    const sw::Bytes pt = {0xAB, 0xCD};
    const sw::Bytes ad = {0x01};
    const sw::Bytes bad_ad = {0x02};
    auto enc = aes_encrypt(key, pt, ad);
    EXPECT_THROW(aes_decrypt(key, enc.nonce, enc.ciphertext, enc.tag, bad_ad),
                 std::runtime_error);
}

TEST(AesGcm, TamperedCiphertextFails) {
    auto key = make_key();
    const sw::Bytes pt = {1, 2, 3};
    auto enc = aes_encrypt(key, pt);
    enc.ciphertext[0] ^= 0xFF;
    EXPECT_THROW(aes_decrypt(key, enc.nonce, enc.ciphertext, enc.tag),
                 std::runtime_error);
}

TEST(AesGcm, TamperedTagFails) {
    auto key = make_key();
    const sw::Bytes pt = {1, 2, 3};
    auto enc = aes_encrypt(key, pt);
    enc.tag[0] ^= 0xFF;
    EXPECT_THROW(aes_decrypt(key, enc.nonce, enc.ciphertext, enc.tag),
                 std::runtime_error);
}

TEST(AesGcm, TwoCiphertextsDifferForSameKey) {
    auto key = make_key();
    const sw::Bytes pt = {1, 2, 3};
    auto enc1 = aes_encrypt(key, pt);
    auto enc2 = aes_encrypt(key, pt);
    // Different random nonces → different ciphertexts
    EXPECT_NE(enc1.nonce, enc2.nonce);
}
