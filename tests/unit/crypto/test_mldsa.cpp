#include <sw/crypto/mldsa.hpp>
#include <gtest/gtest.h>
#include <vector>

using namespace sw::crypto;

TEST(MlDsa, KeygenProducesCorrectSizes) {
    auto kp = mldsa_keygen();
    EXPECT_EQ(kp.pub.size(),  MLDSA65_PUBKEY_BYTES);
    EXPECT_EQ(kp.priv.size(), MLDSA65_PRIVKEY_BYTES);
}

TEST(MlDsa, SignVerifyRoundTrip) {
    auto kp = mldsa_keygen();
    const std::vector<uint8_t> msg = {1, 2, 3, 4, 5};
    auto sig = mldsa_sign(kp.priv, msg);
    EXPECT_EQ(sig.size(), MLDSA65_SIG_BYTES);
    EXPECT_TRUE(mldsa_verify(kp.pub, msg, sig));
}

TEST(MlDsa, WrongKeyFails) {
    auto kp1 = mldsa_keygen();
    auto kp2 = mldsa_keygen();
    const std::vector<uint8_t> msg = {0xDE, 0xAD, 0xBE, 0xEF};
    auto sig = mldsa_sign(kp1.priv, msg);
    EXPECT_FALSE(mldsa_verify(kp2.pub, msg, sig));
}

TEST(MlDsa, TamperedMessageFails) {
    auto kp = mldsa_keygen();
    std::vector<uint8_t> msg = {1, 2, 3};
    auto sig = mldsa_sign(kp.priv, msg);
    msg[0] ^= 0xFF;
    EXPECT_FALSE(mldsa_verify(kp.pub, msg, sig));
}

TEST(MlDsa, TamperedSignatureFails) {
    auto kp = mldsa_keygen();
    const std::vector<uint8_t> msg = {7, 8, 9};
    auto sig = mldsa_sign(kp.priv, msg);
    sig[0] ^= 0xFF;
    EXPECT_FALSE(mldsa_verify(kp.pub, msg, sig));
}

TEST(MlDsa, EmptyMessageSignVerify) {
    auto kp = mldsa_keygen();
    const std::vector<uint8_t> msg;
    auto sig = mldsa_sign(kp.priv, msg);
    EXPECT_TRUE(mldsa_verify(kp.pub, msg, sig));
}
