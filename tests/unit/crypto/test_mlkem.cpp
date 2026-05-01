#include <sw/crypto/mlkem.hpp>
#include <gtest/gtest.h>

using namespace sw::crypto;

TEST(MlKem, KeygenProducesCorrectSizes) {
    auto kp = mlkem_keygen();
    EXPECT_EQ(kp.pub.size(),  MLKEM768_PUBKEY_BYTES);
    EXPECT_EQ(kp.priv.size(), MLKEM768_PRIVKEY_BYTES);
}

TEST(MlKem, TwoKeygensDiffer) {
    auto kp1 = mlkem_keygen();
    auto kp2 = mlkem_keygen();
    EXPECT_NE(kp1.pub,  kp2.pub);
    EXPECT_NE(kp1.priv, kp2.priv);
}

TEST(MlKem, EncapsulateDecapsulateAgree) {
    auto kp = mlkem_keygen();
    auto [ct, ss_enc] = mlkem_encapsulate(kp.pub);
    auto ss_dec       = mlkem_decapsulate(kp.priv, ct);
    EXPECT_EQ(ss_enc, ss_dec);
}

TEST(MlKem, WrongPrivkeyProducesDifferentSS) {
    auto kp1 = mlkem_keygen();
    auto kp2 = mlkem_keygen();
    auto [ct, ss_enc] = mlkem_encapsulate(kp1.pub);
    auto ss_wrong     = mlkem_decapsulate(kp2.priv, ct);
    EXPECT_NE(ss_enc, ss_wrong);
}

TEST(MlKem, EncapsulateProducesCorrectSizes) {
    auto kp = mlkem_keygen();
    auto enc = mlkem_encapsulate(kp.pub);
    EXPECT_EQ(enc.ct.size(), MLKEM768_CT_BYTES);
    EXPECT_EQ(enc.ss.size(), MLKEM768_SS_BYTES);
}
