#include <sw/ratchet/ratchet.hpp>
#include <sw/crypto/mlkem.hpp>
#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace sw::ratchet;
using namespace sw::crypto;

namespace {

struct Session {
    State alice;
    State bob;

    static Session setup() {
        // Generate Key B keypairs and a prekey for Bob.
        auto alice_key_b = mlkem_keygen();
        auto bob_key_b   = mlkem_keygen();
        auto bob_prekey  = mlkem_keygen();

        auto [a_state, prekey_ct, a_ratchet_pub] =
            init_as_sender(bob_prekey.pub, alice_key_b.pub, bob_key_b.pub);

        State b_state = init_as_receiver(
            bob_prekey.priv, prekey_ct,
            alice_key_b.pub, bob_key_b.pub,
            a_ratchet_pub);

        return {std::move(a_state), std::move(b_state)};
    }
};

sw::Bytes str_to_bytes(const std::string& s) {
    return {s.begin(), s.end()};
}

std::string bytes_to_str(const sw::Bytes& b) {
    return {b.begin(), b.end()};
}

} // namespace

TEST(Ratchet, AliceSendsBobReceives) {
    auto [alice, bob] = Session::setup();

    auto msg = encrypt(alice, str_to_bytes("hello"));
    auto pt  = decrypt(bob,   msg);
    EXPECT_EQ(bytes_to_str(pt), "hello");
}

TEST(Ratchet, BobReplies) {
    auto [alice, bob] = Session::setup();

    auto m1 = encrypt(alice, str_to_bytes("ping"));
    decrypt(bob, m1);  // Bob receives, direction tracked

    auto m2 = encrypt(bob,   str_to_bytes("pong"));
    auto pt  = decrypt(alice, m2);
    EXPECT_EQ(bytes_to_str(pt), "pong");
}

TEST(Ratchet, MultipleMessagesInEachDirection) {
    auto [alice, bob] = Session::setup();

    // Alice sends 3
    for (int i = 0; i < 3; ++i) {
        auto m = encrypt(alice, str_to_bytes("a" + std::to_string(i)));
        auto p = decrypt(bob,   m);
        EXPECT_EQ(bytes_to_str(p), "a" + std::to_string(i));
    }

    // Bob replies 3
    for (int i = 0; i < 3; ++i) {
        auto m = encrypt(bob,   str_to_bytes("b" + std::to_string(i)));
        auto p = decrypt(alice, m);
        EXPECT_EQ(bytes_to_str(p), "b" + std::to_string(i));
    }

    // Alice replies again (new KEM epoch)
    auto m = encrypt(alice, str_to_bytes("done"));
    auto p = decrypt(bob,   m);
    EXPECT_EQ(bytes_to_str(p), "done");
}

TEST(Ratchet, SkippedMessagesDeliveredOutOfOrder) {
    auto [alice, bob] = Session::setup();

    // Alice sends 3 messages.
    auto m0 = encrypt(alice, str_to_bytes("msg0"));
    auto m1 = encrypt(alice, str_to_bytes("msg1"));
    auto m2 = encrypt(alice, str_to_bytes("msg2"));

    // Bob receives m2 first (m0, m1 skipped).
    auto p2 = decrypt(bob, m2);
    EXPECT_EQ(bytes_to_str(p2), "msg2");

    // Now Bob receives m0 and m1 from the cache.
    auto p0 = decrypt(bob, m0);
    EXPECT_EQ(bytes_to_str(p0), "msg0");

    auto p1 = decrypt(bob, m1);
    EXPECT_EQ(bytes_to_str(p1), "msg1");
}

TEST(Ratchet, WrongCiphertextThrows) {
    auto [alice, bob] = Session::setup();

    auto msg = encrypt(alice, str_to_bytes("secret"));
    msg.ciphertext[0] ^= 0xFF;
    EXPECT_THROW(decrypt(bob, msg), std::runtime_error);
}

TEST(Ratchet, SerializeDeserializeState) {
    auto [alice, bob] = Session::setup();

    // Exchange a message to advance state.
    auto m = encrypt(alice, str_to_bytes("x"));
    decrypt(bob, m);

    Bytes serialized = serialize(alice);
    State alice2     = deserialize(serialized);

    // alice2 should produce messages bob can decrypt.
    auto m2 = encrypt(alice2, str_to_bytes("after restore"));
    auto p2 = decrypt(bob, m2);
    EXPECT_EQ(bytes_to_str(p2), "after restore");
}

TEST(Ratchet, EpochsAdvanceOnDirectionChange) {
    auto [alice, bob] = Session::setup();

    uint32_t alice_epoch_before = alice.send_epoch;

    // Alice → Bob
    auto m1 = encrypt(alice, str_to_bytes("a1"));
    decrypt(bob, m1);

    // Bob → Alice (Bob should do a KEM step)
    auto m2 = encrypt(bob, str_to_bytes("b1"));
    EXPECT_TRUE(m2.header.kem_ct.has_value());
    decrypt(alice, m2);

    // Alice → Bob again (Alice should do a KEM step)
    auto m3 = encrypt(alice, str_to_bytes("a2"));
    EXPECT_TRUE(m3.header.kem_ct.has_value());
    EXPECT_GT(alice.send_epoch, alice_epoch_before);
}
