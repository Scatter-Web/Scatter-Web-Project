#include <sw/dht/record.hpp>
#include <sw/crypto/mlkem.hpp>
#include <sw/crypto/mldsa.hpp>
#include <gtest/gtest.h>
#include <ctime>

using namespace sw::dht;
using namespace sw::crypto;

namespace {

struct Fixture {
    KemKeyPair key_b  = mlkem_keygen();
    DsaKeyPair key_a  = mldsa_keygen();
    uint64_t timeslot = sw::current_timeslot();

    GuardPlaintext make_plaintext() const {
        GuardPlaintext p;
        p.guard_node_id  = sw::Bytes(32, 0xAA);
        p.guard_endpoint = "10.0.0.1:9000";
        p.session_token.fill(0xBB);
        p.prekey_available    = true;
        p.inbox_auth_key      = sw::Bytes(MLDSA65_PUBKEY_BYTES, 0xCC);
        p.inbox_auth_expiry   = static_cast<uint64_t>(std::time(nullptr)) + 3600;
        return p;
    }
};

} // namespace

TEST(DhtKeys, GuardDhtKeyDeterministic) {
    Fixture f;
    auto k1 = guard_dht_key(f.key_b.pub, f.timeslot);
    auto k2 = guard_dht_key(f.key_b.pub, f.timeslot);
    EXPECT_EQ(k1, k2);
    EXPECT_EQ(k1.size(), 32u);
}

TEST(DhtKeys, GuardDhtKeyChangesWithTimeslot) {
    Fixture f;
    auto k1 = guard_dht_key(f.key_b.pub, f.timeslot);
    auto k2 = guard_dht_key(f.key_b.pub, f.timeslot + 1);
    EXPECT_NE(k1, k2);
}

TEST(DhtKeys, GuardAeadKeyDeterministic) {
    Fixture f;
    auto k1 = guard_aead_key(f.key_b.pub, f.timeslot);
    auto k2 = guard_aead_key(f.key_b.pub, f.timeslot);
    EXPECT_EQ(k1, k2);
}

TEST(DhtKeys, PrekeyDhtKeyDeterministic) {
    Fixture f;
    auto k1 = prekey_dht_key(f.key_b.pub);
    auto k2 = prekey_dht_key(f.key_b.pub);
    EXPECT_EQ(k1, k2);
}

TEST(DhtKeys, PrekeyDhtKeyStableAcrossTimeslots) {
    Fixture f;
    auto k1 = prekey_dht_key(f.key_b.pub);
    // Prekey key doesn't use timeslot — should stay stable.
    EXPECT_EQ(k1, prekey_dht_key(f.key_b.pub));
}

TEST(GuardRecord, V1BuildAndParse) {
    Fixture f;
    auto pt = f.make_plaintext();

    auto record_cbor = build_guard_record_v1(f.key_b.pub, f.timeslot, pt, f.key_a.priv);
    EXPECT_FALSE(record_cbor.empty());

    auto parsed = parse_guard_record(record_cbor, f.key_b.pub, f.key_a.pub, f.timeslot);

    EXPECT_EQ(parsed.guard_endpoint,    pt.guard_endpoint);
    EXPECT_EQ(parsed.session_token,     pt.session_token);
    EXPECT_EQ(parsed.prekey_available,  pt.prekey_available);
    EXPECT_EQ(parsed.guard_node_id,     pt.guard_node_id);
}

TEST(GuardRecord, WrongTimeslotFails) {
    Fixture f;
    auto record_cbor = build_guard_record_v1(f.key_b.pub, f.timeslot,
                                              f.make_plaintext(), f.key_a.priv);
    EXPECT_THROW(
        parse_guard_record(record_cbor, f.key_b.pub, f.key_a.pub, f.timeslot + 1),
        std::runtime_error);
}

TEST(GuardRecord, WrongKeyFails) {
    Fixture f;
    DsaKeyPair wrong_key = mldsa_keygen();
    auto record_cbor = build_guard_record_v1(f.key_b.pub, f.timeslot,
                                              f.make_plaintext(), f.key_a.priv);
    EXPECT_THROW(
        parse_guard_record(record_cbor, f.key_b.pub, wrong_key.pub, f.timeslot),
        std::runtime_error);
}

TEST(PrekeyRecord, BuildAndParse) {
    Fixture f;

    PrekeyRecord rec;
    rec.timestamp = static_cast<uint64_t>(std::time(nullptr));
    for (int i = 0; i < 5; ++i)
        rec.prekeys.push_back(mlkem_keygen().pub);

    auto record_cbor = build_prekey_record(f.key_b.pub, rec, f.key_a.priv);
    EXPECT_FALSE(record_cbor.empty());

    auto parsed = parse_prekey_record(record_cbor, f.key_b.pub, f.key_a.pub);

    EXPECT_EQ(parsed.timestamp,       rec.timestamp);
    EXPECT_EQ(parsed.prekeys.size(),  rec.prekeys.size());
    for (size_t i = 0; i < rec.prekeys.size(); ++i)
        EXPECT_EQ(parsed.prekeys[i], rec.prekeys[i]);
}

TEST(PrekeyRecord, TamperedSignatureFails) {
    Fixture f;
    PrekeyRecord rec;
    rec.timestamp = 1;
    rec.prekeys.push_back(mlkem_keygen().pub);

    auto record_cbor = build_prekey_record(f.key_b.pub, rec, f.key_a.priv);
    // Flip a byte somewhere in the middle.
    record_cbor[record_cbor.size() / 2] ^= 0xFF;
    EXPECT_THROW(parse_prekey_record(record_cbor, f.key_b.pub, f.key_a.pub),
                 std::runtime_error);
}
