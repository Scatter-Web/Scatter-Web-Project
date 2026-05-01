#include <sw/crypto/mlkem.hpp>
#include <oqs/oqs.h>
#include <stdexcept>

namespace sw::crypto {

namespace {

OQS_KEM* open_kem() {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem)
        throw std::runtime_error("OQS_KEM_new(ml_kem_768) failed");
    return kem;
}

} // namespace

KemKeyPair mlkem_keygen() {
    OQS_KEM* kem = open_kem();
    KemKeyPair kp;
    OQS_STATUS rc = OQS_KEM_keypair(kem, kp.pub.data(), kp.priv.data());
    OQS_KEM_free(kem);
    if (rc != OQS_SUCCESS)
        throw std::runtime_error("ML-KEM-768 keygen failed");
    return kp;
}

KemEncapsulated mlkem_encapsulate(const KemPubKey& pub) {
    OQS_KEM* kem = open_kem();
    KemEncapsulated out;
    OQS_STATUS rc = OQS_KEM_encaps(kem, out.ct.data(), out.ss.data(), pub.data());
    OQS_KEM_free(kem);
    if (rc != OQS_SUCCESS)
        throw std::runtime_error("ML-KEM-768 encapsulate failed");
    return out;
}

KemSS mlkem_decapsulate(const KemPrivKey& priv, const KemCt& ct) {
    OQS_KEM* kem = open_kem();
    KemSS ss;
    OQS_STATUS rc = OQS_KEM_decaps(kem, ss.data(), ct.data(), priv.data());
    OQS_KEM_free(kem);
    if (rc != OQS_SUCCESS)
        throw std::runtime_error("ML-KEM-768 decapsulate failed");
    return ss;
}

} // namespace sw::crypto
