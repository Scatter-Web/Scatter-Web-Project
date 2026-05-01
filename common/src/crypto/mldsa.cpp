#include <sw/crypto/mldsa.hpp>
#include <oqs/oqs.h>
#include <stdexcept>

namespace sw::crypto {

namespace {

OQS_SIG* open_sig() {
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig)
        throw std::runtime_error("OQS_SIG_new(ml_dsa_65) failed");
    return sig;
}

} // namespace

DsaKeyPair mldsa_keygen() {
    OQS_SIG* sig = open_sig();
    DsaKeyPair kp;
    OQS_STATUS rc = OQS_SIG_keypair(sig, kp.pub.data(), kp.priv.data());
    OQS_SIG_free(sig);
    if (rc != OQS_SUCCESS)
        throw std::runtime_error("ML-DSA-65 keygen failed");
    return kp;
}

DsaSig mldsa_sign(const DsaPrivKey& priv, ByteSpan msg) {
    OQS_SIG* sig = open_sig();
    DsaSig out;
    size_t sig_len = out.size();
    OQS_STATUS rc = OQS_SIG_sign(sig, out.data(), &sig_len,
                                  msg.data(), msg.size(), priv.data());
    OQS_SIG_free(sig);
    if (rc != OQS_SUCCESS)
        throw std::runtime_error("ML-DSA-65 sign failed");
    // liboqs ML-DSA-65 always produces exactly MLDSA65_SIG_BYTES
    if (sig_len != MLDSA65_SIG_BYTES)
        throw std::runtime_error("ML-DSA-65 unexpected signature length");
    return out;
}

bool mldsa_verify(const DsaPubKey& pub, ByteSpan msg, const DsaSig& sig) {
    OQS_SIG* s = open_sig();
    OQS_STATUS rc = OQS_SIG_verify(s, msg.data(), msg.size(),
                                    sig.data(), sig.size(), pub.data());
    OQS_SIG_free(s);
    return rc == OQS_SUCCESS;
}

} // namespace sw::crypto
