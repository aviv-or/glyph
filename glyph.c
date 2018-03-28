//
// Created by isaac on 18-3-28.
//

#include "glyph.h"
#include "glp.h"

void glyph_gen_keypair(byte *privateKey, byte *publicKey, const byte* seed) {
    glp_signing_key_t sk;
    glp_public_key_t pk;
    glp_gen_sk(&sk, seed);
    glp_gen_pk(&pk, sk);
    memcpy(privateKey, &sk, sizeof(sk));
    memcpy(publicKey, &pk, sizeof(pk));
}

int glyph_sign(byte *signature, const byte *message, size_t messageLength, const byte *privateKey) {
    glp_signature_t sig;
    glp_signing_key_t sk;
    memcpy(&sk, privateKey, sizeof(sk));
    int ret = glp_sign(&sig, sk, message, messageLength);
    memcpy(signature, &sig, sizeof(sig));
    return ret;
}

int glyph_verify(const byte *message, size_t messageLength, const byte *signature, const byte *publicKey) {
    glp_signature_t sig;
    glp_public_key_t pk;
    memcpy(&sig, signature, sizeof(sig));
    memcpy(&pk, publicKey, sizeof(pk));
    return glp_verify(sig, pk, message, messageLength);
}
