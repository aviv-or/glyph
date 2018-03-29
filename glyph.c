//
// Created by isaac on 18-3-28.
//

#include "glyph.h"
#include "glp.h"

size_t glyph_private_keysize() {
    return sizeof(byte) * N * 2;
}

size_t glyph_public_keysize() {
    return sizeof(int16_t) * N;
}

size_t glyph_signature_size() {
    return sizeof(glp_signature_t);
//    return sizeof(uint16_t) * N * 2 + sizeof(uint16_t) * OMEGA * 2;
}


static void encodePrivateKey(const RINGELT *array, int count, byte * buffer) {
    for (int i = 0; i < count; ++i) {
        RINGELT n = 2 * array[i] < Q ? array[i] : array[i] - Q;
        buffer[i] = (byte)n;
    }
}

static void decodePrivateKeyFromBuffer(RINGELT *array, int count, const byte *buffer) {
    for (int i = 0; i < count; ++i) {
        byte n = buffer[i];
        if (n > 1) {
            array[i] = Q - 1;
        } else {
            array[i] = n;
        }
    }
}

static void encodePublicKey(const RINGELT *pk, int count, byte *buffer) {
    int16_t *b = buffer;
    for (int i = 0; i < count; ++i) {
        RINGELT n = pk[i];
        n = 2 * n < Q ? n : n - Q;
        b[i] = (int16_t)n;
    }
}

static void decodePublicKey(RINGELT *pk, int count, const byte *buffer) {
    int16_t *b = buffer;
    for (int i = 0; i < count; ++i) {
        int16_t n = b[i];
        if (n < 0) {
            pk[i] = Q + n;
        } else {
            pk[i] = n;
        }
    }
}

void glyph_gen_keypair(byte *privateKey, byte *publicKey, const byte* seed) {
    glp_signing_key_t sk;
    glp_public_key_t pk;
    glp_gen_sk(&sk, seed);
    glp_gen_pk(&pk, sk);
    encodePrivateKey(&sk, N * 2, privateKey);
    encodePublicKey(&pk, N, publicKey);
}

int glyph_sign(byte *signature, const byte *message, size_t messageLength, const byte *privateKey) {
    glp_signature_t sig;
    glp_signing_key_t sk;
//    glyp_fromBuffer(privateKey, &sk, N);
    decodePrivateKeyFromBuffer(&sk, N * 2, privateKey);
    int ret = glp_sign(&sig, sk, message, messageLength);
    memcpy(signature, &sig, sizeof(sig));
    return ret;
}

int glyph_verify(const byte *message, size_t messageLength, const byte *signature, const byte *publicKey) {
    glp_signature_t sig;
    glp_public_key_t pk;
    memcpy(&sig, signature, sizeof(sig));
    decodePublicKey(&pk, N, publicKey);
    return glp_verify(sig, pk, message, messageLength);
}
