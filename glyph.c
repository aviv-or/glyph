//
// Created by isaac on 18-3-28.
//

#include "glyph.h"
#include "glp.h"

size_t glyph_private_keysize() {
//     return sizeof(glp_signing_key_t);
    return sizeof(byte) * N * 2;
}

size_t glyph_public_keysize() {
    return sizeof(glp_public_key_t);
    //return sizeof(uint16_t) * N * 2;
}

size_t glyph_signature_size() {
    return sizeof(glp_signature_t);
//    return sizeof(uint16_t) * N * 2 + sizeof(uint16_t) * OMEGA * 2;
}


static void encodePrivateKey(const RINGELT *array, int count, byte * buffer) {
    for (int i = 0; i < count; ++i) {
        RINGELT n = 2 * array[i] < Q ? array[i] : array[i] - Q;
        if (n < 0) {
            buffer[i] = 2;
        } else {
            buffer[i] = (byte)n;
        }
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

// converters

static void glyp_toBuffer(const RINGELT *obj, byte *buffer, int count) {
    uint16_t *dest = buffer;
    for (int i = 0; i < count; ++i) {
        dest[i] = obj[i];
    }
}

static void glyp_fromBuffer(const byte *buffer, RINGELT *obj, int count) {
    uint16_t *src = buffer;
    for (int i = 0; i < count; ++i) {
        obj[i] = src[i];
    }
}

static void glyp_sig_toBuffer(const glp_signature_t *sig, byte *buffer) {
    glyp_toBuffer(&(sig->z1), buffer, N);
    byte *b2 = buffer + N * (sizeof(uint16_t) / sizeof(byte));
    glyp_toBuffer(&(sig->z2), b2, N);

    byte  *b3 = b2 + N * (sizeof(uint16_t) / sizeof(byte));
    uint16_t *b4 = b3;
    int n1 = OMEGA;
    uint16_t *src = sig->c.pos;
    for (int i = 0; i < n1; ++i) {
        b4[i] = src[i];
    }
    b4 = b4 + OMEGA;
    src = sig->c.sign;
    for (int i = 0; i < n1; ++i) {
        b4[i] = src[i];
    }
}

static void glyp_sig_fromBuffer(glp_signature_t *sig, const byte *buffer) {
    glyp_fromBuffer(buffer, &(sig->z1), N);
    byte *b2 = buffer + N * (sizeof(uint16_t) / sizeof(byte));
    glyp_fromBuffer(b2, &(sig->z2), N);
    byte *b3 = b2 + N * (sizeof(uint16_t) / sizeof(byte));
    uint16_t *b4 = b3;
    int n1 = OMEGA;
    RINGELT *dest = sig->c.pos;
    for (int i = 0; i < n1; ++i) {
        dest[i] = b4[i];
    }
    b4 = b4 + OMEGA;
    dest = sig->c.sign;
    for (int i = 0; i < n1; ++i) {
        dest[i] = b4[i];
    }
}

void glyph_gen_keypair(byte *privateKey, byte *publicKey, const byte* seed) {
    glp_signing_key_t sk;
    glp_public_key_t pk;
    glp_gen_sk(&sk, seed);
    glp_gen_pk(&pk, sk);
//    glyp_toBuffer(&sk, privateKey, N);
    encodePrivateKey(&sk, N * 2, privateKey);
    memcpy(publicKey, &pk, sizeof(pk));
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
    memcpy(&pk, publicKey, sizeof(pk));
    return glp_verify(sig, pk, message, messageLength);
}
