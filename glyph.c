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
    // | z1 | z2 | c |
    return sizeof(int16_t) * N + sizeof(byte) * N + sizeof(int16_t) * OMEGA * 2;
}

static inline RINGELT convert(RINGELT v) {
    return 2 * v < Q ? v : v - Q;
}

static inline byte convert_z2(RINGELT v) {
    if (0 == v) {
        return v;
    } else if (2 * v < Q) {
        return 1;
    } else {
        return 2;
    }
}

static RINGELT kConvertMap[] = {0, 16367, Q -16367};

static inline RINGELT recover_z2(byte v) {
    return kConvertMap[v];
}

static inline RINGELT recover(RINGELT v) {
    if ((int64_t)v < 0) {
        return Q + v;
    } else {
        return v;
    }
}

/**
 * encode private key to byte buffer
 * @param array
 * @param count
 * @param buffer
 */
static void encodePrivateKey(const RINGELT *array, int count, byte * buffer) {
    for (int i = 0; i < count; ++i) {
        RINGELT n = convert(array[i]);
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

/**
 * encode public key to byte buffer
 * @param pk
 * @param count
 * @param buffer
 */
static void encodePublicKey(const RINGELT *pk, int count, byte *buffer) {
    int16_t *b = buffer;
    for (int i = 0; i < count; ++i) {
        RINGELT n = convert(pk[i]);
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

void encodeSignature(const glp_signature_t *sig, void *buffer) {
    int16_t *b = buffer;
    for (int i = 0; i < N; ++i) {
        b[i] = (int16_t)convert(sig->z1[i]);
    }
    b = b + N;
    byte *z2 = b;
    for (int i = 0; i < N; ++i) {
        z2[i] = convert_z2(sig->z2[i]);
    }
    b = (void *)(z2 + N);
    uint16_t *ext = b;
    for (int i = 0; i < OMEGA; ++i) {
        ext[i] = sig->c.pos[i];
    }
    ext = ext + OMEGA;
    for (int i = 0; i < OMEGA; ++i) {
        ext[i] = sig->c.sign[i];
    }
}

void decodeSignature(glp_signature_t *sig, const void* buffer) {
    int16_t *b = buffer;
    for (int i = 0; i < N; ++i) {
        sig->z1[i] = recover(b[i]);
    }
    b = b + N;
    byte *z2 = b;
    for (int i = 0; i < N; ++i) {
        sig->z2[i] = recover_z2(z2[i]);
    }
    b = (void *)(z2 + N);
    uint16_t *ext = b;
    for (int i = 0; i < OMEGA; ++i) {
        sig->c.pos[i] = ext[i];
    }
    ext = ext + OMEGA;
    for (int i = 0; i < OMEGA; ++i) {
        sig->c.sign[i] = ext[i];
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
    decodePrivateKeyFromBuffer(&sk, N * 2, privateKey);
    int ret = glp_sign(&sig, sk, message, messageLength);
    encodeSignature(&sig, signature);
    return ret;
}

int glyph_verify(const byte *message, size_t messageLength, const byte *signature, const byte *publicKey) {
    glp_signature_t sig;
    glp_public_key_t pk;
    decodeSignature(&sig, signature);
    decodePublicKey(&pk, N, publicKey);
    return glp_verify(sig, pk, message, messageLength);
}
