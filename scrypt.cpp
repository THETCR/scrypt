/*
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2012-2013 pooler
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */
// Copyright (c) 2018-2019 The WISPR developers

#include <scrypt.h>
#include <hmac_sha256.h>
#include <string>

#include <cstring>
#include <cstdint>

#ifndef __FreeBSD__
static inline void be32enc(void *pp, uint32_t x)
{
    auto *p = (uint8_t *)pp;
    p[3] = x & 0xff;
    p[2] = (x >> 8) & 0xff;
    p[1] = (x >> 16) & 0xff;
    p[0] = (x >> 24) & 0xff;
}
#endif

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen, const uint8_t *salt,
              size_t saltlen, uint64_t c, uint8_t *buf, size_t dkLen)
{
    CHMAC_SHA256 PShctx(passwd, passwdlen);
    CHMAC_SHA256 hctx(passwd, passwdlen);
    size_t i;
    uint8_t ivec[4];
    uint8_t U[32];
    uint8_t T[32];
    uint64_t j;
    int k;
    size_t clen;

    /* Compute HMAC state after processing P and S. */
    PShctx.Write(salt, saltlen);

    /* Iterate through the blocks. */
    for (i = 0; i * 32 < dkLen; i++) {
        /* Generate INT(i + 1). */
        be32enc(ivec, (uint32_t)(i + 1));

        /* Compute U_1 = PRF(P, S || INT(i)). */
        memcpy(&hctx, &PShctx, sizeof(CHMAC_SHA256));
        hctx.Write(ivec, 4);
        hctx.Finalize(U);

        /* T_i = U_1 ... */
        memcpy(T, U, 32);

        for (j = 2; j <= c; j++) {
            /* Compute U_j. */
            CHMAC_SHA256 hctx(passwd, passwdlen);
            hctx.Write(U, 32);
            hctx.Finalize(U);

            /* ... xor U_j ... */
            for (k = 0; k < 32; k++)
                T[k] ^= U[k];
        }

        /* Copy as many bytes as necessary into buf. */
        clen = dkLen - i * 32;
        if (clen > 32)
            clen = 32;
        memcpy(&buf[i * 32], T, clen);
    }

    /* Clean PShctx, since we never called _Final on it. */
    memset(&PShctx, 0, sizeof(CHMAC_SHA256));
}

static inline uint32_t le32dec_2(const void * pp)
{
    const auto * p = (uint8_t const *)pp;

    return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
            ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static inline void le32enc_2(void * pp, uint32_t x)
{
    auto * p = (uint8_t *)pp;

    p[0] = x & 0xff;
    p[1] = (x >> 8) & 0xff;
    p[2] = (x >> 16) & 0xff;
    p[3] = (x >> 24) & 0xff;
}

static void blkcpy(void * dest, const void * src, size_t len)
{
    auto * D = (size_t*)dest;
    const size_t * S = (size_t*)src;
    size_t L = len / sizeof(size_t);
    size_t i;

    for (i = 0; i < L; i++)
        D[i] = S[i];
}

static void blkxor(void * dest, const void * src, size_t len)
{
    auto * D = (size_t*)dest;
    const size_t* S = (size_t*)src;
    size_t L = len / sizeof(size_t);
    size_t i;

    for (i = 0; i < L; i++)
        D[i] ^= S[i];
}

/**
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
 */
static void salsa20_8(uint32_t B[16])
{
    uint32_t x[16];
    size_t i;

    blkcpy(x, B, 64);
    for (i = 0; i < 8; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
        /* Operate on columns. */
        x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
        x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);

        x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
        x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);

        x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
        x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);

        x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
        x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);

        /* Operate on rows. */
        x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
        x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);

        x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
        x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);

        x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
        x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);

        x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
        x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
#undef R
    }
    for (i = 0; i < 16; i++)
        B[i] += x[i];
}

/**
 * blockmix_salsa8(Bin, Bout, X, r):
 * Compute Bout = BlockMix_{salsa20/8, r}(Bin).  The input Bin must be 128r
 * bytes in length; the output Bout must also be the same size.  The
 * temporary space X must be 64 bytes.
 */
static void blockmix_salsa8(const uint32_t * Bin, uint32_t * Bout, uint32_t * X, size_t r)
{
    size_t i;

    /* 1: X <-- B_{2r - 1} */
    blkcpy(X, &Bin[(2 * r - 1) * 16], 64);

    /* 2: for i = 0 to 2r - 1 do */
    for (i = 0; i < 2 * r; i += 2) {
        /* 3: X <-- H(X \xor B_i) */
        blkxor(X, &Bin[i * 16], 64);
        salsa20_8(X);

        /* 4: Y_i <-- X */
        /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
        blkcpy(&Bout[i * 8], X, 64);

        /* 3: X <-- H(X \xor B_i) */
        blkxor(X, &Bin[i * 16 + 16], 64);
        salsa20_8(X);

        /* 4: Y_i <-- X */
        /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
        blkcpy(&Bout[i * 8 + r * 16], X, 64);
    }
}

/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static uint64_t integerify(const void * B, size_t r)
{
    const auto * X = (const uint32_t*)((uintptr_t)(B) + (2 * r - 1) * 64);

    return (((uint64_t)(X[1]) << 32) + X[0]);
}

void SMix(uint8_t *B, unsigned int r, unsigned int N, void* _V, void* XY)
{
    //new
    auto * X = (uint32_t*)XY;
    auto * Y = (uint32_t*)((uint8_t*)(XY) + 128 * r);
    auto * Z = (uint32_t*)((uint8_t *)(XY) + 256 * r);
    auto * V = (uint32_t*)_V;

    uint32_t j, k;

    /* 1: X <-- B */
    for (k = 0; k < 32 * r; k++)
        X[k] = le32dec_2(&B[4 * k]);

    /* 2: for i = 0 to N - 1 do */
    for (unsigned int i = 0; i < N; i += 2)
    {
        /* 3: V_i <-- X */
        blkcpy(&V[i * (32 * r)], X, 128 * r);

        /* 4: X <-- H(X) */
        blockmix_salsa8(X, Y, Z, r);

        /* 3: V_i <-- X */
        blkcpy(&V[(i + 1) * (32 * r)], Y, 128 * r);

        /* 4: X <-- H(X) */
        blockmix_salsa8(Y, X, Z, r);
    }

    /* 6: for i = 0 to N - 1 do */
    for (unsigned int i = 0; i < N; i += 2)
    {
        /* 7: j <-- Integerify(X) mod N */
        j = integerify(X, r) & (N - 1);

        /* 8: X <-- H(X \xor V_j) */
        blkxor(X, &V[j * (32 * r)], 128 * r);
        blockmix_salsa8(X, Y, Z, r);

        /* 7: j <-- Integerify(X) mod N */
        j = integerify(Y, r) & (N - 1);

        /* 8: X <-- H(X \xor V_j) */
        blkxor(Y, &V[j * (32 * r)], 128 * r);
        blockmix_salsa8(Y, X, Z, r);
    }

    /* 10: B' <-- X */
    for (k = 0; k < 32 * r; k++)
        le32enc_2(&B[4 * k], X[k]);
}

void scrypt(const char* pass, unsigned int pLen, const char* salt, unsigned int sLen, char *output, unsigned int N, unsigned int r, unsigned int p, unsigned int dkLen)
{
    //containers
    void* V0 = malloc(128 * r * N + 63);
    void* XY0 = malloc(256 * r + 64 + 63);
    void* B1 = malloc(128 * r * p + 63);
    auto * B = (uint8_t *)(((uintptr_t)(B1) + 63) & ~ (uintptr_t)(63));
    auto * V = (uint32_t *)(((uintptr_t)(V0) + 63) & ~ (uintptr_t)(63));
    auto * XY = (uint32_t *)(((uintptr_t)(XY0) + 63) & ~ (uintptr_t)(63));

    PBKDF2_SHA256((const uint8_t *)pass, pLen, (const uint8_t *)salt, sLen, 1, B, p * 128 * r);

    for(unsigned int i = 0; i < p; i++)
    {
        SMix(&B[i * 128 * r], r, N, V, XY);
    }

    PBKDF2_SHA256((const uint8_t *)pass, pLen, B, p * 128 * r, 1, (uint8_t *)output, dkLen);

    free(V0);
    free(XY0);
    free(B1);
}

#define SCRYPT_BUFFER_SIZE (131072 + 63)

#if defined (OPTIMIZED_SALSA) && (defined (__x86_64__) || defined (__i386__) || defined(__arm__))
extern "C" void scrypt_core(unsigned int *X, unsigned int *V);
#else
// Generic scrypt_core implementation

static inline void xor_salsa8(unsigned int B[16], const unsigned int Bx[16]) {
    unsigned int x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, x11, x12, x13, x14, x15;
    int i;

    x00 = (B[0] ^= Bx[0]);
    x01 = (B[1] ^= Bx[1]);
    x02 = (B[2] ^= Bx[2]);
    x03 = (B[3] ^= Bx[3]);
    x04 = (B[4] ^= Bx[4]);
    x05 = (B[5] ^= Bx[5]);
    x06 = (B[6] ^= Bx[6]);
    x07 = (B[7] ^= Bx[7]);
    x08 = (B[8] ^= Bx[8]);
    x09 = (B[9] ^= Bx[9]);
    x10 = (B[10] ^= Bx[10]);
    x11 = (B[11] ^= Bx[11]);
    x12 = (B[12] ^= Bx[12]);
    x13 = (B[13] ^= Bx[13]);
    x14 = (B[14] ^= Bx[14]);
    x15 = (B[15] ^= Bx[15]);
    for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
        /* Operate on columns. */
        x04 ^= R(x00 + x12, 7);
        x09 ^= R(x05 + x01, 7);
        x14 ^= R(x10 + x06, 7);
        x03 ^= R(x15 + x11, 7);

        x08 ^= R(x04 + x00, 9);
        x13 ^= R(x09 + x05, 9);
        x02 ^= R(x14 + x10, 9);
        x07 ^= R(x03 + x15, 9);

        x12 ^= R(x08 + x04, 13);
        x01 ^= R(x13 + x09, 13);
        x06 ^= R(x02 + x14, 13);
        x11 ^= R(x07 + x03, 13);

        x00 ^= R(x12 + x08, 18);
        x05 ^= R(x01 + x13, 18);
        x10 ^= R(x06 + x02, 18);
        x15 ^= R(x11 + x07, 18);

        /* Operate on rows. */
        x01 ^= R(x00 + x03, 7);
        x06 ^= R(x05 + x04, 7);
        x11 ^= R(x10 + x09, 7);
        x12 ^= R(x15 + x14, 7);

        x02 ^= R(x01 + x00, 9);
        x07 ^= R(x06 + x05, 9);
        x08 ^= R(x11 + x10, 9);
        x13 ^= R(x12 + x15, 9);

        x03 ^= R(x02 + x01, 13);
        x04 ^= R(x07 + x06, 13);
        x09 ^= R(x08 + x11, 13);
        x14 ^= R(x13 + x12, 13);

        x00 ^= R(x03 + x02, 18);
        x05 ^= R(x04 + x07, 18);
        x10 ^= R(x09 + x08, 18);
        x15 ^= R(x14 + x13, 18);
#undef R
    }
    B[0] += x00;
    B[1] += x01;
    B[2] += x02;
    B[3] += x03;
    B[4] += x04;
    B[5] += x05;
    B[6] += x06;
    B[7] += x07;
    B[8] += x08;
    B[9] += x09;
    B[10] += x10;
    B[11] += x11;
    B[12] += x12;
    B[13] += x13;
    B[14] += x14;
    B[15] += x15;
}

static inline void scrypt_core(unsigned int *X, unsigned int *V) {
    unsigned int i, j, k;

    for (i = 0; i < 1024; i++) {
        memcpy(&V[i * 32], X, 128);
        xor_salsa8(&X[0], &X[16]);
        xor_salsa8(&X[16], &X[0]);
    }
    for (i = 0; i < 1024; i++) {
        j = 32 * (X[16] & 1023);
        for (k = 0; k < 32; k++)
            X[k] ^= V[j + k];
        xor_salsa8(&X[0], &X[16]);
        xor_salsa8(&X[16], &X[0]);
    }
}

#endif

/* cpu and memory intensive function to transform a 80 byte buffer into a 32 byte output
   scratchpad size needs to be at least 63 + (128 * r * p) + (256 * r + 64) + (128 * r * N) bytes
   r = 1, p = 1, N = 1024
 */

uint256 scrypt_nosalt(const void *input, size_t inputlen, void *scratchpad) {
    unsigned int *V;
    unsigned int X[32];
    uint256 result = 0;
    V = (unsigned int *) (((uintptr_t)(scratchpad) + 63) & ~(uintptr_t)(63));

    PBKDF2_SHA256((const uint8_t *) input, inputlen, (const uint8_t *) input, inputlen, 1, (uint8_t *) X, 128);
    scrypt_core(X, V);
    PBKDF2_SHA256((const uint8_t *) input, inputlen, (uint8_t *) X, 128, 1, (uint8_t * ) & result, 32);

    return result;
}

uint256 scrypt(const void *data, size_t datalen, const void *salt, size_t saltlen, void *scratchpad) {
    unsigned int *V;
    unsigned int X[32];
    uint256 result = 0;
    V = (unsigned int *) (((uintptr_t)(scratchpad) + 63) & ~(uintptr_t)(63));

    PBKDF2_SHA256((const uint8_t *) data, datalen, (const uint8_t *) salt, saltlen, 1, (uint8_t *) X, 128);
    scrypt_core(X, V);
    PBKDF2_SHA256((const uint8_t *) data, datalen, (uint8_t *) X, 128, 1, (uint8_t * ) & result, 32);

    return result;
}

uint256 scrypt_hash(const void *input, size_t inputlen) {
    unsigned char scratchpad[SCRYPT_BUFFER_SIZE];
    return scrypt_nosalt(input, inputlen, scratchpad);
}

uint256 scrypt_salted_hash(const void *input, size_t inputlen, const void *salt, size_t saltlen) {
    unsigned char scratchpad[SCRYPT_BUFFER_SIZE];
    return scrypt(input, inputlen, salt, saltlen, scratchpad);
}

uint256 scrypt_salted_multiround_hash(const void *input, size_t inputlen, const void *salt, size_t saltlen,
                                      const unsigned int nRounds) {
    uint256 resultHash = scrypt_salted_hash(input, inputlen, salt, saltlen);
    uint256 transitionalHash = resultHash;

    for (unsigned int i = 1; i < nRounds; i++) {
        resultHash = scrypt_salted_hash(input, inputlen, (const void *) &transitionalHash, 32);
        transitionalHash = resultHash;
    }

    return resultHash;
}

uint256 scrypt_blockhash(const void *input) {
    unsigned char scratchpad[SCRYPT_BUFFER_SIZE];
    return scrypt_nosalt(input, 80, scratchpad);
}

