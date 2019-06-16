// Copyright (c) 2014-2018 The Bitcoin Core developers
// Copyright (c) 2018-2019 The WISPR developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <cstdint>
#include <cstring>

#include <endian.h>

uint32_t static inline ReadBE32(const unsigned char* ptr)
{
    uint32_t x;
    memcpy((char*)&x, ptr, 4);
    return be32toh(x);
}

void static inline WriteBE32(unsigned char* ptr, uint32_t x)
{
    uint32_t v = htobe32(x);
    memcpy(ptr, (char*)&v, 4);
}

void static inline WriteBE64(unsigned char* ptr, uint64_t x)
{
    uint64_t v = htobe64(x);
    memcpy(ptr, (char*)&v, 8);
}

#endif // CRYPTO_COMMON_H
