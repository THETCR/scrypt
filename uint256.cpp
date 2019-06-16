// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2017 The PIVX developers
// Copyright (c) 2018-2019 The WISPR developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "uint256.h"

#include <cstdio>
#include <cstring>

const signed char p_util_hexdigit[256] =
    { -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
      -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };

signed char HexDigit(char c)
{
  return p_util_hexdigit[(unsigned char)c];
}

template <unsigned int BITS>
base_blob<BITS>::base_blob(const std::string& str)
{
    SetHex(str);
}
template <unsigned int BITS>
base_blob<BITS>::base_blob(const uint32_t *p, size_t l)
{
    assert(sizeof(pn) >= l);
    memset(pn, 0, sizeof(pn));
    memcpy(pn, p, l);
}
template <unsigned int BITS>
base_blob<BITS>::base_blob(const std::vector<unsigned char>& vch)
{
    if (vch.size() != sizeof(pn))
        throw std::runtime_error("Converting vector of wrong size to base_uint");
    memcpy(pn, &vch[0], sizeof(pn));
}
template <unsigned int BITS>
base_blob<BITS>::base_blob(const uint8_t *p, size_t l)
{
    assert(sizeof(pn) >= l);
    memset(pn, 0, sizeof(pn));
    memcpy(pn, p, l);
}
template <unsigned int BITS>
base_blob<BITS>& base_blob<BITS>::operator<<=(unsigned int shift)
{
    base_blob<BITS> a(*this);
    for (int i = 0; i < WIDTH; i++)
        pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (int i = 0; i < WIDTH; i++) {
        if (i + k + 1 < WIDTH && shift != 0)
            pn[i + k + 1] |= (a.pn[i] >> (32 - shift));
        if (i + k < WIDTH)
            pn[i + k] |= (a.pn[i] << shift);
    }
    return *this;
}

template <unsigned int BITS>
base_blob<BITS>& base_blob<BITS>::operator>>=(unsigned int shift)
{
    base_blob<BITS> a(*this);
    for (int i = 0; i < WIDTH; i++)
        pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (int i = 0; i < WIDTH; i++) {
        if (i - k - 1 >= 0 && shift != 0)
            pn[i - k - 1] |= (a.pn[i] << (32 - shift));
        if (i - k >= 0)
            pn[i - k] |= (a.pn[i] >> shift);
    }
    return *this;
}

template <unsigned int BITS>
base_blob<BITS>& base_blob<BITS>::operator*=(uint32_t b32)
{
    uint64_t carry = 0;
    for (int i = 0; i < WIDTH; i++) {
        uint64_t n = carry + (uint64_t)b32 * pn[i];
        pn[i] = n & 0xffffffff;
        carry = n >> 32;
    }
    return *this;
}

template <unsigned int BITS>
base_blob<BITS>& base_blob<BITS>::operator*=(const base_blob& b)
{
    base_blob<BITS> a = *this;
    *this = 0;
    for (int j = 0; j < WIDTH; j++) {
        uint64_t carry = 0;
        for (int i = 0; i + j < WIDTH; i++) {
            uint64_t n = carry + pn[i + j] + (uint64_t)a.pn[j] * b.pn[i];
            pn[i + j] = n & 0xffffffff;
            carry = n >> 32;
        }
    }
    return *this;
}

template <unsigned int BITS>
base_blob<BITS>& base_blob<BITS>::operator/=(const base_blob& b)
{
    base_blob<BITS> div = b;     // make a copy, so we can shift.
    base_blob<BITS> num = *this; // make a copy, so we can subtract.
    *this = 0;                   // the quotient.
    int num_bits = num.bits();
    int div_bits = div.bits();
    if (div_bits > num_bits) // the result is certainly 0.
        return *this;
    int shift = num_bits - div_bits;
    div <<= shift; // shift so that div and nun align.
    while (shift >= 0) {
        if (num >= div) {
            num -= div;
            pn[shift / 32] |= (1 << (shift & 31)); // set a bit of the result.
        }
        div >>= 1; // shift back.
        shift--;
    }
    // num now contains the remainder of the division.
    return *this;
}

template <unsigned int BITS>
int base_blob<BITS>::CompareTo(const base_blob<BITS>& b) const
{
    for (int i = WIDTH - 1; i >= 0; i--) {
        if (pn[i] < b.pn[i])
            return -1;
        if (pn[i] > b.pn[i])
            return 1;
    }
    return 0;
}

template <unsigned int BITS>
bool base_blob<BITS>::EqualTo(uint64_t b) const
{
    for (int i = WIDTH - 1; i >= 2; i--) {
        if (pn[i])
            return false;
    }
    if (pn[1] != (b >> 32))
        return false;
    if (pn[0] != (b & 0xfffffffful))
        return false;
    return true;
}

template <unsigned int BITS>
double base_blob<BITS>::getdouble() const
{
    double ret = 0.0;
    double fact = 1.0;
    for (int i = 0; i < WIDTH; i++) {
        ret += fact * pn[i];
        fact *= 4294967296.0;
    }
    return ret;
}

template <unsigned int BITS>
std::string base_blob<BITS>::GetHex() const
{
    char psz[sizeof(pn) * 2 + 1];
    for (unsigned int i = 0; i < sizeof(pn); i++)
        sprintf(psz + i * 2, "%02x", ((unsigned char*)pn)[sizeof(pn) - i - 1]);
    return std::string(psz, psz + sizeof(pn) * 2);
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(const char* psz)
{
    memset(pn, 0, sizeof(pn));

    // skip leading spaces
    while (isspace(*psz))
        psz++;

    // skip 0x
    if (psz[0] == '0' && tolower(psz[1]) == 'x')
        psz += 2;

    // hex string to uint
    const char* pbegin = psz;
    while (::HexDigit(*psz) != -1)
        psz++;
    psz--;
    auto * p1 = (unsigned char*)pn;
    unsigned char* pend = p1 + WIDTH * 4;
    while (psz >= pbegin && p1 < pend) {
        *p1 = ::HexDigit(*psz--);
        if (psz >= pbegin) {
            *p1 |= ((unsigned char)::HexDigit(*psz--) << 4);
            p1++;
        }
    }
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(const std::string& str)
{
    SetHex(str.c_str());
}

template <unsigned int BITS>
std::string base_blob<BITS>::ToString() const
{
    return (GetHex());
}

template <unsigned int BITS>
std::string base_blob<BITS>::ToStringReverseEndian() const
{
    char psz[sizeof(pn) * 2 + 1];
    for (unsigned int i = 0; i < sizeof(pn); i++)
        sprintf(psz + i * 2, "%02x", ((unsigned char*)pn)[i]);
    return std::string(psz, psz + sizeof(pn) * 2);
}

template <unsigned int BITS>
unsigned int base_blob<BITS>::bits() const
{
    for (int pos = WIDTH - 1; pos >= 0; pos--) {
        if (pn[pos]) {
            for (int bits = 31; bits > 0; bits--) {
                if (pn[pos] & 1 << bits)
                    return 32 * pos + bits + 1;
            }
            return 32 * pos + 1;
        }
    }
    return 0;
}

// Explicit instantiations for base_blob<160>
template base_blob<160>::base_blob(const std::string&);
template base_blob<160>::base_blob(const std::vector<unsigned char>&);
template base_blob<160>& base_blob<160>::operator<<=(unsigned int);
template base_blob<160>& base_blob<160>::operator>>=(unsigned int);
template base_blob<160>& base_blob<160>::operator*=(uint32_t b32);
template base_blob<160>& base_blob<160>::operator*=(const base_blob<160>& b);
template base_blob<160>& base_blob<160>::operator/=(const base_blob<160>& b);
template int base_blob<160>::CompareTo(const base_blob<160>&) const;
template bool base_blob<160>::EqualTo(uint64_t) const;
template double base_blob<160>::getdouble() const;
template std::string base_blob<160>::GetHex() const;
template std::string base_blob<160>::ToString() const;
template void base_blob<160>::SetHex(const char*);
template void base_blob<160>::SetHex(const std::string&);
template unsigned int base_blob<160>::bits() const;
template base_blob<160>::base_blob(const uint32_t *p, size_t l);
template base_blob<160>::base_blob(const uint8_t *p, size_t l);

// Explicit instantiations for base_blob<256>
template base_blob<256>::base_blob(const std::string&);
template base_blob<256>::base_blob(const uint32_t *p, size_t l);
template base_blob<256>::base_blob(const uint8_t *p, size_t l);
template base_blob<256>::base_blob(const std::vector<unsigned char>&);
template base_blob<256>& base_blob<256>::operator<<=(unsigned int);
template base_blob<256>& base_blob<256>::operator>>=(unsigned int);
template base_blob<256>& base_blob<256>::operator*=(uint32_t b32);
template base_blob<256>& base_blob<256>::operator*=(const base_blob<256>& b);
template base_blob<256>& base_blob<256>::operator/=(const base_blob<256>& b);
template int base_blob<256>::CompareTo(const base_blob<256>&) const;
template bool base_blob<256>::EqualTo(uint64_t) const;
template double base_blob<256>::getdouble() const;
template std::string base_blob<256>::GetHex() const;
template std::string base_blob<256>::ToString() const;
template void base_blob<256>::SetHex(const char*);
template void base_blob<256>::SetHex(const std::string&);
template unsigned int base_blob<256>::bits() const;
template std::string base_blob<256>::ToStringReverseEndian() const;

// Explicit instantiations for base_blob<512>
template base_blob<512>::base_blob(const std::string&);
template base_blob<512>& base_blob<512>::operator<<=(unsigned int);
template base_blob<512>& base_blob<512>::operator>>=(unsigned int);
template std::string base_blob<512>::GetHex() const;
template std::string base_blob<512>::ToString() const;
template std::string base_blob<512>::ToStringReverseEndian() const;

// This implementation directly uses shifts instead of going
// through an intermediate MPI representation.
uint256& uint256::SetCompact(uint32_t nCompact, bool* pfNegative, bool* pfOverflow)
{
    int nSize = nCompact >> 24;
    uint32_t nWord = nCompact & 0x007fffff;
    if (nSize <= 3) {
        nWord >>= 8 * (3 - nSize);
        *this = nWord;
    } else {
        *this = nWord;
        *this <<= 8 * (nSize - 3);
    }
    if (pfNegative)
        *pfNegative = nWord != 0 && (nCompact & 0x00800000) != 0;
    if (pfOverflow)
        *pfOverflow = nWord != 0 && ((nSize > 34) ||
                                     (nWord > 0xff && nSize > 33) ||
                                     (nWord > 0xffff && nSize > 32));
    return *this;
}

uint32_t uint256::GetCompact(bool fNegative) const
{
    int nSize = (bits() + 7) / 8;
    uint32_t nCompact = 0;
    if (nSize <= 3) {
        nCompact = GetLow64() << 8 * (3 - nSize);
    } else {
        uint256 bn = *this >> 8 * (nSize - 3);
        nCompact = bn.GetLow64();
    }
    // The 0x00800000 bit denotes the sign.
    // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
    if (nCompact & 0x00800000) {
        nCompact >>= 8;
        nSize++;
    }
    assert((nCompact & ~0x007fffff) == 0);
    assert(nSize < 256);
    nCompact |= nSize << 24;
    nCompact |= (fNegative && (nCompact & 0x007fffff) ? 0x00800000 : 0);
    return nCompact;
}

static void inline HashMix(uint32_t& a, uint32_t& b, uint32_t& c)
{
    // Taken from lookup3, by Bob Jenkins.
    a -= c;
    a ^= ((c << 4) | (c >> 28));
    c += b;
    b -= a;
    b ^= ((a << 6) | (a >> 26));
    a += c;
    c -= b;
    c ^= ((b << 8) | (b >> 24));
    b += a;
    a -= c;
    a ^= ((c << 16) | (c >> 16));
    c += b;
    b -= a;
    b ^= ((a << 19) | (a >> 13));
    a += c;
    c -= b;
    c ^= ((b << 4) | (b >> 28));
    b += a;
}

static void inline HashFinal(uint32_t& a, uint32_t& b, uint32_t& c)
{
    // Taken from lookup3, by Bob Jenkins.
    c ^= b;
    c -= ((b << 14) | (b >> 18));
    a ^= c;
    a -= ((c << 11) | (c >> 21));
    b ^= a;
    b -= ((a << 25) | (a >> 7));
    c ^= b;
    c -= ((b << 16) | (b >> 16));
    a ^= c;
    a -= ((c << 4) | (c >> 28));
    b ^= a;
    b -= ((a << 14) | (a >> 18));
    c ^= b;
    c -= ((b << 24) | (b >> 8));
}

uint64_t uint256::GetHash(const uint256& salt) const
{
    uint32_t a, b, c;
    a = b = c = 0xdeadbeef + (WIDTH << 2);

    a += pn[0] ^ salt.pn[0];
    b += pn[1] ^ salt.pn[1];
    c += pn[2] ^ salt.pn[2];
    HashMix(a, b, c);
    a += pn[3] ^ salt.pn[3];
    b += pn[4] ^ salt.pn[4];
    c += pn[5] ^ salt.pn[5];
    HashMix(a, b, c);
    a += pn[6] ^ salt.pn[6];
    b += pn[7] ^ salt.pn[7];
    HashFinal(a, b, c);

    return ((((uint64_t)b) << 32) | c);
}
