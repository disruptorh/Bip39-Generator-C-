#include "crypto/ripemd160.hpp"

#include <cstring>

#include <sodium.h>

namespace crypto {
namespace {

// Constants from the RIPEMD-160 specification (Dobbertin/Bosselaers/Preneel).
constexpr std::uint32_t kK1 = 0x00000000U;
constexpr std::uint32_t kK2 = 0x5a827999U;
constexpr std::uint32_t kK3 = 0x6ed9eba1U;
constexpr std::uint32_t kK4 = 0x8f1bbcdcU;
constexpr std::uint32_t kK5 = 0xa953fd4eU;
constexpr std::uint32_t kK6 = 0x50a28be6U;
constexpr std::uint32_t kK7 = 0x5c4dd124U;
constexpr std::uint32_t kK8 = 0x6d703ef3U;
constexpr std::uint32_t kK9 = 0x7a6d76e9U;
constexpr std::uint32_t kK10 = 0x00000000U;

// Message word order for the left and right lines, per round (0..4).
constexpr std::uint8_t kR[5][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8},
    {3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12},
    {1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2},
    {4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13}};
constexpr std::uint8_t kRp[5][16] = {
    {5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12},
    {6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2},
    {15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13},
    {8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14},
    {12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11}};

// Left-shift amounts per round.
constexpr std::uint8_t kS[5][16] = {
    {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8},
    {7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12},
    {11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5},
    {11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12},
    {9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6}};
constexpr std::uint8_t kSp[5][16] = {
    {8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6},
    {9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11},
    {9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5},
    {15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8},
    {8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11}};

// Left-line round functions.
inline std::uint32_t f1(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
  return x ^ y ^ z;
}
inline std::uint32_t f2(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
  return (x & y) | (~x & z);
}
inline std::uint32_t f3(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
  return (x | ~y) ^ z;
}
inline std::uint32_t f4(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
  return (x & z) | (y & ~z);
}
inline std::uint32_t f5(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
  return x ^ (y | ~z);
}

inline std::uint32_t rol(std::uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

// Compress one 512-bit block. `h` holds the 5 chaining words, updated in place.
void compress(std::uint32_t h[5], const std::uint8_t block[64]) {
  std::uint32_t x[16];
  for (int i = 0; i < 16; ++i) {
    x[i] = static_cast<std::uint32_t>(block[4 * i]) |
           (static_cast<std::uint32_t>(block[4 * i + 1]) << 8) |
           (static_cast<std::uint32_t>(block[4 * i + 2]) << 16) |
           (static_cast<std::uint32_t>(block[4 * i + 3]) << 24);
  }

  std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
  std::uint32_t aa = h[0], bb = h[1], cc = h[2], dd = h[3], ee = h[4];

  for (int round = 0; round < 5; ++round) {
    const std::uint32_t k = (round == 0)   ? kK1
                            : (round == 1) ? kK2
                            : (round == 2) ? kK3
                            : (round == 3) ? kK4
                                           : kK5;
    const std::uint32_t kp = (round == 0)   ? kK6
                             : (round == 1) ? kK7
                             : (round == 2) ? kK8
                             : (round == 3) ? kK9
                                            : kK10;
    for (int step = 0; step < 16; ++step) {
      std::uint32_t f, fp;
      switch (round) {
        case 0: f = f1(b, c, d); fp = f5(bb, cc, dd); break;
        case 1: f = f2(b, c, d); fp = f4(bb, cc, dd); break;
        case 2: f = f3(b, c, d); fp = f3(bb, cc, dd); break;
        case 3: f = f4(b, c, d); fp = f2(bb, cc, dd); break;
        default: f = f5(b, c, d); fp = f1(bb, cc, dd); break;
      }
      // One RIPEMD-160 step for each line:
      //   a = ROL(a + f(b,c,d) + x + k, s) + e ;  c = ROL(c, 10)
      // then rotate register roles (a,b,c,d,e) <- (e,a,b,c,d).
      const std::uint32_t oa = a, ob = b, oc = c, od = d, oe = e;
      const std::uint32_t oaa = aa, obb = bb, occ = cc, odd = dd, oee = ee;
      const std::uint32_t na = rol(oa + f + x[kR[round][step]] + k,
                                   kS[round][step]) + oe;
      const std::uint32_t nc = rol(oc, 10);
      a = oe; b = na; c = ob; d = nc; e = od;
      const std::uint32_t nna = rol(oaa + fp + x[kRp[round][step]] + kp,
                                    kSp[round][step]) + oee;
      const std::uint32_t nnc = rol(occ, 10);
      aa = oee; bb = nna; cc = obb; dd = nnc; ee = odd;
    }
  }

  const std::uint32_t t = h[1] + c + dd;
  h[1] = h[2] + d + ee;
  h[2] = h[3] + e + aa;
  h[3] = h[4] + a + bb;
  h[4] = h[0] + b + cc;
  h[0] = t;
}

}  // namespace

void ripemd160(std::uint8_t out[20], const std::uint8_t* data,
               std::size_t len) {
  std::uint32_t h[5] = {0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U,
                        0xc3d2e1f0U};

  const std::size_t full = len - (len % 64);
  for (std::size_t off = 0; off < full; off += 64) compress(h, data + off);

  // Final padded block(s): 0x80, zeros, 64-bit little-endian bit length.
  std::uint8_t block[128];
  const std::size_t rem = len - full;
  std::memset(block, 0, sizeof(block));
  std::memcpy(block, data + full, rem);
  block[rem] = 0x80;
  const std::uint64_t bits = static_cast<std::uint64_t>(len) * 8;
  const std::size_t total = rem + 1 <= 56 ? 64 : 128;
  std::memcpy(block + total - 8, &bits, 8);
  compress(h, block);
  if (total == 128) compress(h, block + 64);

  for (int i = 0; i < 5; ++i) {
    out[4 * i] = static_cast<std::uint8_t>(h[i]);
    out[4 * i + 1] = static_cast<std::uint8_t>(h[i] >> 8);
    out[4 * i + 2] = static_cast<std::uint8_t>(h[i] >> 16);
    out[4 * i + 3] = static_cast<std::uint8_t>(h[i] >> 24);
  }
  sodium_memzero(h, sizeof(h));
}

}  // namespace crypto
